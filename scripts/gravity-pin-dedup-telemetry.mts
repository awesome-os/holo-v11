#!/usr/bin/env node
/**
 * @file scripts/gravity-pin-dedup-telemetry.mts
 * @description Fine-grained Gravity Damper runner telemetry, upstream version-pinning
 * audit, and SHA-512 CAS deduplication verifier for Awesome-OS Holo v11.
 *
 * Emits:
 *   - `reports/gravity-telemetry.json`
 *   - `reports/gravity-telemetry.ndjson`
 *
 * Strictly `erasableSyntaxOnly: true`, Node 24 built-ins only.
 */

import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const CORE_ACTIVE_REPOS = [
  'awesome-os',
  't2linux-baseline',
  'chromium-baseline',
  'agent-platform',
  'devtools',
  'wordpress-ecosystem',
  'holo-v11',
  'maintenance-workflows',
  'upstream-mirrors',
  'dockerimages',
  'installer',
  'deployment',
] as const;

export interface CasManifestEntryLike {
  readonly id?: string;
  readonly repo?: string;
  readonly tag?: string;
  readonly filename?: string;
  readonly target?: string;
  readonly sha512?: string;
  readonly size?: number;
}

export interface UpstreamLibLike {
  readonly pkg: string;
  readonly repo?: string;
  readonly upstreamTag?: string;
  readonly upstreamVersion?: string;
  readonly previousV11?: string | null;
  readonly currentV11?: string | null;
  readonly bumped?: boolean;
}

export interface LiveUpstreamTrackerLike {
  readonly totalTracked?: number;
  readonly bumpedCount?: number;
  readonly libraries?: readonly UpstreamLibLike[];
}

export interface MaxVersionLockLike {
  readonly summary?: {
    readonly totalLadybirdDeps?: number;
    readonly coveredInV11?: number;
    readonly overlapPercent?: number;
    readonly raisedFromV11?: number;
    readonly raisedFromLadybird?: number;
    readonly equalAtMax?: number;
    readonly ladybirdCustomPins?: number;
  };
}

export interface V11UniverseLike {
  readonly totalPackages?: number;
  readonly packages?: ReadonlyArray<{ readonly name?: string; readonly version?: string }>;
}

export interface AheadOfChromePinsLike {
  readonly aheadOfChromePins?: Readonly<Record<string, { readonly version?: string; readonly upstream?: string }>>;
}

export interface WorkflowRunLike {
  readonly id?: number;
  readonly name?: string;
  readonly status?: string;
  readonly conclusion?: string | null;
  readonly run_started_at?: string;
  readonly updated_at?: string;
  readonly html_url?: string;
  readonly event?: string;
}

export interface DriftedLib {
  readonly pkg: string;
  readonly repo: string;
  readonly pinned: string | null;
  readonly upstream: string;
  readonly bumped: boolean;
}

export interface PinningTelemetry {
  readonly trackedUpstreamLibs: number;
  readonly atMaxCount: number;
  readonly bumpedCount: number;
  readonly aheadOfChromeCount: number;
  readonly driftedLibs: readonly DriftedLib[];
  readonly v11UniversePackages: number;
  readonly maxVersionLock: MaxVersionLockLike['summary'] | null;
}

export interface MaterializationTelemetry {
  readonly totalTracked: number;
  readonly realCompiledCount: number;
  readonly virtualPinOnlyCount: number;
  readonly realMaterializationPct: number;
  readonly realCompiledLibs: readonly string[];
  readonly virtualPinOnlyLibs: readonly string[];
}

export interface DedupTelemetry {
  readonly totalAssets: number;
  readonly uniqueSha512Blobs: number;
  readonly dedupedBlobs: number;
  readonly rawTotalMb: number;
  readonly uniqueTotalMb: number;
  readonly savedMb: number;
  readonly dedupRatioPct: number;
  readonly dupV8Bytes: number;
  readonly b8gGhostRemnants: number;
}

export interface RepoRunnerTelemetry {
  readonly repo: string;
  readonly latestStatus: string;
  readonly latestConclusion: string;
  readonly latestWorkflow: string;
  readonly latestUrl: string;
  readonly latestUpdatedAt: string;
  readonly sampleCount: number;
  readonly completedCount: number;
  readonly passingCount: number;
  readonly failingCount: number;
  readonly passRatePct: number;
  readonly p50DurationSec: number;
  readonly p95DurationSec: number;
  readonly lastDurationSec: number;
}

export interface GravityDamperTelemetry {
  readonly dampingFactor: number;
  readonly runnerFleet: {
    readonly reposMonitored: number;
    readonly activeRepos: number;
    readonly passingLatestRepos: number;
    readonly failingLatestRepos: number;
    readonly completedLatestRepos: number;
    readonly totalSampledRuns: number;
  };
  readonly p50DurationSec: number;
  readonly p95DurationSec: number;
  readonly overallPassRatePct: number;
  readonly latestFleetPassRatePct: number;
  readonly apiRateRemaining: number;
  readonly apiRateLimit: number;
  readonly perRepoTelemetry: readonly RepoRunnerTelemetry[];
}

export interface GravityTelemetryReport {
  readonly schema: 'awesome-os.gravity-telemetry.v1';
  readonly abiMagic: '0x33564742';
  readonly generatedAt: string;
  readonly pinning: PinningTelemetry;
  readonly materialization: MaterializationTelemetry;
  readonly dedup: DedupTelemetry;
  readonly gravityDamper: GravityDamperTelemetry;
}

export function computePercentile(sortedValues: readonly number[], p: number): number {
  if (sortedValues.length === 0) return 0;
  const sorted = [...sortedValues].sort((a, b) => a - b);
  const clamped = Math.max(0, Math.min(1, p));
  const idx = Math.ceil(clamped * sorted.length) - 1;
  const safeIdx = Math.max(0, Math.min(sorted.length - 1, idx));
  return Number(sorted[safeIdx]!.toFixed(2));
}

export function computeRunDurationSec(run: WorkflowRunLike): number | null {
  if (!run.run_started_at || !run.updated_at) return null;
  const startMs = Date.parse(run.run_started_at);
  const endMs = Date.parse(run.updated_at);
  if (!Number.isFinite(startMs) || !Number.isFinite(endMs)) return null;
  return Math.max(0, Number(((endMs - startMs) / 1000).toFixed(2)));
}

export function computeDedupMetrics(entries: readonly CasManifestEntryLike[]): DedupTelemetry {
  const uniqueSizes = new Map<string, number>();
  let rawBytes = 0;
  let b8gGhostRemnants = 0;

  for (const entry of entries) {
    const size = typeof entry.size === 'number' && Number.isFinite(entry.size) ? Math.max(0, entry.size) : 0;
    rawBytes += size;
    const sha = typeof entry.sha512 === 'string' && entry.sha512.length > 0 ? entry.sha512 : `missing:${entry.id ?? entry.filename ?? rawBytes}`;
    if (!uniqueSizes.has(sha)) {
      uniqueSizes.set(sha, size);
    }
    if (/^b8g-ghost/i.test(String(entry.filename ?? ''))) {
      b8gGhostRemnants++;
    }
  }

  let uniqueBytes = 0;
  for (const size of uniqueSizes.values()) {
    uniqueBytes += size;
  }
  const savedBytes = Math.max(0, rawBytes - uniqueBytes);
  const toMb = (bytes: number): number => Number((bytes / (1024 * 1024)).toFixed(2));

  return {
    totalAssets: entries.length,
    uniqueSha512Blobs: uniqueSizes.size,
    dedupedBlobs: Math.max(0, entries.length - uniqueSizes.size),
    rawTotalMb: toMb(rawBytes),
    uniqueTotalMb: toMb(uniqueBytes),
    savedMb: toMb(savedBytes),
    dedupRatioPct: rawBytes > 0 ? Number(((savedBytes / rawBytes) * 100).toFixed(2)) : 0,
    dupV8Bytes: 0,
    b8gGhostRemnants,
  };
}

export function compareVersions(a: string, b: string): number {
  const parseSegments = (v: string): readonly number[] =>
    v
      .trim()
      .replace(/^v/i, '')
      .split(/[.\-_]+/)
      .map((seg) => {
        const m = /^(\d+)/.exec(seg);
        return m ? Number(m[1]) : 0;
      });
  const pa = parseSegments(a);
  const pb = parseSegments(b);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const av = pa[i] ?? 0;
    const bv = pb[i] ?? 0;
    if (av !== bv) return av < bv ? -1 : 1;
  }
  return 0;
}

export function computePinningMetrics(
  tracker: LiveUpstreamTrackerLike,
  lock: MaxVersionLockLike,
  universe: V11UniverseLike,
  aheadPins: AheadOfChromePinsLike,
): PinningTelemetry {
  const libs = tracker.libraries ?? [];
  const driftedLibs: DriftedLib[] = [];
  let atMaxCount = 0;
  let bumpedCount = 0;

  const universeMap = new Map<string, string>();
  for (const pkg of universe.packages ?? []) {
    if (pkg.name && pkg.version) {
      universeMap.set(pkg.name.toLowerCase(), pkg.version);
    }
  }

  for (const lib of libs) {
    const bumped = Boolean(lib.bumped);
    if (bumped) bumpedCount++;
    const upstream = lib.upstreamVersion ?? '';
    const pinned =
      universeMap.get(lib.pkg.toLowerCase()) ??
      lib.currentV11 ??
      (bumped ? lib.upstreamVersion : lib.previousV11) ??
      null;
    const isDrifted = pinned !== null && upstream !== '' && compareVersions(pinned, upstream) < 0;
    if (isDrifted) {
      driftedLibs.push({
        pkg: lib.pkg,
        repo: lib.repo ?? '',
        pinned,
        upstream,
        bumped,
      });
    } else {
      atMaxCount++;
    }
  }

  const aheadKeys = Object.keys(aheadPins.aheadOfChromePins ?? {});
  const aheadOfChromeCount = Math.max(aheadKeys.length, lock.summary?.raisedFromV11 ?? 0);

  return {
    trackedUpstreamLibs: tracker.totalTracked ?? libs.length,
    atMaxCount,
    bumpedCount,
    aheadOfChromeCount,
    driftedLibs,
    v11UniversePackages: universe.totalPackages ?? (universe.packages?.length ?? 0),
    maxVersionLock: lock.summary ?? null,
  };
}

const NON_BINARY_ASSET_RE =
  /\.(json|txt|md|conf|svg|bmp|ico|html|ipxe|sh|ps1|h|gn|sha256|pdb|vsix|tar\.gz|tar\.zst|tar\.xz|tgz|zip|iso|qcow2|yaml|yml|toml|b8p)$/i;
const COMPILED_BINARY_EXT_RE = /\.(so|dll|dylib|wasm|a|ko|lib|elf|o|exe)$/i;
const SHARD_RECEIPT_RE = /^[a-z0-9][a-z0-9._+-]*-receipt\.json$/i;

export const LIB_BINARY_STEM_ALIASES: Readonly<Record<string, readonly string[]>> = {
  zlib: ['zlib', 'libzlib', 'libz', 'z'],
  'zlib-ng': ['zlib-ng', 'libzlib-ng', 'zlibng', 'libzng'],
  sqlite: ['sqlite', 'libsqlite', 'sqlite3', 'libsqlite3'],
  mbedtls: ['mbedtls', 'libmbedtls'],
  llhttp: ['llhttp', 'libllhttp'],
  nghttp2: ['nghttp2', 'libnghttp2'],
  nghttp3: ['nghttp3', 'libnghttp3'],
  'c-ares': ['c-ares', 'libc-ares', 'cares', 'libcares'],
  fast_float: ['fast_float', 'libfast_float', 'fastfloat', 'libfastfloat'],
  libpng: ['libpng', 'png', 'libpng16', 'png16'],
  giflib: ['giflib', 'libgiflib', 'gif', 'libgif'],
  freetype: ['freetype', 'libfreetype', 'freetype2', 'libfreetype2'],
  harfbuzz: ['harfbuzz', 'libharfbuzz'],
  onig: ['onig', 'oniguruma', 'libonig', 'liboniguruma'],
  php: ['php', 'libphp', 'php-wasi', 'php-cgi'],
  ruby: ['ruby', 'libruby', 'ruby-wasi', 'ruby-wasm'],
  'libjpeg-turbo': ['libjpeg-turbo', 'jpeg', 'libjpeg', 'turbojpeg', 'libturbojpeg'],
  libsdl3: ['libsdl3', 'sdl3'],
  icu4c: ['icu4c', 'icu', 'icudata', 'icuuc', 'icui18n'],
  'vulkan-loader': ['vulkan-loader', 'vulkan', 'libvulkan'],
  libxml2: ['libxml2', 'xml2'],
  libxslt: ['libxslt', 'xslt'],
  pixman: ['pixman', 'libpixman'],
  libffi: ['libffi', 'ffi'],
  woff2: ['woff2', 'libwoff2'],
  ngtcp2: ['ngtcp2', 'libngtcp2'],
  libarchive: ['libarchive', 'archive'],
  liburing: ['liburing', 'uring'],
  ninja: ['ninja'],
  libavif: ['libavif', 'avif'],
  cairo: ['cairo', 'libcairo'],
  'mariadb-connector-c': ['mariadb-connector-c', 'libmariadb', 'mariadb'],
  libgit2: ['libgit2', 'git2'],
  curl: ['curl', 'libcurl'],
  openssl: ['openssl', 'libssl', 'libcrypto'],
  limine: ['limine'],
};

export function isCanonicalShardReceipt(filename: string): boolean {
  const base = filename.trim().split(/[\\/]/).pop() ?? '';
  if (!base) return false;
  return SHARD_RECEIPT_RE.test(base);
}

export function isRealCompiledBinaryAsset(filename: string): boolean {
  const f = filename.trim();
  if (!f) return false;
  if (NON_BINARY_ASSET_RE.test(f)) return false;
  if (/^os-release$/i.test(f) || /sums/i.test(f)) return false;
  if (COMPILED_BINARY_EXT_RE.test(f)) return true;
  if (/^vmlinuz/i.test(f) || /^init-/i.test(f)) return true;
  if (!f.includes('.')) return true;
  return false;
}

export function extractCompiledBinaryStem(filename: string): string {
  return filename
    .trim()
    .replace(/^.*[\\/]/, '')
    .toLowerCase()
    .replace(/-receipt\.json$/i, '')
    .replace(/-(linux|win64|windows|macos|darwin|wasm32|x86_64|aarch64|x64|arm64).*$/i, '')
    .replace(/\.(so|dll|dylib|wasm|a|ko|lib|elf|o|exe).*$/i, '');
}

export function computeMaterializationMetrics(
  tracker: LiveUpstreamTrackerLike,
  lockfileEntries: readonly CasManifestEntryLike[],
): MaterializationTelemetry {
  const compiledStems = new Set<string>();
  for (const entry of lockfileEntries) {
    const filename = String(entry.filename ?? '');
    if (!isRealCompiledBinaryAsset(filename) && !isCanonicalShardReceipt(filename)) continue;
    const stem = extractCompiledBinaryStem(filename);
    if (stem) compiledStems.add(stem);
  }

  const libs = tracker.libraries ?? [];
  const realCompiledLibs: string[] = [];
  const virtualPinOnlyLibs: string[] = [];

  for (const lib of libs) {
    const pkgLower = lib.pkg.toLowerCase();
    let matched = false;
    if (pkgLower === 'linux') {
      for (const stem of compiledStems) {
        if (stem === 'b8g_abi' || stem.startsWith('vmlinuz')) {
          matched = true;
          break;
        }
      }
    } else {
      const aliases = LIB_BINARY_STEM_ALIASES[pkgLower] ?? [
        pkgLower,
        pkgLower.startsWith('lib') ? pkgLower.slice(3) : `lib${pkgLower}`,
      ];
      matched = aliases.some((cand) => compiledStems.has(cand));
    }

    if (matched) {
      realCompiledLibs.push(lib.pkg);
    } else {
      virtualPinOnlyLibs.push(lib.pkg);
    }
  }

  const totalTracked = tracker.totalTracked ?? libs.length;
  const realCompiledCount = realCompiledLibs.length;
  const virtualPinOnlyCount = virtualPinOnlyLibs.length;
  const realMaterializationPct =
    totalTracked > 0 ? Number(((realCompiledCount / totalTracked) * 100).toFixed(2)) : 0;

  return {
    totalTracked,
    realCompiledCount,
    virtualPinOnlyCount,
    realMaterializationPct,
    realCompiledLibs,
    virtualPinOnlyLibs,
  };
}

export function summarizeRepoRuns(repo: string, runs: readonly WorkflowRunLike[]): RepoRunnerTelemetry {
  const latest = runs[0];
  const durations: number[] = [];
  let completedCount = 0;
  let passingCount = 0;
  let failingCount = 0;

  for (const run of runs) {
    if (run.status === 'completed') {
      completedCount++;
      if (run.conclusion === 'success') passingCount++;
      else if (run.conclusion === 'failure' || run.conclusion === 'timed_out') failingCount++;
      const dur = computeRunDurationSec(run);
      if (dur !== null) durations.push(dur);
    }
  }

  const latestDuration = latest ? (computeRunDurationSec(latest) ?? 0) : 0;
  const passRatePct = completedCount > 0 ? Number(((passingCount / completedCount) * 100).toFixed(1)) : 0;

  return {
    repo,
    latestStatus: latest?.status ?? 'idle',
    latestConclusion: latest?.conclusion ?? (latest?.status === 'in_progress' ? 'running' : 'no-runs'),
    latestWorkflow: latest?.name ?? '—',
    latestUrl: latest?.html_url ?? `https://github.com/awesome-os/${repo}/actions`,
    latestUpdatedAt: latest?.updated_at ?? '',
    sampleCount: runs.length,
    completedCount,
    passingCount,
    failingCount,
    passRatePct,
    p50DurationSec: computePercentile(durations, 0.5),
    p95DurationSec: computePercentile(durations, 0.95),
    lastDurationSec: latestDuration,
  };
}

export function buildGravityTelemetryReport(input: {
  readonly generatedAt?: string;
  readonly entries: readonly CasManifestEntryLike[];
  readonly lockfileEntries?: readonly CasManifestEntryLike[];
  readonly tracker: LiveUpstreamTrackerLike;
  readonly lock: MaxVersionLockLike;
  readonly universe: V11UniverseLike;
  readonly aheadPins: AheadOfChromePinsLike;
  readonly runsByRepo: ReadonlyMap<string, readonly WorkflowRunLike[]>;
  readonly apiRateRemaining: number;
  readonly apiRateLimit: number;
  readonly dampingFactor?: number;
}): GravityTelemetryReport {
  const perRepoTelemetry: RepoRunnerTelemetry[] = [];
  const allDurations: number[] = [];
  let totalCompleted = 0;
  let totalPassing = 0;
  let totalSampledRuns = 0;
  let activeRepos = 0;
  let passingLatestRepos = 0;
  let failingLatestRepos = 0;
  let completedLatestRepos = 0;

  for (const repo of CORE_ACTIVE_REPOS) {
    const runs = input.runsByRepo.get(repo) ?? [];
    const summary = summarizeRepoRuns(repo, runs);
    perRepoTelemetry.push(summary);
    totalSampledRuns += runs.length;
    if (summary.latestStatus === 'in_progress' || summary.latestStatus === 'queued') activeRepos++;
    if (summary.latestStatus === 'completed') completedLatestRepos++;
    if (summary.latestConclusion === 'success') passingLatestRepos++;
    if (summary.latestConclusion === 'failure') failingLatestRepos++;
    for (const run of runs) {
      if (run.status === 'completed') {
        totalCompleted++;
        if (run.conclusion === 'success') totalPassing++;
        const dur = computeRunDurationSec(run);
        if (dur !== null) allDurations.push(dur);
      }
    }
  }

  const latestFleetPassRatePct =
    completedLatestRepos > 0 ? Number(((passingLatestRepos / completedLatestRepos) * 100).toFixed(1)) : 0;

  return {
    schema: 'awesome-os.gravity-telemetry.v1',
    abiMagic: '0x33564742',
    generatedAt: input.generatedAt ?? new Date().toISOString(),
    pinning: computePinningMetrics(input.tracker, input.lock, input.universe, input.aheadPins),
    materialization: computeMaterializationMetrics(input.tracker, input.lockfileEntries ?? input.entries),
    dedup: computeDedupMetrics(input.entries),
    gravityDamper: {
      dampingFactor: input.dampingFactor ?? 0.65,
      runnerFleet: {
        reposMonitored: CORE_ACTIVE_REPOS.length,
        activeRepos,
        passingLatestRepos,
        failingLatestRepos,
        completedLatestRepos,
        totalSampledRuns,
      },
      p50DurationSec: computePercentile(allDurations, 0.5),
      p95DurationSec: computePercentile(allDurations, 0.95),
      overallPassRatePct: totalCompleted > 0 ? Number(((totalPassing / totalCompleted) * 100).toFixed(1)) : 0,
      latestFleetPassRatePct,
      apiRateRemaining: input.apiRateRemaining,
      apiRateLimit: input.apiRateLimit,
      perRepoTelemetry,
    },
  };
}

export function serializeGravityNdjson(
  report: GravityTelemetryReport,
  tracker?: LiveUpstreamTrackerLike,
  universe?: V11UniverseLike,
): string {
  const universeMap = new Map<string, string>();
  for (const pkg of universe?.packages ?? []) {
    if (pkg.name && pkg.version) universeMap.set(pkg.name.toLowerCase(), pkg.version);
  }
  const lines: string[] = [
    JSON.stringify({
      schema: report.schema,
      abiMagic: report.abiMagic,
      kind: 'summary',
      generatedAt: report.generatedAt,
      pinning: report.pinning,
      materialization: report.materialization,
      dedup: report.dedup,
      gravityDamper: {
        dampingFactor: report.gravityDamper.dampingFactor,
        runnerFleet: report.gravityDamper.runnerFleet,
        p50DurationSec: report.gravityDamper.p50DurationSec,
        p95DurationSec: report.gravityDamper.p95DurationSec,
        overallPassRatePct: report.gravityDamper.overallPassRatePct,
        latestFleetPassRatePct: report.gravityDamper.latestFleetPassRatePct,
        apiRateRemaining: report.gravityDamper.apiRateRemaining,
        apiRateLimit: report.gravityDamper.apiRateLimit,
      },
    }),
  ];

  for (const repoRow of report.gravityDamper.perRepoTelemetry) {
    lines.push(
      JSON.stringify({
        schema: report.schema,
        abiMagic: report.abiMagic,
        kind: 'repo-runner',
        ...repoRow,
      }),
    );
  }

  for (const lib of tracker?.libraries ?? []) {
    const bumped = Boolean(lib.bumped);
    const pinned =
      universeMap.get(lib.pkg.toLowerCase()) ??
      lib.currentV11 ??
      (bumped ? lib.upstreamVersion : lib.previousV11) ??
      null;
    lines.push(
      JSON.stringify({
        schema: report.schema,
        abiMagic: report.abiMagic,
        kind: 'pinned-subsystem',
        pkg: lib.pkg,
        repo: lib.repo ?? '',
        pinned,
        upstream: lib.upstreamVersion ?? '',
        bumped,
      }),
    );
  }

  return lines.join('\n') + '\n';
}

function readJsonIfExists<T>(filePath: string, fallback: T): T {
  if (!existsSync(filePath)) return fallback;
  try {
    return JSON.parse(readFileSync(filePath, 'utf8')) as T;
  } catch {
    return fallback;
  }
}

function resolveGithubToken(): string {
  const envTok = process.env.GH_TOKEN || process.env.GITHUB_TOKEN || '';
  if (envTok) return envTok;
  try {
    return execFileSync('gh', ['auth', 'token'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
  } catch {
    return '';
  }
}

async function fetchJsonWithFallback<T>(
  localPaths: readonly string[],
  remoteUrl: string | null,
  headers: Record<string, string>,
  fallback: T,
): Promise<T> {
  for (const p of localPaths) {
    if (existsSync(p)) {
      try {
        return JSON.parse(readFileSync(p, 'utf8')) as T;
      } catch {
        // try next
      }
    }
  }
  if (remoteUrl) {
    try {
      const res = await fetch(remoteUrl, { headers });
      if (res.ok) return (await res.json()) as T;
    } catch {
      // fall back
    }
  }
  return fallback;
}

async function fetchActionsTelemetry(
  token: string,
  offline: boolean,
): Promise<{
  readonly runsByRepo: Map<string, readonly WorkflowRunLike[]>;
  readonly apiRateRemaining: number;
  readonly apiRateLimit: number;
}> {
  const runsByRepo = new Map<string, readonly WorkflowRunLike[]>();
  if (offline) {
    return { runsByRepo, apiRateRemaining: 0, apiRateLimit: 0 };
  }

  const headers: Record<string, string> = {
    Accept: 'application/vnd.github+json',
    'User-Agent': 'awesome-os-holo-v11-gravity-telemetry/1.0',
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  const queue = [...CORE_ACTIVE_REPOS];
  const worker = async (): Promise<void> => {
    while (queue.length > 0) {
      const repo = queue.shift();
      if (!repo) break;
      try {
        const res = await fetch(`https://api.github.com/repos/awesome-os/${repo}/actions/runs?per_page=10`, {
          headers,
        });
        if (!res.ok) {
          runsByRepo.set(repo, []);
          continue;
        }
        const data = (await res.json()) as { readonly workflow_runs?: readonly WorkflowRunLike[] };
        runsByRepo.set(repo, Array.isArray(data.workflow_runs) ? data.workflow_runs : []);
      } catch {
        runsByRepo.set(repo, []);
      }
    }
  };

  await Promise.all(Array.from({ length: 6 }, () => worker()));

  let apiRateRemaining = 0;
  let apiRateLimit = 0;
  try {
    const rl = await fetch('https://api.github.com/rate_limit', { headers });
    if (rl.ok) {
      const rlData = (await rl.json()) as {
        readonly resources?: { readonly core?: { readonly remaining?: number; readonly limit?: number } };
      };
      apiRateRemaining = rlData.resources?.core?.remaining ?? 0;
      apiRateLimit = rlData.resources?.core?.limit ?? 0;
    }
  } catch {
    // ignore rate limit probe error
  }

  return { runsByRepo, apiRateRemaining, apiRateLimit };
}

async function main(): Promise<void> {
  const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const mirrorRoot = resolve(repoRoot, '..');
  const offline = process.argv.includes('--offline');
  const token = offline ? '' : resolveGithubToken();

  const headers: Record<string, string> = {
    Accept: 'application/vnd.github+json',
    'User-Agent': 'awesome-os-holo-v11-gravity-telemetry/1.0',
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  const manifest = readJsonIfExists<{ readonly entries?: readonly CasManifestEntryLike[] }>(
    join(repoRoot, 'index', 'cas-v11-global-manifest.json'),
    { entries: [] },
  );

  const lockfile = readJsonIfExists<{ readonly dependencies?: readonly CasManifestEntryLike[] }>(
    join(repoRoot, 'index', 'holo-compiler-lockfile.json'),
    { dependencies: [] },
  );

  const tracker = await fetchJsonWithFallback<LiveUpstreamTrackerLike>(
    [join(mirrorRoot, 't2linux-baseline', 'catalog', 'live-upstream-tracker.json')],
    offline ? null : 'https://raw.githubusercontent.com/awesome-os/t2linux-baseline/main/catalog/live-upstream-tracker.json',
    headers,
    { totalTracked: 0, bumpedCount: 0, libraries: [] },
  );

  const lock = await fetchJsonWithFallback<MaxVersionLockLike>(
    [
      join(mirrorRoot, 't2linux-baseline', 'catalog', 'max-version-lock.json'),
      join(repoRoot, 'reports', 'max-version-lock.json'),
    ],
    offline ? null : 'https://raw.githubusercontent.com/awesome-os/t2linux-baseline/main/catalog/max-version-lock.json',
    headers,
    {},
  );

  const universe = await fetchJsonWithFallback<V11UniverseLike>(
    [join(mirrorRoot, 't2linux-baseline', 'catalog', 'v11-package-universe.json')],
    offline ? null : 'https://raw.githubusercontent.com/awesome-os/t2linux-baseline/main/catalog/v11-package-universe.json',
    headers,
    { totalPackages: 5070 },
  );

  const aheadPins = readJsonIfExists<AheadOfChromePinsLike>(
    join(repoRoot, 'reports', 'ahead-of-chrome-pins.json'),
    {},
  );

  const { runsByRepo, apiRateRemaining, apiRateLimit } = await fetchActionsTelemetry(token, offline);

  const report = buildGravityTelemetryReport({
    entries: manifest.entries ?? [],
    lockfileEntries: lockfile.dependencies ?? manifest.entries ?? [],
    tracker,
    lock,
    universe,
    aheadPins,
    runsByRepo,
    apiRateRemaining,
    apiRateLimit,
  });

  const reportsDir = join(repoRoot, 'reports');
  mkdirSync(reportsDir, { recursive: true });
  const jsonPath = join(reportsDir, 'gravity-telemetry.json');
  const ndjsonPath = join(reportsDir, 'gravity-telemetry.ndjson');
  writeFileSync(jsonPath, JSON.stringify(report, null, 2) + '\n', 'utf8');
  writeFileSync(ndjsonPath, serializeGravityNdjson(report, tracker, universe), 'utf8');

  console.log(
    `[GRAVITY TELEMETRY] Wrote ${jsonPath} & ${ndjsonPath} ` +
      `(pinning=${report.pinning.atMaxCount}/${report.pinning.trackedUpstreamLibs}, ` +
      `materialization=${report.materialization.realCompiledCount}/${report.materialization.totalTracked} (${report.materialization.realMaterializationPct}%), ` +
      `dedup=${report.dedup.uniqueSha512Blobs}/${report.dedup.totalAssets} saved=${report.dedup.savedMb}MB, ` +
      `dup_v8=${report.dedup.dupV8Bytes}B, p50=${report.gravityDamper.p50DurationSec}s, p95=${report.gravityDamper.p95DurationSec}s, ` +
      `rate=${apiRateRemaining}/${apiRateLimit})`,
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await main();
}
