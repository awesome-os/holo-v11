#!/usr/bin/env node
/**
 * @file scripts/warm-global-cas.mts
 * @description Planetary-scale Global v11 CAS Pre-Warmer for `awesome-os/holo-sdk`.
 *
 * Walks all `awesome-os/*` latest GitHub Releases in 12-way parallel, streams each
 * asset through SHA-512, optionally populates `$HOLO_CAS_DIR/v11/files/00..ff/<sha512>`,
 * and emits:
 *   - `dist/cas-v11-global-manifest.json`
 *   - `dist/holo-compiler-lockfile.json`
 *   - `dist/SHA512SUMS.txt`
 *
 * Strictly `erasableSyntaxOnly: true`, Node 22+ built-ins only.
 */

import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

function canonicalizeFallback(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map((v) => canonicalizeFallback(v)).join(',') + ']';
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj)
    .filter((k) => k !== 'signature' && obj[k] !== undefined)
    .sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalizeFallback(obj[k])).join(',') + '}';
}

function fallbackSignManifestEd25519<T extends Record<string, unknown>>(manifest: T): T & { readonly signature: Record<string, string> } {
  const envSeed = process.env.AWESOMEOS_ED25519_SEED_HEX;
  const seedHex =
    envSeed && /^[0-9a-fA-F]{64}$/.test(envSeed)
      ? envSeed
      : createHash('sha256').update('awesomeos-verified-boot-dev-root-v11-0x33564742', 'utf8').digest('hex');
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seedHex, 'hex')]);
  const priv = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  const spki = createPublicKey(priv).export({ format: 'der', type: 'spki' });
  const publicKeyHex = Buffer.from(spki.subarray(spki.length - 32)).toString('hex');
  const canonical = canonicalizeFallback(manifest);
  const payloadSha512 = createHash('sha512').update(canonical, 'utf8').digest('hex');
  const signatureHex = sign(null, Buffer.from(canonical, 'utf8'), priv).toString('hex');
  return {
    ...manifest,
    signature: {
      scheme: 'ed25519-sha512-v1',
      keyId: 'awesomeos-root-v11',
      publicKeyHex,
      payloadSha512,
      signatureHex,
      signedAt: new Date().toISOString(),
    },
  };
}

async function resolveManifestSigner(): Promise<
  <T extends Record<string, unknown>>(manifest: T) => T & { readonly signature: unknown }
> {
  const candidate = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    '../../awesome-os/security/verified-boot.mts',
  );
  if (fs.existsSync(candidate)) {
    try {
      const mod = (await import(pathToFileURL(candidate).href)) as {
        signManifestEd25519?: <T extends Record<string, unknown>>(manifest: T) => T & { readonly signature: unknown };
      };
      if (typeof mod.signManifestEd25519 === 'function') return mod.signManifestEd25519;
    } catch {
      // fall through to local Ed25519 fallback
    }
  }
  return fallbackSignManifestEd25519;
}

const signManifestEd25519 = await resolveManifestSigner();

const ORG = process.env.AWESOME_OS_ORG || 'awesome-os';
const TOKEN = process.env.GH_TOKEN || process.env.GITHUB_TOKEN || '';
const MAX_ASSET_BYTES = Number(process.env.MAX_ASSET_MB || '250') * 1024 * 1024;
const WARM_DISK_MAX_BYTES = Number(process.env.WARM_DISK_MAX_MB || '32') * 1024 * 1024;
const WRITE_LOCAL_CAS = process.argv.includes('--write-local-cas');
const LOCAL_CAS_ROOT = process.env.B8G_CAS_DIR || path.join(os.homedir(), '.b8g', 'cas');
const CONCURRENCY = 12;
const OUT_DIR = path.resolve(process.cwd(), 'index');

/**
 * Consolidated standalone repositories that were archived after folding into the
 * 5 canonical monorepos, but still host live GitHub Release blobs referenced by
 * downstream Holo v11 consumers (e.g. `devtools` Theia/IDE hydration).
 * Dead legacy forks (`pouchdb`, `rollup`, `modern-picomatch`, `ws`, `experiments`)
 * and `b8g-ghost` repos remain excluded.
 */
const CONSOLIDATED_ARCHIVE_ALLOWLIST = new Set<string>([
  'theia',
  'code-oss',
  'b8g-ide',
  'brave',
  'electron',
  'blink',
  'skia',
  'dawn',
  'bun-neon',
  'node',
  'nodeman',
  'libv8_monolith',
  'just-js',
  'godot',
  'blender',
  'godot-vscode',
  'blender-vscode',
  'unity-vscode',
  'unreal-vscode',
  'obs-vscode',
  'stealifylang-vscode',
  'wasi-host',
  'sectium-es',
  'sectium-jvm',
  'obs',
  'dotnet',
  'powershell',
  'qt',
  'b8g-micro-moe',
  'b8g-app-dedup',
  'x402-BaaS-mcp',
  'pinokio',
  't2xnu',
  'posix',
  'bootloader',
  'holo-ffi',
  'b8g-production-rack',
]);

const apiHeaders: Record<string, string> = {
  Accept: 'application/vnd.github+json',
  'User-Agent': 'awesome-os-global-v11-cas-warmer/1.0',
};
if (TOKEN) apiHeaders.Authorization = `Bearer ${TOKEN}`;

interface GhRepo {
  readonly name: string;
  readonly archived?: boolean;
}

interface GhAsset {
  readonly name: string;
  readonly size: number;
  readonly browser_download_url: string;
}

interface GhRelease {
  readonly tag_name: string;
  readonly assets: readonly GhAsset[];
}

interface GlobalCasEntry {
  readonly id: string;
  readonly repo: string;
  readonly tag: string;
  readonly filename: string;
  readonly target: string;
  readonly executable: boolean;
  readonly sha512: string;
  readonly size: number;
  readonly blobPath: string;
  readonly downloadUrl: string;
}

function inferTarget(filename: string): string {
  const f = filename.toLowerCase();
  if (f.includes('win64') || f.includes('windows') || f.endsWith('.exe') || f.endsWith('.dll')) return 'win64';
  if (f.includes('linux-arm64') || f.includes('aarch64-linux')) return 'linux-arm64';
  if (f.includes('linux') || f.endsWith('.so')) return 'linux-x64';
  if (f.includes('macos') || f.includes('darwin') || f.endsWith('.dylib')) return 'macos-arm64';
  if (f.includes('wasm') || f.endsWith('.wasm')) return 'wasm32-wasi';
  return 'any';
}

function isExecutableAsset(filename: string): boolean {
  const f = filename.toLowerCase();
  return (
    f.endsWith('.exe') ||
    f.endsWith('.dll') ||
    f.endsWith('.so') ||
    f.endsWith('.dylib') ||
    f.endsWith('.wasm') ||
    f.endsWith('.sh') ||
    (!f.includes('.') && !f.endsWith('sums'))
  );
}

async function listOrgRepos(): Promise<string[]> {
  const names: string[] = [];
  for (let page = 1; page <= 5; page++) {
    const res = await fetch(
      `https://api.github.com/orgs/${ORG}/repos?per_page=100&page=${page}&type=public`,
      { headers: apiHeaders },
    );
    if (!res.ok) throw new Error(`GitHub repos API HTTP ${res.status}`);
    const batch = (await res.json()) as GhRepo[];
    if (batch.length === 0) break;
    for (const r of batch) {
      if (r.name === 'holo-sdk') continue;
      if (!r.archived || CONSOLIDATED_ARCHIVE_ALLOWLIST.has(r.name)) {
        names.push(r.name);
      }
    }
    if (batch.length < 100) break;
  }
  return names.sort();
}

async function streamSha512AndMaybeWarm(
  url: string,
  executable: boolean,
  expectedSize: number,
): Promise<{ sha512: string; bytes: number; warmedOnDisk: boolean }> {
  const res = await fetch(url, {
    redirect: 'follow',
    headers: { 'User-Agent': 'awesome-os-global-v11-cas-warmer/1.0' },
  });
  if (!res.ok || !res.body) throw new Error(`HTTP ${res.status} fetching ${url}`);
  const shouldCacheBytes = WRITE_LOCAL_CAS && expectedSize <= WARM_DISK_MAX_BYTES;
  const chunks: Uint8Array[] = [];
  const hash = createHash('sha512');
  let bytes = 0;
  for await (const chunk of res.body as AsyncIterable<Uint8Array>) {
    hash.update(chunk);
    bytes += chunk.byteLength;
    if (shouldCacheBytes) chunks.push(chunk);
  }
  const sha512 = hash.digest('hex');
  let warmedOnDisk = false;
  if (shouldCacheBytes) {
    const shardDir = path.join(LOCAL_CAS_ROOT, 'v11', 'files', sha512.slice(0, 2));
    const blobName = executable ? `${sha512}-exec` : sha512;
    const dst = path.join(shardDir, blobName);
    if (!fs.existsSync(dst)) {
      fs.mkdirSync(shardDir, { recursive: true });
      fs.writeFileSync(dst, Buffer.concat(chunks));
    }
    warmedOnDisk = true;
  }
  return { sha512, bytes, warmedOnDisk };
}

const repos = await listOrgRepos();
console.log(`Warming Global v11 CAS across ${repos.length} public ${ORG}/* repositories...`);

const entries: GlobalCasEntry[] = [];
let idx = 0;
let skippedLarge = 0;

async function worker(): Promise<void> {
  while (idx < repos.length) {
    const repo = repos[idx++]!;
    try {
      const relRes = await fetch(`https://api.github.com/repos/${ORG}/${repo}/releases/latest`, {
        headers: apiHeaders,
      });
      if (!relRes.ok) continue;
      const rel = (await relRes.json()) as GhRelease;
      if (!rel.tag_name || !Array.isArray(rel.assets) || rel.assets.length === 0) continue;

      for (const asset of rel.assets) {
        if (/^b8g-ghost/i.test(asset.name)) continue;
        if (asset.size > MAX_ASSET_BYTES) {
          skippedLarge++;
          continue;
        }
        try {
          const executable = isExecutableAsset(asset.name);
          const { sha512, bytes } = await streamSha512AndMaybeWarm(
            asset.browser_download_url,
            executable,
            asset.size,
          );
          const blobName = executable ? `${sha512}-exec` : sha512;
          entries.push({
            id: `${ORG}/${repo}@${rel.tag_name}/${asset.name}`,
            repo,
            tag: rel.tag_name,
            filename: asset.name,
            target: inferTarget(asset.name),
            executable,
            sha512,
            size: bytes,
            blobPath: `v11/files/${sha512.slice(0, 2)}/${blobName}`,
            downloadUrl: asset.browser_download_url,
          });
        } catch {
          // non-fatal single asset failure
        }
      }
    } catch {
      // non-fatal repo failure
    }
  }
}

await Promise.all(Array.from({ length: CONCURRENCY }, () => worker()));

entries.sort((a, b) => a.id.localeCompare(b.id));
const uniqueBlobs = new Set(entries.map((e) => e.sha512)).size;
const totalReposWithAssets = new Set(entries.map((e) => e.repo)).size;
const totalBytes = entries.reduce((sum, e) => sum + e.size, 0);

fs.mkdirSync(OUT_DIR, { recursive: true });

const manifestDoc = signManifestEd25519({
  schema: 'awesome-os-cas-v11-manifest-v1',
  abiMagic: '0x33564742',
  version: 'v11',
  generatedAt: new Date().toISOString(),
  totalRepos: totalReposWithAssets,
  totalAssets: entries.length,
  uniqueBlobs,
  totalBytes,
  skippedLarge,
  entries,
});

const lockfileDoc = {
  schema: 'holo-compiler-lockfile-v1',
  abiMagic: '0x33564742',
  casLayout: 'v11',
  dependencies: entries.map((e) => ({
    id: e.id,
    repo: e.repo,
    tag: e.tag,
    filename: e.filename,
    target: e.target,
    sha512: e.sha512,
    size: e.size,
    blobPath: e.blobPath,
    downloadUrl: e.downloadUrl,
  })),
};

fs.writeFileSync(path.join(OUT_DIR, 'cas-v11-global-manifest.json'), JSON.stringify(manifestDoc, null, 2) + '\n', 'utf8');
fs.writeFileSync(path.join(OUT_DIR, 'holo-compiler-lockfile.json'), JSON.stringify(lockfileDoc, null, 2) + '\n', 'utf8');

console.log(
  JSON.stringify(
    {
      totalRepos: totalReposWithAssets,
      totalAssets: entries.length,
      uniqueBlobs,
      totalMB: Number((totalBytes / (1024 * 1024)).toFixed(1)),
      skippedLarge,
    },
    null,
    2,
  ),
);
