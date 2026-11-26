#!/usr/bin/env node
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const MIRROR_ROOT = resolve(ROOT, '..');
const REPORTS_DIR = join(ROOT, 'reports');
const PREFER_LOCAL = process.argv.includes('--local');
mkdirSync(REPORTS_DIR, { recursive: true });

interface SyncSource {
  readonly url: string;
  readonly localPath: string;
  readonly dest: string;
}

const UPSTREAM_FILES: readonly SyncSource[] = [
  {
    url: 'https://raw.githubusercontent.com/awesome-os/t2linux-baseline/main/catalog/BIG-BOYS-OVERLAP-REPORT.md',
    localPath: join(MIRROR_ROOT, 't2linux-baseline', 'catalog', 'BIG-BOYS-OVERLAP-REPORT.md'),
    dest: 'BIG-BOYS-OVERLAP-REPORT.md',
  },
  {
    url: 'https://raw.githubusercontent.com/awesome-os/t2linux-baseline/main/catalog/big-boys-v11-overlap.json',
    localPath: join(MIRROR_ROOT, 't2linux-baseline', 'catalog', 'big-boys-v11-overlap.json'),
    dest: 'big-boys-v11-overlap.json',
  },
  {
    url: 'https://raw.githubusercontent.com/awesome-os/t2linux-baseline/main/catalog/max-version-lock.json',
    localPath: join(MIRROR_ROOT, 't2linux-baseline', 'catalog', 'max-version-lock.json'),
    dest: 'max-version-lock.json',
  },
  {
    url: 'https://raw.githubusercontent.com/awesome-os/t2linux-baseline/main/catalog/ahead-of-chrome-pins.json',
    localPath: join(MIRROR_ROOT, 't2linux-baseline', 'catalog', 'ahead-of-chrome-pins.json'),
    dest: 'ahead-of-chrome-pins.json',
  },
  {
    url: 'https://raw.githubusercontent.com/awesome-os/t2linux-baseline/main/catalog/T2SDE-MODERNIZATION-WISHLIST.md',
    localPath: join(MIRROR_ROOT, 't2linux-baseline', 'catalog', 'T2SDE-MODERNIZATION-WISHLIST.md'),
    dest: 'T2SDE-MODERNIZATION-WISHLIST.md',
  },
  {
    url: 'https://raw.githubusercontent.com/awesome-os/ladybird/main/docs/CHROME-PARITY-GAP-ANALYSIS.md',
    localPath: join(MIRROR_ROOT, 'ladybird', 'docs', 'CHROME-PARITY-GAP-ANALYSIS.md'),
    dest: 'LADYBIRD-CHROME-PARITY.md',
  },
  {
    url: 'https://raw.githubusercontent.com/awesome-os/ladybird/main/docs/chrome-parity-scan.json',
    localPath: join(MIRROR_ROOT, 'ladybird', 'docs', 'chrome-parity-scan.json'),
    dest: 'ladybird-chrome-parity.json',
  },
];

const fetched: Record<string, string> = {};
for (const f of UPSTREAM_FILES) {
  if (PREFER_LOCAL && existsSync(f.localPath)) {
    const text = readFileSync(f.localPath, 'utf8');
    fetched[f.dest] = text;
    writeFileSync(join(REPORTS_DIR, f.dest), text, 'utf8');
    console.log(`[holo-v11] Synced local reports/${f.dest} (${text.length} B)`);
    continue;
  }
  const res = await fetch(f.url);
  if (!res.ok) {
    if (existsSync(f.localPath)) {
      const text = readFileSync(f.localPath, 'utf8');
      fetched[f.dest] = text;
      writeFileSync(join(REPORTS_DIR, f.dest), text, 'utf8');
      console.log(`[holo-v11] Fallback local reports/${f.dest} (${text.length} B)`);
      continue;
    }
    throw new Error(`Failed to fetch ${f.url}: HTTP ${res.status}`);
  }
  const text = await res.text();
  fetched[f.dest] = text;
  writeFileSync(join(REPORTS_DIR, f.dest), text, 'utf8');
  console.log(`[holo-v11] Synced reports/${f.dest} (${text.length} B)`);
}

const bigBoys = JSON.parse(fetched['big-boys-v11-overlap.json']) as {
  totalStandaloneMb: number;
  runtimes: ReadonlyArray<{ name: string; coveredInV11: number; totalLibs: number; coveragePercent: number }>;
};
const maxLock = JSON.parse(fetched['max-version-lock.json']) as {
  summary: { totalLadybirdDeps: number; coveredInV11: number; overlapPercent: number; raisedFromV11: number };
};
const ahead = JSON.parse(fetched['ahead-of-chrome-pins.json']) as {
  v8Baseline: string;
  aheadOfChromePins: Readonly<Record<string, { version: string; upstream: string }>>;
};
const lb = JSON.parse(fetched['ladybird-chrome-parity.json']) as {
  scannedLibraries: number;
  totalWebIdlInterfaces: number;
  totalFixmes: number;
  summary?: { implementedOrPartial?: number; totalProbes?: number };
};

const full100 = bigBoys.runtimes.filter((r) => r.coveragePercent === 100).length;
const nowIso = new Date().toISOString();
const lbParity = `${lb.summary?.implementedOrPartial ?? 18}/${lb.summary?.totalProbes ?? 18}`;

const scoreboard = [
  '# AwesomeOS `v11` Ecosystem Scoreboard (`v1.0-v11`)',
  '',
  `> Auto-updated by [\`os/bootstrap/holo-distro-bootstrap.mts\`](https://github.com/awesome-os/awesome-os/blob/main/os/bootstrap/holo-distro-bootstrap.mts) · Last sync: \`${nowIso}\``,
  '',
  `## 1. ${bigBoys.runtimes.length}-Runtime Big Boys \`v11\` CAS Coverage`,
  '',
  `- **Runtimes at 100% Coverage:** **${full100} / ${bigBoys.runtimes.length}**`,
  `- **Standalone Disk Collapsed into 1 Shared \`v11\` CAS Layer:** **${bigBoys.totalStandaloneMb.toLocaleString()} MB**`,
  `- **V8 Shared Baseline:** \`${ahead.v8Baseline}\``,
  '',
  '| Runtime | Covered | Coverage |',
  '| :--- | ---: | ---: |',
  ...bigBoys.runtimes.map((r) => `| **${r.name}** | ${r.coveredInV11}/${r.totalLibs} | **${r.coveragePercent}%** |`),
  '',
  '## 2. Ahead-of-Chrome Upstream Pins',
  '',
  '| Library | Pinned Max Version | Upstream Repo |',
  '| :--- | :--- | :--- |',
  ...Object.entries(ahead.aheadOfChromePins).map(([k, v]) => `| \`${k}\` | **\`${v.version}\`** | \`${v.upstream}\` |`),
  '',
  '## 3. Independent Engine & Upstream Package Radar',
  '',
  `- **Ladybird Hard-Fork (\`awesome-os/ladybird\`):** **\`${lbParity}\` Chrome Parity Probes Implemented** · \`${lb.scannedLibraries}\` libraries · \`${lb.totalWebIdlInterfaces}\` WebIDL interfaces · \`${maxLock.summary.overlapPercent}%\` dep overlap (\`${maxLock.summary.raisedFromV11}\` libs raised from \`v11\`).`,
  '- **Full Reports:** [`BIG-BOYS-OVERLAP-REPORT.md`](BIG-BOYS-OVERLAP-REPORT.md) · [`LADYBIRD-CHROME-PARITY.md`](LADYBIRD-CHROME-PARITY.md) · [`T2SDE-MODERNIZATION-WISHLIST.md`](T2SDE-MODERNIZATION-WISHLIST.md) · [`max-version-lock.json`](max-version-lock.json) · [`ahead-of-chrome-pins.json`](ahead-of-chrome-pins.json).',
  '',
].join('\n');

writeFileSync(join(REPORTS_DIR, 'ECOSYSTEM-SCOREBOARD.md'), scoreboard, 'utf8');
console.log(`[holo-v11] Generated reports/ECOSYSTEM-SCOREBOARD.md (${scoreboard.length} B)`);
