#!/usr/bin/env node
/**
 * @file scripts/export-static-cas-pages.mts
 * @description Generates zero-rate-limit static sharded CAS JSON manifests for GitHub Pages
 * from `index/cas-v11-global-manifest.json`:
 *   - `<outDir>/index.json` (with deterministic `forwardBundleHash` Merkle root over all unique SHA-512 blobs)
 *   - `<outDir>/shards/<aa>.json` (`00..ff` for populated prefixes)
 *
 * Strictly `erasableSyntaxOnly: true`, Node 24/26 built-ins only.
 */

import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { comparePosixPaths, computeForwardBundleHash } from './b8p-forward-bundle.mts';

export interface GlobalCasManifestEntry {
  readonly id?: string;
  readonly repo?: string;
  readonly tag?: string;
  readonly filename?: string;
  readonly target?: string;
  readonly executable?: boolean;
  readonly sha512?: string;
  readonly size?: number;
  readonly blobPath?: string;
  readonly downloadUrl?: string;
}

export interface GlobalCasManifest {
  readonly schema?: string;
  readonly abiMagic?: string;
  readonly version?: string;
  readonly generatedAt?: string;
  readonly totalRepos?: number;
  readonly totalAssets?: number;
  readonly uniqueBlobs?: number;
  readonly totalBytes?: number;
  readonly entries?: readonly GlobalCasManifestEntry[];
}

export interface StaticCasBlobRef {
  readonly id: string;
  readonly repo: string;
  readonly tag: string;
  readonly filename: string;
  readonly target: string;
  readonly executable: boolean;
  readonly downloadUrl: string;
}

export interface StaticCasBlobRecord {
  readonly sha512: string;
  readonly size: number;
  readonly blobPath: string;
  readonly refs: readonly StaticCasBlobRef[];
}

export interface StaticCasShardDocument {
  readonly schema: 'awesome-os.cas-v11-shard.v1';
  readonly abiMagic: '0x33564742';
  readonly prefix: string;
  readonly blobCount: number;
  readonly totalBytes: number;
  readonly forwardBundleHash: string;
  readonly blobs: readonly StaticCasBlobRecord[];
}

export interface StaticCasShardSummary {
  readonly path: string;
  readonly blobCount: number;
  readonly totalBytes: number;
  readonly forwardBundleHash: string;
}

export interface StaticCasIndexDocument {
  readonly schema: 'awesome-os.cas-v11-static-index.v1';
  readonly abiMagic: '0x33564742';
  readonly casLayout: 'v11';
  readonly generatedAt: string;
  readonly sourceGeneratedAt: string | null;
  readonly forwardBundleHash: string;
  readonly totalRepos: number;
  readonly totalAssets: number;
  readonly uniqueBlobs: number;
  readonly rawTotalBytes: number;
  readonly uniqueTotalBytes: number;
  readonly savedBytes: number;
  readonly populatedShards: number;
  readonly shardBasePath: 'shards';
  readonly shards: Readonly<Record<string, StaticCasShardSummary>>;
}

export interface ExportStaticCasPagesOptions {
  readonly manifestPath?: string;
  readonly outDir?: string;
  readonly generatedAt?: string;
}

export interface ExportStaticCasPagesResult {
  readonly indexPath: string;
  readonly shardsDir: string;
  readonly index: StaticCasIndexDocument;
  readonly totalOutputBytes: number;
}

const SHA512_HEX_RE = /^[0-9a-f]{128}$/;

export function exportStaticCasPages(options?: ExportStaticCasPagesOptions): ExportStaticCasPagesResult {
  const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const manifestPath = resolve(options?.manifestPath ?? join(repoRoot, 'index', 'cas-v11-global-manifest.json'));
  const outDir = resolve(options?.outDir ?? join(repoRoot, 'dashboard', 'cas', 'v11'));
  const shardsDir = join(outDir, 'shards');

  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as GlobalCasManifest;
  const entries = Array.isArray(manifest.entries) ? manifest.entries : [];

  const repos = new Set<string>();
  let rawTotalBytes = 0;

  interface MutableBlob {
    readonly sha512: string;
    readonly size: number;
    readonly blobPath: string;
    readonly refs: StaticCasBlobRef[];
  }

  const bySha = new Map<string, MutableBlob>();

  for (const e of entries) {
    const size = typeof e.size === 'number' && Number.isFinite(e.size) ? Math.max(0, Math.trunc(e.size)) : 0;
    rawTotalBytes += size;
    if (typeof e.repo === 'string' && e.repo.length > 0) repos.add(e.repo);

    const sha = typeof e.sha512 === 'string' ? e.sha512.trim().toLowerCase() : '';
    if (!SHA512_HEX_RE.test(sha)) continue;

    const canonicalBlobPath = `v11/files/${sha.slice(0, 2)}/${sha}`;
    let blob = bySha.get(sha);
    if (!blob) {
      blob = {
        sha512: sha,
        size,
        blobPath: canonicalBlobPath,
        refs: [],
      };
      bySha.set(sha, blob);
    }

    blob.refs.push({
      id: String(e.id ?? `${e.repo ?? 'unknown'}@${e.tag ?? 'latest'}/${e.filename ?? sha}`),
      repo: String(e.repo ?? ''),
      tag: String(e.tag ?? ''),
      filename: String(e.filename ?? ''),
      target: String(e.target ?? 'any'),
      executable: Boolean(e.executable),
      downloadUrl: String(e.downloadUrl ?? ''),
    });
  }

  // Canonical UTF-8 byte order for all blobs and refs
  const sortedBlobs: StaticCasBlobRecord[] = [...bySha.values()]
    .sort((a, b) => comparePosixPaths(a.blobPath, b.blobPath))
    .map((b) => ({
      sha512: b.sha512,
      size: b.size,
      blobPath: b.blobPath,
      refs: [...b.refs].sort((a, bRef) => comparePosixPaths(a.id, bRef.id)),
    }));

  let uniqueTotalBytes = 0;
  const shardGroups = new Map<string, StaticCasBlobRecord[]>();
  for (const blob of sortedBlobs) {
    uniqueTotalBytes += blob.size;
    const prefix = blob.sha512.slice(0, 2);
    const list = shardGroups.get(prefix);
    if (list) list.push(blob);
    else shardGroups.set(prefix, [blob]);
  }

  const globalForwardBundleHash = computeForwardBundleHash(
    sortedBlobs.map((b) => ({
      path: b.blobPath,
      bytes: b.size,
      sha512: b.sha512,
    })),
  );

  mkdirSync(shardsDir, { recursive: true });
  if (existsSync(shardsDir)) {
    for (const existing of readdirSync(shardsDir)) {
      if (existing.endsWith('.json')) {
        rmSync(join(shardsDir, existing), { force: true });
      }
    }
  }

  const shardSummaries: Record<string, StaticCasShardSummary> = {};
  const sortedPrefixes = [...shardGroups.keys()].sort(comparePosixPaths);
  let totalOutputBytes = 0;

  for (const prefix of sortedPrefixes) {
    const blobs = shardGroups.get(prefix)!;
    const shardBytes = blobs.reduce((acc, b) => acc + b.size, 0);
    const shardForwardHash = computeForwardBundleHash(
      blobs.map((b) => ({
        path: b.blobPath,
        bytes: b.size,
        sha512: b.sha512,
      })),
    );
    const shardDoc: StaticCasShardDocument = {
      schema: 'awesome-os.cas-v11-shard.v1',
      abiMagic: '0x33564742',
      prefix,
      blobCount: blobs.length,
      totalBytes: shardBytes,
      forwardBundleHash: shardForwardHash,
      blobs,
    };
    const serialized = JSON.stringify(shardDoc) + '\n';
    writeFileSync(join(shardsDir, `${prefix}.json`), serialized, 'utf8');
    totalOutputBytes += Buffer.byteLength(serialized, 'utf8');

    shardSummaries[prefix] = {
      path: `shards/${prefix}.json`,
      blobCount: blobs.length,
      totalBytes: shardBytes,
      forwardBundleHash: shardForwardHash,
    };
  }

  const index: StaticCasIndexDocument = {
    schema: 'awesome-os.cas-v11-static-index.v1',
    abiMagic: '0x33564742',
    casLayout: 'v11',
    generatedAt: options?.generatedAt ?? new Date().toISOString(),
    sourceGeneratedAt: typeof manifest.generatedAt === 'string' ? manifest.generatedAt : null,
    forwardBundleHash: globalForwardBundleHash,
    totalRepos: manifest.totalRepos ?? repos.size,
    totalAssets: entries.length,
    uniqueBlobs: sortedBlobs.length,
    rawTotalBytes,
    uniqueTotalBytes,
    savedBytes: Math.max(0, rawTotalBytes - uniqueTotalBytes),
    populatedShards: sortedPrefixes.length,
    shardBasePath: 'shards',
    shards: shardSummaries,
  };

  const indexPath = join(outDir, 'index.json');
  const indexSerialized = JSON.stringify(index, null, 2) + '\n';
  writeFileSync(indexPath, indexSerialized, 'utf8');
  totalOutputBytes += Buffer.byteLength(indexSerialized, 'utf8');

  return {
    indexPath,
    shardsDir,
    index,
    totalOutputBytes,
  };
}

function parseCliArgs(argv: readonly string[]): ExportStaticCasPagesOptions {
  let manifestPath: string | undefined;
  let outDir: string | undefined;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--manifest' && argv[i + 1]) {
      manifestPath = argv[++i];
    } else if (arg === '--out-dir' && argv[i + 1]) {
      outDir = argv[++i];
    }
  }
  return { manifestPath, outDir };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const opts = parseCliArgs(process.argv.slice(2));
  const res = exportStaticCasPages(opts);
  console.log(
    `[STATIC-CAS-PAGES] Wrote ${res.indexPath} + ${res.index.populatedShards} shards ` +
      `(${res.index.uniqueBlobs} unique blobs / ${res.index.totalAssets} assets, ` +
      `output=${(res.totalOutputBytes / 1024).toFixed(1)} KB, ` +
      `forwardBundleHash=${res.index.forwardBundleHash.slice(0, 16)}…)`,
  );
}
