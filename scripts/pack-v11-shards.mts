#!/usr/bin/env node
/**
 * @file scripts/pack-v11-shards.mts
 * @description Runner-side v11 CAS shard packer — replaces monolithic .tar.zst releases
 * by splitting any app build directory into deduplicated SHA-512 blobs under
 * <out>/v11/files/<aa>/<sha512> + a deterministic <out>/v11-tree.json manifest
 * with a canonical `forwardBundleHash` (and optional `--emit-b8p` forward-hashed `.b8p` bundle).
 */

import { createHash } from 'node:crypto';
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  comparePosixPaths,
  computeForwardBundleHash,
  packForwardB8pBundle,
} from './b8p-forward-bundle.mts';

export interface V11TreeFileEntry {
  path: string;
  sha512: string;
  bytes: number;
  casPath: string;
}

export interface V11TreeB8pBundleMeta {
  file: string;
  bytes: number;
  forwardHash: string;
}

export interface V11TreeManifest {
  schema: 'awesome-os.v11-tree.v1';
  abiMagic: '0x33564742';
  casLayout: 'v11';
  appId: string;
  generatedAt: string;
  forwardBundleHash: string;
  totalFiles: number;
  uniqueBlobs: number;
  logicalBytes: number;
  uniqueBytes: number;
  savedBytes: number;
  b8pBundle?: V11TreeB8pBundleMeta;
  files: V11TreeFileEntry[];
}

export interface PackV11ShardsOptions {
  readonly emitB8p?: boolean;
}

function walk(dir: string, out: string[] = []): string[] {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, e.name);
    if (e.isDirectory()) walk(full, out);
    else if (e.isFile()) out.push(full);
  }
  return out;
}

export function packDirectoryToV11Shards(
  srcDir: string,
  outDir: string,
  appId: string,
  options?: PackV11ShardsOptions,
): V11TreeManifest {
  const srcRoot = resolve(srcDir);
  const outRoot = resolve(outDir);
  const files = walk(srcRoot);
  const entries: V11TreeFileEntry[] = [];
  const seen = new Set<string>();
  let logicalBytes = 0;
  let uniqueBytes = 0;

  for (const full of files) {
    const buf = readFileSync(full);
    const sha512 = createHash('sha512').update(buf).digest('hex');
    const rel = relative(srcRoot, full).replace(/\\/g, '/');
    const casRel = `v11/files/${sha512.slice(0, 2)}/${sha512}`;
    const casAbs = join(outRoot, casRel);
    const bytes = statSync(full).size;

    logicalBytes += bytes;
    if (!seen.has(sha512)) {
      seen.add(sha512);
      uniqueBytes += bytes;
      mkdirSync(join(outRoot, 'v11', 'files', sha512.slice(0, 2)), { recursive: true });
      if (!existsSync(casAbs)) copyFileSync(full, casAbs);
    }

    entries.push({ path: rel, sha512, bytes, casPath: casRel });
  }

  // Deterministic canonical UTF-8 byte-order sort so v11-tree.json is 100% deterministic
  entries.sort((a, b) => comparePosixPaths(a.path, b.path));

  const forwardBundleHash = computeForwardBundleHash(entries);

  let b8pBundle: V11TreeB8pBundleMeta | undefined;
  if (options?.emitB8p) {
    const b8pFile = `${appId}.b8p`;
    const packed = packForwardB8pBundle(srcRoot, join(outRoot, b8pFile), appId);
    b8pBundle = {
      file: b8pFile,
      bytes: packed.bundleBytes,
      forwardHash: packed.forwardHash,
    };
  }

  const manifest: V11TreeManifest = {
    schema: 'awesome-os.v11-tree.v1',
    abiMagic: '0x33564742',
    casLayout: 'v11',
    appId,
    generatedAt: new Date().toISOString(),
    forwardBundleHash,
    totalFiles: entries.length,
    uniqueBlobs: seen.size,
    logicalBytes,
    uniqueBytes,
    savedBytes: logicalBytes - uniqueBytes,
    ...(b8pBundle ? { b8pBundle } : {}),
    files: entries,
  };

  mkdirSync(outRoot, { recursive: true });
  writeFileSync(join(outRoot, 'v11-tree.json'), JSON.stringify(manifest, null, 2) + '\n', 'utf8');
  return manifest;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const rawArgs = process.argv.slice(2);
  const emitB8p = rawArgs.includes('--emit-b8p');
  const positional = rawArgs.filter((a) => a !== '--emit-b8p');
  const [src, out, appId = 'app'] = positional;
  if (!src || !out) {
    console.log('Usage: node scripts/pack-v11-shards.mts <src-dir> <out-dir> [app-id] [--emit-b8p]');
    process.exit(0);
  }
  const m = packDirectoryToV11Shards(src, out, appId, { emitB8p });
  console.log(
    `[v11-pack] ${m.appId}: ${m.totalFiles} files -> ${m.uniqueBlobs} unique blobs ` +
      `(saved ${(m.savedBytes / 1048576).toFixed(2)} MB, forwardHash=${m.forwardBundleHash.slice(0, 16)}…` +
      `${m.b8pBundle ? `, b8p=${m.b8pBundle.file} (${m.b8pBundle.bytes} B)` : ''})`,
  );
}
