#!/usr/bin/env node
/**
 * @file scripts/holo-cas-dedup.mts
 * @description Fast, safe v11 CAS Deduplicator & Tar-Monolith Analyzer.
 * Default mode is strictly READ-ONLY (--dry-run): reports exact duplicate bytes,
 * monolithic .tar* archives, and top reclaimable files across any CAS root.
 * Pass --apply to atomically hardlink duplicates into v11/files/<aa>/<sha512>.
 */

import { createHash } from 'node:crypto';
import {
  copyFileSync,
  existsSync,
  linkSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { join, relative, resolve } from 'node:path';

interface FileRec {
  path: string;
  size: number;
  ino: number;
  dev: number;
}

function walkFiles(dir: string, out: FileRec[] = []): FileRec[] {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    const full = join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name === 'v11') continue;
      walkFiles(full, out);
    } else if (e.isFile()) {
      try {
        const st = statSync(full);
        out.push({ path: full, size: st.size, ino: st.ino, dev: st.dev });
      } catch {
        // skip unreadable
      }
    }
  }
  return out;
}

function sha512File(path: string): string {
  return createHash('sha512').update(readFileSync(path)).digest('hex');
}

const args = process.argv.slice(2);
const apply = args.includes('--apply');
const dirIdx = args.indexOf('--dir');
const casRoot = resolve(dirIdx !== -1 && args[dirIdx + 1] ? args[dirIdx + 1] : join(homedir(), '.b8g', 'cas'));

if (!existsSync(casRoot)) {
  console.error(`CAS root not found: ${casRoot}`);
  process.exit(1);
}

const t0 = performance.now();
const files = walkFiles(casRoot);

let totalLogicalBytes = 0;
let archiveBytes = 0;
const archives: Array<{ rel: string; mb: number }> = [];
const bySize = new Map<number, FileRec[]>();

for (const f of files) {
  totalLogicalBytes += f.size;
  if (/\.(tar|tar\.zst|tar\.gz|tgz|tar\.xz|zip|7z)$/i.test(f.path)) {
    archiveBytes += f.size;
    archives.push({ rel: relative(casRoot, f.path), mb: Number((f.size / 1048576).toFixed(2)) });
  }
  if (f.size > 0) {
    const arr = bySize.get(f.size) ?? [];
    arr.push(f);
    bySize.set(f.size, arr);
  }
}

let reclaimableDuplicateBytes = 0;
let duplicateFileCount = 0;
let hardlinkedCount = 0;
const topDupes: Array<{ name: string; copies: number; savedMb: number; sha12: string }> = [];

for (const [size, group] of bySize.entries()) {
  if (group.length < 2) continue;
  const byHash = new Map<string, FileRec[]>();
  for (const rec of group) {
    const h = sha512File(rec.path);
    const arr = byHash.get(h) ?? [];
    arr.push(rec);
    byHash.set(h, arr);
  }
  for (const [sha512, matches] of byHash.entries()) {
    if (matches.length < 2) continue;
    // Count distinct physical inodes (already-hardlinked copies share dev+ino)
    const uniqueInodes = new Set(matches.map((m) => `${m.dev}:${m.ino}`));
    const extraCopies = uniqueInodes.size - 1;
    if (extraCopies <= 0) continue;

    const saved = extraCopies * size;
    reclaimableDuplicateBytes += saved;
    duplicateFileCount += extraCopies;
    topDupes.push({
      name: relative(casRoot, matches[0].path),
      copies: uniqueInodes.size,
      savedMb: Number((saved / 1048576).toFixed(2)),
      sha12: sha512.slice(0, 12),
    });

    if (apply) {
      const shardDir = join(casRoot, 'v11', 'files', sha512.slice(0, 2));
      mkdirSync(shardDir, { recursive: true });
      const casBlob = join(shardDir, sha512);
      if (!existsSync(casBlob)) {
        try {
          linkSync(matches[0].path, casBlob);
        } catch {
          copyFileSync(matches[0].path, casBlob);
        }
      }
      for (const m of matches) {
        const tmpLink = `${m.path}.v11tmp`;
        try {
          if (existsSync(tmpLink)) unlinkSync(tmpLink);
          linkSync(casBlob, tmpLink);
          renameSync(tmpLink, m.path);
          hardlinkedCount++;
        } catch {
          if (existsSync(tmpLink)) unlinkSync(tmpLink);
        }
      }
    }
  }
}

topDupes.sort((a, b) => b.savedMb - a.savedMb);
archives.sort((a, b) => b.mb - a.mb);

const ms = (performance.now() - t0).toFixed(0);
console.log(`\n=== HOLO v11 CAS DEDUP REPORT (${apply ? 'APPLIED' : 'DRY-RUN'}) ===`);
console.log(`CAS Root:             ${casRoot}`);
console.log(`Files Scanned:        ${files.length} (${(totalLogicalBytes / 1048576).toFixed(2)} MB) in ${ms} ms`);
console.log(`Exact Duplicates:     ${duplicateFileCount} extra copies -> ${(reclaimableDuplicateBytes / 1048576).toFixed(2)} MB immediately reclaimable via v11 hardlinks`);
console.log(`Monolithic Archives:  ${archives.length} archive files -> ${(archiveBytes / 1048576).toFixed(2)} MB (.tar*/.zip)`);
if (apply) {
  console.log(`Hardlinked into v11:  ${hardlinkedCount} files projected from cas/v11/files/<aa>/<sha512>`);
}

if (archives.length > 0) {
  console.log('\nTop Monolithic Archives (.tar*/.zip):');
  for (const a of archives.slice(0, 10)) {
    console.log(`  ${String(a.mb).padStart(8)} MB  ${a.rel}`);
  }
}

if (topDupes.length > 0) {
  console.log('\nTop 10 Reclaimable Duplicate Files:');
  for (const d of topDupes.slice(0, 10)) {
    console.log(`  ${String(d.savedMb).padStart(8)} MB  (${d.copies}x)  [${d.sha12}]  ${d.name}`);
  }
}
