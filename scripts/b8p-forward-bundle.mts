#!/usr/bin/env node
/**
 * @file scripts/b8p-forward-bundle.mts
 * @description Deterministic Forward-Hashed `.b8p` Bundler implementing the Hyperscaler
 * dual-layer CAS design:
 *   "Address by Leaf `v11/files/00..ff/<sha512>`, Transport by Deterministic `.b8p` Bundle"
 *
 * Binary layout (little-endian, 64-byte `B8G_ARENA_V1` mmap-ready alignment):
 *   - Fixed 64-byte header:
 *       [0..4)   magic:          "B8P1"
 *       [4..8)   abiMagic:       uint32LE = 0x33564742 (B8G_ABI_MAGIC_V3)
 *       [8..12)  version:        uint32LE = 1
 *       [12..16) flags:          uint32LE = 0
 *       [16..20) entryCount:     uint32LE
 *       [20..24) reserved:       uint32LE = 0
 *       [24..32) tableOffset:    uint64LE = 64
 *       [32..40) tableBytes:     uint64LE
 *       [40..48) payloadOffset:  uint64LE = align64(tableOffset + tableBytes)
 *       [48..56) totalBytes:     uint64LE
 *       [56..64) forwardHashPre: first 8 raw bytes of SHA-512 forwardHash
 *   - Canonical UTF-8 JSON entry table at [tableOffset, tableOffset + tableBytes)
 *   - Zero-filled padding to payloadOffset
 *   - Uncompressed per-entry payloads at 64-byte aligned offsets with zero-filled
 *     64-byte tail padding so any peer can read `[offset, offset + bytes)` at O(1).
 *
 * Strictly `erasableSyntaxOnly: true`, Node 24/26 built-ins only.
 */

import { createHash } from 'node:crypto';
import {
  closeSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  readSync,
  statSync,
  writeSync,
} from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export const B8P_MAGIC = 'B8P1';
export const B8G_ABI_MAGIC_V3 = 0x33564742;
export const B8P_VERSION = 1;
export const B8P_FLAGS = 0;
export const B8P_HEADER_SIZE = 64;
export const B8P_ALIGN = 64;

export interface ForwardHashInputEntry {
  readonly path: string;
  readonly sha512: string;
  readonly bytes?: number;
  readonly size?: number;
}

export interface B8pBundleEntry {
  readonly path: string;
  readonly sha512: string;
  readonly bytes: number;
  readonly offset: number;
  readonly alignedEnd: number;
  readonly casPath: string;
}

export interface B8pBundleHeader {
  readonly magic: string;
  readonly abiMagic: number;
  readonly version: number;
  readonly flags: number;
  readonly entryCount: number;
  readonly reserved: number;
  readonly tableOffset: number;
  readonly tableBytes: number;
  readonly payloadOffset: number;
  readonly totalBytes: number;
  readonly forwardHashPrefixHex: string;
}

export interface B8pBundleTable {
  readonly schema: 'awesome-os.b8p-forward-bundle.v1';
  readonly abiMagic: '0x33564742';
  readonly version: 1;
  readonly appId: string;
  readonly forwardHash: string;
  readonly entryCount: number;
  readonly payloadOffset: number;
  readonly entries: readonly B8pBundleEntry[];
}

export interface PackForwardB8pResult {
  readonly forwardHash: string;
  readonly bundleBytes: number;
  readonly entryCount: number;
  readonly entries: readonly B8pBundleEntry[];
}

export interface B8pBundleIndex {
  readonly header: B8pBundleHeader;
  readonly appId: string;
  readonly forwardHash: string;
  readonly entryCount: number;
  readonly bundleBytes: number;
  readonly entries: readonly B8pBundleEntry[];
}

export interface VerifyB8pBundleResult {
  readonly ok: boolean;
  readonly forwardHash: string | null;
  readonly entryCount: number;
  readonly bundleBytes: number;
  readonly errors: readonly string[];
}

export interface ExtractedB8pEntry {
  readonly entry: B8pBundleEntry;
  readonly data: Buffer;
  readonly bytesRead: number;
  readonly sha512: string;
}

export function align64(n: number): number {
  if (!Number.isSafeInteger(n) || n < 0) {
    throw new RangeError(`align64 requires a non-negative safe integer, got ${n}`);
  }
  const rem = n % B8P_ALIGN;
  return rem === 0 ? n : n + (B8P_ALIGN - rem);
}

export function normalizePosixPath(p: string): string {
  return p.replace(/\\/g, '/').replace(/^\/+/, '');
}

/**
 * Locale-independent canonical UTF-8 byte-order comparator for POSIX paths.
 */
export function comparePosixPaths(a: string, b: string): number {
  return Buffer.compare(Buffer.from(normalizePosixPath(a), 'utf8'), Buffer.from(normalizePosixPath(b), 'utf8'));
}

/**
 * Computes the deterministic Forward Hash purely from entry metadata (before downloading payload bytes):
 *   SHA512("B8P1\0" || uint32LE(0x33564742) || sorted [(uint32LE(len(path)), path, uint64LE(size), leafSha512)])
 */
export function computeForwardBundleHash(entries: readonly ForwardHashInputEntry[]): string {
  const normalized = entries.map((e) => {
    const posixPath = normalizePosixPath(e.path);
    const size = typeof e.bytes === 'number' ? e.bytes : typeof e.size === 'number' ? e.size : 0;
    if (!Number.isSafeInteger(size) || size < 0) {
      throw new RangeError(`Invalid entry byte size for "${posixPath}": ${size}`);
    }
    const sha512 = e.sha512.trim().toLowerCase();
    return { path: posixPath, size, sha512 };
  });

  normalized.sort((a, b) => {
    const cmp = Buffer.compare(Buffer.from(a.path, 'utf8'), Buffer.from(b.path, 'utf8'));
    if (cmp !== 0) return cmp;
    return Buffer.compare(Buffer.from(a.sha512, 'utf8'), Buffer.from(b.sha512, 'utf8'));
  });

  const hash = createHash('sha512');
  hash.update(Buffer.from(`${B8P_MAGIC}\0`, 'ascii'));

  const abiBuf = Buffer.alloc(4);
  abiBuf.writeUInt32LE(B8G_ABI_MAGIC_V3, 0);
  hash.update(abiBuf);

  const lenBuf = Buffer.alloc(4);
  const sizeBuf = Buffer.alloc(8);
  const nulBuf = Buffer.from([0]);

  for (const entry of normalized) {
    const pathBuf = Buffer.from(entry.path, 'utf8');
    lenBuf.writeUInt32LE(pathBuf.length, 0);
    sizeBuf.writeBigUInt64LE(BigInt(entry.size), 0);
    hash.update(lenBuf);
    hash.update(pathBuf);
    hash.update(sizeBuf);
    hash.update(Buffer.from(entry.sha512, 'utf8'));
    hash.update(nulBuf);
  }

  return hash.digest('hex');
}

function walkFilesCanonical(rootDir: string): string[] {
  const relPaths: string[] = [];
  const visit = (dir: string): void => {
    const dirents = readdirSync(dir, { withFileTypes: true });
    for (const d of dirents) {
      const full = join(dir, d.name);
      if (d.isDirectory()) {
        visit(full);
      } else if (d.isFile()) {
        relPaths.push(normalizePosixPath(relative(rootDir, full)));
      }
    }
  };
  visit(rootDir);
  relPaths.sort(comparePosixPaths);
  return relPaths;
}

function encodeHeader(header: B8pBundleHeader): Buffer {
  const buf = Buffer.alloc(B8P_HEADER_SIZE);
  buf.write(header.magic, 0, 4, 'ascii');
  buf.writeUInt32LE(header.abiMagic >>> 0, 4);
  buf.writeUInt32LE(header.version >>> 0, 8);
  buf.writeUInt32LE(header.flags >>> 0, 12);
  buf.writeUInt32LE(header.entryCount >>> 0, 16);
  buf.writeUInt32LE(header.reserved >>> 0, 20);
  buf.writeBigUInt64LE(BigInt(header.tableOffset), 24);
  buf.writeBigUInt64LE(BigInt(header.tableBytes), 32);
  buf.writeBigUInt64LE(BigInt(header.payloadOffset), 40);
  buf.writeBigUInt64LE(BigInt(header.totalBytes), 48);
  const prefix = Buffer.from(header.forwardHashPrefixHex.slice(0, 16), 'hex');
  prefix.copy(buf, 56, 0, Math.min(8, prefix.length));
  return buf;
}

function decodeHeader(buf: Buffer): B8pBundleHeader {
  if (buf.length < B8P_HEADER_SIZE) {
    throw new Error(`Invalid .b8p header: expected ${B8P_HEADER_SIZE} bytes, got ${buf.length}`);
  }
  return {
    magic: buf.subarray(0, 4).toString('ascii'),
    abiMagic: buf.readUInt32LE(4),
    version: buf.readUInt32LE(8),
    flags: buf.readUInt32LE(12),
    entryCount: buf.readUInt32LE(16),
    reserved: buf.readUInt32LE(20),
    tableOffset: Number(buf.readBigUInt64LE(24)),
    tableBytes: Number(buf.readBigUInt64LE(32)),
    payloadOffset: Number(buf.readBigUInt64LE(40)),
    totalBytes: Number(buf.readBigUInt64LE(48)),
    forwardHashPrefixHex: buf.subarray(56, 64).toString('hex'),
  };
}

function readExactSync(fd: number, target: Buffer, length: number, position: number): number {
  let totalRead = 0;
  while (totalRead < length) {
    const n = readSync(fd, target, totalRead, length - totalRead, position + totalRead);
    if (n <= 0) break;
    totalRead += n;
  }
  return totalRead;
}

/**
 * Packs `srcDir` into a deterministic, 64-byte aligned, forward-hashed `.b8p` bundle.
 * Identical file contents + POSIX paths produce bit-for-bit identical output regardless
 * of filesystem walk order, mtime, uid, or gid.
 */
export function packForwardB8pBundle(
  srcDir: string,
  outBundlePath: string,
  appId: string,
): PackForwardB8pResult {
  const srcRoot = resolve(srcDir);
  const outAbs = resolve(outBundlePath);
  const relPaths = walkFilesCanonical(srcRoot);

  interface StagedEntry {
    readonly path: string;
    readonly sha512: string;
    readonly bytes: number;
    readonly casPath: string;
    readonly data: Buffer;
  }

  const staged: StagedEntry[] = [];
  for (const relPath of relPaths) {
    const data = readFileSync(join(srcRoot, relPath));
    const sha512 = createHash('sha512').update(data).digest('hex');
    staged.push({
      path: relPath,
      sha512,
      bytes: data.length,
      casPath: `v11/files/${sha512.slice(0, 2)}/${sha512}`,
      data,
    });
  }

  const forwardHash = computeForwardBundleHash(staged);

  const buildTableBytes = (payloadOffset: number): { readonly entries: B8pBundleEntry[]; readonly tableBuf: Buffer; readonly totalBytes: number } => {
    const entries: B8pBundleEntry[] = [];
    let cursor = payloadOffset;
    for (const s of staged) {
      const offset = cursor;
      const alignedEnd = align64(offset + s.bytes);
      entries.push({
        path: s.path,
        sha512: s.sha512,
        bytes: s.bytes,
        offset,
        alignedEnd,
        casPath: s.casPath,
      });
      cursor = alignedEnd;
    }
    const table: B8pBundleTable = {
      schema: 'awesome-os.b8p-forward-bundle.v1',
      abiMagic: '0x33564742',
      version: 1,
      appId,
      forwardHash,
      entryCount: entries.length,
      payloadOffset,
      entries,
    };
    const tableBuf = Buffer.from(JSON.stringify(table), 'utf8');
    return { entries, tableBuf, totalBytes: cursor };
  };

  // Fixed-point convergence for payloadOffset (since offset digits affect tableBuf length)
  let payloadOffset = B8P_HEADER_SIZE;
  let finalLayout = buildTableBytes(payloadOffset);
  for (let i = 0; i < 8; i++) {
    const neededPayloadOffset = align64(B8P_HEADER_SIZE + finalLayout.tableBuf.length);
    if (neededPayloadOffset === payloadOffset) break;
    payloadOffset = neededPayloadOffset;
    finalLayout = buildTableBytes(payloadOffset);
  }
  const requiredPayloadOffset = align64(B8P_HEADER_SIZE + finalLayout.tableBuf.length);
  if (requiredPayloadOffset > payloadOffset) {
    payloadOffset = requiredPayloadOffset;
    finalLayout = buildTableBytes(payloadOffset);
  }

  const headerBuf = encodeHeader({
    magic: B8P_MAGIC,
    abiMagic: B8G_ABI_MAGIC_V3,
    version: B8P_VERSION,
    flags: B8P_FLAGS,
    entryCount: finalLayout.entries.length,
    reserved: 0,
    tableOffset: B8P_HEADER_SIZE,
    tableBytes: finalLayout.tableBuf.length,
    payloadOffset,
    totalBytes: finalLayout.totalBytes,
    forwardHashPrefixHex: forwardHash.slice(0, 16),
  });

  mkdirSync(dirname(outAbs), { recursive: true });
  const fd = openSync(outAbs, 'w');
  try {
    writeSync(fd, headerBuf);
    writeSync(fd, finalLayout.tableBuf);

    const tablePad = payloadOffset - (B8P_HEADER_SIZE + finalLayout.tableBuf.length);
    if (tablePad > 0) {
      writeSync(fd, Buffer.alloc(tablePad));
    }

    for (let i = 0; i < staged.length; i++) {
      const s = staged[i]!;
      const e = finalLayout.entries[i]!;
      if (s.bytes > 0) {
        writeSync(fd, s.data);
      }
      const pad = e.alignedEnd - (e.offset + e.bytes);
      if (pad > 0) {
        writeSync(fd, Buffer.alloc(pad));
      }
    }
  } finally {
    closeSync(fd);
  }

  return {
    forwardHash,
    bundleBytes: finalLayout.totalBytes,
    entryCount: finalLayout.entries.length,
    entries: finalLayout.entries,
  };
}

/**
 * Parses ONLY the 64-byte header + entry table from a `.b8p` bundle without reading payload bytes.
 */
export function readB8pBundleIndex(bundlePath: string): B8pBundleIndex {
  const abs = resolve(bundlePath);
  const st = statSync(abs);
  if (st.size < B8P_HEADER_SIZE) {
    throw new Error(`Invalid .b8p bundle: file size ${st.size} is smaller than ${B8P_HEADER_SIZE}-byte header`);
  }

  const fd = openSync(abs, 'r');
  try {
    const headerBuf = Buffer.alloc(B8P_HEADER_SIZE);
    const hdrRead = readExactSync(fd, headerBuf, B8P_HEADER_SIZE, 0);
    if (hdrRead !== B8P_HEADER_SIZE) {
      throw new Error(`Short read on .b8p header: expected ${B8P_HEADER_SIZE}, got ${hdrRead}`);
    }
    const header = decodeHeader(headerBuf);
    if (header.magic !== B8P_MAGIC) {
      throw new Error(`Invalid .b8p magic: expected "${B8P_MAGIC}", got "${header.magic}"`);
    }
    if (header.abiMagic !== B8G_ABI_MAGIC_V3) {
      throw new Error(
        `Invalid B8G ABI magic: expected 0x${B8G_ABI_MAGIC_V3.toString(16)}, got 0x${header.abiMagic.toString(16)}`,
      );
    }
    if (header.version !== B8P_VERSION) {
      throw new Error(`Unsupported .b8p version: expected ${B8P_VERSION}, got ${header.version}`);
    }
    if (header.tableOffset !== B8P_HEADER_SIZE) {
      throw new Error(`Invalid .b8p tableOffset: expected ${B8P_HEADER_SIZE}, got ${header.tableOffset}`);
    }
    if (header.tableOffset + header.tableBytes > st.size || header.tableOffset + header.tableBytes > header.payloadOffset) {
      throw new Error(`Invalid .b8p table bounds: offset=${header.tableOffset}, bytes=${header.tableBytes}, payloadOffset=${header.payloadOffset}, size=${st.size}`);
    }

    const tableBuf = Buffer.alloc(header.tableBytes);
    const tblRead = readExactSync(fd, tableBuf, header.tableBytes, header.tableOffset);
    if (tblRead !== header.tableBytes) {
      throw new Error(`Short read on .b8p table: expected ${header.tableBytes}, got ${tblRead}`);
    }

    const table = JSON.parse(tableBuf.toString('utf8')) as B8pBundleTable;
    return {
      header,
      appId: table.appId,
      forwardHash: table.forwardHash,
      entryCount: header.entryCount,
      bundleBytes: st.size,
      entries: table.entries,
    };
  } finally {
    closeSync(fd);
  }
}

function isAllZero(buf: Buffer): boolean {
  for (let i = 0; i < buf.length; i++) {
    if (buf[i] !== 0) return false;
  }
  return true;
}

/**
 * Verifies magic, ABI magic `0x33564742`, header invariants, 64-byte alignment of every
 * entry offset, every leaf SHA-512 payload slice, and recomputes `forwardHash` bit-for-bit.
 */
export function verifyB8pBundle(bundlePath: string): VerifyB8pBundleResult {
  const abs = resolve(bundlePath);
  const errors: string[] = [];

  let fileSize = 0;
  try {
    fileSize = statSync(abs).size;
  } catch (err) {
    return {
      ok: false,
      forwardHash: null,
      entryCount: 0,
      bundleBytes: 0,
      errors: [`Cannot stat bundle: ${err instanceof Error ? err.message : String(err)}`],
    };
  }

  if (fileSize < B8P_HEADER_SIZE) {
    return {
      ok: false,
      forwardHash: null,
      entryCount: 0,
      bundleBytes: fileSize,
      errors: [`Bundle too small (${fileSize} bytes < ${B8P_HEADER_SIZE} header)`],
    };
  }

  const fd = openSync(abs, 'r');
  try {
    const headerBuf = Buffer.alloc(B8P_HEADER_SIZE);
    if (readExactSync(fd, headerBuf, B8P_HEADER_SIZE, 0) !== B8P_HEADER_SIZE) {
      return { ok: false, forwardHash: null, entryCount: 0, bundleBytes: fileSize, errors: ['Short header read'] };
    }
    const header = decodeHeader(headerBuf);

    if (header.magic !== B8P_MAGIC) errors.push(`Invalid magic "${header.magic}" (expected "${B8P_MAGIC}")`);
    if (header.abiMagic !== B8G_ABI_MAGIC_V3) {
      errors.push(`Invalid abiMagic 0x${header.abiMagic.toString(16)} (expected 0x${B8G_ABI_MAGIC_V3.toString(16)})`);
    }
    if (header.version !== B8P_VERSION) errors.push(`Invalid version ${header.version} (expected ${B8P_VERSION})`);
    if (header.flags !== B8P_FLAGS) errors.push(`Unexpected flags ${header.flags} (expected ${B8P_FLAGS})`);
    if (header.reserved !== 0) errors.push(`Non-zero reserved header field: ${header.reserved}`);
    if (header.tableOffset !== B8P_HEADER_SIZE) {
      errors.push(`Invalid tableOffset ${header.tableOffset} (expected ${B8P_HEADER_SIZE})`);
    }
    if (header.payloadOffset % B8P_ALIGN !== 0) {
      errors.push(`payloadOffset ${header.payloadOffset} is not ${B8P_ALIGN}-byte aligned`);
    }
    if (header.payloadOffset < align64(header.tableOffset + header.tableBytes)) {
      errors.push(`payloadOffset ${header.payloadOffset} overlaps entry table`);
    }
    if (header.totalBytes !== fileSize) {
      errors.push(`Header totalBytes ${header.totalBytes} does not match file size ${fileSize}`);
    }

    if (errors.length > 0 || header.tableOffset + header.tableBytes > fileSize) {
      if (header.tableOffset + header.tableBytes > fileSize) {
        errors.push(`Entry table exceeds file size (${fileSize})`);
      }
      return {
        ok: false,
        forwardHash: null,
        entryCount: header.entryCount,
        bundleBytes: fileSize,
        errors,
      };
    }

    const tableBuf = Buffer.alloc(header.tableBytes);
    readExactSync(fd, tableBuf, header.tableBytes, header.tableOffset);

    let table: B8pBundleTable;
    try {
      table = JSON.parse(tableBuf.toString('utf8')) as B8pBundleTable;
    } catch (err) {
      return {
        ok: false,
        forwardHash: null,
        entryCount: header.entryCount,
        bundleBytes: fileSize,
        errors: [`Corrupt JSON entry table: ${err instanceof Error ? err.message : String(err)}`],
      };
    }

    // Verify table->payload zero padding
    const tablePadLen = header.payloadOffset - (header.tableOffset + header.tableBytes);
    if (tablePadLen > 0) {
      const padBuf = Buffer.alloc(tablePadLen);
      readExactSync(fd, padBuf, tablePadLen, header.tableOffset + header.tableBytes);
      if (!isAllZero(padBuf)) {
        errors.push('Non-zero padding between table and payloadOffset');
      }
    }

    if (!Array.isArray(table.entries)) {
      errors.push('Table missing entries array');
      return { ok: false, forwardHash: null, entryCount: header.entryCount, bundleBytes: fileSize, errors };
    }
    if (table.entries.length !== header.entryCount) {
      errors.push(`Header entryCount ${header.entryCount} != table entries length ${table.entries.length}`);
    }
    if (table.payloadOffset !== header.payloadOffset) {
      errors.push(`Table payloadOffset ${table.payloadOffset} != header payloadOffset ${header.payloadOffset}`);
    }

    let prevPath: string | null = null;
    let expectedOffset = header.payloadOffset;

    for (const entry of table.entries) {
      if (prevPath !== null) {
        const cmp = comparePosixPaths(prevPath, entry.path);
        if (cmp >= 0) {
          errors.push(`Entries out of canonical UTF-8 order: "${prevPath}" before "${entry.path}"`);
        }
      }
      prevPath = entry.path;

      if (entry.offset % B8P_ALIGN !== 0) {
        errors.push(`Entry "${entry.path}" offset ${entry.offset} is not ${B8P_ALIGN}-byte aligned`);
      }
      if (entry.offset < header.payloadOffset || entry.offset < expectedOffset) {
        errors.push(`Entry "${entry.path}" offset ${entry.offset} overlaps previous data (expected >= ${expectedOffset})`);
      }
      const expectedAlignedEnd = align64(entry.offset + entry.bytes);
      if (entry.alignedEnd !== expectedAlignedEnd) {
        errors.push(`Entry "${entry.path}" alignedEnd ${entry.alignedEnd} != expected ${expectedAlignedEnd}`);
      }
      if (entry.alignedEnd > fileSize) {
        errors.push(`Entry "${entry.path}" exceeds bundle EOF (${entry.alignedEnd} > ${fileSize})`);
        continue;
      }

      const expectedCasPath = `v11/files/${entry.sha512.slice(0, 2)}/${entry.sha512}`;
      if (entry.casPath !== expectedCasPath) {
        errors.push(`Entry "${entry.path}" casPath mismatch: "${entry.casPath}" != "${expectedCasPath}"`);
      }

      const payload = Buffer.alloc(entry.bytes);
      if (entry.bytes > 0) {
        const readN = readExactSync(fd, payload, entry.bytes, entry.offset);
        if (readN !== entry.bytes) {
          errors.push(`Short read on entry "${entry.path}": expected ${entry.bytes}, got ${readN}`);
          continue;
        }
      }
      const actualSha = createHash('sha512').update(payload).digest('hex');
      if (actualSha !== entry.sha512) {
        errors.push(`Leaf SHA-512 mismatch for "${entry.path}": expected ${entry.sha512}, got ${actualSha}`);
      }

      const tailPadLen = entry.alignedEnd - (entry.offset + entry.bytes);
      if (tailPadLen > 0) {
        const padBuf = Buffer.alloc(tailPadLen);
        readExactSync(fd, padBuf, tailPadLen, entry.offset + entry.bytes);
        if (!isAllZero(padBuf)) {
          errors.push(`Non-zero alignment padding after "${entry.path}"`);
        }
      }

      expectedOffset = entry.alignedEnd;
    }

    const recomputedForwardHash = computeForwardBundleHash(table.entries);
    if (recomputedForwardHash !== table.forwardHash) {
      errors.push(`ForwardHash mismatch: table=${table.forwardHash}, recomputed=${recomputedForwardHash}`);
    }
    if (recomputedForwardHash.slice(0, 16) !== header.forwardHashPrefixHex) {
      errors.push(
        `Header forwardHash prefix mismatch: header=${header.forwardHashPrefixHex}, expected=${recomputedForwardHash.slice(0, 16)}`,
      );
    }

    return {
      ok: errors.length === 0,
      forwardHash: recomputedForwardHash,
      entryCount: table.entries.length,
      bundleBytes: fileSize,
      errors,
    };
  } finally {
    closeSync(fd);
  }
}

function findEntryBinarySearch(entries: readonly B8pBundleEntry[], targetPath: string): B8pBundleEntry | null {
  const normTarget = normalizePosixPath(targetPath);
  let lo = 0;
  let hi = entries.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    const cur = entries[mid]!;
    const cmp = comparePosixPaths(cur.path, normTarget);
    if (cmp === 0) return cur;
    if (cmp < 0) lo = mid + 1;
    else hi = mid - 1;
  }
  return null;
}

/**
 * Extracts a single entry directly via O(1) byte-range read `[offset, offset + bytes)`
 * without scanning the rest of the bundle, and validates its leaf SHA-512 digest.
 */
export function extractEntryByRange(bundlePath: string, entryPath: string): ExtractedB8pEntry {
  const index = readB8pBundleIndex(bundlePath);
  const entry = findEntryBinarySearch(index.entries, entryPath);
  if (!entry) {
    throw new Error(`Entry "${normalizePosixPath(entryPath)}" not found in ${bundlePath}`);
  }
  if (entry.offset % B8P_ALIGN !== 0) {
    throw new Error(`Entry "${entry.path}" offset ${entry.offset} is not ${B8P_ALIGN}-byte aligned`);
  }

  const fd = openSync(resolve(bundlePath), 'r');
  try {
    const data = Buffer.alloc(entry.bytes);
    const bytesRead = entry.bytes > 0 ? readExactSync(fd, data, entry.bytes, entry.offset) : 0;
    if (bytesRead !== entry.bytes) {
      throw new Error(`Short range read for "${entry.path}": expected ${entry.bytes}, got ${bytesRead}`);
    }
    const sha512 = createHash('sha512').update(data).digest('hex');
    if (sha512 !== entry.sha512) {
      throw new Error(`Leaf SHA-512 verification failed for "${entry.path}": expected ${entry.sha512}, got ${sha512}`);
    }
    return { entry, data, bytesRead, sha512 };
  } finally {
    closeSync(fd);
  }
}

function runCli(): void {
  const [cmd, ...args] = process.argv.slice(2);
  if (!cmd || cmd === '--help' || cmd === '-h') {
    console.log(
      [
        'Usage:',
        '  node scripts/b8p-forward-bundle.mts pack <src-dir> <out.b8p> [app-id]',
        '  node scripts/b8p-forward-bundle.mts verify <bundle.b8p>',
        '  node scripts/b8p-forward-bundle.mts inspect <bundle.b8p>',
        '  node scripts/b8p-forward-bundle.mts extract <bundle.b8p> <entry-path>',
      ].join('\n'),
    );
    return;
  }

  if (cmd === 'pack') {
    const [srcDir, outBundle, appId = 'app'] = args;
    if (!srcDir || !outBundle) {
      console.error('Missing <src-dir> or <out.b8p>');
      process.exit(1);
    }
    const res = packForwardB8pBundle(srcDir, outBundle, appId);
    console.log(JSON.stringify({ appId, forwardHash: res.forwardHash, bundleBytes: res.bundleBytes, entryCount: res.entryCount }, null, 2));
    return;
  }

  if (cmd === 'verify') {
    const [bundlePath] = args;
    if (!bundlePath) {
      console.error('Missing <bundle.b8p>');
      process.exit(1);
    }
    const res = verifyB8pBundle(bundlePath);
    console.log(JSON.stringify(res, null, 2));
    if (!res.ok) process.exit(1);
    return;
  }

  if (cmd === 'inspect') {
    const [bundlePath] = args;
    if (!bundlePath) {
      console.error('Missing <bundle.b8p>');
      process.exit(1);
    }
    const idx = readB8pBundleIndex(bundlePath);
    console.log(JSON.stringify(idx, null, 2));
    return;
  }

  if (cmd === 'extract') {
    const [bundlePath, entryPath] = args;
    if (!bundlePath || !entryPath) {
      console.error('Missing <bundle.b8p> or <entry-path>');
      process.exit(1);
    }
    const extracted = extractEntryByRange(bundlePath, entryPath);
    process.stdout.write(extracted.data);
    return;
  }

  console.error(`Unknown subcommand: ${cmd}`);
  process.exit(1);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  runCli();
}
