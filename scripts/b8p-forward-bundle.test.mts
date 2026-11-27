import test from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  utimesSync,
  writeFileSync,
  existsSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  B8G_ABI_MAGIC_V3,
  B8P_ALIGN,
  B8P_HEADER_SIZE,
  B8P_MAGIC,
  computeForwardBundleHash,
  extractEntryByRange,
  packForwardB8pBundle,
  readB8pBundleIndex,
  verifyB8pBundle,
} from './b8p-forward-bundle.mts';
import { packDirectoryToV11Shards } from './pack-v11-shards.mts';

function withTempDir(fn: (dir: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), 'holo-v11-b8p-'));
  try {
    fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('packForwardB8pBundle is bit-for-bit deterministic across walk order and mtimes', () => {
  withTempDir((root) => {
    const dirA = join(root, 'tree-a');
    const dirB = join(root, 'tree-b');

    // Create files in order 1 with timestamps from 2021
    mkdirSync(join(dirA, 'bin'), { recursive: true });
    mkdirSync(join(dirA, 'assets', 'nested'), { recursive: true });
    writeFileSync(join(dirA, 'z-last.txt'), 'zeta payload\n');
    writeFileSync(join(dirA, 'bin', 'app.wasm'), Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]));
    writeFileSync(join(dirA, 'assets', 'nested', 'empty.dat'), Buffer.alloc(0));
    writeFileSync(join(dirA, 'a-first.json'), '{"hello":"world"}\n');
    utimesSync(join(dirA, 'z-last.txt'), new Date('2021-01-01T00:00:00Z'), new Date('2021-01-01T00:00:00Z'));
    utimesSync(join(dirA, 'a-first.json'), new Date('2021-05-05T12:00:00Z'), new Date('2021-05-05T12:00:00Z'));

    // Create identical files in reverse order with timestamps from 2026
    mkdirSync(join(dirB, 'assets', 'nested'), { recursive: true });
    mkdirSync(join(dirB, 'bin'), { recursive: true });
    writeFileSync(join(dirB, 'a-first.json'), '{"hello":"world"}\n');
    writeFileSync(join(dirB, 'assets', 'nested', 'empty.dat'), Buffer.alloc(0));
    writeFileSync(join(dirB, 'bin', 'app.wasm'), Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]));
    writeFileSync(join(dirB, 'z-last.txt'), 'zeta payload\n');
    utimesSync(join(dirB, 'z-last.txt'), new Date('2026-11-27T09:00:00Z'), new Date('2026-11-27T09:00:00Z'));
    utimesSync(join(dirB, 'a-first.json'), new Date('2026-11-27T09:00:00Z'), new Date('2026-11-27T09:00:00Z'));

    const bundleA = join(root, 'a.b8p');
    const bundleB = join(root, 'b.b8p');
    const resA = packForwardB8pBundle(dirA, bundleA, 'sectium-test');
    const resB = packForwardB8pBundle(dirB, bundleB, 'sectium-test');

    assert.equal(resA.forwardHash, resB.forwardHash);
    assert.equal(resA.forwardHash.length, 128);
    assert.equal(resA.bundleBytes, resB.bundleBytes);
    assert.equal(resA.entryCount, 4);
    assert.deepEqual(resA.entries, resB.entries);
    assert.equal(Buffer.compare(readFileSync(bundleA), readFileSync(bundleB)), 0);

    // Forward hash computed from shuffled entries matches packed forwardHash
    const shuffled = [...resA.entries].reverse();
    assert.equal(computeForwardBundleHash(shuffled), resA.forwardHash);
  });
});

test('every entry offset is 64-byte aligned and index parses without reading payload', () => {
  withTempDir((root) => {
    const src = join(root, 'src');
    mkdirSync(src, { recursive: true });
    writeFileSync(join(src, '01-one-byte.bin'), Buffer.from([0x42]));
    writeFileSync(join(src, '02-sixty-four.bin'), Buffer.alloc(64, 0xaa));
    writeFileSync(join(src, '03-sixty-five.bin'), Buffer.alloc(65, 0xbb));
    writeFileSync(join(src, '04-empty.bin'), Buffer.alloc(0));
    writeFileSync(join(src, '05-large.bin'), Buffer.alloc(4097, 0xcd));

    const bundlePath = join(root, 'aligned.b8p');
    const packed = packForwardB8pBundle(src, bundlePath, 'align-check');
    const idx = readB8pBundleIndex(bundlePath);

    assert.equal(idx.header.magic, B8P_MAGIC);
    assert.equal(idx.header.abiMagic, B8G_ABI_MAGIC_V3);
    assert.equal(idx.header.tableOffset, B8P_HEADER_SIZE);
    assert.equal(idx.header.payloadOffset % B8P_ALIGN, 0);
    assert.equal(idx.forwardHash, packed.forwardHash);
    assert.equal(idx.entryCount, 5);

    for (const entry of idx.entries) {
      assert.equal(entry.offset % B8P_ALIGN, 0, `offset ${entry.offset} for ${entry.path} must be 64-byte aligned`);
      assert.equal(entry.alignedEnd % B8P_ALIGN, 0, `alignedEnd ${entry.alignedEnd} for ${entry.path} must be 64-byte aligned`);
      assert.ok(entry.offset >= idx.header.payloadOffset);
    }

    const verified = verifyB8pBundle(bundlePath);
    assert.equal(verified.ok, true, verified.errors.join('; '));
    assert.equal(verified.forwardHash, packed.forwardHash);
  });
});

test('verifyB8pBundle detects 1-bit payload tampering and header tampering', () => {
  withTempDir((root) => {
    const src = join(root, 'src');
    mkdirSync(src, { recursive: true });
    writeFileSync(join(src, 'kernel.elf'), Buffer.from('B8G-SOVEREIGN-KERNEL-PAYLOAD-V3'));
    writeFileSync(join(src, 'config.json'), '{"abi":"0x33564742"}');

    const bundlePath = join(root, 'valid.b8p');
    const packed = packForwardB8pBundle(src, bundlePath, 'tamper-test');
    assert.equal(verifyB8pBundle(bundlePath).ok, true);

    // 1-bit payload flip
    const payloadTampered = join(root, 'payload-tampered.b8p');
    const raw1 = Buffer.from(readFileSync(bundlePath));
    const kernelEntry = packed.entries.find((e) => e.path === 'kernel.elf')!;
    raw1[kernelEntry.offset] = raw1[kernelEntry.offset]! ^ 0x01;
    writeFileSync(payloadTampered, raw1);

    const res1 = verifyB8pBundle(payloadTampered);
    assert.equal(res1.ok, false);
    assert.ok(res1.errors.some((e) => e.includes('Leaf SHA-512 mismatch')));
    assert.throws(() => extractEntryByRange(payloadTampered, 'kernel.elf'), /Leaf SHA-512 verification failed/);

    // 1-bit ABI magic header flip
    const headerTampered = join(root, 'header-tampered.b8p');
    const raw2 = Buffer.from(readFileSync(bundlePath));
    raw2[4] = raw2[4]! ^ 0x01;
    writeFileSync(headerTampered, raw2);

    const res2 = verifyB8pBundle(headerTampered);
    assert.equal(res2.ok, false);
    assert.ok(res2.errors.some((e) => e.includes('Invalid abiMagic')));

    // 1-bit magic flip
    const magicTampered = join(root, 'magic-tampered.b8p');
    const raw3 = Buffer.from(readFileSync(bundlePath));
    raw3[0] = raw3[0]! ^ 0x01;
    writeFileSync(magicTampered, raw3);

    const res3 = verifyB8pBundle(magicTampered);
    assert.equal(res3.ok, false);
    assert.ok(res3.errors.some((e) => e.includes('Invalid magic')));

    // 1-bit forwardHash header prefix flip
    const prefixTampered = join(root, 'prefix-tampered.b8p');
    const raw4 = Buffer.from(readFileSync(bundlePath));
    raw4[56] = raw4[56]! ^ 0x01;
    writeFileSync(prefixTampered, raw4);

    const res4 = verifyB8pBundle(prefixTampered);
    assert.equal(res4.ok, false);
    assert.ok(res4.errors.some((e) => e.includes('Header forwardHash prefix mismatch')));
  });
});

test('extractEntryByRange reads a single entry directly by offset without scanning other entries', () => {
  withTempDir((root) => {
    const src = join(root, 'src');
    mkdirSync(join(src, 'libs'), { recursive: true });
    const targetPayload = Buffer.from('DIRECT-RANGE-PAYLOAD-0x33564742');
    writeFileSync(join(src, 'libs', 'alpha.bin'), Buffer.alloc(1024, 0x11));
    writeFileSync(join(src, 'libs', 'target.so'), targetPayload);
    writeFileSync(join(src, 'libs', 'omega.bin'), Buffer.alloc(2048, 0x22));

    const bundlePath = join(root, 'range.b8p');
    const packed = packForwardB8pBundle(src, bundlePath, 'range-test');

    // Deliberately corrupt an UNRELATED entry (`alpha.bin`) to prove extractEntryByRange
    // does NOT scan or verify unrelated payload ranges!
    const raw = Buffer.from(readFileSync(bundlePath));
    const alphaEntry = packed.entries.find((e) => e.path === 'libs/alpha.bin')!;
    raw[alphaEntry.offset] = raw[alphaEntry.offset]! ^ 0xff;
    const partialPath = join(root, 'range-partial-corrupt.b8p');
    writeFileSync(partialPath, raw);

    // Full verify catches the unrelated corruption
    assert.equal(verifyB8pBundle(partialPath).ok, false);

    // Direct O(1) range extract of `libs/target.so` succeeds cleanly and validates its leaf SHA-512
    const extracted = extractEntryByRange(partialPath, 'libs/target.so');
    assert.equal(extracted.entry.path, 'libs/target.so');
    assert.equal(extracted.bytesRead, targetPayload.length);
    assert.equal(Buffer.compare(extracted.data, targetPayload), 0);

    // Missing entry throws
    assert.throws(() => extractEntryByRange(bundlePath, 'libs/does-not-exist.so'), /not found/);
  });
});

test('packDirectoryToV11Shards emits canonical sorted v11-tree.json with deterministic forwardBundleHash and optional .b8p', () => {
  withTempDir((root) => {
    const src = join(root, 'app-src');
    const out1 = join(root, 'out-1');
    const out2 = join(root, 'out-2');
    mkdirSync(join(src, 'sub'), { recursive: true });
    writeFileSync(join(src, 'sub', 'b.txt'), 'bravo');
    writeFileSync(join(src, 'a.txt'), 'alpha');
    writeFileSync(join(src, 'dup.txt'), 'alpha');

    const m1 = packDirectoryToV11Shards(src, out1, 'demo-app');
    const m2 = packDirectoryToV11Shards(src, out2, 'demo-app', { emitB8p: true });

    assert.equal(m1.forwardBundleHash, m2.forwardBundleHash);
    assert.equal(m1.forwardBundleHash.length, 128);
    assert.deepEqual(
      m1.files.map((f) => f.path),
      ['a.txt', 'dup.txt', 'sub/b.txt'],
    );
    assert.equal(m1.uniqueBlobs, 2);
    assert.equal(m1.b8pBundle, undefined);

    assert.ok(m2.b8pBundle);
    assert.equal(m2.b8pBundle.file, 'demo-app.b8p');
    assert.equal(m2.b8pBundle.forwardHash, m2.forwardBundleHash);
    const b8pAbs = join(out2, 'demo-app.b8p');
    assert.equal(existsSync(b8pAbs), true);
    const verifyRes = verifyB8pBundle(b8pAbs);
    assert.equal(verifyRes.ok, true, verifyRes.errors.join('; '));
    assert.equal(verifyRes.forwardHash, m2.forwardBundleHash);
  });
});
