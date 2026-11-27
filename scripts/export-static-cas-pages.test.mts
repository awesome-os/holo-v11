import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { computeForwardBundleHash } from './b8p-forward-bundle.mts';
import {
  exportStaticCasPages,
  type StaticCasIndexDocument,
  type StaticCasShardDocument,
} from './export-static-cas-pages.mts';

function withTempDir(fn: (dir: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), 'holo-v11-cas-pages-'));
  try {
    fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('exportStaticCasPages generates deterministic index.json with forwardBundleHash and populated 00..ff shards', () => {
  withTempDir((root) => {
    const shaA = '0a' + '11'.repeat(63);
    const shaB = 'ff' + '22'.repeat(63);
    const shaC = '0a' + '33'.repeat(63);

    const manifest1 = {
      schema: 'awesome-os-cas-v11-manifest-v1',
      abiMagic: '0x33564742',
      generatedAt: '2026-11-27T01:00:00Z',
      totalRepos: 2,
      entries: [
        {
          id: 'awesome-os/holo-v11@v1/b.bin',
          repo: 'holo-v11',
          tag: 'v1',
          filename: 'b.bin',
          target: 'linux-x64',
          executable: true,
          sha512: shaB,
          size: 4096,
          downloadUrl: 'https://github.com/awesome-os/holo-v11/releases/download/v1/b.bin',
        },
        {
          id: 'awesome-os/awesome-os@v1/a.bin',
          repo: 'awesome-os',
          tag: 'v1',
          filename: 'a.bin',
          target: 'any',
          executable: false,
          sha512: shaA,
          size: 1024,
          downloadUrl: 'https://github.com/awesome-os/awesome-os/releases/download/v1/a.bin',
        },
        // Duplicate SHA-512 blob across two repos
        {
          id: 'awesome-os/holo-v11@v1/a-copy.bin',
          repo: 'holo-v11',
          tag: 'v1',
          filename: 'a-copy.bin',
          target: 'any',
          executable: false,
          sha512: shaA,
          size: 1024,
          downloadUrl: 'https://github.com/awesome-os/holo-v11/releases/download/v1/a-copy.bin',
        },
        {
          id: 'awesome-os/awesome-os@v1/c.bin',
          repo: 'awesome-os',
          tag: 'v1',
          filename: 'c.bin',
          target: 'win64',
          executable: false,
          sha512: shaC,
          size: 512,
          downloadUrl: 'https://github.com/awesome-os/awesome-os/releases/download/v1/c.bin',
        },
      ],
    };

    const mPath1 = join(root, 'manifest1.json');
    const mPath2 = join(root, 'manifest2.json');
    writeFileSync(mPath1, JSON.stringify(manifest1), 'utf8');
    // Reverse entry order to verify forwardBundleHash determinism
    writeFileSync(mPath2, JSON.stringify({ ...manifest1, entries: [...manifest1.entries].reverse() }), 'utf8');

    const out1 = join(root, 'out1');
    const out2 = join(root, 'out2');

    const r1 = exportStaticCasPages({ manifestPath: mPath1, outDir: out1, generatedAt: '2026-11-27T09:00:00Z' });
    const r2 = exportStaticCasPages({ manifestPath: mPath2, outDir: out2, generatedAt: '2026-11-27T09:00:00Z' });

    assert.equal(r1.index.forwardBundleHash, r2.index.forwardBundleHash);
    assert.equal(r1.index.schema, 'awesome-os.cas-v11-static-index.v1');
    assert.equal(r1.index.abiMagic, '0x33564742');
    assert.equal(r1.index.totalAssets, 4);
    assert.equal(r1.index.uniqueBlobs, 3);
    assert.equal(r1.index.rawTotalBytes, 6656);
    assert.equal(r1.index.uniqueTotalBytes, 5632);
    assert.equal(r1.index.savedBytes, 1024);
    assert.equal(r1.index.populatedShards, 2);

    const shardFiles = readdirSync(join(out1, 'shards')).sort();
    assert.deepEqual(shardFiles, ['0a.json', 'ff.json']);

    const idxDoc = JSON.parse(readFileSync(join(out1, 'index.json'), 'utf8')) as StaticCasIndexDocument;
    assert.equal(idxDoc.shards['0a']?.blobCount, 2);
    assert.equal(idxDoc.shards['ff']?.blobCount, 1);

    const shard0a = JSON.parse(readFileSync(join(out1, 'shards', '0a.json'), 'utf8')) as StaticCasShardDocument;
    assert.equal(shard0a.schema, 'awesome-os.cas-v11-shard.v1');
    assert.equal(shard0a.prefix, '0a');
    assert.equal(shard0a.blobs.length, 2);
    assert.equal(shard0a.blobs[0]?.sha512, shaA);
    assert.equal(shard0a.blobs[0]?.refs.length, 2);
    assert.equal(shard0a.blobs[1]?.sha512, shaC);

    const expectedRoot = computeForwardBundleHash([
      { path: `v11/files/0a/${shaA}`, bytes: 1024, sha512: shaA },
      { path: `v11/files/0a/${shaC}`, bytes: 512, sha512: shaC },
      { path: `v11/files/ff/${shaB}`, bytes: 4096, sha512: shaB },
    ]);
    assert.equal(idxDoc.forwardBundleHash, expectedRoot);
    assert.equal(existsSync(join(out1, 'shards', '00.json')), false);
  });
});

test('exportStaticCasPages works against the real index/cas-v11-global-manifest.json into a temp dir', () => {
  withTempDir((root) => {
    const outDir = join(root, 'live-cas');
    const res = exportStaticCasPages({ outDir });
    assert.ok(res.index.uniqueBlobs > 0);
    assert.ok(res.index.populatedShards > 0);
    assert.equal(res.index.forwardBundleHash.length, 128);
    assert.equal(existsSync(join(outDir, 'index.json')), true);
  });
});
