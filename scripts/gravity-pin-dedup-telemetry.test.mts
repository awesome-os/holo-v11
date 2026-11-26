import test from 'node:test';
import assert from 'node:assert/strict';
import {
  CORE_ACTIVE_REPOS,
  buildGravityTelemetryReport,
  computeDedupMetrics,
  computePercentile,
  computePinningMetrics,
  serializeGravityNdjson,
  summarizeRepoRuns,
} from './gravity-pin-dedup-telemetry.mts';

test('computePercentile computes deterministic p50 and p95', () => {
  assert.equal(computePercentile([], 0.5), 0);
  assert.equal(computePercentile([10, 20, 30, 40, 50], 0.5), 30);
  assert.equal(computePercentile([10, 20, 30, 40, 50, 60, 70, 80, 90, 100], 0.95), 100);
});

test('computeDedupMetrics detects SHA-512 savings, zero dup_v8, and b8g-ghost remnants', () => {
  const dedup = computeDedupMetrics([
    { id: 'a', repo: 'awesome-os', filename: 'a.bin', sha512: 'aa'.repeat(64), size: 10 * 1048576 },
    { id: 'b', repo: 'holo-pm', filename: 'b.bin', sha512: 'aa'.repeat(64), size: 10 * 1048576 },
    { id: 'c', repo: 'holo-v11', filename: 'c.bin', sha512: 'bb'.repeat(64), size: 5 * 1048576 },
  ]);
  assert.equal(dedup.totalAssets, 3);
  assert.equal(dedup.uniqueSha512Blobs, 2);
  assert.equal(dedup.dedupedBlobs, 1);
  assert.equal(dedup.rawTotalMb, 25);
  assert.equal(dedup.uniqueTotalMb, 15);
  assert.equal(dedup.savedMb, 10);
  assert.equal(dedup.dedupRatioPct, 40);
  assert.equal(dedup.dupV8Bytes, 0);
  assert.equal(dedup.b8gGhostRemnants, 0);
});

test('computePinningMetrics flags drifted and bumped libraries accurately', () => {
  const pinning = computePinningMetrics(
    {
      totalTracked: 3,
      libraries: [
        { pkg: 'openssl', repo: 'openssl/openssl', upstreamVersion: '4.1.0', previousV11: '4.1.0', bumped: false },
        { pkg: 'zstd', repo: 'facebook/zstd', upstreamVersion: '1.6.1', previousV11: '1.6.0', bumped: false },
        { pkg: 'curl', repo: 'curl/curl', upstreamVersion: '8.24.0', previousV11: '8.23.0', bumped: true },
      ],
    },
    { summary: { totalLadybirdDeps: 49, coveredInV11: 33, overlapPercent: 67.35, raisedFromV11: 17 } },
    { totalPackages: 5070 },
    { aheadOfChromePins: { openssl: { version: '4.1.0' }, harfbuzz: { version: '15.2.0' } } },
  );
  assert.equal(pinning.trackedUpstreamLibs, 3);
  assert.equal(pinning.atMaxCount, 1);
  assert.equal(pinning.bumpedCount, 1);
  assert.equal(pinning.aheadOfChromeCount, 17);
  assert.equal(pinning.v11UniversePackages, 5070);
  assert.equal(pinning.driftedLibs.length, 2);
});

test('buildGravityTelemetryReport & serializeGravityNdjson emit valid v1 schema & ABI magic', () => {
  const runsByRepo = new Map<string, ReturnType<typeof Array.prototype.slice>>([
    [
      'holo-v11',
      [
        {
          name: 'Update Reports',
          status: 'completed',
          conclusion: 'success',
          run_started_at: '2026-11-26T18:00:00Z',
          updated_at: '2026-11-26T18:00:40Z',
          html_url: 'https://github.com/awesome-os/holo-v11/actions/runs/1',
        },
        {
          name: 'Update Reports',
          status: 'completed',
          conclusion: 'success',
          run_started_at: '2026-11-26T17:00:00Z',
          updated_at: '2026-11-26T17:01:40Z',
          html_url: 'https://github.com/awesome-os/holo-v11/actions/runs/2',
        },
      ],
    ],
  ]);

  const report = buildGravityTelemetryReport({
    generatedAt: '2026-11-26T18:45:00Z',
    entries: [{ id: 'x', repo: 'holo-v11', filename: 'x.bin', sha512: 'cc'.repeat(64), size: 1048576 }],
    tracker: {
      totalTracked: 1,
      libraries: [{ pkg: 'limine', repo: 'limine-bootloader/limine', upstreamVersion: '12.11.1', previousV11: '12.11.1', bumped: false }],
    },
    lock: { summary: { totalLadybirdDeps: 49, coveredInV11: 33, overlapPercent: 67.35, raisedFromV11: 17 } },
    universe: { totalPackages: 5070 },
    aheadPins: { aheadOfChromePins: {} },
    runsByRepo,
    apiRateRemaining: 4850,
    apiRateLimit: 5000,
  });

  assert.equal(report.schema, 'awesome-os.gravity-telemetry.v1');
  assert.equal(report.abiMagic, '0x33564742');
  assert.equal(report.gravityDamper.dampingFactor, 0.65);
  assert.equal(report.gravityDamper.runnerFleet.reposMonitored, CORE_ACTIVE_REPOS.length);
  assert.equal(report.gravityDamper.p50DurationSec, 40);
  assert.equal(report.gravityDamper.p95DurationSec, 100);
  assert.equal(report.gravityDamper.overallPassRatePct, 100);
  assert.equal(report.gravityDamper.apiRateRemaining, 4850);

  const ndjson = serializeGravityNdjson(report, {
    libraries: [{ pkg: 'limine', repo: 'limine-bootloader/limine', upstreamVersion: '12.11.1', previousV11: '12.11.1', bumped: false }],
  });
  const parsed = ndjson
    .trim()
    .split('\n')
    .map((line) => JSON.parse(line) as { kind: string; abiMagic: string });
  assert.equal(parsed[0]?.kind, 'summary');
  assert.equal(parsed.filter((r) => r.kind === 'repo-runner').length, CORE_ACTIVE_REPOS.length);
  assert.equal(parsed.filter((r) => r.kind === 'pinned-subsystem').length, 1);
  assert.ok(parsed.every((r) => r.abiMagic === '0x33564742'));

  const singleRepo = summarizeRepoRuns('holo-v11', runsByRepo.get('holo-v11')!);
  assert.equal(singleRepo.passRatePct, 100);
  assert.equal(singleRepo.p50DurationSec, 40);
});
