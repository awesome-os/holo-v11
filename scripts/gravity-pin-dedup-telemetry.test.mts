import test from 'node:test';
import assert from 'node:assert/strict';
import {
  CORE_ACTIVE_REPOS,
  LIB_BINARY_STEM_ALIASES,
  buildGravityTelemetryReport,
  compareVersions,
  computeDedupMetrics,
  computeMaterializationMetrics,
  computePercentile,
  computePinningMetrics,
  isCanonicalShardReceipt,
  isRealCompiledBinaryAsset,
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
  assert.equal(pinning.atMaxCount, 2);
  assert.equal(pinning.bumpedCount, 1);
  assert.equal(pinning.aheadOfChromeCount, 17);
  assert.equal(pinning.v11UniversePackages, 5070);
  assert.equal(pinning.driftedLibs.length, 1);
  assert.equal(pinning.driftedLibs[0]?.pkg, 'zstd');
});

test('computePinningMetrics Bug #1 fix: universe version & bumped flag eliminate false drift on fresh bumps', () => {
  const freshBump = computePinningMetrics(
    {
      totalTracked: 1,
      libraries: [
        { pkg: 'libpng', repo: 'pnggroup/libpng', upstreamVersion: '1.6.59', previousV11: '1.6.58', bumped: true },
      ],
    },
    {},
    { totalPackages: 5078, packages: [{ name: 'libpng', version: '1.6.59' }] },
    {},
  );
  assert.deepEqual(freshBump.driftedLibs, []);
  assert.equal(freshBump.atMaxCount, 1);
  assert.equal(freshBump.bumpedCount, 1);

  const laggingUnbumped = computePinningMetrics(
    {
      totalTracked: 1,
      libraries: [
        { pkg: 'libpng', repo: 'pnggroup/libpng', upstreamVersion: '1.6.59', previousV11: '1.6.58', bumped: false },
      ],
    },
    {},
    { totalPackages: 5078, packages: [{ name: 'libpng', version: '1.6.58' }] },
    {},
  );
  assert.equal(laggingUnbumped.driftedLibs.length, 1);
  assert.equal(laggingUnbumped.driftedLibs[0]?.pkg, 'libpng');
  assert.equal(laggingUnbumped.driftedLibs[0]?.pinned, '1.6.58');
  assert.equal(laggingUnbumped.atMaxCount, 0);
});

test('computeMaterializationMetrics distinguishes real compiled binaries from metadata assets', () => {
  const mat = computeMaterializationMetrics(
    {
      totalTracked: 5,
      libraries: [
        { pkg: 'brotli', upstreamVersion: '1.2.1' },
        { pkg: 'zlib', upstreamVersion: '1.4' },
        { pkg: 'ada', upstreamVersion: '4.1.1' },
        { pkg: 'openssl', upstreamVersion: '4.1.0' },
        { pkg: 'limine', upstreamVersion: '12.11.1' },
      ],
    },
    [
      { repo: 'upstream-mirrors', filename: 'libbrotli-linux-x64.so' },
      { repo: 'upstream-mirrors', filename: 'libz-win64.dll' },
      { repo: 'upstream-mirrors', filename: 'libada-wasm32-wasi.wasm' },
      { repo: 'upstream-mirrors', filename: 'SHA512SUMS-openssl.txt' },
      { repo: 'upstream-mirrors', filename: 'openssl-manifest.json' },
      { repo: 'awesome-os', filename: 'limine.conf' },
      { repo: 'awesome-os', filename: 'README.md' },
    ],
  );
  assert.equal(mat.totalTracked, 5);
  assert.equal(mat.realCompiledCount, 3);
  assert.equal(mat.virtualPinOnlyCount, 2);
  assert.equal(mat.realMaterializationPct, 60);
  assert.deepEqual(mat.realCompiledLibs, ['brotli', 'zlib', 'ada']);
  assert.deepEqual(mat.virtualPinOnlyLibs, ['openssl', 'limine']);
});

test('compareVersions & computePinningMetrics treat pinned >= upstream (e.g. linux 7.3.6 vs 7.3) as at-max', () => {
  assert.equal(compareVersions('7.3.6', '7.3') > 0, true);
  assert.equal(compareVersions('7.2', '7.3') < 0, true);
  assert.equal(compareVersions('7.3.0', '7.3'), 0);

  const aheadPinning = computePinningMetrics(
    {
      totalTracked: 1,
      libraries: [{ pkg: 'linux', repo: 'torvalds/linux', upstreamVersion: '7.3', previousV11: '7.3.6', bumped: false }],
    },
    {},
    { totalPackages: 5070 },
    {},
  );
  assert.equal(aheadPinning.driftedLibs.length, 0);
  assert.equal(aheadPinning.atMaxCount, 1);

  const behindPinning = computePinningMetrics(
    {
      totalTracked: 1,
      libraries: [{ pkg: 'linux', repo: 'torvalds/linux', upstreamVersion: '7.3', previousV11: '7.2', bumped: false }],
    },
    {},
    { totalPackages: 5070 },
    {},
  );
  assert.equal(behindPinning.driftedLibs.length, 1);
  assert.equal(behindPinning.atMaxCount, 0);
  assert.equal(behindPinning.driftedLibs[0]?.pkg, 'linux');
});

test('CORE_ACTIVE_REPOS tracks the 12 active flat-org engineering repos without archived repos', () => {
  const repos: readonly string[] = CORE_ACTIVE_REPOS;
  assert.equal(repos.length, 12);
  for (const archived of ['ladybird', 'llama.cpp', 'colibri', 'firecracker', 'desktop', 'holo-compiler']) {
    assert.equal(repos.includes(archived), false, `Expected archived ${archived} to be excluded`);
  }
  for (const required of [
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
  ]) {
    assert.equal(repos.includes(required), true, `Expected ${required} in CORE_ACTIVE_REPOS`);
  }
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
  assert.equal(report.gravityDamper.latestFleetPassRatePct, 100);
  assert.equal(report.gravityDamper.runnerFleet.completedLatestRepos, 1);
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

test('latestFleetPassRatePct reflects head health independently of rolling history', () => {
  const runsByRepo = new Map([
    [
      'holo-v11',
      [
        { name: 'CI', status: 'completed', conclusion: 'success', run_started_at: '2026-11-26T18:00:00Z', updated_at: '2026-11-26T18:00:20Z' },
        { name: 'CI', status: 'completed', conclusion: 'failure', run_started_at: '2026-11-26T17:00:00Z', updated_at: '2026-11-26T17:00:20Z' },
      ],
    ],
    [
      'awesome-os',
      [
        { name: 'CI', status: 'completed', conclusion: 'success', run_started_at: '2026-11-26T18:10:00Z', updated_at: '2026-11-26T18:10:30Z' },
      ],
    ],
    [
      'devtools',
      [
        { name: 'CI', status: 'in_progress', conclusion: null, run_started_at: '2026-11-26T18:15:00Z', updated_at: '2026-11-26T18:15:10Z' },
      ],
    ],
  ]);

  const allHeadGreen = buildGravityTelemetryReport({
    entries: [],
    tracker: { totalTracked: 0, libraries: [] },
    lock: {},
    universe: { totalPackages: 5070 },
    aheadPins: {},
    runsByRepo,
    apiRateRemaining: 5000,
    apiRateLimit: 5000,
  });
  assert.equal(allHeadGreen.gravityDamper.runnerFleet.completedLatestRepos, 2);
  assert.equal(allHeadGreen.gravityDamper.runnerFleet.passingLatestRepos, 2);
  assert.equal(allHeadGreen.gravityDamper.latestFleetPassRatePct, 100);
  assert.equal(allHeadGreen.gravityDamper.overallPassRatePct, 66.7);

  runsByRepo.set('t2linux-baseline', [
    { name: 'CI', status: 'completed', conclusion: 'failure', run_started_at: '2026-11-26T18:20:00Z', updated_at: '2026-11-26T18:20:10Z' },
  ]);
  const partialHead = buildGravityTelemetryReport({
    entries: [],
    tracker: { totalTracked: 0, libraries: [] },
    lock: {},
    universe: { totalPackages: 5070 },
    aheadPins: {},
    runsByRepo,
    apiRateRemaining: 5000,
    apiRateLimit: 5000,
  });
  assert.equal(partialHead.gravityDamper.runnerFleet.completedLatestRepos, 3);
  assert.equal(partialHead.gravityDamper.runnerFleet.passingLatestRepos, 2);
  assert.equal(partialHead.gravityDamper.latestFleetPassRatePct, 66.7);
});

test('computeMaterializationMetrics resolves all 12 Tier-2 libs plus php/ruby/sqlite via binaries & shard receipts while excluding ordinary JSON', () => {
  const tier2AndPolyglot = [
    'mbedtls',
    'llhttp',
    'nghttp2',
    'nghttp3',
    'c-ares',
    'fast_float',
    'libpng',
    'giflib',
    'freetype',
    'harfbuzz',
    'onig',
    'zlib-ng',
    'php',
    'ruby',
    'sqlite',
  ] as const;

  for (const pkg of tier2AndPolyglot) {
    assert.ok(Array.isArray(LIB_BINARY_STEM_ALIASES[pkg]) && LIB_BINARY_STEM_ALIASES[pkg].length >= 2, `Missing aliases for ${pkg}`);
  }

  assert.equal(isCanonicalShardReceipt('libpng-receipt.json'), true);
  assert.equal(isCanonicalShardReceipt('libzlib-ng-receipt.json'), true);
  assert.equal(isCanonicalShardReceipt('resolved-tier2-versions.json'), false);
  assert.equal(isCanonicalShardReceipt('cas-manifest.json'), false);
  assert.equal(isCanonicalShardReceipt('-receipt.json'), false);
  assert.equal(isRealCompiledBinaryAsset('libpng-receipt.json'), false);

  const tracker = {
    totalTracked: tier2AndPolyglot.length + 3,
    libraries: [
      ...tier2AndPolyglot.map((pkg) => ({ pkg })),
      { pkg: 'openssl' },
      { pkg: 'curl' },
      { pkg: 're2' },
    ],
  };

  // Compiled binaries for Tier-2 + polyglot + ordinary metadata JSONs that must stay excluded
  const binaryRun = computeMaterializationMetrics(tracker, [
    { filename: 'libmbedtls-linux-x64.so' },
    { filename: 'libllhttp-win64.dll' },
    { filename: 'libnghttp2-linux-arm64.so' },
    { filename: 'libnghttp3-wasm32-wasi.wasm' },
    { filename: 'libcares-win64.dll' },
    { filename: 'libfast_float-linux-x64.so' },
    { filename: 'libpng-macos-arm64.dylib' },
    { filename: 'libgiflib-linux-x64.so' },
    { filename: 'libfreetype-win64.dll' },
    { filename: 'libharfbuzz-linux-x64.so' },
    { filename: 'libonig-wasm32-wasi.wasm' },
    { filename: 'libzlib-ng-linux-x64.so' },
    { filename: 'php-wasi-wasm32-wasi.wasm' },
    { filename: 'libruby-linux-x64.so' },
    { filename: 'libsqlite3-win64.dll' },
    { filename: 'resolved-tier2-versions.json' },
    { filename: 'cas-manifest.json' },
    { filename: 'openssl-manifest.json' },
    { filename: 'curl.json' },
    { filename: 're2-metadata.json' },
  ]);

  assert.deepEqual(binaryRun.realCompiledLibs, [...tier2AndPolyglot]);
  assert.deepEqual(binaryRun.virtualPinOnlyLibs, ['openssl', 'curl', 're2']);
  assert.equal(binaryRun.realCompiledCount, 15);
  assert.equal(binaryRun.virtualPinOnlyCount, 3);

  // Canonical shard receipt files (*-receipt.json / lib*-receipt.json) also resolve all 15
  const receiptRun = computeMaterializationMetrics(tracker, [
    { filename: 'libmbedtls-receipt.json' },
    { filename: 'libllhttp-receipt.json' },
    { filename: 'libnghttp2-receipt.json' },
    { filename: 'libnghttp3-receipt.json' },
    { filename: 'libcares-receipt.json' },
    { filename: 'libfast_float-receipt.json' },
    { filename: 'libpng-receipt.json' },
    { filename: 'libgiflib-receipt.json' },
    { filename: 'libfreetype-receipt.json' },
    { filename: 'libharfbuzz-receipt.json' },
    { filename: 'libonig-receipt.json' },
    { filename: 'libzlib-ng-receipt.json' },
    { filename: 'php-receipt.json' },
    { filename: 'ruby-receipt.json' },
    { filename: 'libsqlite3-receipt.json' },
    { filename: 'resolved-tier2-versions.json' },
    { filename: 'cas-manifest.json' },
    { filename: 'openssl.json' },
    { filename: 'curl-config.json' },
    { filename: '-receipt.json' },
  ]);

  assert.deepEqual(receiptRun.realCompiledLibs, [...tier2AndPolyglot]);
  assert.deepEqual(receiptRun.virtualPinOnlyLibs, ['openssl', 'curl', 're2']);
  assert.equal(receiptRun.realCompiledCount, 15);
  assert.equal(receiptRun.virtualPinOnlyCount, 3);
});

test('computeMaterializationMetrics resolves all Tier-3 and Tier-4 libraries via binaries and shard receipts', () => {
  const tier3And4 = [
    'pixman',
    'libffi',
    'woff2',
    'ngtcp2',
    'libxml2',
    'libxslt',
    'libarchive',
    'liburing',
    'ninja',
    'libavif',
    'cairo',
    'mariadb-connector-c',
    'libgit2',
    'curl',
    'openssl',
    'limine',
    'vulkan-loader',
  ] as const;

  const tracker = {
    totalTracked: tier3And4.length + 1,
    libraries: [...tier3And4.map((pkg) => ({ pkg })), { pkg: 're2' }],
  };

  const run = computeMaterializationMetrics(tracker, [
    { filename: 'libpixman-receipt.json' },
    { filename: 'libffi-receipt.json' },
    { filename: 'libwoff2-receipt.json' },
    { filename: 'libngtcp2-receipt.json' },
    { filename: 'libxml2-receipt.json' },
    { filename: 'libxslt-receipt.json' },
    { filename: 'libarchive-receipt.json' },
    { filename: 'liburing-receipt.json' },
    { filename: 'ninja-receipt.json' },
    { filename: 'libavif-receipt.json' },
    { filename: 'libcairo-receipt.json' },
    { filename: 'libmariadb-receipt.json' },
    { filename: 'libgit2-receipt.json' },
    { filename: 'libcurl-receipt.json' },
    { filename: 'libssl-receipt.json' },
    { filename: 'limine-receipt.json' },
    { filename: 'libvulkan-receipt.json' },
  ]);

  assert.deepEqual(run.realCompiledLibs, [...tier3And4]);
  assert.deepEqual(run.virtualPinOnlyLibs, ['re2']);
  assert.equal(run.realCompiledCount, tier3And4.length);
  assert.equal(run.virtualPinOnlyCount, 1);
});

test('computeMaterializationMetrics resolves all Tier-5 and Tier-6 stem aliases case-insensitively with receiptKinds & casForwardHash', () => {
  const tier5And6 = [
    'vulkan-headers',
    'spirv-headers',
    'cccl',
    'cutlass',
    'dav1d',
    'librdkafka',
    'libsdl3',
    're2',
    'spirv-tools',
    'glslang',
    'ffmpeg',
    'meson',
    'protobuf',
    'icu4c',
    'vips',
    'openblas',
    'onednn',
    'cmake',
    'nccl',
    'rocm',
    'triton',
    'flash-attention',
    'xdna-driver',
  ] as const;

  for (const pkg of tier5And6) {
    assert.ok(Array.isArray(LIB_BINARY_STEM_ALIASES[pkg]) && LIB_BINARY_STEM_ALIASES[pkg].length >= 1, `Missing alias for ${pkg}`);
  }

  const tracker = {
    totalTracked: tier5And6.length,
    libraries: tier5And6.map((pkg) => ({ pkg })),
  };

  const assets = [
    { id: 'u/vulkan_headers', filename: 'libvulkan_headers-receipt.json', sha512: '01'.repeat(64), size: 128, receiptKind: 'header-pack' },
    { id: 'u/spirv_headers', filename: 'libspirv_headers-receipt.json', sha512: '02'.repeat(64), size: 128, receiptKind: 'header-pack' },
    { id: 'u/cccl', filename: 'libcccl-receipt.json', sha512: '03'.repeat(64), size: 128, receiptKind: 'header-pack' },
    { id: 'u/cutlass', filename: 'libcutlass-receipt.json', sha512: '04'.repeat(64), size: 128, receiptKind: 'header-pack' },
    { id: 'u/dav1d', filename: 'libdav1d-linux-x64.so', sha512: '05'.repeat(64), size: 4096 },
    { id: 'u/rdkafka', filename: 'rdkafka-win64.dll', sha512: '06'.repeat(64), size: 4096 },
    { id: 'u/libsdl3', filename: 'libSDL3-win64.dll', sha512: '07'.repeat(64), size: 8192 },
    { id: 'u/re2', filename: 'libre2-linux-x64.so', sha512: '08'.repeat(64), size: 4096 },
    { id: 'u/spirv-tools', filename: 'libSPIRV-Tools-receipt.json', sha512: '09'.repeat(64), size: 256, receiptKind: 'compiled-shard' },
    { id: 'u/glslang', filename: 'libglslang-linux-x64.so', sha512: '0a'.repeat(64), size: 4096 },
    { id: 'u/ffmpeg', filename: 'libavcodec-linux-x64.so', sha512: '0b'.repeat(64), size: 16384 },
    { id: 'u/meson', filename: 'meson-receipt.json', sha512: '0c'.repeat(64), size: 256, receiptKind: 'tool-shard' },
    { id: 'u/protobuf', filename: 'libprotobuf-linux-x64.so', sha512: '0d'.repeat(64), size: 8192 },
    { id: 'u/icu4c', filename: 'libicuuc-win64.dll', sha512: '0e'.repeat(64), size: 8192 },
    { id: 'u/vips', filename: 'libvips-linux-x64.so', sha512: '0f'.repeat(64), size: 8192 },
    { id: 'u/openblas', filename: 'libopenblas-linux-x64.so', sha512: '10'.repeat(64), size: 8192 },
    { id: 'u/onednn', filename: 'libdnnl-linux-x64.so', sha512: '11'.repeat(64), size: 8192 },
    { id: 'u/cmake', filename: 'cmake-receipt.json', sha512: '12'.repeat(64), size: 256, receiptKind: 'tool-shard' },
    { id: 'u/nccl', filename: 'libnccl-receipt.json', sha512: '13'.repeat(64), size: 256, receiptKind: 'gpu-bridge' },
    { id: 'u/rocm', filename: 'librocm-receipt.json', sha512: '14'.repeat(64), size: 256, receiptKind: 'gpu-bridge' },
    { id: 'u/triton', filename: 'libtriton-receipt.json', sha512: '15'.repeat(64), size: 256, receiptKind: 'gpu-bridge' },
    { id: 'u/flash-attention', filename: 'libflash_attention-receipt.json', sha512: '16'.repeat(64), size: 256, receiptKind: 'gpu-bridge' },
    { id: 'u/xdna-driver', filename: 'libxdna_driver-receipt.json', sha512: '17'.repeat(64), size: 256, receiptKind: 'npu-bridge' },
  ];

  const run = computeMaterializationMetrics(tracker, assets);
  assert.deepEqual(run.realCompiledLibs, [...tier5And6]);
  assert.deepEqual(run.virtualPinOnlyLibs, []);
  assert.equal(run.realCompiledCount, tier5And6.length);
  assert.equal(run.realMaterializationPct, 100);
  assert.equal(run.receiptKinds?.compiledBinaries, 11);
  assert.equal(run.receiptKinds?.shardReceipts, 12);
  assert.equal(run.receiptKinds?.byKind?.['header-pack'], 4);
  assert.equal(run.receiptKinds?.byKind?.['gpu-bridge'], 4);
  assert.equal(typeof run.casForwardHash, 'string');
  assert.equal(run.casForwardHash?.length, 128);
});
