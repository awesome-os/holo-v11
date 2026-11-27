import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  aggregateFailuresByRule,
  AUDIT_PUSH_SCHEMA,
  AUDIT_STACK_FAILURES_SCHEMA,
  AUDIT_STACK_RUN_SCHEMA,
  AUDIT_STACK_SUMMARY_SCHEMA,
  B8G_ABI_MAGIC_V3,
  CDP_AUDIT_REPORT_SCHEMA,
  computeAuditViolationFingerprint,
  computeCanonicalSha512,
  DEFAULT_RATCHET_FLOORS,
  evaluateRatification,
  FAST_FAIL_GATE_SCHEMA,
  HOLO_CI_RECEIPT_SCHEMA,
  HOLO_CI_WF_HARDEN_SCHEMA,
  HOLO_FAILURE_TELEMETRY_SCHEMA,
  HOLO_RULE_VIOLATION_SCHEMA,
  ingestAuditPayload,
  PROJECT_GEOMETRY_SCHEMA,
  RATIFICATION_RECEIPT_SCHEMA,
  REGRESSION_LEDGER_SCHEMA,
  runAuditStackHub,
} from './audit-stack-hub.mts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..');
const SCRIPT_PATH = path.resolve(__dirname, 'audit-stack-hub.mts');
const OVERSIGHT_HTML_PATH = path.join(REPO_ROOT, 'dashboard', 'oversight.html');

function makeTempDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

describe('scripts/audit-stack-hub.mts — Universal Programmatic Audit Ingestion', () => {
  it('ingests holo-rule-violation.v1 (single object, array, and JSONL lines)', () => {
    const single = {
      schema: HOLO_RULE_VIOLATION_SCHEMA,
      ruleId: 'B8G016',
      severity: 'error',
      category: 'ipc',
      repo: 'awesome-os',
      file: 'sections\\bus\\server.mts',
      line: 42,
      snippet: 'createServer()',
      message: 'Illegal loopback HTTP binding',
      autofixable: false,
    };
    const resSingle = ingestAuditPayload(single, 'unit:single', '2026-11-27T10:00:00.000Z');
    assert.equal(resSingle.violations.length, 1);
    assert.equal(resSingle.violations[0]!.file, 'sections/bus/server.mts');
    assert.equal(
      resSingle.violations[0]!.fingerprint,
      computeAuditViolationFingerprint(
        'B8G016',
        'awesome-os',
        'sections/bus/server.mts',
        'Illegal loopback HTTP binding',
      ),
    );
    assert.equal(resSingle.signals.httpIpcUnits, 1);

    const jsonlText = [
      JSON.stringify(single),
      JSON.stringify({
        schema: HOLO_RULE_VIOLATION_SCHEMA,
        ruleId: 'holo.governance.non-github-io-cname',
        severity: 'error',
        category: 'governance',
        repo: 'b8g.app',
        file: 'CNAME',
        line: 1,
        snippet: 'b8g.app',
        message: 'Custom CNAME file forbidden',
        autofixable: true,
      }),
    ].join('\n');

    const resJsonl = ingestAuditPayload(jsonlText, 'unit:jsonl', '2026-11-27T10:00:00.000Z');
    assert.equal(resJsonl.violations.length, 2);
    assert.equal(resJsonl.signals.cnameViolations, 1);
    assert.equal(resJsonl.signals.httpIpcUnits, 1);
  });

  it('ingests holo-failure-telemetry.v1 JSONL and JSON summary wrapper', () => {
    const rec1 = {
      schema: HOLO_FAILURE_TELEMETRY_SCHEMA,
      timestamp: '2026-11-27T10:01:00.000Z',
      gateId: 'bin-parity',
      category: 'parity',
      exitCode: 1,
      durationMs: 120,
      fingerprint: 'a1b2c3d4e5f60708',
      summary: '1 orphaned wrapper in bin/',
      remediationCmd: '.\\bin\\b8g-bin-parity.ps1 verify',
      rollbackHint: 'Restore missing triplet wrapper',
      mode: 'exhaust',
    };
    const rec2 = {
      schema: HOLO_FAILURE_TELEMETRY_SCHEMA,
      timestamp: '2026-11-27T10:01:05.000Z',
      gateId: 'rollback-contract',
      category: 'rollback',
      exitCode: 1,
      durationMs: 45,
      fingerprint: '1122334455667788',
      summary: 'RollingReleaseManifest missing O(1) rollback target',
      remediationCmd: '.\\bin\\holo-upgrade.ps1 --check',
      rollbackHint: 'Revert release manifest pointer',
      mode: 'exhaust',
    };

    const jsonl = `${JSON.stringify(rec1)}\n${JSON.stringify(rec2)}\n`;
    const fromJsonl = ingestAuditPayload(jsonl, 'telemetry.jsonl', '2026-11-27T10:02:00.000Z');
    assert.equal(fromJsonl.violations.length, 2);
    assert.equal(fromJsonl.violations[0]!.ruleId, 'fast-fail.bin-parity');
    assert.equal(fromJsonl.violations[0]!.fingerprint, 'a1b2c3d4e5f60708');
    assert.equal(fromJsonl.violations[0]!.remediationCmd, '.\\bin\\b8g-bin-parity.ps1 verify');
    assert.equal(fromJsonl.signals.rollbackContractOk, false);

    const fromWrapper = ingestAuditPayload(
      {
        schema: HOLO_FAILURE_TELEMETRY_SCHEMA,
        abiMagic: B8G_ABI_MAGIC_V3,
        timestamp: '2026-11-27T10:02:00.000Z',
        mode: 'exhaust',
        totalGates: 6,
        failedCount: 1,
        records: [rec1],
      },
      'telemetry.json',
      '2026-11-27T10:02:00.000Z',
    );
    assert.equal(fromWrapper.violations.length, 1);
    assert.equal(fromWrapper.violations[0]!.fingerprint, 'a1b2c3d4e5f60708');
  });

  it('ingests b8g.fast-fail-gate.v1 receipts', () => {
    const receipt = {
      schema: FAST_FAIL_GATE_SCHEMA,
      abiMagic: B8G_ABI_MAGIC_V3,
      timestamp: '2026-11-27T10:05:00.000Z',
      cwd: 'e:\\awesome-os',
      mode: 'exhaust',
      failFast: false,
      failedFast: false,
      firstFailureGateId: 'docs-links',
      ok: false,
      exitCode: 1,
      totalDurationMs: 842.5,
      counts: { total: 2, passed: 1, failed: 1, aborted: 0, skipped: 0 },
      thresholds: { minGeometry: 95, maxHttpIpc: 0 },
      telemetryOut: null,
      telemetryRecordsWritten: 0,
      gates: [
        {
          id: 'rollback-contract',
          label: 'O(1) Rollback Contract',
          category: 'rollback',
          status: 'pass',
          durationMs: 110,
          exitCode: 0,
          summary: 'Rollback manifest verified',
          rollbackHint: 'n/a',
          remediationCmd: 'n/a',
          stdoutSnippet: '',
          stderrSnippet: '',
        },
        {
          id: 'docs-links',
          label: 'Web Doc Links',
          category: 'docs',
          status: 'fail',
          durationMs: 732,
          exitCode: 1,
          summary: '2 broken markdown anchors in ARCHITECTURE.md',
          rollbackHint: 'Restore section anchors',
          remediationCmd: '.\\bin\\b8g-web-doc.ps1 ARCHITECTURE.md',
          stdoutSnippet: '',
          stderrSnippet: '',
        },
      ],
    };

    const res = ingestAuditPayload(receipt, 'fast-fail.json', '2026-11-27T10:05:00.000Z');
    assert.equal(res.gates.length, 1);
    assert.equal(res.gates[0]!.ok, false);
    assert.equal(res.violations.length, 1);
    assert.equal(res.violations[0]!.ruleId, 'fast-fail.docs-links');
    assert.equal(res.signals.rollbackContractOk, true);
  });

  it('ingests holo-ci.receipt.v1 (verify, boundary-audit, wf-harden) and direct wf-harden.v1', () => {
    const verifyReceipt = {
      schema: HOLO_CI_RECEIPT_SCHEMA,
      abiMagic: B8G_ABI_MAGIC_V3,
      generatedAt: '2026-11-27T10:10:00.000Z',
      phase: 'verify',
      name: 'devtools',
      kind: 'monorepo',
      ok: false,
      durationMs: 250,
      verify: {
        ok: false,
        tests: [{ command: 'node --test a.test.mts', kind: 'test', exitCode: 1, durationMs: 90, ok: false, stdout: '', stderr: 'Assertion failed' }],
        nativeGates: [],
        docs: [{ path: 'README.md', exists: true }],
        guardViolations: [
          { guard: 'zeroHttpIpc', file: 'src/dev.mts', line: 12, snippet: 'loopback http server' },
          { guard: 'requireWorkflowHardening', file: '.github/workflows/ci.yml', line: 1, snippet: 'missing concurrency' },
        ],
      },
    };
    const rVerify = ingestAuditPayload(verifyReceipt, 'verify.json');
    assert.equal(rVerify.violations.length, 3);
    assert.equal(rVerify.violations.some((v) => v.ruleId === 'B8G016'), true);
    assert.equal(rVerify.violations.some((v) => v.ruleId === 'holo.workflow.hardening'), true);
    assert.equal(rVerify.violations.some((v) => v.ruleId === 'holo.ci.test-failure'), true);
    assert.equal(rVerify.signals.httpIpcUnits, 1);

    const boundaryReceipt = {
      schema: HOLO_CI_RECEIPT_SCHEMA,
      abiMagic: B8G_ABI_MAGIC_V3,
      generatedAt: '2026-11-27T10:11:00.000Z',
      phase: 'boundary-audit',
      name: 'holo-v11',
      kind: 'control-plane',
      ok: true,
      durationMs: 85,
      boundaryAudit: {
        ok: true,
        score: 100,
        manifestFound: true,
        scannedFiles: 14,
        axes: { dependencyPurity: 20, encapsulation: 20, ipcCompliance: 20, abiContract: 20, governance: 20 },
        violations: [],
      },
    };
    const rBoundary = ingestAuditPayload(boundaryReceipt, 'boundary.json');
    assert.equal(rBoundary.gates[0]!.ok, true);
    assert.equal(rBoundary.signals.boundaryScore, 100);
    assert.equal(rBoundary.signals.httpIpcUnits, 0);

    const wfHardenReceipt = {
      schema: HOLO_CI_WF_HARDEN_SCHEMA,
      abiMagic: B8G_ABI_MAGIC_V3,
      repoDir: 'e:\\awesome-os\\github-mirror\\awesome-os\\upstream-mirrors',
      mode: 'check',
      ok: false,
      workflowsScanned: 1,
      totalFindings: 1,
      remainingFindings: 1,
      totalFixesApplied: 0,
      modifiedFiles: [],
      files: [
        {
          fileName: '.github/workflows/build.yml',
          ok: false,
          changed: false,
          content: '',
          findings: [],
          remainingFindings: [
            {
              rule: 'missing-timeout-minutes',
              severity: 'warning',
              file: '.github/workflows/build.yml',
              line: 14,
              message: 'Job build missing timeout-minutes',
              snippet: 'runs-on: ubuntu-latest',
            },
          ],
          fixesApplied: [],
        },
      ],
    };
    const rWf = ingestAuditPayload(wfHardenReceipt, 'wf-harden.json');
    assert.equal(rWf.violations.length, 1);
    assert.equal(rWf.violations[0]!.ruleId, 'holo.workflow.missing-timeout-minutes');
    assert.equal(rWf.violations[0]!.repo, 'upstream-mirrors');
  });

  it('ingests awesome-os.regression-ledger.v1 and awesome-os.cdp-network-audit.v1', () => {
    const regReport = {
      schema: REGRESSION_LEDGER_SCHEMA,
      abiMagic: B8G_ABI_MAGIC_V3,
      generatedAt: '2026-11-27T10:15:00.000Z',
      ok: false,
      findings: [
        {
          id: 'f1',
          category: 'abi',
          repo: 'awesome-os',
          alertKey: 'abi:runtime',
          rule: 'missing-abi-golden',
          severity: 'error',
          message: 'sections/runtime/runtime_abi.h missing abi-golden.json',
          file: 'sections/runtime/runtime_abi.h',
          line: 1,
        },
      ],
    };
    const rReg = ingestAuditPayload(regReport, 'regression.json');
    assert.equal(rReg.violations.length, 1);
    assert.equal(rReg.violations[0]!.ruleId, 'regression.abi.missing-abi-golden');

    const cdpReport = {
      schema: CDP_AUDIT_REPORT_SCHEMA,
      generatedAt: '2026-11-27T10:16:00.000Z',
      suite: 'pages',
      ok: false,
      pages: [
        {
          url: 'https://awesome-os.github.io/holo-v11/oversight.html',
          responseErrors: [
            { url: 'https://awesome-os.github.io/favicon.ico', status: 404, ignored: true },
            { url: 'https://awesome-os.github.io/holo-v11/missing.json', status: 404, ignored: false },
          ],
          loadingFailed: [
            { url: 'https://awesome-os.github.io/holo-v11/app.wasm', errorText: 'net::ERR_ABORTED' },
          ],
          runtimeExceptions: [
            { text: 'TypeError: cannot read property of null', url: 'oversight.html', lineNumber: 99 },
          ],
          logErrors: [],
        },
      ],
      brokenLinks: [
        { url: 'https://awesome-os.github.io/dead-link', status: 404, ok: false },
      ],
    };
    const rCdp = ingestAuditPayload(cdpReport, 'cdp.json');
    assert.equal(rCdp.gates[0]!.ok, false);
    assert.equal(rCdp.violations.length, 4); // ignored favicon 404 excluded
    assert.equal(rCdp.violations.some((v) => v.ruleId === 'cdp.http-404'), true);
    assert.equal(rCdp.violations.some((v) => v.ruleId === 'cdp.loading-failed'), true);
    assert.equal(rCdp.violations.some((v) => v.ruleId === 'cdp.runtime-exception'), true);
    assert.equal(rCdp.violations.some((v) => v.ruleId === 'cdp.broken-link'), true);
  });

  it('ingests project-geometry JSON (both canonical and shorthand fields) and b8g.audit-push.v1', () => {
    const geomCanonical = {
      schema: PROJECT_GEOMETRY_SCHEMA,
      rating: { totalScore: 100, maxScore: 100, grade: 'A' },
      topology: {
        coreSccs: [],
        coreLayerInversionsCount: 0,
        coreLayerInversions: [],
        httpIpcViolationUnits: [],
      },
    };
    const rCanon = ingestAuditPayload(geomCanonical, 'geom-canonical.json');
    assert.equal(rCanon.gates[0]!.ok, true);
    assert.equal(rCanon.signals.geometryScore, 100);
    assert.equal(rCanon.signals.coreSccs, 0);
    assert.equal(rCanon.signals.coreLayerInversions, 0);
    assert.equal(rCanon.signals.httpIpcUnits, 0);

    const geomShorthand = {
      rating: { totalScore: 82 },
      topology: {
        coreStronglyConnectedComponents: [['sections/a', 'sections/b']],
        coreLayerInversions: 2,
        httpIpcViolationUnits: ['sections/net'],
      },
    };
    const rShort = ingestAuditPayload(geomShorthand, 'geom-short.json');
    assert.equal(rShort.gates[0]!.ok, false);
    assert.equal(rShort.signals.geometryScore, 82);
    assert.equal(rShort.signals.coreSccs, 1);
    assert.equal(rShort.signals.coreLayerInversions, 2);
    assert.equal(rShort.signals.httpIpcUnits, 1);
    assert.equal(rShort.violations.length, 3);

    const customPush = {
      schema: AUDIT_PUSH_SCHEMA,
      auditId: 'pages-cname-check',
      repo: 'awesome-os.github.io',
      ok: true,
      durationMs: 14,
      metrics: { cnameViolations: 0, rollbackContractOk: true },
      violations: [],
    };
    const rPush = ingestAuditPayload(customPush, 'push.json');
    assert.equal(rPush.gates[0]!.auditId, 'pages-cname-check');
    assert.equal(rPush.gates[0]!.ok, true);
    assert.equal(rPush.signals.cnameViolations, 0);
    assert.equal(rPush.signals.rollbackContractOk, true);
  });
});

describe('scripts/audit-stack-hub.mts — Monotonic Continuous Ratification & Telemetry Accumulation', () => {
  it('ratchets floors monotonically upward on verified better scores and rejects regressions loudly', () => {
    const clean100 = ingestAuditPayload(
      {
        schema: PROJECT_GEOMETRY_SCHEMA,
        rating: { totalScore: 100 },
        topology: {
          coreSccs: [],
          coreLayerInversionsCount: 0,
          httpIpcViolationUnits: [],
        },
      },
      'geom-100.json',
      '2026-11-27T11:00:00.000Z',
    );

    const r1 = evaluateRatification(
      clean100,
      null,
      { minGeometryScore: 74, maxCoreSccs: 2, maxHttpIpcUnits: 3 },
      '2026-11-27T11:00:00.000Z',
    );
    assert.equal(r1.schema, RATIFICATION_RECEIPT_SCHEMA);
    assert.equal(r1.abiMagic, B8G_ABI_MAGIC_V3);
    assert.equal(r1.ratified, true);
    assert.equal(r1.action, 'PROMOTE');
    assert.equal(r1.floors.minGeometryScore, 100);
    assert.equal(r1.floors.maxCoreSccs, 0);
    assert.equal(r1.floors.maxHttpIpcUnits, 0);
    assert.equal(r1.ratchetUpdates.length, 3);
    assert.match(r1.sha512, /^[a-f0-9]{128}$/);

    // Verify SHA-512 reproducibility
    const { sha512: recordedSha, ...unsigned } = r1;
    assert.equal(recordedSha, computeCanonicalSha512(unsigned));

    // Regress geometry 100 -> 96: must HOLD_AND_ROLLBACK_O1 and keep locked floor at 100
    const regressed96 = ingestAuditPayload(
      {
        schema: PROJECT_GEOMETRY_SCHEMA,
        rating: { totalScore: 96 },
        topology: {
          coreSccs: [],
          coreLayerInversionsCount: 0,
          httpIpcViolationUnits: [],
        },
      },
      'geom-96.json',
      '2026-11-27T12:00:00.000Z',
    );

    const r2 = evaluateRatification(
      regressed96,
      { floors: r1.floors },
      undefined,
      '2026-11-27T12:00:00.000Z',
    );
    assert.equal(r2.ratified, false);
    assert.equal(r2.action, 'HOLD_AND_ROLLBACK_O1');
    assert.equal(r2.floors.minGeometryScore, 100);
    assert.equal(r2.ratchetViolations.length, 1);
    assert.equal(r2.ratchetViolations[0]!.metric, 'minGeometryScore');
    assert.equal(r2.ratchetViolations[0]!.floor, 100);
    assert.equal(r2.ratchetViolations[0]!.observed, 96);
  });

  it('accumulates failure telemetry across runs with deterministic SHA-256 deduplication and gravity scoring', () => {
    const tmp = makeTempDir('holo-audit-stack-');
    try {
      const outDir = path.join(tmp, 'audit-stack');
      const failA = {
        schema: HOLO_RULE_VIOLATION_SCHEMA,
        ruleId: 'B8G016',
        severity: 'error',
        category: 'ipc',
        repo: 'awesome-os',
        file: 'sections/net/server.mts',
        line: 20,
        snippet: 'loopback listener',
        message: 'Illegal loopback listener',
        autofixable: false,
      };

      const run1 = runAuditStackHub({
        outDir,
        timestamp: '2026-11-27T08:00:00.000Z',
        payloads: [{ raw: failA, sourceLabel: 'run1' }],
      });
      assert.equal(run1.receipt.ratified, false);
      assert.equal(run1.failures.schema, AUDIT_STACK_FAILURES_SCHEMA);
      assert.equal(run1.failures.totalOccurrences, 1);
      assert.equal(run1.failures.uniqueFingerprints, 1);

      // Run 2 repeats same exact violation + adds a second repo with same ruleId
      const failB = {
        ...failA,
        repo: 'devtools',
        file: 'src/bridge.mts',
      };
      const run2 = runAuditStackHub({
        outDir,
        timestamp: '2026-11-27T09:00:00.000Z',
        payloads: [{ raw: [failA, failB], sourceLabel: 'run2' }],
      });

      assert.equal(run2.failures.totalOccurrences, 3);
      assert.equal(run2.failures.uniqueFingerprints, 2);
      assert.equal(run2.failures.uniqueRules, 1);
      const fpA = computeAuditViolationFingerprint(
        'B8G016',
        'awesome-os',
        'sections/net/server.mts',
        'Illegal loopback listener',
      );
      const entryA = run2.failures.entries.find((e) => e.fingerprint === fpA);
      assert.ok(entryA);
      assert.equal(entryA.occurrences, 2);
      assert.equal(entryA.firstSeenAt, '2026-11-27T08:00:00.000Z');
      assert.equal(entryA.lastSeenAt, '2026-11-27T09:00:00.000Z');
      assert.ok(entryA.gravityScore > run1.failures.entries[0]!.gravityScore);

      const ruleRollup = run2.failures.byRule[0]!;
      assert.equal(ruleRollup.ruleId, 'B8G016');
      assert.equal(ruleRollup.occurrences, 3);
      assert.deepEqual(ruleRollup.repos, ['awesome-os', 'devtools']);

      // Verify runs.jsonl accumulated 2 valid NDJSON lines
      const lines = fs
        .readFileSync(run2.runsPath, 'utf8')
        .trim()
        .split(/\r?\n/)
        .map((l) => JSON.parse(l) as { schema: string });
      assert.equal(lines.length, 2);
      assert.equal(lines[0]!.schema, AUDIT_STACK_RUN_SCHEMA);
      assert.equal(lines[1]!.schema, AUDIT_STACK_RUN_SCHEMA);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('enforces --enforce-ratchet non-zero exit on CLI regression (100 -> 96)', () => {
    const tmp = makeTempDir('holo-audit-cli-');
    try {
      const outDir = path.join(tmp, 'audit-stack');
      const g100 = path.join(tmp, 'geom-100.json');
      const g96 = path.join(tmp, 'geom-96.json');
      fs.writeFileSync(
        g100,
        JSON.stringify({
          schema: PROJECT_GEOMETRY_SCHEMA,
          rating: { totalScore: 100 },
          topology: { coreSccs: [], coreLayerInversionsCount: 0, httpIpcViolationUnits: [] },
        }),
        'utf8',
      );
      fs.writeFileSync(
        g96,
        JSON.stringify({
          schema: PROJECT_GEOMETRY_SCHEMA,
          rating: { totalScore: 96 },
          topology: { coreSccs: [], coreLayerInversionsCount: 0, httpIpcViolationUnits: [] },
        }),
        'utf8',
      );

      const out1 = execFileSync(
        process.execPath,
        [SCRIPT_PATH, '--ingest', g100, '--out-dir', outDir, '--enforce-ratchet', '--json'],
        { encoding: 'utf8' },
      );
      const parsed1 = JSON.parse(out1) as { ratified: boolean; floors: { minGeometryScore: number } };
      assert.equal(parsed1.ratified, true);
      assert.equal(parsed1.floors.minGeometryScore, 100);

      let failedExitCode = 0;
      let stdoutOnFail = '';
      try {
        execFileSync(
          process.execPath,
          [SCRIPT_PATH, '--ingest', g96, '--out-dir', outDir, '--enforce-ratchet', '--json'],
          { encoding: 'utf8' },
        );
      } catch (err) {
        const e = err as { status?: number; stdout?: string };
        failedExitCode = e.status ?? 0;
        stdoutOnFail = e.stdout ?? '';
      }
      assert.equal(failedExitCode, 1);
      const parsed2 = JSON.parse(stdoutOnFail) as {
        ratified: boolean;
        action: string;
        floors: { minGeometryScore: number };
      };
      assert.equal(parsed2.ratified, false);
      assert.equal(parsed2.action, 'HOLD_AND_ROLLBACK_O1');
      assert.equal(parsed2.floors.minGeometryScore, 100);

      // Verify --help works
      const helpOut = execFileSync(process.execPath, [SCRIPT_PATH, '--help'], { encoding: 'utf8' });
      assert.match(helpOut, /--enforce-ratchet/);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('wires dashboard/oversight.html to ./audit-stack/{latest,failures-by-rule}.json with zero loopback HTTP URLs', () => {
    const html = fs.readFileSync(OVERSIGHT_HTML_PATH, 'utf8');
    assert.ok(html.includes('id="continuous-ratification-panel"'));
    assert.ok(html.includes('./audit-stack/latest.json'));
    assert.ok(html.includes('./audit-stack/failures-by-rule.json'));

    const loopbackHost = ['127', '0', '0', '1'].join('.');
    const loopbackHttp = ['http', '://', loopbackHost].join('');
    const localhostHttp = ['http', '://', 'localhost'].join('');
    assert.equal(html.includes(loopbackHost), false, 'oversight.html must not reference loopback IP');
    assert.equal(html.includes(loopbackHttp), false, 'oversight.html must not reference loopback HTTP');
    assert.equal(html.includes(localhostHttp), false, 'oversight.html must not reference localhost HTTP');
  });

  it('validates aggregateFailuresByRule handles empty baseline cleanly', () => {
    const doc = aggregateFailuresByRule([], null, '2026-11-27T00:00:00.000Z');
    assert.equal(doc.schema, AUDIT_STACK_FAILURES_SCHEMA);
    assert.equal(doc.abiMagic, B8G_ABI_MAGIC_V3);
    assert.equal(doc.totalOccurrences, 0);
    assert.equal(doc.entries.length, 0);
    assert.equal(doc.byRule.length, 0);
    assert.equal(DEFAULT_RATCHET_FLOORS.maxHttpIpcUnits, 0);
    assert.equal(DEFAULT_RATCHET_FLOORS.requireRollbackContract, true);
  });

  it('validates seeded audit-stack baseline artifacts exist and carry B8G_ABI_MAGIC_V3', () => {
    const auditStackDir = path.join(REPO_ROOT, 'audit-stack');
    const latest = JSON.parse(
      fs.readFileSync(path.join(auditStackDir, 'latest.json'), 'utf8'),
    ) as { schema: string; abiMagic: string; ratified: boolean };
    const failures = JSON.parse(
      fs.readFileSync(path.join(auditStackDir, 'failures-by-rule.json'), 'utf8'),
    ) as { schema: string; abiMagic: string };
    const receipt = JSON.parse(
      fs.readFileSync(path.join(auditStackDir, 'ratification-receipt.json'), 'utf8'),
    ) as { schema: string; abiMagic: string; sha512: string };
    const runsLines = fs
      .readFileSync(path.join(auditStackDir, 'runs.jsonl'), 'utf8')
      .trim()
      .split(/\r?\n/);

    assert.equal(latest.schema, AUDIT_STACK_SUMMARY_SCHEMA);
    assert.equal(latest.abiMagic, B8G_ABI_MAGIC_V3);
    assert.equal(failures.schema, AUDIT_STACK_FAILURES_SCHEMA);
    assert.equal(failures.abiMagic, B8G_ABI_MAGIC_V3);
    assert.equal(receipt.schema, RATIFICATION_RECEIPT_SCHEMA);
    assert.equal(receipt.abiMagic, B8G_ABI_MAGIC_V3);
    assert.match(receipt.sha512, /^[a-f0-9]{128}$/);
    assert.ok(runsLines.length >= 1);
    const lastRun = JSON.parse(runsLines[runsLines.length - 1]!) as { schema: string };
    assert.equal(lastRun.schema, AUDIT_STACK_RUN_SCHEMA);
  });
});
