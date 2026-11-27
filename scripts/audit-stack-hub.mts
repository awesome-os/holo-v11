#!/usr/bin/env node
/**
 * @file scripts/audit-stack-hub.mts
 * @description Unified Central Audit Stack Hub & Monotonic Continuous Ratification Engine
 * for Awesome-OS (`awesome-os/holo-v11`).
 *
 * Capabilities:
 *   1. Universal Programmatic Audit Ingestion (`ingestAuditPayload`) normalizing:
 *      - `holo-rule-violation.v1` (object, array, envelope, or JSONL)
 *      - `holo-failure-telemetry.v1` (JSONL or `.json` summary from `b8g-fast-fail`)
 *      - `b8g.fast-fail-gate.v1` (`b8g-fast-fail --json`)
 *      - `holo-ci.receipt.v1` (`verify`, `boundary-audit`, `wf-harden`, `sync`, `maintain`, etc.)
 *      - `holo-ci.wf-harden.v1` (direct `wf-harden.mts --json`)
 *      - `awesome-os.regression-ledger.v1` (`regression-watch.mts --json`)
 *      - `awesome-os.cdp-network-audit.v1` (`cdp-network-audit.mts --json-out`)
 *      - `awesome-os.project-geometry.v1` (`project-geometry.mts --json`)
 *      - `b8g.audit-push.v1` (lightweight programmatic push from any repo/script)
 *   2. Monotonic Continuous Ratification Engine (`evaluateRatification`) enforcing
 *      non-regressing `RatchetFloors` and emitting SHA-512 signed `b8g.ratification-receipt.v1`
 *      (`PROMOTE` vs `HOLD_AND_ROLLBACK_O1`).
 *   3. Cross-Run Failure Telemetry Aggregator (`aggregateFailuresByRule`) deduplicating by
 *      deterministic 16-hex SHA-256 fingerprint and computing damped-gravity priority scores.
 *
 * Strictly `erasableSyntaxOnly: true`, Node 24/26 built-ins only, `shell: false`, zero loopback HTTP IPC.
 */

import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const B8G_ABI_MAGIC_V3 = '0x33564742' as const;
export const HOLO_RULE_VIOLATION_SCHEMA = 'holo-rule-violation.v1' as const;
export const HOLO_FAILURE_TELEMETRY_SCHEMA = 'holo-failure-telemetry.v1' as const;
export const FAST_FAIL_GATE_SCHEMA = 'b8g.fast-fail-gate.v1' as const;
export const HOLO_CI_RECEIPT_SCHEMA = 'holo-ci.receipt.v1' as const;
export const HOLO_CI_WF_HARDEN_SCHEMA = 'holo-ci.wf-harden.v1' as const;
export const REGRESSION_LEDGER_SCHEMA = 'awesome-os.regression-ledger.v1' as const;
export const CDP_AUDIT_REPORT_SCHEMA = 'awesome-os.cdp-network-audit.v1' as const;
export const PROJECT_GEOMETRY_SCHEMA = 'awesome-os.project-geometry.v1' as const;
export const AUDIT_PUSH_SCHEMA = 'b8g.audit-push.v1' as const;

export const AUDIT_STACK_SUMMARY_SCHEMA = 'b8g.audit-stack-summary.v1' as const;
export const AUDIT_STACK_FAILURES_SCHEMA = 'b8g.audit-stack-failures.v1' as const;
export const RATIFICATION_RECEIPT_SCHEMA = 'b8g.ratification-receipt.v1' as const;
export const AUDIT_STACK_RUN_SCHEMA = 'b8g.audit-stack-run.v1' as const;

export const DEFAULT_OUT_DIR = 'audit-stack' as const;
export const DEFAULT_MAX_HISTORY_RUNS = 500;
export const DEFAULT_ROLLBACK_COMMAND =
  '.\\bin\\holo-upgrade.ps1 --rollback-o1 --manifest RollingReleaseManifest.json';

export type AuditRuleSeverity = 'error' | 'warning' | 'info';

export type AuditRuleCategory =
  | 'security'
  | 'ipc'
  | 'geometry'
  | 'abi'
  | 'governance'
  | 'workflow'
  | 'docs'
  | 'brand'
  | 'telemetry'
  | 'network'
  | 'runtime'
  | 'custom';

export type RatificationAction = 'PROMOTE' | 'HOLD_AND_ROLLBACK_O1';

export interface AuditViolationRecord {
  readonly schema: typeof HOLO_RULE_VIOLATION_SCHEMA;
  readonly ruleId: string;
  readonly severity: AuditRuleSeverity;
  readonly category: AuditRuleCategory;
  readonly repo: string;
  readonly file: string;
  readonly line: number;
  readonly snippet: string;
  readonly message: string;
  readonly autofixable: boolean;
  readonly fingerprint: string;
  readonly source: string;
  readonly timestamp: string;
  readonly remediationCmd?: string;
  readonly rollbackHint?: string;
}

export interface AuditGateSummary {
  readonly auditId: string;
  readonly schema: string;
  readonly source: string;
  readonly repo: string;
  readonly ok: boolean;
  readonly durationMs: number;
  readonly timestamp: string;
  readonly violationCount: number;
  readonly metrics?: Readonly<Record<string, number | boolean | string>>;
}

export interface ObservedRatchetSignals {
  readonly geometryScore?: number;
  readonly coreSccs?: number;
  readonly coreLayerInversions?: number;
  readonly httpIpcUnits?: number;
  readonly boundaryScore?: number;
  readonly cnameViolations?: number;
  readonly rollbackContractOk?: boolean;
}

export interface IngestedAuditResult {
  readonly source: string;
  readonly schemasDetected: readonly string[];
  readonly gates: readonly AuditGateSummary[];
  readonly violations: readonly AuditViolationRecord[];
  readonly signals: ObservedRatchetSignals;
}

export interface RatchetFloors {
  readonly minGeometryScore: number;
  readonly maxCoreSccs: number;
  readonly maxCoreLayerInversions: number;
  readonly maxHttpIpcUnits: number;
  readonly minBoundaryScore: number;
  readonly maxCnameViolations: number;
  readonly requireRollbackContract: boolean;
}

export const DEFAULT_RATCHET_FLOORS: RatchetFloors = {
  minGeometryScore: 74,
  maxCoreSccs: 0,
  maxCoreLayerInversions: 0,
  maxHttpIpcUnits: 0,
  minBoundaryScore: 100,
  maxCnameViolations: 0,
  requireRollbackContract: true,
};

export interface RatchetViolation {
  readonly metric: keyof RatchetFloors;
  readonly direction: 'min' | 'max' | 'require';
  readonly floor: number | boolean;
  readonly observed: number | boolean;
  readonly message: string;
  readonly remediationCmd: string;
}

export interface RatchetUpdate {
  readonly metric: keyof RatchetFloors;
  readonly previous: number | boolean;
  readonly next: number | boolean;
}

export interface RatificationReceipt {
  readonly schema: typeof RATIFICATION_RECEIPT_SCHEMA;
  readonly abiMagic: typeof B8G_ABI_MAGIC_V3;
  readonly generatedAt: string;
  readonly ratified: boolean;
  readonly action: RatificationAction;
  readonly floors: RatchetFloors;
  readonly previousFloors: RatchetFloors;
  readonly ratchetUpdates: readonly RatchetUpdate[];
  readonly ratchetViolations: readonly RatchetViolation[];
  readonly observedSignals: ObservedRatchetSignals;
  readonly violationCount: number;
  readonly errorViolationCount: number;
  readonly passedAudits: number;
  readonly failedAudits: number;
  readonly rollbackCommand: string;
  readonly sha512: string;
}

export interface AggregatedFailureEntry {
  readonly fingerprint: string;
  readonly ruleId: string;
  readonly severity: AuditRuleSeverity;
  readonly category: AuditRuleCategory;
  readonly occurrences: number;
  readonly firstSeenAt: string;
  readonly lastSeenAt: string;
  readonly repos: readonly string[];
  readonly files: readonly string[];
  readonly sampleMessage: string;
  readonly remediationCmd: string;
  readonly rollbackHint: string;
  readonly gravityScore: number;
}

export interface RuleFailureRollup {
  readonly ruleId: string;
  readonly severity: AuditRuleSeverity;
  readonly category: AuditRuleCategory;
  readonly occurrences: number;
  readonly uniqueFingerprints: number;
  readonly firstSeenAt: string;
  readonly lastSeenAt: string;
  readonly repos: readonly string[];
  readonly remediationCmd: string;
  readonly rollbackHint: string;
  readonly gravityScore: number;
  readonly sampleMessage: string;
}

export interface AuditStackFailuresDocument {
  readonly schema: typeof AUDIT_STACK_FAILURES_SCHEMA;
  readonly abiMagic: typeof B8G_ABI_MAGIC_V3;
  readonly generatedAt: string;
  readonly totalOccurrences: number;
  readonly uniqueFingerprints: number;
  readonly uniqueRules: number;
  readonly entries: readonly AggregatedFailureEntry[];
  readonly byRule: readonly RuleFailureRollup[];
}

export interface AuditStackSummaryDocument {
  readonly schema: typeof AUDIT_STACK_SUMMARY_SCHEMA;
  readonly abiMagic: typeof B8G_ABI_MAGIC_V3;
  readonly generatedAt: string;
  readonly runId: string;
  readonly ratified: boolean;
  readonly action: RatificationAction;
  readonly floors: RatchetFloors;
  readonly previousFloors: RatchetFloors;
  readonly ratchetUpdates: readonly RatchetUpdate[];
  readonly ratchetViolations: readonly RatchetViolation[];
  readonly observedSignals: ObservedRatchetSignals;
  readonly totals: {
    readonly ingestedSources: number;
    readonly totalAudits: number;
    readonly passedAudits: number;
    readonly failedAudits: number;
    readonly violationCount: number;
    readonly errorViolationCount: number;
    readonly warningViolationCount: number;
    readonly uniqueRules: number;
    readonly accumulatedFailureOccurrences: number;
  };
  readonly audits: readonly AuditGateSummary[];
  readonly topFailingRules: readonly RuleFailureRollup[];
  readonly receiptSha512: string;
}

export interface AuditStackRunRecord {
  readonly schema: typeof AUDIT_STACK_RUN_SCHEMA;
  readonly runId: string;
  readonly generatedAt: string;
  readonly ratified: boolean;
  readonly action: RatificationAction;
  readonly passedAudits: number;
  readonly failedAudits: number;
  readonly violationCount: number;
  readonly ratchetViolationCount: number;
  readonly floors: RatchetFloors;
  readonly receiptSha512: string;
}

export interface RunAuditStackHubOptions {
  readonly ingestPaths?: readonly string[];
  readonly payloads?: readonly { readonly raw: unknown; readonly sourceLabel: string }[];
  readonly outDir?: string;
  readonly floors?: Partial<RatchetFloors>;
  readonly timestamp?: string;
  readonly maxHistoryRuns?: number;
}

export interface RunAuditStackHubResult {
  readonly outDir: string;
  readonly latestPath: string;
  readonly failuresPath: string;
  readonly receiptPath: string;
  readonly runsPath: string;
  readonly latest: AuditStackSummaryDocument;
  readonly failures: AuditStackFailuresDocument;
  readonly receipt: RatificationReceipt;
  readonly runRecord: AuditStackRunRecord;
}

export interface ParsedAuditStackCliArgs {
  readonly ingestPaths: readonly string[];
  readonly outDir: string;
  readonly enforceRatchet: boolean;
  readonly json: boolean;
  readonly help: boolean;
  readonly maxHistoryRuns: number;
  readonly timestamp?: string;
}

const VALID_SEVERITIES = new Set<AuditRuleSeverity>(['error', 'warning', 'info']);
const VALID_CATEGORIES = new Set<AuditRuleCategory>([
  'security',
  'ipc',
  'geometry',
  'abi',
  'governance',
  'workflow',
  'docs',
  'brand',
  'telemetry',
  'network',
  'runtime',
  'custom',
]);

const SEVERITY_RANK: Readonly<Record<AuditRuleSeverity, number>> = {
  error: 3,
  warning: 2,
  info: 1,
};

const SEVERITY_GRAVITY_WEIGHT: Readonly<Record<AuditRuleSeverity, number>> = {
  error: 10,
  warning: 4,
  info: 1,
};

const CATEGORY_GRAVITY_MULTIPLIER: Readonly<Record<AuditRuleCategory, number>> = {
  security: 1.5,
  ipc: 1.5,
  abi: 1.4,
  geometry: 1.25,
  workflow: 1.2,
  governance: 1.15,
  network: 1.15,
  runtime: 1.15,
  brand: 1.1,
  docs: 1.0,
  telemetry: 1.0,
  custom: 1.0,
};

const OUTPUT_FILENAMES = new Set<string>([
  'latest.json',
  'failures-by-rule.json',
  'ratification-receipt.json',
  'runs.jsonl',
]);

const HOLO_CI_GUARD_META: Readonly<
  Record<
    string,
    {
      readonly ruleId: string;
      readonly severity: AuditRuleSeverity;
      readonly category: AuditRuleCategory;
      readonly autofixable: boolean;
      readonly remediationCmd: string;
    }
  >
> = {
  zeroGhost: {
    ruleId: 'holo.brand.zero-ghost',
    severity: 'error',
    category: 'brand',
    autofixable: false,
    remediationCmd: '.\\bin\\holo-ci.ps1 verify',
  },
  zeroCasV1: {
    ruleId: 'holo.governance.zero-cas-v1',
    severity: 'error',
    category: 'governance',
    autofixable: false,
    remediationCmd: '.\\bin\\holo-ci.ps1 verify',
  },
  zeroHttpIpc: {
    ruleId: 'B8G016',
    severity: 'error',
    category: 'ipc',
    autofixable: false,
    remediationCmd: '.\\bin\\holo-ci.ps1 boundary-audit --boundary boundary.json --min-score 100',
  },
  spdxLicense: {
    ruleId: 'holo.governance.spdx-license',
    severity: 'error',
    category: 'governance',
    autofixable: true,
    remediationCmd: '.\\bin\\holo-ci.ps1 verify',
  },
  gitattributes: {
    ruleId: 'holo.governance.gitattributes',
    severity: 'error',
    category: 'governance',
    autofixable: true,
    remediationCmd: '.\\bin\\holo-ci.ps1 verify',
  },
  codeowners: {
    ruleId: 'holo.governance.codeowners',
    severity: 'error',
    category: 'governance',
    autofixable: true,
    remediationCmd: '.\\bin\\holo-ci.ps1 verify',
  },
  noBrokenBadges: {
    ruleId: 'holo.docs.no-broken-badges',
    severity: 'warning',
    category: 'docs',
    autofixable: true,
    remediationCmd: '.\\bin\\holo-ci.ps1 verify',
  },
  noWorkflowBloat: {
    ruleId: 'holo.workflow.no-bloat',
    severity: 'error',
    category: 'workflow',
    autofixable: false,
    remediationCmd: '.\\bin\\node.ps1 github-mirror/awesome-os/maintenance-workflows/holo-ci/wf-harden.mts --check',
  },
  requireWorkflowHardening: {
    ruleId: 'holo.workflow.hardening',
    severity: 'error',
    category: 'workflow',
    autofixable: true,
    remediationCmd: '.\\bin\\node.ps1 github-mirror/awesome-os/maintenance-workflows/holo-ci/wf-harden.mts --fix',
  },
};

const HOLO_CI_BOUNDARY_META: Readonly<
  Record<
    string,
    {
      readonly ruleId: string;
      readonly category: AuditRuleCategory;
    }
  >
> = {
  boundaryManifest: { ruleId: 'holo.geometry.boundary-manifest', category: 'governance' },
  forbiddenImport: { ruleId: 'holo.geometry.forbidden-import', category: 'geometry' },
  parentTraversal: { ruleId: 'holo.geometry.parent-traversal', category: 'geometry' },
  httpIpc: { ruleId: 'B8G016', category: 'ipc' },
  abiGolden: { ruleId: 'holo.abi.golden', category: 'abi' },
  cyclicImport: { ruleId: 'holo.geometry.cyclic-import', category: 'geometry' },
  layerInversion: { ruleId: 'holo.geometry.layer-inversion', category: 'geometry' },
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function asString(value: unknown, fallback = ''): string {
  return typeof value === 'string' && value.trim().length > 0 ? value.trim() : fallback;
}

function asFiniteNumber(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

function asCount(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return Math.max(0, Math.trunc(value));
  }
  if (Array.isArray(value)) {
    return value.length;
  }
  return undefined;
}

function normalizeSeverity(value: unknown, fallback: AuditRuleSeverity = 'error'): AuditRuleSeverity {
  if (typeof value === 'string') {
    const lower = value.toLowerCase();
    if (VALID_SEVERITIES.has(lower as AuditRuleSeverity)) {
      return lower as AuditRuleSeverity;
    }
    if (lower === 'critical' || lower === 'high' || lower === 'fail') return 'error';
    if (lower === 'medium' || lower === 'warn') return 'warning';
    if (lower === 'low') return 'info';
  }
  return fallback;
}

function normalizeCategory(value: unknown, fallback: AuditRuleCategory = 'custom'): AuditRuleCategory {
  if (typeof value === 'string') {
    const lower = value.toLowerCase();
    if (VALID_CATEGORIES.has(lower as AuditRuleCategory)) {
      return lower as AuditRuleCategory;
    }
    if (lower === 'parity' || lower === 'boundary' || lower === 'assets' || lower === 'sync') {
      return 'governance';
    }
    if (lower === 'rollback') return 'runtime';
    if (lower === 'sla' || lower === 'endpoint') return 'network';
  }
  return fallback;
}

function normalizePosixPath(filePath: string): string {
  return filePath.replace(/\\/g, '/');
}

function inferRepoFromSource(sourceLabel: string): string {
  const norm = normalizePosixPath(sourceLabel);
  const mirrorMatch = norm.match(/github-mirror\/awesome-os\/([A-Za-z0-9_.-]+)/);
  if (mirrorMatch && mirrorMatch[1]) return mirrorMatch[1];
  const allMatches = [...norm.matchAll(/awesome-os\/([A-Za-z0-9_.-]+)/g)];
  for (let i = allMatches.length - 1; i >= 0; i--) {
    const candidate = allMatches[i]?.[1];
    if (candidate && candidate !== 'github-mirror') return candidate;
  }
  return 'awesome-os';
}

function defaultRemediationForRule(ruleId: string, category: AuditRuleCategory): string {
  if (ruleId === 'B8G016' || category === 'ipc') {
    return '.\\bin\\holo-ci.ps1 boundary-audit --boundary boundary.json --min-score 100';
  }
  if (category === 'geometry') {
    return '.\\bin\\node.ps1 scripts/project-geometry.mts --check --json';
  }
  if (category === 'workflow') {
    return '.\\bin\\node.ps1 github-mirror/awesome-os/maintenance-workflows/holo-ci/wf-harden.mts --fix';
  }
  if (category === 'network' && ruleId.startsWith('cdp.')) {
    return '.\\bin\\node.ps1 github-mirror/awesome-os/holo-v11/scripts/cdp-network-audit.mts --suite all --check-links';
  }
  if (category === 'abi') {
    return '.\\bin\\node.ps1 scripts/regression-watch.mts --json';
  }
  return '.\\bin\\holo-ci.ps1 verify';
}

function defaultRollbackForRule(category: AuditRuleCategory): string {
  if (category === 'ipc' || category === 'security' || category === 'abi') {
    return `Hold promotion and run ${DEFAULT_ROLLBACK_COMMAND}`;
  }
  return DEFAULT_ROLLBACK_COMMAND;
}

/**
 * Computes a deterministic 16-char lowercase hex SHA-256 fingerprint compatible with `holo-rule-violation.v1`.
 */
export function computeAuditViolationFingerprint(
  ruleId: string,
  repo: string,
  file: string,
  message: string,
): string {
  const normalizedFile = normalizePosixPath(file);
  return createHash('sha256')
    .update(`${ruleId}\0${repo}\0${normalizedFile}\0${message}`, 'utf8')
    .digest('hex')
    .slice(0, 16);
}

/**
 * Computes deterministic SHA-512 over any JSON-serializable payload with recursively sorted keys.
 */
export function computeCanonicalSha512(value: unknown): string {
  const canonicalize = (v: unknown): unknown => {
    if (Array.isArray(v)) {
      return v.map(canonicalize);
    }
    if (isRecord(v)) {
      const sorted: Record<string, unknown> = {};
      for (const key of Object.keys(v).sort()) {
        if (v[key] !== undefined) {
          sorted[key] = canonicalize(v[key]);
        }
      }
      return sorted;
    }
    return v;
  };
  return createHash('sha512').update(JSON.stringify(canonicalize(value)), 'utf8').digest('hex');
}

function makeViolation(input: {
  readonly ruleId: string;
  readonly severity: AuditRuleSeverity;
  readonly category: AuditRuleCategory;
  readonly repo: string;
  readonly file: string;
  readonly line?: number;
  readonly snippet?: string;
  readonly message: string;
  readonly autofixable?: boolean;
  readonly fingerprint?: string;
  readonly source: string;
  readonly timestamp: string;
  readonly remediationCmd?: string;
  readonly rollbackHint?: string;
}): AuditViolationRecord {
  const file = normalizePosixPath(input.file || 'unknown');
  const line =
    typeof input.line === 'number' && Number.isFinite(input.line) && input.line > 0
      ? Math.trunc(input.line)
      : 1;
  const snippet = (input.snippet ?? input.message).slice(0, 160);
  const providedFp =
    typeof input.fingerprint === 'string' && /^[a-f0-9]{12,64}$/i.test(input.fingerprint.trim())
      ? input.fingerprint.trim().toLowerCase()
      : undefined;
  const fingerprint =
    providedFp ?? computeAuditViolationFingerprint(input.ruleId, input.repo, file, input.message);

  return {
    schema: HOLO_RULE_VIOLATION_SCHEMA,
    ruleId: input.ruleId,
    severity: input.severity,
    category: input.category,
    repo: input.repo,
    file,
    line,
    snippet,
    message: input.message,
    autofixable: Boolean(input.autofixable),
    fingerprint,
    source: input.source,
    timestamp: input.timestamp,
    remediationCmd: input.remediationCmd || defaultRemediationForRule(input.ruleId, input.category),
    rollbackHint: input.rollbackHint || defaultRollbackForRule(input.category),
  };
}

function parseRawInput(raw: unknown): readonly unknown[] {
  if (typeof raw !== 'string') {
    if (Array.isArray(raw)) return raw;
    return [raw];
  }
  const trimmed = raw.trim();
  if (!trimmed) return [];
  try {
    const parsed: unknown = JSON.parse(trimmed);
    return Array.isArray(parsed) ? parsed : [parsed];
  } catch {
    // Parse as JSONL / NDJSON lines
    const items: unknown[] = [];
    const lines = trimmed.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!.trim();
      if (!line || line.startsWith('#')) continue;
      try {
        items.push(JSON.parse(line));
      } catch (err) {
        throw new Error(
          `Failed to parse JSONL line ${i + 1}: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }
    return items;
  }
}

interface MutableSignals {
  geometryScore?: number;
  coreSccs?: number;
  coreLayerInversions?: number;
  httpIpcUnits?: number;
  boundaryScore?: number;
  cnameViolations?: number;
  rollbackContractOk?: boolean;
}

function mergeSignalsInto(target: MutableSignals, next: ObservedRatchetSignals): void {
  if (next.geometryScore !== undefined) {
    target.geometryScore =
      target.geometryScore === undefined
        ? next.geometryScore
        : Math.min(target.geometryScore, next.geometryScore);
  }
  if (next.coreSccs !== undefined) {
    target.coreSccs =
      target.coreSccs === undefined ? next.coreSccs : Math.max(target.coreSccs, next.coreSccs);
  }
  if (next.coreLayerInversions !== undefined) {
    target.coreLayerInversions =
      target.coreLayerInversions === undefined
        ? next.coreLayerInversions
        : Math.max(target.coreLayerInversions, next.coreLayerInversions);
  }
  if (next.httpIpcUnits !== undefined) {
    target.httpIpcUnits =
      target.httpIpcUnits === undefined
        ? next.httpIpcUnits
        : Math.max(target.httpIpcUnits, next.httpIpcUnits);
  }
  if (next.boundaryScore !== undefined) {
    target.boundaryScore =
      target.boundaryScore === undefined
        ? next.boundaryScore
        : Math.min(target.boundaryScore, next.boundaryScore);
  }
  if (next.cnameViolations !== undefined) {
    target.cnameViolations =
      target.cnameViolations === undefined
        ? next.cnameViolations
        : Math.max(target.cnameViolations, next.cnameViolations);
  }
  if (next.rollbackContractOk !== undefined) {
    target.rollbackContractOk =
      target.rollbackContractOk === undefined
        ? next.rollbackContractOk
        : target.rollbackContractOk && next.rollbackContractOk;
  }
}

function isProjectGeometryLike(obj: Record<string, unknown>): boolean {
  if (obj.schema === PROJECT_GEOMETRY_SCHEMA) return true;
  if (isRecord(obj.rating) && isRecord(obj.topology) && typeof obj.rating.totalScore === 'number') {
    return true;
  }
  return false;
}

function ingestSingleObject(
  obj: Record<string, unknown>,
  sourceLabel: string,
  defaultTimestamp: string,
  schemasDetected: Set<string>,
  gates: AuditGateSummary[],
  violations: AuditViolationRecord[],
  signals: MutableSignals,
): void {
  const schema = asString(obj.schema, '');
  const defaultRepo = inferRepoFromSource(sourceLabel);

  // 1. holo-rule-violation.v1 (single violation or envelope with violations[])
  if (schema === HOLO_RULE_VIOLATION_SCHEMA) {
    schemasDetected.add(HOLO_RULE_VIOLATION_SCHEMA);
    const items: Record<string, unknown>[] = Array.isArray(obj.violations)
      ? obj.violations.filter(isRecord)
      : [obj];
    let errorCount = 0;
    let ipcCount = 0;
    let cnameCount = 0;
    for (const item of items) {
      const ruleId = asString(item.ruleId, 'holo.rule.unknown');
      const severity = normalizeSeverity(item.severity, 'error');
      const category = normalizeCategory(item.category, 'governance');
      const repo = asString(item.repo, defaultRepo);
      const file = asString(item.file, sourceLabel);
      const message = asString(item.message, `${ruleId} violation in ${file}`);
      const rec = makeViolation({
        ruleId,
        severity,
        category,
        repo,
        file,
        line: asFiniteNumber(item.line),
        snippet: asString(item.snippet, message),
        message,
        autofixable: Boolean(item.autofixable),
        fingerprint: asString(item.fingerprint, '') || undefined,
        source: sourceLabel,
        timestamp: asString(item.timestamp, defaultTimestamp),
        remediationCmd: asString(item.remediationCmd, '') || undefined,
        rollbackHint: asString(item.rollbackHint, '') || undefined,
      });
      violations.push(rec);
      if (rec.severity === 'error') errorCount++;
      if (rec.ruleId === 'B8G016' || rec.category === 'ipc') ipcCount++;
      if (/cname/i.test(rec.ruleId)) cnameCount++;
    }
    if (ipcCount > 0) mergeSignalsInto(signals, { httpIpcUnits: ipcCount });
    if (cnameCount > 0) mergeSignalsInto(signals, { cnameViolations: cnameCount });
    gates.push({
      auditId: `rule-violation:${sourceLabel}`,
      schema: HOLO_RULE_VIOLATION_SCHEMA,
      source: sourceLabel,
      repo: asString(obj.repo, defaultRepo),
      ok: errorCount === 0,
      durationMs: asFiniteNumber(obj.durationMs) ?? 0,
      timestamp: asString(obj.timestamp, defaultTimestamp),
      violationCount: items.length,
    });
    return;
  }

  // 2. holo-failure-telemetry.v1 (single JSONL line OR summary doc with records[])
  if (schema === HOLO_FAILURE_TELEMETRY_SCHEMA) {
    schemasDetected.add(HOLO_FAILURE_TELEMETRY_SCHEMA);
    const records: Record<string, unknown>[] = Array.isArray(obj.records)
      ? obj.records.filter(isRecord)
      : [obj];
    let rollbackFailed = false;
    for (const r of records) {
      const gateId = asString(r.gateId, 'unknown-gate');
      const rawCat = asString(r.category, 'custom');
      const category = normalizeCategory(rawCat, 'custom');
      const ruleId =
        gateId.startsWith('B8G') || gateId.startsWith('holo.') ? gateId : `fast-fail.${gateId}`;
      const repo = asString(r.repo, defaultRepo);
      const summary = asString(r.summary, `Gate ${gateId} failed`);
      if (rawCat.toLowerCase() === 'rollback' || /rollback/i.test(gateId)) {
        rollbackFailed = true;
      }
      violations.push(
        makeViolation({
          ruleId,
          severity: 'error',
          category,
          repo,
          file: `gate:${gateId}`,
          line: 1,
          snippet: summary,
          message: summary,
          autofixable: false,
          fingerprint: asString(r.fingerprint, '') || undefined,
          source: sourceLabel,
          timestamp: asString(r.timestamp, defaultTimestamp),
          remediationCmd: asString(r.remediationCmd, '') || undefined,
          rollbackHint: asString(r.rollbackHint, '') || undefined,
        }),
      );
    }
    if (rollbackFailed) {
      mergeSignalsInto(signals, { rollbackContractOk: false });
    }
    gates.push({
      auditId: `failure-telemetry:${asString(obj.gateId, sourceLabel)}`,
      schema: HOLO_FAILURE_TELEMETRY_SCHEMA,
      source: sourceLabel,
      repo: asString(obj.repo, defaultRepo),
      ok: records.length === 0,
      durationMs: asFiniteNumber(obj.durationMs) ?? 0,
      timestamp: asString(obj.timestamp, defaultTimestamp),
      violationCount: records.length,
    });
    return;
  }

  // 3. b8g.fast-fail-gate.v1
  if (schema === FAST_FAIL_GATE_SCHEMA) {
    schemasDetected.add(FAST_FAIL_GATE_SCHEMA);
    const ts = asString(obj.timestamp, defaultTimestamp);
    const gateList = Array.isArray(obj.gates) ? obj.gates.filter(isRecord) : [];
    let failedViolations = 0;
    for (const g of gateList) {
      const gateId = asString(g.id, 'unknown-gate');
      const status = asString(g.status, 'fail');
      const rawCat = asString(g.category, 'custom');
      if (rawCat.toLowerCase() === 'rollback' || /rollback/i.test(gateId)) {
        if (status === 'pass') mergeSignalsInto(signals, { rollbackContractOk: true });
        if (status === 'fail') mergeSignalsInto(signals, { rollbackContractOk: false });
      }
      if (status === 'fail') {
        const category = normalizeCategory(rawCat, 'custom');
        const ruleId =
          gateId.startsWith('B8G') || gateId.startsWith('holo.') ? gateId : `fast-fail.${gateId}`;
        const summary = asString(g.summary, `${asString(g.label, gateId)} failed`);
        failedViolations++;
        violations.push(
          makeViolation({
            ruleId,
            severity: 'error',
            category,
            repo: defaultRepo,
            file: `gate:${gateId}`,
            line: 1,
            snippet: summary,
            message: summary,
            autofixable: false,
            source: sourceLabel,
            timestamp: ts,
            remediationCmd: asString(g.remediationCmd, '') || undefined,
            rollbackHint: asString(g.rollbackHint, '') || undefined,
          }),
        );
      }
    }
    const counts = isRecord(obj.counts) ? obj.counts : {};
    gates.push({
      auditId: 'fast-fail-gate',
      schema: FAST_FAIL_GATE_SCHEMA,
      source: sourceLabel,
      repo: defaultRepo,
      ok: obj.ok === true && failedViolations === 0,
      durationMs: asFiniteNumber(obj.totalDurationMs) ?? 0,
      timestamp: ts,
      violationCount: failedViolations,
      metrics: {
        total: asFiniteNumber(counts.total) ?? gateList.length,
        passed: asFiniteNumber(counts.passed) ?? 0,
        failed: asFiniteNumber(counts.failed) ?? failedViolations,
        aborted: asFiniteNumber(counts.aborted) ?? 0,
        skipped: asFiniteNumber(counts.skipped) ?? 0,
      },
    });
    return;
  }

  // 4. holo-ci.receipt.v1
  if (schema === HOLO_CI_RECEIPT_SCHEMA) {
    schemasDetected.add(HOLO_CI_RECEIPT_SCHEMA);
    const phase = asString(obj.phase, 'verify');
    const repo = asString(obj.name, defaultRepo);
    const ts = asString(obj.generatedAt, defaultTimestamp);
    const beforeLen = violations.length;
    const metrics: Record<string, number | boolean | string> = { phase };

    if (isRecord(obj.verify)) {
      const guardViolations = Array.isArray(obj.verify.guardViolations)
        ? obj.verify.guardViolations.filter(isRecord)
        : [];
      let ipcHits = 0;
      for (const gv of guardViolations) {
        const guardName = asString(gv.guard, 'unknown');
        const meta = HOLO_CI_GUARD_META[guardName] ?? {
          ruleId: `holo.guard.${guardName}`,
          severity: 'error' as AuditRuleSeverity,
          category: 'governance' as AuditRuleCategory,
          autofixable: false,
          remediationCmd: '.\\bin\\holo-ci.ps1 verify',
        };
        if (meta.ruleId === 'B8G016') ipcHits++;
        const snippet = asString(gv.snippet, `Guard violation: ${guardName}`);
        violations.push(
          makeViolation({
            ruleId: meta.ruleId,
            severity: meta.severity,
            category: meta.category,
            repo,
            file: asString(gv.file, sourceLabel),
            line: asFiniteNumber(gv.line),
            snippet,
            message: `${meta.ruleId}: ${snippet}`,
            autofixable: meta.autofixable,
            source: sourceLabel,
            timestamp: ts,
            remediationCmd: meta.remediationCmd,
          }),
        );
      }
      if (ipcHits > 0) mergeSignalsInto(signals, { httpIpcUnits: ipcHits });

      const checkCommands = [
        ...(Array.isArray(obj.verify.tests) ? obj.verify.tests.filter(isRecord) : []),
        ...(Array.isArray(obj.verify.nativeGates) ? obj.verify.nativeGates.filter(isRecord) : []),
      ];
      for (const cmd of checkCommands) {
        if (cmd.ok === false) {
          const kind = asString(cmd.kind, 'test');
          const commandStr = asString(cmd.command, 'unknown-command');
          violations.push(
            makeViolation({
              ruleId: kind === 'nativeGate' ? 'holo.ci.native-gate-failure' : 'holo.ci.test-failure',
              severity: 'error',
              category: 'runtime',
              repo,
              file: commandStr,
              line: 1,
              snippet: asString(cmd.stderr, asString(cmd.stdout, `Exit ${String(cmd.exitCode ?? 1)}`)),
              message: `${kind} failed (exit ${String(cmd.exitCode ?? 1)}): ${commandStr}`,
              autofixable: false,
              source: sourceLabel,
              timestamp: ts,
              remediationCmd: commandStr,
            }),
          );
        }
      }

      const docs = Array.isArray(obj.verify.docs) ? obj.verify.docs.filter(isRecord) : [];
      for (const d of docs) {
        if (d.exists === false) {
          const docPath = asString(d.path, 'README.md');
          violations.push(
            makeViolation({
              ruleId: 'holo.docs.missing',
              severity: 'error',
              category: 'docs',
              repo,
              file: docPath,
              line: 1,
              snippet: `Missing required doc: ${docPath}`,
              message: `Declared doc file "${docPath}" does not exist`,
              autofixable: false,
              source: sourceLabel,
              timestamp: ts,
              remediationCmd: '.\\bin\\holo-ci.ps1 verify',
            }),
          );
        }
      }
    }

    if (isRecord(obj.boundaryAudit)) {
      const score = asFiniteNumber(obj.boundaryAudit.score);
      if (score !== undefined) {
        mergeSignalsInto(signals, { boundaryScore: score });
        metrics.boundaryScore = score;
      }
      const bViolations = Array.isArray(obj.boundaryAudit.violations)
        ? obj.boundaryAudit.violations.filter(isRecord)
        : [];
      let ipcCount = 0;
      for (const bv of bViolations) {
        const ruleName = asString(bv.rule, 'boundary');
        const meta = HOLO_CI_BOUNDARY_META[ruleName] ?? {
          ruleId: `holo.geometry.${ruleName}`,
          category: 'geometry' as AuditRuleCategory,
        };
        if (meta.ruleId === 'B8G016') ipcCount++;
        const msg = asString(bv.message, `Boundary violation: ${ruleName}`);
        violations.push(
          makeViolation({
            ruleId: meta.ruleId,
            severity: 'error',
            category: meta.category,
            repo,
            file: asString(bv.file, 'boundary.json'),
            line: asFiniteNumber(bv.line),
            snippet: asString(bv.snippet, msg),
            message: msg,
            autofixable: false,
            source: sourceLabel,
            timestamp: ts,
            remediationCmd: '.\\bin\\holo-ci.ps1 boundary-audit --boundary boundary.json --min-score 100',
          }),
        );
      }
      if (ipcCount > 0) {
        mergeSignalsInto(signals, { httpIpcUnits: ipcCount });
      } else if (obj.boundaryAudit.ok === true && score === 100) {
        mergeSignalsInto(signals, { httpIpcUnits: 0 });
      }
    }

    if (isRecord(obj.wfHarden)) {
      ingestWfHardenBody(obj.wfHarden, repo, sourceLabel, ts, violations);
    }

    if (Array.isArray(obj.errors) && obj.errors.length > 0 && violations.length === beforeLen) {
      for (const errText of obj.errors) {
        const msg = asString(errText, 'holo-ci error');
        violations.push(
          makeViolation({
            ruleId: `holo.ci.${phase}-error`,
            severity: 'error',
            category: 'governance',
            repo,
            file: 'holo-ci.json',
            line: 1,
            snippet: msg,
            message: msg,
            autofixable: false,
            source: sourceLabel,
            timestamp: ts,
            remediationCmd: `.\\bin\\holo-ci.ps1 ${phase}`,
          }),
        );
      }
    }

    const added = violations.length - beforeLen;
    gates.push({
      auditId: `holo-ci:${phase}:${repo}`,
      schema: HOLO_CI_RECEIPT_SCHEMA,
      source: sourceLabel,
      repo,
      ok: obj.ok === true,
      durationMs: asFiniteNumber(obj.durationMs) ?? 0,
      timestamp: ts,
      violationCount: added,
      metrics,
    });
    return;
  }

  // 4b. Direct wf-harden.mts --json output (`holo-ci.wf-harden.v1`)
  if (schema === HOLO_CI_WF_HARDEN_SCHEMA) {
    schemasDetected.add(HOLO_CI_WF_HARDEN_SCHEMA);
    const repo = inferRepoFromSource(asString(obj.repoDir, sourceLabel));
    const beforeLen = violations.length;
    ingestWfHardenBody(obj, repo, sourceLabel, defaultTimestamp, violations);
    gates.push({
      auditId: `wf-harden:${repo}`,
      schema: HOLO_CI_WF_HARDEN_SCHEMA,
      source: sourceLabel,
      repo,
      ok: obj.ok === true && violations.length === beforeLen,
      durationMs: 0,
      timestamp: defaultTimestamp,
      violationCount: violations.length - beforeLen,
      metrics: {
        workflowsScanned: asFiniteNumber(obj.workflowsScanned) ?? 0,
        remainingFindings: asFiniteNumber(obj.remainingFindings) ?? violations.length - beforeLen,
      },
    });
    return;
  }

  // 5. awesome-os.regression-ledger.v1
  if (schema === REGRESSION_LEDGER_SCHEMA) {
    schemasDetected.add(REGRESSION_LEDGER_SCHEMA);
    const ts = asString(obj.generatedAt, defaultTimestamp);
    const findings = Array.isArray(obj.findings) ? obj.findings.filter(isRecord) : [];
    let cnameHits = 0;
    for (const f of findings) {
      const fCat = asString(f.category, 'governance');
      const fRule = asString(f.rule, 'regression');
      const ruleId = `regression.${fCat}.${fRule}`;
      if (/cname/i.test(fRule)) cnameHits++;
      const repo = asString(f.repo, defaultRepo);
      const file = asString(f.file, asString(f.url, asString(f.alertKey, sourceLabel)));
      const msg = asString(f.message, `Regression finding ${ruleId}`);
      violations.push(
        makeViolation({
          ruleId,
          severity: normalizeSeverity(f.severity, 'error'),
          category: normalizeCategory(fCat, 'governance'),
          repo,
          file,
          line: asFiniteNumber(f.line),
          snippet: msg,
          message: msg,
          autofixable: fCat === 'workflow',
          source: sourceLabel,
          timestamp: ts,
          remediationCmd: '.\\bin\\node.ps1 scripts/regression-watch.mts --json',
          rollbackHint: DEFAULT_ROLLBACK_COMMAND,
        }),
      );
    }
    if (cnameHits > 0) mergeSignalsInto(signals, { cnameViolations: cnameHits });
    gates.push({
      auditId: 'regression-watch',
      schema: REGRESSION_LEDGER_SCHEMA,
      source: sourceLabel,
      repo: defaultRepo,
      ok: obj.ok === true && findings.every((f) => normalizeSeverity(f.severity, 'error') !== 'error'),
      durationMs: 0,
      timestamp: ts,
      violationCount: findings.length,
    });
    return;
  }

  // 6. awesome-os.cdp-network-audit.v1
  if (schema === CDP_AUDIT_REPORT_SCHEMA) {
    schemasDetected.add(CDP_AUDIT_REPORT_SCHEMA);
    const ts = asString(obj.generatedAt, defaultTimestamp);
    const suite = asString(obj.suite, 'all');
    const beforeLen = violations.length;
    const pages = Array.isArray(obj.pages) ? obj.pages.filter(isRecord) : [];

    for (const page of pages) {
      const pageUrl = asString(page.url, 'unknown-page');
      const navErr = asString(page.navigationError, '');
      if (navErr) {
        violations.push(
          makeViolation({
            ruleId: 'cdp.navigation-error',
            severity: 'error',
            category: 'network',
            repo: 'awesome-os.github.io',
            file: pageUrl,
            line: 1,
            snippet: navErr,
            message: `CDP navigation error on ${pageUrl}: ${navErr}`,
            autofixable: false,
            source: sourceLabel,
            timestamp: ts,
          }),
        );
      }

      const respErrors = Array.isArray(page.responseErrors)
        ? page.responseErrors.filter(isRecord)
        : [];
      for (const re of respErrors) {
        if (re.ignored === true) continue;
        const status = asFiniteNumber(re.status) ?? 500;
        const reqUrl = asString(re.url, pageUrl);
        violations.push(
          makeViolation({
            ruleId: `cdp.http-${status}`,
            severity: 'error',
            category: 'network',
            repo: 'awesome-os.github.io',
            file: reqUrl,
            line: 1,
            snippet: `HTTP ${status} ${reqUrl}`,
            message: `HTTP ${status} while loading ${reqUrl} on ${pageUrl}`,
            autofixable: false,
            source: sourceLabel,
            timestamp: ts,
          }),
        );
      }

      const loadFails = Array.isArray(page.loadingFailed)
        ? page.loadingFailed.filter(isRecord)
        : [];
      for (const lf of loadFails) {
        const reqUrl = asString(lf.url, pageUrl);
        const errText = asString(lf.errorText, 'net::ERR_FAILED');
        violations.push(
          makeViolation({
            ruleId: 'cdp.loading-failed',
            severity: 'error',
            category: 'network',
            repo: 'awesome-os.github.io',
            file: reqUrl,
            line: 1,
            snippet: errText,
            message: `Resource load failed (${errText}) for ${reqUrl} on ${pageUrl}`,
            autofixable: false,
            source: sourceLabel,
            timestamp: ts,
          }),
        );
      }

      const runtimeExcs = Array.isArray(page.runtimeExceptions)
        ? page.runtimeExceptions.filter(isRecord)
        : [];
      for (const ex of runtimeExcs) {
        const text = asString(ex.text, 'Uncaught runtime exception');
        const exUrl = asString(ex.url, pageUrl);
        const lineNum = asFiniteNumber(ex.lineNumber);
        violations.push(
          makeViolation({
            ruleId: 'cdp.runtime-exception',
            severity: 'error',
            category: 'runtime',
            repo: 'awesome-os.github.io',
            file: exUrl,
            line: lineNum !== undefined ? lineNum + 1 : 1,
            snippet: text,
            message: `Runtime exception on ${pageUrl}: ${text}`,
            autofixable: false,
            source: sourceLabel,
            timestamp: ts,
          }),
        );
      }

      const logErrors = Array.isArray(page.logErrors) ? page.logErrors.filter(isRecord) : [];
      for (const le of logErrors) {
        const text = asString(le.text, 'Console/Log error');
        const leUrl = asString(le.url, pageUrl);
        violations.push(
          makeViolation({
            ruleId: 'cdp.console-error',
            severity: 'error',
            category: 'runtime',
            repo: 'awesome-os.github.io',
            file: leUrl,
            line: 1,
            snippet: text,
            message: `Console error on ${pageUrl}: ${text}`,
            autofixable: false,
            source: sourceLabel,
            timestamp: ts,
          }),
        );
      }
    }

    const brokenLinks = Array.isArray(obj.brokenLinks) ? obj.brokenLinks.filter(isRecord) : [];
    for (const bl of brokenLinks) {
      if (bl.ok === true) continue;
      const blUrl = asString(bl.url, 'unknown-link');
      const statusStr = bl.status != null ? String(bl.status) : asString(bl.error, 'ERR');
      violations.push(
        makeViolation({
          ruleId: 'cdp.broken-link',
          severity: 'error',
          category: 'network',
          repo: 'awesome-os.github.io',
          file: blUrl,
          line: 1,
          snippet: `Broken link [${statusStr}] ${blUrl}`,
          message: `Broken link (${statusStr}): ${blUrl}`,
          autofixable: false,
          source: sourceLabel,
          timestamp: ts,
        }),
      );
    }

    const added = violations.length - beforeLen;
    gates.push({
      auditId: `cdp-network-audit:${suite}`,
      schema: CDP_AUDIT_REPORT_SCHEMA,
      source: sourceLabel,
      repo: 'awesome-os.github.io',
      ok: obj.ok === true && added === 0,
      durationMs: 0,
      timestamp: ts,
      violationCount: added,
      metrics: {
        suite,
        pagesAudited: pages.length,
        brokenLinks: brokenLinks.length,
      },
    });
    return;
  }

  // 7. project-geometry JSON (`awesome-os.project-geometry.v1` or structural match)
  if (isProjectGeometryLike(obj)) {
    const detectedSchema = schema || PROJECT_GEOMETRY_SCHEMA;
    schemasDetected.add(detectedSchema);
    const rating = isRecord(obj.rating) ? obj.rating : {};
    const topology = isRecord(obj.topology) ? obj.topology : {};
    const totalScore = asFiniteNumber(rating.totalScore) ?? 0;

    const coreSccsRaw = topology.coreSccs ?? topology.coreStronglyConnectedComponents;
    const coreSccs = asCount(coreSccsRaw) ?? 0;

    const coreInversionsRaw = topology.coreLayerInversionsCount ?? topology.coreLayerInversions;
    const coreLayerInversions = asCount(coreInversionsRaw) ?? 0;

    const httpUnitsRaw = topology.httpIpcViolationUnits ?? topology.httpIpcViolationCount;
    const httpIpcUnits = asCount(httpUnitsRaw) ?? 0;

    mergeSignalsInto(signals, {
      geometryScore: totalScore,
      coreSccs,
      coreLayerInversions,
      httpIpcUnits,
    });

    const beforeLen = violations.length;
    if (Array.isArray(coreSccsRaw)) {
      for (const scc of coreSccsRaw) {
        const label = Array.isArray(scc) ? scc.map(String).join(' <-> ') : String(scc);
        violations.push(
          makeViolation({
            ruleId: 'holo.geometry.core-scc',
            severity: 'error',
            category: 'geometry',
            repo: defaultRepo,
            file: label,
            line: 1,
            snippet: `Core SCC cycle: ${label}`,
            message: `Core strongly connected component cycle detected: ${label}`,
            autofixable: false,
            source: sourceLabel,
            timestamp: defaultTimestamp,
          }),
        );
      }
    } else if (coreSccs > 0) {
      violations.push(
        makeViolation({
          ruleId: 'holo.geometry.core-scc',
          severity: 'error',
          category: 'geometry',
          repo: defaultRepo,
          file: 'docs/project-geometry.json',
          line: 1,
          snippet: `coreSccs=${coreSccs}`,
          message: `Project geometry reported ${coreSccs} core strongly connected component(s)`,
          autofixable: false,
          source: sourceLabel,
          timestamp: defaultTimestamp,
        }),
      );
    }

    if (Array.isArray(topology.coreLayerInversions)) {
      for (const inv of topology.coreLayerInversions) {
        if (isRecord(inv)) {
          const fromUnit = asString(inv.fromUnit, 'unknown');
          const toUnit = asString(inv.toUnit, 'unknown');
          const file = asString(inv.file, fromUnit);
          violations.push(
            makeViolation({
              ruleId: 'holo.geometry.core-layer-inversion',
              severity: 'error',
              category: 'geometry',
              repo: defaultRepo,
              file,
              line: 1,
              snippet: `${fromUnit} -> ${toUnit}`,
              message: `Core layer inversion: ${fromUnit} depends upward on ${toUnit}`,
              autofixable: false,
              source: sourceLabel,
              timestamp: defaultTimestamp,
            }),
          );
        }
      }
    } else if (coreLayerInversions > 0) {
      violations.push(
        makeViolation({
          ruleId: 'holo.geometry.core-layer-inversion',
          severity: 'error',
          category: 'geometry',
          repo: defaultRepo,
          file: 'docs/project-geometry.json',
          line: 1,
          snippet: `coreLayerInversions=${coreLayerInversions}`,
          message: `Project geometry reported ${coreLayerInversions} core layer inversion(s)`,
          autofixable: false,
          source: sourceLabel,
          timestamp: defaultTimestamp,
        }),
      );
    }

    if (Array.isArray(topology.httpIpcViolationUnits)) {
      for (const unit of topology.httpIpcViolationUnits) {
        const unitStr = String(unit);
        violations.push(
          makeViolation({
            ruleId: 'B8G016',
            severity: 'error',
            category: 'ipc',
            repo: defaultRepo,
            file: unitStr,
            line: 1,
            snippet: `B8G016 loopback HTTP IPC unit: ${unitStr}`,
            message: `B8G016 violation in unit ${unitStr}`,
            autofixable: false,
            source: sourceLabel,
            timestamp: defaultTimestamp,
          }),
        );
      }
    } else if (httpIpcUnits > 0) {
      violations.push(
        makeViolation({
          ruleId: 'B8G016',
          severity: 'error',
          category: 'ipc',
          repo: defaultRepo,
          file: 'docs/project-geometry.json',
          line: 1,
          snippet: `httpIpcViolationUnits=${httpIpcUnits}`,
          message: `Project geometry reported ${httpIpcUnits} B8G016 HTTP IPC violation unit(s)`,
          autofixable: false,
          source: sourceLabel,
          timestamp: defaultTimestamp,
        }),
      );
    }

    const added = violations.length - beforeLen;
    gates.push({
      auditId: 'project-geometry',
      schema: detectedSchema,
      source: sourceLabel,
      repo: defaultRepo,
      ok: coreSccs === 0 && coreLayerInversions === 0 && httpIpcUnits === 0 && totalScore >= 70,
      durationMs: 0,
      timestamp: defaultTimestamp,
      violationCount: added,
      metrics: {
        totalScore,
        coreSccs,
        coreLayerInversions,
        httpIpcUnits,
      },
    });
    return;
  }

  // 8. Custom programmatic push (`b8g.audit-push.v1`)
  if (schema === AUDIT_PUSH_SCHEMA) {
    schemasDetected.add(AUDIT_PUSH_SCHEMA);
    const auditId = asString(obj.auditId, `custom:${sourceLabel}`);
    const repo = asString(obj.repo, defaultRepo);
    const ts = asString(obj.timestamp, defaultTimestamp);
    const durationMs = asFiniteNumber(obj.durationMs) ?? 0;
    const rawViolations = Array.isArray(obj.violations) ? obj.violations.filter(isRecord) : [];
    const metricsObj: Record<string, number | boolean | string> = {};

    if (isRecord(obj.metrics)) {
      for (const [k, v] of Object.entries(obj.metrics)) {
        if (typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') {
          metricsObj[k] = v;
        }
      }
      const m = obj.metrics;
      const gScore = asFiniteNumber(m.geometryScore ?? m.totalScore);
      const sccs = asCount(m.coreSccs ?? m.coreStronglyConnectedComponents);
      const invs = asCount(m.coreLayerInversions);
      const ipcs = asCount(m.httpIpcUnits ?? m.httpIpcViolationUnits);
      const bScore = asFiniteNumber(m.boundaryScore);
      const cnames = asCount(m.cnameViolations);
      const rbOk =
        typeof m.rollbackContractOk === 'boolean'
          ? m.rollbackContractOk
          : typeof m.rollbackOk === 'boolean'
            ? m.rollbackOk
            : undefined;
      mergeSignalsInto(signals, {
        ...(gScore !== undefined ? { geometryScore: gScore } : {}),
        ...(sccs !== undefined ? { coreSccs: sccs } : {}),
        ...(invs !== undefined ? { coreLayerInversions: invs } : {}),
        ...(ipcs !== undefined ? { httpIpcUnits: ipcs } : {}),
        ...(bScore !== undefined ? { boundaryScore: bScore } : {}),
        ...(cnames !== undefined ? { cnameViolations: cnames } : {}),
        ...(rbOk !== undefined ? { rollbackContractOk: rbOk } : {}),
      });
    }

    let cnameHits = 0;
    let ipcHits = 0;
    for (const v of rawViolations) {
      const ruleId = asString(v.ruleId, `custom.${auditId}`);
      const category = normalizeCategory(v.category, 'custom');
      const severity = normalizeSeverity(v.severity, 'error');
      const file = asString(v.file, sourceLabel);
      const message = asString(v.message, `${ruleId} failed in ${repo}`);
      if (ruleId === 'B8G016' || category === 'ipc') ipcHits++;
      if (/cname/i.test(ruleId)) cnameHits++;
      violations.push(
        makeViolation({
          ruleId,
          severity,
          category,
          repo: asString(v.repo, repo),
          file,
          line: asFiniteNumber(v.line),
          snippet: asString(v.snippet, message),
          message,
          autofixable: Boolean(v.autofixable),
          fingerprint: asString(v.fingerprint, '') || undefined,
          source: sourceLabel,
          timestamp: asString(v.timestamp, ts),
          remediationCmd: asString(v.remediationCmd, '') || undefined,
          rollbackHint: asString(v.rollbackHint, '') || undefined,
        }),
      );
    }
    if (ipcHits > 0) mergeSignalsInto(signals, { httpIpcUnits: ipcHits });
    if (cnameHits > 0) mergeSignalsInto(signals, { cnameViolations: cnameHits });

    gates.push({
      auditId,
      schema: AUDIT_PUSH_SCHEMA,
      source: sourceLabel,
      repo,
      ok: obj.ok === true,
      durationMs,
      timestamp: ts,
      violationCount: rawViolations.length,
      ...(Object.keys(metricsObj).length > 0 ? { metrics: metricsObj } : {}),
    });
    return;
  }

  throw new Error(
    `Unsupported audit payload schema "${schema || '(missing schema)'}" from "${sourceLabel}"`,
  );
}

function ingestWfHardenBody(
  wfHarden: Record<string, unknown>,
  repo: string,
  sourceLabel: string,
  timestamp: string,
  violations: AuditViolationRecord[],
): void {
  const files = Array.isArray(wfHarden.files) ? wfHarden.files.filter(isRecord) : [];
  for (const f of files) {
    const fileFindings = Array.isArray(f.remainingFindings)
      ? f.remainingFindings.filter(isRecord)
      : Array.isArray(f.findings)
        ? f.findings.filter(isRecord)
        : [];
    for (const finding of fileFindings) {
      const rule = asString(finding.rule, 'hardening');
      const file = asString(finding.file, asString(f.fileName, '.github/workflows'));
      const msg = asString(finding.message, `Workflow hardening finding: ${rule}`);
      violations.push(
        makeViolation({
          ruleId: `holo.workflow.${rule}`,
          severity: normalizeSeverity(finding.severity, 'warning'),
          category: 'workflow',
          repo,
          file,
          line: asFiniteNumber(finding.line),
          snippet: asString(finding.snippet, msg),
          message: msg,
          autofixable: true,
          source: sourceLabel,
          timestamp,
          remediationCmd:
            '.\\bin\\node.ps1 github-mirror/awesome-os/maintenance-workflows/holo-ci/wf-harden.mts --fix',
        }),
      );
    }
  }
}

/**
 * Universally ingests and normalizes any supported Awesome-OS audit payload (object, array, or JSON/JSONL text).
 */
export function ingestAuditPayload(
  raw: unknown,
  sourceLabel = 'inline',
  timestamp: string = new Date().toISOString(),
): IngestedAuditResult {
  const items = parseRawInput(raw);
  const schemasDetected = new Set<string>();
  const gates: AuditGateSummary[] = [];
  const violations: AuditViolationRecord[] = [];
  const signals: MutableSignals = {};

  for (const item of items) {
    if (!isRecord(item)) {
      throw new Error(`Expected JSON object in audit payload "${sourceLabel}"`);
    }
    ingestSingleObject(item, sourceLabel, timestamp, schemasDetected, gates, violations, signals);
  }

  return {
    source: sourceLabel,
    schemasDetected: [...schemasDetected].sort(),
    gates,
    violations,
    signals,
  };
}

/**
 * Merges multiple `IngestedAuditResult` objects into one unified batch.
 */
export function mergeIngestedAudits(results: readonly IngestedAuditResult[]): IngestedAuditResult {
  const schemas = new Set<string>();
  const gates: AuditGateSummary[] = [];
  const violations: AuditViolationRecord[] = [];
  const signals: MutableSignals = {};

  for (const r of results) {
    for (const s of r.schemasDetected) schemas.add(s);
    gates.push(...r.gates);
    violations.push(...r.violations);
    mergeSignalsInto(signals, r.signals);
  }

  return {
    source: results.map((r) => r.source).join(', ') || 'baseline',
    schemasDetected: [...schemas].sort(),
    gates,
    violations,
    signals,
  };
}

function resolveEffectiveFloors(
  previousLatest?: Pick<AuditStackSummaryDocument, 'floors'> | { readonly floors?: Partial<RatchetFloors> } | null,
  explicitFloors?: Partial<RatchetFloors>,
): RatchetFloors {
  const hasPrev = Boolean(previousLatest?.floors);
  const prevMerged: RatchetFloors = hasPrev
    ? { ...DEFAULT_RATCHET_FLOORS, ...previousLatest!.floors }
    : { ...DEFAULT_RATCHET_FLOORS };

  if (!explicitFloors) {
    return prevMerged;
  }

  if (!hasPrev) {
    return { ...DEFAULT_RATCHET_FLOORS, ...explicitFloors };
  }

  // Monotonic merge: explicit overrides can only tighten already-persisted floors, never loosen them.
  return {
    minGeometryScore:
      explicitFloors.minGeometryScore !== undefined
        ? Math.max(prevMerged.minGeometryScore, explicitFloors.minGeometryScore)
        : prevMerged.minGeometryScore,
    maxCoreSccs:
      explicitFloors.maxCoreSccs !== undefined
        ? Math.min(prevMerged.maxCoreSccs, explicitFloors.maxCoreSccs)
        : prevMerged.maxCoreSccs,
    maxCoreLayerInversions:
      explicitFloors.maxCoreLayerInversions !== undefined
        ? Math.min(prevMerged.maxCoreLayerInversions, explicitFloors.maxCoreLayerInversions)
        : prevMerged.maxCoreLayerInversions,
    maxHttpIpcUnits:
      explicitFloors.maxHttpIpcUnits !== undefined
        ? Math.min(prevMerged.maxHttpIpcUnits, explicitFloors.maxHttpIpcUnits)
        : prevMerged.maxHttpIpcUnits,
    minBoundaryScore:
      explicitFloors.minBoundaryScore !== undefined
        ? Math.max(prevMerged.minBoundaryScore, explicitFloors.minBoundaryScore)
        : prevMerged.minBoundaryScore,
    maxCnameViolations:
      explicitFloors.maxCnameViolations !== undefined
        ? Math.min(prevMerged.maxCnameViolations, explicitFloors.maxCnameViolations)
        : prevMerged.maxCnameViolations,
    requireRollbackContract:
      explicitFloors.requireRollbackContract !== undefined
        ? prevMerged.requireRollbackContract || explicitFloors.requireRollbackContract
        : prevMerged.requireRollbackContract,
  };
}

/**
 * Evaluates monotonic ratification floors against ingested audit batches and emits a
 * SHA-512 verified `b8g.ratification-receipt.v1`.
 */
export function evaluateRatification(
  ingested: IngestedAuditResult | readonly IngestedAuditResult[],
  previousLatest?: Pick<AuditStackSummaryDocument, 'floors'> | { readonly floors?: Partial<RatchetFloors> } | null,
  floors?: Partial<RatchetFloors>,
  generatedAt: string = new Date().toISOString(),
): RatificationReceipt {
  const merged = Array.isArray(ingested) ? mergeIngestedAudits(ingested) : (ingested as IngestedAuditResult);
  const previousFloors = resolveEffectiveFloors(previousLatest, floors);
  const signals = merged.signals;

  const ratchetViolations: RatchetViolation[] = [];

  if (signals.geometryScore !== undefined && signals.geometryScore < previousFloors.minGeometryScore) {
    ratchetViolations.push({
      metric: 'minGeometryScore',
      direction: 'min',
      floor: previousFloors.minGeometryScore,
      observed: signals.geometryScore,
      message: `Monotonic floor regression: geometryScore ${signals.geometryScore} < locked floor ${previousFloors.minGeometryScore}`,
      remediationCmd: '.\\bin\\node.ps1 scripts/project-geometry.mts --check --json',
    });
  }

  if (signals.coreSccs !== undefined && signals.coreSccs > previousFloors.maxCoreSccs) {
    ratchetViolations.push({
      metric: 'maxCoreSccs',
      direction: 'max',
      floor: previousFloors.maxCoreSccs,
      observed: signals.coreSccs,
      message: `Monotonic floor regression: coreSccs ${signals.coreSccs} > locked ceiling ${previousFloors.maxCoreSccs}`,
      remediationCmd: '.\\bin\\node.ps1 scripts/project-geometry.mts --check --json',
    });
  }

  if (
    signals.coreLayerInversions !== undefined &&
    signals.coreLayerInversions > previousFloors.maxCoreLayerInversions
  ) {
    ratchetViolations.push({
      metric: 'maxCoreLayerInversions',
      direction: 'max',
      floor: previousFloors.maxCoreLayerInversions,
      observed: signals.coreLayerInversions,
      message: `Monotonic floor regression: coreLayerInversions ${signals.coreLayerInversions} > locked ceiling ${previousFloors.maxCoreLayerInversions}`,
      remediationCmd: '.\\bin\\node.ps1 scripts/project-geometry.mts --check --json',
    });
  }

  if (signals.httpIpcUnits !== undefined && signals.httpIpcUnits > previousFloors.maxHttpIpcUnits) {
    ratchetViolations.push({
      metric: 'maxHttpIpcUnits',
      direction: 'max',
      floor: previousFloors.maxHttpIpcUnits,
      observed: signals.httpIpcUnits,
      message: `Monotonic floor regression: B8G016 httpIpcUnits ${signals.httpIpcUnits} > locked ceiling ${previousFloors.maxHttpIpcUnits}`,
      remediationCmd: '.\\bin\\holo-ci.ps1 boundary-audit --boundary boundary.json --min-score 100',
    });
  }

  if (signals.boundaryScore !== undefined && signals.boundaryScore < previousFloors.minBoundaryScore) {
    ratchetViolations.push({
      metric: 'minBoundaryScore',
      direction: 'min',
      floor: previousFloors.minBoundaryScore,
      observed: signals.boundaryScore,
      message: `Monotonic floor regression: boundaryScore ${signals.boundaryScore} < locked floor ${previousFloors.minBoundaryScore}`,
      remediationCmd: '.\\bin\\holo-ci.ps1 boundary-audit --boundary boundary.json --min-score 100',
    });
  }

  if (
    signals.cnameViolations !== undefined &&
    signals.cnameViolations > previousFloors.maxCnameViolations
  ) {
    ratchetViolations.push({
      metric: 'maxCnameViolations',
      direction: 'max',
      floor: previousFloors.maxCnameViolations,
      observed: signals.cnameViolations,
      message: `Monotonic floor regression: cnameViolations ${signals.cnameViolations} > locked ceiling ${previousFloors.maxCnameViolations}`,
      remediationCmd: '.\\bin\\holo-ci.ps1 verify',
    });
  }

  if (previousFloors.requireRollbackContract && signals.rollbackContractOk === false) {
    ratchetViolations.push({
      metric: 'requireRollbackContract',
      direction: 'require',
      floor: true,
      observed: false,
      message: 'Monotonic floor regression: O(1) rollback contract verification failed',
      remediationCmd: DEFAULT_ROLLBACK_COMMAND,
    });
  }

  let passedAudits = 0;
  let failedAudits = 0;
  for (const g of merged.gates) {
    if (g.ok) passedAudits++;
    else failedAudits++;
  }

  const errorViolationCount = merged.violations.filter((v) => v.severity === 'error').length;
  const ratified =
    ratchetViolations.length === 0 && failedAudits === 0 && errorViolationCount === 0;
  const action: RatificationAction = ratified ? 'PROMOTE' : 'HOLD_AND_ROLLBACK_O1';

  // Monotonically ratchet floors strictly tighter when verified clean scores beat current floors.
  const ratchetUpdates: RatchetUpdate[] = [];
  let nextFloors: RatchetFloors = previousFloors;

  if (ratified) {
    const minGeometryScore =
      signals.geometryScore !== undefined && signals.geometryScore > previousFloors.minGeometryScore
        ? signals.geometryScore
        : previousFloors.minGeometryScore;
    if (minGeometryScore !== previousFloors.minGeometryScore) {
      ratchetUpdates.push({
        metric: 'minGeometryScore',
        previous: previousFloors.minGeometryScore,
        next: minGeometryScore,
      });
    }

    const maxCoreSccs =
      signals.coreSccs !== undefined && signals.coreSccs < previousFloors.maxCoreSccs
        ? signals.coreSccs
        : previousFloors.maxCoreSccs;
    if (maxCoreSccs !== previousFloors.maxCoreSccs) {
      ratchetUpdates.push({
        metric: 'maxCoreSccs',
        previous: previousFloors.maxCoreSccs,
        next: maxCoreSccs,
      });
    }

    const maxCoreLayerInversions =
      signals.coreLayerInversions !== undefined &&
      signals.coreLayerInversions < previousFloors.maxCoreLayerInversions
        ? signals.coreLayerInversions
        : previousFloors.maxCoreLayerInversions;
    if (maxCoreLayerInversions !== previousFloors.maxCoreLayerInversions) {
      ratchetUpdates.push({
        metric: 'maxCoreLayerInversions',
        previous: previousFloors.maxCoreLayerInversions,
        next: maxCoreLayerInversions,
      });
    }

    const maxHttpIpcUnits =
      signals.httpIpcUnits !== undefined && signals.httpIpcUnits < previousFloors.maxHttpIpcUnits
        ? signals.httpIpcUnits
        : previousFloors.maxHttpIpcUnits;
    if (maxHttpIpcUnits !== previousFloors.maxHttpIpcUnits) {
      ratchetUpdates.push({
        metric: 'maxHttpIpcUnits',
        previous: previousFloors.maxHttpIpcUnits,
        next: maxHttpIpcUnits,
      });
    }

    const minBoundaryScore =
      signals.boundaryScore !== undefined && signals.boundaryScore > previousFloors.minBoundaryScore
        ? signals.boundaryScore
        : previousFloors.minBoundaryScore;
    if (minBoundaryScore !== previousFloors.minBoundaryScore) {
      ratchetUpdates.push({
        metric: 'minBoundaryScore',
        previous: previousFloors.minBoundaryScore,
        next: minBoundaryScore,
      });
    }

    const maxCnameViolations =
      signals.cnameViolations !== undefined &&
      signals.cnameViolations < previousFloors.maxCnameViolations
        ? signals.cnameViolations
        : previousFloors.maxCnameViolations;
    if (maxCnameViolations !== previousFloors.maxCnameViolations) {
      ratchetUpdates.push({
        metric: 'maxCnameViolations',
        previous: previousFloors.maxCnameViolations,
        next: maxCnameViolations,
      });
    }

    const requireRollbackContract =
      previousFloors.requireRollbackContract || signals.rollbackContractOk === true;
    if (requireRollbackContract !== previousFloors.requireRollbackContract) {
      ratchetUpdates.push({
        metric: 'requireRollbackContract',
        previous: previousFloors.requireRollbackContract,
        next: requireRollbackContract,
      });
    }

    nextFloors = {
      minGeometryScore,
      maxCoreSccs,
      maxCoreLayerInversions,
      maxHttpIpcUnits,
      minBoundaryScore,
      maxCnameViolations,
      requireRollbackContract,
    };
  }

  const unsignedReceipt = {
    schema: RATIFICATION_RECEIPT_SCHEMA,
    abiMagic: B8G_ABI_MAGIC_V3,
    generatedAt,
    ratified,
    action,
    floors: nextFloors,
    previousFloors,
    ratchetUpdates,
    ratchetViolations,
    observedSignals: signals,
    violationCount: merged.violations.length,
    errorViolationCount,
    passedAudits,
    failedAudits,
    rollbackCommand: DEFAULT_ROLLBACK_COMMAND,
  };

  const sha512 = computeCanonicalSha512(unsignedReceipt);
  return {
    ...unsignedReceipt,
    sha512,
  };
}

/**
 * Computes deterministic damped-gravity score for prioritizing recurring rule failures.
 */
export function computeFailureGravityScore(
  severity: AuditRuleSeverity,
  category: AuditRuleCategory,
  occurrences: number,
  repoCount: number,
): number {
  const baseWeight = SEVERITY_GRAVITY_WEIGHT[severity] ?? 4;
  const catMult = CATEGORY_GRAVITY_MULTIPLIER[category] ?? 1.0;
  const freqFactor = 1 + Math.log2(Math.max(1, occurrences));
  const blastRadiusFactor = 1 + 0.25 * Math.max(0, repoCount - 1);
  return Number((baseWeight * catMult * freqFactor * blastRadiusFactor).toFixed(2));
}

function higherSeverity(a: AuditRuleSeverity, b: AuditRuleSeverity): AuditRuleSeverity {
  return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;
}

/**
 * Aggregates failing telemetry across runs by deterministic SHA-256 fingerprint and ruleId,
 * accumulating occurrences, timestamps, affected repos, remediation hints, and gravity scores.
 */
export function aggregateFailuresByRule(
  violations: readonly AuditViolationRecord[],
  previousDoc?: AuditStackFailuresDocument | null,
  generatedAt: string = new Date().toISOString(),
): AuditStackFailuresDocument {
  interface MutableFpEntry {
    readonly fingerprint: string;
    readonly ruleId: string;
    severity: AuditRuleSeverity;
    readonly category: AuditRuleCategory;
    occurrences: number;
    firstSeenAt: string;
    lastSeenAt: string;
    readonly repos: Set<string>;
    readonly files: Set<string>;
    sampleMessage: string;
    remediationCmd: string;
    rollbackHint: string;
  }

  const byFp = new Map<string, MutableFpEntry>();

  if (previousDoc && Array.isArray(previousDoc.entries)) {
    for (const prev of previousDoc.entries) {
      byFp.set(prev.fingerprint, {
        fingerprint: prev.fingerprint,
        ruleId: prev.ruleId,
        severity: normalizeSeverity(prev.severity, 'error'),
        category: normalizeCategory(prev.category, 'custom'),
        occurrences: Math.max(1, Math.trunc(prev.occurrences || 1)),
        firstSeenAt: prev.firstSeenAt || generatedAt,
        lastSeenAt: prev.lastSeenAt || generatedAt,
        repos: new Set(Array.isArray(prev.repos) ? prev.repos : []),
        files: new Set(Array.isArray(prev.files) ? prev.files : []),
        sampleMessage: prev.sampleMessage || '',
        remediationCmd:
          prev.remediationCmd || defaultRemediationForRule(prev.ruleId, prev.category),
        rollbackHint: prev.rollbackHint || defaultRollbackForRule(prev.category),
      });
    }
  }

  for (const v of violations) {
    const ts = v.timestamp || generatedAt;
    const existing = byFp.get(v.fingerprint);
    if (existing) {
      existing.occurrences += 1;
      existing.severity = higherSeverity(existing.severity, v.severity);
      if (ts < existing.firstSeenAt) existing.firstSeenAt = ts;
      if (ts > existing.lastSeenAt) existing.lastSeenAt = ts;
      if (v.repo) existing.repos.add(v.repo);
      if (v.file && existing.files.size < 20) existing.files.add(v.file);
      if (v.message) existing.sampleMessage = v.message;
      if (v.remediationCmd) existing.remediationCmd = v.remediationCmd;
      if (v.rollbackHint) existing.rollbackHint = v.rollbackHint;
    } else {
      byFp.set(v.fingerprint, {
        fingerprint: v.fingerprint,
        ruleId: v.ruleId,
        severity: v.severity,
        category: v.category,
        occurrences: 1,
        firstSeenAt: ts,
        lastSeenAt: ts,
        repos: new Set(v.repo ? [v.repo] : []),
        files: new Set(v.file ? [v.file] : []),
        sampleMessage: v.message,
        remediationCmd: v.remediationCmd || defaultRemediationForRule(v.ruleId, v.category),
        rollbackHint: v.rollbackHint || defaultRollbackForRule(v.category),
      });
    }
  }

  const entries: AggregatedFailureEntry[] = [...byFp.values()]
    .map((e) => {
      const repos = [...e.repos].sort();
      const files = [...e.files].sort();
      return {
        fingerprint: e.fingerprint,
        ruleId: e.ruleId,
        severity: e.severity,
        category: e.category,
        occurrences: e.occurrences,
        firstSeenAt: e.firstSeenAt,
        lastSeenAt: e.lastSeenAt,
        repos,
        files,
        sampleMessage: e.sampleMessage,
        remediationCmd: e.remediationCmd,
        rollbackHint: e.rollbackHint,
        gravityScore: computeFailureGravityScore(e.severity, e.category, e.occurrences, repos.length),
      };
    })
    .sort(
      (a, b) =>
        b.gravityScore - a.gravityScore ||
        b.occurrences - a.occurrences ||
        a.ruleId.localeCompare(b.ruleId) ||
        a.fingerprint.localeCompare(b.fingerprint),
    );

  // Build rule-level rollup
  interface MutableRuleRollup {
    readonly ruleId: string;
    severity: AuditRuleSeverity;
    readonly category: AuditRuleCategory;
    occurrences: number;
    uniqueFingerprints: number;
    firstSeenAt: string;
    lastSeenAt: string;
    readonly repos: Set<string>;
    remediationCmd: string;
    rollbackHint: string;
    sampleMessage: string;
  }

  const ruleMap = new Map<string, MutableRuleRollup>();
  for (const e of entries) {
    const existing = ruleMap.get(e.ruleId);
    if (existing) {
      existing.occurrences += e.occurrences;
      existing.uniqueFingerprints += 1;
      existing.severity = higherSeverity(existing.severity, e.severity);
      if (e.firstSeenAt < existing.firstSeenAt) existing.firstSeenAt = e.firstSeenAt;
      if (e.lastSeenAt > existing.lastSeenAt) existing.lastSeenAt = e.lastSeenAt;
      for (const r of e.repos) existing.repos.add(r);
    } else {
      ruleMap.set(e.ruleId, {
        ruleId: e.ruleId,
        severity: e.severity,
        category: e.category,
        occurrences: e.occurrences,
        uniqueFingerprints: 1,
        firstSeenAt: e.firstSeenAt,
        lastSeenAt: e.lastSeenAt,
        repos: new Set(e.repos),
        remediationCmd: e.remediationCmd,
        rollbackHint: e.rollbackHint,
        sampleMessage: e.sampleMessage,
      });
    }
  }

  const byRule: RuleFailureRollup[] = [...ruleMap.values()]
    .map((r) => {
      const repos = [...r.repos].sort();
      return {
        ruleId: r.ruleId,
        severity: r.severity,
        category: r.category,
        occurrences: r.occurrences,
        uniqueFingerprints: r.uniqueFingerprints,
        firstSeenAt: r.firstSeenAt,
        lastSeenAt: r.lastSeenAt,
        repos,
        remediationCmd: r.remediationCmd,
        rollbackHint: r.rollbackHint,
        gravityScore: computeFailureGravityScore(r.severity, r.category, r.occurrences, repos.length),
        sampleMessage: r.sampleMessage,
      };
    })
    .sort(
      (a, b) =>
        b.gravityScore - a.gravityScore ||
        b.occurrences - a.occurrences ||
        a.ruleId.localeCompare(b.ruleId),
    );

  const totalOccurrences = entries.reduce((acc, e) => acc + e.occurrences, 0);

  return {
    schema: AUDIT_STACK_FAILURES_SCHEMA,
    abiMagic: B8G_ABI_MAGIC_V3,
    generatedAt,
    totalOccurrences,
    uniqueFingerprints: entries.length,
    uniqueRules: byRule.length,
    entries,
    byRule,
  };
}

function collectIngestFiles(ingestPaths: readonly string[], outDirResolved: string): string[] {
  const files: string[] = [];
  const seen = new Set<string>();

  const visit = (target: string): void => {
    const abs = path.resolve(target);
    if (!fs.existsSync(abs)) {
      throw new Error(`Ingest path not found: ${abs}`);
    }
    const stat = fs.statSync(abs);
    if (stat.isFile()) {
      if (
        path.dirname(abs) === outDirResolved &&
        OUTPUT_FILENAMES.has(path.basename(abs))
      ) {
        return;
      }
      if (!seen.has(abs)) {
        seen.add(abs);
        files.push(abs);
      }
      return;
    }
    if (stat.isDirectory()) {
      const entries = fs
        .readdirSync(abs, { withFileTypes: true })
        .sort((a, b) => a.name.localeCompare(b.name));
      for (const ent of entries) {
        const child = path.join(abs, ent.name);
        if (ent.isDirectory()) {
          if (ent.name === '.git' || ent.name === 'node_modules') continue;
          visit(child);
        } else if (ent.isFile() && /\.(?:json|jsonl|ndjson)$/i.test(ent.name)) {
          visit(child);
        }
      }
    }
  };

  for (const p of ingestPaths) {
    visit(p);
  }
  return files;
}

function readJsonIfExists<T>(filePath: string): T | null {
  if (!fs.existsSync(filePath)) return null;
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8')) as T;
  } catch {
    return null;
  }
}

function appendBoundedRunHistory(
  runsPath: string,
  record: AuditStackRunRecord,
  maxHistoryRuns: number,
): void {
  const existingLines: string[] = [];
  if (fs.existsSync(runsPath)) {
    const raw = fs.readFileSync(runsPath, 'utf8');
    for (const line of raw.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (trimmed.length > 0) existingLines.push(trimmed);
    }
  }
  existingLines.push(JSON.stringify(record));
  const bounded =
    existingLines.length > maxHistoryRuns
      ? existingLines.slice(existingLines.length - maxHistoryRuns)
      : existingLines;
  fs.writeFileSync(runsPath, `${bounded.join('\n')}\n`, 'utf8');
}

/**
 * Runs the full Central Audit Stack Hub pipeline:
 * ingests files/payloads -> evaluates monotonic ratification -> aggregates failures -> writes `audit-stack/*`.
 */
export function runAuditStackHub(options: RunAuditStackHubOptions = {}): RunAuditStackHubResult {
  const outDir = path.resolve(options.outDir ?? DEFAULT_OUT_DIR);
  const generatedAt = options.timestamp ?? new Date().toISOString();
  const maxHistoryRuns =
    typeof options.maxHistoryRuns === 'number' && options.maxHistoryRuns > 0
      ? Math.trunc(options.maxHistoryRuns)
      : DEFAULT_MAX_HISTORY_RUNS;

  const latestPath = path.join(outDir, 'latest.json');
  const failuresPath = path.join(outDir, 'failures-by-rule.json');
  const receiptPath = path.join(outDir, 'ratification-receipt.json');
  const runsPath = path.join(outDir, 'runs.jsonl');

  const previousLatest = readJsonIfExists<AuditStackSummaryDocument>(latestPath);
  const previousFailures = readJsonIfExists<AuditStackFailuresDocument>(failuresPath);

  const ingestedBatches: IngestedAuditResult[] = [];
  const ingestFiles = collectIngestFiles(options.ingestPaths ?? [], outDir);
  for (const filePath of ingestFiles) {
    const text = fs.readFileSync(filePath, 'utf8');
    const label = normalizePosixPath(path.relative(process.cwd(), filePath) || path.basename(filePath));
    ingestedBatches.push(ingestAuditPayload(text, label, generatedAt));
  }

  for (const p of options.payloads ?? []) {
    ingestedBatches.push(ingestAuditPayload(p.raw, p.sourceLabel, generatedAt));
  }

  const merged = mergeIngestedAudits(ingestedBatches);
  const receipt = evaluateRatification(merged, previousLatest, options.floors, generatedAt);
  const failures = aggregateFailuresByRule(merged.violations, previousFailures, generatedAt);

  const runId = `run-${generatedAt.replace(/[^0-9]/g, '').slice(0, 14)}-${receipt.sha512.slice(0, 8)}`;
  const warningViolationCount = merged.violations.filter((v) => v.severity === 'warning').length;

  const latest: AuditStackSummaryDocument = {
    schema: AUDIT_STACK_SUMMARY_SCHEMA,
    abiMagic: B8G_ABI_MAGIC_V3,
    generatedAt,
    runId,
    ratified: receipt.ratified,
    action: receipt.action,
    floors: receipt.floors,
    previousFloors: receipt.previousFloors,
    ratchetUpdates: receipt.ratchetUpdates,
    ratchetViolations: receipt.ratchetViolations,
    observedSignals: receipt.observedSignals,
    totals: {
      ingestedSources: ingestedBatches.length,
      totalAudits: merged.gates.length,
      passedAudits: receipt.passedAudits,
      failedAudits: receipt.failedAudits,
      violationCount: receipt.violationCount,
      errorViolationCount: receipt.errorViolationCount,
      warningViolationCount,
      uniqueRules: failures.uniqueRules,
      accumulatedFailureOccurrences: failures.totalOccurrences,
    },
    audits: merged.gates,
    topFailingRules: failures.byRule.slice(0, 10),
    receiptSha512: receipt.sha512,
  };

  const runRecord: AuditStackRunRecord = {
    schema: AUDIT_STACK_RUN_SCHEMA,
    runId,
    generatedAt,
    ratified: receipt.ratified,
    action: receipt.action,
    passedAudits: receipt.passedAudits,
    failedAudits: receipt.failedAudits,
    violationCount: receipt.violationCount,
    ratchetViolationCount: receipt.ratchetViolations.length,
    floors: receipt.floors,
    receiptSha512: receipt.sha512,
  };

  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(latestPath, `${JSON.stringify(latest, null, 2)}\n`, 'utf8');
  fs.writeFileSync(failuresPath, `${JSON.stringify(failures, null, 2)}\n`, 'utf8');
  fs.writeFileSync(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, 'utf8');
  appendBoundedRunHistory(runsPath, runRecord, maxHistoryRuns);

  return {
    outDir,
    latestPath,
    failuresPath,
    receiptPath,
    runsPath,
    latest,
    failures,
    receipt,
    runRecord,
  };
}

export function getHelpText(): string {
  return [
    'audit-stack-hub — Central Audit Stack Hub & Monotonic Continuous Ratification Engine',
    '',
    'Usage:',
    '  node scripts/audit-stack-hub.mts [options]',
    '',
    'Options:',
    '  --ingest <file-or-dir>  Ingest JSON/JSONL audit receipt or directory (repeatable)',
    `  --out-dir <dir>         Output directory for audit-stack artifacts (default: ${DEFAULT_OUT_DIR})`,
    '  --enforce-ratchet       Exit non-zero if ratification action is HOLD_AND_ROLLBACK_O1',
    '  --max-runs <n>          Maximum NDJSON records retained in runs.jsonl (default: 500)',
    '  --timestamp <iso>       Override ISO-8601 timestamp for deterministic runs',
    '  --json                  Emit structured JSON summary to stdout',
    '  -h, --help              Show this help message',
    '',
  ].join('\n');
}

export function parseCliArgs(argv: readonly string[]): ParsedAuditStackCliArgs {
  const ingestPaths: string[] = [];
  let outDir: string = DEFAULT_OUT_DIR;
  let enforceRatchet = false;
  let json = false;
  let help = false;
  let maxHistoryRuns = DEFAULT_MAX_HISTORY_RUNS;
  let timestamp: string | undefined;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === '--help' || arg === '-h') {
      help = true;
    } else if (arg === '--ingest' && i + 1 < argv.length) {
      ingestPaths.push(argv[++i]!);
    } else if (arg === '--out-dir' && i + 1 < argv.length) {
      outDir = argv[++i]!;
    } else if (arg === '--enforce-ratchet') {
      enforceRatchet = true;
    } else if (arg === '--json') {
      json = true;
    } else if (arg === '--max-runs' && i + 1 < argv.length) {
      const parsed = Number(argv[++i]!);
      if (!Number.isInteger(parsed) || parsed <= 0) {
        throw new Error(`Invalid --max-runs value: "${argv[i]}"`);
      }
      maxHistoryRuns = parsed;
    } else if (arg === '--timestamp' && i + 1 < argv.length) {
      timestamp = argv[++i]!;
    } else {
      throw new Error(`Unknown or incomplete argument: "${arg}"`);
    }
  }

  return {
    ingestPaths,
    outDir,
    enforceRatchet,
    json,
    help,
    maxHistoryRuns,
    ...(timestamp ? { timestamp } : {}),
  };
}

export function runAuditStackCli(argv: readonly string[]): {
  readonly exitCode: number;
  readonly result?: RunAuditStackHubResult;
} {
  const opts = parseCliArgs(argv);
  if (opts.help) {
    process.stdout.write(getHelpText());
    return { exitCode: 0 };
  }

  const result = runAuditStackHub({
    ingestPaths: opts.ingestPaths,
    outDir: opts.outDir,
    maxHistoryRuns: opts.maxHistoryRuns,
    timestamp: opts.timestamp,
  });

  if (opts.json) {
    process.stdout.write(`${JSON.stringify(result.latest, null, 2)}\n`);
  } else {
    const statusLabel = result.receipt.ratified ? 'RATIFIED (PROMOTE)' : 'HOLD_AND_ROLLBACK_O1';
    process.stdout.write(
      `[audit-stack-hub] ${statusLabel} | audits=${result.receipt.passedAudits}/${result.latest.totals.totalAudits} ` +
        `violations=${result.receipt.violationCount} ratchetViolations=${result.receipt.ratchetViolations.length} ` +
        `sha512=${result.receipt.sha512.slice(0, 16)}...\n`,
    );
    for (const rv of result.receipt.ratchetViolations) {
      process.stdout.write(`  [RATCHET BREACH] ${rv.message}\n`);
    }
  }

  const exitCode = opts.enforceRatchet && !result.receipt.ratified ? 1 : 0;
  return { exitCode, result };
}

const isDirectEntry =
  typeof process.argv[1] === 'string' &&
  path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url));

if (isDirectEntry || (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href)) {
  try {
    const { exitCode } = runAuditStackCli(process.argv.slice(2));
    process.exitCode = exitCode;
  } catch (err) {
    process.stderr.write(
      `[audit-stack-hub] ERROR: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    process.exitCode = 1;
  }
}
