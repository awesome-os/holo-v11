#!/usr/bin/env node
/**
 * @file cdp-network-audit.mts
 * @description Zero-dependency Chrome DevTools Protocol (CDP) network, console,
 * runtime-exception, and DOM link auditor communicating strictly over
 * `--remote-debugging-pipe` (`stdio[3]` write, `stdio[4]` read, `\0`-delimited
 * JSON-RPC). Complies with B8G016 (zero loopback HTTP IPC) and the Sectium
 * Host Device Boundary (resolves system/CI Chrome/Chromium/Edge; never spawns
 * `sectium.exe`).
 *
 * Strictly `erasableSyntaxOnly: true`, Node 24/26 built-ins only, `shell: false`.
 */

import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, posix, resolve, win32 } from 'node:path';
import type { Readable, Writable } from 'node:stream';
import { fileURLToPath } from 'node:url';

export type AuditSuiteName = 'all' | 'pages' | 'packages' | 'cas';

export const DEFAULT_AUDIT_SUITES: {
  readonly pages: readonly string[];
  readonly packages: readonly string[];
  readonly cas: readonly string[];
} = {
  pages: [
    'https://awesome-os.github.io/',
    'https://awesome-os.github.io/demos/',
    'https://awesome-os.github.io/demos/arch/pdp11/',
    'https://awesome-os.github.io/demos/arch/task-manager/',
    'https://awesome-os.github.io/demos/arch/graphics/',
    'https://awesome-os.github.io/holo-v11/oversight.html',
    'https://awesome-os.github.io/installer/',
    'https://awesome-os.github.io/agent-platform/',
  ],
  packages: [
    'https://github.com/orgs/awesome-os/packages',
    'https://github.com/awesome-os/dockerimages/releases/tag/v11-oci-latest',
    'https://github.com/awesome-os/upstream-mirrors/releases/tag/v11-max-5os-latest',
  ],
  cas: [
    'https://awesome-os.github.io/holo-v11/cas/v11/index.json',
  ],
};

export interface CdpJsonRpcRequest {
  readonly id: number;
  readonly method: string;
  readonly params?: Record<string, unknown>;
  readonly sessionId?: string;
}

export interface CdpJsonRpcError {
  readonly code: number;
  readonly message: string;
  readonly data?: unknown;
}

export interface CdpJsonRpcResponse {
  readonly id?: number;
  readonly method?: string;
  readonly params?: Record<string, unknown>;
  readonly sessionId?: string;
  readonly result?: Record<string, unknown>;
  readonly error?: CdpJsonRpcError;
}

export interface CdpEventMessage {
  readonly method: string;
  readonly params: Record<string, unknown>;
  readonly sessionId?: string;
}

export type CdpEventListener = (event: CdpEventMessage) => void;

export interface CdpPipeTransportOptions {
  readonly writeStream: Writable;
  readonly readStream: Readable;
  readonly defaultTimeoutMs?: number;
}

export class CdpPipeTransport {
  readonly #writeStream: Writable;
  readonly #readStream: Readable;
  readonly #defaultTimeoutMs: number;
  readonly #pending = new Map<
    number,
    {
      resolve: (result: Record<string, unknown>) => void;
      reject: (err: Error) => void;
      timer: ReturnType<typeof setTimeout>;
    }
  >();
  readonly #listeners = new Set<CdpEventListener>();
  readonly #closeListeners = new Set<() => void>();
  #pendingChunks: Buffer[] = [];
  #nextId = 1;
  #closed = false;

  readonly #onData = (chunk: Buffer | string): void => {
    const buf = typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : chunk;
    this.#handleIncomingChunk(buf);
  };

  readonly #onClose = (): void => {
    this.close();
  };

  readonly #onError = (err: Error): void => {
    this.#failAllPending(err);
  };

  constructor(options: CdpPipeTransportOptions) {
    this.#writeStream = options.writeStream;
    this.#readStream = options.readStream;
    this.#defaultTimeoutMs = options.defaultTimeoutMs ?? 20_000;

    this.#readStream.on('data', this.#onData);
    this.#readStream.on('close', this.#onClose);
    this.#readStream.on('end', this.#onClose);
    this.#readStream.on('error', this.#onError);
    this.#writeStream.on('error', this.#onError);
  }

  get isClosed(): boolean {
    return this.#closed;
  }

  onEvent(listener: CdpEventListener): () => void {
    this.#listeners.add(listener);
    return () => {
      this.#listeners.delete(listener);
    };
  }

  onClose(listener: () => void): () => void {
    this.#closeListeners.add(listener);
    return () => {
      this.#closeListeners.delete(listener);
    };
  }

  sendCommand<T extends Record<string, unknown> = Record<string, unknown>>(
    method: string,
    params: Record<string, unknown> = {},
    sessionId?: string,
    timeoutMs: number = this.#defaultTimeoutMs,
  ): Promise<T> {
    if (this.#closed) {
      return Promise.reject(new Error(`CDP pipe transport is closed (attempted ${method})`));
    }
    const id = this.#nextId++;
    const frame: CdpJsonRpcRequest = sessionId
      ? { id, method, params, sessionId }
      : { id, method, params };
    const encoded = `${JSON.stringify(frame)}\0`;

    return new Promise<T>((resolveRpc, rejectRpc) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        rejectRpc(new Error(`CDP command timed out after ${timeoutMs} ms: ${method}`));
      }, timeoutMs);

      this.#pending.set(id, {
        resolve: (res) => resolveRpc(res as T),
        reject: rejectRpc,
        timer,
      });

      try {
        this.#writeStream.write(encoded, 'utf8');
      } catch (err) {
        this.#pending.delete(id);
        clearTimeout(timer);
        rejectRpc(err instanceof Error ? err : new Error(String(err)));
      }
    });
  }

  close(): void {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    this.#readStream.off('data', this.#onData);
    this.#readStream.off('close', this.#onClose);
    this.#readStream.off('end', this.#onClose);
    this.#readStream.off('error', this.#onError);
    this.#writeStream.off('error', this.#onError);

    this.#failAllPending(new Error('CDP pipe transport closed'));
    for (const listener of [...this.#closeListeners]) {
      try {
        listener();
      } catch {
        // ignore listener cleanup errors
      }
    }
  }

  #failAllPending(err: Error): void {
    for (const [id, entry] of this.#pending.entries()) {
      clearTimeout(entry.timer);
      entry.reject(err);
      this.#pending.delete(id);
    }
  }

  #handleIncomingChunk(buf: Buffer): void {
    if (this.#closed || buf.length === 0) {
      return;
    }
    this.#pendingChunks.push(buf);
    if (buf.indexOf(0) === -1) {
      return;
    }

    const combined =
      this.#pendingChunks.length === 1 ? this.#pendingChunks[0] : Buffer.concat(this.#pendingChunks);
    let start = 0;
    let nulIndex = combined.indexOf(0, start);

    while (nulIndex !== -1) {
      if (nulIndex > start) {
        const rawJson = combined.toString('utf8', start, nulIndex);
        this.#dispatchRawMessage(rawJson);
      }
      start = nulIndex + 1;
      nulIndex = combined.indexOf(0, start);
    }

    this.#pendingChunks = start < combined.length ? [combined.subarray(start)] : [];
  }

  #dispatchRawMessage(rawJson: string): void {
    let parsed: CdpJsonRpcResponse;
    try {
      parsed = JSON.parse(rawJson) as CdpJsonRpcResponse;
    } catch {
      return;
    }

    if (typeof parsed.id === 'number') {
      const pending = this.#pending.get(parsed.id);
      if (pending) {
        this.#pending.delete(parsed.id);
        clearTimeout(pending.timer);
        if (parsed.error) {
          pending.reject(
            new Error(`CDP error ${parsed.error.code}: ${parsed.error.message}`),
          );
        } else {
          pending.resolve(parsed.result ?? {});
        }
      }
      return;
    }

    if (typeof parsed.method === 'string') {
      const evt: CdpEventMessage = {
        method: parsed.method,
        params: parsed.params ?? {},
        ...(parsed.sessionId ? { sessionId: parsed.sessionId } : {}),
      };
      for (const listener of [...this.#listeners]) {
        try {
          listener(evt);
        } catch {
          // isolate listener errors
        }
      }
    }
  }
}

const OS_ESSENTIAL_ENV_KEYS = new Set([
  'ALLUSERSPROFILE',
  'APPDATA',
  'COMMONPROGRAMFILES',
  'COMMONPROGRAMFILES(X86)',
  'COMPUTERNAME',
  'COMSPEC',
  'DBUS_SESSION_BUS_ADDRESS',
  'DISPLAY',
  'DRIVERDATA',
  'HOME',
  'HOMEDRIVE',
  'HOMEPATH',
  'LANG',
  'LC_ALL',
  'LC_CTYPE',
  'LOCALAPPDATA',
  'LOGNAME',
  'NUMBER_OF_PROCESSORS',
  'OS',
  'PATH',
  'PATHEXT',
  'PROCESSOR_ARCHITECTURE',
  'PROCESSOR_IDENTIFIER',
  'PROCESSOR_LEVEL',
  'PROCESSOR_REVISION',
  'PROGRAMDATA',
  'PROGRAMFILES',
  'PROGRAMFILES(X86)',
  'PROGRAMW6432',
  'PUBLIC',
  'SHELL',
  'SYSTEMDRIVE',
  'SYSTEMROOT',
  'TEMP',
  'TMP',
  'TMPDIR',
  'TZ',
  'USER',
  'USERDOMAIN',
  'USERDOMAIN_ROAMINGPROFILE',
  'USERNAME',
  'USERPROFILE',
  'WAYLAND_DISPLAY',
  'WINDIR',
  'XDG_CACHE_HOME',
  'XDG_CONFIG_HOME',
  'XDG_DATA_HOME',
  'XDG_RUNTIME_DIR',
]);

export function buildSanitizedBrowserEnv(
  baseEnv: NodeJS.ProcessEnv = process.env,
): Record<string, string> {
  const sanitized: Record<string, string> = {};
  for (const [key, value] of Object.entries(baseEnv)) {
    if (value !== undefined && OS_ESSENTIAL_ENV_KEYS.has(key.toUpperCase())) {
      sanitized[key] = value;
    }
  }
  sanitized.GOOGLE_API_KEY = 'no';
  sanitized.GOOGLE_DEFAULT_CLIENT_ID = 'no';
  sanitized.GOOGLE_DEFAULT_CLIENT_SECRET = 'no';
  return sanitized;
}

function isProhibitedSectiumBinary(candidatePath: string): boolean {
  const base = candidatePath.split(/[\\/]/).pop()?.toLowerCase() ?? '';
  if (base === 'sectium.exe' || base === 'sectium') {
    return true;
  }
  const normalized = candidatePath.replace(/\//g, '\\').toLowerCase();
  return normalized.startsWith('d:\\sectium\\');
}

export interface ResolveBrowserBinaryOptions {
  readonly chromePath?: string;
  readonly env?: NodeJS.ProcessEnv;
  readonly platform?: NodeJS.Platform;
  readonly fileExists?: (filePath: string) => boolean;
}

export function resolveBrowserBinary(options: ResolveBrowserBinaryOptions = {}): string {
  const env = options.env ?? process.env;
  const platform = options.platform ?? process.platform;
  const fileExists = options.fileExists ?? existsSync;
  const platformJoin = platform === 'win32' ? win32.join : posix.join;

  const explicit = options.chromePath?.trim() || env.CHROME_PATH?.trim();
  if (explicit) {
    if (isProhibitedSectiumBinary(explicit)) {
      throw new Error(
        `Refusing to launch Sectium binary directly (${explicit}); sectium-host-device-boundary prohibits ad-hoc sectium.exe spawning.`,
      );
    }
    if (fileExists(explicit)) {
      return explicit;
    }
    throw new Error(`Configured CHROME_PATH binary does not exist: ${explicit}`);
  }

  const fixedCandidates: string[] = [];
  if (platform === 'win32') {
    const localAppData = env.LOCALAPPDATA ?? '';
    const programFiles = env.PROGRAMFILES ?? 'C:\\Program Files';
    const programFilesX86 = env['PROGRAMFILES(X86)'] ?? 'C:\\Program Files (x86)';
    fixedCandidates.push(
      platformJoin(programFiles, 'Google', 'Chrome', 'Application', 'chrome.exe'),
      platformJoin(programFilesX86, 'Google', 'Chrome', 'Application', 'chrome.exe'),
      ...(localAppData
        ? [platformJoin(localAppData, 'Google', 'Chrome', 'Application', 'chrome.exe')]
        : []),
      platformJoin(programFilesX86, 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
      platformJoin(programFiles, 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
      ...(localAppData
        ? [platformJoin(localAppData, 'Microsoft', 'Edge', 'Application', 'msedge.exe')]
        : []),
    );
  } else if (platform === 'darwin') {
    fixedCandidates.push(
      '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
      '/Applications/Chromium.app/Contents/MacOS/Chromium',
      '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
    );
  } else {
    fixedCandidates.push(
      '/usr/bin/google-chrome',
      '/usr/bin/google-chrome-stable',
      '/usr/bin/chromium',
      '/usr/bin/chromium-browser',
      '/snap/bin/chromium',
      '/usr/bin/microsoft-edge',
    );
  }

  for (const candidate of fixedCandidates) {
    if (!isProhibitedSectiumBinary(candidate) && fileExists(candidate)) {
      return candidate;
    }
  }

  const pathVar = env.PATH ?? env.Path ?? '';
  const pathSep = platform === 'win32' ? ';' : ':';
  const pathNames =
    platform === 'win32'
      ? ['chrome.exe', 'msedge.exe', 'chromium.exe']
      : ['google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser', 'microsoft-edge'];

  for (const dir of pathVar.split(pathSep)) {
    const trimmed = dir.trim();
    if (!trimmed) {
      continue;
    }
    for (const binName of pathNames) {
      const candidate = platformJoin(trimmed, binName);
      if (!isProhibitedSectiumBinary(candidate) && fileExists(candidate)) {
        return candidate;
      }
    }
  }

  throw new Error(
    `No supported Chrome/Chromium/Edge binary found for platform=${platform}. Set CHROME_PATH or install google-chrome / chromium / chrome.exe / msedge.exe.`,
  );
}

export interface BrowserPipeLaunchHandle {
  readonly executablePath: string;
  readonly transport: CdpPipeTransport;
  readonly process: ChildProcess;
  readonly userDataDir: string;
  readonly getStderrLogs: () => string;
  readonly close: () => Promise<void>;
}

export function launchHeadlessBrowserOverPipe(options: {
  readonly chromePath?: string;
  readonly defaultTimeoutMs?: number;
} = {}): BrowserPipeLaunchHandle {
  const executablePath = resolveBrowserBinary({ chromePath: options.chromePath });
  const userDataDir = mkdtempSync(join(tmpdir(), 'cdp-network-audit-'));

  const args = [
    '--remote-debugging-pipe',
    '--headless=new',
    '--disable-gpu',
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-background-networking',
    '--disable-sync',
    '--disable-extensions',
    '--disable-component-update',
    '--metrics-recording-only',
    '--mute-audio',
    `--user-data-dir=${userDataDir}`,
    ...(process.platform === 'linux'
      ? ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
      : []),
    'about:blank',
  ];

  const proc = spawn(executablePath, args, {
    stdio: ['pipe', 'pipe', 'pipe', 'pipe', 'pipe'],
    shell: false,
    windowsHide: true,
    detached: false,
    env: buildSanitizedBrowserEnv(process.env),
  });

  const stderrChunks: string[] = [];
  proc.stdout?.resume();
  proc.stderr?.setEncoding('utf8');
  proc.stderr?.on('data', (chunk: string) => {
    stderrChunks.push(chunk);
    if (stderrChunks.length > 200) {
      stderrChunks.shift();
    }
  });

  const writeStream = proc.stdio[3] as Writable | undefined;
  const readStream = proc.stdio[4] as Readable | undefined;
  if (!writeStream || !readStream) {
    try {
      proc.kill();
    } catch {
      // ignore
    }
    throw new Error('Failed to open CDP --remote-debugging-pipe streams stdio[3]/stdio[4]');
  }

  const transport = new CdpPipeTransport({
    writeStream,
    readStream,
    defaultTimeoutMs: options.defaultTimeoutMs ?? 20_000,
  });

  const exitPromise = new Promise<void>((resolveExit) => {
    proc.once('exit', () => {
      transport.close();
      resolveExit();
    });
    proc.once('error', () => {
      transport.close();
      resolveExit();
    });
  });

  const close = async (): Promise<void> => {
    if (!transport.isClosed) {
      try {
        await transport.sendCommand('Browser.close', {}, undefined, 3_000);
      } catch {
        // ignore if already closing
      }
      transport.close();
    }
    if (proc.exitCode === null && !proc.killed) {
      try {
        proc.kill();
      } catch {
        // ignore
      }
    }
    let exitWaitTimer: ReturnType<typeof setTimeout> | undefined;
    try {
      await Promise.race([
        exitPromise,
        new Promise<void>((resolveWait) => {
          exitWaitTimer = setTimeout(resolveWait, 2_500);
        }),
      ]);
    } finally {
      if (exitWaitTimer !== undefined) {
        clearTimeout(exitWaitTimer);
      }
    }
    try {
      rmSync(userDataDir, { recursive: true, force: true });
    } catch {
      // ignore locked Windows cleanup residue
    }
  };

  return {
    executablePath,
    transport,
    process: proc,
    userDataDir,
    getStderrLogs: () => stderrChunks.join(''),
    close,
  };
}

export interface CdpResponseError {
  readonly pageUrl: string;
  readonly url: string;
  readonly status: number;
  readonly statusText: string;
  readonly mimeType: string;
  readonly resourceType: string;
  readonly initiator: string;
  readonly isFavicon: boolean;
  readonly ignored: boolean;
}

export interface CdpLoadingFailed {
  readonly pageUrl: string;
  readonly url: string;
  readonly resourceType: string;
  readonly errorText: string;
  readonly canceled: boolean;
  readonly blockedReason?: string;
  readonly initiator: string;
}

export interface CdpRuntimeException {
  readonly pageUrl: string;
  readonly text: string;
  readonly url?: string;
  readonly lineNumber?: number;
  readonly columnNumber?: number;
}

export interface CdpLogError {
  readonly pageUrl: string;
  readonly source: string;
  readonly level: string;
  readonly text: string;
  readonly url?: string;
}

export interface ExtractedLinkRef {
  readonly url: string;
  readonly tag: 'a' | 'script' | 'link' | 'img';
  readonly rel?: string;
}

export interface CdpPageAuditResult {
  readonly url: string;
  readonly finalUrl: string;
  readonly title: string;
  readonly documentStatus: number | null;
  readonly durationMs: number;
  readonly totalRequests: number;
  readonly responseErrors: readonly CdpResponseError[];
  readonly loadingFailed: readonly CdpLoadingFailed[];
  readonly runtimeExceptions: readonly CdpRuntimeException[];
  readonly logErrors: readonly CdpLogError[];
  readonly extractedLinks: readonly ExtractedLinkRef[];
  readonly navigationError?: string;
}

export interface CheckedLinkResult {
  readonly url: string;
  readonly method: 'HEAD' | 'GET';
  readonly status: number | null;
  readonly ok: boolean;
  readonly finalUrl?: string;
  readonly error?: string;
  readonly foundOnPages: readonly string[];
  readonly tags: readonly string[];
}

export interface CdpAuditSummary {
  readonly totalPages: number;
  readonly totalRequests: number;
  readonly totalResponseErrors: number;
  readonly activeResponseErrors: number;
  readonly ignoredFavicon404Count: number;
  readonly totalLoadingFailed: number;
  readonly totalRuntimeExceptions: number;
  readonly totalLogErrors: number;
  readonly totalNavigationErrors: number;
  readonly extractedUniqueLinks: number;
  readonly checkedLinks: number;
  readonly brokenLinks: number;
  readonly totalErrors: number;
}

export interface CdpAuditReport {
  readonly schema: 'awesome-os.cdp-network-audit.v1';
  readonly generatedAt: string;
  readonly browserBinary: string;
  readonly browserVersion: string;
  readonly transport: 'remote-debugging-pipe';
  readonly suite: string;
  readonly checkLinks: boolean;
  readonly allowIgnoreFavicon: boolean;
  readonly strict: boolean;
  readonly ok: boolean;
  readonly summary: CdpAuditSummary;
  readonly pages: readonly CdpPageAuditResult[];
  readonly brokenLinks: readonly CheckedLinkResult[];
  readonly checkedLinks: readonly CheckedLinkResult[];
}

function isFaviconUrl(rawUrl: string): boolean {
  try {
    const parsed = new URL(rawUrl);
    return parsed.pathname.toLowerCase().endsWith('/favicon.ico');
  } catch {
    return rawUrl.toLowerCase().includes('/favicon.ico');
  }
}

export async function auditUrlOverCdp(
  transport: CdpPipeTransport,
  targetUrl: string,
  options: {
    readonly timeoutMs?: number;
    readonly settleMs?: number;
    readonly allowIgnoreFavicon?: boolean;
  } = {},
): Promise<CdpPageAuditResult> {
  const timeoutMs = options.timeoutMs ?? 25_000;
  const settleMs = options.settleMs ?? 2_000;
  const allowIgnoreFavicon = options.allowIgnoreFavicon ?? false;
  const start = Date.now();

  const { targetId } = (await transport.sendCommand<{ targetId: string }>(
    'Target.createTarget',
    { url: 'about:blank' },
  ));

  let sessionId = '';
  let unlisten: (() => void) | undefined;

  const inflight = new Set<string>();
  const requests = new Map<
    string,
    { url: string; resourceType: string; initiator: string }
  >();
  const responseErrors: CdpResponseError[] = [];
  const loadingFailed: CdpLoadingFailed[] = [];
  const runtimeExceptions: CdpRuntimeException[] = [];
  const logErrors: CdpLogError[] = [];
  let totalRequests = 0;
  let mainFrameId = '';
  let documentStatus: number | null = null;
  let navigationError: string | undefined;
  let collecting = true;
  let lastNetworkActivity = Date.now();
  let resolveLoad!: () => void;
  let loadResolved = false;

  const loadPromise = new Promise<void>((res) => {
    resolveLoad = () => {
      if (!loadResolved) {
        loadResolved = true;
        res();
      }
    };
  });

  try {
    const attached = await transport.sendCommand<{ sessionId: string }>(
      'Target.attachToTarget',
      { targetId, flatten: true },
    );
    sessionId = attached.sessionId;

    unlisten = transport.onEvent((evt) => {
      if (!collecting || evt.sessionId !== sessionId) {
        return;
      }
      const p = evt.params;

      if (evt.method === 'Network.requestWillBeSent') {
        lastNetworkActivity = Date.now();
        const requestId = String(p.requestId ?? '');
        const reqObj = (p.request ?? {}) as Record<string, unknown>;
        const initObj = (p.initiator ?? {}) as Record<string, unknown>;
        const url = String(reqObj.url ?? '');
        const resourceType = String(p.type ?? 'Other');
        const initiator = String(initObj.url ?? initObj.type ?? 'unknown');
        if (requestId) {
          totalRequests++;
          inflight.add(requestId);
          requests.set(requestId, { url, resourceType, initiator });
        }
      } else if (evt.method === 'Network.responseReceived') {
        lastNetworkActivity = Date.now();
        const requestId = String(p.requestId ?? '');
        const resp = (p.response ?? {}) as Record<string, unknown>;
        const status = typeof resp.status === 'number' ? resp.status : 0;
        const statusText = String(resp.statusText ?? '');
        const mimeType = String(resp.mimeType ?? '');
        const reqMeta = requests.get(requestId);
        const url = String(resp.url ?? reqMeta?.url ?? '');
        const resourceType = String(p.type ?? reqMeta?.resourceType ?? 'Other');
        const frameId = typeof p.frameId === 'string' ? p.frameId : '';

        if (
          resourceType === 'Document' &&
          (!mainFrameId || frameId === mainFrameId) &&
          status > 0
        ) {
          documentStatus = status;
        }

        if (status >= 400) {
          const favicon = isFaviconUrl(url);
          responseErrors.push({
            pageUrl: targetUrl,
            url,
            status,
            statusText,
            mimeType,
            resourceType,
            initiator: reqMeta?.initiator ?? 'unknown',
            isFavicon: favicon,
            ignored: Boolean(allowIgnoreFavicon && favicon && status === 404),
          });
        }
      } else if (evt.method === 'Network.loadingFinished') {
        lastNetworkActivity = Date.now();
        const requestId = String(p.requestId ?? '');
        inflight.delete(requestId);
      } else if (evt.method === 'Network.loadingFailed') {
        lastNetworkActivity = Date.now();
        const requestId = String(p.requestId ?? '');
        inflight.delete(requestId);
        const reqMeta = requests.get(requestId);
        loadingFailed.push({
          pageUrl: targetUrl,
          url: reqMeta?.url ?? 'unknown',
          resourceType: String(p.type ?? reqMeta?.resourceType ?? 'Other'),
          errorText: String(p.errorText ?? 'net::ERR_FAILED'),
          canceled: Boolean(p.canceled),
          ...(typeof p.blockedReason === 'string'
            ? { blockedReason: p.blockedReason }
            : {}),
          initiator: reqMeta?.initiator ?? 'unknown',
        });
      } else if (evt.method === 'Runtime.exceptionThrown') {
        const details = (p.exceptionDetails ?? {}) as Record<string, unknown>;
        const exc = (details.exception ?? {}) as Record<string, unknown>;
        runtimeExceptions.push({
          pageUrl: targetUrl,
          text: String(exc.description ?? details.text ?? 'Uncaught runtime exception'),
          ...(typeof details.url === 'string' ? { url: details.url } : {}),
          ...(typeof details.lineNumber === 'number'
            ? { lineNumber: details.lineNumber }
            : {}),
          ...(typeof details.columnNumber === 'number'
            ? { columnNumber: details.columnNumber }
            : {}),
        });
      } else if (evt.method === 'Log.entryAdded') {
        const entry = (p.entry ?? {}) as Record<string, unknown>;
        if (entry.level === 'error') {
          logErrors.push({
            pageUrl: targetUrl,
            source: String(entry.source ?? 'other'),
            level: 'error',
            text: String(entry.text ?? ''),
            ...(typeof entry.url === 'string' ? { url: entry.url } : {}),
          });
        }
      } else if (evt.method === 'Page.loadEventFired') {
        resolveLoad();
      }
    });

    await transport.sendCommand('Network.enable', {}, sessionId);
    await transport.sendCommand('Page.enable', {}, sessionId);
    await transport.sendCommand('Runtime.enable', {}, sessionId);
    await transport.sendCommand('Log.enable', {}, sessionId);

    const navRes = await transport.sendCommand<{
      frameId?: string;
      errorText?: string;
    }>('Page.navigate', { url: targetUrl }, sessionId, timeoutMs);

    if (navRes.frameId) {
      mainFrameId = navRes.frameId;
    }
    if (navRes.errorText) {
      navigationError = navRes.errorText;
      resolveLoad();
    }

    let loadTimer: ReturnType<typeof setTimeout> | undefined;
    try {
      await Promise.race([
        loadPromise,
        new Promise<void>((res) => {
          loadTimer = setTimeout(res, timeoutMs);
        }),
      ]);
    } finally {
      if (loadTimer !== undefined) {
        clearTimeout(loadTimer);
      }
    }

    // Wait for async fetch() / dynamic script activity to settle
    const settleDeadline = Date.now() + Math.max(settleMs, 600);
    while (Date.now() < settleDeadline) {
      const idleDuration = Date.now() - lastNetworkActivity;
      if (inflight.size === 0 && idleDuration >= 450) {
        break;
      }
      await new Promise<void>((res) => setTimeout(res, 150));
    }

    let finalUrl = targetUrl;
    let title = '';
    let extractedLinks: ExtractedLinkRef[] = [];

    try {
      const evalRes = await transport.sendCommand<{
        result?: { value?: { finalUrl?: string; title?: string; links?: ExtractedLinkRef[] } };
      }>(
        'Runtime.evaluate',
        {
          expression: `(() => {
            const out = [];
            const seen = new Set();
            const add = (raw, tag, rel) => {
              if (!raw) return;
              try {
                const u = new URL(raw, document.baseURI);
                if (u.protocol !== 'http:' && u.protocol !== 'https:') return;
                u.hash = '';
                const href = u.href;
                const key = tag + ':' + href;
                if (seen.has(key)) return;
                seen.add(key);
                out.push(rel ? { url: href, tag, rel } : { url: href, tag });
              } catch {}
            };
            for (const el of document.querySelectorAll('a[href]')) add(el.getAttribute('href'), 'a');
            for (const el of document.querySelectorAll('script[src]')) add(el.getAttribute('src'), 'script');
            for (const el of document.querySelectorAll('link[href]')) add(el.getAttribute('href'), 'link', el.getAttribute('rel') || undefined);
            for (const el of document.querySelectorAll('img[src]')) add(el.getAttribute('src'), 'img');
            return {
              finalUrl: String(location.href || ''),
              title: String(document.title || ''),
              links: out,
            };
          })()`,
          returnByValue: true,
        },
        sessionId,
        10_000,
      );
      const val = evalRes.result?.value;
      if (val) {
        finalUrl = val.finalUrl || targetUrl;
        title = val.title || '';
        extractedLinks = Array.isArray(val.links) ? val.links : [];
      }
    } catch {
      // ignore DOM evaluation failure on non-HTML/aborted pages
    }

    return {
      url: targetUrl,
      finalUrl,
      title,
      documentStatus,
      durationMs: Date.now() - start,
      totalRequests,
      responseErrors,
      loadingFailed,
      runtimeExceptions,
      logErrors,
      extractedLinks,
      ...(navigationError ? { navigationError } : {}),
    };
  } finally {
    collecting = false;
    unlisten?.();
    await transport.sendCommand('Target.closeTarget', { targetId }, undefined, 3_000).catch(() => {});
  }
}

export type FetchLike = (
  input: string | URL,
  init?: RequestInit,
) => Promise<{ readonly status: number; readonly ok: boolean; readonly url: string; readonly body?: { cancel?: () => Promise<void> } | null }>;

const NON_RESOURCE_LINK_RELS = new Set(['dns-prefetch', 'preconnect', 'assets']);

const GITHUB_HOSTS = new Set(['github.com', 'www.github.com']);

const GITHUB_CHROME_TOP_LEVEL_SEGMENTS = new Set([
  'about',
  'customer-stories',
  'enterprise',
  'features',
  'login',
  'marketplace',
  'partners',
  'platform',
  'pricing',
  'resources',
  'security',
  'signup',
  'solutions',
  'sponsors',
  'team',
  'trending',
  'trust-center',
  'why-github',
]);

const GITHUB_PROJECTS_TAB_PATTERN = /^\/(?:orgs\/[^/]+|[^/]+\/[^/]+)\/projects(?:\/.*)?$/i;

export function shouldSkipGitHubChromeLink(linkUrl: string, pageUrl: string): boolean {
  let pageParsed: URL;
  let targetParsed: URL;
  try {
    pageParsed = new URL(pageUrl);
    targetParsed = new URL(linkUrl);
  } catch {
    return false;
  }

  if (!GITHUB_HOSTS.has(pageParsed.hostname.toLowerCase())) {
    return false;
  }
  if (!GITHUB_HOSTS.has(targetParsed.hostname.toLowerCase())) {
    return false;
  }

  const pathname = targetParsed.pathname;
  if (
    GITHUB_PROJECTS_TAB_PATTERN.test(pathname) ||
    pathname === '/open-source/sponsors' ||
    pathname.startsWith('/open-source/sponsors/')
  ) {
    return true;
  }

  const firstSegment = pathname.split('/').filter(Boolean)[0]?.toLowerCase() ?? '';
  return GITHUB_CHROME_TOP_LEVEL_SEGMENTS.has(firstSegment);
}

export interface LinkCheckInput {
  readonly url: string;
  readonly pageUrl: string;
  readonly tag: string;
  readonly rel?: string;
}

export async function verifyLinks(
  inputs: readonly LinkCheckInput[],
  options: {
    readonly concurrency?: number;
    readonly timeoutMs?: number;
    readonly retryDelayMs?: number;
    readonly fetchImpl?: FetchLike;
  } = {},
): Promise<CheckedLinkResult[]> {
  const concurrency = Math.max(1, options.concurrency ?? 4);
  const timeoutMs = options.timeoutMs ?? 15_000;
  const retryDelayMs = options.retryDelayMs ?? 450;
  const fetchImpl: FetchLike = options.fetchImpl ?? (fetch as unknown as FetchLike);

  const grouped = new Map<string, { pages: Set<string>; tags: Set<string> }>();
  for (const item of inputs) {
    if (item.tag === 'link' && item.rel) {
      const relTokens = item.rel.toLowerCase().split(/\s+/).filter(Boolean);
      if (relTokens.length > 0 && relTokens.every((t) => NON_RESOURCE_LINK_RELS.has(t))) {
        continue;
      }
    }
    if (shouldSkipGitHubChromeLink(item.url, item.pageUrl)) {
      continue;
    }
    let normalized = item.url;
    try {
      const parsed = new URL(item.url);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        continue;
      }
      parsed.hash = '';
      normalized = parsed.href;
    } catch {
      continue;
    }
    let entry = grouped.get(normalized);
    if (!entry) {
      entry = { pages: new Set<string>(), tags: new Set<string>() };
      grouped.set(normalized, entry);
    }
    entry.pages.add(item.pageUrl);
    entry.tags.add(item.tag);
  }

  const urls = [...grouped.keys()];
  const results: CheckedLinkResult[] = new Array(urls.length);
  let cursor = 0;

  const checkOne = async (targetUrl: string): Promise<CheckedLinkResult> => {
    const meta = grouped.get(targetUrl)!;
    const foundOnPages = [...meta.pages];
    const tags = [...meta.tags];
    const commonHeaders = {
      'user-agent': 'awesome-os-cdp-network-auditor/1.0',
    };

    const runRequest = async (
      method: 'HEAD' | 'GET',
      extraHeaders: Record<string, string> = {},
    ) => {
      const resp = await fetchImpl(targetUrl, {
        method,
        redirect: 'follow',
        headers: { ...commonHeaders, ...extraHeaders },
        signal: AbortSignal.timeout(timeoutMs),
      });
      await resp.body?.cancel?.().catch(() => {});
      return resp;
    };

    const attemptCheck = async (): Promise<CheckedLinkResult> => {
      try {
        let method: 'HEAD' | 'GET' = 'HEAD';
        let resp = await runRequest('HEAD');

        if (resp.status === 405 || resp.status === 501) {
          method = 'GET';
          resp = await runRequest('GET', { Range: 'bytes=0-0' });
        }

        const ok = resp.status >= 200 && resp.status < 400;
        return {
          url: targetUrl,
          method,
          status: resp.status,
          ok,
          ...(resp.url ? { finalUrl: resp.url } : {}),
          foundOnPages,
          tags,
        };
      } catch (err) {
        return {
          url: targetUrl,
          method: 'HEAD',
          status: null,
          ok: false,
          error: err instanceof Error ? err.message : String(err),
          foundOnPages,
          tags,
        };
      }
    };

    const TRANSIENT_STATUSES = new Set([429, 502, 503, 504]);
    let last = await attemptCheck();
    if (!last.ok && (last.status === null || TRANSIENT_STATUSES.has(last.status))) {
      await new Promise<void>((res) => setTimeout(res, retryDelayMs));
      last = await attemptCheck();
    }
    return last;
  };

  const worker = async (): Promise<void> => {
    while (true) {
      const idx = cursor++;
      if (idx >= urls.length) {
        return;
      }
      results[idx] = await checkOne(urls[idx]);
    }
  };

  await Promise.all(
    Array.from({ length: Math.min(concurrency, Math.max(1, urls.length)) }, () => worker()),
  );
  return results;
}

export interface RunCdpNetworkAuditOptions {
  readonly suite?: string;
  readonly urls?: readonly string[];
  readonly checkLinks?: boolean;
  readonly allowIgnoreFavicon?: boolean;
  readonly strict?: boolean;
  readonly chromePath?: string;
  readonly timeoutMs?: number;
  readonly settleMs?: number;
  readonly concurrency?: number;
  readonly jsonOut?: string;
  readonly fetchImpl?: FetchLike;
}

export function resolveSuiteUrls(suite: string, explicitUrls?: readonly string[]): string[] {
  if (explicitUrls && explicitUrls.length > 0) {
    return [...new Set(explicitUrls)];
  }
  const tokens = suite
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  const selected = new Set<string>();
  for (const token of tokens) {
    if (token === 'all') {
      for (const u of DEFAULT_AUDIT_SUITES.pages) selected.add(u);
      for (const u of DEFAULT_AUDIT_SUITES.packages) selected.add(u);
      for (const u of DEFAULT_AUDIT_SUITES.cas) selected.add(u);
    } else if (token === 'pages') {
      for (const u of DEFAULT_AUDIT_SUITES.pages) selected.add(u);
    } else if (token === 'packages') {
      for (const u of DEFAULT_AUDIT_SUITES.packages) selected.add(u);
    } else if (token === 'cas') {
      for (const u of DEFAULT_AUDIT_SUITES.cas) selected.add(u);
    } else {
      throw new Error(
        `Unknown suite "${token}". Expected one of: all, pages, packages, cas`,
      );
    }
  }
  if (selected.size === 0) {
    throw new Error('No audit URLs selected.');
  }
  return [...selected];
}

export async function runCdpNetworkAudit(
  options: RunCdpNetworkAuditOptions = {},
): Promise<CdpAuditReport> {
  const suite = options.suite ?? (options.urls?.length ? 'custom' : 'all');
  const targetUrls = resolveSuiteUrls(suite, options.urls);
  const checkLinks = Boolean(options.checkLinks);
  const allowIgnoreFavicon = Boolean(options.allowIgnoreFavicon);
  const strict = Boolean(options.strict);

  const browser = launchHeadlessBrowserOverPipe({
    chromePath: options.chromePath,
    defaultTimeoutMs: options.timeoutMs ?? 25_000,
  });

  try {
    let browserVersion = 'unknown';
    try {
      const ver = await browser.transport.sendCommand<{ product?: string }>(
        'Browser.getVersion',
        {},
        undefined,
        5_000,
      );
      browserVersion = ver.product ?? 'unknown';
    } catch {
      // continue even if Browser.getVersion fails
    }

    const pages: CdpPageAuditResult[] = [];
    for (const url of targetUrls) {
      const pageRes = await auditUrlOverCdp(browser.transport, url, {
        timeoutMs: options.timeoutMs,
        settleMs: options.settleMs,
        allowIgnoreFavicon,
      });
      pages.push(pageRes);
    }

    const linkInputs: LinkCheckInput[] = [];
    for (const page of pages) {
      for (const link of page.extractedLinks) {
        linkInputs.push({
          url: link.url,
          pageUrl: page.url,
          tag: link.tag,
          ...(link.rel ? { rel: link.rel } : {}),
        });
      }
    }

    const uniqueExtractedCount = new Set(linkInputs.map((l) => l.url)).size;
    const checkedLinks = checkLinks
      ? await verifyLinks(linkInputs, {
          concurrency: options.concurrency,
          fetchImpl: options.fetchImpl,
        })
      : [];
    const brokenLinks = checkedLinks.filter((l) => !l.ok);

    let totalRequests = 0;
    let totalResponseErrors = 0;
    let activeResponseErrors = 0;
    let ignoredFavicon404Count = 0;
    let totalLoadingFailed = 0;
    let totalRuntimeExceptions = 0;
    let totalLogErrors = 0;
    let totalNavigationErrors = 0;

    for (const p of pages) {
      totalRequests += p.totalRequests;
      totalResponseErrors += p.responseErrors.length;
      for (const re of p.responseErrors) {
        if (re.ignored) {
          ignoredFavicon404Count++;
        } else {
          activeResponseErrors++;
        }
      }
      totalLoadingFailed += p.loadingFailed.length;
      totalRuntimeExceptions += p.runtimeExceptions.length;
      totalLogErrors += p.logErrors.length;
      if (p.navigationError) {
        totalNavigationErrors++;
      }
    }

    const totalErrors =
      activeResponseErrors +
      totalLoadingFailed +
      totalRuntimeExceptions +
      totalLogErrors +
      totalNavigationErrors +
      brokenLinks.length;

    const report: CdpAuditReport = {
      schema: 'awesome-os.cdp-network-audit.v1',
      generatedAt: new Date().toISOString(),
      browserBinary: browser.executablePath,
      browserVersion,
      transport: 'remote-debugging-pipe',
      suite,
      checkLinks,
      allowIgnoreFavicon,
      strict,
      ok: totalErrors === 0,
      summary: {
        totalPages: pages.length,
        totalRequests,
        totalResponseErrors,
        activeResponseErrors,
        ignoredFavicon404Count,
        totalLoadingFailed,
        totalRuntimeExceptions,
        totalLogErrors,
        totalNavigationErrors,
        extractedUniqueLinks: uniqueExtractedCount,
        checkedLinks: checkedLinks.length,
        brokenLinks: brokenLinks.length,
        totalErrors,
      },
      pages,
      brokenLinks,
      checkedLinks,
    };

    if (options.jsonOut) {
      const outPath = resolve(options.jsonOut);
      mkdirSync(dirname(outPath), { recursive: true });
      writeFileSync(outPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
    }

    return report;
  } finally {
    await browser.close();
  }
}

export interface ParsedCliArgs {
  readonly help: boolean;
  readonly suite: string;
  readonly urls: string[];
  readonly checkLinks: boolean;
  readonly allowIgnoreFavicon: boolean;
  readonly jsonOut?: string;
  readonly strict: boolean;
  readonly chromePath?: string;
  readonly timeoutMs?: number;
  readonly settleMs?: number;
  readonly concurrency?: number;
}

export function getHelpText(): string {
  return [
    'cdp-network-audit — Chrome/Edge CDP (--remote-debugging-pipe) Network & Link Auditor',
    '',
    'Usage:',
    '  node cdp-network-audit.mts [options]',
    '',
    'Options:',
    '  --suite <all|pages|packages|cas>  Built-in URL suite (default: all)',
    '  --urls <u1,u2,...>                Explicit comma-separated or space-separated URLs',
    '  --check-links                     Verify extracted <a href>/<script>/<link>/<img> URLs via HEAD/Range GET',
    '  --allow-ignore-favicon            Exclude /favicon.ico HTTP 404 from active/strict error counts',
    '  --json-out <file>                 Write full JSON audit report to <file>',
    '  --strict                          Exit non-zero if any active CDP/link error is detected',
    '  --chrome-path <path>              Explicit Chrome/Chromium/Edge binary override (never sectium.exe)',
    '  --timeout-ms <ms>                 Navigation timeout per page (default: 25000)',
    '  --settle-ms <ms>                  Post-load async network settle window (default: 2000)',
    '  --concurrency <n>                 Link verification concurrency (default: 6)',
    '  -h, --help                        Show help text',
    '',
  ].join('\n');
}

export function parseCliArgs(argv: readonly string[]): ParsedCliArgs {
  let help = false;
  let suite = 'all';
  const urls: string[] = [];
  let checkLinks = false;
  let allowIgnoreFavicon = false;
  let jsonOut: string | undefined;
  let strict = false;
  let chromePath: string | undefined;
  let timeoutMs: number | undefined;
  let settleMs: number | undefined;
  let concurrency: number | undefined;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      help = true;
    } else if (arg === '--suite' && argv[i + 1]) {
      suite = argv[++i];
    } else if (arg === '--urls' || arg === '--url') {
      while (i + 1 < argv.length && !argv[i + 1].startsWith('-')) {
        const raw = argv[++i];
        for (const part of raw.split(',')) {
          const trimmed = part.trim();
          if (trimmed) urls.push(trimmed);
        }
      }
    } else if (arg === '--check-links') {
      checkLinks = true;
    } else if (arg === '--allow-ignore-favicon') {
      allowIgnoreFavicon = true;
    } else if (arg === '--json-out' && argv[i + 1]) {
      jsonOut = argv[++i];
    } else if (arg === '--strict') {
      strict = true;
    } else if (arg === '--chrome-path' && argv[i + 1]) {
      chromePath = argv[++i];
    } else if (arg === '--timeout-ms' && argv[i + 1]) {
      timeoutMs = Number(argv[++i]);
    } else if (arg === '--settle-ms' && argv[i + 1]) {
      settleMs = Number(argv[++i]);
    } else if (arg === '--concurrency' && argv[i + 1]) {
      concurrency = Number(argv[++i]);
    } else {
      throw new Error(`Unknown or incomplete argument "${arg}"`);
    }
  }

  return {
    help,
    suite,
    urls,
    checkLinks,
    allowIgnoreFavicon,
    ...(jsonOut ? { jsonOut } : {}),
    strict,
    ...(chromePath ? { chromePath } : {}),
    ...(timeoutMs !== undefined && Number.isFinite(timeoutMs) ? { timeoutMs } : {}),
    ...(settleMs !== undefined && Number.isFinite(settleMs) ? { settleMs } : {}),
    ...(concurrency !== undefined && Number.isFinite(concurrency) ? { concurrency } : {}),
  };
}

export function formatHumanSummary(report: CdpAuditReport): string {
  const lines: string[] = [
    `[cdp-network-audit] browser=${report.browserVersion} (${report.browserBinary})`,
    `[cdp-network-audit] suite=${report.suite} pages=${report.summary.totalPages} requests=${report.summary.totalRequests} activeErrors=${report.summary.activeResponseErrors} ignoredFavicon404=${report.summary.ignoredFavicon404Count} loadingFailed=${report.summary.totalLoadingFailed} runtimeExceptions=${report.summary.totalRuntimeExceptions} logErrors=${report.summary.totalLogErrors} checkedLinks=${report.summary.checkedLinks} brokenLinks=${report.summary.brokenLinks} ok=${report.ok}`,
  ];

  for (const page of report.pages) {
    lines.push(
      `  PAGE [${page.documentStatus ?? 'ERR'}] ${page.url} (${page.durationMs}ms, req=${page.totalRequests}, respErr=${page.responseErrors.length}, fail=${page.loadingFailed.length}, exc=${page.runtimeExceptions.length}, logErr=${page.logErrors.length}, links=${page.extractedLinks.length})`,
    );
    if (page.navigationError) {
      lines.push(`    NAV_ERROR: ${page.navigationError}`);
    }
    for (const r of page.responseErrors) {
      lines.push(
        `    HTTP_${r.status}${r.ignored ? ' [IGNORED_FAVICON]' : ''} [${r.resourceType}] ${r.url} (initiator=${r.initiator})`,
      );
    }
    for (const f of page.loadingFailed) {
      lines.push(
        `    LOAD_FAIL [${f.resourceType}] ${f.url} -> ${f.errorText}${f.canceled ? ' (canceled)' : ''}${f.blockedReason ? ` [${f.blockedReason}]` : ''}`,
      );
    }
    for (const e of page.runtimeExceptions) {
      lines.push(`    RUNTIME_EXC: ${e.text}`);
    }
    for (const l of page.logErrors) {
      lines.push(`    LOG_ERROR [${l.source}]: ${l.text}${l.url ? ` (${l.url})` : ''}`);
    }
  }

  if (report.brokenLinks.length > 0) {
    lines.push(`  BROKEN_LINKS (${report.brokenLinks.length}):`);
    for (const b of report.brokenLinks) {
      lines.push(
        `    [${b.status ?? 'ERR'} ${b.method}] ${b.url}${b.error ? ` -> ${b.error}` : ''} (from: ${b.foundOnPages.join(', ')})`,
      );
    }
  }

  return `${lines.join('\n')}\n`;
}

const isDirectEntry =
  typeof process.argv[1] === 'string' &&
  resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));

if (isDirectEntry) {
  try {
    const parsed = parseCliArgs(process.argv.slice(2));
    if (parsed.help) {
      process.stdout.write(getHelpText());
      process.exitCode = 0;
    } else {
      runCdpNetworkAudit({
        suite: parsed.suite,
        urls: parsed.urls.length > 0 ? parsed.urls : undefined,
        checkLinks: parsed.checkLinks,
        allowIgnoreFavicon: parsed.allowIgnoreFavicon,
        strict: parsed.strict,
        chromePath: parsed.chromePath,
        timeoutMs: parsed.timeoutMs,
        settleMs: parsed.settleMs,
        concurrency: parsed.concurrency,
        jsonOut: parsed.jsonOut,
      })
        .then((report) => {
          process.stdout.write(formatHumanSummary(report));
          if (parsed.strict && !report.ok) {
            process.exitCode = 1;
          }
        })
        .catch((err) => {
          process.stderr.write(
            `[cdp-network-audit] ERROR: ${err instanceof Error ? err.message : String(err)}\n`,
          );
          process.exitCode = 1;
        });
    }
  } catch (err) {
    process.stderr.write(
      `[cdp-network-audit] ERROR: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    process.exitCode = 1;
  }
}
