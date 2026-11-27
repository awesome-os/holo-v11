import test from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import {
  auditUrlOverCdp,
  buildSanitizedBrowserEnv,
  CdpPipeTransport,
  DEFAULT_AUDIT_SUITES,
  parseCliArgs,
  resolveBrowserBinary,
  resolveSuiteUrls,
  verifyLinks,
} from './cdp-network-audit.mts';

function createMockCdpPipePair(): {
  transport: CdpPipeTransport;
  serverWrite: PassThrough;
  serverRead: PassThrough;
} {
  const clientWrite = new PassThrough();
  const serverRead = clientWrite;
  const serverWrite = new PassThrough();
  const clientRead = serverWrite;
  const transport = new CdpPipeTransport({
    writeStream: clientWrite,
    readStream: clientRead,
    defaultTimeoutMs: 2_000,
  });
  return { transport, serverWrite, serverRead };
}

function attachMockCdpResponder(
  serverWrite: PassThrough,
  serverRead: PassThrough,
  handler: (msg: { id: number; method: string; params?: Record<string, unknown>; sessionId?: string }, send: (payload: Record<string, unknown>) => void) => void,
): void {
  const send = (payload: Record<string, unknown>): void => {
    serverWrite.write(`${JSON.stringify(payload)}\0`, 'utf8');
  };
  let chunks: Buffer[] = [];
  serverRead.on('data', (chunk: Buffer) => {
    chunks.push(chunk);
    if (chunk.indexOf(0) === -1) return;
    const all = Buffer.concat(chunks);
    let start = 0;
    let nul = all.indexOf(0, start);
    while (nul !== -1) {
      if (nul > start) {
        const msg = JSON.parse(all.toString('utf8', start, nul)) as {
          id: number;
          method: string;
          params?: Record<string, unknown>;
          sessionId?: string;
        };
        handler(msg, send);
      }
      start = nul + 1;
      nul = all.indexOf(0, start);
    }
    chunks = start < all.length ? [all.subarray(start)] : [];
  });
}

test('CdpPipeTransport frames NUL-delimited JSON-RPC across split UTF-8 chunks and coalesced messages', async () => {
  const { transport, serverWrite, serverRead } = createMockCdpPipePair();
  const receivedEvents: Array<{ method: string; sessionId?: string }> = [];
  transport.onEvent((evt) => {
    receivedEvents.push({ method: evt.method, sessionId: evt.sessionId });
  });

  serverRead.on('data', (raw: Buffer) => {
    const text = raw.toString('utf8').replace(/\0$/, '');
    const msg = JSON.parse(text) as { id: number; method: string; sessionId?: string };
    // Send two NUL-delimited messages where the first contains multi-byte UTF-8 split mid-rune
    const evtFrame = Buffer.from(
      `${JSON.stringify({ method: 'Network.requestWillBeSent', sessionId: msg.sessionId, params: { note: '✓' } })}\0`,
      'utf8',
    );
    const respFrame = Buffer.from(
      `${JSON.stringify({ id: msg.id, result: { product: 'Chrome/Test ✓' } })}\0`,
      'utf8',
    );
    const combined = Buffer.concat([evtFrame, respFrame]);
    const splitAt = Math.floor(evtFrame.length / 2);
    serverWrite.write(combined.subarray(0, splitAt));
    serverWrite.write(combined.subarray(splitAt));
  });

  const res = await transport.sendCommand<{ product: string }>('Browser.getVersion', {}, 'sess-1');
  assert.equal(res.product, 'Chrome/Test ✓');
  assert.equal(receivedEvents.length, 1);
  assert.equal(receivedEvents[0]?.method, 'Network.requestWillBeSent');
  assert.equal(receivedEvents[0]?.sessionId, 'sess-1');
  transport.close();
});

test('CdpPipeTransport rejects pending commands immediately when pipe closes', async () => {
  const { transport, serverWrite } = createMockCdpPipePair();
  const pending = transport.sendCommand('Browser.getVersion');
  serverWrite.destroy();
  await assert.rejects(pending, /closed/i);
});

test('auditUrlOverCdp captures HTTP >= 400, favicon handling, loadingFailed, runtimeException, logError, and DOM links', async () => {
  const runFixture = async (allowIgnoreFavicon: boolean) => {
    const { transport, serverWrite, serverRead } = createMockCdpPipePair();
    attachMockCdpResponder(serverWrite, serverRead, (msg, send) => {
      if (msg.method === 'Target.createTarget') {
        send({ id: msg.id, result: { targetId: 'target-1' } });
      } else if (msg.method === 'Target.attachToTarget') {
        send({ id: msg.id, result: { sessionId: 'session-1' } });
      } else if (
        msg.method === 'Network.enable' ||
        msg.method === 'Page.enable' ||
        msg.method === 'Runtime.enable' ||
        msg.method === 'Log.enable'
      ) {
        send({ id: msg.id, result: {} });
      } else if (msg.method === 'Page.navigate') {
        send({ id: msg.id, result: { frameId: 'frame-main' } });
        // Simulate requests + errors on session-1
        send({
          method: 'Network.requestWillBeSent',
          sessionId: 'session-1',
          params: {
            requestId: 'req-doc',
            type: 'Document',
            request: { url: 'https://awesome-os.github.io/demos/' },
            initiator: { type: 'other' },
          },
        });
        send({
          method: 'Network.responseReceived',
          sessionId: 'session-1',
          params: {
            requestId: 'req-doc',
            frameId: 'frame-main',
            type: 'Document',
            response: {
              url: 'https://awesome-os.github.io/demos/',
              status: 200,
              statusText: 'OK',
              mimeType: 'text/html',
            },
          },
        });
        send({
          method: 'Network.loadingFinished',
          sessionId: 'session-1',
          params: { requestId: 'req-doc' },
        });
        send({
          method: 'Network.requestWillBeSent',
          sessionId: 'session-1',
          params: {
            requestId: 'req-css',
            type: 'Stylesheet',
            request: { url: 'https://awesome-os.github.io/demos/missing.css' },
            initiator: { type: 'parser', url: 'https://awesome-os.github.io/demos/' },
          },
        });
        send({
          method: 'Network.responseReceived',
          sessionId: 'session-1',
          params: {
            requestId: 'req-css',
            frameId: 'frame-main',
            type: 'Stylesheet',
            response: {
              url: 'https://awesome-os.github.io/demos/missing.css',
              status: 404,
              statusText: 'Not Found',
              mimeType: 'text/html',
            },
          },
        });
        send({
          method: 'Network.loadingFinished',
          sessionId: 'session-1',
          params: { requestId: 'req-css' },
        });
        send({
          method: 'Network.requestWillBeSent',
          sessionId: 'session-1',
          params: {
            requestId: 'req-fav',
            type: 'Other',
            request: { url: 'https://awesome-os.github.io/favicon.ico' },
            initiator: { type: 'other' },
          },
        });
        send({
          method: 'Network.responseReceived',
          sessionId: 'session-1',
          params: {
            requestId: 'req-fav',
            frameId: 'frame-main',
            type: 'Other',
            response: {
              url: 'https://awesome-os.github.io/favicon.ico',
              status: 404,
              statusText: 'Not Found',
              mimeType: 'text/html',
            },
          },
        });
        send({
          method: 'Network.loadingFinished',
          sessionId: 'session-1',
          params: { requestId: 'req-fav' },
        });
        send({
          method: 'Network.requestWillBeSent',
          sessionId: 'session-1',
          params: {
            requestId: 'req-fail',
            type: 'Script',
            request: { url: 'https://awesome-os.github.io/demos/aborted.js' },
            initiator: { type: 'script', url: 'https://awesome-os.github.io/demos/app.js' },
          },
        });
        send({
          method: 'Network.loadingFailed',
          sessionId: 'session-1',
          params: {
            requestId: 'req-fail',
            type: 'Script',
            errorText: 'net::ERR_FAILED',
            canceled: false,
          },
        });
        send({
          method: 'Runtime.exceptionThrown',
          sessionId: 'session-1',
          params: {
            exceptionDetails: {
              text: 'Uncaught ReferenceError: foo is not defined',
              url: 'https://awesome-os.github.io/demos/app.js',
              lineNumber: 12,
              columnNumber: 4,
            },
          },
        });
        send({
          method: 'Log.entryAdded',
          sessionId: 'session-1',
          params: {
            entry: {
              source: 'network',
              level: 'error',
              text: 'Failed to load resource: 404',
              url: 'https://awesome-os.github.io/demos/missing.css',
            },
          },
        });
        send({
          method: 'Page.loadEventFired',
          sessionId: 'session-1',
          params: { timestamp: 123 },
        });
      } else if (msg.method === 'Runtime.evaluate') {
        send({
          id: msg.id,
          result: {
            result: {
              value: {
                finalUrl: 'https://awesome-os.github.io/demos/',
                title: 'Awesome-OS Demos',
                links: [
                  { url: 'https://awesome-os.github.io/demos/arch/pdp11/', tag: 'a' },
                  { url: 'https://awesome-os.github.io/demos/missing.css', tag: 'link', rel: 'stylesheet' },
                ],
              },
            },
          },
        });
      } else if (msg.method === 'Target.closeTarget') {
        send({ id: msg.id, result: { success: true } });
      }
    });

    const result = await auditUrlOverCdp(transport, 'https://awesome-os.github.io/demos/', {
      settleMs: 650,
      allowIgnoreFavicon,
    });
    transport.close();
    return result;
  };

  const strictFav = await runFixture(false);
  assert.equal(strictFav.documentStatus, 200);
  assert.equal(strictFav.title, 'Awesome-OS Demos');
  assert.equal(strictFav.totalRequests, 4);
  assert.equal(strictFav.responseErrors.length, 2);
  assert.equal(strictFav.responseErrors.every((e) => !e.ignored), true);
  assert.equal(strictFav.loadingFailed.length, 1);
  assert.equal(strictFav.loadingFailed[0]?.errorText, 'net::ERR_FAILED');
  assert.equal(strictFav.runtimeExceptions.length, 1);
  assert.equal(strictFav.logErrors.length, 1);
  assert.equal(strictFav.extractedLinks.length, 2);

  const ignoredFav = await runFixture(true);
  assert.equal(ignoredFav.responseErrors.length, 2);
  assert.equal(ignoredFav.responseErrors.filter((e) => e.ignored).length, 1);
  assert.equal(ignoredFav.responseErrors.filter((e) => !e.ignored).length, 1);
});

test('verifyLinks deduplicates across pages, strips hashes, skips origin-hint links, and falls back from HEAD 405 to Range GET', async () => {
  const calls: Array<{ url: string; method: string; range?: string }> = [];
  const results = await verifyLinks(
    [
      { url: 'https://awesome-os.github.io/a#top', pageUrl: 'https://awesome-os.github.io/', tag: 'a' },
      { url: 'https://awesome-os.github.io/a#bottom', pageUrl: 'https://awesome-os.github.io/demos/', tag: 'a' },
      { url: 'https://github.com/awesome-os/asset.tar.gz', pageUrl: 'https://awesome-os.github.io/', tag: 'a' },
      { url: 'https://awesome-os.github.io/missing.js', pageUrl: 'https://awesome-os.github.io/', tag: 'script' },
      { url: 'https://github-cloud.s3.amazonaws.com/', pageUrl: 'https://github.com/orgs/awesome-os/packages', tag: 'link', rel: 'dns-prefetch' },
      { url: 'https://github.githubassets.com/', pageUrl: 'https://github.com/orgs/awesome-os/packages', tag: 'link', rel: 'preconnect' },
    ],
    {
      concurrency: 2,
      fetchImpl: async (input, init) => {
        const url = String(input);
        const method = init?.method ?? 'GET';
        const headers = (init?.headers ?? {}) as Record<string, string>;
        calls.push({ url, method, range: headers.Range });

        if (url === 'https://awesome-os.github.io/a') {
          return { status: 200, ok: true, url };
        }
        if (url === 'https://github.com/awesome-os/asset.tar.gz') {
          if (method === 'HEAD') {
            return { status: 405, ok: false, url };
          }
          return { status: 206, ok: true, url };
        }
        return { status: 404, ok: false, url };
      },
    },
  );

  assert.equal(results.length, 3);
  const byUrl = new Map(results.map((r) => [r.url, r]));
  assert.deepEqual(byUrl.get('https://awesome-os.github.io/a')?.foundOnPages, [
    'https://awesome-os.github.io/',
    'https://awesome-os.github.io/demos/',
  ]);
  assert.equal(byUrl.get('https://github.com/awesome-os/asset.tar.gz')?.method, 'GET');
  assert.equal(byUrl.get('https://github.com/awesome-os/asset.tar.gz')?.status, 206);
  assert.equal(byUrl.get('https://github.com/awesome-os/asset.tar.gz')?.ok, true);
  assert.equal(byUrl.get('https://awesome-os.github.io/missing.js')?.status, 404);
  assert.equal(byUrl.get('https://awesome-os.github.io/missing.js')?.ok, false);
  assert.equal(
    calls.some((c) => c.url === 'https://github.com/awesome-os/asset.tar.gz' && c.method === 'GET' && c.range === 'bytes=0-0'),
    true,
  );
});

test('verifyLinks retries transient 504/network failures once before settling', async () => {
  let attempts = 0;
  const results = await verifyLinks(
    [{ url: 'https://github.com/facebook/zstd', pageUrl: 'https://awesome-os.github.io/holo-v11/oversight.html', tag: 'a' }],
    {
      retryDelayMs: 5,
      fetchImpl: async (input) => {
        attempts++;
        const url = String(input);
        if (attempts === 1) {
          return { status: 504, ok: false, url };
        }
        return { status: 200, ok: true, url };
      },
    },
  );
  assert.equal(attempts, 2);
  assert.equal(results[0]?.ok, true);
  assert.equal(results[0]?.status, 200);
});

test('resolveBrowserBinary honors CHROME_PATH, skips D:\\Sectium, and blocks sectium.exe', () => {
  assert.throws(
    () =>
      resolveBrowserBinary({
        chromePath: 'D:\\Sectium\\sectium.exe',
        fileExists: () => true,
      }),
    /sectium/i,
  );

  const chosenWin = resolveBrowserBinary({
    platform: 'win32',
    env: {
      PATH: 'D:\\Sectium;C:\\CustomBin',
      PROGRAMFILES: 'C:\\Program Files',
      'PROGRAMFILES(X86)': 'C:\\Program Files (x86)',
    },
    fileExists: (p) =>
      p === 'D:\\Sectium\\chromium.exe' ||
      p === 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  });
  assert.equal(chosenWin, 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe');

  const chosenLinux = resolveBrowserBinary({
    platform: 'linux',
    env: { CHROME_PATH: '/opt/google/chrome/chrome' },
    fileExists: (p) => p === '/opt/google/chrome/chrome',
  });
  assert.equal(chosenLinux, '/opt/google/chrome/chrome');
});

test('buildSanitizedBrowserEnv strips caller tokens and disables Google API prompts', () => {
  const env = buildSanitizedBrowserEnv({
    PATH: '/usr/bin',
    GITHUB_TOKEN: 'secret',
    NODE_OPTIONS: '--inspect',
    PNPM_HOME: '/tmp/pnpm',
  });
  assert.equal(env.PATH, '/usr/bin');
  assert.equal(env.GITHUB_TOKEN, undefined);
  assert.equal(env.NODE_OPTIONS, undefined);
  assert.equal(env.PNPM_HOME, undefined);
  assert.equal(env.GOOGLE_API_KEY, 'no');
  assert.equal(env.GOOGLE_DEFAULT_CLIENT_ID, 'no');
  assert.equal(env.GOOGLE_DEFAULT_CLIENT_SECRET, 'no');
});

test('parseCliArgs and resolveSuiteUrls support all required flags and built-in suites', () => {
  const parsed = parseCliArgs([
    '--suite',
    'pages',
    '--check-links',
    '--allow-ignore-favicon',
    '--json-out',
    'cdp-audit-report.json',
    '--strict',
  ]);
  assert.equal(parsed.suite, 'pages');
  assert.equal(parsed.checkLinks, true);
  assert.equal(parsed.allowIgnoreFavicon, true);
  assert.equal(parsed.jsonOut, 'cdp-audit-report.json');
  assert.equal(parsed.strict, true);

  const allUrls = resolveSuiteUrls('all');
  assert.equal(
    allUrls.length,
    DEFAULT_AUDIT_SUITES.pages.length +
      DEFAULT_AUDIT_SUITES.packages.length +
      DEFAULT_AUDIT_SUITES.cas.length,
  );
});
