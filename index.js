/**********************************************************************
 *  HTTP + HTTPS proxy with:                                          *
 *    •  site-blocklist.txt  – content sites to block                 *
 *    •  dns-blocklist.txt   – DoH endpoints to block                 *
 *    •  browser-only console logging (toggle)                        *
 *    •  log.txt (ISO-timestamped, append mode, survives restarts)    *
 *    •  hard TypeError guards → proxy never crashes                  *
 *********************************************************************/

const fs        = require('fs');
const path      = require('path');
const http      = require('http');
const net       = require('net');
const { URL }   = require('url');
const httpProxy = require('http-proxy');

/* ───────────── CONFIG ─────────────────────────────────────────────── */
const PORT = process.env.PORT || 8080;
const LOG_BROWSER_ONLY = true;
const browserUARegex   = /(mozilla|chrome|safari|firefox|edge)/i;

/* ───────────── LOAD BLOCK-LISTS ───────────────────────────────────── */
function loadList(file) {
  try {
    return fs.readFileSync(path.join(__dirname, file), 'utf8')
      .split(/\r?\n/)
      .map(l => l.trim())
      .filter(l => l && !l.startsWith('#'));
  } catch (e) {
    console.warn(`⚠️  Could not read ${file}: ${e.message}  (using empty list)`);
    return [];
  }
}
const siteBlockList = loadList('site-blocklist.txt');
const dnsBlockList  = loadList('dns-blocklist.txt');

/* ───────────── LOG STREAM (append) ────────────────────────────────── */
const logPath   = path.join(__dirname, 'log.txt');
const logStream = fs.createWriteStream(logPath, { flags: 'a' });

function logLine(prefix, method, host, path = '') {
  const ts = new Date().toISOString();
  const line = `${ts}  ${prefix} ${method.padEnd(6)} ${host}${path}`;
  if (!LOG_BROWSER_ONLY || browserUARegex.test(host)) console.log(line);
  logStream.write(line + '\n');
}

/* ───────────── HELPERS ───────────────────────────────────────────── */
const proxy = httpProxy.createProxyServer({});

// suppress any uncaught error from http-proxy internals
proxy.on('error', err => {
  if (err && err.code !== 'ECONNRESET') console.error('>> proxy core error:', err.message);
});

const matches = (host, base) => host === base || host.endsWith('.' + base);

function classify(host) {
  if (!host) return null;
  const lc = host.toLowerCase();
  if (dnsBlockList .some(b => matches(lc, b))) return 'DNS';
  if (siteBlockList.some(b => matches(lc, b))) return 'WEB';
  return null;
}
const safeWrite = (sock, data) => { if (sock.writable) try { sock.write(data); } catch {} };

/* ───────────── HTTP HANDLER ───────────────────────────────────────── */
const server = http.createServer((req, res) => {
  // ------------ figure out hostname ------------
  let host;
  try { host = new URL(req.url).hostname; } // absolute form
  catch { host = (req.headers.host || '').split(':')[0]; }

  const block = classify(host);

  if (block === 'WEB') {
    logLine('[WEB BLOCKED]', req.method, host, req.url);
    const original = encodeURIComponent(req.url);
    res.writeHead(302, { Location: `https://www.google.com/search?q=site+blocked&u=${original}` });
    return res.end();
  }
  if (block === 'DNS') {
    logLine('[DNS BLOCKED]', req.method, host, req.url);
    res.writeHead(403);
    return res.end('Forbidden');
  }

  // ------------- BUILD *GUARANTEED* ABSOLUTE TARGET ------------
  let target;
  try {
    const maybe = new URL(req.url);               // throws on relative
    target = maybe.protocol ? maybe.href : null;
  } catch { target = null; }

  if (!target) {
    // req.url was relative (e.g., "/path") – prepend scheme + host
    target = `http://${host}${req.url.startsWith('/') ? '' : '/'}${req.url}`;
  }
  // -------------------------------------------------------------

  logLine('[ALLOWED]', req.method, host, req.url);

  // ensure any stray TypeError inside proxy.web is caught
  try {
    proxy.web(req, res,
      { target, changeOrigin: true, secure: false },
      err => {
        console.error('>> HTTP proxy error:', err?.message || err);
        if (!res.headersSent) res.writeHead(500);
        res.end('Internal Server Error');
      });
  } catch (e) {
    console.error('>> Caught proxy.web exception:', e.message);
    if (!res.headersSent) res.writeHead(500);
    res.end('Internal Server Error');
  }
});

/* ───────────── HTTPS / CONNECT HANDLER ────────────────────────────── */
server.on('connect', (req, clientSock, head) => {
  const [host, portStr] = req.url.split(':');
  const port  = +portStr || 443;
  const block = classify(host);

  if (block) {
    const lbl = block === 'DNS' ? '[DNS BLOCKED]' : '[WEB BLOCKED]';
    logLine(lbl, 'CONNECT', host);
    safeWrite(clientSock, 'HTTP/1.1 403 Forbidden\r\n\r\n');
    return clientSock.destroy();
  }

  logLine('[ALLOWED]', 'CONNECT', host);

  const serverSock = net.connect(port, host, () => {
    safeWrite(clientSock, 'HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head?.length) serverSock.write(head);
    serverSock.pipe(clientSock).pipe(serverSock);
  });

  const linkErr = (tag, opposite) => err => {
    if (err.code !== 'ECONNRESET') console.error(`>> ${tag}:`, err.message);
    opposite.destroy();
  };
  clientSock.on('error', linkErr('CLIENT error', serverSock));
  serverSock.on('error', linkErr('SERVER error', clientSock));
});

/* ───────────── CLEAN EXIT (close log stream) ─────────────────────── */
function shutdown(code = 0) {
  console.log('\nShutting down proxy…');
  logStream.end(() => process.exit(code));
}
process.on('SIGINT',  () => shutdown(0));
process.on('SIGTERM', () => shutdown(0));
process.on('uncaughtException',  err => { console.error('>> Uncaught:', err); shutdown(1); });
process.on('unhandledRejection', err => { console.error('>> Unhandled:', err); });

/* ───────────── STARTUP ─────────────────────────────────────────────── */
server.listen(PORT, () => {
  const banner = [
    `🔌 Proxy listening on port ${PORT}`,
    `   Site-block entries : ${siteBlockList.length}`,
    `   DNS-block entries  : ${dnsBlockList.length}`,
    `   Log file           : ${logPath}`
  ];
  banner.forEach(line => { console.log(line); logStream.write(`${new Date().toISOString()}  ${line}\n`); });
});
