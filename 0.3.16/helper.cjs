/*
 * DevEN local helper.
 *
 * A Stalker portal identifies a set-top box by a `mac` cookie, a MAG User-Agent and a Bearer token.
 * A web page can set none of those headers itself, so the app talks to the portal through this
 * small server instead: on the TV it runs as the app's Tizen web service, on a PC it runs from
 * `npm run proxy` so the same app can be developed in Chrome against a real portal.
 *
 * Plain Node, no dependencies, CommonJS: it has to start on the TV's own Node runtime, which can be
 * as old as Node 4. So: no destructuring, default or rest parameters, trailing commas in calls,
 * optional catch bindings, URL / URLSearchParams classes or newer library functions.
 *
 *   GET /health                          -> {"ok":true}
 *   GET /portal?u=<url>&mac=..&token=..  -> the portal's answer, with the box headers added
 *   GET /stream?u=<url>                  -> a stream through the helper; HLS playlists are rewritten
 *                                           so their segments come through here too
 *   GET /fetch?u=<url>                   -> any other URL (logos, XMLTV) with CORS added
 *   GET /opensubtitles/search|download   -> OpenSubtitles with the headers it wants (see below)
 *   GET /pair/start?kind=..&title=..     -> opens the phone keyboard (see below); {code, session, urls}
 *   GET /pair/result?session=..          -> what the phone has sent so far
 *   GET /pair/stop?session=..            -> closes the phone keyboard
 *
 * Phone keyboard: typing on a TV remote is miserable, so while a screen needs typing (provider
 * setup, Search, a profile name) a second server answers on the home network (PAIR_PORT) with a
 * page that shows the matching form. It only answers a phone that has the code shown on the TV,
 * locks for a minute after a few wrong codes, never sends the TV's settings back, and closes when
 * the screen does (or after 15 minutes).
 */
'use strict';

const http = require('http');
const os = require('os');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const https = require('https');
const zlib = require('zlib');
const urlLib = require('url');
const querystring = require('querystring');

const PORT = Number(process.env.DEVEN_PROXY_PORT || 3001);
const PAIR_PORT = Number(process.env.DEVEN_PAIR_PORT || 3002);
const MAG_UA =
  'Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 2 rev: 250 Safari/533.3';
const keepAliveHttp = new http.Agent({ keepAlive: true, maxSockets: 8 });
const keepAliveHttps = new https.Agent({ keepAlive: true, maxSockets: 8, rejectUnauthorized: false });

/** Cookies the portal sets, kept per host + MAC so two boxes never share a session. */
const cookieJar = new Map();

function jarKey(host, mac) {
  return host + '|' + (mac || '');
}

function rememberCookies(host, mac, setCookie) {
  if (!setCookie) return;
  const jar = cookieJar.get(jarKey(host, mac)) || {};
  for (const line of [].concat(setCookie)) {
    const pair = String(line).split(';')[0];
    const eq = pair.indexOf('=');
    if (eq > 0) jar[pair.slice(0, eq).trim()] = pair.slice(eq + 1).trim();
  }
  cookieJar.set(jarKey(host, mac), jar);
}

function cookieHeader(host, mac, tz, adid) {
  const base = { mac: mac ? encodeURIComponent(mac) : undefined, stb_lang: 'en', timezone: tz || 'UTC' };
  if (adid) base.adid = adid;
  const jar = cookieJar.get(jarKey(host, mac)) || {};
  const all = Object.assign({}, jar, base);
  return Object.keys(all)
    .filter((k) => all[k] !== undefined)
    .map((k) => k + '=' + all[k])
    .join('; ');
}

/** A request URL's query as an object with get(), like URLSearchParams (which old Node lacks). */
function queryOf(u) {
  const q = querystring.parse(urlLib.parse(u).query || '');
  return { get: (k) => (q[k] === undefined ? null : [].concat(q[k])[0]) };
}

function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
}

function fail(res, code, message) {
  if (res.headersSent) {
    res.end();
    return;
  }
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: message }));
}

/** GET [target] with [headers], following up to 5 redirects; calls back with the upstream response. */
function get(target, headers, cb, redirects) {
  return send('GET', target, headers, null, cb, redirects);
}

/** Like get(), with a method and an optional body (redirects are followed as GETs). */
function send(method, target, headers, body, cb, redirects) {
  const url = urlLib.parse(String(target));
  if (!/^https?:$/.test(url.protocol || '') || !url.host) {
    cb(new Error('bad url'));
    return null;
  }
  const lib = url.protocol === 'https:' ? https : http;
  let answered = false;
  const answer = (err, up) => {
    if (answered) return;
    answered = true;
    cb(err, up, url);
  };
  const options = Object.assign({}, url, {
    method: method,
    headers: Object.assign({ Host: url.host }, headers, body ? { 'Content-Length': Buffer.byteLength(body) } : {}),
    agent: url.protocol === 'https:' ? keepAliveHttps : keepAliveHttp
  });
  const req = lib.request(options, (up) => {
    const left = redirects === undefined ? 5 : redirects;
    if (up.statusCode >= 300 && up.statusCode < 400 && up.headers.location && left > 0) {
      up.resume();
      answered = true;
      get(urlLib.resolve(url.href, up.headers.location), headers, cb, left - 1);
      return;
    }
    answer(null, up);
  });
  req.setTimeout(30000, () => {
    req.abort();
    answer(new Error('timeout'));
  });
  req.on('error', (e) => answer(e));
  req.end(body || undefined);
  return req;
}

function decode(up, done) {
  const chunks = [];
  up.on('data', (c) => chunks.push(c));
  up.on('end', () => {
    const raw = Buffer.concat(chunks);
    const enc = String(up.headers['content-encoding'] || '').toLowerCase();
    const finish = (err, buf) => done(err ? raw : buf);
    if (enc.includes('gzip')) zlib.gunzip(raw, finish);
    else if (enc.includes('deflate')) zlib.inflate(raw, (e, b) => (e ? zlib.inflateRaw(raw, finish) : finish(null, b)));
    else done(raw);
  });
  up.on('error', () => done(Buffer.concat(chunks)));
}

function handlePortal(query, res) {
  const target = query.get('u');
  const mac = query.get('mac') || '';
  const token = query.get('token') || '';
  const tz = query.get('tz') || 'UTC';
  // A MAG-locked portal: the box's own browser identity, passed by the client (store/settings MagBox).
  const ua = query.get('ua') || '';
  const model = query.get('model') || '';
  const adid = query.get('adid') || '';
  if (!target) return fail(res, 400, 'missing u');
  const host = urlLib.parse(target).host;
  if (!host) return fail(res, 400, 'bad url');
  const origin = target.replace(/^(https?:\/\/[^/]+).*$/, '$1');
  const headers = {
    'User-Agent': ua || MAG_UA,
    'X-User-Agent': model ? 'Model: ' + model + '; Link: WiFi' : 'Model: MAG250; Link: WiFi',
    Accept: '*/*',
    'Accept-Encoding': 'gzip, deflate',
    Cookie: cookieHeader(host, mac, tz, adid),
    Referer: origin + '/c/',
  };
  if (token) headers.Authorization = 'Bearer ' + token;
  get(target, headers, (err, up) => {
    if (err) return fail(res, 502, err.message);
    rememberCookies(host, mac, up.headers['set-cookie']);
    decode(up, (body) => {
      res.writeHead(up.statusCode || 502, {
        'Content-Type': up.headers['content-type'] || 'application/json',
        'X-Upstream-Url': up.req && up.req.path ? up.req.path.split('?')[0] : '',
      });
      res.end(body);
    });
  });
}

/** Rewrite every URI in an HLS playlist so its segments and sub-playlists come through /stream. */
function rewritePlaylist(text, base) {
  const via = (u) => '/stream?u=' + encodeURIComponent(urlLib.resolve(base, u));
  return text
    .split(/\r?\n/)
    .map((line) => {
      const t = line.trim();
      if (!t) return line;
      if (t.startsWith('#')) return line.replace(/URI="([^"]+)"/g, (_, u) => 'URI="' + via(u) + '"');
      return via(t);
    })
    .join('\n');
}

function handleStream(query, req, res) {
  const target = query.get('u');
  if (!target) return fail(res, 400, 'missing u');
  const headers = { 'User-Agent': MAG_UA, Accept: '*/*' };
  if (req.headers.range) headers.Range = req.headers.range;
  const upReq = get(target, headers, (err, up, finalUrl) => {
    if (err) return fail(res, 502, err.message);
    const type = String(up.headers['content-type'] || '').toLowerCase();
    const isPlaylist = type.includes('mpegurl') || /\.m3u8?($|\?)/i.test(finalUrl.pathname);
    if (isPlaylist) {
      decode(up, (body) => {
        const text = body.toString('utf8');
        // Only a real playlist is rewritten; an error page passes through so the player sees the error.
        if ((up.statusCode || 200) >= 400 || !text.replace(/^\s+/, '').startsWith('#EXTM3U')) {
          res.writeHead(up.statusCode && up.statusCode >= 400 ? up.statusCode : 502, { 'Content-Type': 'text/plain; charset=utf-8' });
          return res.end(`stream refused (${up.statusCode})`);
        }
        res.writeHead(up.statusCode || 200, { 'Content-Type': 'application/vnd.apple.mpegurl' });
        res.end(rewritePlaylist(text, finalUrl.href));
      });
      return;
    }
    const out = { 'Content-Type': up.headers['content-type'] || 'video/mp2t' };
    for (const h of ['content-length', 'content-range', 'accept-ranges']) if (up.headers[h]) out[h] = up.headers[h];
    res.writeHead(up.statusCode || 200, out);
    up.pipe(res);
  });
  req.on('close', () => upReq && upReq.abort());
}

function handleFetch(query, res) {
  const target = query.get('u');
  if (!target) return fail(res, 400, 'missing u');
  get(target, { 'User-Agent': MAG_UA, Accept: '*/*', 'Accept-Encoding': 'gzip, deflate' }, (err, up) => {
    if (err) return fail(res, 502, err.message);
    decode(up, (body) => {
      res.writeHead(up.statusCode || 200, { 'Content-Type': up.headers['content-type'] || 'application/octet-stream' });
      res.end(body);
    });
  });
}

/**
 * A page that plays one YouTube trailer, filling the frame. The app embeds it from here because
 * YouTube refuses embeds on pages loaded from files (no referrer). `sound=1` plays with sound (the
 * full-screen trailer); otherwise muted and looping behind the artwork. The page tells the app what
 * the video is doing (postMessage {devenTrailer: 'playing' | 'ended' | 'error'}), so the app can keep
 * it hidden until it really plays, and takes {devenTrailer: 'toggle'} to pause or resume and
 * {devenTrailer: 'unmute'} to turn the sound on (it always starts muted, so it can start out of sight).
 */
function handleTrailer(params, res) {
  const id = String(params.get('v') || '');
  if (!/^[\w-]{6,20}$/.test(id)) return fail(res, 400, 'bad video id');
  const sound = params.get('sound') === '1';
  const vars = JSON.stringify({
    autoplay: 1,
    mute: 1,
    controls: 0,
    // Played once, as Netflix does: when it ends the page goes back to the artwork.
    loop: 0,
    modestbranding: 1,
    rel: 0,
    playsinline: 1,
    iv_load_policy: 3,
    cc_load_policy: 0,
    disablekb: 1,
    fs: 0,
    vq: 'hd1080'
  });
  const html = `<!doctype html><html><head><meta name="referrer" content="origin"><style>
html,body{margin:0;height:100%;background:#000;overflow:hidden}
#p{position:absolute;top:50%;left:50%;width:1920px;height:1080px;transform:translate(-50%,-50%);pointer-events:none}
</style></head><body><div id="p"></div><script>
function tell(state) { parent.postMessage({ devenTrailer: state }, '*'); }
// YouTube picks the quality from the player's size, so it's laid out at 1920x1080 (for 1080p) and
// scaled to cover the frame, zoomed a little when muted to crop its title and buttons.
function fit() {
  var el = document.getElementById('p');
  var s = Math.max(innerWidth / 1920, innerHeight / 1080) * ${sound ? 1 : 1.35};
  if (el) el.style.transform = 'translate(-50%,-50%) scale(' + s + ')';
}
addEventListener('resize', fit);
// YouTube turns captions on for muted autoplay whatever cc_load_policy says, loading its captions
// module after playback starts: each time it loads, the track is cleared and the module unloaded.
// Said a moment before the end, so the page has faded back to the artwork before YouTube's end
// screen (more videos) appears.
var ended = false;
function ending() {
  if (ended) return;
  ended = true;
  tell('ended');
}
setInterval(function () {
  try {
    var d = player.getDuration();
    if (d > 0 && d - player.getCurrentTime() < 1.5) ending();
  } catch (e) {}
}, 250);
function noCaptions() {
  try { player.setOption('captions', 'track', {}); } catch (e) {}
  try { player.unloadModule('captions'); player.unloadModule('cc'); } catch (e) {}
}
var player;
function onYouTubeIframeAPIReady() {
  fit();
  player = new YT.Player('p', {
    host: 'https://www.youtube-nocookie.com',
    videoId: '${id}',
    playerVars: ${vars},
    events: {
      onReady: function () { fit(); noCaptions(); },
      // Fires when a module (captions among them) loads, which it does after playback starts.
      onApiChange: noCaptions,
      onStateChange: function (e) {
        if (e.data === YT.PlayerState.PLAYING) { noCaptions(); tell('playing'); }
        else if (e.data === YT.PlayerState.ENDED) ending();
      },
      onError: function () { tell('error'); }
    }
  });
}
addEventListener('message', function (e) {
  if (!player || !e.data) return;
  if (e.data.devenTrailer === 'unmute') { player.unMute(); player.setVolume(100); }
  if (e.data.devenTrailer !== 'toggle') return;
  if (player.getPlayerState() === YT.PlayerState.PLAYING) player.pauseVideo(); else player.playVideo();
});
</script><script src="https://www.youtube.com/iframe_api" onerror="tell('error')"></script></body></html>`;
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(html);
}

// --- OpenSubtitles ---

const OS_API = 'https://api.opensubtitles.com/api/v1';

/**
 * OpenSubtitles wants an Api-Key and a User-Agent naming the app, which a web page can't send, so
 * the app asks here with plain GETs:
 *   /opensubtitles/search?key=..&<their search parameters>  -> their /subtitles answer
 *   /opensubtitles/download?key=..&file_id=..               -> {link, remaining} (POST /download)
 */
function handleOpenSubtitles(path, params, query, res) {
  const key = params.get('key');
  if (!key) return fail(res, 400, 'missing key');
  const headers = { 'Api-Key': key, 'User-Agent': 'DevEN v0.1.0', Accept: 'application/json', 'Accept-Encoding': 'gzip, deflate' };
  const relay = (err, up) => {
    if (err) return fail(res, 502, err.message);
    decode(up, (body) => {
      res.writeHead(up.statusCode || 502, { 'Content-Type': 'application/json' });
      res.end(body);
    });
  };
  if (path === '/opensubtitles/search') {
    // Everything but our own key goes through as their search parameters.
    const q = querystring.parse(query || '');
    delete q.key;
    return get(OS_API + '/subtitles?' + querystring.stringify(q), headers, relay);
  }
  const fileId = Number(params.get('file_id'));
  if (!fileId) return fail(res, 400, 'missing file_id');
  send('POST', OS_API + '/download', Object.assign({ 'Content-Type': 'application/json' }, headers), JSON.stringify({ file_id: fileId }), relay);
}

// --- Phone keyboard ---

const PAIR_TTL = 15 * 60 * 1000;
const PAIR_TRIES = 5;
const LOCKOUT = 60 * 1000;
// --- Over-the-air updates (see src/ota/ota.ts) ---

/** This helper's version: "dev" in the repo, the release's when packaged or published. */
const HELPER_VERSION = '0.3.16';
/** The release key's public half: an update runs only if its manifest carries this key's signature. */
const OTA_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+3/xRrt+MGWULR+3ubnIFC/kbnSl\nNJsgcRYAnEnGFLrF3R2KcVuqmffbQujwiVxT9j2aleq/toThMexfNpGQlg==\n-----END PUBLIC KEY-----\n';
/** Where a downloaded helper is kept: the entry file (service/boot.cjs) finds a writable folder. */
function otaDir() {
  return global.__devenOtaDir || process.env.DEVEN_DATA || null;
}
const OTA_FILE = 'helper-ota.cjs';
const OTA_META = 'helper-ota.json';

/** Whether version a is newer than b ("dev" counts as 0). */
function newerVersion(a, b) {
  const parts = (v) => (/^\d+(\.\d+)*$/.test(String(v)) ? String(v).split('.').map(Number) : [0]);
  const x = parts(a);
  const y = parts(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (x[i] || 0) - (y[i] || 0);
    if (d) return d > 0;
  }
  return false;
}

function pendingHelper() {
  const dir = otaDir();
  if (!dir) return null;
  try {
    return JSON.parse(fs.readFileSync(path.join(dir, OTA_META), 'utf8'));
  } catch (e) {
    return null;
  }
}

/**
 * /ota/version, /ota/helper, /ota/activate (the app only). A new helper arrives with the signed
 * manifest; it's kept only if the signature is the release key's and the file matches the
 * manifest's checksum, and runs from the next start (or /ota/activate).
 */
function handleOta(path_, req, res) {
  const json = (status, data) => {
    res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify(data));
  };
  const pending = pendingHelper();
  if (path_ === '/ota/version') {
    // `keptIn`: where updates are kept (useful when one doesn't stick).
    return json(200, { version: HELPER_VERSION, running: global.__devenHelperRunning || HELPER_VERSION, pending: pending ? pending.version : null, canUpdate: !!otaDir() && typeof global.__devenHelperSwap === 'function', keptIn: otaDir() });
  }
  if (req.method !== 'POST') return json(405, { error: 'POST' });
  // A pulled helper: forget the downloaded one and start the installed one again.
  if (path_ === '/ota/revert') {
    const dir = otaDir();
    if (dir) {
      [OTA_FILE, OTA_META].forEach((f) => {
        try {
          fs.unlinkSync(path.join(dir, f));
        } catch (e) {
          // already gone
        }
      });
    }
    json(202, { ok: true });
    if (typeof global.__devenHelperSwap === 'function') setTimeout(() => global.__devenHelperSwap(), 100);
    return;
  }
  if (path_ === '/ota/activate') {
    if (!pending || !newerVersion(pending.version, HELPER_VERSION) || typeof global.__devenHelperSwap !== 'function') return json(200, { ok: false });
    json(202, { ok: true, version: pending.version });
    return setTimeout(() => global.__devenHelperSwap(), 100);
  }
  if (path_ !== '/ota/helper') return json(404, { error: 'not found' });
  readJson(req, (data) => {
    const dir = otaDir();
    if (!data || !dir) return json(400, { error: 'nowhere to keep it' });
    try {
      const verify = crypto.createVerify('sha256');
      verify.update(String(data.manifest));
      if (!verify.verify(OTA_PUBLIC_KEY, String(data.sig), 'base64')) return json(403, { error: 'not signed by the release key' });
      const m = JSON.parse(data.manifest);
      const code = String(data.code);
      if (crypto.createHash('sha256').update(code, 'utf8').digest('hex') !== m.helper.sha256) return json(400, { error: 'checksum' });
      if (!newerVersion(m.helper.version, HELPER_VERSION)) return json(200, { ok: false, reason: 'not newer' });
      fs.writeFileSync(path.join(dir, OTA_FILE + '.tmp'), code);
      fs.renameSync(path.join(dir, OTA_FILE + '.tmp'), path.join(dir, OTA_FILE));
      fs.writeFileSync(path.join(dir, OTA_META), JSON.stringify({ version: m.helper.version, sha256: m.helper.sha256 }));
      json(200, { ok: true, version: m.helper.version });
    } catch (e) {
      json(500, { error: String(e && e.message) });
    }
  }, 1024 * 1024);
}

/** The biggest backup (profiles, lists, progress, settings) taken or restored through the phone page. */
const BACKUP_MAX = 2 * 1024 * 1024;
// One code for as long as the helper runs, so a phone tab left open keeps working from one screen
// to the next. Five wrong codes in a row lock the form for a minute and change the code.
let pairCode = null;
let wrongTries = 0;
let lockedUntil = 0;
let sessions = 0;
let pair = null; // { session, kind, title, value, server, timer, result, seq }

function newCode() {
  pairCode = ('00000' + (crypto.randomBytes(4).readUInt32BE(0) % 1000000)).slice(-6);
  wrongTries = 0;
}

function lanAddresses() {
  const out = [];
  const all = os.networkInterfaces();
  for (const list of Object.keys(all).map((k) => all[k])) {
    for (const a of list || []) {
      if ((a.family === 'IPv4' || a.family === 4) && !a.internal) out.push(a.address);
    }
  }
  // Home networks first (192.168 / 10 / 172.16-31), anything else after.
  const home = (ip) => /^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip);
  return out.sort((a, b) => Number(home(b)) - Number(home(a)));
}

function stopPairing() {
  if (!pair) return;
  clearTimeout(pair.timer);
  pair.server.close();
  pair = null;
}

/** Compares two codes in constant time, so how long a guess takes says nothing about the code. */
function sameCode(a, b) {
  if (!b || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function codeOk(given) {
  if (sameCode(String(given || '').replace(/\D/g, ''), pairCode)) {
    wrongTries = 0;
    return true;
  }
  wrongTries += 1;
  if (wrongTries >= PAIR_TRIES) {
    lockedUntil = Date.now() + LOCKOUT;
    newCode();
  }
  return false;
}

/** The page the phone opens. It asks the TV what it wants typed and shows the matching form. */
const PHONE_PAGE = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>DevEN keyboard</title><style>
body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#0b0d10;color:#f2f4f7}
main{max-width:440px;margin:0 auto;padding:32px 20px}
h1{font-size:26px;margin:0 0 6px}p{color:#9aa3ad;margin:0 0 24px;line-height:1.4}
label{display:block;font-weight:600;font-size:14px;margin:0 0 16px;color:#c9d0d8}
input,textarea{display:block;box-sizing:border-box;width:100%;margin-top:6px;padding:12px;font-size:16px;border-radius:10px;border:1px solid #2a3038;background:#14171c;color:#f2f4f7}
textarea{resize:vertical;font-family:inherit}
input.big{font-size:22px;padding:16px}
button{width:100%;padding:14px;font-size:17px;font-weight:700;border:0;border-radius:10px;background:#19c3b0;color:#04201c}
.msg{padding:14px;border-radius:10px;margin-bottom:20px;background:#14171c}.err{background:#3a1416;color:#ffb4b4}
.log{white-space:pre-wrap;word-break:break-word;font-size:12px;line-height:1.45;background:#14171c;border-radius:10px;padding:12px;color:#c9d0d8}
.or{margin:32px 0 12px;color:#c9d0d8;font-weight:600}.note{font-size:14px}a{text-decoration:none}a button{display:block}
h2{font-size:19px;margin:28px 0 6px}.tag{font-size:12px;font-weight:600;color:#9aa3ad;margin-left:8px}
ol{padding-left:22px;margin:0 0 8px;color:#c9d0d8;line-height:1.45}li{margin-bottom:14px}
button.link{margin-top:8px;background:#22272e;color:#f2f4f7;font-size:15px;padding:11px}
.ans{display:flex;align-items:center;gap:10px;margin:8px 0;padding:8px 10px;border-radius:8px;background:#14171c}.ans span{flex:1;font-size:14px}
button.copy{width:auto;padding:7px 12px;font-size:13px;background:#22272e;color:#f2f4f7}
.ok{background:#0f2e29;color:#7ee8d8}details{margin:4px 0 22px}summary{color:#19c3b0;font-weight:600;cursor:pointer;margin-bottom:6px}
</style></head><body><main id="m"><h1>DevEN</h1><p>Connecting to your TV…</p></main><script>
var m = document.getElementById('m');
var q = new URLSearchParams(location.search);
var code = q.get('c') || '';
try { code = code || localStorage.getItem('deven.code') || ''; } catch (e) {}
var session = null, timer = 0, sendTimer = 0;
function esc(s) { var d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
function later(ms) { clearTimeout(timer); timer = setTimeout(tick, ms || 1500); }
function page(title, body) { m.innerHTML = '<h1>' + esc(title) + '</h1>' + body; }
function send(data) {
  return fetch('/send?c=' + encodeURIComponent(code), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
}
// Getting the two free keys, step by step (TMDB's key form isn't made for phones: this page opens on a computer too).
var SUMMARY = 'Personal TV app that shows posters and details for what I watch at home.';
function linkBtn(href, label) { return '<a href="' + href + '" target="_blank" rel="noopener"><button type="button" class="link">' + esc(label) + '</button></a>'; }
function copyBtn(text) { return '<button type="button" class="copy" data-copy="' + esc(text) + '">Copy</button>'; }
function guide() {
  return '<h2>TMDB<span class="tag">recommended</span></h2>' +
    '<p>Adds posters, cast, trailers and the Trending rows. Free, about 5 minutes. TMDB\\u2019s key form is easier on a computer: on the same Wi-Fi, open <b>' + esc(location.host) + '</b> there and enter the same code.</p><ol>' +
    '<li>Make a free account, then confirm the email TMDB sends you.' + linkBtn('https://www.themoviedb.org/signup', 'Open TMDB sign-up') + '</li>' +
    '<li>Signed in, open your API settings and create a key for personal use. Accept their terms.' + linkBtn('https://www.themoviedb.org/settings/api', 'Open TMDB API settings') + '</li>' +
    '<li>If it asks about your app, you can use:' +
    '<div class="ans"><span>Name: <b>DevEN</b></span>' + copyBtn('DevEN') + '</div>' +
    '<div class="ans"><span>Website: <b>http://localhost</b></span>' + copyBtn('http://localhost') + '</div>' +
    '<div class="ans"><span>Summary: ' + esc(SUMMARY) + '</span>' + copyBtn(SUMMARY) + '</div>Fill in the rest with your own details.</li>' +
    '<li>Copy the <b>API Key</b>: the short one, 32 letters and numbers. Not the long \\u201cAPI Read Access Token\\u201d.</li></ol>' +
    '<h2>OpenSubtitles<span class="tag">optional</span></h2><p>Finds subtitles online when a movie has none.</p><ol>' +
    '<li>Make a free account, then confirm the email.' + linkBtn('https://www.opensubtitles.com', 'Open OpenSubtitles') + '</li>' +
    '<li>In your account, open <b>API consumers</b> and add one called DevEN.' + linkBtn('https://www.opensubtitles.com/en/consumers', 'Open API consumers') + '</li>' +
    '<li>Copy its <b>API key</b>.</li></ol>';
}
// Plain http on the home network has no clipboard API: copy the old way.
function wireCopy() {
  [].forEach.call(m.querySelectorAll('[data-copy]'), function (b) {
    b.onclick = function () {
      var t = document.createElement('textarea');
      t.value = b.getAttribute('data-copy');
      document.body.appendChild(t);
      t.select();
      try { document.execCommand('copy'); b.textContent = 'Copied'; } catch (e) {}
      document.body.removeChild(t);
    };
  });
}
// After sending keys: the TV tries each one and says how it went.
function waitFeedback(n) {
  fetch('/state?c=' + encodeURIComponent(code)).then(function (r) { return r.json(); }).then(function (s) {
    var fb = document.getElementById('fb');
    if (!fb) return;
    if (s.feedback && s.feedback.lines) {
      fb.innerHTML = s.feedback.lines.map(function (l) { return '<div class="msg ' + (l.ok ? 'ok' : 'err') + '">' + esc(l.text) + '</div>'; }).join('');
      return;
    }
    if (n < 20) setTimeout(function () { waitFeedback(n + 1); }, 1500);
    else fb.innerHTML = '<div class="msg err">The TV didn\\u2019t answer. Is DevEN still open on it?</div>';
  }).catch(function () { if (n < 20) setTimeout(function () { waitFeedback(n + 1); }, 1500); });
}
function askCode(error) {
  session = null;
  page('DevEN', '<p>Enter the code shown on your TV.</p>' + (error ? '<div class="msg err">' + esc(error) + '</div>' : '') +
    '<form id="f"><label>Code<input id="c" class="big" inputmode="numeric" autocomplete="off" required></label><button>Continue</button></form>');
  document.getElementById('f').onsubmit = function (e) { e.preventDefault(); code = document.getElementById('c').value.replace(/\\D/g, ''); tick(); };
}
// A backup file chosen on the phone goes to the TV as it is; the TV checks it.
function restoreForm() {
  return '<form id="r"><label>Restore from a backup<input id="file" type="file" accept=".json,application/json" required></label><button>Restore on TV</button></form>';
}
function wireRestore() {
  var r = document.getElementById('r');
  if (!r) return;
  r.onsubmit = function (e) {
    e.preventDefault();
    var file = document.getElementById('file').files[0];
    if (!file) return;
    var reader = new FileReader();
    reader.onload = function () {
      var data;
      try { data = JSON.parse(reader.result); } catch (err) { data = null; }
      if (!data || data.app !== 'DevEN') return page('Not a DevEN backup', '<div class="msg err">Pick the file you downloaded from DevEN.</div>' + restoreForm()) || wireRestore();
      send({ restore: data }).then(function (res) {
        page(res.ok ? 'Sent' : 'Too big', '<div class="msg' + (res.ok ? '' : ' err') + '">' + (res.ok ? 'Check your TV.' : 'That file is too big.') + '</div>');
      });
    };
    reader.readAsText(file);
  };
}
function render(s) {
  if (s.kind === 'keys') {
    page('Get your free keys', '<p>Two free keys make DevEN look and work its best. Follow the steps, paste the keys at the bottom and tap Send: your TV tries them.</p>' + guide() +
      '<h2>Paste your keys</h2><form id="f">' +
      '<label>TMDB API key<input name="tmdbKey" autocomplete="off" autocapitalize="off" spellcheck="false"></label>' +
      '<label>OpenSubtitles API key (optional)<input name="subtitlesKey" autocomplete="off" autocapitalize="off" spellcheck="false"></label>' +
      '<button>Send to TV</button></form><div id="fb" style="margin-top:16px"></div>');
    wireCopy();
    var kf = document.getElementById('f');
    kf.onsubmit = function (e) {
      e.preventDefault();
      if (!kf.tmdbKey.value.trim() && !kf.subtitlesKey.value.trim()) return;
      document.getElementById('fb').innerHTML = '<div class="msg">Trying them on your TV\\u2026</div>';
      send({ tmdbKey: kf.tmdbKey.value, subtitlesKey: kf.subtitlesKey.value }).then(function () { waitFeedback(0); });
    };
    return;
  }
  if (s.kind === 'diag') {
    page('DevEN diagnostics', '<p>What this TV has logged. Send it to whoever looks after DevEN for you.</p>' +
      '<p><button type="button" id="share">Share</button></p>' +
      '<p><a href="/diag?c=' + encodeURIComponent(code) + '" download="deven-diagnostics.txt"><button type="button">Download as a file</button></a></p>' +
      '<pre id="log" class="log">Loading…</pre>');
    fetch('/diag?c=' + encodeURIComponent(code)).then(function (r) { return r.text(); }).then(function (text) {
      document.getElementById('log').textContent = text;
      document.getElementById('share').onclick = function () {
        if (navigator.share) navigator.share({ title: 'DevEN diagnostics', text: text }).catch(function () {});
        else if (navigator.clipboard) navigator.clipboard.writeText(text).then(function () { document.getElementById('share').textContent = 'Copied'; });
      };
    });
    return;
  }
  if (s.kind === 'backup') {
    page('Move DevEN', '<p>Download this TV\u2019s profiles, My List, watch progress and settings to your phone. On the other TV, open the same page and restore it.</p>' +
      '<p><a href="/backup?c=' + encodeURIComponent(code) + '" download="deven-backup.json"><button type="button">Download backup</button></a></p>' +
      '<p class="note">The file holds your provider login too: keep it to yourself.</p>' + restoreForm());
    wireRestore();
    return;
  }
  if (s.kind === 'setup') {
    page('Set up DevEN', '<p>Fill this in and your TV will connect by itself.</p><form id="f">' +
      '<label>Portal name (optional)<input name="portalName" placeholder="My provider" autocomplete="off" spellcheck="false"></label>' +
      '<label>Portal address<input name="portalUrl" placeholder="http://example.com/c/" inputmode="url" autocomplete="off" autocapitalize="off" spellcheck="false" required></label>' +
      '<label>MAC address<input name="mac" placeholder="00:1A:79:00:00:00" autocomplete="off" autocapitalize="off" spellcheck="false" required></label>' +
      '<label>TMDB API key (optional)<input name="tmdbKey" placeholder="Leave empty to keep the current one" autocomplete="off" autocapitalize="off" spellcheck="false"></label>' +
      '<label>OpenSubtitles API key (optional)<input name="subtitlesKey" placeholder="Leave empty to keep the current one" autocomplete="off" autocapitalize="off" spellcheck="false"></label>' +
      '<details><summary>How do I get these free keys?</summary>' + guide() + '</details>' +
      '<details><summary>Subscription locked to a MAG box?</summary>' +
      '<p class="note">Only if your provider tied this line to a physical MAG box. Paste the box details here (most portals only need the two device ids); leave the MAC above set to the box MAC.</p>' +
      '<label>MAG box details<textarea name="boxText" rows="6" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="MAG_SN=...\\nMAG_DEVICE_ID=...\\nMAG_DEVICE_ID2=..."></textarea></label></details>' +
      '<button>Send to TV</button></form>');
    wireCopy();
    var f = document.getElementById('f');
    f.onsubmit = function (e) {
      e.preventDefault();
      send({ portalName: f.portalName.value, portalUrl: f.portalUrl.value, mac: f.mac.value, tmdbKey: f.tmdbKey.value, subtitlesKey: f.subtitlesKey.value, boxText: f.boxText.value }).then(function () { page('Sent', '<div class="msg">Check your TV.</div>'); });
    };
    // Moving from another TV: its backup sets up everything at once.
    m.insertAdjacentHTML('beforeend', '<p class="or">Moving from another TV?</p>' + restoreForm());
    wireRestore();
  } else {
    page(s.title || 'Type', '<p>' + (s.live ? 'Your TV updates as you type. The mic on your keyboard works too.' : 'Type here, then tap Done.') + '</p>' +
      '<form id="f"><input id="t" class="big" autocomplete="off" spellcheck="false"><br><button>Done</button></form>');
    var t = document.getElementById('t');
    t.value = s.value || '';
    t.focus();
    t.oninput = function () { clearTimeout(sendTimer); sendTimer = setTimeout(function () { send({ text: t.value }); }, 250); };
    document.getElementById('f').onsubmit = function (e) {
      e.preventDefault();
      clearTimeout(sendTimer);
      send({ text: t.value, final: true }).then(function () { if (!s.live) page('Sent', '<div class="msg">Check your TV.</div>'); else t.blur(); });
    };
  }
}
function tick() {
  if (!code) return askCode();
  fetch('/state?c=' + encodeURIComponent(code)).then(function (r) {
    if (r.status === 403) { code = ''; try { localStorage.removeItem('deven.code'); } catch (e) {} return askCode('That code doesn’t match the one on the TV.'); }
    if (r.status === 429) { page('DevEN', '<div class="msg err">Too many wrong codes. Wait a minute, then try the code on the TV again.</div>'); session = null; return later(5000); }
    return r.json().then(function (s) {
      try { localStorage.setItem('deven.code', code); } catch (e) {}
      if (s.session !== session) { session = s.session; render(s); }
      later();
    });
  }).catch(function () {
    if (session !== 'idle') { session = 'idle'; page('DevEN', '<p>Nothing to type right now. Open Search or setup on the TV and this page will follow.</p>'); }
    later(2500);
  });
}
tick();
</script></body></html>`;

/** A JSON request body, up to [limit] characters (4 KB unless said); null when it isn't JSON. */
function readJson(req, cb, limit) {
  const max = limit || 4096;
  let body = '';
  req.on('data', (chunk) => {
    body += chunk;
    if (body.length > max) req.destroy();
  });
  req.on('end', () => {
    try {
      cb(JSON.parse(body || '{}'));
    } catch (e) {
      cb(null);
    }
  });
}

function handlePhone(req, res) {
  // No kept-alive connections: closing the phone keyboard has to cut off the phone at once.
  res.setHeader('Connection', 'close');
  const json = (status, data) => {
    res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify(data));
  };
  const path = urlLib.parse(req.url).pathname;
  const params = queryOf(req.url);
  if (path === '/' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    return res.end(PHONE_PAGE);
  }
  const p = pair;
  if (!p) return json(410, { error: 'closed' });
  if (Date.now() < lockedUntil) return json(429, { error: 'locked' });
  if (!codeOk(params.get('c'))) return json(403, { error: 'code' });
  if (path === '/diag' && req.method === 'GET') {
    if (p.kind !== 'diag' || !p.backup) return json(404, { error: 'no log' });
    let text = '';
    try {
      text = String(JSON.parse(p.backup).report || '');
    } catch (e) {
      text = '';
    }
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Content-Disposition': 'attachment; filename="deven-diagnostics.txt"', 'Cache-Control': 'no-store' });
    return res.end(text);
  }
  if (path === '/backup' && req.method === 'GET') {
    if (p.kind !== 'backup' || !p.backup) return json(404, { error: 'no backup' });
    res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Disposition': 'attachment; filename="deven-backup.json"', 'Cache-Control': 'no-store' });
    return res.end(p.backup);
  }
  if (path === '/state' && req.method === 'GET') {
    let feedback;
    try {
      feedback = p.kind === 'keys' && p.backup ? JSON.parse(p.backup) : undefined;
    } catch (e) {
      feedback = undefined;
    }
    return json(200, { session: p.session, kind: p.kind, title: p.title, live: p.live, value: p.kind === 'text' ? p.value : undefined, feedback: feedback });
  }
  if (path === '/send' && req.method === 'POST') {
    return readJson(req, (data) => {
      if (!data || pair !== p) return json(400, { error: 'bad request' });
      const clean = (v, max) => String(v == null ? '' : v).trim().slice(0, max);
      // A backup to restore (from the backup page, or setting up a new TV): the TV checks it.
      if (data.restore && (p.kind === 'backup' || p.kind === 'setup')) {
        if (data.restore.app !== 'DevEN' || typeof data.restore.keys !== 'object') return json(400, { error: 'not a backup' });
        p.result = { restore: data.restore };
        return json(200, { ok: true });
      }
      if (p.kind === 'keys') {
        // Each send goes to the TV once (seq); the TV's answer about the one before is cleared.
        p.seq += 1;
        p.backup = null;
        p.result = { keys: { tmdbKey: clean(data.tmdbKey, 200), subtitlesKey: clean(data.subtitlesKey, 200) }, seq: p.seq };
      } else if (p.kind === 'setup') {
        p.result = { settings: { portalName: clean(data.portalName, 30), portalUrl: clean(data.portalUrl, 300), mac: clean(data.mac, 40), tmdbKey: clean(data.tmdbKey, 200), subtitlesKey: clean(data.subtitlesKey, 200), boxText: clean(data.boxText, 2000) } };
      } else {
        p.value = String(data.text == null ? '' : data.text).slice(0, 100);
        p.seq += 1;
        p.result = { text: p.value, seq: p.seq, final: !!data.final };
      }
      json(200, { ok: true });
    }, p.kind === 'text' ? 4096 : BACKUP_MAX);
  }
  return json(404, { error: 'not found' });
}

/**
 * Opens the phone page for what the TV screen needs typed: kind "setup" (the provider form),
 * "text" (one field; `live` sends every keystroke) or "keys" (how to get the free API keys, and a
 * form for them). Opening again replaces what is asked for.
 */
function startPairing(params, res) {
  const asked = params.get('kind');
  const kind = asked === 'text' || asked === 'backup' || asked === 'diag' || asked === 'keys' ? asked : 'setup';
  const ask = { kind, title: String(params.get('title') || '').slice(0, 60), live: params.get('live') === '1', value: String(params.get('value') || '').slice(0, 100) };
  if (!pairCode) newCode();
  const reply = () => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ code: pairCode, session: pair.session, port: PAIR_PORT, urls: lanAddresses().map((ip) => `http://${ip}:${PAIR_PORT}/`) }));
  };
  if (pair) {
    Object.assign(pair, ask, { session: ++sessions, result: null, seq: 0, backup: null });
    clearTimeout(pair.timer);
    pair.timer = setTimeout(stopPairing, PAIR_TTL);
    return reply();
  }
  const lan = http.createServer(handlePhone);
  lan.on('error', () => {
    if (pair && pair.server === lan) pair = null;
    if (!res.headersSent) fail(res, 503, 'phone keyboard could not start');
  });
  lan.listen(PAIR_PORT, '0.0.0.0', () => {
    pair = Object.assign({ session: ++sessions, server: lan, timer: setTimeout(stopPairing, PAIR_TTL), result: null, seq: 0 }, ask);
    reply();
  });
}

function handlePair(path, params, res, req) {
  res.setHeader('Cache-Control', 'no-store');
  if (path === '/pair/start') return startPairing(params, res);
  // POST /pair/backup?session=..: the backup the phone can download from the backup page.
  if (path === '/pair/backup') {
    return readJson(req, (data) => {
      const p = pair;
      // The backup or log for the phone to download, or (keys page) what the TV made of the keys sent.
      if (!data || !p || (p.kind !== 'backup' && p.kind !== 'diag' && p.kind !== 'keys') || Number(params.get('session')) !== p.session) return fail(res, 400, 'no backup page open');
      p.backup = JSON.stringify(data);
      res.writeHead(204);
      res.end();
    }, BACKUP_MAX);
  }
  if (path === '/pair/stop') {
    // Only close what this screen opened: another screen may have taken over meanwhile.
    if (pair && (!params.get('session') || Number(params.get('session')) === pair.session)) stopPairing();
    res.writeHead(204);
    return res.end();
  }
  // /pair/result?session=..: what the phone sent, only to the screen that asked for it. The
  // provider form is handed over once and then closes.
  const p = pair;
  const out = { pending: !!p, code: pairCode, session: p ? p.session : null };
  if (p && p.result && Number(params.get('session')) === p.session) {
    Object.assign(out, p.result);
    if (p.kind === 'setup' || p.result.restore) stopPairing();
  }
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(out));
}

/** The pairing answer holds the portal login, so only the app itself (file:// on the TV, the dev server on a PC) may read it. */
function appOrigin(origin) {
  return !origin || origin === 'null' || origin.startsWith('file://') || /^https?:\/\/(127\.0\.0\.1|localhost)(:\d+)?$/.test(origin);
}

const server = http.createServer((req, res) => {
  cors(res);
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }
  const path = urlLib.parse(req.url).pathname;
  const params = queryOf(req.url);
  switch (path) {
    case '/health':
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ ok: true, name: 'deven-proxy', version: 1 }));
    case '/portal':
      return handlePortal(params, res);
    case '/stream':
      return handleStream(params, req, res);
    case '/fetch':
      return handleFetch(params, res);
    case '/opensubtitles/search':
    case '/opensubtitles/download':
      return handleOpenSubtitles(path, params, urlLib.parse(req.url).query, res);
    case '/trailer':
      return handleTrailer(params, res);
    case '/pair/start':
    case '/pair/result':
    case '/pair/stop':
    case '/pair/backup':
      if (!appOrigin(req.headers.origin)) return fail(res, 403, 'not allowed');
      return handlePair(path, params, res, req);
    case '/ota/version':
    case '/ota/helper':
    case '/ota/activate':
    case '/ota/revert':
      if (!appOrigin(req.headers.origin)) return fail(res, 403, 'not allowed');
      return handleOta(path, req, res);
    default:
      return fail(res, 404, 'not found');
  }
});

// --- Status for the app ---
// On the TV the app can't see this service's console, so the service tells it how starting went
// through a Tizen message port (if the app is listening). On a PC there is no `tizen`: no-op.

const APP_ID = 'DevENTizen.DevEN';
const STATUS_PORT = 'deven.helper.status';
let status = 'loaded';

function report(text) {
  status = text;
  try {
    if (typeof tizen === 'undefined') return;
    const port = tizen.messageport.requestRemoteMessagePort(APP_ID, STATUS_PORT);
    port.sendMessage([{ key: 'status', value: text }]);
  } catch (e) {
    // The app isn't listening yet; it asks again (onRequest) once it is.
  }
}

process.on('uncaughtException', (e) => report('crashed: ' + (e && e.stack ? String(e.stack).split('\n').slice(0, 2).join(' ') : e)));

server.on('error', (e) => {
  // Already running (the TV restarted the service, or a dev copy is up): nothing to do.
  if (e && e.code === 'EADDRINUSE') return report('port ' + PORT + ' already in use');
  report('could not listen: ' + (e && (e.code || e.message)));
});
server.on('listening', () => report('listening on 127.0.0.1:' + PORT));
server.listen(PORT, '127.0.0.1');

// Tizen web services export lifecycle hooks; on a PC these are simply unused.
module.exports.onStart = function () {
  report(status);
};
// The app launches the service again to ask how it is: answer with the latest status.
module.exports.onRequest = function () {
  report(status);
};
module.exports.onExit = function () {
  stopPairing();
  server.close();
};
/** Stops serving, so a newer helper can take the ports (service/boot.cjs). */
module.exports.shutdown = module.exports.onExit;
