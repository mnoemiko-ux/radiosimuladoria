'use strict';
/*
 * Radio comunitaria IA · El Colorado, Formosa
 * Backend sin dependencias externas (solo módulos incluidos en Node 20 o superior).
 *
 *  - Recibe mensajes de los vecinos (audio o texto) desde cualquier dispositivo.
 *  - Bandeja privada para locutores, protegida con usuario y contraseña.
 *  - Aprobación, categorías, respuestas y cola "al aire" (solo con consentimiento y acción explícita).
 *  - Proxy de voz artificial (ElevenLabs): la clave vive en este servidor y nunca llega al navegador.
 *  - Clonación de voz autorizada (requiere sesión de locutor y declaración de consentimiento).
 */
const http = require('node:http');
const fs = require('node:fs');
const fsp = fs.promises;
const path = require('node:path');
const crypto = require('node:crypto');

/* ------------------------------------------------------------------ configuración */
function loadEnvFile(file){
  try{
    fs.readFileSync(file, 'utf8').split(/\r?\n/).forEach(function(line){
      var m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
      if(!m || m[1] in process.env) return;
      var v = m[2];
      if(/^(['"]).*\1$/.test(v)) v = v.slice(1, -1);
      process.env[m[1]] = v;
    });
  }catch(e){ /* sin archivo .env: se usan variables del sistema */ }
}

function readConfig(over){
  var e = Object.assign({}, process.env, (over && over.env) || {});
  var root = path.resolve(__dirname, '..');
  return {
    port: Number(e.PORT || 3000),
    host: e.HOST || '0.0.0.0',
    production: e.NODE_ENV === 'production',
    dataDir: path.resolve((over && over.dataDir) || e.DATA_DIR || path.join(__dirname, 'data')),
    origins: String(e.ALLOWED_ORIGINS || '').split(',').map(function(s){ return s.trim().replace(/\/$/, ''); }).filter(Boolean),
    sessionHours: Number(e.SESSION_HOURS || 12),
    maxAudioBytes: Math.round(Number(e.MAX_AUDIO_MB || 8) * 1024 * 1024),
    trustProxy: e.TRUST_PROXY === 'true',
    serveStatic: e.SERVE_STATIC !== 'false',
    staticRoot: root,
    elKey: e.ELEVENLABS_API_KEY || '',
    elBase: (e.ELEVENLABS_BASE_URL || 'https://api.elevenlabs.io').replace(/\/$/, ''),
    elModel: e.ELEVENLABS_MODEL || 'eleven_multilingual_v2',
    elVoice: e.ELEVENLABS_VOICE_ID || '',
    publicTts: e.PUBLIC_TTS !== 'false',
    ttsPublicPerHour: Number(e.TTS_PUBLIC_PER_HOUR || 6),
    msgPerHour: Number(e.MESSAGES_PER_HOUR || 10),
    loginAttempts: Number(e.LOGIN_ATTEMPTS || 6)
  };
}

const CATEGORIES = ['consultas-comunitarias', 'educacion', 'salud-bienestar', 'noticias-locales', 'servicios-publicos', 'actividades-eventos', 'opiniones-sugerencias', 'otros'];
const STATUSES = ['nuevo', 'aprobado', 'rechazado'];
const SOURCES = ['grabado', 'generado', 'texto'];
const REPLY_TYPES = ['voz', 'biblioteca', 'ia'];

const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.webp': 'image/webp', '.txt': 'text/plain; charset=utf-8', '.md': 'text/plain; charset=utf-8' };
const AUDIO_EXT = { 'audio/webm': 'webm', 'audio/ogg': 'ogg', 'audio/mp4': 'm4a', 'audio/mpeg': 'mp3', 'audio/wav': 'wav' };

/* ------------------------------------------------------------------ utilidades */
class HttpError extends Error {
  constructor(status, code, message){ super(message || code); this.status = status; this.code = code; }
}
function nowIso(){ return new Date().toISOString(); }
function newId(){ return crypto.randomBytes(9).toString('base64url'); }
function sha256(s){ return crypto.createHash('sha256').update(s).digest('hex'); }
function clean(s, max){
  return String(s == null ? '' : s).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '').trim().slice(0, max);
}

/* Detecta el tipo de audio por los primeros bytes (no se confía en el tipo que declara el navegador). */
function sniffAudio(buf){
  if(!buf || buf.length < 12) return null;
  if(buf.toString('latin1', 0, 4) === 'RIFF' && buf.toString('latin1', 8, 12) === 'WAVE') return 'audio/wav';
  if(buf.toString('latin1', 0, 3) === 'ID3' || (buf[0] === 0xFF && (buf[1] & 0xE0) === 0xE0)) return 'audio/mpeg';
  if(buf.toString('latin1', 0, 4) === 'OggS') return 'audio/ogg';
  if(buf[0] === 0x1A && buf[1] === 0x45 && buf[2] === 0xDF && buf[3] === 0xA3) return 'audio/webm';
  if(buf.toString('latin1', 4, 8) === 'ftyp') return 'audio/mp4';
  return null;
}

function hashPassword(password){
  var salt = crypto.randomBytes(16).toString('hex');
  var N = 16384;
  var h = crypto.scryptSync(password, salt, 64, { N: N }).toString('hex');
  return 'scrypt$' + N + '$' + salt + '$' + h;
}
function verifyPassword(password, stored){
  try{
    var p = String(stored).split('$');
    if(p[0] !== 'scrypt') return false;
    var h = crypto.scryptSync(password, p[2], 64, { N: Number(p[1]) });
    var want = Buffer.from(p[3], 'hex');
    return want.length === h.length && crypto.timingSafeEqual(h, want);
  }catch(e){ return false; }
}
const DUMMY_HASH = hashPassword('x-dummy-password');

function RateLimiter(){
  var hits = new Map();
  return function(key, max, windowMs){
    var t = Date.now(), arr = (hits.get(key) || []).filter(function(x){ return t - x < windowMs; });
    if(arr.length >= max){ hits.set(key, arr); return false; }
    arr.push(t); hits.set(key, arr);
    if(hits.size > 5000){ hits.forEach(function(v, k){ if(!v.length || t - v[v.length - 1] > windowMs) hits.delete(k); }); }
    return true;
  };
}

/* ------------------------------------------------------------------ almacenamiento en disco */
class Store {
  constructor(dir){
    this.dir = dir;
    this.audioDir = path.join(dir, 'audio');
    this.file = path.join(dir, 'messages.json');
    this.settingsFile = path.join(dir, 'settings.json');
    this.voicesFile = path.join(dir, 'voices.json');
    this.usersFile = path.join(dir, 'users.json');
    this.msgs = new Map();
    this.settings = {};
    this.voices = [];
    this.users = {};
    this.chain = Promise.resolve();
  }
  async init(){
    await fsp.mkdir(this.audioDir, { recursive: true });
    var self = this;
    async function readJson(f, fb){ try{ return JSON.parse(await fsp.readFile(f, 'utf8')); }catch(e){ return fb; } }
    (await readJson(this.file, [])).forEach(function(m){ self.msgs.set(m.id, m); });
    this.settings = await readJson(this.settingsFile, {});
    this.voices = await readJson(this.voicesFile, []);
    this.users = await readJson(this.usersFile, {});
  }
  _write(file, data){
    var self = this;
    this.chain = this.chain.then(async function(){
      var tmp = file + '.tmp';
      await fsp.writeFile(tmp, JSON.stringify(data, null, 1), { mode: 0o600 });
      await fsp.rename(tmp, file);
    }).catch(function(e){ console.error('No se pudo guardar', path.basename(file), e.message); });
    return this.chain;
  }
  saveMessages(){ return this._write(this.file, Array.from(this.msgs.values())); }
  saveSettings(){ return this._write(this.settingsFile, this.settings); }
  saveVoices(){ return this._write(this.voicesFile, this.voices); }
  audioPath(name){
    if(!/^[A-Za-z0-9_-]+\.[a-z0-9]{2,4}$/.test(name)) throw new HttpError(400, 'bad_file');
    return path.join(this.audioDir, name);
  }
  async saveAudio(id, buf, mime){
    var name = id + '.' + AUDIO_EXT[mime];
    await fsp.writeFile(this.audioPath(name), buf, { mode: 0o600 });
    return name;
  }
  async removeAudio(name){ if(name){ try{ await fsp.unlink(this.audioPath(name)); }catch(e){} } }
}

/* ------------------------------------------------------------------ servidor */
async function createApp(over){
  var cfg = readConfig(over);
  var store = new Store(cfg.dataDir);
  await store.init();
  var rate = RateLimiter();
  var sessions = new Map();

  function clientIp(req){
    if(cfg.trustProxy && req.headers['x-forwarded-for']){ return String(req.headers['x-forwarded-for']).split(',')[0].trim(); }
    return req.socket.remoteAddress || 'unknown';
  }
  function ttsVoice(){ return store.settings.aiVoiceId || cfg.elVoice; }
  function ttsReady(){ return Boolean(cfg.elKey && ttsVoice()); }

  /* ----- CORS y cabeceras ----- */
  function originAllowed(req){
    var o = req.headers.origin;
    if(!o) return true;
    var host = req.headers.host;
    if(host && (o === 'http://' + host || o === 'https://' + host)) return true;
    if(cfg.origins.indexOf(o.replace(/\/$/, '')) >= 0) return true;
    if(!cfg.production && /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(o)) return true;
    return false;
  }
  function baseHeaders(req, extra){
    var h = { 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Cross-Origin-Resource-Policy': 'cross-origin' };
    var o = req.headers.origin;
    if(o && originAllowed(req)){
      h['Access-Control-Allow-Origin'] = o;
      h['Vary'] = 'Origin';
      h['Access-Control-Allow-Headers'] = 'Authorization, Content-Type, X-Delete-Token';
      h['Access-Control-Allow-Methods'] = 'GET, POST, PATCH, DELETE, OPTIONS';
      h['Access-Control-Max-Age'] = '600';
    }
    return Object.assign(h, extra || {});
  }
  function sendJson(req, res, status, obj){
    var body = JSON.stringify(obj);
    res.writeHead(status, baseHeaders(req, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'Content-Length': Buffer.byteLength(body) }));
    res.end(body);
  }
  function sendBuffer(req, res, status, buf, type, extra){
    res.writeHead(status, baseHeaders(req, Object.assign({ 'Content-Type': type, 'Content-Length': buf.length, 'Cache-Control': 'no-store' }, extra || {})));
    res.end(buf);
  }

  /* ----- lectura del cuerpo ----- */
  function readBody(req, max){
    return new Promise(function(resolve, reject){
      var len = Number(req.headers['content-length'] || 0);
      if(len > max){ reject(new HttpError(413, 'too_large', 'El archivo es demasiado grande.')); req.resume(); return; }
      var chunks = [], size = 0, dead = false;
      req.on('data', function(c){
        if(dead) return;
        size += c.length;
        if(size > max){ dead = true; reject(new HttpError(413, 'too_large', 'El archivo es demasiado grande.')); req.resume(); return; }
        chunks.push(c);
      });
      req.on('end', function(){ if(!dead) resolve(Buffer.concat(chunks)); });
      req.on('error', function(e){ if(!dead){ dead = true; reject(e); } });
    });
  }
  async function readJson(req, max){
    var buf = await readBody(req, max || 64 * 1024);
    if(!buf.length) return {};
    try{ return JSON.parse(buf.toString('utf8')); }catch(e){ throw new HttpError(400, 'bad_json', 'El pedido no es JSON válido.'); }
  }
  async function readForm(req, max){
    var ct = req.headers['content-type'] || '';
    if(!/^multipart\/form-data/i.test(ct)) throw new HttpError(415, 'bad_content_type', 'Se esperaba un formulario multipart.');
    var buf = await readBody(req, max);
    try{ return await new Response(buf, { headers: { 'content-type': ct } }).formData(); }
    catch(e){ throw new HttpError(400, 'bad_form', 'No se pudo leer el formulario.'); }
  }
  async function fileFrom(form, field, maxBytes){
    var f = form.get(field);
    if(!f || typeof f === 'string') return null;
    if(f.size > maxBytes) throw new HttpError(413, 'too_large', 'El audio supera el tamaño máximo permitido.');
    var buf = Buffer.from(await f.arrayBuffer());
    var mime = sniffAudio(buf);
    if(!mime) throw new HttpError(415, 'bad_audio', 'El archivo no es un audio válido (se aceptan WebM, OGG, MP3, WAV y M4A).');
    return { buf: buf, mime: mime };
  }

  /* ----- sesiones de locutores ----- */
  function newSession(user){
    var token = crypto.randomBytes(32).toString('base64url');
    var exp = Date.now() + cfg.sessionHours * 3600 * 1000;
    sessions.set(sha256(token), { user: user, exp: exp });
    return { token: token, expiresAt: new Date(exp).toISOString() };
  }
  function auth(req){
    var m = /^Bearer\s+([A-Za-z0-9_-]{20,})$/.exec(req.headers.authorization || '');
    var s = m && sessions.get(sha256(m[1]));
    if(!s || s.exp < Date.now()){
      if(s && m) sessions.delete(sha256(m[1]));
      throw new HttpError(401, 'unauthorized', 'Iniciá sesión como locutor para ver esto.');
    }
    return s;
  }
  var sweep = setInterval(function(){ var t = Date.now(); sessions.forEach(function(v, k){ if(v.exp < t) sessions.delete(k); }); }, 600000);
  sweep.unref();

  /* ----- voz artificial ----- */
  async function elevenFetch(pathname, init){
    var r;
    try{ r = await fetch(cfg.elBase + pathname, Object.assign({ signal: AbortSignal.timeout(60000) }, init, { headers: Object.assign({ 'xi-api-key': cfg.elKey }, (init && init.headers) || {}) })); }
    catch(e){ throw new HttpError(502, 'tts_unreachable', 'No se pudo conectar con el servicio de voz.'); }
    if(!r.ok){
      var detail = '';
      try{ var j = await r.json(); detail = (j.detail && (j.detail.message || j.detail.status)) || ''; }catch(e){}
      var msg = r.status === 401 ? 'El servicio de voz rechazó la clave configurada en el servidor.'
        : r.status === 402 || r.status === 403 ? 'La cuenta de voz no tiene créditos o no permite esa voz.'
        : r.status === 429 ? 'El servicio de voz pide esperar un momento.'
        : r.status === 404 || r.status === 422 ? 'El servicio de voz no aceptó esa voz o ese texto.'
        : 'El servicio de voz falló.';
      throw new HttpError(502, 'tts_failed', msg + (detail && typeof detail === 'string' ? ' (' + detail.slice(0, 120) + ')' : ''));
    }
    return r;
  }
  async function synth(text){
    if(!ttsReady()) throw new HttpError(503, 'tts_not_configured', 'La voz artificial todavía no está configurada en el servidor. No se generó ningún audio.');
    var r = await elevenFetch('/v1/text-to-speech/' + encodeURIComponent(ttsVoice()) + '?output_format=mp3_44100_128', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'audio/mpeg' },
      body: JSON.stringify({ text: text, model_id: cfg.elModel, voice_settings: { stability: 0.45, similarity_boost: 0.8, style: 0.25, use_speaker_boost: true } })
    });
    var buf = Buffer.from(await r.arrayBuffer());
    if(!sniffAudio(buf)) throw new HttpError(502, 'tts_bad_audio', 'El servicio de voz devolvió un audio inválido.');
    return buf;
  }

  /* ----- vistas de datos ----- */
  function publicName(m){ return m.anonymous || !m.name ? 'Un vecino o vecina de El Colorado' : m.name; }
  function adminView(m){
    return {
      id: m.id, createdAt: m.createdAt, category: m.category, suggestedCategory: m.suggestedCategory, source: m.source,
      name: m.anonymous ? null : m.name, anonymous: m.anonymous, text: m.text, hasAudio: Boolean(m.audio), mime: m.mime, duration: m.duration,
      consentStore: m.consentStore, consentBroadcast: m.consentBroadcast, status: m.status, answered: m.answered,
      onAir: m.onAir, airAt: m.airAt, notes: m.notes, decidedBy: m.decidedBy, decidedAt: m.decidedAt,
      replies: (m.replies || []).map(function(r){ return { id: r.id, type: r.type, text: r.text, hasAudio: Boolean(r.audio), createdAt: r.createdAt, by: r.by }; })
    };
  }
  function airView(m){
    return {
      id: m.id, category: m.category, who: publicName(m), text: m.text || '',
      audioUrl: m.audio ? '/api/air/audio/' + m.id : null,
      replies: (m.replies || []).filter(function(r){ return r.audio; }).map(function(r){ return { id: r.id, type: r.type, text: r.text || '', audioUrl: '/api/air/reply/' + r.id }; })
    };
  }
  function getMsg(id){
    var m = store.msgs.get(id);
    if(!m) throw new HttpError(404, 'not_found', 'No se encontró ese mensaje.');
    return m;
  }
  function findReply(rid){
    var found = null;
    store.msgs.forEach(function(m){ (m.replies || []).forEach(function(r){ if(r.id === rid) found = { m: m, r: r }; }); });
    return found;
  }
  function airable(m){ return m.onAir && m.status === 'aprobado' && m.consentBroadcast; }

  /* envía un archivo de audio con soporte de Range (para poder adelantar/atrasar) */
  async function streamAudio(req, res, name, mime){
    var file = store.audioPath(name), st;
    try{ st = await fsp.stat(file); }catch(e){ throw new HttpError(404, 'not_found', 'El audio ya no está disponible.'); }
    var range = /^bytes=(\d*)-(\d*)$/.exec(req.headers.range || ''), start = 0, end = st.size - 1, status = 200;
    if(range && (range[1] || range[2])){
      if(range[1] === ''){ start = Math.max(0, st.size - Number(range[2])); } else { start = Number(range[1]); if(range[2]) end = Math.min(end, Number(range[2])); }
      if(start > end || start >= st.size){ res.writeHead(416, baseHeaders(req, { 'Content-Range': 'bytes */' + st.size })); res.end(); return; }
      status = 206;
    }
    var h = { 'Content-Type': mime || 'application/octet-stream', 'Content-Length': end - start + 1, 'Accept-Ranges': 'bytes', 'Cache-Control': 'private, no-store' };
    if(status === 206) h['Content-Range'] = 'bytes ' + start + '-' + end + '/' + st.size;
    res.writeHead(status, baseHeaders(req, h));
    fs.createReadStream(file, { start: start, end: end }).pipe(res);
  }

  /* ================================================================== rutas de la API */
  async function api(req, res, url){
    var method = req.method, p = url.pathname, ip = clientIp(req), m;

    if(method === 'GET' && p === '/api/health'){
      return sendJson(req, res, 200, { ok: true, service: 'radio-comunitaria-ia', tts: ttsReady(), publicTts: ttsReady() && cfg.publicTts, maxAudioMb: Math.round(cfg.maxAudioBytes / 1048576), categories: CATEGORIES });
    }

    /* --- públicas: recibir mensaje --- */
    if(method === 'POST' && p === '/api/messages'){
      if(!rate('msg:' + ip, cfg.msgPerHour, 3600000)) throw new HttpError(429, 'rate_limited', 'Enviaste muchos mensajes seguidos. Probá de nuevo en un rato.');
      var form = await readForm(req, cfg.maxAudioBytes + 64 * 1024);
      var source = clean(form.get('source'), 20) || 'grabado';
      if(SOURCES.indexOf(source) < 0) throw new HttpError(400, 'bad_source', 'Origen del mensaje inválido.');
      var category = clean(form.get('category'), 40) || 'otros';
      if(CATEGORIES.indexOf(category) < 0) throw new HttpError(400, 'bad_category', 'Categoría inválida.');
      var text = clean(form.get('text'), 1000);
      var anonymous = form.get('anonymous') === 'true';
      var name = anonymous ? '' : clean(form.get('name'), 60);
      if(form.get('consentStore') !== 'true') throw new HttpError(400, 'consent_required', 'Para enviar tu mensaje tenés que aceptar que la radio lo guarde y lo revise.');
      var audio = await fileFrom(form, 'audio', cfg.maxAudioBytes);
      if(!audio && !text) throw new HttpError(400, 'empty', 'Enviá un audio o escribí tu mensaje.');
      if(source !== 'texto' && !audio) throw new HttpError(400, 'audio_required', 'Falta el audio.');
      var duration = Math.max(0, Math.min(600, Number(form.get('duration')) || 0));
      var id = newId(), deleteToken = crypto.randomBytes(18).toString('base64url');
      var msg = {
        id: id, createdAt: nowIso(), category: category, suggestedCategory: category, source: source, name: name, anonymous: anonymous || !name,
        text: text, audio: null, mime: audio ? audio.mime : null, duration: duration,
        consentStore: true, consentBroadcast: form.get('consentBroadcast') === 'true',
        status: 'nuevo', answered: false, onAir: false, airAt: null, notes: '', decidedBy: null, decidedAt: null,
        deleteTokenHash: sha256(deleteToken), replies: []
      };
      if(audio) msg.audio = await store.saveAudio(id, audio.buf, audio.mime);
      store.msgs.set(id, msg);
      await store.saveMessages();
      return sendJson(req, res, 201, { ok: true, id: id, deleteToken: deleteToken });
    }

    /* --- públicas: borrar mi propio mensaje --- */
    if(method === 'DELETE' && (m = /^\/api\/messages\/([\w-]+)$/.exec(p))){
      var mine = getMsg(m[1]), tok = String(req.headers['x-delete-token'] || '');
      if(!tok || sha256(tok) !== mine.deleteTokenHash) throw new HttpError(403, 'forbidden', 'No se pudo comprobar que el mensaje sea tuyo.');
      await removeMessage(mine);
      return sendJson(req, res, 200, { ok: true });
    }

    /* --- públicas: voz artificial para que el vecino "genere audios" --- */
    if(method === 'POST' && p === '/api/tts'){
      if(!cfg.publicTts) throw new HttpError(403, 'tts_disabled', 'La generación pública de audios está desactivada.');
      if(!ttsReady()) throw new HttpError(503, 'tts_not_configured', 'La voz artificial todavía no está configurada en el servidor. No se generó ningún audio.');
      if(!rate('tts:' + ip, cfg.ttsPublicPerHour, 3600000)) throw new HttpError(429, 'rate_limited', 'Llegaste al límite de audios por hora. Probá más tarde.');
      var body = await readJson(req, 8 * 1024), t = clean(body.text, 400);
      if(t.length < 3) throw new HttpError(400, 'empty', 'Escribí tu pregunta o mensaje.');
      return sendBuffer(req, res, 200, await synth(t), 'audio/mpeg');
    }

    /* --- públicas: lo que está al aire --- */
    if(method === 'GET' && p === '/api/air'){
      var list = Array.from(store.msgs.values()).filter(airable).sort(function(a, b){ return String(a.airAt).localeCompare(String(b.airAt)); }).map(airView);
      return sendJson(req, res, 200, { items: list });
    }
    if(method === 'GET' && (m = /^\/api\/air\/audio\/([\w-]+)$/.exec(p))){
      var am = getMsg(m[1]);
      if(!airable(am) || !am.audio) throw new HttpError(404, 'not_found', 'Ese audio no está al aire.');
      return streamAudio(req, res, am.audio, am.mime);
    }
    if(method === 'GET' && (m = /^\/api\/air\/reply\/([\w-]+)$/.exec(p))){
      var ar = findReply(m[1]);
      if(!ar || !airable(ar.m) || !ar.r.audio) throw new HttpError(404, 'not_found', 'Esa respuesta no está al aire.');
      return streamAudio(req, res, ar.r.audio, ar.r.mime);
    }

    /* --- sesión de locutores --- */
    if(method === 'POST' && p === '/api/auth/login'){
      if(!rate('login:' + ip, cfg.loginAttempts, 600000)) throw new HttpError(429, 'rate_limited', 'Demasiados intentos. Esperá unos minutos.');
      var b = await readJson(req), user = clean(b.user, 40).toLowerCase(), pass = String(b.password || '').slice(0, 200);
      var rec = store.users[user];
      var ok = verifyPassword(pass, rec ? rec.hash : DUMMY_HASH) && Boolean(rec);
      if(!ok) throw new HttpError(401, 'bad_credentials', 'Usuario o contraseña incorrectos.');
      var s = newSession(user);
      return sendJson(req, res, 200, { ok: true, user: user, display: rec.display || user, token: s.token, expiresAt: s.expiresAt });
    }

    /* =========== desde acá, todo requiere sesión =========== */
    if(!p.startsWith('/api/')) throw new HttpError(404, 'not_found');
    var sess = auth(req);

    if(method === 'POST' && p === '/api/auth/logout'){
      var mm = /^Bearer\s+(\S+)$/.exec(req.headers.authorization || ''); if(mm) sessions.delete(sha256(mm[1]));
      return sendJson(req, res, 200, { ok: true });
    }
    if(method === 'GET' && p === '/api/auth/me'){
      return sendJson(req, res, 200, { user: sess.user, display: (store.users[sess.user] || {}).display || sess.user, expiresAt: new Date(sess.exp).toISOString() });
    }

    if(method === 'GET' && p === '/api/inbox'){
      var q = url.searchParams, status = q.get('status'), cat = q.get('category'), term = (q.get('q') || '').toLowerCase();
      var items = Array.from(store.msgs.values()).filter(function(x){
        return (!status || x.status === status) && (!cat || x.category === cat) &&
          (q.get('answered') == null || String(x.answered) === q.get('answered')) &&
          (!term || (x.text || '').toLowerCase().indexOf(term) >= 0 || (x.name || '').toLowerCase().indexOf(term) >= 0);
      }).sort(function(a, b){ return String(b.createdAt).localeCompare(String(a.createdAt)); }).map(adminView);
      return sendJson(req, res, 200, { items: items, categories: CATEGORIES });
    }
    if(method === 'GET' && (m = /^\/api\/inbox\/([\w-]+)$/.exec(p))){ return sendJson(req, res, 200, adminView(getMsg(m[1]))); }
    if(method === 'GET' && (m = /^\/api\/inbox\/([\w-]+)\/audio$/.exec(p))){
      var gm = getMsg(m[1]); if(!gm.audio) throw new HttpError(404, 'not_found', 'Este mensaje no tiene audio.');
      return streamAudio(req, res, gm.audio, gm.mime);
    }
    if(method === 'GET' && (m = /^\/api\/replies\/([\w-]+)\/audio$/.exec(p))){
      var fr = findReply(m[1]); if(!fr || !fr.r.audio) throw new HttpError(404, 'not_found', 'Esa respuesta no tiene audio.');
      return streamAudio(req, res, fr.r.audio, fr.r.mime);
    }

    if(method === 'PATCH' && (m = /^\/api\/inbox\/([\w-]+)$/.exec(p))){
      var pm = getMsg(m[1]), pb = await readJson(req);
      if(pb.category != null){
        if(CATEGORIES.indexOf(pb.category) < 0) throw new HttpError(400, 'bad_category', 'Categoría inválida.');
        pm.category = pb.category;
      }
      if(pb.status != null){
        if(STATUSES.indexOf(pb.status) < 0) throw new HttpError(400, 'bad_status', 'Estado inválido.');
        pm.status = pb.status; pm.decidedBy = sess.user; pm.decidedAt = nowIso();
        if(pb.status !== 'aprobado'){ pm.onAir = false; pm.airAt = null; }
      }
      if(pb.answered != null){ pm.answered = Boolean(pb.answered); }
      if(pb.notes != null){ pm.notes = clean(pb.notes, 500); }
      await store.saveMessages();
      return sendJson(req, res, 200, adminView(pm));
    }

    if(method === 'POST' && (m = /^\/api\/inbox\/([\w-]+)\/air$/.exec(p))){
      var om = getMsg(m[1]), ob = await readJson(req);
      if(ob.on){
        if(ob.confirm !== true) throw new HttpError(400, 'confirm_required', 'Confirmá explícitamente que querés enviar este mensaje al aire.');
        if(om.status !== 'aprobado') throw new HttpError(409, 'not_approved', 'Solo se pueden enviar al aire los mensajes aprobados.');
        if(!om.consentBroadcast) throw new HttpError(409, 'no_broadcast_consent', 'La persona no autorizó que su mensaje se difunda por radio.');
        om.onAir = true; om.airAt = nowIso();
      } else { om.onAir = false; om.airAt = null; }
      await store.saveMessages();
      return sendJson(req, res, 200, adminView(om));
    }

    if(method === 'DELETE' && (m = /^\/api\/inbox\/([\w-]+)$/.exec(p))){
      await removeMessage(getMsg(m[1]));
      return sendJson(req, res, 200, { ok: true });
    }

    if(method === 'POST' && (m = /^\/api\/inbox\/([\w-]+)\/replies$/.exec(p))){
      var rm = getMsg(m[1]);
      var rf = await readForm(req, cfg.maxAudioBytes + 64 * 1024);
      var rtype = clean(rf.get('type'), 20), rtext = clean(rf.get('text'), 600), raudio, rmime;
      if(REPLY_TYPES.indexOf(rtype) < 0) throw new HttpError(400, 'bad_type', 'Tipo de respuesta inválido.');
      if(rtype === 'ia'){
        if(rtext.length < 3) throw new HttpError(400, 'empty', 'Escribí el texto de la respuesta.');
        raudio = await synth(rtext); rmime = 'audio/mpeg';
      } else {
        var up = await fileFrom(rf, 'audio', cfg.maxAudioBytes);
        if(!up) throw new HttpError(400, 'audio_required', 'Falta el audio de la respuesta.');
        raudio = up.buf; rmime = up.mime;
      }
      var rid = newId(), rname = await store.saveAudio('r-' + rid, raudio, rmime);
      var reply = { id: rid, messageId: rm.id, type: rtype, text: rtext, audio: rname, mime: rmime, createdAt: nowIso(), by: sess.user };
      rm.replies = rm.replies || []; rm.replies.push(reply); rm.answered = true;
      await store.saveMessages();
      return sendJson(req, res, 201, adminView(rm));
    }
    if(method === 'DELETE' && (m = /^\/api\/inbox\/([\w-]+)\/replies\/([\w-]+)$/.exec(p))){
      var dm = getMsg(m[1]), di = (dm.replies || []).findIndex(function(r){ return r.id === m[2]; });
      if(di < 0) throw new HttpError(404, 'not_found', 'No se encontró esa respuesta.');
      await store.removeAudio(dm.replies[di].audio); dm.replies.splice(di, 1);
      await store.saveMessages();
      return sendJson(req, res, 200, adminView(dm));
    }

    /* texto -> voz para locutores (sin el límite de las personas del público) */
    if(method === 'POST' && p === '/api/inbox/tts'){
      var tb = await readJson(req, 8 * 1024), tt = clean(tb.text, 600);
      if(tt.length < 3) throw new HttpError(400, 'empty', 'Escribí el texto.');
      return sendBuffer(req, res, 200, await synth(tt), 'audio/mpeg');
    }

    /* voz artificial: estado, ajustes y clonación autorizada */
    if(method === 'GET' && p === '/api/settings'){
      return sendJson(req, res, 200, { ttsConfigured: ttsReady(), apiKeyConfigured: Boolean(cfg.elKey), aiVoiceId: ttsVoice() || null, aiVoiceName: store.settings.aiVoiceName || null, model: cfg.elModel, clonedVoices: store.voices.map(function(v){ return { voiceId: v.voiceId, name: v.name, createdAt: v.createdAt, createdBy: v.createdBy }; }) });
    }
    if(method === 'POST' && p === '/api/settings'){
      var sb = await readJson(req), vid = clean(sb.aiVoiceId, 60);
      if(!/^[A-Za-z0-9]{10,40}$/.test(vid)) throw new HttpError(400, 'bad_voice', 'El identificador de voz no es válido.');
      store.settings.aiVoiceId = vid; store.settings.aiVoiceName = clean(sb.aiVoiceName, 80) || null;
      await store.saveSettings();
      return sendJson(req, res, 200, { ok: true, aiVoiceId: vid });
    }
    if(method === 'POST' && p === '/api/voices/clone'){
      if(!cfg.elKey) throw new HttpError(503, 'tts_not_configured', 'Falta configurar la clave del servicio de voz en el servidor. No se creó ninguna voz.');
      var cf = await readForm(req, 25 * 1024 * 1024);
      var vname = clean(cf.get('name'), 60), owner = clean(cf.get('ownerName'), 80);
      if(cf.get('consent') !== 'true' || owner.length < 4) throw new HttpError(400, 'consent_required', 'Para clonar una voz tenés que declarar que es tuya o que tenés autorización escrita de su dueño, y escribir su nombre completo.');
      if(vname.length < 2) throw new HttpError(400, 'bad_name', 'Poné un nombre para la voz.');
      var files = cf.getAll('samples').filter(function(f){ return f && typeof f !== 'string'; });
      if(!files.length || files.length > 5) throw new HttpError(400, 'samples_required', 'Subí entre 1 y 5 muestras de audio.');
      var up2 = new FormData();
      up2.append('name', vname);
      up2.append('description', 'Voz clonada con autorización de ' + owner + ' para Radio comunitaria IA El Colorado.');
      up2.append('remove_background_noise', 'false');
      for(var i = 0; i < files.length; i++){
        var buf = Buffer.from(await files[i].arrayBuffer()), mime = sniffAudio(buf);
        if(!mime) throw new HttpError(415, 'bad_audio', 'Una de las muestras no es un audio válido.');
        up2.append('files', new Blob([buf], { type: mime }), 'muestra-' + (i + 1) + '.' + AUDIO_EXT[mime]);
      }
      var cr = await elevenFetch('/v1/voices/add', { method: 'POST', body: up2 });
      var cj = await cr.json();
      if(!cj.voice_id) throw new HttpError(502, 'clone_failed', 'El servicio de voz no devolvió la voz creada.');
      store.voices.push({ voiceId: cj.voice_id, name: vname, ownerName: owner, consentAt: nowIso(), createdAt: nowIso(), createdBy: sess.user });
      await store.saveVoices();
      return sendJson(req, res, 201, { ok: true, voiceId: cj.voice_id, name: vname, requiresVerification: Boolean(cj.requires_verification) });
    }

    throw new HttpError(404, 'not_found', 'No existe esa dirección.');
  }

  async function removeMessage(m){
    await store.removeAudio(m.audio);
    for(var i = 0; i < (m.replies || []).length; i++){ await store.removeAudio(m.replies[i].audio); }
    store.msgs.delete(m.id);
    await store.saveMessages();
  }

  /* ----- archivos estáticos (solo para probar todo junto en tu computadora o en un servidor propio) ----- */
  async function serveStatic(req, res, url){
    var rel = decodeURIComponent(url.pathname);
    if(rel === '/') rel = '/index.html';
    var abs = path.resolve(cfg.staticRoot, '.' + rel);
    var inside = abs.startsWith(cfg.staticRoot + path.sep);
    var parts = path.relative(cfg.staticRoot, abs).split(path.sep);
    var blocked = !inside || parts.some(function(s){ return s.startsWith('.') || s === 'backend' || s === 'node_modules' || s === 'data'; });
    var type = MIME[path.extname(abs).toLowerCase()];
    if(blocked || !type) throw new HttpError(404, 'not_found', 'No encontrado.');
    var buf;
    try{ buf = await fsp.readFile(abs); }catch(e){ throw new HttpError(404, 'not_found', 'No encontrado.'); }
    var extra = { 'Cache-Control': 'no-cache' };
    if(type.startsWith('text/html')){
      extra['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data: blob:; media-src 'self' blob: data: https://storage.googleapis.com; connect-src 'self' https://api.elevenlabs.io; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
    }
    sendBuffer(req, res, 200, buf, type, extra);
  }

  var server = http.createServer(function(req, res){
    var url;
    (async function(){
      url = new URL(req.url, 'http://localhost');
      if(req.headers.origin && !originAllowed(req) && url.pathname.startsWith('/api/')){ throw new HttpError(403, 'origin_not_allowed', 'Origen no permitido.'); }
      if(req.method === 'OPTIONS'){ res.writeHead(204, baseHeaders(req)); res.end(); return; }
      if(url.pathname.startsWith('/api/')) return api(req, res, url);
      if(cfg.serveStatic && (req.method === 'GET' || req.method === 'HEAD')) return serveStatic(req, res, url);
      throw new HttpError(404, 'not_found', 'No encontrado.');
    })().catch(function(err){
      var e = err instanceof HttpError ? err : new HttpError(500, 'server_error', 'Ocurrió un error en el servidor.');
      if(!(err instanceof HttpError)) console.error('Error', req.method, req.url, err && err.message);
      if(res.headersSent){ try{ res.end(); }catch(x){} return; }
      sendJson(req, res, e.status, { error: e.code, message: e.message });
    });
  });
  server.requestTimeout = 120000;

  return { server: server, cfg: cfg, store: store, sessions: sessions };
}

module.exports = { createApp, hashPassword, verifyPassword, sniffAudio, CATEGORIES, loadEnvFile };

if(require.main === module){
  loadEnvFile(path.join(__dirname, '.env'));
  loadEnvFile(path.join(__dirname, '..', '.env'));
  createApp().then(function(app){
    app.server.listen(app.cfg.port, app.cfg.host, function(){
      console.log('Radio comunitaria IA escuchando en http://localhost:' + app.cfg.port);
      console.log('Voz artificial:', app.cfg.elKey ? 'clave configurada' : 'SIN clave (los audios IA no se generarán)');
      console.log('Locutores registrados:', Object.keys(app.store.users).length || 'ninguno (ejecutá: node create-user.js)');
    });
  }).catch(function(e){ console.error('No se pudo iniciar:', e); process.exit(1); });
}
