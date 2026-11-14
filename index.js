const enc = new TextEncoder();
const MAX_BODY = 4096;
const MAX_TOKEN = 2048;
const TTL = 120;
const SHAPES = ["circle", "square", "triangle", "diamond", "hex", "plus"];
const PLURAL = { circle: "circles", square: "squares", triangle: "triangles", diamond: "diamonds", hex: "hexagons", plus: "plus signs" };
const COLORS = ["#0369a1", "#0f766e", "#7c3aed", "#c2410c", "#be123c"];
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Max-Age": "86400",
};

const now = () => Math.floor(Date.now() / 1000);
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const sha256Hex = async (s) => hex(await crypto.subtle.digest("SHA-256", enc.encode(s)));
const rhex = (n) => hex(crypto.getRandomValues(new Uint8Array(n)));
const rand = (n) => crypto.getRandomValues(new Uint32Array(1))[0] % n;
const b64u = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

function b64uToBytes(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  s += "=".repeat((4 - (s.length % 4)) % 4);
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

function json(body, status = 200, extra = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...extra },
  });
}

const fail = (codes, status = 200, extra = {}) => json({ success: false, "error-codes": codes }, status, extra);

function safeEqualHex(a, b) {
  const x = enc.encode(a), y = enc.encode(b);
  return x.length === y.length && crypto.subtle.timingSafeEqual(x, y);
}

async function readInput(req) {
  const len = Number(req.headers.get("content-length") || 0);
  if (len > MAX_BODY) return null;
  const type = req.headers.get("content-type") || "";
  try {
    if (type.includes("application/json")) return await req.json();
    if (type.includes("application/x-www-form-urlencoded")) {
      return Object.fromEntries(new URLSearchParams(await req.text()));
    }
  } catch {}
  return null;
}

function originHost(req) {
  try { return new URL(req.headers.get("Origin")).hostname.toLowerCase(); } catch { return ""; }
}

const domainOk = (host, domain) => !!domain && !!host && (host === domain || host.endsWith("." + domain));

function sameOrigin(req) {
  const o = req.headers.get("Origin");
  return !o || o === new URL(req.url).origin;
}

const ipHash = (req, env) => sha256Hex((req.headers.get("CF-Connecting-IP") || "") + (env.IP_SALT || ""));

async function signToken(payload, env) {
  const p = b64u(enc.encode(JSON.stringify(payload)));
  const key = await crypto.subtle.importKey("raw", enc.encode(env.TOKEN_SIGNING_KEY), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode("v1." + p));
  return "v1." + p + "." + b64u(sig);
}

async function verifySignature(token, env) {
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== "v1") return null;
  const [v, p, s] = parts;
  let sig;
  try { sig = b64uToBytes(s); } catch { return null; }
  for (const secret of [env.TOKEN_SIGNING_KEY, env.TOKEN_SIGNING_KEY_PREV]) {
    if (!secret) continue;
    const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    if (await crypto.subtle.verify("HMAC", key, sig, enc.encode(v + "." + p))) {
      try { return JSON.parse(new TextDecoder().decode(b64uToBytes(p))); } catch { return null; }
    }
  }
  return null;
}

async function authSite(env, sitekey, secret) {
  if (!sitekey || !secret) return null;
  const site = await env.DB.prepare("SELECT sitekey, secret_hash, active, domain, created_at FROM sites WHERE sitekey = ?").bind(String(sitekey)).first();
  const given = await sha256Hex(String(secret));
  if (!site || site.active !== 1 || !safeEqualHex(given, site.secret_hash)) return null;
  return site;
}

async function handleSignup(req, env) {
  if (!sameOrigin(req)) return json({ error: "forbidden" }, 403);
  const i = await readInput(req);
  if (!i) return json({ error: "bad-request" }, 400);
  const email = String(i.email || "").trim().toLowerCase();
  const domain = String(i.domain || "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/[\/:?#].*$/, "");
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) return json({ error: "invalid-email" }, 400);
  if (!/^(localhost|([a-z0-9-]+\.)+[a-z]{2,})$/.test(domain)) return json({ error: "invalid-domain" }, 400);

  const ih = await ipHash(req, env);
  const recent = await env.DB.prepare("SELECT COUNT(*) AS n FROM sites WHERE ip_hash = ? AND created_at > ?").bind(ih, now() - 3600).first();
  if (recent && recent.n >= 5) return json({ error: "rate-limited" }, 429);

  const sitekey = "hc_site_" + rhex(8);
  const secret = "hc_sec_" + rhex(24);
  await env.DB.prepare("INSERT INTO sites (sitekey, secret_hash, active, created_at, email, domain, ip_hash) VALUES (?, ?, 1, ?, ?, ?, ?)")
    .bind(sitekey, await sha256Hex(secret), now(), email, domain, ih).run();
  return json({ sitekey, secret, domain });
}

async function handleSite(req, env) {
  if (!sameOrigin(req)) return json({ error: "forbidden" }, 403);
  const i = await readInput(req);
  const site = i && await authSite(env, i.sitekey, i.secret);
  if (!site) return json({ error: "invalid-keys" }, 401);
  return json({ sitekey: site.sitekey, domain: site.domain, active: site.active === 1, created_at: site.created_at });
}

async function handleRotate(req, env) {
  if (!sameOrigin(req)) return json({ error: "forbidden" }, 403);
  const i = await readInput(req);
  const site = i && await authSite(env, i.sitekey, i.secret);
  if (!site) return json({ error: "invalid-keys" }, 401);
  const secret = "hc_sec_" + rhex(24);
  await env.DB.prepare("UPDATE sites SET secret_hash = ? WHERE sitekey = ?").bind(await sha256Hex(secret), site.sitekey).run();
  return json({ sitekey: site.sitekey, secret, domain: site.domain });
}

async function handleChallenge(req, env) {
  const i = await readInput(req);
  if (!i || !i.sitekey) return json({ error: "missing-sitekey" }, 400, CORS);
  const site = await env.DB.prepare("SELECT domain, active FROM sites WHERE sitekey = ?").bind(String(i.sitekey)).first();
  if (!site || site.active !== 1) return json({ error: "invalid-sitekey" }, 400, CORS);
  if (!domainOk(originHost(req), site.domain)) return json({ error: "domain-not-allowed" }, 403, CORS);

  const target = SHAPES[rand(SHAPES.length)];
  const n = 2 + rand(3);
  const tiles = [];
  for (let k = 0; k < 9; k++) {
    let s = target;
    if (k >= n) { do { s = SHAPES[rand(SHAPES.length)]; } while (s === target); }
    tiles.push({ s, c: COLORS[rand(COLORS.length)] });
  }
  for (let k = tiles.length - 1; k > 0; k--) {
    const j = rand(k + 1);
    [tiles[k], tiles[j]] = [tiles[j], tiles[k]];
  }
  const answer = tiles.map((t, k) => (t.s === target ? k : -1)).filter((k) => k >= 0);
  const id = rhex(16);
  await env.DB.prepare("INSERT INTO challenges (id, sitekey, answer, host, exp, used) VALUES (?, ?, ?, ?, ?, 0)")
    .bind(id, String(i.sitekey), JSON.stringify(answer), originHost(req), now() + TTL).run();
  return json({ id, prompt: "Select all " + PLURAL[target], tiles }, 200, CORS);
}

async function handleSolve(req, env) {
  const i = await readInput(req);
  if (!i || !i.id) return fail(["bad-request"], 400, CORS);
  const row = await env.DB.prepare("SELECT sitekey, answer, host, exp FROM challenges WHERE id = ?").bind(String(i.id)).first();
  if (!row || row.exp <= now() || originHost(req) !== row.host) return fail(["expired-or-invalid"], 200, CORS);
  const used = await env.DB.prepare("UPDATE challenges SET used = 1 WHERE id = ? AND used = 0").bind(row.id || String(i.id)).run();
  if (!used.meta || used.meta.changes === 0) return fail(["expired-or-invalid"], 200, CORS);

  const given = Array.isArray(i.answer) ? [...new Set(i.answer.map(Number))].sort((a, b) => a - b) : [];
  if (JSON.stringify(given) !== row.answer) return fail(["wrong-answer"], 200, CORS);

  const t = now();
  const token = await signToken({ jti: rhex(16), sk: row.sitekey, iat: t, exp: t + TTL, host: row.host, iph: await ipHash(req, env) }, env);
  return json({ success: true, token, expires_in: TTL }, 200, CORS);
}

async function handleVerify(req, env) {
  const input = await readInput(req);
  if (!input) return fail(["bad-request"], 400);
  const { secret, response: token, remoteip, expected_hostname } = input;
  if (!secret) return fail(["missing-input-secret"]);
  if (!token) return fail(["missing-input-response"]);
  if (typeof token !== "string" || token.length > MAX_TOKEN) return fail(["invalid-input-response"]);

  const payload = await verifySignature(token, env);
  if (!payload || !payload.jti || !payload.sk) return fail(["invalid-input-response"]);
  const t = now();
  if (payload.exp <= t || payload.iat > t + 30) return fail(["timeout-or-duplicate"]);

  const site = await authSite(env, payload.sk, secret);
  if (!site) return fail(["invalid-input-secret"]);

  if (expected_hostname && payload.host && String(expected_hostname).toLowerCase() !== payload.host) return fail(["hostname-mismatch"]);
  if (remoteip && payload.iph) {
    const h = await sha256Hex(String(remoteip) + (env.IP_SALT || ""));
    if (!safeEqualHex(h, payload.iph)) return fail(["remoteip-mismatch"]);
  }

  const res = await env.DB.prepare("INSERT OR IGNORE INTO used_tokens (jti, exp) VALUES (?, ?)").bind(payload.jti, payload.exp).run();
  if (!res.meta || res.meta.changes === 0) return fail(["timeout-or-duplicate"]);

  return json({
    success: true,
    challenge_ts: new Date(payload.iat * 1000).toISOString(),
    hostname: payload.host || null,
    score: typeof payload.score === "number" ? payload.score : null,
    "error-codes": [],
  });
}


const MAX_CHAT_BODY = 6000000;
const GEMINI = "https://generativelanguage.googleapis.com/v1beta/models/";
const FILE_MIMES = ["image/jpeg", "image/png", "image/webp", "application/pdf", "text/plain"];
const SYSTEM = "You are the hClutcha Assistant, the support and developer guide for hClutcha, a privacy-first CAPTCHA and bot-protection platform. " +
  "Voice: reliable, clear, warm but brief. Lead with the answer. Reply in the language the user writes in (Bengali or English); keep technical terms such as site key, secret key and siteverify in English. " +
  "Keep simple answers to 1-3 sentences and put all code in fenced blocks. If you are not sure, say so instead of guessing, and never invent features, prices or certifications. " +
  "Never ask for a secret key; if a user pastes one, tell them to rotate it in the Console. Do not help bypass hClutcha or attack other sites. " +
  "You can also describe and analyse images and documents the user attaches.";

function chatCors(origin) {
  return { "Access-Control-Allow-Origin": origin, "Access-Control-Allow-Methods": "POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type", "Access-Control-Max-Age": "86400", "Vary": "Origin" };
}

function allowedOrigin(req, env) {
  const o = req.headers.get("Origin") || "";
  const list = String(env.ALLOWED_ORIGINS || "").split(",").map((x) => x.trim().replace(/\/$/, "")).filter(Boolean);
  return o && list.includes(o) ? o : "";
}

async function overLimit(env, req, kind, max) {
  const k = kind + ":" + (await ipHash(req, env)) + ":" + Math.floor(now() / 60);
  await env.DB.prepare("INSERT INTO rl (k, n, exp) VALUES (?, 1, ?) ON CONFLICT(k) DO UPDATE SET n = n + 1").bind(k, now() + 120).run();
  const row = await env.DB.prepare("SELECT n FROM rl WHERE k = ?").bind(k).first();
  return !!row && row.n > max;
}

function buildContents(messages, files) {
  const list = (Array.isArray(messages) ? messages : []).slice(-20)
    .map((m) => ({ role: m && m.role === "assistant" ? "model" : "user", text: String((m && m.content) || "").slice(0, 4000) }))
    .filter((m) => m.text);
  const contents = list.map((m) => ({ role: m.role, parts: [{ text: m.text }] }));
  while (contents.length && contents[0].role === "model") contents.shift();
  const last = contents[contents.length - 1];
  if (!last || last.role !== "user") return null;
  for (const f of (Array.isArray(files) ? files : []).slice(0, 3)) {
    if (!f || !FILE_MIMES.includes(f.mime) || typeof f.data !== "string" || f.data.length > 5500000 || !/^[A-Za-z0-9+/=]+$/.test(f.data)) return null;
    last.parts.push({ inline_data: { mime_type: f.mime, data: f.data } });
  }
  return contents;
}

async function handleChat(req, env, ctx) {
  const origin = allowedOrigin(req, env);
  if (!origin) return json({ error: "origin-not-allowed" }, 403);
  const cors = chatCors(origin);
  if (!env.GEMINI_API_KEY || !env.DB) return json({ error: "server-not-configured" }, 500, cors);
  const raw = await req.text();
  if (raw.length > MAX_CHAT_BODY) return json({ error: "too-large" }, 413, cors);
  let body;
  try { body = JSON.parse(raw); } catch { return json({ error: "bad-request" }, 400, cors); }
  const image = body.mode === "image";
  if (await overLimit(env, req, image ? "img" : "txt", image ? 5 : 20)) return json({ error: "rate-limited" }, 429, cors);
  const contents = buildContents(body.messages, body.files);
  if (!contents) return json({ error: "bad-request" }, 400, cors);
  const headers = { "Content-Type": "application/json", "x-goog-api-key": env.GEMINI_API_KEY };

  if (image) {
    const model = env.GEMINI_IMAGE_MODEL || "gemini-3.1-flash-image";
    const up = await fetch(GEMINI + model + ":generateContent", {
      method: "POST", headers,
      body: JSON.stringify({ contents: [contents[contents.length - 1]], generationConfig: { responseModalities: ["TEXT", "IMAGE"] } }),
    });
    if (!up.ok) { console.error("gemini_image", up.status); return json({ error: "upstream-error", status: up.status }, 502, cors); }
    const j = await up.json();
    const parts = (j.candidates && j.candidates[0] && j.candidates[0].content && j.candidates[0].content.parts) || [];
    let text = "";
    const images = [];
    for (const p of parts) {
      const d = p.inlineData || p.inline_data;
      if (p.text) text += p.text;
      else if (d && d.data) images.push({ mime: d.mimeType || d.mime_type || "image/png", data: d.data });
    }
    if (!images.length) return json({ error: "no-image", text }, 422, cors);
    return json({ text, images }, 200, cors);
  }

  const model = env.GEMINI_MODEL || "gemini-flash-latest";
  const system = SYSTEM + (body.think ? " Think carefully and verify your reasoning step by step before answering." : "");
  const up = await fetch(GEMINI + model + ":streamGenerateContent?alt=sse", {
    method: "POST", headers,
    body: JSON.stringify({ systemInstruction: { parts: [{ text: system }] }, contents, generationConfig: { maxOutputTokens: body.think ? 3000 : 1500 } }),
  });
  if (!up.ok || !up.body) { console.error("gemini_text", up.status); return json({ error: "upstream-error", status: up.status }, 502, cors); }

  const { readable, writable } = new TransformStream();
  const pump = (async () => {
    const w = writable.getWriter();
    const rd = up.body.getReader();
    const dec = new TextDecoder();
    let buf = "", any = false;
    const emit = (t) => w.write(enc.encode("data: " + JSON.stringify({ delta: { text: t } }) + "\n\n"));
    try {
      for (;;) {
        const { done, value } = await rd.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        const lines = buf.split("\n");
        buf = lines.pop();
        for (const l of lines) {
          if (l.indexOf("data:") !== 0) continue;
          try {
            const j = JSON.parse(l.slice(5));
            const ps = (j.candidates && j.candidates[0] && j.candidates[0].content && j.candidates[0].content.parts) || [];
            for (const p of ps) if (p.text && !p.thought) { any = true; await emit(p.text); }
          } catch {}
        }
      }
      if (!any) await emit("I can\u2019t help with that request.");
    } catch (e) {
      console.error("stream_error", e && e.message);
    } finally {
      try { await w.close(); } catch {}
    }
  })();
  if (ctx && ctx.waitUntil) ctx.waitUntil(pump);
  return new Response(readable, { headers: { "Content-Type": "text/event-stream", "Cache-Control": "no-store", ...cors } });
}

const WIDGET_JS = `(function(){
var cs=document.currentScript;
var API=cs&&cs.src?new URL(cs.src).origin:"";
var P={circle:'<circle cx="12" cy="12" r="9"/>',square:'<rect x="3" y="3" width="18" height="18" rx="2"/>',triangle:'<path d="M12 3l10 18H2z"/>',diamond:'<path d="M12 2l10 10-10 10L2 12z"/>',hex:'<path d="M12 2l9 5v10l-9 5-9-5V7z"/>',plus:'<path d="M9 2h6v7h7v6h-7v7H9v-7H2V9h7z"/>'};
var CSS=':host{display:block;font-family:system-ui,sans-serif}.hc{width:300px;max-width:100%;border:1px solid #cfe0e8;border-radius:10px;background:#fff;color:#0b2233;box-shadow:0 4px 16px rgba(3,105,161,.15);overflow:hidden}.bar{display:flex;align-items:center;gap:12px;padding:13px;font-weight:600;font-size:15px}.bar span{flex:1}.bar small{font-size:11px;color:#58738a}.box{width:26px;height:26px;border:2px solid #0369a1;border-radius:6px;background:#fff;cursor:pointer;padding:0;color:#fff;font-size:15px}.box.ok{background:#0f9d6b;border-color:#0f9d6b}.body{display:none;border-top:1px solid #cfe0e8;padding:12px}.body.open{display:block}.q{font-weight:600;font-size:14px;margin:0 0 8px}.g{display:grid;grid-template-columns:repeat(3,1fr);gap:4px}.t{aspect-ratio:1;border:0;border-radius:3px;background:linear-gradient(135deg,#bff3fb,#8fd8f4);position:relative;cursor:pointer;padding:0;display:grid;place-items:center}.t svg{width:56%;height:56%}.t.s::after{content:"✓";position:absolute;inset:0;display:grid;place-items:center;background:rgba(3,105,161,.8);color:#fff;font-size:24px;border-radius:3px}.row{display:flex;align-items:center;gap:10px;margin-top:10px}.go{background:#0369a1;color:#fff;border:0;border-radius:6px;padding:7px 14px;font-weight:600;font-size:13px;cursor:pointer}.msg{font-size:13px;color:#0f9d6b}.msg.bad{color:#d6354b}';
function mount(el){
if(el.__hc)return;
var sk=el.getAttribute("data-sitekey");if(!sk)return;
el.__hc=1;
var r=el.attachShadow({mode:"open"});
r.innerHTML='<style>'+CSS+'</style><div class="hc"><div class="bar"><button class="box" type="button" aria-label="I am human"></button><span>I am human</span><small>hClutcha</small></div><div class="body"><p class="q"></p><div class="g"></div><div class="row"><button class="go" type="button">Verify</button><span class="msg" role="status"></span></div></div></div>';
var $=function(s){return r.querySelector(s)};
var box=$(".box"),body=$(".body"),q=$(".q"),g=$(".g"),msg=$(".msg"),ch=null,sel=[],busy=false,timer=0;
var inp=document.createElement("input");inp.type="hidden";inp.name="hclutcha-response";el.appendChild(inp);
function say(t,bad){msg.textContent=t;msg.className="msg"+(bad?" bad":"")}
function post(path,data){return fetch(API+path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(data)}).then(function(x){return x.json()})}
function reset(){inp.value="";box.classList.remove("ok");box.textContent=""}
function load(){
say("Loading...");sel=[];
post("/v1/challenge",{sitekey:sk}).then(function(c){
if(c.error){say(c.error==="domain-not-allowed"?"This site is not allowed for this key.":"Could not load the challenge.",true);return}
ch=c;q.textContent=c.prompt;say("");
g.innerHTML=c.tiles.map(function(t,i){return '<button class="t" type="button" data-i="'+i+'" aria-label="'+t.s+'"><svg viewBox="0 0 24 24" fill="'+t.c+'">'+(P[t.s]||"")+'</svg></button>'}).join("");
}).catch(function(){say("Network error.",true)})}
g.addEventListener("click",function(e){var b=e.target.closest(".t");if(!b)return;var i=+b.dataset.i,k=sel.indexOf(i);if(k<0)sel.push(i);else sel.splice(k,1);b.classList.toggle("s",k<0)});
box.addEventListener("click",function(){if(box.classList.contains("ok")||body.classList.contains("open"))return;body.classList.add("open");load()});
$(".go").addEventListener("click",function(){
if(!ch||busy)return;busy=true;
post("/v1/solve",{id:ch.id,answer:sel}).then(function(res){
busy=false;
if(res.success){inp.value=res.token;box.classList.add("ok");box.textContent="✓";body.classList.remove("open");
var cb=el.getAttribute("data-callback");if(cb&&typeof window[cb]==="function")window[cb](res.token);
clearTimeout(timer);timer=setTimeout(reset,((res.expires_in||120)-5)*1000)}
else{say("Not a match. Try again.",true);setTimeout(load,800)}
}).catch(function(){busy=false;say("Network error.",true)})});
}
function scan(){document.querySelectorAll(".hclutcha[data-sitekey]").forEach(mount)}
if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",scan);else scan();
window.hclutcha={render:scan};
})();`;

const CONSOLE_HTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>hClutcha Console</title>
<style>
:root{--ink:#0b2233;--mut:#58738a;--line:#d6e7ef;--c3:#0369a1;--bg:#f2f9fc}
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,sans-serif;background:var(--bg);color:var(--ink);line-height:1.55}
.w{max-width:620px;margin:0 auto;padding:20px 16px 60px}
.logo{display:flex;gap:10px;align-items:center;margin-bottom:18px}.logo h1{font-size:24px;margin:0}
.tabs{display:flex;gap:6px;margin-bottom:16px}
.tabs button{flex:1;padding:10px;border:1px solid var(--line);background:#fff;border-radius:8px;font:600 15px system-ui,sans-serif;cursor:pointer;color:var(--ink)}
.tabs button.on{background:var(--c3);color:#fff;border-color:var(--c3)}
.card{background:#fff;border:1px solid var(--line);border-radius:12px;padding:18px}
label{display:block;font-weight:600;font-size:14px;margin:14px 0 4px}
input{width:100%;padding:10px;border:1px solid var(--line);border-radius:8px;font:16px system-ui,sans-serif}
button.p{margin-top:16px;background:var(--c3);color:#fff;border:0;border-radius:8px;padding:11px 20px;font:700 15px system-ui,sans-serif;cursor:pointer}
.err{color:#d6354b;font-size:14px;margin-top:10px}
pre{background:#06303d;color:#c8f1fb;padding:12px;border-radius:8px;overflow-x:auto;font-size:12.5px;margin:6px 0}
.k{display:flex;gap:8px;align-items:center}
.k code{flex:1;word-break:break-all;background:#eef7fb;padding:8px;border-radius:6px;font-size:13px}
.k button{padding:8px 12px;border:1px solid var(--line);background:#fff;border-radius:6px;cursor:pointer;font-weight:600}
.warn{background:#fff7e6;border:1px solid #f5d48a;padding:10px;border-radius:8px;font-size:14px;margin:14px 0 0}
</style></head><body><div class="w">
<div class="logo"><svg width="34" height="34" viewBox="0 0 30 30" aria-hidden="true"><rect x="7" width="16" height="7" fill="#22d3ee"/><rect y="7" width="30" height="16" fill="#0ea5e9"/><rect x="7" y="23" width="16" height="7" fill="#38bdf8"/><path d="M9 19c-2-3 0-7 2-8l1 2 2-6 2 1-1 5 3-4 1 1-3 5 3-3 1 2-5 5c-2 2-5 3-8 1z" fill="#fff"/></svg><h1>hClutcha Console</h1></div>
<div class="tabs"><button id="t1">Create site</button><button id="t2">My site</button></div>
<div class="card" id="v1">
<label for="em">Email</label><input id="em" type="email" autocomplete="email">
<label for="dm">Website domain</label><input id="dm" placeholder="example.com" autocapitalize="off" autocorrect="off">
<button class="p" id="go1">Create site</button><div class="err" id="e1" role="alert"></div><div id="res" hidden></div>
</div>
<div class="card" id="v2" hidden>
<label for="sk">Site key</label><input id="sk" autocapitalize="off">
<label for="sc">Secret key</label><input id="sc" type="password" autocomplete="off">
<button class="p" id="go2">Open site</button><div class="err" id="e2" role="alert"></div>
<div id="info" hidden><p id="meta"></p><button class="p" id="rot" style="margin-top:0">Rotate secret key</button><div id="rr" hidden></div></div>
</div>
</div>
<script>
(function(){
var $=function(i){return document.getElementById(i)};
var NL=String.fromCharCode(10);
var MSG={"invalid-email":"Enter a valid email address.","invalid-domain":"Enter a domain like example.com.","rate-limited":"Too many sites created. Try again in an hour.","invalid-keys":"Site key or secret key is wrong.","forbidden":"Request blocked."};
function tab(n){$("v1").hidden=n!==1;$("v2").hidden=n!==2;$("t1").className=n===1?"on":"";$("t2").className=n===2?"on":""}
function route(){tab(location.hash==="#console"||location.hash==="#login"?2:1)}
window.addEventListener("hashchange",route);route();
$("t1").onclick=function(){location.hash="signup"};
$("t2").onclick=function(){location.hash="console"};
function api(path,data){return fetch(path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(data)}).then(function(r){return r.json()})}
function el(t,txt,cls){var e=document.createElement(t);if(txt!=null)e.textContent=txt;if(cls)e.className=cls;return e}
function keyRow(label,val){var d=el("div");d.appendChild(el("label",label));var r=el("div",null,"k");r.appendChild(el("code",val));var b=el("button","Copy");b.type="button";b.onclick=function(){navigator.clipboard.writeText(val).then(function(){b.textContent="Copied"})};r.appendChild(b);d.appendChild(r);return d}
function show(box,sk,sc){
box.textContent="";box.hidden=false;
box.appendChild(el("div","Copy your secret key now. It is shown only once and cannot be recovered.","warn"));
box.appendChild(keyRow("Site key (public)",sk));
box.appendChild(keyRow("Secret key (server only)",sc));
box.appendChild(el("label","1. Add the widget to your form"));
box.appendChild(el("pre",'<script src="'+location.origin+'/widget.js" async defer></scr'+'ipt>'+NL+'<div class="hclutcha" data-sitekey="'+sk+'"></div>'));
box.appendChild(el("label","2. Verify the token on your server"));
box.appendChild(el("pre",'const r = await fetch("'+location.origin+'/v1/siteverify", {'+NL+'  method: "POST",'+NL+'  headers: { "Content-Type": "application/json" },'+NL+'  body: JSON.stringify({'+NL+'    secret: process.env.HC_SECRET,'+NL+'    response: req.body["hclutcha-response"],'+NL+'    remoteip: req.ip'+NL+'  })'+NL+'});'+NL+'const { success } = await r.json();'));
}
$("go1").onclick=function(){
$("e1").textContent="";$("res").hidden=true;
api("/v1/signup",{email:$("em").value,domain:$("dm").value}).then(function(j){
if(!j.sitekey){$("e1").textContent=MSG[j.error]||"Something went wrong. Try again.";return}
show($("res"),j.sitekey,j.secret);
}).catch(function(){$("e1").textContent="Network error. Try again."})};
$("go2").onclick=function(){
$("e2").textContent="";$("info").hidden=true;
api("/v1/site",{sitekey:$("sk").value.trim(),secret:$("sc").value.trim()}).then(function(j){
if(!j.sitekey){$("e2").textContent=MSG[j.error]||"Something went wrong. Try again.";return}
$("meta").textContent="Domain: "+j.domain+" | Status: "+(j.active?"active":"disabled")+" | Created: "+new Date(j.created_at*1000).toLocaleDateString();
$("info").hidden=false;$("rr").hidden=true;
}).catch(function(){$("e2").textContent="Network error. Try again."})};
$("rot").onclick=function(){
api("/v1/rotate",{sitekey:$("sk").value.trim(),secret:$("sc").value.trim()}).then(function(j){
if(!j.secret){$("e2").textContent=MSG[j.error]||"Something went wrong.";return}
$("sc").value=j.secret;show($("rr"),j.sitekey,j.secret);
}).catch(function(){$("e2").textContent="Network error. Try again."})};
})();
</script></body></html>`;

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    const path = url.pathname;
    if (path === "/health") return json({ ok: true, configured: !!(env.DB && env.TOKEN_SIGNING_KEY) });
    if (path === "/") return Response.redirect(url.origin + "/console", 302);
    if (path === "/console") {
      return new Response(CONSOLE_HTML, { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY" } });
    }
    if (path === "/widget.js") {
      return new Response(WIDGET_JS, { headers: { "Content-Type": "application/javascript; charset=utf-8", "Cache-Control": "public, max-age=300", "Access-Control-Allow-Origin": "*" } });
    }

    if (path === "/chat") {
      if (req.method === "OPTIONS") {
        const o = allowedOrigin(req, env);
        return o ? new Response(null, { status: 204, headers: chatCors(o) }) : new Response(null, { status: 403 });
      }
      if (req.method !== "POST") return json({ error: "method_not_allowed" }, 405, { Allow: "POST" });
      try { return await handleChat(req, env, ctx); }
      catch (e) { console.error("chat_error", e && e.message); return json({ error: "internal-error" }, 500); }
    }

    const routes = {
      "/v1/signup": handleSignup, "/v1/site": handleSite, "/v1/rotate": handleRotate,
      "/v1/challenge": handleChallenge, "/v1/solve": handleSolve, "/v1/siteverify": handleVerify,
    };
    const handler = routes[path];
    if (!handler) return json({ error: "not_found" }, 404);
    const cors = path === "/v1/challenge" || path === "/v1/solve";
    if (req.method === "OPTIONS" && cors) return new Response(null, { status: 204, headers: CORS });
    if (req.method !== "POST") return json({ error: "method_not_allowed" }, 405, { Allow: "POST" });
    if (!env.DB || !env.TOKEN_SIGNING_KEY) return json({ error: "server-not-configured: add the DB binding and TOKEN_SIGNING_KEY secret" }, 500, cors ? CORS : {});
    try {
      return await handler(req, env);
    } catch (e) {
      console.error("error", path, e && e.message);
      return json({ error: "internal-error" }, 500, cors ? CORS : {});
    }
  },

  async scheduled(_event, env, ctx) {
    const t = now();
    ctx.waitUntil(Promise.all([
      env.DB.prepare("DELETE FROM used_tokens WHERE exp < ?").bind(t).run(),
      env.DB.prepare("DELETE FROM challenges WHERE exp < ?").bind(t).run(),
      env.DB.prepare("DELETE FROM rl WHERE exp < ?").bind(t).run(),
    ]));
  },
};
