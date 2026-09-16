const COOKIE = "yc_session";
const SESSION_DAYS = 7;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "GET" && path === "/") return page();
    if (request.method === "GET" && path === "/panel") return panel();

    if (path === "/api/login" && request.method === "POST") return login(request, env);
    if (path === "/api/logout" && request.method === "POST") return logout(request);
    if (path === "/api/me" && request.method === "GET") return me(request, env);

    if (path.startsWith("/api/")) {
      const user = await auth(request, env);
      if (!user) return json({ error: "unauthorized" }, 401);

      if (path === "/api/settings" && request.method === "GET") return settings(env);
      if (path === "/api/settings" && request.method === "PUT") return updateSettings(request, env);
      if (path === "/api/posts" && request.method === "GET") return posts(env);
      if (path === "/api/posts" && request.method === "POST") return createPost(request, env);
      if (path.startsWith("/api/posts/") && request.method === "DELETE") {
        return deletePost(path.split("/").pop(), env);
      }
    }

    // Ana sayfadaki görsel Cloudflare Static Assets'tan gelir.
    if (path === "/site.png") {
      const asset = await env.ASSETS.fetch(new Request(new URL("/site.png", request.url)));
      return new Response(asset.body, {
        status: asset.status,
        headers: {
          "content-type": "image/png",
          "cache-control": "public, max-age=86400"
        }
      });
    }

    return new Response("Not found", { status: 404 });
  }
};

async function login(request, env) {
  const body = await request.json().catch(() => ({}));
  const username = String(body.username || "");
  const password = String(body.password || "");

  if (!username || !password) {
    return json({ error: "Kullan\u0131c\u0131 ad\u0131 ve \u015fifre gerekli" }, 400);
  }

  const admin = await env.DB
    .prepare("SELECT id,username,password_hash FROM admins WHERE username=?")
    .bind(username)
    .first();

  if (!admin || (await sha256(password)) !== admin.password_hash) {
    return json({ error: "Giri\u015f bilgileri hatal\u0131" }, 401);
  }

  const token = crypto.randomUUID() + "." + crypto.randomUUID();
  const hash = await sha256(token);
  const expires = Math.floor(Date.now() / 1000) + SESSION_DAYS * 86400;

  await env.DB
    .prepare("INSERT INTO sessions(token_hash,admin_id,expires_at) VALUES(?,?,?)")
    .bind(hash, admin.id, expires)
    .run();

  return json(
    { ok: true },
    200,
    {
      "Set-Cookie": `${COOKIE}=${token}; Path=/; Max-Age=${SESSION_DAYS * 86400}; HttpOnly; Secure; SameSite=Strict`
    }
  );
}

async function auth(request, env) {
  const token = cookie(request, COOKIE);
  if (!token) return null;

  const h = await sha256(token);
  const now = Math.floor(Date.now() / 1000);

  return await env.DB
    .prepare("SELECT admins.id,admins.username FROM sessions JOIN admins ON admins.id=sessions.admin_id WHERE sessions.token_hash=? AND sessions.expires_at>?")
    .bind(h, now)
    .first();
}

async function logout() {
  return new Response(JSON.stringify({ ok: true }), {
    headers: {
      "content-type": "application/json; charset=utf-8",
      "Set-Cookie": `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`
    }
  });
}

async function me(request, env) {
  const u = await auth(request, env);
  return u ? json({ ok: true, username: u.username }) : json({ ok: false }, 401);
}

async function settings(env) {
  const rows = await env.DB.prepare("SELECT key,value FROM settings").all();
  return json(Object.fromEntries(rows.results.map(x => [x.key, x.value])));
}

async function updateSettings(request, env) {
  const b = await request.json();
  for (const [k, v] of Object.entries(b)) {
    await env.DB
      .prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
      .bind(k, String(v))
      .run();
  }
  return settings(env);
}

async function posts(env) {
  const r = await env.DB.prepare("SELECT * FROM posts ORDER BY created_at DESC").all();
  return json(r.results);
}

async function createPost(request, env) {
  const b = await request.json();
  if (!b.title) return json({ error: "Ba\u015fl\u0131k gerekli" }, 400);

  await env.DB
    .prepare("INSERT INTO posts(title,version,status,description,link,created_at) VALUES(?,?,?,?,?,?)")
    .bind(
      b.title,
      b.version || "",
      b.status || "Yeni",
      b.description || "",
      b.link || "",
      new Date().toISOString()
    )
    .run();

  return posts(env);
}

async function deletePost(id, env) {
  await env.DB.prepare("DELETE FROM posts WHERE id=?").bind(id).run();
  return posts(env);
}

async function sha256(s) {
  const b = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(b)]
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

function cookie(r, n) {
  const c = r.headers.get("Cookie") || "";
  const escaped = n.replace(/[.*+?^${}()|[\\]\\]/g, "\\$&");
  const m = c.match(new RegExp("(?:^|; )" + escaped + "=([^;]+)"));
  return m && m[1];
}

function json(x, status = 200, extra = {}) {
  return new Response(JSON.stringify(x), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...extra
    }
  });
}

function page() {
  return new Response(
    `<!doctype html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>YargiConfig</title>
<style>
body{margin:0;background:#02060a;color:#fff;font-family:Arial,sans-serif;display:grid;place-items:center;min-height:100vh}
.wrap{width:min(1536px,100%);position:relative}
img{width:100%;height:auto;display:block}
.tg{position:absolute;left:6%;top:39%;width:23%;height:6%;display:block}
</style>
</head>
<body>
<div class="wrap">
<img src="/site.png" alt="YargiConfig">
<a class="tg" href="https://t.me/ioscedrixddconfig" aria-label="Telegram"></a>
</div>
</body>
</html>`,
    { headers: { "content-type": "text/html; charset=UTF-8" } }
  );
}

function panel() {
  return new Response(PANEL, {
    headers: { "content-type": "text/html; charset=UTF-8" }
  });
}

// Panelde Türkçe karakterleri HTML entity olarak kullandık; böylece kaynak dosyanın
// yanlış kodlanması durumunda bile "Kullanıcı", "Şifre" ve "Giriş Yap" bozulmaz.
const PANEL = `<!doctype html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>YargiConfig Admin</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#03070b;color:#eaf3ff;font-family:Arial,sans-serif}
.wrap{max-width:1100px;margin:auto;padding:25px}
.card{background:#08121b;border:1px solid #1b3548;border-radius:14px;padding:22px;margin-bottom:18px;box-shadow:0 15px 45px #0008}
h1{margin:0 0 5px}
h2{font-size:18px}
.blue{color:#0792ff}
input,textarea,select{width:100%;padding:12px;margin:6px 0 12px;background:#03090e;color:#fff;border:1px solid #263d4d;border-radius:8px}
button{padding:12px 17px;border:0;border-radius:9px;background:#078cff;color:#fff;font-weight:800;cursor:pointer}
.danger{background:#b52b45}
.muted{color:#8495a7}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.stat{padding:17px;border:1px solid #193044;border-radius:12px;background:#061018}
.stat b{display:block;color:#0792ff;font-size:24px}
.hidden{display:none}
.post{padding:12px 0;border-top:1px solid #18303e;display:flex;gap:10px;align-items:center}
.post div{flex:1}
@media(max-width:700px){.grid{grid-template-columns:1fr}.wrap{padding:15px}}
</style>
</head>
<body>
<div class="wrap">
  <div id="login" class="card">
    <h1>♛ YARGI<span class="blue">CONFIG</span></h1>
    <p class="muted">Admin Paneli</p>
    <input id="u" placeholder="Kullan&#305;c&#305; ad&#305;" autocomplete="username">
    <input id="p" type="password" placeholder="&#350;ifre" autocomplete="current-password">
    <button onclick="login()">Giri&#351; Yap</button>
    <p id="err"></p>
  </div>

  <div id="app" class="hidden">
    <div class="card">
      <h1>♛ YARGI<span class="blue">CONFIG</span></h1>
      <p class="muted">Y&ouml;netim Paneli</p>
      <button onclick="logout()">&Ccedil;ıkış</button>
    </div>

    <div class="grid">
      <div class="stat"><b id="pc">0</b>Paylaşım</div>
      <div class="stat"><b>4.6</b>Site s&uuml;r&uuml;m&uuml;</div>
      <div class="stat"><b>●</b>Sistem aktif</div>
    </div>

    <div class="card">
      <h2>📰 Yeni Paylaşım</h2>
      <input id="title" placeholder="Ba&#351;l&#305;k">
      <input id="version" placeholder="S&uuml;r&uuml;m (örn. 4.6)">
      <select id="status">
        <option>Yeni</option>
        <option>G&uuml;ncel</option>
        <option>Taslak</option>
      </select>
      <textarea id="desc" placeholder="A&ccedil;&#305;klama"></textarea>
      <input id="link" placeholder="Telegram / indirme bağlant&#305;s&#305;">
      <button onclick="addPost()">Yay&#305;nla</button>
    </div>

    <div class="card">
      <h2>📋 Payla&#351;&#305;mlar</h2>
      <div id="posts"></div>
    </div>

    <div class="card">
      <h2>🏠 Ana Sayfa Ayarlar&#305;</h2>
      <input id="hero" placeholder="Hero ba&#351;l&#305;&#287;&#305;">
      <input id="telegram" placeholder="Telegram ba&#287;lant&#305;s&#305;">
      <input id="members" placeholder="Aktif &uuml;ye say&#305;s&#305;">
      <input id="shares" placeholder="Payla&#351;&#305;m say&#305;s&#305;">
      <button onclick="saveSettings()">Kaydet</button>
    </div>
  </div>
</div>

<script>
async function api(url,opt){
  let r=await fetch(url,opt);
  let d=await r.json();
  if(!r.ok)throw Error(d.error||'Hata');
  return d;
}

async function boot(){
  try{await api('/api/me');show()}catch{}
}

function show(){
  loginBox.classList.add('hidden');
  app.classList.remove('hidden');
  load();
}

const loginBox=document.getElementById('login');
const app=document.getElementById('app');

async function login(){
  try{
    await api('/api/login',{
      method:'POST',
      headers:{'content-type':'application/json'},
      body:JSON.stringify({username:u.value,password:p.value})
    });
    show();
  }catch(e){
    err.textContent=e.message;
    err.style.color='#ff6680';
  }
}

async function logout(){
  await api('/api/logout',{method:'POST'});
  location.reload();
}

async function load(){
  let ps=await api('/api/posts');
  pc.textContent=ps.length;
  posts.innerHTML=ps.map(x=>
    '<div class="post"><div><b>'+esc(x.title)+'</b><small class="muted"> '+esc(x.version||'')+' · '+esc(x.status||'')+'</small></div><button class="danger" onclick="del('+x.id+')">Sil</button></div>'
  ).join('')||'<span class="muted">Hen&uuml;z payla&#351;&#305;m yok.</span>';

  let s=await api('/api/settings');
  hero.value=s.hero||'';
  telegram.value=s.telegram||'https://t.me/ioscedrixddconfig';
  members.value=s.members||'';
  shares.value=s.shares||'';
}

async function addPost(){
  await api('/api/posts',{
    method:'POST',
    headers:{'content-type':'application/json'},
    body:JSON.stringify({
      title:title.value,
      version:version.value,
      status:status.value,
      description:desc.value,
      link:link.value
    })
  });
  title.value=version.value=desc.value=link.value='';
  load();
}

async function del(id){
  if(confirm('Bu payla&#351;&#305;m silinsin mi?')){
    await api('/api/posts/'+id,{method:'DELETE'});
    load();
  }
}

async function saveSettings(){
  await api('/api/settings',{
    method:'PUT',
    headers:{'content-type':'application/json'},
    body:JSON.stringify({
      hero:hero.value,
      telegram:telegram.value,
      members:members.value,
      shares:shares.value
    })
  });
  alert('Kaydedildi');
}

function esc(s){
  return String(s||'').replace(/[&<>"']/g,c=>({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  }[c]));
}

boot();
</script>
</body>
</html>`;
