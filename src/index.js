const COOKIE = "yc_session";
const SESSION_DAYS = 7;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "GET" && path === "/") {
      return page();
    }

    if (request.method === "GET" && path === "/panel") {
      return panel();
    }

    if (path === "/api/login" && request.method === "POST") {
      return login(request, env);
    }

    if (path === "/api/logout" && request.method === "POST") {
      return logout(request);
    }

    if (path === "/api/me" && request.method === "GET") {
      return me(request, env);
    }

    if (path.startsWith("/api/")) {
      const user = await auth(request, env);

      if (!user) {
        return json({ error: "unauthorized" }, 401);
      }

      if (path === "/api/settings" && request.method === "GET") {
        return settings(env);
      }

      if (path === "/api/settings" && request.method === "PUT") {
        return updateSettings(request, env);
      }

      if (path === "/api/posts" && request.method === "GET") {
        return posts(env);
      }

      if (path === "/api/posts" && request.method === "POST") {
        return createPost(request, env);
      }

      if (
        path.startsWith("/api/posts/") &&
        request.method === "DELETE"
      ) {
        return deletePost(path.split("/").pop(), env);
      }
    }

    if (path === "/site.png") {
      return env.ASSETS.fetch(
        new Request(new URL("/site.png", request.url))
      );
    }

    return new Response("Not found", { status: 404 });
  }
};

async function login(request, env) {
  const body = await request.json().catch(() => ({}));

  const username = String(body.username || "");
  const password = String(body.password || "");

  if (!username || !password) {
    return json(
      { error: "KullanÄ±cÄ± adÄ± ve Åifre gerekli" },
      400
    );
  }

  const admin = await env.DB
    .prepare(
      "SELECT id, username, password_hash FROM admins WHERE username=?"
    )
    .bind(username)
    .first();

  if (
    !admin ||
    (await sha256(password)) !== admin.password_hash
  ) {
    return json(
      { error: "GiriÅ bilgileri hatalÄ±" },
      401
    );
  }

  const token =
    crypto.randomUUID() + "." + crypto.randomUUID();

  const hash = await sha256(token);

  const expires =
    Math.floor(Date.now() / 1000) +
    SESSION_DAYS * 86400;

  await env.DB
    .prepare(
      "INSERT INTO sessions(token_hash,admin_id,expires_at) VALUES(?,?,?)"
    )
    .bind(hash, admin.id, expires)
    .run();

  return json(
    { ok: true },
    200,
    {
      "Set-Cookie":
        `${COOKIE}=${token}; Path=/; Max-Age=${SESSION_DAYS * 86400}; HttpOnly; Secure; SameSite=Strict`
    }
  );
}

async function auth(request, env) {
  const token = cookie(request, COOKIE);

  if (!token) {
    return null;
  }

  const hash = await sha256(token);
  const now = Math.floor(Date.now() / 1000);

  const session = await env.DB
    .prepare(
      `SELECT admins.id, admins.username
       FROM sessions
       JOIN admins ON admins.id = sessions.admin_id
       WHERE sessions.token_hash=?
       AND sessions.expires_at>?`
    )
    .bind(hash, now)
    .first();

  return session || null;
}

async function logout(request) {
  return new Response(
    JSON.stringify({ ok: true }),
    {
      headers: {
        "content-type": "application/json",
        "Set-Cookie":
          `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`
      }
    }
  );
}

async function me(request, env) {
  const user = await auth(request, env);

  if (!user) {
    return json({ ok: false }, 401);
  }

  return json({
    ok: true,
    username: user.username
  });
}

async function settings(env) {
  const rows = await env.DB
    .prepare("SELECT key,value FROM settings")
    .all();

  return json(
    Object.fromEntries(
      rows.results.map(row => [
        row.key,
        row.value
      ])
    )
  );
}

async function updateSettings(request, env) {
  const body = await request.json();

  for (const [key, value] of Object.entries(body)) {
    await env.DB
      .prepare(
        `INSERT INTO settings(key,value)
         VALUES(?,?)
         ON CONFLICT(key)
         DO UPDATE SET value=excluded.value`
      )
      .bind(key, String(value))
      .run();
  }

  return settings(env);
}

async function posts(env) {
  const result = await env.DB
    .prepare(
      "SELECT * FROM posts ORDER BY created_at DESC"
    )
    .all();

  return json(result.results);
}

async function createPost(request, env) {
  const body = await request.json();

  if (!body.title) {
    return json(
      { error: "BaÅlÄ±k gerekli" },
      400
    );
  }

  await env.DB
    .prepare(
      `INSERT INTO posts
       (title,version,status,description,link,created_at)
       VALUES(?,?,?,?,?,?)`
    )
    .bind(
      body.title,
      body.version || "",
      body.status || "Yeni",
      body.description || "",
      body.link || "",
      new Date().toISOString()
    )
    .run();

  return posts(env);
}

async function deletePost(id, env) {
  await env.DB
    .prepare("DELETE FROM posts WHERE id=?")
    .bind(id)
    .run();

  return posts(env);
}

async function sha256(value) {
  const buffer =
    await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(value)
    );

  return [...new Uint8Array(buffer)]
    .map(
      byte =>
        byte.toString(16).padStart(2, "0")
    )
    .join("");
}

function cookie(request, name) {
  const cookies =
    request.headers.get("Cookie") || "";

  const regex = new RegExp(
    "(?:^|; )" +
    name.replace(
      /[.*+?^${}()|[\]\\]/g,
      "\\$&"
    ) +
    "=([^;]+)"
  );

  const match = cookies.match(regex);

  return match && match[1];
}

function json(data, status = 200, extra = {}) {
  return new Response(
    JSON.stringify(data),
    {
      status,
      headers: {
        "content-type":
          "application/json; charset=utf-8",
        ...extra
      }
    }
  );
}

function page() {
  return new Response(
    `<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport"
content="width=device-width,initial-scale=1">
<title>YargiConfig</title>
<style>
body{
margin:0;
background:#02060a;
color:#fff;
font-family:Arial;
display:grid;
place-items:center;
min-height:100vh
}
.wrap{
width:min(1536px,100%);
position:relative
}
img{
width:100%;
height:auto;
display:block
}
.tg{
position:absolute;
left:6%;
top:39%;
width:23%;
height:6%;
display:block
}
</style>
</head>
<body>
<div class="wrap">
<img src="/site.png">
<a class="tg"
href="https://t.me/ioscedrixddconfig"></a>
</div>
</body>
</html>`,
    {
      headers: {
        "content-type":
          "text/html;charset=utf-8"
      }
    }
  );
}

function panel() {
  return new Response(
    PANEL,
    {
      headers: {
        "content-type":
          "text/html;charset=utf-8"
      }
    }
  );
}

const PANEL = `<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport"
content="width=device-width,initial-scale=1">
<title>YargiConfig Admin</title>

<style>
*{
box-sizing:border-box
}

body{
margin:0;
background:#03070b;
color:#eaf3ff;
font-family:Arial
}

.wrap{
max-width:1100px;
margin:auto;
padding:25px
}

.card{
background:#08121b;
border:1px solid #1b3548;
border-radius:14px;
padding:22px;
margin-bottom:18px;
box-shadow:0 15px 45px #0008
}

h1{
margin:0 0 5px
}

h2{
font-size:18px
}

.blue{
color:#0792ff
}

input,
textarea,
select{
width:100%;
padding:12px;
margin:6px 0 12px;
background:#03090e;
color:#fff;
border:1px solid #263d4d;
border-radius:8px
}

button{
padding:12px 17px;
border:0;
border-radius:9px;
background:#078cff;
color:#fff;
font-weight:800;
cursor:pointer
}

.danger{
background:#b52b45
}

.muted{
color:#8495a7
}

.grid{
display:grid;
grid-template-columns:
repeat(3,1fr);
gap:14px
}

.stat{
padding:17px;
border:1px solid #193044;
border-radius:12px;
background:#061018
}

.stat b{
display:block;
color:#0792ff;
font-size:24px
}

.hidden{
display:none
}

.post{
padding:12px 0;
border-top:1px solid #18303e;
display:flex;
gap:10px;
align-items:center
}

.post div{
flex:1
}

@media(max-width:700px){
.grid{
grid-template-columns:1fr
}

.wrap{
padding:15px
}
}
</style>
</head>

<body>

<div class="wrap">

<div id="login" class="card">

<h1>
â YARGI<span class="blue">CONFIG</span>
</h1>

<p class="muted">
Admin Panel
</p>

<input
id="u"
placeholder="KullanÄ±cÄ± adÄ±">

<input
id="p"
type="password"
placeholder="Åifre">

<button onclick="login()">
GiriÅ Yap
</button>

<p id="err"></p>

</div>


<div id="app" class="hidden">

<div class="card">

<h1>
â YARGI<span class="blue">CONFIG</span>
</h1>

<p class="muted">
YÃ¶netim Paneli
</p>

<button onclick="logout()">
ÃÄ±kÄ±Å
</button>

</div>


<div class="grid">

<div class="stat">
<b id="pc">0</b>
PaylaÅÄ±m
</div>

<div class="stat">
<b>4.6</b>
Site sÃ¼rÃ¼mÃ¼
</div>

<div class="stat">
<b>â</b>
Sistem aktif
</div>

</div>


<div class="card">

<h2>
ð° Yeni PaylaÅÄ±m
</h2>

<input
id="title"
placeholder="BaÅlÄ±k">

<input
id="version"
placeholder="SÃ¼rÃ¼m (Ã¶rn. 4.6)">

<select id="status">
<option>Yeni</option>
<option>GÃ¼ncel</option>
<option>Taslak</option>
</select>

<textarea
id="desc"
placeholder="AÃ§Ä±klama">
</textarea>

<input
id="link"
placeholder="Telegram / indirme baÄlantÄ±sÄ±">

<button onclick="addPost()">
YayÄ±nla
</button>

</div>


<div class="card">

<h2>
ð PaylaÅÄ±mlar
</h2>

<div id="posts"></div>

</div>


<div class="card">

<h2>
ð  Ana Sayfa AyarlarÄ±
</h2>

<input
id="hero"
placeholder="Hero baÅlÄ±ÄÄ±">

<input
id="telegram"
placeholder="Telegram baÄlantÄ±sÄ±">

<input
id="members"
placeholder="Aktif Ã¼ye sayÄ±sÄ±">

<input
id="shares"
placeholder="PaylaÅÄ±m sayÄ±sÄ±">

<button onclick="saveSettings()">
Kaydet
</button>

</div>

</div>

</div>


<script>

async function api(url,opt){

let response =
await fetch(url,opt);

let data =
await response.json();

if(!response.ok){
throw Error(
data.error || "Hata"
);
}

return data;
}


async function boot(){

try{

await api("/api/me");

show();

}catch{}

}


function show(){

loginBox.classList.add(
"hidden"
);

app.classList.remove(
"hidden"
);

load();

}


const loginBox =
document.getElementById(
"login"
);

const app =
document.getElementById(
"app"
);


async function login(){

try{

await api(
"/api/login",
{
method:"POST",
headers:{
"content-type":
"application/json"
},
body:JSON.stringify({
username:u.value,
password:p.value
})
}
);

show();

}catch(error){

err.textContent =
error.message;

err.style.color =
"#ff6680";

}

}


async function logout(){

await api(
"/api/logout",
{
method:"POST"
}
);

location.reload();

}


async function load(){

let ps =
await api("/api/posts");

pc.textContent =
ps.length;

posts.innerHTML =
ps.map(
x => \`
<div class="post">

<div>

<b>
\${esc(x.title)}
</b>

<small class="muted">
\${esc(x.version || "")}
Â·
\${esc(x.status || "")}
</small>

</div>

<button
class="danger"
onclick="del(\${x.id})">

Sil

</button>

</div>
\`
).join("")
||
'<span class="muted">HenÃ¼z paylaÅÄ±m yok.</span>';


let s =
await api("/api/settings");

hero.value =
s.hero || "";

telegram.value =
s.telegram ||
"https://t.me/ioscedrixddconfig";

members.value =
s.members || "";

shares.value =
s.shares || "";

}


async function addPost(){

await api(
"/api/posts",
{
method:"POST",
headers:{
"content-type":
"application/json"
},
body:JSON.stringify({
title:title.value,
version:version.value,
status:status.value,
description:desc.value,
link:link.value
})
}
);

title.value = "";
version.value = "";
desc.value = "";
link.value = "";

load();

}


async function del(id){

if(
confirm(
"Bu paylaÅÄ±m silinsin mi?"
)
){

await api(
"/api/posts/" + id,
{
method:"DELETE"
}
);

load();

}

}


async function saveSettings(){

await api(
"/api/settings",
{
method:"PUT",
headers:{
"content-type":
"application/json"
},
body:JSON.stringify({
hero:hero.value,
telegram:telegram.value,
members:members.value,
shares:shares.value
})
}
);

alert("Kaydedildi");

}


function esc(value){

return String(value || "")
.replace(
/[&<>"']/g,
char => ({
"&":"&amp;",
"<":"&lt;",
">":"&gt;",
'"':"&quot;",
"'":"&#39;"
}[char])
);

}

boot();

</script>

</body>
</html>`;
