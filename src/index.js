const IMAGE_URL =
  "https://raw.githubusercontent.com/46jfw59vrw-creator/Yargiconfigv5/main/public/site.png";

const COOKIE = "yc_session";
const SESSION_DAYS = 7;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === "/site.png") {
      return fetch(IMAGE_URL);
    }

    if (path === "/") {
      return new Response(`
<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>YargiConfig</title>
<style>
html,body{margin:0;padding:0;background:#000}
img{display:block;width:100%;height:auto}
a{position:absolute;display:block}
.page{position:relative;width:100%;max-width:1920px;margin:auto}
</style>
</head>
<body>
<div class="page">
<img src="/site.png" alt="YargiConfig">
<a href="https://t.me/ioscedrixddconfig"
style="left:35%;top:58%;width:30%;height:8%;"></a>
</div>
</body>
</html>
`, {
        headers: {
          "content-type": "text/html; charset=UTF-8"
        }
      });
    }

    if (path === "/panel") {
      return new Response(PANEL_HTML, {
        headers: {
          "content-type": "text/html; charset=UTF-8"
        }
      });
    }

    if (path === "/api/login" && request.method === "POST") {
      return login(request, env);
    }

    if (path === "/api/logout" && request.method === "POST") {
      return new Response(JSON.stringify({ ok: true }), {
        headers: {
          "content-type": "application/json",
          "Set-Cookie":
            `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`
        }
      });
    }

    const admin = await authenticate(request, env);

    if (!admin) {
      return json({ error: "Yetkisiz" }, 401);
    }

    if (path === "/api/me") {
      return json({
        ok: true,
        username: admin.username
      });
    }

    if (path === "/api/settings" && request.method === "GET") {
      const result = await env.DB
        .prepare("SELECT key,value FROM settings")
        .all();

      const settings = {};

      for (const row of result.results) {
        settings[row.key] = row.value;
      }

      return json(settings);
    }

    if (path === "/api/settings" && request.method === "PUT") {
      const data = await request.json();

      for (const [key, value] of Object.entries(data)) {
        await env.DB
          .prepare(
            "INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"
          )
          .bind(key, String(value))
          .run();
      }

      return json({ ok: true });
    }

    if (path === "/api/posts" && request.method === "GET") {
      const result = await env.DB
        .prepare(
          "SELECT id,title,version,status,description,link,created_at FROM posts ORDER BY id DESC"
        )
        .all();

      return json(result.results);
    }

    if (path === "/api/posts" && request.method === "POST") {
      const data = await request.json();

      await env.DB
        .prepare(`
          INSERT INTO posts
          (title,version,status,description,link,created_at)
          VALUES(?,?,?,?,?,?)
        `)
        .bind(
          data.title || "",
          data.version || "",
          data.status || "Taslak",
          data.description || "",
          data.link || "",
          new Date().toISOString()
        )
        .run();

      return json({ ok: true });
    }

    if (path.startsWith("/api/posts/") && request.method === "DELETE") {
      const id = path.split("/").pop();

      await env.DB
        .prepare("DELETE FROM posts WHERE id=?")
        .bind(id)
        .run();

      return json({ ok: true });
    }

    return new Response("404", { status: 404 });
  }
};

async function login(request, env) {
  const data = await request.json();

  if (!data.username || !data.password) {
    return json({ error: "KullanÄ±cÄ± adÄ± ve Åifre gerekli" }, 400);
  }

  const admin = await env.DB
    .prepare(
      "SELECT id,username,password_hash FROM admins WHERE username=?"
    )
    .bind(data.username)
    .first();

  if (!admin) {
    return json({ error: "KullanÄ±cÄ± adÄ± veya Åifre hatalÄ±" }, 401);
  }

  const hash = await sha256(data.password);

  if (hash !== admin.password_hash) {
    return json({ error: "KullanÄ±cÄ± adÄ± veya Åifre hatalÄ±" }, 401);
  }

  const token = crypto.randomUUID() + "-" + crypto.randomUUID();
  const tokenHash = await sha256(token);

  const expires =
    Math.floor(Date.now() / 1000) +
    SESSION_DAYS * 24 * 60 * 60;

  await env.DB
    .prepare(
      "INSERT INTO sessions(token_hash,admin_id,expires_at) VALUES(?,?,?)"
    )
    .bind(tokenHash, admin.id, expires)
    .run();

  return new Response(JSON.stringify({
    ok: true
  }), {
    headers: {
      "content-type": "application/json",
      "Set-Cookie":
        `${COOKIE}=${token}; Path=/; Max-Age=${SESSION_DAYS * 86400}; HttpOnly; Secure; SameSite=Strict`
    }
  });
}

async function authenticate(request, env) {
  const cookie = request.headers.get("Cookie") || "";

  const match = cookie.match(
    new RegExp(`${COOKIE}=([^;]+)`)
  );

  if (!match) return null;

  const tokenHash = await sha256(match[1]);

  const row = await env.DB
    .prepare(`
      SELECT admins.id,admins.username
      FROM sessions
      JOIN admins ON admins.id=sessions.admin_id
      WHERE sessions.token_hash=?
      AND sessions.expires_at>?
    `)
    .bind(
      tokenHash,
      Math.floor(Date.now() / 1000)
    )
    .first();

  return row || null;
}

async function sha256(text) {
  const data = new TextEncoder().encode(text);

  const hash = await crypto.subtle.digest(
    "SHA-256",
    data
  );

  return [...new Uint8Array(hash)]
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

function json(data, status = 200) {
  return new Response(
    JSON.stringify(data),
    {
      status,
      headers: {
        "content-type": "application/json; charset=UTF-8"
      }
    }
  );
}

const PANEL_HTML = `
<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>YargiConfig Admin</title>

<style>
*{box-sizing:border-box}
body{
margin:0;
font-family:Arial,sans-serif;
background:#080b12;
color:#fff;
min-height:100vh
}
.container{
max-width:1000px;
margin:auto;
padding:30px 18px
}
.card{
background:#111722;
border:1px solid #263246;
border-radius:16px;
padding:22px;
margin-bottom:18px
}
h1,h2{margin-top:0}
input,textarea,select{
width:100%;
padding:13px;
margin:7px 0 12px;
border-radius:9px;
border:1px solid #344258;
background:#080d16;
color:white
}
button{
border:0;
border-radius:9px;
padding:12px 18px;
background:#147cff;
color:white;
font-weight:bold;
cursor:pointer;
margin-right:6px
}
button.red{background:#d33}
#app{display:none}
.post{
padding:15px;
border:1px solid #29364a;
border-radius:10px;
margin:10px 0
}
.small{color:#9ca9bb;font-size:13px}
</style>
</head>

<body>

<div class="container">

<div id="login" class="card">

<h1>YargiConfig Admin</h1>

<input id="username" placeholder="KullanÄ±cÄ± adÄ±">
<input id="password" type="password" placeholder="Åifre">

<button onclick="login()">GiriÅ Yap</button>

<p id="loginMsg" class="small"></p>

</div>

<div id="app">

<div class="card">

<h1>YargiConfig Panel</h1>

<p class="small">
Admin paneline hoÅ geldin.
</p>

<button onclick="logout()" class="red">
ÃÄ±kÄ±Å Yap
</button>

</div>

<div class="card">

<h2>Ana Sayfa AyarlarÄ±</h2>

<label>Hero baÅlÄ±k</label>
<input id="hero">

<label>Telegram</label>
<input id="telegram">

<label>Ãye sayÄ±sÄ±</label>
<input id="members">

<label>PaylaÅÄ±m sayÄ±sÄ±</label>
<input id="shares">

<button onclick="saveSettings()">
AyarlarÄ± Kaydet
</button>

</div>

<div class="card">

<h2>Yeni PaylaÅÄ±m</h2>

<input id="title" placeholder="BaÅlÄ±k">

<input id="version" placeholder="SÃ¼rÃ¼m">

<select id="status">
<option>YayÄ±nlandÄ±</option>
<option>Taslak</option>
<option>GÃ¼ncelleme</option>
</select>

<textarea id="description"
placeholder="AÃ§Ä±klama"></textarea>

<input id="link"
placeholder="Ä°ndirme / Telegram baÄlantÄ±sÄ±">

<button onclick="addPost()">
PaylaÅÄ±mÄ± Ekle
</button>

</div>

<div class="card">

<h2>PaylaÅÄ±mlar</h2>

<div id="posts"></div>

</div>

</div>

</div>

<script>

async function api(url,options={}){
const r=await fetch(url,{
credentials:"include",
...options
});

return r.json();
}

async function check(){

const r=await api("/api/me");

if(r.ok){

document.getElementById("login").style.display="none";
document.getElementById("app").style.display="block";

loadSettings();
loadPosts();

}

}

async function login(){

const username=
document.getElementById("username").value;

const password=
document.getElementById("password").value;

const r=await api("/api/login",{
method:"POST",
headers:{
"content-type":"application/json"
},
body:JSON.stringify({
username,
password
})
});

if(r.ok){

document.getElementById("login").style.display="none";
document.getElementById("app").style.display="block";

loadSettings();
loadPosts();

}else{

document.getElementById("loginMsg").textContent=
r.error || "GiriÅ baÅarÄ±sÄ±z";

}

}

async function logout(){

await api("/api/logout",{
method:"POST"
});

location.reload();

}

async function loadSettings(){

const s=await api("/api/settings");

document.getElementById("hero").value=s.hero||"";
document.getElementById("telegram").value=s.telegram||"";
document.getElementById("members").value=s.members||"";
document.getElementById("shares").value=s.shares||"";

}

async function saveSettings(){

await api("/api/settings",{
method:"PUT",
headers:{
"content-type":"application/json"
},
body:JSON.stringify({
hero:document.getElementById("hero").value,
telegram:document.getElementById("telegram").value,
members:document.getElementById("members").value,
shares:document.getElementById("shares").value
})
});

alert("Ayarlar kaydedildi.");

}

async function loadPosts(){

const posts=await api("/api/posts");

const box=document.getElementById("posts");

box.innerHTML="";

posts.forEach(p=>{

const div=document.createElement("div");

div.className="post";

div.innerHTML=
"<b>"+escapeHtml(p.title)+"</b>"+
"<br><span class='small'>"+
escapeHtml(p.version||"")+
" â¢ "+
escapeHtml(p.status||"")+
"</span>"+
"<p>"+escapeHtml(p.description||"")+"</p>"+
"<button class='red' onclick='deletePost("+
p.id+
")'>Sil</button>";

box.appendChild(div);

});

}

async function addPost(){

await api("/api/posts",{
method:"POST",
headers:{
"content-type":"application/json"
},
body:JSON.stringify({

title:document.getElementById("title").value,
version:document.getElementById("version").value,
status:document.getElementById("status").value,
description:document.getElementById("description").value,
link:document.getElementById("link").value

})
});

document.getElementById("title").value="";
document.getElementById("version").value="";
document.getElementById("description").value="";
document.getElementById("link").value="";

loadPosts();

}

async function deletePost(id){

if(!confirm("Bu paylaÅÄ±m silinsin mi?")) return;

await api("/api/posts/"+id,{
method:"DELETE"
});

loadPosts();

}

function escapeHtml(text){

return String(text)
.replaceAll("&","&amp;")
.replaceAll("<","&lt;")
.replaceAll(">","&gt;")
.replaceAll('"',"&quot;")
.replaceAll("'","&#039;");

}

check();

</script>

</body>
</html>
`;
