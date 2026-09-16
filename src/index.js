const COOKIE = "yc_session";
const SESSION_DAYS = 7;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // ANA SAYFA
    if (request.method === "GET" && path === "/") {
      return page();
    }

    // ADMIN PANEL
    if (request.method === "GET" && path === "/panel") {
      return panel();
    }

    // LOGIN
    if (path === "/api/login" && request.method === "POST") {
      return login(request, env);
    }

    // LOGOUT
    if (path === "/api/logout" && request.method === "POST") {
      return logout(request, env);
    }

    // SESSION
    if (path === "/api/me" && request.method === "GET") {
      return me(request, env);
    }

    // API
    if (path.startsWith("/api/")) {
      const user = await auth(request, env);

      if (!user) {
        return json(
          { error: "Yetkisiz erişim." },
          401
        );
      }

      if (
        path === "/api/settings" &&
        request.method === "GET"
      ) {
        return settings(env);
      }

      if (
        path === "/api/settings" &&
        request.method === "PUT"
      ) {
        return updateSettings(request, env);
      }

      if (
        path === "/api/posts" &&
        request.method === "GET"
      ) {
        return posts(env);
      }

      if (
        path === "/api/posts" &&
        request.method === "POST"
      ) {
        return createPost(request, env);
      }

      if (
        path.startsWith("/api/posts/") &&
        request.method === "DELETE"
      ) {
        return deletePost(
          path.split("/").pop(),
          env
        );
      }
    }

    // ANA SITE GÖRSELİ
    if (path === "/site.png") {
      const asset = await env.ASSETS.fetch(
        new Request(
          new URL("/site.png", request.url)
        )
      );

      return new Response(asset.body, {
        status: asset.status,
        headers: {
          "content-type": "image/png",
          "cache-control": "public, max-age=86400"
        }
      });
    }

    // DİĞER STATİK DOSYALAR
    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return new Response("Not Found", {
      status: 404
    });
  }
};


// ================================
// LOGIN
// ================================

async function login(request, env) {
  const body = await request.json().catch(() => ({}));

  const username = String(
    body.username || ""
  );

  const password = String(
    body.password || ""
  );

  if (!username || !password) {
    return json(
      {
        error:
          "Kullanıcı adı ve şifre gerekli."
      },
      400
    );
  }

  const admin = await env.DB
    .prepare(
      `SELECT id, username, password_hash
       FROM admins
       WHERE username = ?`
    )
    .bind(username)
    .first();

  if (
    !admin ||
    (await sha256(password)) !==
      admin.password_hash
  ) {
    return json(
      {
        error:
          "Giriş bilgileri hatalı."
      },
      401
    );
  }

  const token =
    crypto.randomUUID() +
    "." +
    crypto.randomUUID();

  const hash = await sha256(token);

  const expires =
    Math.floor(Date.now() / 1000) +
    SESSION_DAYS * 86400;

  await env.DB
    .prepare(
      `INSERT INTO sessions
       (token_hash, admin_id, expires_at)
       VALUES (?, ?, ?)`
    )
    .bind(
      hash,
      admin.id,
      expires
    )
    .run();

  return json(
    { ok: true },
    200,
    {
      "Set-Cookie":
        `${COOKIE}=${token}; ` +
        `Path=/; ` +
        `Max-Age=${SESSION_DAYS * 86400}; ` +
        `HttpOnly; ` +
        `Secure; ` +
        `SameSite=Strict`
    }
  );
}


// ================================
// AUTH
// ================================

async function auth(request, env) {
  const token = cookie(
    request,
    COOKIE
  );

  if (!token) {
    return null;
  }

  const hash =
    await sha256(token);

  const now =
    Math.floor(Date.now() / 1000);

  return await env.DB
    .prepare(
      `SELECT
        admins.id,
        admins.username
       FROM sessions
       JOIN admins
         ON admins.id = sessions.admin_id
       WHERE
         sessions.token_hash = ?
         AND sessions.expires_at > ?`
    )
    .bind(
      hash,
      now
    )
    .first();
}


// ================================
// LOGOUT
// ================================

async function logout(request, env) {
  const token =
    cookie(request, COOKIE);

  if (token) {
    const hash =
      await sha256(token);

    await env.DB
      .prepare(
        `DELETE FROM sessions
         WHERE token_hash = ?`
      )
      .bind(hash)
      .run();
  }

  return json(
    { ok: true },
    200,
    {
      "Set-Cookie":
        `${COOKIE}=; ` +
        `Path=/; ` +
        `Max-Age=0; ` +
        `HttpOnly; ` +
        `Secure; ` +
        `SameSite=Strict`
    }
  );
}


// ================================
// SESSION CHECK
// ================================

async function me(request, env) {
  const user =
    await auth(request, env);

  if (!user) {
    return json(
      { ok: false },
      401
    );
  }

  return json({
    ok: true,
    username: user.username
  });
}


// ================================
// SETTINGS
// ================================

async function settings(env) {
  const rows =
    await env.DB
      .prepare(
        `SELECT key, value
         FROM settings`
      )
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


async function updateSettings(
  request,
  env
) {
  const body =
    await request.json();

  for (
    const [key, value]
    of Object.entries(body)
  ) {
    await env.DB
      .prepare(
        `INSERT INTO settings
         (key, value)
         VALUES (?, ?)
         ON CONFLICT(key)
         DO UPDATE SET
         value = excluded.value`
      )
      .bind(
        key,
        String(value ?? "")
      )
      .run();
  }

  return settings(env);
}


// ================================
// POSTS
// ================================

async function posts(env) {
  const result =
    await env.DB
      .prepare(
        `SELECT *
         FROM posts
         ORDER BY created_at DESC`
      )
      .all();

  return json(
    result.results
  );
}


async function createPost(
  request,
  env
) {
  const body =
    await request.json();

  if (!body.title) {
    return json(
      {
        error:
          "Başlık gerekli."
      },
      400
    );
  }

  await env.DB
    .prepare(
      `INSERT INTO posts
       (
         title,
         version,
         status,
         description,
         link,
         created_at
       )
       VALUES (?, ?, ?, ?, ?, ?)`
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


async function deletePost(
  id,
  env
) {
  await env.DB
    .prepare(
      `DELETE FROM posts
       WHERE id = ?`
    )
    .bind(id)
    .run();

  return posts(env);
}


// ================================
// SHA256
// ================================

async function sha256(text) {
  const buffer =
    await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(text)
    );

  return [
    ...new Uint8Array(buffer)
  ]
    .map(
      value =>
        value
          .toString(16)
          .padStart(2, "0")
    )
    .join("");
}


// ================================
// COOKIE
// ================================

function cookie(
  request,
  name
) {
  const header =
    request.headers.get("Cookie") ||
    "";

  const parts =
    header
      .split(";")
      .map(x => x.trim());

  for (const part of parts) {
    const index =
      part.indexOf("=");

    if (index === -1) {
      continue;
    }

    const key =
      part.slice(0, index);

    const value =
      part.slice(index + 1);

    if (key === name) {
      return value;
    }
  }

  return null;
}


// ================================
// JSON RESPONSE
// ================================

function json(
  data,
  status = 200,
  extra = {}
) {
  return new Response(
    JSON.stringify(data),
    {
      status,
      headers: {
        "content-type":
          "application/json; charset=UTF-8",
        "cache-control":
          "no-store",
        ...extra
      }
    }
  );
}


// ================================
// ANA SAYFA
// ================================

function page() {
  return new Response(
`<!doctype html>
<html lang="tr">

<head>

<meta charset="UTF-8">

<meta
  name="viewport"
  content="width=device-width,
           initial-scale=1,
           maximum-scale=1,
           viewport-fit=cover">

<title>YargiConfig</title>

<style>

* {
  box-sizing: border-box;
}

html,
body {
  margin: 0;
  padding: 0;
  width: 100%;
  min-height: 100%;
  background: #000;
  overflow-x: hidden;
}

body {
  display: flex;
  justify-content: center;
  align-items: flex-start;
}

.wrap {
  position: relative;
  width: 100%;
  max-width: 1600px;
  margin: 0 auto;
}

.wrap img {
  display: block;
  width: 100%;
  height: auto;
  max-width: 100%;
}

/*
   TELEFON
*/

@media (max-width: 600px) {

  body {
    display: block;
  }

  .wrap {
    width: 100vw;
    max-width: none;
  }

  .wrap img {
    width: 100vw;
    height: auto;
  }

}


/*
   TABLET
*/

@media
(min-width: 601px)
and
(max-width: 1100px) {

  .wrap {
    width: 100%;
  }

  .wrap img {
    width: 100%;
    height: auto;
  }

}


/*
   PC
*/

@media (min-width: 1101px) {

  .wrap {
    width: 100%;
    max-width: 1600px;
  }

  .wrap img {
    width: 100%;
    height: auto;
  }

}


/*
   TELEGRAM BUTONU
*/

.telegram {
  position: absolute;

  left: 4.1%;
  top: 67.2%;

  width: 21.5%;
  height: 5.5%;

  display: block;

  border-radius: 18px;

  text-decoration: none;

  z-index: 10;
}


/*
   TABLET TELEGRAM
*/

@media
(min-width: 601px)
and
(max-width: 1100px) {

  .telegram {
    left: 4%;
    top: 67%;
    width: 25%;
    height: 6%;
  }

}


/*
   TELEFON TELEGRAM
*/

@media (max-width: 600px) {

  .telegram {
    left: 4%;
    top: 67%;
    width: 30%;
    height: 7%;
  }

}


/*
   KÜÇÜK TELEFON
*/

@media (max-width: 400px) {

  .telegram {
    width: 32%;
  }

}

</style>

</head>

<body>

<div class="wrap">

  <img
    src="/site.png"
    alt="YargiConfig">

  <a
    class="telegram"
    href="https://t.me/ioscedrixddconfig"
    target="_blank"
    rel="noopener noreferrer"
    aria-label="Telegram">

  </a>

</div>

</body>

</html>`,
    {
      headers: {
        "content-type":
          "text/html; charset=UTF-8",
        "cache-control":
          "no-cache"
      }
    }
  );
}


// ================================
// ADMIN PANEL
// ================================

function panel() {
  return new Response(
    PANEL,
    {
      headers: {
        "content-type":
          "text/html; charset=UTF-8",
        "cache-control":
          "no-store"
      }
    }
  );
}


const PANEL =
`<!doctype html>

<html lang="tr">

<head>

<meta charset="UTF-8">

<meta
  name="viewport"
  content="width=device-width,
           initial-scale=1,
           maximum-scale=1,
           viewport-fit=cover">

<title>YargiConfig Admin</title>

<style>

* {
  box-sizing: border-box;
}

html,
body {
  margin: 0;
  padding: 0;
  width: 100%;
  min-height: 100%;
}

body {
  background: #03070b;
  color: #eaf3ff;
  font-family:
    Arial,
    Helvetica,
    sans-serif;
}

.wrap {
  width: 100%;
  max-width: 1100px;
  margin: auto;
  padding: 25px;
}

.card {
  background: #08121b;
  border: 1px solid #1b3548;
  border-radius: 16px;
  padding: 22px;
  margin-bottom: 18px;
  box-shadow:
    0 15px 45px #0008;
}

h1 {
  margin: 0 0 5px;
}

h2 {
  font-size: 18px;
}

.blue {
  color: #0792ff;
}

input,
textarea,
select {
  width: 100%;
  padding: 13px;
  margin: 6px 0 12px;

  background: #03090e;
  color: #fff;

  border:
    1px solid #263d4d;

  border-radius: 9px;

  font-size: 16px;

  outline: none;
}

input:focus,
textarea:focus,
select:focus {
  border-color: #0792ff;
}

textarea {
  min-height: 120px;
  resize: vertical;
}

button {
  padding: 12px 17px;

  border: 0;
  border-radius: 9px;

  background: #078cff;
  color: #fff;

  font-weight: 800;
  font-size: 15px;

  cursor: pointer;
}

button:hover {
  filter: brightness(1.1);
}

.danger {
  background: #b52b45;
}

.muted {
  color: #8495a7;
}

.grid {
  display: grid;
  grid-template-columns:
    repeat(3, 1fr);
  gap: 14px;
}

.stat {
  padding: 17px;

  border:
    1px solid #193044;

  border-radius: 12px;

  background: #061018;
}

.stat b {
  display: block;

  color: #0792ff;

  font-size: 24px;

  margin-bottom: 4px;
}

.hidden {
  display: none !important;
}

.post {
  padding: 14px 0;

  border-top:
    1px solid #18303e;

  display: flex;

  gap: 12px;

  align-items: center;
}

.post-content {
  flex: 1;
}

.error {
  color: #ff6680;
}

.success {
  color: #55dd99;
}


/*
   TELEFON
*/

@media (max-width: 700px) {

  .wrap {
    padding: 12px;
  }

  .card {
    padding: 18px;
    border-radius: 14px;
  }

  .grid {
    grid-template-columns: 1fr;
  }

  .post {
    align-items: flex-start;
  }

}

</style>

</head>

<body>

<div class="wrap">

  <!-- LOGIN -->

  <div
    id="login"
    class="card">

    <h1>
      ♛ YARGI
      <span class="blue">
        CONFIG
      </span>
    </h1>

    <p class="muted">
      Admin Paneli
    </p>

    <input
      id="u"
      placeholder="Kullanıcı adı"
      autocomplete="username">

    <input
      id="p"
      type="password"
      placeholder="Şifre"
      autocomplete="current-password">

    <button
      onclick="login()">

      Giriş Yap

    </button>

    <p id="err"></p>

  </div>


  <!-- ADMIN -->

  <div
    id="app"
    class="hidden">

    <div class="card">

      <h1>
        ♛ YARGI
        <span class="blue">
          CONFIG
        </span>
      </h1>

      <p class="muted">
        Yönetim Paneli
      </p>

      <button
        class="danger"
        onclick="logout()">

        Çıkış Yap

      </button>

    </div>


    <!-- STATS -->

    <div class="grid">

      <div class="stat">

        <b id="pc">
          0
        </b>

        Paylaşım

      </div>


      <div class="stat">

        <b>
          4.6
        </b>

        Site sürümü

      </div>


      <div class="stat">

        <b>
          ●
        </b>

        Sistem aktif

      </div>

    </div>


    <!-- NEW POST -->

    <div class="card">

      <h2>
        📰 Yeni Paylaşım
      </h2>

      <input
        id="title"
        placeholder="Başlık">

      <input
        id="version"
        placeholder="Sürüm (örn. 4.6)">

      <select id="status">

        <option>
          Yeni
        </option>

        <option>
          Güncel
        </option>

        <option>
          Taslak
        </option>

        <option>
          Yayınlandı
        </option>

      </select>

      <textarea
        id="desc"
        placeholder="Açıklama"></textarea>

      <input
        id="link"
        placeholder="Telegram / indirme bağlantısı">

      <button
        onclick="addPost()">

        Yayınla

      </button>

      <p
        id="postMessage">
      </p>

    </div>


    <!-- POSTS -->

    <div class="card">

      <h2>
        📋 Paylaşımlar
      </h2>

      <div id="posts">
      </div>

    </div>


    <!-- SETTINGS -->

    <div class="card">

      <h2>
        🏠 Ana Sayfa Ayarları
      </h2>

      <input
        id="hero"
        placeholder="Hero başlığı">

      <input
        id="telegram"
        placeholder="Telegram bağlantısı">

      <input
        id="members"
        placeholder="Aktif üye sayısı">

      <input
        id="shares"
        placeholder="Paylaşım sayısı">

      <button
        onclick="saveSettings()">

        Kaydet

      </button>

      <p
        id="settingsMessage">
      </p>

    </div>

  </div>

</div>


<script>

async function api(
  url,
  options = {}
) {

  const response =
    await fetch(
      url,
      {
        credentials:
          "same-origin",
        ...options
      }
    );

  let data = {};

  try {
    data =
      await response.json();
  } catch {}

  if (!response.ok) {
    throw new Error(
      data.error ||
      "İşlem başarısız."
    );
  }

  return data;
}


// ================================
// BOOT
// ================================

async function boot() {

  try {

    await api(
      "/api/me"
    );

    show();

  } catch {

    loginBox
      .classList
      .remove("hidden");

    app
      .classList
      .add("hidden");

  }

}


// ================================
// SHOW
// ================================

function show() {

  loginBox
    .classList
    .add("hidden");

  app
    .classList
    .remove("hidden");

  load();

}


// ================================
// LOGIN
// ================================

async function login() {

  err.textContent =
    "Giriş yapılıyor...";

  try {

    await api(
      "/api/login",
      {
        method:
          "POST",

        headers: {
          "content-type":
            "application/json"
        },

        body:
          JSON.stringify({
            username:
              u.value,

            password:
              p.value
          })
      }
    );

    err.textContent = "";

    show();

  } catch (error) {

    err.textContent =
      error.message;

    err.className =
      "error";

  }

}


// ================================
// LOGOUT
// ================================

async function logout() {

  await api(
    "/api/logout",
    {
      method:
        "POST"
    }
  );

  location.reload();

}


// ================================
// LOAD
// ================================

async function load() {

  try {

    const postData =
      await api(
        "/api/posts"
      );

    pc.textContent =
      postData.length;

    posts.innerHTML =
      postData
        .map(
          post =>
            '<div class="post">' +

              '<div class="post-content">' +

                '<b>' +
                esc(
                  post.title
                ) +
                '</b>' +

                '<small class="muted">' +
                ' ' +
                esc(
                  post.version || ""
                ) +
                ' · ' +
                esc(
                  post.status || ""
                ) +
                '</small>' +

              '</div>' +

              '<button ' +
              'class="danger" ' +
              'onclick="del(' +
              post.id +
              ')">' +

              'Sil' +

              '</button>' +

            '</div>'
        )
        .join("") ||

      '<span class="muted">' +
      'Henüz paylaşım yok.' +
      '</span>';


    const settingsData =
      await api(
        "/api/settings"
      );

    hero.value =
      settingsData.hero || "";

    telegram.value =
      settingsData.telegram ||
      "https://t.me/ioscedrixddconfig";

    members.value =
      settingsData.members || "";

    shares.value =
      settingsData.shares || "";

  } catch (error) {

    console.error(error);

  }

}


// ================================
// ADD POST
// ================================

async function addPost() {

  try {

    await api(
      "/api/posts",
      {
        method:
          "POST",

        headers: {
          "content-type":
            "application/json"
        },

        body:
          JSON.stringify({

            title:
              title.value,

            version:
              version.value,

            status:
              status.value,

            description:
              desc.value,

            link:
              link.value

          })
      }
    );

    title.value = "";
    version.value = "";
    desc.value = "";
    link.value = "";

    postMessage.textContent =
      "Paylaşım başarıyla eklendi.";

    postMessage.className =
      "success";

    load();

  } catch (error) {

    postMessage.textContent =
      error.message;

    postMessage.className =
      "error";

  }

}


// ================================
// DELETE POST
// ================================

async function del(id) {

  if (
    !confirm(
      "Bu paylaşım silinsin mi?"
    )
  ) {
    return;
  }

  try {

    await api(
      "/api/posts/" + id,
      {
        method:
          "DELETE"
      }
    );

    load();

  } catch (error) {

    alert(
      error.message
    );

  }

}


// ================================
// SAVE SETTINGS
// ================================

async function saveSettings() {

  try {

    await api(
      "/api/settings",
      {
        method:
          "PUT",

        headers: {
          "content-type":
            "application/json"
        },

        body:
          JSON.stringify({

            hero:
              hero.value,

            telegram:
              telegram.value,

            members:
              members.value,

            shares:
              shares.value

          })
      }
    );

    settingsMessage.textContent =
      "Ayarlar başarıyla kaydedildi.";

    settingsMessage.className =
      "success";

  } catch (error) {

    settingsMessage.textContent =
      error.message;

    settingsMessage.className =
      "error";

  }

}


// ================================
// ESCAPE HTML
// ================================

function esc(value) {

  return String(
    value || ""
  )
    .replace(
      /[&<>"']/g,
      function(character) {

        return {
          "&":
            "&amp;",

          "<":
            "&lt;",

          ">":
            "&gt;",

          '"':
            "&quot;",

          "'":
            "&#39;"

        }[character];

      }
    );

}


// ================================
// START
// ================================

const loginBox =
  document.getElementById(
    "login"
  );

const app =
  document.getElementById(
    "app"
  );

const u =
  document.getElementById(
    "u"
  );

const p =
  document.getElementById(
    "p"
  );

const err =
  document.getElementById(
    "err"
  );

const pc =
  document.getElementById(
    "pc"
  );

const posts =
  document.getElementById(
    "posts"
  );

const title =
  document.getElementById(
    "title"
  );

const version =
  document.getElementById(
    "version"
  );

const status =
  document.getElementById(
    "status"
  );

const desc =
  document.getElementById(
    "desc"
  );

const link =
  document.getElementById(
    "link"
  );

const hero =
  document.getElementById(
    "hero"
  );

const telegram =
  document.getElementById(
    "telegram"
  );

const members =
  document.getElementById(
    "members"
  );

const shares =
  document.getElementById(
    "shares"
  );

const postMessage =
  document.getElementById(
    "postMessage"
  );

const settingsMessage =
  document.getElementById(
    "settingsMessage"
  );


boot();

</script>

</body>

</html>`; 
