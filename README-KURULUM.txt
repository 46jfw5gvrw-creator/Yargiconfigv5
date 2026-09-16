YARGI CONFIG V5 - CLOUDFLARE WORKER + D1

Proje yapısı:
- src/index.js  -> Worker + /panel
- public/site.png -> ana sayfa görseli
- wrangler.toml -> D1 ve Assets ayarları

D1:
Database: yargiconfig-db
ID: 42ac5bb9-3a7e-45e8-b6df-d3539ae0a8bb
Binding: DB

Kurulum:
1) Bu klasörü GitHub'a yükle.
2) Cloudflare Workers & Pages -> Create -> Import repository ile bağla.
3) Build command gerekmez; deploy komutu: npx wrangler deploy
4) D1 binding wrangler.toml'dan gelir.
5) Ana domaini deployment tamamen çalıştıktan sonra bu Worker'a bağla.

NOT: Admin kullanıcısı ve tablolar daha önce oluşturulduysa tekrar oluşturma.
