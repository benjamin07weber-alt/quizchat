QUIZCHAT v1 — Cloudflare Pages + D1

1. Create a NEW Cloudflare D1 database called quizchat-db (do not reuse Quizforce's DB).
2. In D1 Console, execute the contents of schema.sql to create tables.
3. Create a Cloudflare Pages project and deploy this folder through a GitHub repository. Set build command blank, output directory /.
4. In Pages > Settings > Bindings, add D1 database binding named exactly DB, select quizchat-db.
5. Redeploy the Pages project so Functions receive the binding.
6. Open the Pages domain in two different devices and register two different nicknames; search and send a message.

Security notes: Nicknames are unique in D1; passwords use salted PBKDF2; bearer sessions expire after 30 days. This is a starter, not production-hardened. Add rate limits, abuse reporting/blocking, stronger auth/recovery, privacy controls, end-to-end encryption, and security review before public launch. Chats are stored as readable text in the database. No online status, typing indicators, push notifications, or installable PWA yet.
