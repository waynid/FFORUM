<h1 align="center">FFORUM – Lightweight PHP Forum</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Language-PHP-blue.svg" alt="PHP Badge">
  <img src="https://img.shields.io/badge/Database-SQLite-lightgrey.svg" alt="SQLite Badge">
  <img src="https://img.shields.io/badge/No%20Dependencies-100%25-green.svg" alt="Dependencies Badge">
</p>

<p align="center">
  A minimal, self-contained forum system built in raw PHP using SQLite.<br>
  No frameworks. No packages. Just one file.
</p>

---

## 🚀 Quick Setup

```bash
1. Place index.php in your server's web root
2. Open it in your browser
3. It auto-creates:
   - SQLite database (data.db)
   - Admin credentials file (founder.txt)
4. Log in with the credentials from founder.txt
5. Delete founder.txt immediately
```

---

## 📁 File Overview

```
fforum/
├── index.php       # Core application
├── data.db         # SQLite database (auto-created)
├── founder.txt     # Admin credentials (generated once)
└── .htaccess       # Optional security file for database
```

---

<details>
<summary><strong>💡 Features</strong></summary>

- 🧑 Admin and user login system  
- 🧾 Comment threads and forums  
- 🖼️ Base64 image storage (no /uploads folder)  
- 🔐 User banning and admin panel  
- 🪄 Random password for the founder  
- 📦 SQLite backend, initialized automatically  
- 🧩 No external libraries or packages  

</details>

---

<details>
<summary><strong>🔐 First Launch & Security</strong></summary>

- On first visit, the app generates:
  - `data.db` — SQLite database
  - `founder.txt` — admin credentials

Example `founder.txt`:

```
Username: founder
Password: XyZ98pq1LmN
```

> Delete `founder.txt` after your first login.

You can add a `.htaccess` file to restrict database access on Apache servers:

```apache
<Files "data.db">
  Order Deny,Allow
  Deny from all
</Files>
```

</details>

---

<details>
<summary><strong>📊 Database Overview</strong></summary>

| Table     | Purpose                              |
|-----------|--------------------------------------|
| `users`   | Stores user data and base64 avatars  |
| `forums`  | Forum threads with optional images   |
| `comments`| Replies to threads, linked by ID     |

</details>

---

## 🤝 Contributing

Found a bug? Have an idea?

- 🐛 [Open an issue](https://github.com/waynid/fforum/issues)
- 🔧 Pull requests are welcome

> Contributions that improve security, structure, or performance are appreciated.

---

<p align="center">
  <img src="https://www.php.net/images/logos/php-logo.svg" height="40px" alt="PHP Logo" />
  <img src="https://upload.wikimedia.org/wikipedia/commons/9/97/Sqlite-square-icon.svg" height="40px" alt="SQLite Logo" />
</p>

<p align="center">
  <sub>FFORUM is free to use, modify, and deploy. Keep it simple. Keep it fast.</sub>
</p>
