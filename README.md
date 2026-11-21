# RUDY CP REWARDS — Version 2.0

A Node.js + Express + SQLite community rewards campaign platform with player accounts, claim tracking, and a separate administrator dashboard.

## Included
- Responsive public website (`/`)
- Player registration, sign-in, sign-out, and claim history
- Password hashing with bcrypt
- SQLite persistence for users, campaigns, claims, and sessions
- CSRF token checks for state-changing API requests
- Rate-limited authentication endpoints
- Admin dashboard (`/admin.html`)
- Admin claim approval/rejection with notes
- Admin campaign creation and pause/activate controls
- Admin account disable/enable controls
- Helmet security headers

## Run locally
Requires Node.js 20 or newer.

1. Extract the ZIP.
2. Copy `.env.example` to `.env`.
3. Set a unique `ADMIN_PASSWORD` (at least 12 characters) and a random `SESSION_SECRET` (at least 32 characters).
4. Install dependencies: `npm install`
5. Start: `npm start`
6. Open `http://localhost:3000`
7. Open `http://localhost:3000/admin.html` for the admin dashboard.

The first account is not automatically an administrator. Admin login uses the credentials configured in `.env`; create the admin account once using the bootstrap instructions below.

## Create the first administrator
For safety, the app does not expose public admin registration. After starting the server once, stop it and run:

```bash
node -e "require('dotenv').config(); const Database=require('better-sqlite3'); const bcrypt=require('bcryptjs'); const db=new Database('./data/rudy.sqlite'); const username=process.env.ADMIN_USERNAME||'admin'; const email='admin@localhost.invalid'; const hash=bcrypt.hashSync(process.env.ADMIN_PASSWORD,12); db.prepare(\"INSERT OR IGNORE INTO users(username,email,password_hash,role) VALUES(?,?,?,'admin')\").run(username,email,hash); console.log('Admin account ready:',username);"
```

Then restart `npm start` and sign in at `/` with the admin username and configured password. Visit `/admin.html`.

## Production checklist
- Deploy behind HTTPS. Set `NODE_ENV=production`.
- Set a long random `SESSION_SECRET` and strong unique admin password.
- Use a persistent disk/volume for `data/`; SQLite data must survive restarts.
- Configure backups, monitoring, log retention, and database access controls.
- Add email verification, password reset, privacy policy, terms, data retention and deletion workflows before public launch.
- Consider managed PostgreSQL and a managed session store for multi-instance hosting.
- Review rate limits, abuse controls, and applicable privacy/data-protection laws.
- Never collect Activision passwords, OTPs, payment PINs, or recovery codes.

## Important reward limitation
This software manages campaigns and claims only. It does not generate, mint, transfer, sell, or redeem COD Points. An administrator marking a claim “approved” means only that the claim passed this website's review. Any actual prize must be fulfilled through a legitimate authorized Activision/Call of Duty distribution or redemption method. This is an independent community project and is not affiliated with Activision or Call of Duty.
