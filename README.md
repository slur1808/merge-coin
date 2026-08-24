# Merge Coin — Ready-to-Deploy MVP

## Included
- Mobile-first Merge game UI
- Account registration/login with bcrypt password hashing
- JWT session (7 days)
- Persistent SQLite database (WAL)
- Referral code and one-time referral reward
- Daily reward
- Server-side energy/XP/coin updates for core actions
- Leaderboard
- Basic HTTP security headers
- Global rate limit
- Health endpoint
- Transactional referral creation
- Event audit table

## Run
Requirements: Node.js 18+.

```bash
npm install
JWT_SECRET="put-a-long-random-secret-here" npm start
```

Windows PowerShell:
```powershell
$env:JWT_SECRET="put-a-long-random-secret-here"; npm start
```

Open http://localhost:3000

## Production checklist
1. Set a strong secret in the hosting provider's environment variables.
2. Use HTTPS.
3. Put the SQLite DB on persistent storage, or migrate to PostgreSQL.
4. Add CAPTCHA/email/phone verification if referral abuse becomes a problem.
5. Add per-IP/device/account limits and monitoring before public launch.
6. Replace simulated ad UI with a real ad SDK only after the game loop is tested.
7. Never promise cash withdrawal from in-game coins unless you build the required legal/compliance/payment system.
8. Back up the database.

## API
POST /api/register
POST /api/login
GET /api/me
POST /api/game/spawn
POST /api/game/merge
POST /api/daily
GET /api/leaderboard
GET /api/health
