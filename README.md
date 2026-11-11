# SecurePass – One Command Edition

Password breach + strength checker (Express + React + MongoDB, all in one process).

## Run

```bash
npm install     # first time only
npm run dev     # every time
```

Open http://localhost:5000

- Frontend and backend both run on port 5000 (Vite runs inside the Express server).
- MongoDB (`mongodb://127.0.0.1:27017/pwndpass`) is optional: if it is not running, scan history is kept in memory and the app does not crash.
- To change settings, set env vars: `PORT`, `MONGO_URI`.

## API

- `POST /api/password/check` body `{ "password": "..." }`
- `GET /api/scans/history`
- `GET /api/scans/stats`
- `GET /api/health`

## Privacy

Only the first 5 characters of the SHA-1 hash go to Have I Been Pwned (k-anonymity). Passwords and hashes are never stored or logged; only breach count, strength score and timestamp are saved.
