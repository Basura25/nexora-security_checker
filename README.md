# Noxora Lab · Website Security Checker

A free tool that checks a website's HTTPS, SSL certificate and security headers, and gives it an A+ to F grade with plain-English fixes.

All files sit in one folder: Node.js + Express backend (`index.js`, `ssrf.js`, `fetcher.js`, `grader.js`) and React frontend (`index.html`, `main.jsx`, `App.jsx`, `styles.css`).

## Deploy on Render (free)

- **Build Command:** `npm install && npm run build`
- **Start Command:** `npm start`
- **Instance Type:** Free

## Run on your computer

```bash
npm install
npm run build
npm start          # open http://localhost:4000
```

While editing the design, run `npm run dev:server` in one terminal and `npm run dev` in another, then open http://localhost:5173.

Tests: `npm test`

Before going live, change `CONTACT_URL` at the top of `App.jsx` to your contact page, WhatsApp link or email.

## How the tool protects itself

- Blocks SSRF: only http/https on ports 80/443, domain names only, private/loopback/cloud-metadata IPs blocked at connect time, every redirect re-checked
- 8-second timeout, never downloads the page body
- 5 checks per minute per IP
- Visitor must confirm they own the site or have permission
- Sends every security header it checks for

This tool makes one normal request, the same as opening the site in a browser. It does not test for vulnerabilities.
