import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { parseTarget } from './ssrf.js';
import { fetchWithRedirects, checkHttpRedirect, friendlyNetworkError } from './fetcher.js';
import { gradeSite } from './grader.js';

const PORT = Number(process.env.PORT) || 4000;
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
app.disable('x-powered-by');
// Behind Nginx / a hosting proxy, trust one hop so rate limiting sees the real IP.
app.set('trust proxy', Number(process.env.TRUST_PROXY ?? 1));

// Practise what we preach: this app sends every header it checks for.
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", 'https://fonts.googleapis.com'],
        fontSrc: ["'self'", 'https://fonts.gstatic.com'],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        frameAncestors: ["'none'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
      },
    },
    strictTransportSecurity: { maxAge: 31536000, includeSubDomains: true },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  }),
);
app.use((req, res, next) => {
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});
app.use(express.json({ limit: '4kb' }));

// Stops the checker from being used to hammer other people's websites.
const scanLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many checks. Please wait a minute and try again.' },
});

app.post('/api/scan', scanLimiter, async (req, res) => {
  const { url: input, consent } = req.body ?? {};
  if (consent !== true) {
    return res.status(400).json({ error: 'Please confirm you own this website or have permission to check it.' });
  }

  let target;
  try {
    target = parseTarget(input);
  } catch (err) {
    return res.status(400).json({ error: err.expose ? err.message : 'Invalid address.' });
  }

  try {
    const [page, httpRedirect] = await Promise.all([
      fetchWithRedirects(target),
      checkHttpRedirect(target.hostname),
    ]);
    const result = gradeSite({ finalUrl: page.finalUrl, headers: page.headers, cert: page.cert, httpRedirect });
    console.log(`[scan] ${target.hostname} -> ${result.grade} (${result.score})`);
    return res.json({
      target: target.hostname,
      finalUrl: page.finalUrl.href,
      redirects: page.chain,
      status: page.status,
      certificate: page.cert,
      scannedAt: new Date().toISOString(),
      ...result,
    });
  } catch (err) {
    console.warn(`[scan] ${target.hostname} failed: ${err.code || err.message}`);
    return res.status(502).json({ error: friendlyNetworkError(err) });
  }
});

app.get('/api/health', (req, res) => res.json({ ok: true }));

// Serve the built React app (created by `npm run build` in ./dist).
const clientDist = path.resolve(__dirname, 'dist');
app.use(express.static(clientDist));
app.get(/^(?!\/api\/).*/, (req, res, next) => {
  res.sendFile(path.join(clientDist, 'index.html'), (err) => err && next());
});

app.listen(PORT, () => console.log(`Noxora scanner API listening on http://localhost:${PORT}`));
