// Fetches a page the same way a browser would, and records the response headers,
// the redirect chain and the TLS certificate. Nothing is attacked or probed:
// it is one ordinary GET request per hop, the same as opening the site.

import http from 'node:http';
import https from 'node:https';
import { parseTarget, safeLookup, UserError } from './ssrf.js';

const MAX_REDIRECTS = 5;
const TIMEOUT_MS = 8000;
const USER_AGENT = 'NoxoraLab-SecurityChecker/1.0 (+https://noxoralab.com/tools/header-check)';

function requestOnce(url) {
  return new Promise((resolve, reject) => {
    const lib = url.protocol === 'https:' ? https : http;
    const req = lib.request(
      url,
      {
        method: 'GET',
        lookup: safeLookup,
        timeout: TIMEOUT_MS,
        headers: { 'User-Agent': USER_AGENT, Accept: 'text/html,*/*' },
        // We still want to report on sites with broken certificates, so we
        // don't reject here; we read `socket.authorized` and report it instead.
        rejectUnauthorized: false,
        agent: false,
      },
      (res) => {
        let cert = null;
        if (url.protocol === 'https:') {
          const s = res.socket;
          const peer = s.getPeerCertificate?.();
          cert = {
            authorized: s.authorized === true,
            authorizationError: s.authorizationError ? String(s.authorizationError) : null,
            validFrom: peer?.valid_from ?? null,
            validTo: peer?.valid_to ?? null,
            issuer: peer?.issuer?.O ?? peer?.issuer?.CN ?? null,
            subject: peer?.subject?.CN ?? null,
            protocol: s.getProtocol?.() ?? null,
          };
        }
        // We only need headers. Drop the body so big pages don't cost memory.
        res.resume();
        resolve({ status: res.statusCode, headers: res.headers, cert });
      },
    );
    req.on('timeout', () => req.destroy(new UserError('The website took too long to respond.')));
    req.on('error', reject);
    req.end();
  });
}

// Follow redirects ourselves so every hop goes through the same SSRF checks.
export async function fetchWithRedirects(startUrl) {
  const chain = [];
  let url = startUrl;
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    const res = await requestOnce(url);
    chain.push({ url: url.href, status: res.status });
    const loc = res.headers.location;
    if (res.status >= 300 && res.status < 400 && loc) {
      url = parseTarget(new URL(loc, url).href);
      continue;
    }
    return { finalUrl: url, chain, ...res };
  }
  throw new UserError('The website redirected too many times.');
}

// Does plain http:// send visitors on to https://?
export async function checkHttpRedirect(hostname) {
  try {
    const res = await requestOnce(new URL(`http://${hostname}/`));
    const loc = res.headers.location ?? '';
    const redirectsToHttps = res.status >= 300 && res.status < 400 && /^https:\/\//i.test(new URL(loc, `http://${hostname}/`).href);
    return { reachable: true, redirectsToHttps };
  } catch {
    return { reachable: false, redirectsToHttps: false };
  }
}

export function friendlyNetworkError(err) {
  if (err?.expose) return err.message;
  switch (err?.code) {
    case 'ENOTFOUND':
    case 'EAI_AGAIN':
      return 'We could not find that domain. Check the spelling and try again.';
    case 'ECONNREFUSED':
      return 'The website refused the connection.';
    case 'ECONNRESET':
      return 'The website closed the connection unexpectedly.';
    default:
      return 'We could not reach that website.';
  }
}
