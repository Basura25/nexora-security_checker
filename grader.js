// Turns raw headers + certificate info into a list of checks and an A+–F grade.
// Pure functions, no network: easy to unit test.

const SIX_MONTHS = 15552000;

const pass = (id, title, detail, weight) => ({ id, title, status: 'pass', detail, weight, lost: 0 });
const warn = (id, title, detail, weight, lost, fix) => ({ id, title, status: 'warn', detail, weight, lost, fix });
const fail = (id, title, detail, weight, fix) => ({ id, title, status: 'fail', detail, weight, lost: weight, fix });

function daysUntil(dateStr, now) {
  const t = Date.parse(dateStr);
  if (Number.isNaN(t)) return null;
  return Math.floor((t - now) / 86400000);
}

export function gradeSite({ finalUrl, headers, cert, httpRedirect, now = Date.now() }) {
  const h = Object.fromEntries(Object.entries(headers || {}).map(([k, v]) => [k.toLowerCase(), v]));
  const isHttps = finalUrl.protocol === 'https:';
  const checks = [];

  // 1. HTTPS
  if (isHttps && cert?.authorized) {
    checks.push(pass('https', 'HTTPS', 'The site loads over HTTPS with a trusted certificate.', 20));
  } else if (isHttps) {
    checks.push(fail('https', 'HTTPS', `The site uses HTTPS but the certificate is not trusted (${cert?.authorizationError || 'unknown error'}).`, 20,
      'Install a valid certificate from a trusted authority. Let\'s Encrypt is free.'));
  } else {
    checks.push(fail('https', 'HTTPS', 'The site does not use HTTPS. Data is sent in plain text.', 20,
      'Install an SSL/TLS certificate and serve every page over HTTPS.'));
  }

  // 2. HTTP -> HTTPS redirect
  if (httpRedirect?.redirectsToHttps) {
    checks.push(pass('redirect', 'HTTP to HTTPS redirect', 'Visitors who type http:// are sent to the secure version.', 5));
  } else if (httpRedirect?.reachable === false && isHttps) {
    checks.push(pass('redirect', 'HTTP to HTTPS redirect', 'Plain HTTP is not served at all.', 5));
  } else {
    checks.push(fail('redirect', 'HTTP to HTTPS redirect', 'The http:// version does not redirect to https://.', 5,
      'Add a permanent (301) redirect from http:// to https:// on your server.'));
  }

  // 3. Certificate expiry
  if (isHttps && cert?.validTo) {
    const days = daysUntil(cert.validTo, now);
    if (days === null) {
      checks.push(warn('cert', 'Certificate expiry', 'Could not read the certificate expiry date.', 5, 2));
    } else if (days < 0) {
      checks.push(fail('cert', 'Certificate expiry', `The certificate expired ${-days} days ago.`, 5, 'Renew the certificate now.'));
    } else if (days < 14) {
      checks.push(warn('cert', 'Certificate expiry', `The certificate expires in ${days} days.`, 5, 3, 'Renew soon, or turn on automatic renewal.'));
    } else {
      checks.push(pass('cert', 'Certificate expiry', `Valid for another ${days} days${cert.issuer ? ` (issued by ${cert.issuer})` : ''}.`, 5));
    }
  }

  // 4. HSTS
  const hsts = h['strict-transport-security'];
  if (!isHttps) {
    checks.push(fail('hsts', 'Strict-Transport-Security', 'Not possible without HTTPS.', 15, 'Enable HTTPS first, then add HSTS.'));
  } else if (!hsts) {
    checks.push(fail('hsts', 'Strict-Transport-Security', 'Missing. Browsers may still try the insecure http:// version.', 15,
      'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains'));
  } else {
    const m = /max-age=(\d+)/i.exec(hsts);
    const age = m ? Number(m[1]) : 0;
    if (age >= SIX_MONTHS) checks.push(pass('hsts', 'Strict-Transport-Security', `Set (${hsts}).`, 15));
    else checks.push(warn('hsts', 'Strict-Transport-Security', `Set, but max-age is short (${age} seconds).`, 15, 7,
      'Use max-age of at least 15552000 (6 months); 31536000 (1 year) is common.'));
  }

  // 5. Content-Security-Policy
  const csp = h['content-security-policy'];
  if (!csp) {
    checks.push(fail('csp', 'Content-Security-Policy', 'Missing. Nothing limits which scripts can run on the page.', 20,
      "Start with: Content-Security-Policy: default-src 'self'; then allow the sources your site needs."));
  } else if (/'unsafe-inline'|'unsafe-eval'/.test(csp) && /script-src|default-src/.test(csp)) {
    checks.push(warn('csp', 'Content-Security-Policy', "Set, but allows 'unsafe-inline' or 'unsafe-eval', which weakens XSS protection.", 20, 8,
      "Remove 'unsafe-inline'/'unsafe-eval' and use nonces or hashes for inline scripts."));
  } else {
    checks.push(pass('csp', 'Content-Security-Policy', 'Set.', 20));
  }

  // 6. Clickjacking: X-Frame-Options or CSP frame-ancestors
  const xfo = h['x-frame-options'];
  const frameAncestors = csp && /frame-ancestors/i.test(csp);
  if (frameAncestors || (xfo && /deny|sameorigin/i.test(xfo))) {
    checks.push(pass('frame', 'Clickjacking protection', frameAncestors ? 'Set via CSP frame-ancestors.' : `X-Frame-Options: ${xfo}.`, 10));
  } else {
    checks.push(fail('frame', 'Clickjacking protection', 'Other sites can load this site inside a hidden frame.', 10,
      "Add: X-Frame-Options: SAMEORIGIN (or CSP frame-ancestors 'self')."));
  }

  // 7. X-Content-Type-Options
  if (/nosniff/i.test(h['x-content-type-options'] || '')) {
    checks.push(pass('nosniff', 'X-Content-Type-Options', 'Set to nosniff.', 10));
  } else {
    checks.push(fail('nosniff', 'X-Content-Type-Options', 'Missing. Browsers may guess file types, which attackers can abuse.', 10,
      'Add: X-Content-Type-Options: nosniff'));
  }

  // 8. Referrer-Policy
  if (h['referrer-policy']) {
    checks.push(pass('referrer', 'Referrer-Policy', `Set (${h['referrer-policy']}).`, 5));
  } else {
    checks.push(fail('referrer', 'Referrer-Policy', 'Missing. Full page URLs may leak to other sites.', 5,
      'Add: Referrer-Policy: strict-origin-when-cross-origin'));
  }

  // 9. Permissions-Policy
  if (h['permissions-policy']) {
    checks.push(pass('permissions', 'Permissions-Policy', 'Set.', 5));
  } else {
    checks.push(fail('permissions', 'Permissions-Policy', 'Missing. Camera, microphone and location access are not restricted.', 5,
      'Add: Permissions-Policy: camera=(), microphone=(), geolocation=()'));
  }

  // 10. Information leakage
  const leaks = [];
  if (h['x-powered-by']) leaks.push(`X-Powered-By: ${h['x-powered-by']}`);
  if (h.server && /\d/.test(h.server)) leaks.push(`Server: ${h.server}`);
  if (h['x-aspnet-version']) leaks.push(`X-AspNet-Version: ${h['x-aspnet-version']}`);
  if (leaks.length === 0) {
    checks.push(pass('leak', 'Software version hidden', 'The server does not reveal software versions.', 5));
  } else {
    checks.push(fail('leak', 'Software version hidden', `Reveals: ${leaks.join(', ')}. This helps attackers find known bugs.`, 5,
      'Remove X-Powered-By and hide version numbers in the Server header.'));
  }

  // 11. Cookies (only if the page sets any)
  const rawCookies = h['set-cookie'];
  const cookies = Array.isArray(rawCookies) ? rawCookies : rawCookies ? [rawCookies] : [];
  if (cookies.length > 0) {
    const weak = cookies.filter((c) => !/;\s*secure/i.test(c) || !/;\s*httponly/i.test(c) || !/;\s*samesite/i.test(c));
    if (weak.length === 0) {
      checks.push(pass('cookies', 'Cookie flags', `All ${cookies.length} cookie(s) use Secure, HttpOnly and SameSite.`, 5));
    } else {
      const names = weak.map((c) => c.split('=')[0]).join(', ');
      checks.push(warn('cookies', 'Cookie flags', `${weak.length} of ${cookies.length} cookie(s) are missing Secure, HttpOnly or SameSite (${names}).`, 5, 3,
        'Set cookies with: Secure; HttpOnly; SameSite=Lax'));
    }
  }

  const total = checks.reduce((s, c) => s + c.weight, 0);
  const lost = checks.reduce((s, c) => s + c.lost, 0);
  const score = Math.round(((total - lost) / total) * 100);
  const httpsOk = checks.find((c) => c.id === 'https').status === 'pass';
  const grade = toGrade(score, httpsOk, checks);

  return { score, grade, checks };
}

export function toGrade(score, httpsOk, checks) {
  // No trusted HTTPS caps the grade at F, however good the headers are.
  if (!httpsOk) return 'F';
  if (score >= 95 && checks.every((c) => c.status === 'pass')) return 'A+';
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 45) return 'D';
  return 'F';
}
