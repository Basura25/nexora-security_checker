import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isPublicIp, parseTarget } from './ssrf.js';
import { gradeSite } from './grader.js';

test('blocks private, loopback and metadata addresses', () => {
  for (const ip of ['127.0.0.1', '10.0.0.5', '192.168.1.1', '172.16.0.1', '169.254.169.254', '0.0.0.0', '::1', '::ffff:127.0.0.1', 'fd00::1', '100.64.0.1']) {
    assert.equal(isPublicIp(ip), false, ip);
  }
  for (const ip of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111']) {
    assert.equal(isPublicIp(ip), true, ip);
  }
});

test('rejects unsafe URLs', () => {
  for (const bad of ['', 'localhost', 'http://localhost', 'http://127.0.0.1', 'ftp://example.com', 'https://example.com:6379', 'https://user:pw@example.com', 'file:///etc/passwd', 'http://printer.local', 'http://[::1]/']) {
    assert.throws(() => parseTarget(bad), bad);
  }
});

test('accepts normal domains and adds https', () => {
  assert.equal(parseTarget('example.com').href, 'https://example.com/');
  assert.equal(parseTarget('http://example.lk/page').protocol, 'http:');
});

const goodCert = { authorized: true, validTo: new Date(Date.now() + 90 * 86400000).toUTCString(), issuer: "Let's Encrypt" };

test('a well configured site gets A+', () => {
  const r = gradeSite({
    finalUrl: new URL('https://good.example/'),
    cert: goodCert,
    httpRedirect: { reachable: true, redirectsToHttps: true },
    headers: {
      'strict-transport-security': 'max-age=31536000; includeSubDomains',
      'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'strict-origin-when-cross-origin',
      'permissions-policy': 'camera=()',
      server: 'nginx',
    },
  });
  assert.equal(r.grade, 'A+');
  assert.equal(r.score, 100);
});

test('a bare HTTPS site with no headers gets a low grade', () => {
  const r = gradeSite({
    finalUrl: new URL('https://bare.example/'),
    cert: goodCert,
    httpRedirect: { reachable: true, redirectsToHttps: false },
    headers: { server: 'Apache/2.4.41 (Ubuntu)', 'x-powered-by': 'PHP/7.4.3' },
  });
  assert.equal(r.grade, 'F');
  assert.ok(r.checks.find((c) => c.id === 'leak').status === 'fail');
});

test('no HTTPS is always F', () => {
  const r = gradeSite({
    finalUrl: new URL('http://plain.example/'),
    cert: null,
    httpRedirect: { reachable: true, redirectsToHttps: false },
    headers: { 'content-security-policy': "default-src 'self'", 'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY' },
  });
  assert.equal(r.grade, 'F');
});
