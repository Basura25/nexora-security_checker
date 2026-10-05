// SSRF protection.
// A tool that fetches any URL a visitor types is a classic SSRF risk: someone could
// ask it to fetch http://localhost:6379 or http://169.254.169.254 (cloud metadata)
// and use OUR server to reach things on OUR network. These helpers stop that.

import dns from 'node:dns';
import net from 'node:net';
import ipaddr from 'ipaddr.js';

const ALLOWED_PORTS = new Set([80, 443]);

// True only for normal public internet addresses.
export function isPublicIp(ip) {
  if (!net.isIP(ip)) return false;
  let addr = ipaddr.parse(ip);
  // Treat IPv4-mapped IPv6 (::ffff:127.0.0.1) as the IPv4 it wraps.
  if (addr.kind() === 'ipv6' && addr.isIPv4MappedAddress()) {
    addr = addr.toIPv4Address();
  }
  return addr.range() === 'unicast';
}

// Validate the URL a visitor typed. Returns a URL object or throws a friendly error.
export function parseTarget(input) {
  if (typeof input !== 'string' || input.trim().length === 0) {
    throw new UserError('Please enter a website address.');
  }
  let raw = input.trim();
  if (raw.length > 2048) throw new UserError('That address is too long.');
  if (!/^https?:\/\//i.test(raw)) raw = `https://${raw}`;

  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new UserError('That does not look like a valid website address.');
  }
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new UserError('Only http and https addresses can be checked.');
  }
  if (url.username || url.password) {
    throw new UserError('Addresses with usernames or passwords are not allowed.');
  }
  const port = url.port ? Number(url.port) : url.protocol === 'https:' ? 443 : 80;
  if (!ALLOWED_PORTS.has(port)) {
    throw new UserError('Only standard web ports (80 and 443) can be checked.');
  }
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(host)) {
    throw new UserError('Please enter a domain name, not an IP address.');
  }
  if (!host.includes('.') || host.endsWith('.local') || host.endsWith('.internal') || host === 'localhost') {
    throw new UserError('Please enter a public website domain.');
  }
  return url;
}

// A DNS lookup function for http/https requests that refuses private addresses.
// Because the check happens at connect time (not before), it also blocks
// DNS-rebinding tricks where a domain resolves to a public IP first, then a private one.
export function safeLookup(hostname, options, callback) {
  dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) return callback(err);
    const list = Array.isArray(addresses) ? addresses : [{ address: addresses, family: options.family }];
    const bad = list.find((a) => !isPublicIp(a.address));
    if (bad || list.length === 0) {
      const e = new UserError('This address points to a private or reserved network and cannot be checked.');
      e.code = 'EPRIVATE';
      return callback(e);
    }
    if (options.all) return callback(null, list);
    return callback(null, list[0].address, list[0].family);
  });
}

export class UserError extends Error {
  constructor(message) {
    super(message);
    this.expose = true;
  }
}
