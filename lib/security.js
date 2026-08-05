'use strict';

const crypto = require('node:crypto');
const path = require('node:path');

// ─── 密码哈希 (scrypt) ──────────────────────────────────────
const SCRYPT_PARAMS = Object.freeze({ N: 16384, r: 8, p: 1, keyLength: 64 });

function scryptHash(password, salt, params) {
  const maxmem = Math.max(32 * 1024 * 1024, 128 * params.N * params.r + 256 * params.r * params.p);
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, params.keyLength, {
      cost: params.N,
      blockSize: params.r,
      parallelization: params.p,
      maxmem,
    }, (err, key) => (err ? reject(err) : resolve(key)));
  });
}

async function hashPassword(password) {
  if (typeof password !== 'string' || password.length === 0) throw new TypeError('password required');
  const salt = crypto.randomBytes(16);
  const hash = await scryptHash(password, salt, SCRYPT_PARAMS);
  return `scrypt$${SCRYPT_PARAMS.N}$${SCRYPT_PARAMS.r}$${SCRYPT_PARAMS.p}$${salt.toString('base64url')}$${hash.toString('base64url')}`;
}

async function verifyPassword(password, record) {
  const candidate = typeof password === 'string' ? password : '';
  if (typeof record !== 'string') return false;
  const m = /^scrypt\$(\d+)\$(\d+)\$(\d+)\$([A-Za-z0-9_-]+)\$([A-Za-z0-9_-]+)$/.exec(record);
  if (!m) return false;
  const params = { N: +m[1], r: +m[2], p: +m[3], keyLength: SCRYPT_PARAMS.keyLength };
  const salt = Buffer.from(m[4], 'base64url');
  const hash = Buffer.from(m[5], 'base64url');
  if (salt.length < 16 || hash.length !== SCRYPT_PARAMS.keyLength) return false;
  try {
    const derived = await scryptHash(candidate, salt, params);
    return crypto.timingSafeEqual(derived, hash);
  } catch {
    return false;
  }
}

// ─── 身份加密 (AES-256-GCM) ─────────────────────────────────
function deriveKey(keyMaterial) {
  if (typeof keyMaterial !== 'string' || keyMaterial.length === 0) {
    throw new TypeError('encryption key required');
  }
  return crypto.createHash('sha256').update(keyMaterial).digest();
}

function encryptIdentity(identity, keyMaterial) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', deriveKey(keyMaterial), iv);
  const plaintext = Buffer.from(JSON.stringify(identity), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    alg: 'aes-256-gcm',
    iv: iv.toString('base64url'),
    tag: cipher.getAuthTag().toString('base64url'),
    ciphertext: ciphertext.toString('base64url'),
  };
}

function decryptIdentity(encrypted, keyMaterial) {
  if (!encrypted || encrypted.alg !== 'aes-256-gcm') throw new Error('无效的加密数据');
  const iv = Buffer.from(encrypted.iv, 'base64url');
  const tag = Buffer.from(encrypted.tag, 'base64url');
  const ciphertext = Buffer.from(encrypted.ciphertext, 'base64url');
  if (iv.length !== 12 || tag.length !== 16 || ciphertext.length === 0) throw new Error('加密数据损坏');
  const decipher = crypto.createDecipheriv('aes-256-gcm', deriveKey(keyMaterial), iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(plaintext.toString('utf8'));
}

// ─── Token & Cookie ─────────────────────────────────────────
function createToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

function createSessionCookie(name, token, { expiresAt, path = '/' } = {}) {
  const expiry = expiresAt ? new Date(expiresAt) : new Date(Date.now() + 8 * 3600_000);
  return `${name}=${token}; Path=${path}; Expires=${expiry.toUTCString()}; HttpOnly; SameSite=Lax${expiresAt ? '; Secure' : ''}`;
}

function clearCookie(name, path = '/') {
  return `${name}=; Path=${path}; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax`;
}

// ─── HMAC 摘要 ──────────────────────────────────────────────
function hmacDigest(data, secret) {
  return crypto.createHmac('sha256', secret).update(data).digest('base64url');
}

function timingSafeEqualStr(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  return bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB);
}

// ─── CSRF ───────────────────────────────────────────────────
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function requireCsrf(request, session, { origin, secret }) {
  if (SAFE_METHODS.has(String(request.method || 'GET').toUpperCase())) return true;
  const token = request.headers['x-csrf-token'];
  const sessionDigest = session?.csrf_digest;
  if (typeof token !== 'string' || typeof sessionDigest !== 'string') return false;
  return timingSafeEqualStr(hmacDigest(token, secret), sessionDigest);
}

// ─── 限流 ───────────────────────────────────────────────────
function createRateLimiter({ clock = () => Date.now(), policies = {} } = {}) {
  const defaults = {
    login: { maxFailures: 5, windowMs: 15 * 60_000, cooldownMs: 30_000 },
    query: { maxFailures: 5, windowMs: 15 * 60_000, cooldownMs: 30_000 },
    submit: { maxFailures: 10, windowMs: 15 * 60_000, cooldownMs: 10_000 },
  };
  const merged = { ...defaults, ...policies };
  const attempts = new Map();

  function attempt({ category, ip, success = false }) {
    const policy = merged[category];
    if (!policy) return { allowed: true, retryAfterMs: 0 };
    const now = clock();
    const key = `${category}:${ip}`;
    let state = attempts.get(key);

    if (state && now >= state.expiresAt) {
      attempts.delete(key);
      state = undefined;
    }
    if (state && now < state.blockedUntil) {
      return { allowed: false, retryAfterMs: state.blockedUntil - now };
    }
    if (success) {
      attempts.delete(key);
      return { allowed: true, retryAfterMs: 0 };
    }
    if (!state) {
      state = { failures: 0, createdAt: now, expiresAt: now + policy.windowMs, blockedUntil: 0 };
    }
    state.failures += 1;
    if (state.failures >= policy.maxFailures) {
      state.blockedUntil = now + policy.cooldownMs;
      state.expiresAt = Math.max(state.expiresAt, state.blockedUntil);
      attempts.set(key, state);
      return { allowed: false, retryAfterMs: policy.cooldownMs };
    }
    attempts.set(key, state);
    return { allowed: true, retryAfterMs: 0 };
  }

  return { attempt };
}

// ─── 文件类型白名单 ─────────────────────────────────────────
const ALLOWED_EXTENSIONS = new Set([
  '.bmp', '.doc', '.docx', '.gif', '.heic', '.jpeg', '.jpg',
  '.m4a', '.mov', '.mp3', '.mp4', '.mpeg', '.mpg', '.ogg',
  '.pdf', '.png', '.ppt', '.pptx', '.tif', '.tiff', '.txt',
  '.wav', '.webm', '.webp', '.xls', '.xlsx',
]);

const MIME_OVERRIDES = {
  '.pdf': 'application/pdf',
  '.doc': 'application/msword',
  '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  '.xls': 'application/vnd.ms-excel',
  '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  '.ppt': 'application/vnd.ms-powerpoint',
  '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  '.txt': 'text/plain',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.bmp': 'image/bmp',
  '.mp4': 'video/mp4',
  '.mp3': 'audio/mpeg',
  '.wav': 'audio/wav',
};

function validateFileDeclaration(filename, declaredMime) {
  const ext = path.extname(filename).toLowerCase();
  if (!ALLOWED_EXTENSIONS.has(ext)) {
    return { valid: false, reason: '不支持的文件类型' };
  }
  const expectedMime = MIME_OVERRIDES[ext] || declaredMime || 'application/octet-stream';
  return { valid: true, ext, mime: expectedMime };
}

// ─── Cookie 解析 ────────────────────────────────────────────
function parseCookies(header) {
  const cookies = {};
  for (const part of String(header || '').split(';')) {
    const idx = part.indexOf('=');
    if (idx < 1) continue;
    cookies[part.slice(0, idx).trim()] = part.slice(idx + 1).trim();
  }
  return cookies;
}

module.exports = {
  hashPassword,
  verifyPassword,
  encryptIdentity,
  decryptIdentity,
  createToken,
  createSessionCookie,
  clearCookie,
  hmacDigest,
  timingSafeEqualStr,
  requireCsrf,
  createRateLimiter,
  parseCookies,
  validateFileDeclaration,
  ALLOWED_EXTENSIONS,
};
