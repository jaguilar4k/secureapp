'use strict';

function parseTrustProxy(value) {
  if (value === undefined || value === null || value === '') return 0;

  const normalized = String(value).trim().toLowerCase();
  if (['true', 'yes', 'on'].includes(normalized)) return 1;
  if (['false', 'no', 'off'].includes(normalized)) return 0;

  const numericValue = Number.parseInt(normalized, 10);
  return Number.isNaN(numericValue) ? 0 : numericValue;
}

function parseSecureCookie(value, nodeEnv) {
  if (value === undefined || value === null || value === '') {
    return nodeEnv === 'production' ? 'auto' : false;
  }

  const normalized = String(value).trim().toLowerCase();

  if (normalized === 'auto') return 'auto';
  if (['true', '1', 'yes', 'on'].includes(normalized)) return true;
  if (['false', '0', 'no', 'off'].includes(normalized)) return false;

  return nodeEnv === 'production' ? 'auto' : false;
}

function getSessionRuntimeConfig(env = process.env) {
  return {
    trustProxy: parseTrustProxy(env.TRUST_PROXY),
    cookieSecure: parseSecureCookie(env.SESSION_COOKIE_SECURE, env.NODE_ENV),
  };
}

function resolveSecureCookie(req, runtime = getSessionRuntimeConfig()) {
  if (runtime.cookieSecure === 'auto') {
    return Boolean(req && req.secure);
  }

  return Boolean(runtime.cookieSecure);
}

function buildHttpOnlyCookieOptions(req, options = {}) {
  const runtime = options.runtime || getSessionRuntimeConfig();
  const cookieOptions = {
    httpOnly: true,
    sameSite: options.sameSite || 'strict',
    secure: resolveSecureCookie(req, runtime),
    path: options.path || '/',
  };

  if (options.maxAge !== undefined) {
    cookieOptions.maxAge = options.maxAge;
  }

  return cookieOptions;
}

module.exports = {
  buildHttpOnlyCookieOptions,
  getSessionRuntimeConfig,
  resolveSecureCookie,
};
