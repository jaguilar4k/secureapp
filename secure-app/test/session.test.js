'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  buildHttpOnlyCookieOptions,
  getSessionRuntimeConfig,
  resolveSecureCookie,
} = require('../src/config/session');

test('production defaults to secure auto mode', async () => {
  const config = getSessionRuntimeConfig({ NODE_ENV: 'production' });
  assert.equal(config.cookieSecure, 'auto');
  assert.equal(config.trustProxy, 0);
});

test('development defaults to non-secure cookies', async () => {
  const config = getSessionRuntimeConfig({ NODE_ENV: 'development' });
  assert.equal(config.cookieSecure, false);
});

test('auto secure cookies follow req.secure', async () => {
  const runtime = getSessionRuntimeConfig({
    NODE_ENV: 'production',
    SESSION_COOKIE_SECURE: 'auto',
  });

  assert.equal(resolveSecureCookie({ secure: true }, runtime), true);
  assert.equal(resolveSecureCookie({ secure: false }, runtime), false);
});

test('http only cookie builder keeps strict same-site and max-age', async () => {
  const runtime = getSessionRuntimeConfig({
    NODE_ENV: 'production',
    SESSION_COOKIE_SECURE: 'auto',
  });

  const cookieOptions = buildHttpOnlyCookieOptions(
    { secure: true },
    { runtime, maxAge: 60000 }
  );

  assert.deepEqual(cookieOptions, {
    httpOnly: true,
    sameSite: 'strict',
    secure: true,
    path: '/',
    maxAge: 60000,
  });
});
