'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { requireAnyRole, requireRoleAPI } = require('../src/middleware/rbac');

test('requireAnyRole accepts roles as separate arguments', async () => {
  const middleware = requireAnyRole('SuperAdmin', 'Auditor', 'Registrador');

  const req = { session: { user: { rol: 'Auditor' } } };
  const res = {
    statusCode: 200,
    status(code) {
      this.statusCode = code;
      return this;
    },
    render() {
      throw new Error('render should not be called');
    },
  };

  let nextCalled = false;
  middleware(req, res, () => {
    nextCalled = true;
  });

  assert.equal(nextCalled, true);
});

test('requireAnyRole also accepts an array of roles', async () => {
  const middleware = requireAnyRole(['SuperAdmin', 'Auditor']);

  const req = { session: { user: { rol: 'Auditor' } } };
  const res = {
    status(code) {
      this.statusCode = code;
      return this;
    },
    render() {
      throw new Error('render should not be called');
    },
  };

  let nextCalled = false;
  middleware(req, res, () => {
    nextCalled = true;
  });

  assert.equal(nextCalled, true);
});

test('requireRoleAPI denies users without the expected role', async () => {
  const middleware = requireRoleAPI('SuperAdmin');

  const req = { jwtUser: { rol: 'Auditor' } };
  const res = {
    body: null,
    statusCode: 200,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.body = payload;
      return this;
    },
  };

  let nextCalled = false;
  middleware(req, res, () => {
    nextCalled = true;
  });

  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 403);
  assert.deepEqual(res.body, { error: 'Permiso denegado.' });
});
