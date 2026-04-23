'use strict';

const db = require('../db');

async function getRoleById(roleId) {
  const result = await db.query('SELECT id, nombre, descripcion FROM roles WHERE id = $1', [roleId]);
  return result.rows[0] || null;
}

async function getUserWithRole(userId) {
  const result = await db.query(
    `SELECT u.id, u.username, u.rol_id, r.nombre AS rol
     FROM usuarios u
     JOIN roles r ON r.id = u.rol_id
     WHERE u.id = $1`,
    [userId]
  );

  return result.rows[0] || null;
}

async function countOtherSuperAdmins(userId) {
  const result = await db.query(
    `SELECT COUNT(*) AS total
     FROM usuarios u
     JOIN roles r ON r.id = u.rol_id
     WHERE r.nombre = 'SuperAdmin' AND u.id <> $1`,
    [userId]
  );

  return Number.parseInt(result.rows[0].total, 10);
}

async function assertRoleExists(roleId) {
  const role = await getRoleById(roleId);
  if (!role) {
    const error = new Error('El rol seleccionado no existe.');
    error.statusCode = 400;
    throw error;
  }

  return role;
}

async function assertCanChangeUserRole(userId, nextRoleId) {
  const [user, nextRole] = await Promise.all([
    getUserWithRole(userId),
    assertRoleExists(nextRoleId),
  ]);

  if (!user) {
    const error = new Error('Usuario no encontrado.');
    error.statusCode = 404;
    throw error;
  }

  if (user.rol === 'SuperAdmin' && nextRole.nombre !== 'SuperAdmin') {
    const otherAdmins = await countOtherSuperAdmins(userId);
    if (otherAdmins === 0) {
      const error = new Error('No puedes quitar el rol al ultimo SuperAdmin del sistema.');
      error.statusCode = 400;
      throw error;
    }
  }

  return { nextRole, user };
}

async function assertCanDeleteUser(userId) {
  const user = await getUserWithRole(userId);

  if (!user) {
    const error = new Error('Usuario no encontrado.');
    error.statusCode = 404;
    throw error;
  }

  if (user.rol === 'SuperAdmin') {
    const otherAdmins = await countOtherSuperAdmins(userId);
    if (otherAdmins === 0) {
      const error = new Error('No puedes eliminar al ultimo SuperAdmin del sistema.');
      error.statusCode = 400;
      throw error;
    }
  }

  return user;
}

module.exports = {
  assertCanChangeUserRole,
  assertCanDeleteUser,
  assertRoleExists,
  getRoleById,
  getUserWithRole,
};
