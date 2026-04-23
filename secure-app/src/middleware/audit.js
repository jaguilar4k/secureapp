'use strict';
const db = require('../db');

/**
 * Registra un evento en el log de auditoría.
 * Nunca lanza excepción – falla silenciosamente para no interrumpir el flujo.
 *
 * @param {Object} opts
 * @param {string}  opts.ip        - IP de origen
 * @param {number|null} opts.userId    - ID del usuario (puede ser null en login fallido)
 * @param {string|null} opts.username  - Username (para cuando userId sea null)
 * @param {string}  opts.evento    - Tipo de evento (e.g. 'LOGIN_EXITOSO')
 * @param {string}  opts.detalle   - Descripción adicional
 * @param {string}  opts.ruta      - Ruta HTTP afectada
 * @param {string}  opts.resultado - 'exitoso' | 'fallido' | 'denegado'
 */
async function registrarEvento({ ip, userId, username, evento, detalle, ruta, resultado }) {
  try {
    await db.query(
      `INSERT INTO audit_log (ip_origen, usuario_id, username, evento, detalle, ruta, resultado)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [ip || null, userId || null, username || null, evento, detalle || null, ruta || null, resultado || null]
    );
  } catch (err) {
    console.error('[AUDIT] Error al registrar evento:', err.message);
  }
}

/**
 * Middleware Express: registra accesos denegados (403) automáticamente.
 * Agrégalo DESPUÉS de tus middleware de RBAC.
 */
function auditDenegado(req, res, next) {
  const originalSend = res.send.bind(res);
  res.send = function (body) {
    if (res.statusCode === 403) {
      const user = req.session && req.session.user;
      registrarEvento({
        ip:        getIP(req),
        userId:    user ? user.id : null,
        username:  user ? user.username : 'anónimo',
        evento:    'ACCESO_DENEGADO',
        detalle:   `Intento de acceso denegado: ${req.method} ${req.originalUrl}`,
        ruta:      req.originalUrl,
        resultado: 'denegado',
      });
    }
    return originalSend(body);
  };
  next();
}

function getIP(req) {
  return (
    req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    req.socket?.remoteAddress ||
    'desconocida'
  );
}

module.exports = { registrarEvento, auditDenegado, getIP };
