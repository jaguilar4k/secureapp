'use strict';
const { Pool } = require('pg');

const pool = new Pool({
  host:     process.env.DB_HOST     || 'localhost',
  port:     parseInt(process.env.DB_PORT || '5432'),
  database: process.env.DB_NAME     || 'secureapp',
  user:     process.env.DB_USER     || 'appuser',
  password: process.env.DB_PASSWORD || 'StrongPass123!',
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

pool.on('error', (err) => {
  console.error('[DB] Error inesperado en el pool:', err);
});

/**
 * Ejecuta una consulta parametrizada.
 * NUNCA concatenar input del usuario en el string SQL.
 * Siempre usar $1, $2, … con el arreglo params.
 */
async function query(text, params) {
  const start = Date.now();
  const res = await pool.query(text, params);
  const duration = Date.now() - start;
  if (process.env.NODE_ENV !== 'production') {
    console.debug('[DB] query ejecutada en', duration, 'ms');
  }
  return res;
}

async function getClient() {
  return pool.connect();
}

module.exports = { query, getClient, pool };
