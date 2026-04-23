'use strict';
require('dotenv').config();

const express = require('express');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const cookieParser = require('cookie-parser');
const morgan = require('morgan');
const csurf = require('csurf');
const bcrypt = require('bcrypt');
const db = require('./db');
const { auditDenegado } = require('./middleware/audit');
const { getSessionRuntimeConfig } = require('./config/session');

const app = express();
const PORT = parseInt(process.env.PORT || '3000', 10);
const sessionRuntime = getSessionRuntimeConfig();

if (sessionRuntime.trustProxy) {
  app.set('trust proxy', sessionRuntime.trustProxy);
}

// 1. View engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// 2. RS-06: HTTP security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'none'"],
      frameSrc: ["'none'"],
      frameAncestors: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  noSniff: true,
  frameguard: { action: 'deny' },
  xssFilter: true,
}));

// 3. Basic middleware
app.use(morgan('combined'));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// 4. RS-04: Session management
app.use(session({
  store: new PgSession({
    pool: db.pool,
    tableName: 'session',
    createTableIfMissing: true,
  }),
  proxy: Boolean(sessionRuntime.trustProxy),
  name: 'connect.sid',
  secret: process.env.SESSION_SECRET || 'fallback-secret-change-me',
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    // "auto" keeps the cookie Secure on HTTPS, but does not break local HTTP logins.
    secure: sessionRuntime.cookieSecure,
    sameSite: 'strict',
    maxAge: 5 * 60 * 1000,
  },
}));

// 5. RS-03: CSRF protection for web routes only
const csrfProtection = csurf({ cookie: false });
app.use((req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  csrfProtection(req, res, next);
});

// 6. Audit denied accesses
app.use(auditDenegado);

// 7. Shared locals for views
app.use((req, res, next) => {
  res.locals.user = req.session && req.session.user ? req.session.user : null;

  if (!req.path.startsWith('/api/') && typeof req.csrfToken === 'function') {
    res.locals.csrfToken = req.csrfToken();
  } else {
    res.locals.csrfToken = '';
  }

  next();
});

// 8. Routes
app.get('/', (req, res) => res.redirect('/dashboard'));

app.get('/dashboard', require('./middleware/auth').requireAuth, (req, res) => {
  res.render('dashboard', { user: req.session.user });
});

app.use('/auth', require('./routes/auth'));
app.use('/productos', require('./routes/products'));
app.use('/usuarios', require('./routes/users'));
app.use('/auditoria', require('./routes/audit'));

// REST API
app.use('/api/auth', require('./routes/api/auth'));
app.use('/api/productos', require('./routes/api/products'));
app.use('/api/usuarios', require('./routes/api/users'));

// 9. CSRF error handler
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).render('error', {
      titulo: 'Token CSRF invalido',
      mensaje: 'La solicitud fue rechazada por seguridad. Por favor recarga la pagina e intenta nuevamente.',
      user: res.locals.user,
    });
  }
  next(err);
});

// 10. Global error handler
app.use((err, req, res, next) => {
  console.error('[APP]', err.stack);
  res.status(500).render('error', {
    titulo: 'Error interno',
    mensaje: 'Ocurrio un error inesperado.',
    user: res.locals.user,
  });
});

// 11. Database bootstrap
async function initDB() {
  const schema = fs.readFileSync(path.join(__dirname, 'db', 'schema.sql'), 'utf8');
  await db.query(schema);
  console.log('[DB] Esquema aplicado.');

  const existing = await db.query("SELECT id FROM usuarios WHERE username='admin'");
  if (!existing.rows.length) {
    const hash = await bcrypt.hash('Admin1234!', 12);
    await db.query(
      `INSERT INTO usuarios (username, password_hash, email, rol_id)
       SELECT 'admin', $1, 'admin@secureapp.local', r.id
       FROM roles r WHERE r.nombre='SuperAdmin'`,
      [hash]
    );
    console.log('[SEED] Usuario admin creado. Contrasena: Admin1234! - CAMBIAR EN PRODUCCION');
  }
}

// 12. Startup
async function start() {
  try {
    await initDB();
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`[APP] Servidor corriendo en http://0.0.0.0:${PORT}`);
    });
  } catch (err) {
    console.error('[APP] Error al iniciar:', err);
    process.exit(1);
  }
}

start();

module.exports = app;
