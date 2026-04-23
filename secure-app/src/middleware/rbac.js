'use strict';

function normalizeRoles(firstRole, restRoles) {
  if (Array.isArray(firstRole)) {
    return firstRole;
  }

  return [firstRole, ...restRoles].filter(Boolean);
}

function requireRole(...roleArgs) {
  const allowedRoles = normalizeRoles(roleArgs[0], roleArgs.slice(1));

  return (req, res, next) => {
    const user = req.session && req.session.user;

    if (!user) {
      return res.redirect('/auth/login');
    }

    if (allowedRoles.includes(user.rol)) {
      return next();
    }

    return res.status(403).render('error', {
      titulo: 'Acceso Denegado',
      mensaje: 'No tienes permisos para acceder a esta seccion.',
      user,
    });
  };
}

function requireAnyRole(...roleArgs) {
  return requireRole(...roleArgs);
}

function requireRoleAPI(...roleArgs) {
  const allowedRoles = normalizeRoles(roleArgs[0], roleArgs.slice(1));

  return (req, res, next) => {
    const user = req.jwtUser;

    if (!user) {
      return res.status(401).json({ error: 'No autenticado.' });
    }

    if (allowedRoles.includes(user.rol)) {
      return next();
    }

    return res.status(403).json({ error: 'Permiso denegado.' });
  };
}

module.exports = { requireAnyRole, requireRole, requireRoleAPI };
