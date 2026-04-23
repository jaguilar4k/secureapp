-- ============================================================
-- Schema de la base de datos – Blue Team Secure App
-- ============================================================

-- Tabla de roles
CREATE TABLE IF NOT EXISTS roles (
    id        SERIAL PRIMARY KEY,
    nombre    VARCHAR(50) UNIQUE NOT NULL,
    descripcion TEXT
);

-- Roles base
INSERT INTO roles (nombre, descripcion) VALUES
    ('SuperAdmin', 'Acceso total al sistema'),
    ('Auditor',    'Solo lectura en usuarios y productos'),
    ('Registrador','CRUD de productos, lectura de usuarios')
ON CONFLICT (nombre) DO NOTHING;

-- Tabla de usuarios
CREATE TABLE IF NOT EXISTS usuarios (
    id              SERIAL PRIMARY KEY,
    username        VARCHAR(50) UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,
    email           VARCHAR(100) UNIQUE NOT NULL,
    rol_id          INTEGER NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
    activo          BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    ultimo_login    TIMESTAMPTZ,
    ultimo_login_ip VARCHAR(45)
);

-- SuperAdmin por defecto (contraseña: Admin1234! — bcrypt cost 12)
-- Se inserta vía seed en app.js al iniciar
-- Tabla de productos
CREATE TABLE IF NOT EXISTS productos (
    id          SERIAL PRIMARY KEY,
    codigo      VARCHAR(20) UNIQUE NOT NULL,
    nombre      VARCHAR(100) NOT NULL,
    descripcion TEXT,
    cantidad    INTEGER NOT NULL CHECK (cantidad >= 0),
    precio      NUMERIC(12,2) NOT NULL CHECK (precio >= 0),
    creado_por  INTEGER REFERENCES usuarios(id),
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);

-- Log de auditoría
CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGSERIAL PRIMARY KEY,
    timestamp   TIMESTAMPTZ DEFAULT NOW(),
    ip_origen   VARCHAR(45),
    usuario_id  INTEGER REFERENCES usuarios(id) ON DELETE SET NULL,
    username    VARCHAR(50),
    evento      VARCHAR(100) NOT NULL,
    detalle     TEXT,
    ruta        VARCHAR(255),
    resultado   VARCHAR(20)  -- 'exitoso' | 'fallido' | 'denegado'
);

-- Índices útiles
CREATE INDEX IF NOT EXISTS idx_audit_timestamp   ON audit_log (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_usuario     ON audit_log (usuario_id);
CREATE INDEX IF NOT EXISTS idx_audit_evento      ON audit_log (evento);
CREATE INDEX IF NOT EXISTS idx_productos_codigo  ON productos (codigo);
