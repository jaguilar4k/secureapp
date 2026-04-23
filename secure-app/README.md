# 🔒 SecureApp – Blue Team

**Proyecto 2 | ISW-1013 Calidad del Software | UTN | I Cuatrimestre 2026**

Aplicación web segura construida como parte del proyecto de seguridad: *Construye, Ataca, Defiende*.

---

## Stack tecnológico

| Capa | Tecnología | Justificación de seguridad |
|------|-----------|---------------------------|
| Runtime | Node.js 20 LTS | Soporte activo, actualizaciones de seguridad frecuentes |
| Framework | Express 4 | Maduro, ampliamente auditado, middleware ecosystem |
| Base de datos | PostgreSQL 16 | ACID, soporte nativo de prepared statements, sin inyección posible con `pg` parametrizado |
| Hashing | bcrypt (cost=12) | Algoritmo adaptativo con sal integrada (RF-02) |
| Sesiones | express-session + PostgreSQL store | Persistencia sin JWT en cookies, HttpOnly + Secure |
| Autenticación API | JWT HS256 | Expiración 1h, algoritmo 'none' rechazado (RS-05) |
| Plantillas | EJS | Escapa HTML automáticamente con `<%= %>` (RS-02) |
| Headers HTTP | Helmet | CSP, HSTS, X-Frame-Options, nosniff (RS-06) |
| CSRF | csurf | Token en sesión para todos los formularios (RS-03) |
| Rate limiting | express-rate-limit | Bloqueo tras 5 intentos / 5 min (RS-07) |
| Contenedores | Docker + Docker Compose | Reproducibilidad y aislamiento |

---

## Instalación y ejecución

### Requisitos previos

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (incluye Docker Compose)
- [ngrok](https://ngrok.com/) (para exposición pública en el pentest cruzado)

### 1. Clonar el repositorio

```bash
git clone https://github.com/TU_EQUIPO/secureapp.git
cd secureapp
```

### 2. Levantar con Docker Compose (un solo comando)

```bash
docker-compose up --build
```

La aplicación queda disponible en: **http://localhost:3000**

### 3. Credenciales por defecto

| Usuario | Contraseña | Rol |
|---------|-----------|-----|
| `admin` | `Admin1234!` | SuperAdmin |

> ⚠️ **Cambiar la contraseña del admin inmediatamente después del primer login.**

### 4. Exponer con ngrok (pentest cruzado)

```bash
# Instalar y autenticar ngrok (solo la primera vez)
ngrok config add-authtoken <TU_TOKEN>

# Con Docker Compose corriendo:
ngrok http 3000
```

Copiar la URL pública generada (ej: `https://abc123.ngrok-free.app`) y pegarla en el README y notificar al equipo Red Team asignado.

> La URL de ngrok cambia cada vez que se reinicia. Actualizar el README y notificar si es necesario relanzar.

---

## Estructura del proyecto

```
secureapp/
├── src/
│   ├── app.js                 # Entry point, middleware global, inicialización DB
│   ├── db/
│   │   ├── index.js           # Pool de conexiones PostgreSQL
│   │   └── schema.sql         # DDL: tablas, índices, seed de roles
│   ├── middleware/
│   │   ├── audit.js           # Log de auditoría + middleware 403
│   │   ├── auth.js            # requireAuth (sesión) + requireJWT (API)
│   │   └── rbac.js            # requireRole / requireRoleAPI (RBAC backend)
│   ├── routes/
│   │   ├── auth.js            # Login / logout (web)
│   │   ├── products.js        # CRUD productos (web)
│   │   ├── users.js           # CRUD usuarios (web)
│   │   ├── audit.js           # Log de auditoría (web, solo SuperAdmin)
│   │   └── api/
│   │       ├── auth.js        # POST /api/auth/login → JWT
│   │       ├── products.js    # CRUD /api/productos
│   │       └── users.js       # CRUD /api/usuarios
│   ├── views/
│   │   ├── partials/          # header.ejs, footer.ejs
│   │   ├── auth/login.ejs
│   │   ├── dashboard.ejs
│   │   ├── products/          # index.ejs, form.ejs
│   │   ├── users/             # index.ejs, form.ejs
│   │   ├── audit/index.ejs
│   │   └── error.ejs
│   └── public/css/style.css
├── api_docs/
│   └── openapi.yaml           # Especificación OpenAPI 3.0 completa
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── package.json
└── README.md
```

---

## Controles de seguridad implementados

### Funcionales

| Req | Estado | Descripción |
|-----|--------|-------------|
| RF-01 | ✅ | App web con PostgreSQL, stack Node/Express |
| RF-02 | ✅ | bcrypt cost=12, prohibido MD5/SHA-1 sin salt |
| RF-03 | ✅ | CRUD productos con validación front+back |
| RF-04 | ✅ | Gestión usuarios, historial último login + IP |
| RF-05 | ✅ | RBAC en backend: SuperAdmin, Auditor, Registrador |
| RF-06 | ✅ | Log de auditoría completo con timestamp e IP |
| RF-07 | ✅ | API REST con JWT documentada en OpenAPI |

### De seguridad

| Req | Estado | Descripción |
|-----|--------|-------------|
| RS-01 | ✅ | Prepared Statements en 100% de las consultas |
| RS-02 | ✅ | EJS escapa output + CSP configurada |
| RS-03 | ✅ | Token CSRF en todos los formularios de escritura |
| RS-04 | ✅ | Sesión: 5 min timeout, regeneración post-login, HttpOnly+Secure |
| RS-05 | ✅ | JWT HS256, expiración 1h, algoritmo 'none' rechazado |
| RS-06 | ✅ | Helmet: CSP, HSTS, X-Frame-Options DENY, nosniff, Referrer-Policy |
| RS-07 | ✅ | Rate limit login: 5 intentos → bloqueo 5 min |

---

## API REST – Endpoints principales

```
POST   /api/auth/login          → Obtener JWT (no requiere auth)
GET    /api/productos            → Listar productos (auth requerida)
POST   /api/productos            → Crear producto (SuperAdmin, Registrador)
GET    /api/productos/:id        → Obtener producto
PUT    /api/productos/:id        → Actualizar producto (SuperAdmin, Registrador)
DELETE /api/productos/:id        → Eliminar producto (SuperAdmin, Registrador)
GET    /api/usuarios             → Listar usuarios (todos los roles)
POST   /api/usuarios             → Crear usuario (SuperAdmin)
GET    /api/usuarios/:id         → Obtener usuario (SuperAdmin)
DELETE /api/usuarios/:id         → Eliminar usuario (SuperAdmin)
```

Documentación completa: `api_docs/openapi.yaml` (importar en Swagger UI o Postman).

**Ejemplo de uso con curl:**

```bash
# 1. Obtener token
TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Admin1234!"}' | jq -r .token)

# 2. Listar productos
curl -H "Authorization: Bearer $TOKEN" http://localhost:3000/api/productos
```

---

## Uso de IA generativa

Este proyecto utilizó **Claude (Anthropic)** como herramienta de apoyo en:
- Generación del scaffold inicial de código
- Revisión de implementaciones de seguridad (RBAC, CSRF, JWT)
- Redacción de documentación técnica

Todo el código fue revisado, comprendido y adaptado por el equipo. Cada integrante puede defender cualquier sección del proyecto.

---

## Equipo

| Nombre | Correo | Rol |
|--------|--------|-----|
| (Coordinador) | | Coordinador |
| | | Integrante |
| | | Integrante |
| | | Integrante |
