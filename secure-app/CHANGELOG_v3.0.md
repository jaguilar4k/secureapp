# SecureApp v3.0

## Cambios principales

- Correccion del login web en `http://localhost` sin romper cookies seguras en HTTPS.
- Correccion del control RBAC `requireAnyRole`, que antes evaluaba mal los roles permitidos.
- Conservacion correcta de `returnTo` despues del login para redirigir a la ruta solicitada.
- JWT disponible tanto por `Authorization: Bearer` como por cookie `HttpOnly` (`auth_token`).
- Login API ahora actualiza `ultimo_login` y `ultimo_login_ip`.
- Nuevo `POST /api/auth/logout` para limpiar la cookie JWT.
- Validacion mas estricta en rutas web y API para IDs, usuarios y productos.
- Edicion de usuarios reforzada para no permitir contrasenas debiles en updates.
- Proteccion para no eliminar ni degradar al ultimo `SuperAdmin`.
- Sincronizacion de sesion al editar al usuario autenticado.
- Nueva ruta `PUT /api/usuarios/:id` para actualizar usuarios via API.
- Mejor manejo de errores y auditoria en endpoints criticos.

## Verificacion local aplicada en esta revision

- `node --check` sobre los archivos modificados.
- Pruebas unitarias ligeras para RBAC y configuracion de cookies/sesion.
