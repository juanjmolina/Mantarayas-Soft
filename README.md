# Mantarayas — panel del club (100% Python)

Aplicación Flask + SQLite con autenticación real de servidor. El repositorio no tiene ningún archivo `.html`, `.css` ni `.js` suelto: todo el frontend vive como una cadena de texto dentro de `app.py` (constante `FRONTEND_HTML`, al final del archivo) y se sirve directamente desde ahí. Esto hace que el repositorio se detecte como 100% Python en GitHub, sin afectar en nada lo que ve el navegador — es exactamente el mismo contenido, solo que vive en un archivo `.py` en vez de un `.html` aparte.

## Qué incluye

- Autenticación por sesión de servidor (cookie firmada, httponly). Contraseñas con hash — nunca en texto plano, ni siquiera un Super Administrador puede verlas.
- Permisos por rol validados en el servidor (RBAC real): un Profesor que intente leer Pagos, Compras/Egresos, o guardar asistencia de un grupo que no es suyo, recibe un error 403 del servidor.
- Todos los módulos del club (alumnos, pagos, asistencia, horarios, contabilidad, profesores, usuarios) persistidos en una base de datos SQLite propia (`mantarayas.db`).

## Uso local

```bash
pip install -r requirements.txt
export SECRET_KEY="cámbiame-por-algo-largo-y-aleatorio"
python app.py
```

Abre `http://localhost:8000`. La primera vez se crean automáticamente las cuentas de ejemplo (cámbialas o elimínalas desde **Usuarios** apenas ingreses):

| Usuario | Contraseña | Rol |
|---|---|---|
| `admin` | `Mantarayas2026` | Super Administrador |
| `recepcion` | `Recepcion2026` | Recepcionista |
| `aarias` | `Profesor2026` | Profesor |

## Desplegar en Azure App Service

1. Sube este repositorio a GitHub.
2. En el portal de Azure, crea un **App Service** con stack Python 3.11 (Linux).
3. En **Configuration → Application settings** del App Service, agrega la variable `SECRET_KEY` con un valor largo y aleatorio (por ejemplo generado con `python -c "import secrets; print(secrets.token_hex(32))"`). Sin esto, las sesiones no serán seguras.
4. En `.github/workflows/azure-app-service.yml`, reemplaza `your-app-service-name` por el nombre real de tu App Service.
5. En **Settings → Secrets and variables → Actions** de tu repo en GitHub, crea el secreto `AZURE_WEBAPP_PUBLISH_PROFILE` con el perfil de publicación (App Service → Overview → Get publish profile, en el portal de Azure).
6. Cada push a `main` construye y despliega automáticamente.

## Modificar el frontend

Como el HTML/CSS/JS vive dentro de `app.py`, para editar la interfaz busca la constante `FRONTEND_HTML` al final del archivo (es una cadena de texto `r"""..."""`) y edita directamente ese bloque. Sigue siendo HTML/CSS/JS normal por dentro — solo cambió dónde vive el archivo.

### ⚠️ Sobre la base de datos en Azure App Service

Este proyecto usa SQLite (un solo archivo, `mantarayas.db`) por simplicidad. Eso funciona bien en un App Service de una sola instancia, pero:

- Si tu plan escala a **varias instancias**, cada una tendría su propio archivo y verías datos inconsistentes entre ellas.
- Si el App Service reinicia el contenedor sin disco persistente configurado, podrías perder los datos.

Para producción con múltiples instancias o alta disponibilidad, lo recomendable es migrar a una base de datos administrada, por ejemplo **Azure Database for PostgreSQL**.

## Backup de tus datos

Mientras uses SQLite, tu información completa vive en el archivo `mantarayas.db`. Descárgalo periódicamente como respaldo.
