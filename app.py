"""
Mantarayas — backend real con Flask + SQLite, 100% Python.

El frontend (HTML/CSS/JS) vive dentro de este mismo archivo como una cadena
de texto (FRONTEND_HTML, al final del archivo) en vez de un archivo .html
aparte — así el repositorio no tiene ningún archivo de frontend suelto.
El contenido que ve el navegador es exactamente el mismo, solo cambia dónde
vive el texto.

- Autenticación por sesión de servidor (cookie firmada, httponly).
- Contraseñas con hash (nunca en texto plano ni expuestas al cliente).
- Control de acceso por rol aplicado en el servidor (RBAC real): un rol sin
  permiso recibe 403 aunque manipule las peticiones directamente.
- Los módulos del club (alumnos, pagos, asistencia, horarios, contabilidad,
  profesores) se guardan como bloques JSON versionados en SQLite bajo una
  clave por módulo.
"""
import json
import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

from flask import Flask, Response, g, jsonify, request, session
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("MANTARAYAS_DB_PATH", os.path.join(BASE_DIR, "mantarayas.db"))

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-in-production")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)

ROLES = ("super", "admin", "profesor", "recepcionista")

READ_ROLES = {
    "mantarayas:students": ("super", "admin", "profesor", "recepcionista"),
    "mantarayas:groups": ("super", "admin", "profesor", "recepcionista"),
    "mantarayas:payments": ("super", "admin", "profesor", "recepcionista"),
    "mantarayas:attendance": ("super", "admin", "profesor", "recepcionista"),
    "mantarayas:teachers": ("super", "admin", "profesor", "recepcionista"),
    "mantarayas:purchases": ("super", "admin"),
    "mantarayas:expenses": ("super", "admin"),
}
WRITE_ROLES = {
    "mantarayas:students": ("super", "admin", "recepcionista"),
    "mantarayas:groups": ("super", "admin"),
    "mantarayas:payments": ("super", "admin", "recepcionista"),
    "mantarayas:attendance": ("super", "admin", "profesor"),
    "mantarayas:teachers": ("super",),
    "mantarayas:purchases": ("super", "admin"),
    "mantarayas:expenses": ("super", "admin"),
}

DEFAULT_USERS = [
    dict(usuario="admin", password="Mantarayas2026", rol="super", nombre="Juan José", apellido="Fundador",
         correo="admin@mantarayas.co", profesor_nombre="", sede_asignada="Sede Principal"),
    dict(usuario="recepcion", password="Recepcion2026", rol="recepcionista", nombre="Recepción", apellido="Mantarayas",
         correo="recepcion@mantarayas.co", profesor_nombre="", sede_asignada="Sede Principal"),
    dict(usuario="aarias", password="Profesor2026", rol="profesor", nombre="Andrés", apellido="Arias",
         correo="aarias@mantarayas.co", profesor_nombre="Andrés Arias", sede_asignada="Sede Principal"),
    dict(usuario="agarcia", password="Profesor2026", rol="profesor", nombre="Andrea", apellido="García",
         correo="agarcia@mantarayas.co", profesor_nombre="Andrea García", sede_asignada="Sede Principal"),
    dict(usuario="jmolina", password="Profesor2026", rol="profesor", nombre="Juan José", apellido="Molina",
         correo="jmolina@mantarayas.co", profesor_nombre="Juan José Molina", sede_asignada="Sede Principal"),
]
DEFAULT_TEACHERS = ["Andrés Arias", "Andrea García", "Juan José Molina"]


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            usuario TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            rol TEXT NOT NULL,
            nombre TEXT DEFAULT '',
            apellido TEXT DEFAULT '',
            documento TEXT DEFAULT '',
            correo TEXT DEFAULT '',
            celular TEXT DEFAULT '',
            estado TEXT DEFAULT 'activo',
            profesor_nombre TEXT DEFAULT '',
            sede_asignada TEXT DEFAULT '',
            fecha_creacion TEXT,
            ultimo_ingreso TEXT
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS data_store (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT
        )
    """)
    db.commit()

    if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        now = datetime.now(timezone.utc).isoformat()
        for u in DEFAULT_USERS:
            db.execute(
                "INSERT INTO users (id, usuario, password_hash, rol, nombre, apellido, correo, estado, "
                "profesor_nombre, sede_asignada, fecha_creacion, ultimo_ingreso) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), u["usuario"], generate_password_hash(u["password"]), u["rol"], u["nombre"],
                 u["apellido"], u["correo"], "activo", u["profesor_nombre"], u["sede_asignada"], now, None),
            )
        db.commit()

    if db.execute("SELECT COUNT(*) FROM data_store WHERE key='mantarayas:teachers'").fetchone()[0] == 0:
        db.execute("INSERT INTO data_store (key, value, updated_at) VALUES (?,?,?)",
                   ("mantarayas:teachers", json.dumps(DEFAULT_TEACHERS), datetime.now(timezone.utc).isoformat()))
        db.commit()
    db.close()


def user_to_dict(row):
    return {
        "id": row["id"], "usuario": row["usuario"], "rol": row["rol"], "nombre": row["nombre"],
        "apellido": row["apellido"], "documento": row["documento"], "correo": row["correo"],
        "celular": row["celular"], "estado": row["estado"], "profesorNombre": row["profesor_nombre"],
        "sedeAsignada": row["sede_asignada"], "fechaCreacion": row["fecha_creacion"],
        "ultimoIngreso": row["ultimo_ingreso"],
    }


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    row = get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    return row


def require_auth():
    row = current_user()
    if not row:
        return None, (jsonify(error="No autenticado"), 401)
    if row["estado"] != "activo":
        return None, (jsonify(error="Cuenta desactivada"), 403)
    return row, None


def require_role(*roles):
    row, err = require_auth()
    if err:
        return None, err
    if row["rol"] not in roles:
        return None, (jsonify(error="Acceso denegado"), 403)
    return row, None


@app.route("/api/auth/login", methods=["POST"])
def login():
    body = request.get_json(silent=True) or {}
    usuario = (body.get("usuario") or "").strip().lower()
    password = body.get("password") or ""
    row = get_db().execute("SELECT * FROM users WHERE lower(usuario)=?", (usuario,)).fetchone()
    if not row or not check_password_hash(row["password_hash"], password):
        return jsonify(error="Usuario o contraseña incorrectos."), 401
    if row["estado"] != "activo":
        return jsonify(error="Esta cuenta está desactivada. Contacta a un administrador."), 403
    session.clear()
    session["user_id"] = row["id"]
    session.permanent = bool(body.get("remember"))
    now = datetime.now(timezone.utc).isoformat()
    db = get_db()
    db.execute("UPDATE users SET ultimo_ingreso=? WHERE id=?", (now, row["id"]))
    db.commit()
    row = db.execute("SELECT * FROM users WHERE id=?", (row["id"],)).fetchone()
    return jsonify(user_to_dict(row))


@app.route("/api/auth/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify(ok=True)


@app.route("/api/auth/me")
def me():
    row = current_user()
    if not row or row["estado"] != "activo":
        return jsonify(error="No autenticado"), 401
    return jsonify(user_to_dict(row))


@app.route("/api/users", methods=["GET"])
def list_users():
    _, err = require_role("super")
    if err:
        return err
    rows = get_db().execute("SELECT * FROM users ORDER BY nombre").fetchall()
    return jsonify([user_to_dict(r) for r in rows])


@app.route("/api/users", methods=["POST"])
def create_user():
    _, err = require_role("super")
    if err:
        return err
    body = request.get_json(silent=True) or {}
    usuario = (body.get("usuario") or "").strip().lower()
    password = body.get("password") or ""
    if not usuario or not (body.get("nombre") or "").strip() or not password:
        return jsonify(error="Usuario, nombre y contraseña son obligatorios"), 400
    if body.get("rol") not in ROLES:
        return jsonify(error="Rol inválido"), 400
    db = get_db()
    if db.execute("SELECT 1 FROM users WHERE lower(usuario)=?", (usuario,)).fetchone():
        return jsonify(error="Ese nombre de usuario ya existe"), 409
    uid = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT INTO users (id, usuario, password_hash, rol, nombre, apellido, documento, correo, celular, "
        "estado, profesor_nombre, sede_asignada, fecha_creacion, ultimo_ingreso) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (uid, usuario, generate_password_hash(password), body.get("rol"), body.get("nombre", "").strip(),
         body.get("apellido", ""), body.get("documento", ""), body.get("correo", ""), body.get("celular", ""),
         "activo", body.get("profesorNombre", "") if body.get("rol") == "profesor" else "",
         body.get("sedeAsignada", ""), now, None),
    )
    db.commit()
    row = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    return jsonify(user_to_dict(row)), 201


@app.route("/api/users/<uid>", methods=["PUT"])
def update_user(uid):
    _, err = require_role("super")
    if err:
        return err
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not row:
        return jsonify(error="Usuario no encontrado"), 404
    body = request.get_json(silent=True) or {}
    usuario = (body.get("usuario") or row["usuario"]).strip().lower()
    dupe = db.execute("SELECT 1 FROM users WHERE lower(usuario)=? AND id<>?", (usuario, uid)).fetchone()
    if dupe:
        return jsonify(error="Ese nombre de usuario ya existe"), 409
    rol = body.get("rol", row["rol"])
    if rol not in ROLES:
        return jsonify(error="Rol inválido"), 400
    password_hash = row["password_hash"]
    if body.get("password"):
        password_hash = generate_password_hash(body["password"])
    db.execute(
        "UPDATE users SET usuario=?, password_hash=?, rol=?, nombre=?, apellido=?, documento=?, correo=?, "
        "celular=?, profesor_nombre=?, sede_asignada=? WHERE id=?",
        (usuario, password_hash, rol, body.get("nombre", row["nombre"]), body.get("apellido", row["apellido"]),
         body.get("documento", row["documento"]), body.get("correo", row["correo"]),
         body.get("celular", row["celular"]),
         body.get("profesorNombre", row["profesor_nombre"]) if rol == "profesor" else "",
         body.get("sedeAsignada", row["sede_asignada"]), uid),
    )
    db.commit()
    row = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    return jsonify(user_to_dict(row))


@app.route("/api/users/<uid>/toggle", methods=["POST"])
def toggle_user(uid):
    actor, err = require_role("super")
    if err:
        return err
    if actor["id"] == uid:
        return jsonify(error="No puedes desactivar tu propia cuenta"), 400
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not row:
        return jsonify(error="Usuario no encontrado"), 404
    nuevo_estado = "inactivo" if row["estado"] == "activo" else "activo"
    db.execute("UPDATE users SET estado=? WHERE id=?", (nuevo_estado, uid))
    db.commit()
    return jsonify(ok=True, estado=nuevo_estado)


@app.route("/api/users/<uid>", methods=["DELETE"])
def delete_user(uid):
    actor, err = require_role("super")
    if err:
        return err
    if actor["id"] == uid:
        return jsonify(error="No puedes eliminar tu propia cuenta"), 400
    db = get_db()
    db.execute("DELETE FROM users WHERE id=?", (uid,))
    db.commit()
    return jsonify(ok=True)


@app.route("/api/data/<path:key>", methods=["GET"])
def get_data(key):
    row_user, err = require_auth()
    if err:
        return err
    allowed = READ_ROLES.get(key)
    if allowed is None or row_user["rol"] not in allowed:
        return jsonify(error="Acceso denegado"), 403
    row = get_db().execute("SELECT value FROM data_store WHERE key=?", (key,)).fetchone()
    return jsonify(value=json.loads(row["value"]) if row else None)


@app.route("/api/data/<path:key>", methods=["PUT"])
def put_data(key):
    row_user, err = require_auth()
    if err:
        return err
    allowed = WRITE_ROLES.get(key)
    if allowed is None or row_user["rol"] not in allowed:
        return jsonify(error="Acceso denegado"), 403

    body = request.get_json(silent=True) or {}
    value = body.get("value")

    if key == "mantarayas:attendance" and row_user["rol"] == "profesor":
        groups_row = get_db().execute("SELECT value FROM data_store WHERE key='mantarayas:groups'").fetchone()
        groups = json.loads(groups_row["value"]) if groups_row else []
        my_group_ids = {g["id"] for g in groups if g.get("entrenador") == row_user["profesor_nombre"]}
        for rec in value or []:
            if rec.get("groupId") not in my_group_ids:
                return jsonify(error="Solo puedes registrar asistencia de tus propios grupos"), 403

    db = get_db()
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT INTO data_store (key, value, updated_at) VALUES (?,?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
        (key, json.dumps(value), now),
    )
    db.commit()
    return jsonify(ok=True)


@app.route("/")
def index():
    return Response(FRONTEND_HTML, mimetype="text/html")


@app.route("/health")
def health():
    return jsonify(status="ok")


# ===========================================================================
# FRONTEND_MARKER_INSERT_HERE
FRONTEND_HTML = r"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Mantarayas · Panel del club</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#FAFBFC; --surface:#FFFFFF; --surface-2:#F1F5F7; --border:#E3E9EC;
  --ink:#0A1420; --ink-soft:#57707C; --ink-faint:#93A7AF;
  --primary:#0E6E8C; --primary-ink:#ffffff; --primary-soft:#E4F3F6; --primary-dark:#0A5670;
  --accent:#37B7A6;
  --success:#1E9E6D; --success-soft:#E4F7EE;
  --warning:#B9791F; --warning-soft:#FBF0DD;
  --danger:#C7373B; --danger-soft:#FBE7E7;
  --shadow-sm: 0 1px 2px rgba(10,20,32,.05);
  --shadow-md: 0 6px 24px rgba(10,20,32,.08);
  --shadow-lg: 0 18px 48px rgba(10,20,32,.14);
  --radius: 14px;
  --radius-sm: 9px;
  color-scheme: light;
}
html.dark{
  --bg:#0A141B; --surface:#101E27; --surface-2:#152730; --border:#20343F;
  --ink:#EAF3F5; --ink-soft:#9DB4BD; --ink-faint:#5E7981;
  --primary:#49C1DE; --primary-ink:#04222B; --primary-soft:#123542; --primary-dark:#78D7EE;
  --accent:#57E0CF;
  --success:#3FCB94; --success-soft:#123526;
  --warning:#E3AA53; --warning-soft:#33270F;
  --danger:#F0787B; --danger-soft:#391A1B;
  --shadow-sm: 0 1px 2px rgba(0,0,0,.3);
  --shadow-md: 0 6px 24px rgba(0,0,0,.35);
  --shadow-lg: 0 18px 48px rgba(0,0,0,.5);
  color-scheme: dark;
}
*{box-sizing:border-box;}
html,body{height:100%;}
body{
  margin:0; background:var(--bg); color:var(--ink);
  font-family:'Inter',system-ui,sans-serif; font-size:14px; line-height:1.5;
  -webkit-font-smoothing:antialiased;
  transition:background .25s ease, color .25s ease;
}
h1,h2,h3,h4,.display{ font-family:'Space Grotesk',system-ui,sans-serif; letter-spacing:-0.01em; }
::selection{ background:var(--accent); color:#04222B; }
a{color:inherit;}
button{ font-family:inherit; }
:focus-visible{ outline:2px solid var(--primary); outline-offset:2px; border-radius:6px; }

/* ---------- layout ---------- */
.app{ display:flex; min-height:100vh; }
.sidebar{
  width:248px; flex-shrink:0; background:var(--surface); border-right:1px solid var(--border);
  display:flex; flex-direction:column; position:sticky; top:0; height:100vh; padding:20px 14px;
}
.brand{ display:flex; align-items:center; gap:10px; padding:6px 8px 18px; }
.brand-mark{
  width:34px; height:34px; border-radius:10px; position:relative; overflow:hidden; flex-shrink:0;
  background:linear-gradient(160deg, var(--primary), var(--primary-dark) 70%);
  box-shadow: var(--shadow-sm);
}
.brand-mark svg{ position:absolute; inset:0; }
.brand-name{ font-family:'Space Grotesk'; font-weight:700; font-size:15.5px; line-height:1.15; }
.brand-sub{ font-size:11px; color:var(--ink-faint); font-weight:500; letter-spacing:.02em; }

.lanes{ height:1px; margin:2px 0 16px; background:
  repeating-linear-gradient(90deg, var(--border) 0 6px, transparent 6px 10px); }

.nav-group-label{ font-size:10.5px; font-weight:700; letter-spacing:.08em; color:var(--ink-faint); text-transform:uppercase; padding:14px 10px 6px; }
.nav{ display:flex; flex-direction:column; gap:2px; }
.nav-item{
  display:flex; align-items:center; gap:10px; padding:9px 10px; border-radius:9px; cursor:pointer;
  color:var(--ink-soft); font-weight:500; font-size:13.5px; border:none; background:none; width:100%; text-align:left;
  position:relative; transition:background .15s ease, color .15s ease;
}
.nav-item:hover{ background:var(--surface-2); color:var(--ink); }
.nav-item.active{ background:var(--primary-soft); color:var(--primary-dark); font-weight:600; }
html.dark .nav-item.active{ color:var(--primary); }
.nav-item .dot{ width:6px; height:6px; border-radius:50%; background:var(--accent); position:absolute; left:-2px; opacity:0; transition:opacity .15s; }
.nav-item.active .dot{ opacity:1; }
.nav-item svg{ width:17px; height:17px; flex-shrink:0; }
.nav-item .count{ margin-left:auto; font-size:11px; background:var(--surface-2); color:var(--ink-faint); padding:1px 7px; border-radius:99px; font-weight:600; }
.nav-item.active .count{ background:var(--primary); color:var(--primary-ink); }

.sidebar-footer{ margin-top:auto; display:flex; flex-direction:column; gap:8px; }
.role-card{ background:var(--surface-2); border:1px solid var(--border); border-radius:var(--radius-sm); padding:10px; }
.role-card label{ font-size:10px; text-transform:uppercase; letter-spacing:.06em; color:var(--ink-faint); font-weight:700; }
.role-select, select, input, textarea{
  font-family:inherit; font-size:13px; color:var(--ink); background:var(--surface);
  border:1px solid var(--border); border-radius:8px; padding:7px 9px; width:100%;
}
.role-select{ margin-top:5px; background:var(--surface); cursor:pointer; }

/* ---------- main ---------- */
.main{ flex:1; min-width:0; display:flex; flex-direction:column; }
.topbar{
  display:flex; align-items:center; gap:14px; padding:14px 26px; border-bottom:1px solid var(--border);
  background:var(--surface); position:sticky; top:0; z-index:20;
}
.search-wrap{ position:relative; flex:1; max-width:420px; }
.search-wrap svg{ position:absolute; left:11px; top:50%; transform:translateY(-50%); width:15px; height:15px; color:var(--ink-faint); }
.search-input{ width:100%; padding:9px 12px 9px 32px; border-radius:10px; background:var(--surface-2); border:1px solid transparent; }
.search-input:focus{ background:var(--surface); border-color:var(--primary); }
.topbar-right{ margin-left:auto; display:flex; align-items:center; gap:10px; }
.icon-btn{
  width:34px; height:34px; border-radius:9px; border:1px solid var(--border); background:var(--surface);
  display:flex; align-items:center; justify-content:center; cursor:pointer; color:var(--ink-soft);
}
.icon-btn:hover{ background:var(--surface-2); color:var(--ink); }
.icon-btn svg{ width:16px; height:16px; }

.view{ display:none; padding:26px; max-width:1320px; width:100%; margin:0 auto; }
.view.active{ display:block; animation:fadein .28s ease; }
@keyframes fadein{ from{opacity:0; transform:translateY(4px);} to{opacity:1; transform:none;} }

.view-header{ display:flex; align-items:flex-end; justify-content:space-between; margin-bottom:22px; gap:12px; flex-wrap:wrap; }
.view-title{ font-size:22px; font-weight:700; margin:0 0 3px; }
.view-desc{ color:var(--ink-soft); font-size:13px; margin:0; }

.btn{
  display:inline-flex; align-items:center; gap:7px; padding:9px 14px; border-radius:9px; border:1px solid var(--border);
  background:var(--surface); color:var(--ink); font-weight:600; font-size:13px; cursor:pointer; white-space:nowrap;
  transition:transform .1s ease, box-shadow .15s ease;
}
.btn:hover{ box-shadow:var(--shadow-sm); }
.btn:active{ transform:scale(.98); }
.btn svg{ width:15px; height:15px; }
.btn-primary{ background:var(--primary); border-color:var(--primary); color:var(--primary-ink); }
.btn-primary:hover{ box-shadow:0 6px 18px rgba(14,110,140,.28); }
.btn-danger{ color:var(--danger); }
.btn-sm{ padding:6px 10px; font-size:12.5px; }
.btn-ghost{ border-color:transparent; background:transparent; }
.btn-ghost:hover{ background:var(--surface-2); }

/* KPI cards */
.kpi-grid{ display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:12px; margin-bottom:20px; }
.kpi-card{ background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); padding:16px; position:relative; overflow:hidden; }
.kpi-label{ font-size:12px; color:var(--ink-soft); font-weight:600; display:flex; align-items:center; gap:6px; }
.kpi-value{ font-family:'Space Grotesk'; font-size:26px; font-weight:700; margin-top:6px; }
.kpi-sub{ font-size:11.5px; color:var(--ink-faint); margin-top:3px; }
.kpi-card .spark{ position:absolute; right:10px; bottom:10px; opacity:.5; }

.card{ background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); }
.card-pad{ padding:18px; }
.card-head{ display:flex; align-items:center; justify-content:space-between; padding:16px 18px; border-bottom:1px solid var(--border); }
.card-head h3{ margin:0; font-size:14.5px; }

.grid-2{ display:grid; grid-template-columns:1.3fr 1fr; gap:14px; }
.grid-3{ display:grid; grid-template-columns:repeat(3,1fr); gap:14px; }
@media (max-width:980px){ .grid-2,.grid-3{ grid-template-columns:1fr; } }

/* table */
.table-wrap{ overflow-x:auto; }
table{ width:100%; border-collapse:collapse; font-size:13px; }
thead th{ text-align:left; font-size:11px; text-transform:uppercase; letter-spacing:.04em; color:var(--ink-faint); font-weight:700; padding:10px 14px; border-bottom:1px solid var(--border); white-space:nowrap; }
tbody td{ padding:11px 14px; border-bottom:1px solid var(--border); vertical-align:middle; }
tbody tr{ cursor:pointer; transition:background .12s ease; }
tbody tr:hover{ background:var(--surface-2); }
tbody tr:last-child td{ border-bottom:none; }
.cell-name{ font-weight:600; }
.cell-sub{ font-size:11.5px; color:var(--ink-faint); }

.badge{ display:inline-flex; align-items:center; gap:5px; font-size:11.5px; font-weight:700; padding:3px 9px; border-radius:99px; }
.badge-dot{ width:6px; height:6px; border-radius:50%; }
.badge-success{ background:var(--success-soft); color:var(--success); }
.badge-warning{ background:var(--warning-soft); color:var(--warning); }
.badge-danger{ background:var(--danger-soft); color:var(--danger); }
.badge-neutral{ background:var(--surface-2); color:var(--ink-soft); }
.badge-primary{ background:var(--primary-soft); color:var(--primary-dark); }
html.dark .badge-primary{ color:var(--primary); }

.toolbar{ display:flex; align-items:center; gap:8px; margin-bottom:14px; flex-wrap:wrap; }
.toolbar select, .toolbar input{ width:auto; }
.pill-tabs{ display:flex; gap:4px; background:var(--surface-2); padding:3px; border-radius:10px; }
.pill-tab{ padding:7px 12px; border-radius:8px; font-size:12.5px; font-weight:600; color:var(--ink-soft); cursor:pointer; border:none; background:none; }
.pill-tab.active{ background:var(--surface); color:var(--ink); box-shadow:var(--shadow-sm); }

.empty{ text-align:center; padding:50px 20px; color:var(--ink-faint); }
.empty svg{ width:40px; height:40px; margin-bottom:10px; opacity:.5; }

/* modal */
.overlay{ position:fixed; inset:0; background:rgba(6,12,18,.5); backdrop-filter:blur(2px); display:none; align-items:center; justify-content:center; z-index:100; padding:20px; }
.overlay.active{ display:flex; }
.modal{ background:var(--surface); border-radius:16px; width:100%; max-width:640px; max-height:88vh; display:flex; flex-direction:column; box-shadow:var(--shadow-lg); animation:pop .18s ease; }
@keyframes pop{ from{opacity:0; transform:scale(.97) translateY(6px);} to{opacity:1; transform:none;} }
.modal-head{ display:flex; align-items:center; justify-content:space-between; padding:18px 20px; border-bottom:1px solid var(--border); }
.modal-head h3{ margin:0; font-size:16px; }
.modal-body{ padding:20px; overflow-y:auto; }
.modal-foot{ padding:14px 20px; border-top:1px solid var(--border); display:flex; justify-content:flex-end; gap:8px; }

.field{ margin-bottom:13px; }
.field label{ display:block; font-size:12px; font-weight:600; color:var(--ink-soft); margin-bottom:5px; }
.field-row{ display:grid; grid-template-columns:1fr 1fr; gap:10px; }
.field-row3{ display:grid; grid-template-columns:1fr 1fr 1fr; gap:10px; }
.hint{ font-size:11px; color:var(--ink-faint); margin-top:4px; }

.toast-stack{ position:fixed; bottom:20px; right:20px; z-index:200; display:flex; flex-direction:column; gap:8px; }
.toast{ background:var(--ink); color:var(--bg); padding:11px 16px; border-radius:10px; font-size:13px; font-weight:600; box-shadow:var(--shadow-lg); display:flex; align-items:center; gap:8px; animation:toastin .2s ease; }
html.dark .toast{ background:var(--surface-2); color:var(--ink); border:1px solid var(--border); }
@keyframes toastin{ from{opacity:0; transform:translateY(8px);} to{opacity:1; transform:none;} }

.drawer-overlay{ position:fixed; inset:0; background:rgba(6,12,18,.45); display:none; z-index:90; }
.drawer-overlay.active{ display:block; }
.drawer{ position:fixed; top:0; right:0; height:100vh; width:min(460px,100%); background:var(--surface); box-shadow:var(--shadow-lg); z-index:95; transform:translateX(100%); transition:transform .25s ease; display:flex; flex-direction:column; }
.drawer.active{ transform:translateX(0); }
.drawer-head{ padding:20px; border-bottom:1px solid var(--border); }
.drawer-body{ padding:20px; overflow-y:auto; flex:1; }
.avatar{ width:46px; height:46px; border-radius:50%; background:var(--primary-soft); color:var(--primary-dark); display:flex; align-items:center; justify-content:center; font-weight:700; font-family:'Space Grotesk'; font-size:16px; }
html.dark .avatar{ color:var(--primary); }
.drawer-tabs{ display:flex; gap:2px; border-bottom:1px solid var(--border); padding:0 20px; }
.drawer-tab{ padding:10px 4px; margin-right:16px; font-size:12.5px; font-weight:600; color:var(--ink-faint); border:none; background:none; cursor:pointer; border-bottom:2px solid transparent; }
.drawer-tab.active{ color:var(--primary); border-color:var(--primary); }
.kv{ display:flex; justify-content:space-between; padding:8px 0; border-bottom:1px dashed var(--border); font-size:13px; }
.kv:last-child{ border-bottom:none; }
.kv span:first-child{ color:var(--ink-faint); }
.kv span:last-child{ font-weight:600; text-align:right; }

.check-row{ display:flex; align-items:center; justify-content:space-between; padding:9px 0; border-bottom:1px solid var(--border); font-size:13px; }
.check-row:last-child{ border-bottom:none; }
.switch{ position:relative; width:36px; height:21px; }
.switch input{ opacity:0; width:0; height:0; }
.switch .slider{ position:absolute; inset:0; background:var(--border); border-radius:99px; cursor:pointer; transition:.2s; }
.switch .slider:before{ content:''; position:absolute; width:15px; height:15px; left:3px; top:3px; background:#fff; border-radius:50%; transition:.2s; }
.switch input:checked + .slider{ background:var(--success); }
.switch input:checked + .slider:before{ transform:translateX(15px); }

.att-options{ display:flex; gap:4px; flex-wrap:wrap; }
.att-opt{ padding:5px 9px; border-radius:7px; border:1px solid var(--border); font-size:11.5px; font-weight:600; cursor:pointer; background:var(--surface); color:var(--ink-soft); }
.att-opt.sel-asistio.selected{ background:var(--success-soft); border-color:var(--success); color:var(--success); }
.att-opt.sel-tarde.selected{ background:var(--warning-soft); border-color:var(--warning); color:var(--warning); }
.att-opt.sel-falta.selected{ background:var(--danger-soft); border-color:var(--danger); color:var(--danger); }
.att-opt.sel-incapacidad.selected, .att-opt.sel-permiso.selected{ background:var(--primary-soft); border-color:var(--primary); color:var(--primary-dark); }

.bar-chart{ display:flex; align-items:flex-end; gap:10px; height:150px; padding-top:10px; }
.bar-col{ flex:1; display:flex; flex-direction:column; align-items:center; gap:6px; height:100%; justify-content:flex-end; }
.bar{ width:100%; max-width:34px; border-radius:6px 6px 2px 2px; background:linear-gradient(180deg, var(--primary), var(--primary-dark)); transition:height .5s cubic-bezier(.2,.8,.2,1); }
.bar-label{ font-size:10.5px; color:var(--ink-faint); font-weight:600; }
.bar-val{ font-size:11px; color:var(--ink-soft); font-weight:700; }

.donut-wrap{ display:flex; align-items:center; gap:18px; }
.legend{ display:flex; flex-direction:column; gap:8px; font-size:12.5px; }
.legend-item{ display:flex; align-items:center; gap:7px; }
.legend-dot{ width:9px; height:9px; border-radius:3px; flex-shrink:0; }

.grid-2col{ display:grid; grid-template-columns:repeat(auto-fill,minmax(300px,1fr)); gap:12px; }

/* ---------- login ---------- */
.login-screen{ min-height:100vh; display:flex; align-items:center; justify-content:center; background:
  radial-gradient(1200px 600px at 15% -10%, var(--primary-soft), transparent 60%),
  radial-gradient(900px 500px at 110% 110%, var(--primary-soft), transparent 60%), var(--bg); padding:20px; }
.login-card{ width:100%; max-width:380px; background:var(--surface); border:1px solid var(--border); border-radius:20px; box-shadow:var(--shadow-lg); padding:32px 30px; animation:pop .25s ease; }
.login-brand{ display:flex; flex-direction:column; align-items:center; text-align:center; margin-bottom:22px; }
.login-mark{ width:52px; height:52px; border-radius:15px; background:linear-gradient(160deg, var(--primary), var(--primary-dark) 70%); display:flex; align-items:center; justify-content:center; margin-bottom:12px; box-shadow:var(--shadow-md); }
.login-title{ font-family:'Space Grotesk'; font-weight:700; font-size:19px; }
.login-sub{ color:var(--ink-soft); font-size:12.5px; margin-top:2px; }
.pw-wrap{ position:relative; }
.pw-wrap input{ padding-right:38px; }
.pw-toggle{ position:absolute; right:9px; top:50%; transform:translateY(-50%); background:none; border:none; cursor:pointer; color:var(--ink-faint); padding:2px; }
.pw-toggle svg{ width:17px; height:17px; }
.login-row{ display:flex; align-items:center; justify-content:space-between; margin:12px 0 18px; font-size:12.5px; }
.remember-wrap{ display:flex; align-items:center; gap:6px; color:var(--ink-soft); }
.remember-wrap input{ width:auto; }
.link-btn{ background:none; border:none; color:var(--primary); font-weight:600; cursor:pointer; font-size:12.5px; padding:0; }
.login-error{ background:var(--danger-soft); color:var(--danger); font-size:12.5px; font-weight:600; padding:9px 12px; border-radius:9px; margin-bottom:14px; display:none; }
.login-error.active{ display:block; }
.demo-creds{ margin-top:20px; padding:12px 13px; background:var(--surface-2); border-radius:11px; font-size:11.5px; color:var(--ink-soft); }
.demo-creds b{ color:var(--ink); }
.demo-creds table{ width:100%; margin-top:6px; }
.demo-creds td{ padding:2px 0; border:none; font-size:11px; }

.access-denied{ text-align:center; padding:80px 20px; }
.access-denied svg{ width:52px; height:52px; color:var(--danger); margin-bottom:14px; }

@media (max-width:860px){
  .sidebar{ position:fixed; left:-260px; z-index:80; transition:left .2s ease; box-shadow:var(--shadow-lg); }
  .sidebar.open{ left:0; }
  .field-row, .field-row3{ grid-template-columns:1fr; }
}
::-webkit-scrollbar{ width:9px; height:9px; }
::-webkit-scrollbar-thumb{ background:var(--border); border-radius:99px; }

/* ---------- login ---------- */
.login-wrap{ min-height:100vh; display:flex; align-items:center; justify-content:center; background:
  radial-gradient(circle at 15% 20%, var(--primary-soft), transparent 45%),
  radial-gradient(circle at 85% 80%, var(--primary-soft), transparent 40%), var(--bg); padding:20px; }
.login-card{ width:100%; max-width:380px; background:var(--surface); border:1px solid var(--border); border-radius:18px; padding:32px 28px; box-shadow:var(--shadow-lg); animation:pop .25s ease; }
.login-logo{ display:flex; flex-direction:column; align-items:center; gap:10px; margin-bottom:22px; }
.login-mark{ width:52px; height:52px; border-radius:15px; background:linear-gradient(160deg, var(--primary), var(--primary-dark) 70%); display:flex; align-items:center; justify-content:center; box-shadow:var(--shadow-md); position:relative; overflow:hidden; }
.login-title{ font-family:'Space Grotesk'; font-weight:700; font-size:19px; text-align:center; }
.login-sub{ font-size:12.5px; color:var(--ink-soft); text-align:center; }
.pw-wrap{ position:relative; }
.pw-toggle{ position:absolute; right:9px; top:50%; transform:translateY(-50%); background:none; border:none; color:var(--ink-faint); cursor:pointer; padding:4px; }
.pw-toggle svg{ width:16px; height:16px; }
.login-error{ background:var(--danger-soft); color:var(--danger); font-size:12.5px; font-weight:600; padding:9px 11px; border-radius:9px; margin-bottom:14px; display:none; }
.login-error.active{ display:block; }
.login-row{ display:flex; align-items:center; justify-content:space-between; font-size:12.5px; margin:4px 0 18px; }
.checkbox-line{ display:flex; align-items:center; gap:6px; color:var(--ink-soft); cursor:pointer; }
.checkbox-line input{ width:auto; }
.link-btn{ background:none; border:none; color:var(--primary); font-weight:600; font-size:12.5px; cursor:pointer; padding:0; }
.demo-creds{ margin-top:18px; border-top:1px solid var(--border); padding-top:14px; }
.demo-creds summary{ cursor:pointer; font-size:12px; font-weight:600; color:var(--ink-soft); }
.demo-creds table{ margin-top:10px; }
.demo-creds td{ padding:3px 6px 3px 0; font-size:11.5px; border:none; color:var(--ink-soft); }
.access-denied{ display:flex; flex-direction:column; align-items:center; justify-content:center; padding:80px 20px; text-align:center; color:var(--ink-soft); }
.access-denied svg{ width:44px; height:44px; color:var(--danger); margin-bottom:14px; }
</style>
</head>
<body>

<div id="loginScreen"></div>

<div class="app" id="appRoot" style="display:none;">
  <aside class="sidebar" id="sidebar">
    <div class="brand">
      <div class="brand-mark">
        <svg viewBox="0 0 34 34" fill="none"><path d="M4 20c4-9 10-13 13-13 2 0 2 2 0 3-6 3-9 8-9 12 0 3 2 4 4 2 3-3 4-9 8-9 3 0 4 3 2 5-2 2-2 4 1 4 4 0 8-4 10-8" stroke="white" stroke-width="1.6" stroke-linecap="round"/></svg>
      </div>
      <div>
        <div class="brand-name">Mantarayas</div>
        <div class="brand-sub">Panel del club</div>
      </div>
    </div>
    <div class="lanes"></div>
    <nav class="nav" id="navList"></nav>

    <div class="sidebar-footer">
      <div class="role-card" id="sessionCard">
        <div style="display:flex; align-items:center; gap:9px;">
          <div class="avatar" style="width:34px;height:34px;font-size:12px;" id="sessionAvatar">--</div>
          <div style="min-width:0;">
            <div style="font-weight:700; font-size:12.5px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;" id="sessionName">—</div>
            <div style="font-size:10.5px; color:var(--ink-faint);" id="sessionRole">—</div>
          </div>
        </div>
        <button class="btn btn-sm" id="logoutBtn" style="width:100%; justify-content:center; margin-top:9px;">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/></svg>
          Cerrar sesión
        </button>
      </div>
      <button class="btn btn-sm" id="resetBtn" style="justify-content:center; display:none;">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12a9 9 0 1 0 3-6.7M3 4v5h5"/></svg>
        Restablecer datos de ejemplo
      </button>
    </div>
  </aside>

  <div class="main">
    <div class="topbar">
      <button class="icon-btn" id="menuBtn" style="display:none;">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 7h16M4 12h16M4 17h16"/></svg>
      </button>
      <div class="search-wrap">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg>
        <input class="search-input" id="globalSearch" placeholder="Buscar por nombre, documento o celular…">
      </div>
      <div id="globalSearchResults" class="card" style="position:absolute; top:58px; left:290px; width:420px; max-height:320px; overflow-y:auto; display:none; z-index:30; box-shadow:var(--shadow-lg);"></div>
      <div class="topbar-right">
        <button class="icon-btn" id="themeToggle" title="Cambiar tema">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" id="themeIcon"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>
        </button>
      </div>
    </div>

    <!-- VIEWS -->
    <div id="viewRoot"></div>
  </div>
</div>

<div class="drawer-overlay" id="drawerOverlay"></div>
<div class="drawer" id="studentDrawer"></div>

<div class="overlay" id="modalOverlay"><div class="modal" id="modalRoot"></div></div>

<div class="toast-stack" id="toastStack"></div>

<script>
const SEED_STUDENTS = [{"id":"st001","nombre":"Jimena Villa Alvarez","documento":"1036403600","fechaNacimiento":"1998-07-31","edad":27,"eps":"SURA","celular":"3136743123","horarios":["L5-6","M 4-5"],"nClases":8,"matricula":false,"estadoPago":"cortesia","estado":"activo"},{"id":"st002","nombre":"Ana Sofia Gomez","documento":"","fechaNacimiento":"2015-01-23","edad":11,"eps":"SURA","celular":"3195139148","horarios":["V3-4"],"nClases":4,"matricula":false,"estadoPago":"cortesia","estado":"activo"},{"id":"st003","nombre":"Biviana Maria Oviedo Buritica","documento":"21628811","fechaNacimiento":"1985-10-07","edad":40,"eps":"SURA","celular":"3207158689","horarios":["M4-5","V3-4"],"nClases":8,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st004","nombre":"Valentina Montoya Gómez","documento":"1036404322","fechaNacimiento":"1999-03-06","edad":27,"eps":"SURA","celular":"3045863529","horarios":["M5-6"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st005","nombre":"Maria Alejandra Tobon Gómez","documento":"1036403585","fechaNacimiento":"1998-07-20","edad":27,"eps":"Nueva EPS","celular":"3226145312","horarios":["M5-6"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st006","nombre":"Sara Osorio Arboleda","documento":"","fechaNacimiento":"1998-11-03","edad":27,"eps":"SURA","celular":"3116400359","horarios":["M4-5","V3-4"],"nClases":8,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st007","nombre":"Pablo Alzate Cardona","documento":"Rc 10353322190","fechaNacimiento":"2019-06-28","edad":6,"eps":"Salud total","celular":"3217248381","horarios":["V3-4"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st008","nombre":"Aleida Velásquez Alzate","documento":"43711998","fechaNacimiento":"1972-02-25","edad":54,"eps":"SURA","celular":"3193994918","horarios":["V10-11"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st009","nombre":"Valentina Cardona Velásquez","documento":"1036404606","fechaNacimiento":"1999-07-03","edad":26,"eps":"SURA","celular":"3193994918","horarios":["V3-4"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st010","nombre":"Lorena Quintero","documento":"","fechaNacimiento":"1999-05-20","edad":27,"eps":"SURA","celular":"3145206942","horarios":["X9-10","V9-10"],"nClases":8,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st011","nombre":"Alejandro Chica Gonzalez","documento":"TI 1036403095","fechaNacimiento":"2016-02-12","edad":10,"eps":"SURA","celular":"3022157922","horarios":["M4-5"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st012","nombre":"Viviana Osorio Arboleda","documento":"1036392070","fechaNacimiento":"1986-03-23","edad":40,"eps":"SURA","celular":"3117612384","horarios":["V3-4"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st013","nombre":"Emilia Ortega Osorio","documento":"T.I 1023547534","fechaNacimiento":"2018-09-10","edad":7,"eps":"SURA","celular":"3117612284","horarios":["M4-5","V3-4"],"nClases":8,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st014","nombre":"Mariana Franco Orozco","documento":"1001478393","fechaNacimiento":"2001-12-29","edad":24,"eps":"SURA","celular":"3205476298","horarios":["X9-10"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st015","nombre":"Rebeca Arroyo Martinez","documento":"TI 1034302919","fechaNacimiento":"","edad":14,"eps":"SURA","celular":"3045855395","horarios":["L4-5","V3-4"],"nClases":8,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st016","nombre":"Sirley Ramirez Arbelaez","documento":"1036405072","fechaNacimiento":"1999-12-10","edad":26,"eps":"SURA","celular":"3146309576","horarios":["L5-6"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st017","nombre":"Luciana Alvarez Quintero","documento":"RC 1040892876","fechaNacimiento":"2025-04-09","edad":null,"eps":"SURA","celular":"3017051154","horarios":["V2-3"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st018","nombre":"Martín Fonseca Quintero","documento":"1035333758","fechaNacimiento":"2024-10-07","edad":null,"eps":"SURA","celular":"3197289401– 3192778039","horarios":["V2-3"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st019","nombre":"Sofia Cordoba Osorno","documento":"1011397678","fechaNacimiento":"2007-12-17","edad":18,"eps":"SUMIMEDICAL","celular":"3042904064","horarios":["X9-10"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st020","nombre":"Jose Oveider Zuluaga Jimenez","documento":"1036395291","fechaNacimiento":"1990-04-09","edad":36,"eps":"SANITAS","celular":"3122873531","horarios":["M5-6","X9-10"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st021","nombre":"Salome valencia López","documento":"RC 1036406601","fechaNacimiento":"2024-09-17","edad":null,"eps":"SURA","celular":"3148753646","horarios":["V2-3"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st022","nombre":"Johan Sebastian Bran Rivera","documento":"TI 1038336521","fechaNacimiento":"2012-08-20","edad":13,"eps":"NUEVA EPS","celular":"3135487119","horarios":["M4-5","V3-4"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st023","nombre":"Verónica María Bran Rivera","documento":"1039290049","fechaNacimiento":"1996-07-08","edad":29,"eps":"NUEVA EPS","celular":"3135487119","horarios":["M4-5"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st024","nombre":"Maylin Valentina Gamboa Martinez","documento":"TI 1093603287","fechaNacimiento":"2012-08-07","edad":13,"eps":"SURA","celular":"3108371410","horarios":["M4-5"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st025","nombre":"Claudia Patricia Quintero Jimenez","documento":"1036779972","fechaNacimiento":"1989-04-07","edad":37,"eps":"SURA","celular":"3122875538","horarios":["V9-10"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st026","nombre":"Maria Celeste Baena Garcio","documento":"RC 1035333833","fechaNacimiento":"2025-01-12","edad":null,"eps":"SURA","celular":"3104847837","horarios":["V2-3"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st027","nombre":"Juan Felipe Palacio","documento":"TI 1037779664","fechaNacimiento":"2015-12-26","edad":10,"eps":"SURA","celular":"3233955774","horarios":["X9-10","V9-10"],"nClases":8,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st028","nombre":"Salome Palacio","documento":"TI 1037779413","fechaNacimiento":"2013-12-14","edad":12,"eps":"SURA","celular":"3233955774-3122177046","horarios":["L4-5","M5-6"],"nClases":8,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st029","nombre":"Lian David Arango Ciro","documento":"RC 1036406729","fechaNacimiento":"2025-04-30","edad":null,"eps":"SURA","celular":"3128967551","horarios":["V2-3"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st030","nombre":"Gladys Amparo Quintero Muñoz","documento":"43714451","fechaNacimiento":"1978-10-15","edad":47,"eps":"NUEVA EPS","celular":"3114349770","horarios":["L5-6","X10-11"],"nClases":8,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st031","nombre":"Jennifer Lopez Quintero","documento":"1036255577","fechaNacimiento":"2008-01-12","edad":18,"eps":"NUEVA EPS","celular":"3114349770","horarios":["L5-6"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st032","nombre":"Sara Isabel Jaramillo Gómez","documento":"TI 10340881772","fechaNacimiento":"2013-03-03","edad":13,"eps":"SURA","celular":"3127019093","horarios":["L4-5","M5-6"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st033","nombre":"Valeria Jaramillo Gomez","documento":"TI 1036405046","fechaNacimiento":"2017-12-31","edad":8,"eps":"SURA","celular":"3127019093","horarios":["L4-5","M5-6"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st034","nombre":"Yesika Cristina Taborda Ramírez","documento":"1020402782","fechaNacimiento":"1986-12-15","edad":39,"eps":"SURA","celular":"3172606996","horarios":["M5-6"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st035","nombre":"Flor Maria Jaramillo","documento":"43712841","fechaNacimiento":"1969-04-20","edad":null,"eps":"SURA","celular":"3218127692","horarios":["X10-11","V10-11"],"nClases":8,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st036","nombre":"John Fredy Gonzalez Ramirez","documento":"71115259","fechaNacimiento":"1975-06-13","edad":50,"eps":"NUEVA EPS","celular":"3196535339","horarios":["V9-10"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st037","nombre":"Violetta Correa Gomez","documento":"RC 1035333753","fechaNacimiento":"2024-10-10","edad":null,"eps":"SURA","celular":"3215464533","horarios":["V2-3"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st038","nombre":"Violeta Gomez Garcia","documento":"TI 1035332197","fechaNacimiento":"2019-06-11","edad":7,"eps":"Savia Salud","celular":"3215644470","horarios":["M4-5","V3-4"],"nClases":8,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st039","nombre":"Nidia Soley Arrubla Cañaveral","documento":"43898505","fechaNacimiento":"1976-12-15","edad":49,"eps":"SURA","celular":"3147332558","horarios":["X10-11","V10-11"],"nClases":8,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st040","nombre":"Adriana Maria Osorno Pérez","documento":"43623284","fechaNacimiento":"1975-06-04","edad":51,"eps":"SUMIMEDICAL","celular":"3042904064","horarios":["X10-11","V10-11"],"nClases":8,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st041","nombre":"Luciana Henao Ortiz","documento":"RC 1036968102","fechaNacimiento":"2018-11-03","edad":7,"eps":"Nueva EPS","celular":"3122102697","horarios":["V3-4"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st042","nombre":"Mariana Peláez Arias","documento":"1045024625","fechaNacimiento":"1997-01-13","edad":29,"eps":"Sanitas S.A","celular":"3194534413","horarios":["M4-5"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st043","nombre":"Emanuel Salas Giraldo","documento":"1066291976","fechaNacimiento":"2013-10-01","edad":12,"eps":"SANIDAD MILITAR","celular":"3003097188","horarios":["M4-5","V3-4"],"nClases":8,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st044","nombre":"Viviana Salazar Vargas","documento":"1036401384","fechaNacimiento":"1996-03-24","edad":30,"eps":"SURA","celular":"3003182637","horarios":["M5-6"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st045","nombre":"Lina Maria Ososrio Osorio","documento":"1010007104","fechaNacimiento":"2000-03-12","edad":26,"eps":"Summinedical - FOMAG","celular":"3136580253","horarios":["M4-5","V3-4"],"nClases":8,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st046","nombre":"Emiliano Garcia Coy","documento":"RC 1035333194","fechaNacimiento":"2023-01-16","edad":3,"eps":"NUEVA EPS","celular":"3197483125 - 3136135319","horarios":["V2-3"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st047","nombre":"Ivan Castellanos Franco","documento":"1032399002","fechaNacimiento":"1987-11-04","edad":38,"eps":"SURA","celular":"3114443698","horarios":["X9-10","V9-10"],"nClases":8,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st048","nombre":"Karol Michell Mancera Gomez","documento":"1036404463","fechaNacimiento":"2017-05-09","edad":9,"eps":"Nueva EPS","celular":"3146542781","horarios":["V3-4"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st049","nombre":"Erik Alejandro Uribe Patiño","documento":"1036264593","fechaNacimiento":"2020-03-25","edad":6,"eps":"SURA","celular":"3146067873","horarios":["V3-4"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st050","nombre":"Liliana Arbelaez Betancur","documento":"1036395676","fechaNacimiento":"1990-09-04","edad":36,"eps":"SURA","celular":"3113854516","horarios":["X10-11","V10-11"],"nClases":8,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st051","nombre":"Samuel Quintero Montoya","documento":"TI 1122414745","fechaNacimiento":"2015-07-14","edad":10,"eps":"SANITAS","celular":"3148753470","horarios":["V9-10"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st052","nombre":"Maria Elena Lopez Castaño","documento":"43712577","fechaNacimiento":"1973-11-27","edad":52,"eps":"SURA","celular":"3192050357","horarios":["X9-10","V9-10"],"nClases":8,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st053","nombre":"Maria Alejandra Posada Gomez","documento":"TI 1040886548","fechaNacimiento":"2017-02-12","edad":9,"eps":"SURA","celular":"3192050357","horarios":["X10-11","V10-11"],"nClases":8,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st054","nombre":"Duber Pérez Hernandez","documento":"TI 1040882683","fechaNacimiento":"2013-12-25","edad":12,"eps":"SURA","celular":"3128078682","horarios":["L4-5","M4-5"],"nClases":8,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st055","nombre":"Erika Jazmin Hernandez Jaramillo","documento":"1036393650","fechaNacimiento":"1988-06-05","edad":37,"eps":"NUEVA EPS","celular":"3128078688","horarios":["V10-11"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st056","nombre":"Jhonatan Yamid Alzate Gallego","documento":"1036404796","fechaNacimiento":"1999-10-17","edad":26,"eps":"SURA","celular":"3192934969","horarios":["X9-10","V9-10"],"nClases":8,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st057","nombre":"Leidy Johana Bran Rivera","documento":"1039288650","fechaNacimiento":"1993-12-15","edad":32,"eps":"NUEVA EPS","celular":"3218143819","horarios":["M4-5"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st058","nombre":"Agustin Gomez Gomez","documento":"TI 1038874582","fechaNacimiento":"2017-06-03","edad":9,"eps":"SURA","celular":"3105364648","horarios":["M4-5"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st059","nombre":"Emiliano Garcia Perez","documento":"TI 1234438787","fechaNacimiento":"2017-09-20","edad":8,"eps":"SURA","celular":"314754465","horarios":["L4-5"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st060","nombre":"Yon Alexander Arbelaez Martinez","documento":"1036404196","fechaNacimiento":"1999-02-11","edad":27,"eps":"NUEVA EPS","celular":"3192911819","horarios":["M5-6"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st061","nombre":"Maxilimiliano Orozco Gómez","documento":"Rc","fechaNacimiento":"2021-01-20","edad":5,"eps":"SURA","celular":"3207424469","horarios":["M4-5","V3-4"],"nClases":8,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st062","nombre":"Yon Alexander Arbelaez Martinez","documento":"1036404196","fechaNacimiento":"1999-02-11","edad":27,"eps":"NUEVA EPS","celular":"3192911819","horarios":["M5-6"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st063","nombre":"Isabella henao Vargas","documento":"TI 1036259235","fechaNacimiento":"2010-11-14","edad":15,"eps":"SURA","celular":"3106429458","horarios":["V3-4"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st064","nombre":"Maria Edelmira Garcia Ramirez","documento":"21624668","fechaNacimiento":"1954-12-10","edad":71,"eps":"SURA","celular":"3148511923","horarios":["V10-11"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st065","nombre":"Mónica Natalia Gómez García","documento":"1036401345","fechaNacimiento":"1996-05-02","edad":30,"eps":"Nueva EPS","celular":"3226399796","horarios":["M5-6"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st066","nombre":"Sara Yulitza Giraldo Ciro","documento":"Ti 1038568813","fechaNacimiento":"30 diciembre del 2017","edad":8,"eps":"NUEVA EPS","celular":"3128967551-3106164282","horarios":["X9-10"],"nClases":4,"matricula":false,"estadoPago":"pagado","estado":"activo"},{"id":"st067","nombre":"Maria Camila Mazo Hernandez","documento":"TI 1234439153","fechaNacimiento":"2018-05-19","edad":8,"eps":"SURA","celular":"3113500607","horarios":["X9-10","V9-10"],"nClases":8,"matricula":true,"estadoPago":"pagado","estado":"activo"},{"id":"st068","nombre":"Emily Garcia Rendón","documento":"TI 1040884958","fechaNacimiento":"2015-10-10","edad":10,"eps":"SURA","celular":"3215580396","horarios":["M4-5","V3-4"],"nClases":8,"matricula":true,"estadoPago":"pagado","estado":"activo"},{"id":"st069","nombre":"Samanta Garcia Rodon","documento":"TI 1234439328","fechaNacimiento":"2018-09-03","edad":7,"eps":"SURA","celular":"3215580396","horarios":["M4-5","V3-4"],"nClases":8,"matricula":true,"estadoPago":"pagado","estado":"activo"},{"id":"st070","nombre":"Maria José Montoya Gallego","documento":"TI 1035332153","fechaNacimiento":"2026-05-28","edad":7,"eps":"SURA","celular":"3136708868-3104203880","horarios":["M4-5"],"nClases":4,"matricula":true,"estadoPago":"pagado","estado":"activo"},{"id":"st071","nombre":"Adriana Maria Ochoa Duque","documento":"39171860","fechaNacimiento":"1975-02-09","edad":51,"eps":"SURA","celular":"32346008435","horarios":["X10-11","V10-11"],"nClases":8,"matricula":true,"estadoPago":"pagado","estado":"activo"},{"id":"st072","nombre":"Maria Jose Soto Ramirez","documento":"TI 1035331293","fechaNacimiento":"2016-11-25","edad":9,"eps":"Nueva EPS","celular":"3106500227","horarios":["V3-4"],"nClases":4,"matricula":true,"estadoPago":"pagado","estado":"activo"},{"id":"st073","nombre":"Lina Paola Zuluaga Moreno","documento":"1036400276","fechaNacimiento":"1994-12-16","edad":31,"eps":"SURA","celular":"3135388856-3126322407","horarios":["Rotativo"],"nClases":4,"matricula":true,"estadoPago":"pagado","estado":"activo"},{"id":"st074","nombre":"Emiliano Muñoz Arenas","documento":"1040886441","fechaNacimiento":"2016-12-22","edad":9,"eps":"SURA","celular":"30468328255","horarios":["V9-10"],"nClases":4,"matricula":true,"estadoPago":"pagado","estado":"activo"},{"id":"st075","nombre":"Maria Antonia Ramirez Betancur","documento":"TI 1035331108","fechaNacimiento":"2016-05-14","edad":10,"eps":"SURA","celular":"3137753924","horarios":["M4-5"],"nClases":4,"matricula":true,"estadoPago":"pagado","estado":"activo"},{"id":"st076","nombre":"María Paulina Ramírez Castillón","documento":"Ti 1035331248","fechaNacimiento":"2016-09-30","edad":9,"eps":"Nueva Eps","celular":"3127574884","horarios":["V3-4"],"nClases":4,"matricula":true,"estadoPago":"pagado","estado":"activo"},{"id":"st077","nombre":"Sofia Arenas Ramirez","documento":"TI 1040887054","fechaNacimiento":"2017-11-15","edad":8,"eps":"SURA","celular":"3148585303","horarios":["V9-10"],"nClases":4,"matricula":true,"estadoPago":"pagado","estado":"activo"},{"id":"st078","nombre":"Paula Andrea García Moreno","documento":"1036400585","fechaNacimiento":"1995-07-13","edad":30,"eps":"SURA","celular":"3127561566","horarios":["M5-6"],"nClases":4,"matricula":true,"estadoPago":"pagado","estado":"activo"},{"id":"st079","nombre":"Melisa Atehortua Martínez","documento":"1193588445","fechaNacimiento":"2000-04-05","edad":26,"eps":"SURA","celular":"3127989749","horarios":["X9-10"],"nClases":4,"matricula":true,"estadoPago":"pagado","estado":"activo"},{"id":"st080","nombre":"Natalia Gaitan Aldana","documento":"1031179856","fechaNacimiento":"1999-04-11","edad":27,"eps":"COMPENSAR","celular":"3143552126","horarios":["M5-6"],"nClases":4,"matricula":true,"estadoPago":"pagado","estado":"activo"},{"id":"st081","nombre":"Maximiliano buitrago Alzate","documento":"T.I 1036402086","fechaNacimiento":"2014-12-17","edad":11,"eps":"SURA","celular":"3127108833","horarios":["M4-5"],"nClases":4,"matricula":true,"estadoPago":"pagado","estado":"activo"},{"id":"st082","nombre":"María Fernanda Carmona Cardona","documento":"TI 1040879503","fechaNacimiento":"2011-06-07","edad":15,"eps":"SURA","celular":"3206261049","horarios":["V3-4"],"nClases":4,"matricula":true,"estadoPago":"pagado","estado":"activo"},{"id":"st083","nombre":"Cristian Camilo Vargas Gómez","documento":"","fechaNacimiento":"1994-02-21","edad":32,"eps":"SURA","celular":"3142942353","horarios":["V9-10"],"nClases":4,"matricula":false,"estadoPago":"pendiente","estado":"activo"},{"id":"st084","nombre":"Munay londoño marroquin","documento":"","fechaNacimiento":"2021-08-01","edad":5,"eps":"SURA","celular":"3168217344","horarios":["V3-4"],"nClases":4,"matricula":false,"estadoPago":"pendiente","estado":"activo"},{"id":"st085","nombre":"Arami londoño marroquin","documento":"","fechaNacimiento":"2023-10-23","edad":2,"eps":"SURA","celular":"3168217344","horarios":["V3-4"],"nClases":4,"matricula":false,"estadoPago":"pendiente","estado":"activo"},{"id":"st086","nombre":"Eider Julián Zuluaga","documento":"1001455232","fechaNacimiento":"2002-11-11","edad":23,"eps":"SURA","celular":"3137095136","horarios":["V3-4"],"nClases":4,"matricula":true,"estadoPago":"pagado","estado":"activo"},{"id":"st087","nombre":"Lorena Barrios zuluaga","documento":"1050483487","fechaNacimiento":"2002-11-12","edad":23,"eps":"NUEVA EPS","celular":"3226543220","horarios":["V3-4"],"nClases":4,"matricula":true,"estadoPago":"pagado","estado":"activo"},{"id":"st088","nombre":"Alahia Baquero Velasquez","documento":"RC 1036406660","fechaNacimiento":"2024-02-03","edad":null,"eps":"Savia Salud","celular":"3215644470","horarios":["V2-3"],"nClases":4,"matricula":false,"estadoPago":"pendiente","estado":"activo"},{"id":"st089","nombre":"Matias Cardenas Sanchez","documento":"TI 1056131258","fechaNacimiento":"2014-07-26","edad":11,"eps":"SANITAS","celular":"3046231727","horarios":["M4-5"],"nClases":4,"matricula":false,"estadoPago":"pendiente","estado":"activo"},{"id":"st090","nombre":"Isaac Cardenas Sanchez","documento":"TI 1056131258","fechaNacimiento":"2014-07-26","edad":11,"eps":"SANITAS","celular":"3046231727","horarios":["M4-5"],"nClases":4,"matricula":false,"estadoPago":"pendiente","estado":"activo"},{"id":"st091","nombre":"Sofia Castaño Castaño","documento":"TI 1035331305","fechaNacimiento":"2016-12-10","edad":9,"eps":"SURA","celular":"3192225218","horarios":[],"nClases":4,"matricula":false,"estadoPago":"pendiente","estado":"activo"},{"id":"st092","nombre":"Melany Gómez Castaño","documento":"RC 1036405816","fechaNacimiento":"2021-04-11","edad":5,"eps":"SURA","celular":"3234526305","horarios":[],"nClases":4,"matricula":false,"estadoPago":"pendiente","estado":"activo"},{"id":"st093","nombre":"Sofia Henao Gutierrez","documento":"TI 1036404759","fechaNacimiento":"2017-09-10","edad":8,"eps":"NUEVA EPS","celular":"3125653095","horarios":[],"nClases":8,"matricula":false,"estadoPago":"pendiente","estado":"activo"},{"id":"st094","nombre":"Nelida Elcy Hernandez Hernandez","documento":"1036395195","fechaNacimiento":"1990-01-24","edad":36,"eps":"SURA","celular":"3193528728","horarios":[],"nClases":8,"matricula":false,"estadoPago":"pendiente","estado":"activo"},{"id":"st095","nombre":"Emiliano López Peñaloza","documento":"1036969930","fechaNacimiento":"2025-03-04","edad":null,"eps":"SURA","celular":"3024622455 - 3226189725","horarios":[],"nClases":4,"matricula":false,"estadoPago":"pendiente","estado":"activo"},{"id":"st096","nombre":"Alan Garcia Valencia","documento":"TI 10355331910","fechaNacimiento":"2018-07-19","edad":7,"eps":"SURA","celular":"3146237822","horarios":[],"nClases":4,"matricula":false,"estadoPago":"pendiente","estado":"activo"},{"id":"st097","nombre":"Mauricio Garcia Giraldo","documento":"1036393067","fechaNacimiento":"1987-09-12","edad":37,"eps":"SURA","celular":"3148631533","horarios":[],"nClases":4,"matricula":false,"estadoPago":"pendiente","estado":"activo"},{"id":"st098","nombre":"Santiago Andres Carvajal García","documento":"1036403210","fechaNacimiento":"","edad":28,"eps":"SURA","celular":"3216869388","horarios":[],"nClases":4,"matricula":false,"estadoPago":"pendiente","estado":"activo"},{"id":"st099","nombre":"Maria Clara García Villa","documento":"1035331667","fechaNacimiento":"","edad":null,"eps":"SURA","celular":"3117848473","horarios":[],"nClases":4,"matricula":false,"estadoPago":"pendiente","estado":"activo"},{"id":"st100","nombre":"Maria Alejandra Gaviria Hernández","documento":"1036400301","fechaNacimiento":"1995-03-23","edad":31,"eps":"SURA","celular":"3128372571","horarios":[],"nClases":8,"matricula":false,"estadoPago":"pendiente","estado":"activo"},{"id":"st101","nombre":"Vasti Andrea Castaño Gonzalez","documento":"1036404819","fechaNacimiento":"1999-10-13","edad":26,"eps":"Savia Salud","celular":"3012288754","horarios":[],"nClases":8,"matricula":false,"estadoPago":"pendiente","estado":"activo"},{"id":"st102","nombre":"Maria Victoria Valencia Gomez","documento":"TI 1036405207","fechaNacimiento":"2018-08-14","edad":7,"eps":"SURA","celular":"3174864720","horarios":[],"nClases":4,"matricula":false,"estadoPago":"pendiente","estado":"activo"},{"id":"st103","nombre":"Alejandro Aristizabal Vargas","documento":"1036931931","fechaNacimiento":"2006-10-09","edad":19,"eps":"Fomag","celular":"3005528064","horarios":[],"nClases":8,"matricula":false,"estadoPago":"pendiente","estado":"activo"},{"id":"st104","nombre":"Maria Isabel Echeverri Lopez","documento":"1036255299","fechaNacimiento":"2007-10-23","edad":18,"eps":"SURA","celular":"3122617540","horarios":[],"nClases":4,"matricula":false,"estadoPago":"pendiente","estado":"activo"},{"id":"st105","nombre":"Juan Martin Ceballos Echeverry","documento":"RC 1036405986","fechaNacimiento":"2021-10-30","edad":4,"eps":"SURA","celular":"3117892781","horarios":[],"nClases":4,"matricula":false,"estadoPago":"pendiente","estado":"activo"},{"id":"st106","nombre":"Emilio Jose Ceballos Echeverry","documento":"TI 1036967595","fechaNacimiento":"2018-02-01","edad":8,"eps":"SURA","celular":"3117892781","horarios":[],"nClases":4,"matricula":false,"estadoPago":"pendiente","estado":"activo"},{"id":"st107","nombre":"Mariana Quintero Arango","documento":"TI 1040887620","fechaNacimiento":"2018-07-04","edad":7,"eps":"SURA","celular":"3166174166","horarios":[],"nClases":8,"matricula":false,"estadoPago":"pendiente","estado":"activo"},{"id":"st108","nombre":"Wilmar Andrés Rámirez Velásquez","documento":"","fechaNacimiento":"1993-09-20","edad":32,"eps":"SURA","celular":"3218352581","horarios":["Fuera del país en Junio"],"nClases":8,"matricula":false,"estadoPago":"pendiente","estado":"activo"}]
;

</script>
<script>
/* ============ ICONS ============ */
const ICONS = {
  dashboard:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/></svg>',
  alumnos:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="9" cy="8" r="3.2"/><path d="M2.5 20c0-3.6 2.9-6 6.5-6s6.5 2.4 6.5 6"/><circle cx="17.5" cy="8.5" r="2.6"/><path d="M15.5 14.3c2.9.3 5 2.5 5 5.7"/></svg>',
  pagos:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2.5" y="5.5" width="19" height="13" rx="2.2"/><path d="M2.5 10h19"/><path d="M6 14.3h4"/></svg>',
  asistencia:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="17" rx="2.2"/><path d="M3 9h18"/><path d="m8 14 2 2 4-4"/></svg>',
  horarios:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4.5" width="18" height="16" rx="2.2"/><path d="M3 9.5h18M8 2.5v4M16 2.5v4"/></svg>',
  reportes:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 20V10M12 20V4M20 20v-7"/></svg>',
  usuarios:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="8" r="3.3"/><path d="M4.5 20c0-4.1 3.4-7 7.5-7s7.5 2.9 7.5 7"/></svg>',
  contabilidad:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="2.5" width="16" height="19" rx="2"/><path d="M8 7h8M8 11h3M8 15h3M14.5 10.5v6M12 13h5"/></svg>',
};
const ROLE_LABELS = {super:'Super Administrador', admin:'Administrador', profesor:'Profesor', recepcionista:'Recepcionista'};

/* ============ SCHEDULE / GROUPS SEED ============ */
const SEED_GROUPS = [
  {id:'g1', dia:'Lunes', hora:'4:00 - 5:00 pm', codigo:'L4-5', entrenador:'Andrés Arias', sede:'Sede Principal', piscina:'Piscina 1', carril:'2 - 4', cupoMax:20},
  {id:'g2', dia:'Lunes', hora:'5:00 - 6:00 pm', codigo:'L5-6', entrenador:'Andrés Arias', sede:'Sede Principal', piscina:'Piscina 1', carril:'2 - 4', cupoMax:20},
  {id:'g3', dia:'Martes', hora:'4:00 - 5:00 pm', codigo:'M4-5', entrenador:'Andrés Arias', sede:'Sede Principal', piscina:'Piscina 1', carril:'2 - 4', cupoMax:20},
  {id:'g4', dia:'Martes', hora:'5:00 - 6:00 pm', codigo:'M5-6', entrenador:'Andrés Arias', sede:'Sede Principal', piscina:'Piscina 1', carril:'2 - 4', cupoMax:20},
  {id:'g5', dia:'Miércoles', hora:'9:00 - 10:00 am', codigo:'X9-10', entrenador:'Andrés Arias', sede:'Sede Principal', piscina:'Piscina 1', carril:'1 - 3', cupoMax:20},
  {id:'g6', dia:'Miércoles', hora:'10:00 - 11:00 am', codigo:'X10-11', entrenador:'Sin asignar', sede:'Sede Principal', piscina:'Piscina 1', carril:'1 - 3', cupoMax:20},
  {id:'g7', dia:'Miércoles', hora:'11:00 am - 12:00 m', codigo:'X11-12', entrenador:'Sin asignar', sede:'Sede Principal', piscina:'Piscina 1', carril:'1 - 3', cupoMax:20},
  {id:'g8', dia:'Viernes', hora:'9:00 - 10:00 am', codigo:'V9-10', entrenador:'Andrés Arias', sede:'Sede Principal', piscina:'Piscina 1', carril:'1 - 3', cupoMax:20},
  {id:'g9', dia:'Viernes', hora:'10:00 - 11:00 am', codigo:'V10-11', entrenador:'Sin asignar', sede:'Sede Principal', piscina:'Piscina 1', carril:'1 - 3', cupoMax:20},
  {id:'g10', dia:'Viernes', hora:'2:00 - 3:00 pm', codigo:'V2-3', entrenador:'Andrea García', sede:'Sede Principal', piscina:'Piscina 1', carril:'2 - 3', cupoMax:15},
  {id:'g11', dia:'Viernes', hora:'3:00 - 4:00 pm', codigo:'V3-4', entrenador:'Juan José Molina', sede:'Sede Principal', piscina:'Piscina 1', carril:'2 - 3', cupoMax:15},
];
const TEACHERS_SEED = ['Andrés Arias','Andrea García','Juan José Molina'];

/* ============ STATE ============ */
const state = {
  students:[], payments:[], attendance:[], groups:[], users:[], teachers:[],
  purchases:[], expenses:[],
  session:null, sessionUser:null, role:'super', profesorActual: '',
  theme:'light', view:'dashboard',
  drawerStudentId:null, drawerTab:'datos',
};

const NAV_ITEMS = [
  {id:'dashboard', label:'Dashboard', roles:['super','admin','profesor','recepcionista']},
  {id:'alumnos', label:'Inscripciones', roles:['super','admin','recepcionista']},
  {id:'pagos', label:'Pagos', roles:['super','admin','recepcionista']},
  {id:'asistencia', label:'Asistencia', roles:['super','admin','profesor']},
  {id:'horarios', label:'Horarios', roles:['super','admin']},
  {id:'contabilidad', label:'Contabilidad', roles:['super','admin']},
  {id:'reportes', label:'Reportes', roles:['super','admin']},
  {id:'usuarios', label:'Usuarios', roles:['super']},
];

/* ============ STORAGE HELPERS ============ */
const API_BASE = '/api';
async function apiFetch(path, options){
  const res = await fetch(API_BASE + path, {
    credentials: 'include',
    headers: {'Content-Type':'application/json'},
    ...options,
  });
  return res;
}
async function loadKey(key, fallback){
  try{
    const res = await apiFetch('/data/'+encodeURIComponent(key));
    if(!res.ok) return fallback;
    const data = await res.json();
    return (data.value===null || data.value===undefined) ? fallback : data.value;
  }catch(e){ return fallback; }
}
async function saveKey(key, value, _attempt){
  const attempt = _attempt || 1;
  try{
    const res = await apiFetch('/data/'+encodeURIComponent(key), {method:'PUT', body: JSON.stringify({value})});
    if(!res.ok){
      if(res.status===403){ toast('No tienes permiso para guardar esto.', 'danger'); return false; }
      throw new Error('bad status '+res.status);
    }
    return true;
  }catch(e){
    if(attempt < 3){
      await new Promise(r=>setTimeout(r, 300*attempt));
      return saveKey(key, value, attempt+1);
    }
    toast('No se pudo guardar. Revisa tu conexión e intenta de nuevo.', 'danger');
    return false;
  }
}
async function loadTheme(){
  try{ return localStorage.getItem('mantarayas:theme') || 'light'; }catch(e){ return 'light'; }
}
async function saveTheme(t){
  try{ localStorage.setItem('mantarayas:theme', t); }catch(e){}
}

/* ============ UTIL ============ */
function uid(p){ return p + Date.now().toString(36) + Math.random().toString(36).slice(2,6); }
function monthKey(d=new Date()){ return d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0'); }
function monthLabel(mk){
  const [y,m] = mk.split('-');
  const names=['Enero','Febrero','Marzo','Abril','Mayo','Junio','Julio','Agosto','Septiembre','Octubre','Noviembre','Diciembre'];
  return names[parseInt(m,10)-1] + ' ' + y;
}
function fmtMoney(n){ return '$ ' + Math.round(n||0).toLocaleString('es-CO'); }
function fmtDate(iso){
  if(!iso) return '—';
  const d = new Date(iso+'T00:00:00');
  if(isNaN(d)) return iso;
  return d.toLocaleDateString('es-CO',{day:'2-digit',month:'short',year:'numeric'});
}
function calcEdad(fechaISO){
  if(!fechaISO) return null;
  const b = new Date(fechaISO+'T00:00:00');
  if(isNaN(b)) return null;
  const t = new Date();
  let e = t.getFullYear()-b.getFullYear();
  const m = t.getMonth()-b.getMonth();
  if(m<0 || (m===0 && t.getDate()<b.getDate())) e--;
  return e;
}
function todayISO(){ return new Date().toISOString().slice(0,10); }
const MONTH_NAMES=['Enero','Febrero','Marzo','Abril','Mayo','Junio','Julio','Agosto','Septiembre','Octubre','Noviembre','Diciembre'];
function monthYearPickerHTML(prefix, mk){
  const [y,m] = mk.split('-');
  return `<select id="${prefix}Mes" style="width:auto;">${MONTH_NAMES.map((n,i)=>{const v=String(i+1).padStart(2,'0');return `<option value="${v}" ${v===m?'selected':''}>${n}</option>`;}).join('')}</select>
    <input type="number" id="${prefix}Anio" value="${y}" min="2015" max="2100" style="width:84px;">`;
}
function bindMonthYearPicker(prefix, onChange){
  document.getElementById(prefix+'Mes').addEventListener('change', onChange);
  document.getElementById(prefix+'Anio').addEventListener('change', onChange);
}
function readMonthYearPicker(prefix){
  const m = document.getElementById(prefix+'Mes').value;
  const y = document.getElementById(prefix+'Anio').value;
  return y+'-'+m;
}
function initials(name){
  return (name||'').trim().split(/\s+/).slice(0,2).map(w=>w[0]).join('').toUpperCase();
}
function normCode(s){ return (s||'').replace(/\s+/g,'').toUpperCase(); }
function groupOfStudent(s){
  return state.groups.filter(g => (s.horarios||[]).some(h=>normCode(h)===g.codigo));
}
function studentsInGroup(g){
  return state.students.filter(s=>s.estado==='activo' && (s.horarios||[]).some(h=>normCode(h)===g.codigo));
}
function escapeHtml(s){
  return String(s==null?'':s).replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function csvEscape(s){
  s = String(s==null?'':s);
  if(/[",\n]/.test(s)) return '"'+s.replace(/"/g,'""')+'"';
  return s;
}
function downloadCSV(filename, rows){
  const csv = rows.map(r=>r.map(csvEscape).join(',')).join('\n');
  const blob = new Blob(['\ufeff'+csv], {type:'text/csv;charset=utf-8;'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/* ============ TOASTS ============ */
let _lastToastMsg = '', _lastToastAt = 0;
function toast(msg, type){
  const now = Date.now();
  if(msg===_lastToastMsg && (now-_lastToastAt)<1500) return;
  _lastToastMsg = msg; _lastToastAt = now;
  const stack = document.getElementById('toastStack');
  const el = document.createElement('div');
  el.className = 'toast';
  const color = type==='danger' ? 'var(--danger)' : type==='warning' ? 'var(--warning)' : 'var(--success)';
  el.innerHTML = '<span style="width:7px;height:7px;border-radius:50%;background:'+color+';flex-shrink:0;"></span><span>'+escapeHtml(msg)+'</span>';
  stack.appendChild(el);
  setTimeout(()=>{ el.style.transition='opacity .3s ease, transform .3s ease'; el.style.opacity='0'; el.style.transform='translateY(6px)'; setTimeout(()=>el.remove(),300); }, 2600);
}

/* ============ PAYMENT STATUS ============ */
function paymentStatusForMonth(studentId, mk){
  const recs = state.payments.filter(p=>p.studentId===studentId && p.mes===mk && (p.tipo==='mensualidad'||p.tipo==='cortesia'));
  if(recs.length){
    const r = recs[recs.length-1];
    return r.tipo==='cortesia' ? 'cortesia' : 'pagado';
  }
  const now = new Date();
  const [y,m] = mk.split('-').map(Number);
  const isCurrentOrFuture = (y>now.getFullYear()) || (y===now.getFullYear() && m>=now.getMonth()+1);
  if(!isCurrentOrFuture) return 'vencido';
  if(y===now.getFullYear() && m===now.getMonth()+1 && now.getDate()>10) return 'vencido';
  return 'pendiente';
}
function statusBadge(status){
  const map = {
    pagado:['badge-success','Al día'], cortesia:['badge-primary','Cortesía'],
    pendiente:['badge-warning','Pendiente'], vencido:['badge-danger','Vencido'],
    activo:['badge-success','Activo'], retirado:['badge-neutral','Retirado'], suspendido:['badge-danger','Suspendido'],
  };
  const [cls,label] = map[status] || ['badge-neutral', status];
  return '<span class="badge '+cls+'"><span class="badge-dot" style="background:currentColor;"></span>'+label+'</span>';
}
/* ============ SEEDING ============ */
function buildSeedPayments(){
  const mk = monthKey();
  const pays = [];
  SEED_STUDENTS.forEach(s=>{
    const precio = s.nClases>=8 ? 180000 : 120000;
    if(s.estadoPago==='pagado'){
      pays.push({id:uid('pg'), studentId:s.id, mes:mk, tipo:'mensualidad', monto:precio, metodo:'Transferencia', fecha:todayISO(), nota:''});
    } else if(s.estadoPago==='cortesia'){
      pays.push({id:uid('pg'), studentId:s.id, mes:mk, tipo:'cortesia', monto:0, metodo:'—', fecha:todayISO(), nota:'Cortesía asignada'});
    }
    if(s.matricula){
      pays.push({id:uid('pg'), studentId:s.id, mes:mk, tipo:'matricula', monto:50000, metodo:'Transferencia', fecha:todayISO(), nota:''});
    }
  });
  return pays;
}

async function seedAll(){
  const students = SEED_STUDENTS.map(s=>({
    ...s, apellido:'', sexo:'', direccion:'', barrio:'', municipio:'El Carmen de Viboral',
    rh:'', alergias:'', acudiente:'', telefonoAcudiente:'', correo:'', contactoEmergencia:'',
    observaciones:'', fechaInscripcion: todayISO(),
    docs:{foto:false, identidad:false, eps:false, consentimiento:false},
  }));
  state.students = students;
  state.groups = SEED_GROUPS.map(g=>({...g, nivel:'', estado:'activo', observaciones:''}));
  state.payments = buildSeedPayments();
  state.attendance = [];
  if(!state.teachers || !state.teachers.length) state.teachers = TEACHERS_SEED.slice();
  await saveKey('mantarayas:students', state.students);
  await saveKey('mantarayas:groups', state.groups);
  await saveKey('mantarayas:payments', state.payments);
  await saveKey('mantarayas:attendance', state.attendance);
  await saveKey('mantarayas:teachers', state.teachers);
}

async function loadAll(){
  const [students, groups, payments, attendance, teachers, purchases, expenses] = await Promise.all([
    loadKey('mantarayas:students', null),
    loadKey('mantarayas:groups', null),
    loadKey('mantarayas:payments', null),
    loadKey('mantarayas:attendance', null),
    loadKey('mantarayas:teachers', null),
    loadKey('mantarayas:purchases', null),
    loadKey('mantarayas:expenses', null),
  ]);
  state.teachers = teachers && teachers.length ? teachers : TEACHERS_SEED.slice();
  if(!teachers || !teachers.length) await saveKey('mantarayas:teachers', state.teachers);
  state.purchases = purchases || [];
  state.expenses = expenses || [];
  if(!students || !students.length){
    await seedAll();
  } else {
    state.students = students;
    state.groups = groups && groups.length ? groups : SEED_GROUPS.slice();
    state.payments = payments || [];
    state.attendance = attendance || [];
  }
}

/* ============ SESSION ============ */
// La sesión ahora vive del lado del servidor (cookie firmada httponly).
// No hay nada que leer/escribir en almacenamiento del navegador para "recordarme":
// el servidor decide cuánto dura la sesión según lo marcado al iniciar sesión.
function currentUser(){ return state.sessionUser; }

async function resetDemoData(){
  await seedAll();
  toast('Datos de ejemplo restablecidos');
  renderCurrentView();
}

/* ============ NAV ============ */
function renderNav(){
  const nav = document.getElementById('navList');
  nav.innerHTML = NAV_ITEMS.filter(i=>i.roles.includes(state.role)).map(item=>{
    let count = '';
    if(item.id==='alumnos') count = state.students.filter(s=>s.estado==='activo').length;
    if(item.id==='usuarios') count = state.users.length;
    return '<button class="nav-item '+(state.view===item.id?'active':'')+'" data-nav="'+item.id+'">'+
      '<span class="dot"></span>'+ICONS[item.id]+'<span>'+item.label+'</span>'+
      (count!==''?'<span class="count">'+count+'</span>':'')+'</button>';
  }).join('');
  const u = currentUser();
  if(u){
    document.getElementById('sessionAvatar').textContent = initials(u.nombre+' '+u.apellido);
    document.getElementById('sessionName').textContent = u.nombre+' '+u.apellido;
    document.getElementById('sessionRole').textContent = ROLE_LABELS[u.rol]||u.rol;
  }
  document.getElementById('resetBtn').style.display = state.role==='super' ? 'flex' : 'none';
}
function checkAccess(id){
  const item = NAV_ITEMS.find(i=>i.id===id);
  return item && item.roles.includes(state.role);
}
function setView(id){
  state.view = id;
  renderNav();
  renderCurrentView();
  document.getElementById('sidebar').classList.remove('open');
  window.scrollTo({top:0});
}
function renderCurrentView(){
  const root = document.getElementById('viewRoot');
  if(!checkAccess(state.view)){
    root.innerHTML = `<div class="view active"><div class="access-denied"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="m8 8 8 8"/></svg><h3>Acceso denegado</h3><p>Tu rol (${ROLE_LABELS[state.role]||state.role}) no tiene permiso para ver este módulo.</p><button class="btn btn-primary" data-action="goto-dashboard" style="margin-top:14px;">Ir al Dashboard</button></div></div>`;
    return;
  }
  const fns = {dashboard:viewDashboard, alumnos:viewAlumnos, pagos:viewPagos, asistencia:viewAsistencia, horarios:viewHorarios, reportes:viewReportes, usuarios:viewUsuarios, contabilidad:viewContabilidad};
  root.innerHTML = '<div class="view active" id="viewInner"></div>';
  fns[state.view](document.getElementById('viewInner'));
}

/* ============ DASHBOARD ============ */
function viewDashboard(el){
  const activos = state.students.filter(s=>s.estado==='activo');
  const mk = monthKey();
  const ingresosMes = state.payments.filter(p=>p.mes===mk).reduce((a,p)=>a+p.monto,0);
  const morosos = activos.filter(s=>paymentStatusForMonth(s.id, mk)==='vencido').length;
  const pendientes = activos.filter(s=>paymentStatusForMonth(s.id, mk)==='pendiente').length;
  const nuevos = activos.filter(s=>s.fechaInscripcion && s.fechaInscripcion.slice(0,7)===mk).length;
  const retirados = state.students.filter(s=>s.estado==='retirado').length;
  const profesoresActivos = new Set(state.groups.filter(g=>g.entrenador!=='Sin asignar').map(g=>g.entrenador)).size;

  const last30 = new Date(); last30.setDate(last30.getDate()-30);
  const recentAtt = state.attendance.filter(a=>new Date(a.fecha)>=last30);
  const asistPct = recentAtt.length ? Math.round(100*recentAtt.filter(a=>a.estado==='asistio'||a.estado==='tarde').length/recentAtt.length) : null;

  if(state.role==='profesor'){
    el.innerHTML = dashboardProfesor();
    return;
  }

  el.innerHTML = `
    <div class="view-header">
      <div><h1 class="view-title">Hola, bienvenido de nuevo 👋</h1><p class="view-desc">Así va el club hoy, ${new Date().toLocaleDateString('es-CO',{weekday:'long', day:'numeric', month:'long'})}.</p></div>
      <button class="btn btn-primary" data-action="open-add-student"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg>Nuevo alumno</button>
    </div>
    <div class="kpi-grid">
      ${kpi('Alumnos activos', activos.length, activos.length+' en '+new Set(state.groups.map(g=>g.dia)).size+' días de clase')}
      ${kpi('Ingresos '+monthLabel(mk), fmtMoney(ingresosMes), state.payments.filter(p=>p.mes===mk).length+' pagos registrados')}
      ${kpi('Morosos', morosos, morosos>0 ? 'requieren seguimiento':'todo al día', morosos>0?'var(--danger)':'var(--success)')}
      ${kpi('Pendientes del mes', pendientes, 'aún sin registrar pago')}
      ${kpi('Asistencia (30 días)', asistPct===null?'—':asistPct+'%', recentAtt.length+' registros')}
      ${kpi('Nuevos inscritos', nuevos, monthLabel(mk))}
    </div>
    <div class="grid-2">
      <div class="card">
        <div class="card-head"><h3>Alumnos por grupo</h3><span class="cell-sub">${activos.length} activos</span></div>
        <div class="card-pad">${barChartGroups()}</div>
      </div>
      <div class="card">
        <div class="card-head"><h3>Estado de cartera — ${monthLabel(mk)}</h3></div>
        <div class="card-pad">${donutCartera(mk)}</div>
      </div>
    </div>
    <div class="grid-2" style="margin-top:14px;">
      <div class="card">
        <div class="card-head"><h3>Últimos inscritos</h3><button class="btn btn-ghost btn-sm" data-action="goto-alumnos">Ver todos</button></div>
        <div class="table-wrap">${miniStudentTable(activos.slice(-6).reverse())}</div>
      </div>
      <div class="card">
        <div class="card-head"><h3>Alumnos con pago vencido</h3><button class="btn btn-ghost btn-sm" data-action="goto-pagos">Ir a pagos</button></div>
        <div class="table-wrap">${miniStudentTable(activos.filter(s=>paymentStatusForMonth(s.id,mk)==='vencido').slice(0,6), true)}</div>
      </div>
    </div>
  `;
}

function dashboardProfesor(){
  const prof = state.profesorActual;
  const misGrupos = state.groups.filter(g=>g.entrenador===prof && g.estado!=='suspendido');
  const totalAlumnos = new Set(misGrupos.flatMap(g=>studentsInGroup(g).map(s=>s.id))).size;
  const mk = monthKey();
  const misAsistRecientes = state.attendance.filter(a=>misGrupos.some(g=>g.id===a.groupId));
  const diasOrden = ['Domingo','Lunes','Martes','Miércoles','Jueves','Viernes','Sábado'];
  const hoy = diasOrden[new Date().getDay()];
  const proxima = misGrupos.find(g=>g.dia===hoy) || misGrupos[0];
  const hoyAsist = state.attendance.filter(a=>misGrupos.some(g=>g.id===a.groupId) && a.fecha===todayISO()).length;
  return `
    <div class="view-header">
      <div><h1 class="view-title">Hola, ${prof.split(' ')[0]}</h1><p class="view-desc">Tus grupos asignados y el estado de tus alumnos.</p></div>
      <button class="btn btn-primary" data-action="goto-asistencia"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m9 12 2 2 4-4"/><rect x="3" y="4" width="18" height="17" rx="2"/></svg>Registrar asistencia</button>
    </div>
    <div class="kpi-grid">
      ${kpi('Grupos asignados', misGrupos.length, misGrupos.map(g=>g.dia).join(', ')||'—')}
      ${kpi('Próxima clase', proxima?proxima.dia+' '+proxima.hora:'—', proxima?proxima.sede:'')}
      ${kpi('Alumnos a cargo', totalAlumnos, '')}
      ${kpi('Asistencia registrada hoy', hoyAsist, 'registros de hoy')}
    </div>
    <div class="card">
      <div class="card-head"><h3>Mis grupos</h3></div>
      <div class="table-wrap"><table><thead><tr><th>Día</th><th>Horario</th><th>Alumnos</th><th>Cupo</th><th>Debe mensualidad</th></tr></thead><tbody>
      ${misGrupos.map(g=>{
        const ss = studentsInGroup(g);
        const debe = ss.filter(s=>['pendiente','vencido'].includes(paymentStatusForMonth(s.id,mk))).length;
        return '<tr data-action="open-take-attendance" data-group="'+g.id+'"><td class="cell-name">'+g.dia+'</td><td>'+g.hora+'</td><td>'+ss.length+'</td><td>'+ss.length+' / '+g.cupoMax+'</td><td>'+(debe? '<span class="badge badge-warning">'+debe+' alumnos</span>':'<span class="badge badge-success">Ninguno</span>')+'</td></tr>';
      }).join('') || '<tr><td colspan="5"><div class="empty">No tienes grupos asignados todavía.</div></td></tr>'}
      </tbody></table></div>
    </div>
  `;
}

function kpi(label, value, sub, color){
  return `<div class="kpi-card"><div class="kpi-label">${label}</div><div class="kpi-value" style="${color?'color:'+color:''}">${value}</div><div class="kpi-sub">${sub||''}</div></div>`;
}
function barChartGroups(){
  const data = state.groups.map(g=>({label:g.dia.slice(0,3)+' '+g.hora.split(' - ')[0], n:studentsInGroup(g).length}));
  const max = Math.max(1,...data.map(d=>d.n));
  return '<div class="bar-chart">'+data.map(d=>`<div class="bar-col"><span class="bar-val">${d.n}</span><div class="bar" style="height:${Math.max(4,(d.n/max)*110)}px"></div><span class="bar-label">${d.label}</span></div>`).join('')+'</div>';
}
function donutCartera(mk){
  const activos = state.students.filter(s=>s.estado==='activo');
  const buckets = {pagado:0,cortesia:0,pendiente:0,vencido:0};
  activos.forEach(s=>buckets[paymentStatusForMonth(s.id,mk)]++);
  const total = activos.length || 1;
  const colors = {pagado:'var(--success)', cortesia:'var(--primary)', pendiente:'var(--warning)', vencido:'var(--danger)'};
  const labels = {pagado:'Al día', cortesia:'Cortesía', pendiente:'Pendiente', vencido:'Vencido'};
  let acc = 0;
  const stops = Object.keys(buckets).map(k=>{
    const pct = buckets[k]/total*100;
    const s = `${colors[k]} ${acc}% ${acc+pct}%`;
    acc += pct;
    return s;
  }).join(',');
  return `<div class="donut-wrap">
    <div style="width:120px;height:120px;border-radius:50%;background:conic-gradient(${stops || 'var(--border) 0 100%'});flex-shrink:0;display:flex;align-items:center;justify-content:center;">
      <div style="width:70px;height:70px;border-radius:50%;background:var(--surface);display:flex;align-items:center;justify-content:center;font-family:'Space Grotesk';font-weight:700;">${activos.length}</div>
    </div>
    <div class="legend">${Object.keys(buckets).map(k=>`<div class="legend-item"><span class="legend-dot" style="background:${colors[k]}"></span>${labels[k]} · ${buckets[k]}</div>`).join('')}</div>
  </div>`;
}
function miniStudentTable(list, showDebt){
  if(!list.length) return '<div class="empty" style="padding:30px;">Nada para mostrar</div>';
  return '<table><tbody>'+list.map(s=>`<tr data-action="open-student" data-id="${s.id}">
    <td><div style="display:flex;align-items:center;gap:9px;"><div class="avatar" style="width:30px;height:30px;font-size:11px;">${initials(s.nombre)}</div><div><div class="cell-name">${escapeHtml(s.nombre)}</div><div class="cell-sub">${s.edad!=null?s.edad+' años':''}</div></div></div></td>
    <td>${showDebt?statusBadge('vencido'):statusBadge(s.estado)}</td>
  </tr>`).join('')+'</tbody></table>';
}
/* ============ ALUMNOS VIEW ============ */
state._alumFilter = {q:'', estado:'', grupo:''};
function viewAlumnos(el){
  const f = state._alumFilter;
  let list = state.students.slice();
  if(f.q){
    const q = f.q.toLowerCase();
    list = list.filter(s=> (s.nombre||'').toLowerCase().includes(q) || (s.documento||'').includes(q) || (s.celular||'').includes(q));
  }
  if(f.estado) list = list.filter(s=>s.estado===f.estado);
  if(f.grupo) list = list.filter(s=>(s.horarios||[]).some(h=>normCode(h)===f.grupo));
  list.sort((a,b)=>a.nombre.localeCompare(b.nombre));
  const mk = monthKey();

  el.innerHTML = `
    <div class="view-header">
      <div><h1 class="view-title">Inscripciones</h1><p class="view-desc">${state.students.length} alumnos registrados · ${state.students.filter(s=>s.estado==='activo').length} activos</p></div>
      <div style="display:flex;gap:8px;">
        <button class="btn" data-action="export-students"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3v13m0 0-4-4m4 4 4-4M4 20h16"/></svg>Exportar CSV</button>
        <button class="btn btn-primary" data-action="open-add-student"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg>Nuevo alumno</button>
      </div>
    </div>
    <div class="toolbar">
      <input type="text" id="alumFilterQ" placeholder="Filtrar por nombre, documento o celular…" style="max-width:260px;" value="${escapeHtml(f.q)}">
      <select id="alumFilterEstado"><option value="">Todos los estados</option><option value="activo">Activo</option><option value="retirado">Retirado</option><option value="suspendido">Suspendido</option></select>
      <select id="alumFilterGrupo"><option value="">Todos los grupos</option>${state.groups.map(g=>`<option value="${g.codigo}">${g.dia} ${g.hora}</option>`).join('')}</select>
      <span class="cell-sub" style="margin-left:auto;">${list.length} resultado${list.length===1?'':'s'}</span>
    </div>
    <div class="card">
      <div class="table-wrap">
        <table><thead><tr><th>Alumno</th><th>Edad</th><th>Grupo / horario</th><th>EPS</th><th>Pago (${monthLabel(mk)})</th><th>Estado</th></tr></thead>
        <tbody>${list.length? list.map(rowAlumno).join('') : '<tr><td colspan="6"><div class="empty">Sin resultados para este filtro.</div></td></tr>'}</tbody></table>
      </div>
    </div>
  `;
  document.getElementById('alumFilterQ').addEventListener('input', e=>{ state._alumFilter.q = e.target.value; viewAlumnos(el); positionCaret('alumFilterQ'); });
  document.getElementById('alumFilterEstado').value = f.estado;
  document.getElementById('alumFilterEstado').addEventListener('change', e=>{ state._alumFilter.estado = e.target.value; viewAlumnos(el); });
  document.getElementById('alumFilterGrupo').value = f.grupo;
  document.getElementById('alumFilterGrupo').addEventListener('change', e=>{ state._alumFilter.grupo = e.target.value; viewAlumnos(el); });
}
function positionCaret(id){ const i=document.getElementById(id); if(i){ const v=i.value; i.focus(); i.value=''; i.value=v; } }
function rowAlumno(s){
  const mk = monthKey();
  const grupos = groupOfStudent(s);
  return `<tr data-action="open-student" data-id="${s.id}">
    <td><div style="display:flex;align-items:center;gap:10px;"><div class="avatar">${initials(s.nombre)}</div><div><div class="cell-name">${escapeHtml(s.nombre)}</div><div class="cell-sub">${s.documento?('CC '+s.documento):'Sin documento'}</div></div></div></td>
    <td>${s.edad!=null?s.edad+' años':'—'}</td>
    <td>${grupos.length? grupos.map(g=>g.dia.slice(0,3)+' '+g.hora.split(' - ')[0]).join(', ') : (s.horarios||[]).join(', ') || '—'}</td>
    <td>${escapeHtml(s.eps||'—')}</td>
    <td>${statusBadge(paymentStatusForMonth(s.id, mk))}</td>
    <td>${statusBadge(s.estado)}</td>
  </tr>`;
}

/* ============ STUDENT MODAL (add/edit) ============ */
function openStudentModal(studentId){
  const s = studentId ? state.students.find(x=>x.id===studentId) : null;
  const d = s || {nombre:'',documento:'',fechaNacimiento:'',sexo:'',direccion:'',barrio:'',municipio:'El Carmen de Viboral',eps:'',rh:'',alergias:'',celular:'',acudiente:'',telefonoAcudiente:'',correo:'',contactoEmergencia:'',observaciones:'',estado:'activo',horarios:[]};
  const html = `
    <div class="modal-head"><h3>${s?'Editar alumno':'Nuevo alumno'}</h3><button class="icon-btn" data-action="close-modal"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6 6 18M6 6l12 12"/></svg></button></div>
    <div class="modal-body">
      <div class="pill-tabs" id="studentFormTabs" style="margin-bottom:16px;">
        <button class="pill-tab active" data-tab="personal">Datos personales</button>
        <button class="pill-tab" data-tab="club">Club y contacto</button>
        <button class="pill-tab" data-tab="docs">Documentos</button>
      </div>
      <form id="studentForm">
        <div data-pane="personal">
          <div class="field-row">
            <div class="field"><label>Nombre completo *</label><input required name="nombre" value="${escapeHtml(d.nombre)}"></div>
            <div class="field"><label>Documento</label><input name="documento" value="${escapeHtml(d.documento)}"></div>
          </div>
          <div class="field-row3">
            <div class="field"><label>Fecha de nacimiento</label><input type="date" name="fechaNacimiento" value="${d.fechaNacimiento||''}"></div>
            <div class="field"><label>Sexo</label><select name="sexo"><option value="">—</option><option value="F" ${d.sexo==='F'?'selected':''}>Femenino</option><option value="M" ${d.sexo==='M'?'selected':''}>Masculino</option></select></div>
            <div class="field"><label>RH</label><input name="rh" value="${escapeHtml(d.rh)}" placeholder="O+"></div>
          </div>
          <div class="field-row">
            <div class="field"><label>EPS</label><input name="eps" value="${escapeHtml(d.eps)}"></div>
            <div class="field"><label>Alergias</label><input name="alergias" value="${escapeHtml(d.alergias)}"></div>
          </div>
          <div class="field-row">
            <div class="field"><label>Barrio</label><input name="barrio" value="${escapeHtml(d.barrio)}"></div>
            <div class="field"><label>Municipio</label><input name="municipio" value="${escapeHtml(d.municipio)}"></div>
          </div>
          <div class="field"><label>Dirección</label><input name="direccion" value="${escapeHtml(d.direccion)}"></div>
        </div>
        <div data-pane="club" style="display:none;">
          <div class="field-row">
            <div class="field"><label>Celular alumno / acudiente</label><input name="celular" value="${escapeHtml(d.celular)}"></div>
            <div class="field"><label>Correo</label><input type="email" name="correo" value="${escapeHtml(d.correo)}"></div>
          </div>
          <div class="field-row">
            <div class="field"><label>Nombre del acudiente</label><input name="acudiente" value="${escapeHtml(d.acudiente)}"></div>
            <div class="field"><label>Teléfono acudiente</label><input name="telefonoAcudiente" value="${escapeHtml(d.telefonoAcudiente)}"></div>
          </div>
          <div class="field"><label>Contacto de emergencia</label><input name="contactoEmergencia" value="${escapeHtml(d.contactoEmergencia)}"></div>
          <div class="field">
            <label>Horarios / grupos</label>
            <div style="display:flex;flex-wrap:wrap;gap:6px;">
              ${state.groups.map(g=>`<label style="display:flex;align-items:center;gap:5px;font-size:12px;background:var(--surface-2);padding:5px 8px;border-radius:7px;cursor:pointer;">
                <input type="checkbox" name="horarios" value="${g.codigo}" ${(d.horarios||[]).some(h=>normCode(h)===g.codigo)?'checked':''} style="width:auto;">${g.dia.slice(0,3)} ${g.hora.split(' - ')[0]}</label>`).join('')}
            </div>
          </div>
          <div class="field-row">
            <div class="field"><label>Estado del alumno</label><select name="estado">
              <option value="activo" ${d.estado==='activo'?'selected':''}>Activo</option>
              <option value="retirado" ${d.estado==='retirado'?'selected':''}>Retirado</option>
              <option value="suspendido" ${d.estado==='suspendido'?'selected':''}>Suspendido</option>
            </select></div>
          </div>
          <div class="field"><label>Observaciones</label><textarea name="observaciones" rows="3">${escapeHtml(d.observaciones)}</textarea></div>
        </div>
        <div data-pane="docs" style="display:none;">
          <p class="hint" style="margin-bottom:10px;">Marca los documentos ya recibidos. Esta versión guarda la confirmación, no el archivo — para almacenar archivos reales conecta un Drive o servicio de almacenamiento cuando pases a producción.</p>
          ${['foto','identidad','eps','consentimiento'].map(k=>`<div class="check-row"><span>${{foto:'Foto',identidad:'Documento de identidad',eps:'Certificado EPS',consentimiento:'Consentimiento firmado'}[k]}</span>
            <label class="switch"><input type="checkbox" name="doc_${k}" ${d.docs&&d.docs[k]?'checked':''}><span class="slider"></span></label></div>`).join('')}
        </div>
      </form>
    </div>
    <div class="modal-foot">
      <button class="btn" data-action="close-modal">Cancelar</button>
      <button class="btn btn-primary" data-action="save-student" data-id="${s?s.id:''}">${s?'Guardar cambios':'Crear alumno'}</button>
    </div>
  `;
  openModal(html);
  document.querySelectorAll('#studentFormTabs .pill-tab').forEach(t=>t.addEventListener('click', ()=>{
    document.querySelectorAll('#studentFormTabs .pill-tab').forEach(x=>x.classList.remove('active'));
    t.classList.add('active');
    document.querySelectorAll('[data-pane]').forEach(p=>p.style.display = p.dataset.pane===t.dataset.tab?'block':'none');
  }));
}
async function saveStudentFromForm(existingId){
  const form = document.getElementById('studentForm');
  const fd = new FormData(form);
  if(!fd.get('nombre') || !fd.get('nombre').trim()){ toast('El nombre es obligatorio', 'danger'); return; }
  const horarios = fd.getAll('horarios');
  const docs = {foto:!!fd.get('doc_foto'), identidad:!!fd.get('doc_identidad'), eps:!!fd.get('doc_eps'), consentimiento:!!fd.get('doc_consentimiento')};
  const fechaNacimiento = fd.get('fechaNacimiento') || '';
  const payload = {
    nombre: fd.get('nombre').trim(), documento: fd.get('documento')||'', fechaNacimiento,
    edad: calcEdad(fechaNacimiento), sexo: fd.get('sexo')||'', direccion: fd.get('direccion')||'',
    barrio: fd.get('barrio')||'', municipio: fd.get('municipio')||'', eps: fd.get('eps')||'', rh: fd.get('rh')||'',
    alergias: fd.get('alergias')||'', celular: fd.get('celular')||'', acudiente: fd.get('acudiente')||'',
    telefonoAcudiente: fd.get('telefonoAcudiente')||'', correo: fd.get('correo')||'', contactoEmergencia: fd.get('contactoEmergencia')||'',
    observaciones: fd.get('observaciones')||'', estado: fd.get('estado')||'activo', horarios, docs,
  };
  if(existingId){
    const idx = state.students.findIndex(s=>s.id===existingId);
    state.students[idx] = {...state.students[idx], ...payload};
  } else {
    payload.id = uid('st'); payload.fechaInscripcion = todayISO(); payload.estadoPago='pendiente'; payload.nClases = horarios.length*2; payload.matricula=false;
    state.students.push(payload);
  }
  const ok = await saveKey('mantarayas:students', state.students);
  if(ok){ toast(existingId?'Alumno actualizado':'Alumno creado'); closeModal(); renderNav(); renderCurrentView(); }
}

/* ============ STUDENT DRAWER ============ */
function openStudentDrawer(id){
  state.drawerStudentId = id; state.drawerTab='datos';
  document.getElementById('drawerOverlay').classList.add('active');
  document.getElementById('studentDrawer').classList.add('active');
  renderDrawer();
}
function closeDrawer(){
  document.getElementById('drawerOverlay').classList.remove('active');
  document.getElementById('studentDrawer').classList.remove('active');
}
function renderDrawer(){
  const s = state.students.find(x=>x.id===state.drawerStudentId);
  const dr = document.getElementById('studentDrawer');
  if(!s){ dr.innerHTML=''; return; }
  const mk = monthKey();
  dr.innerHTML = `
    <div class="drawer-head">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;">
        <div style="display:flex;gap:12px;align-items:center;">
          <div class="avatar" style="width:46px;height:46px;font-size:16px;">${initials(s.nombre)}</div>
          <div><div style="font-weight:700;font-size:16px;">${escapeHtml(s.nombre)}</div><div class="cell-sub">${s.documento?('CC '+s.documento):'Sin documento'} ${s.edad!=null?'· '+s.edad+' años':''}</div></div>
        </div>
        <button class="icon-btn" data-action="close-drawer"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6 6 18M6 6l12 12"/></svg></button>
      </div>
      <div style="display:flex;gap:6px;margin-top:12px;">${statusBadge(s.estado)}${statusBadge(paymentStatusForMonth(s.id,mk))}</div>
      ${state.role!=='profesor' ? `<div style="display:flex;gap:8px;margin-top:12px;">
        <button class="btn btn-sm" data-action="edit-student" data-id="${s.id}">Editar</button>
        ${state.role==='super' ? '<button class="btn btn-sm btn-danger" data-action="delete-student" data-id="'+s.id+'">Eliminar</button>' : ''}
      </div>` : ''}
    </div>
    <div class="drawer-tabs">
      <button class="drawer-tab ${state.drawerTab==='datos'?'active':''}" data-dtab="datos">Datos</button>
      ${state.role!=='profesor' ? '<button class="drawer-tab '+(state.drawerTab==='pagos'?'active':'')+'" data-dtab="pagos">Pagos</button>' : ''}
      <button class="drawer-tab ${state.drawerTab==='asistencia'?'active':''}" data-dtab="asistencia">Asistencia</button>
    </div>
    <div class="drawer-body" id="drawerBody"></div>
  `;
  renderDrawerBody();
  dr.querySelectorAll('[data-dtab]').forEach(b=>b.addEventListener('click', ()=>{ state.drawerTab=b.dataset.dtab; renderDrawer(); }));
}
function renderDrawerBody(){
  const s = state.students.find(x=>x.id===state.drawerStudentId);
  const body = document.getElementById('drawerBody');
  if(!s || !body) return;
  if(state.drawerTab==='datos'){
    body.innerHTML = `
      <div class="kv"><span>Fecha de nacimiento</span><span>${s.fechaNacimiento?fmtDate(s.fechaNacimiento):'—'}</span></div>
      <div class="kv"><span>Sexo</span><span>${s.sexo==='F'?'Femenino':s.sexo==='M'?'Masculino':'—'}</span></div>
      <div class="kv"><span>EPS</span><span>${escapeHtml(s.eps)||'—'}</span></div>
      <div class="kv"><span>RH</span><span>${escapeHtml(s.rh)||'—'}</span></div>
      <div class="kv"><span>Alergias</span><span>${escapeHtml(s.alergias)||'Ninguna registrada'}</span></div>
      <div class="kv"><span>Celular</span><span>${escapeHtml(s.celular)||'—'}</span></div>
      <div class="kv"><span>Correo</span><span>${escapeHtml(s.correo)||'—'}</span></div>
      <div class="kv"><span>Acudiente</span><span>${escapeHtml(s.acudiente)||'—'}</span></div>
      <div class="kv"><span>Tel. acudiente</span><span>${escapeHtml(s.telefonoAcudiente)||'—'}</span></div>
      <div class="kv"><span>Contacto emergencia</span><span>${escapeHtml(s.contactoEmergencia)||'—'}</span></div>
      <div class="kv"><span>Dirección</span><span>${escapeHtml(s.direccion)||'—'} ${escapeHtml(s.barrio)||''}</span></div>
      <div class="kv"><span>Municipio</span><span>${escapeHtml(s.municipio)||'—'}</span></div>
      <div class="kv"><span>Grupos</span><span>${groupOfStudent(s).map(g=>g.dia+' '+g.hora).join(', ')||'—'}</span></div>
      ${s.observaciones? '<div style="margin-top:12px;padding:10px;background:var(--surface-2);border-radius:9px;font-size:12.5px;"><b>Observaciones:</b> '+escapeHtml(s.observaciones)+'</div>' : ''}
      <div style="margin-top:14px;">
        <div style="font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--ink-faint);font-weight:700;margin-bottom:6px;">Documentos</div>
        ${['foto','identidad','eps','consentimiento'].map(k=>`<div class="kv"><span>${{foto:'Foto',identidad:'Identidad',eps:'Certificado EPS',consentimiento:'Consentimiento'}[k]}</span><span>${s.docs&&s.docs[k]?'✅ Recibido':'— Pendiente'}</span></div>`).join('')}
      </div>
    `;
  } else if(state.drawerTab==='pagos'){
    const recs = state.payments.filter(p=>p.studentId===s.id).sort((a,b)=>b.fecha.localeCompare(a.fecha));
    body.innerHTML = `
      <button class="btn btn-primary btn-sm" style="width:100%;justify-content:center;margin-bottom:12px;" data-action="open-add-payment" data-id="${s.id}">Registrar pago</button>
      ${recs.length? recs.map(r=>`<div class="kv"><span>${monthLabel(r.mes)} · ${{mensualidad:'Mensualidad',matricula:'Matrícula',abono:'Abono',cortesia:'Cortesía',beca:'Beca'}[r.tipo]||r.tipo}</span><span>${fmtMoney(r.monto)}</span></div>`).join('') : '<div class="empty" style="padding:20px;">Sin pagos registrados</div>'}
    `;
  } else if(state.drawerTab==='asistencia'){
    const recs = state.attendance.filter(a=>a.studentId===s.id).sort((a,b)=>b.fecha.localeCompare(a.fecha));
    const total = recs.length;
    const counts = {asistio:0,tarde:0,falta:0,incapacidad:0,permiso:0};
    recs.forEach(r=>counts[r.estado]=(counts[r.estado]||0)+1);
    const pct = total ? Math.round(100*(counts.asistio+counts.tarde)/total) : null;
    const last = recs[0];
    body.innerHTML = `
      <div class="kpi-card" style="margin-bottom:12px;"><div class="kpi-label">Porcentaje de asistencia</div><div class="kpi-value">${pct===null?'—':pct+'%'}</div><div class="kpi-sub">${counts.asistio} asistencias de ${total} registros</div></div>
      <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:8px;margin-bottom:14px;">
        <div class="kv" style="border:1px solid var(--border);border-radius:8px;padding:8px 10px;"><span>Faltas</span><span>${counts.falta}</span></div>
        <div class="kv" style="border:1px solid var(--border);border-radius:8px;padding:8px 10px;"><span>Tarde</span><span>${counts.tarde}</span></div>
        <div class="kv" style="border:1px solid var(--border);border-radius:8px;padding:8px 10px;"><span>Permisos</span><span>${counts.permiso}</span></div>
        <div class="kv" style="border:1px solid var(--border);border-radius:8px;padding:8px 10px;"><span>Incapacidad</span><span>${counts.incapacidad}</span></div>
      </div>
      <div class="kv"><span>Última asistencia</span><span>${last?fmtDate(last.fecha)+' · '+attLabel(last.estado):'—'}</span></div>
      <div class="kv"><span>Profesor</span><span>${last?escapeHtml(last.profesor||'—'):'—'}</span></div>
      <div style="margin:14px 0 8px;"><button class="btn btn-sm" data-action="export-student-attendance" data-id="${s.id}" style="width:100%;justify-content:center;">Exportar historial (CSV)</button></div>
      <div style="font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--ink-faint);font-weight:700;margin:14px 0 8px;">Calendario · ${new Date().toLocaleDateString('es-CO',{month:'long',year:'numeric'})}</div>
      ${buildMiniCalendar(recs)}
      <div style="font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--ink-faint);font-weight:700;margin:16px 0 8px;">Registros</div>
      ${recs.length? recs.map(r=>`<div class="kv"><span>${fmtDate(r.fecha)} ${r.observaciones?'· <i>'+escapeHtml(r.observaciones)+'</i>':''}</span><span>${attLabel(r.estado)}</span></div>`).join('') : '<div class="empty" style="padding:20px;">Aún no hay registros de asistencia</div>'}
    `;
  }
}
function buildMiniCalendar(recs){
  const now = new Date();
  const y = now.getFullYear(), m = now.getMonth();
  const firstDay = new Date(y,m,1).getDay();
  const daysInMonth = new Date(y,m+1,0).getDate();
  const byDate = {};
  recs.forEach(r=>{ byDate[r.fecha] = r.estado; });
  const colors = {asistio:'var(--success)', tarde:'var(--warning)', falta:'var(--danger)', incapacidad:'var(--primary)', permiso:'var(--primary)'};
  let cells = '';
  for(let i=0;i<firstDay;i++) cells += '<div></div>';
  for(let d=1; d<=daysInMonth; d++){
    const iso = y+'-'+String(m+1).padStart(2,'0')+'-'+String(d).padStart(2,'0');
    const est = byDate[iso];
    cells += `<div style="aspect-ratio:1;display:flex;align-items:center;justify-content:center;font-size:10.5px;border-radius:6px;${est?('background:'+colors[est]+'22;color:'+colors[est]+';font-weight:700;'):'color:var(--ink-faint);'}" title="${est?attLabel(est):''}">${d}</div>`;
  }
  return `<div style="display:grid;grid-template-columns:repeat(7,1fr);gap:3px;">${['D','L','M','X','J','V','S'].map(d=>`<div style="text-align:center;font-size:9.5px;color:var(--ink-faint);font-weight:700;">${d}</div>`).join('')}${cells}</div>`;
}
function attLabel(v){
  return {asistio:'✅ Asistió', tarde:'🟡 Tarde', falta:'🔴 Falta', incapacidad:'🩺 Incapacidad', permiso:'📄 Permiso'}[v] || v;
}
async function deleteStudent(id){
  if(!confirm('¿Eliminar este alumno definitivamente? Esta acción no se puede deshacer.')) return;
  state.students = state.students.filter(s=>s.id!==id);
  await saveKey('mantarayas:students', state.students);
  toast('Alumno eliminado'); closeDrawer(); renderNav(); renderCurrentView();
}
/* ============ PAGOS VIEW ============ */
state._pagosMes = monthKey();
function viewPagos(el){
  const mk = state._pagosMes;
  const activos = state.students.filter(s=>s.estado==='activo');
  const ingresos = state.payments.filter(p=>p.mes===mk).reduce((a,p)=>a+p.monto,0);
  const morosos = activos.filter(s=>paymentStatusForMonth(s.id,mk)==='vencido');
  const pendientes = activos.filter(s=>paymentStatusForMonth(s.id,mk)==='pendiente');
  const alDia = activos.filter(s=>['pagado','cortesia'].includes(paymentStatusForMonth(s.id,mk)));

  el.innerHTML = `
    <div class="view-header">
      <div><h1 class="view-title">Pagos</h1><p class="view-desc">Cartera y mensualidades del club.</p></div>
      <div style="display:flex;gap:8px;align-items:center;">
        ${monthYearPickerHTML('pagosMes', mk)}
        <button class="btn" data-action="export-pagos"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3v13m0 0-4-4m4 4 4-4M4 20h16"/></svg>Exportar CSV</button>
      </div>
    </div>
    <div class="kpi-grid">
      ${kpi('Ingresos del mes', fmtMoney(ingresos), state.payments.filter(p=>p.mes===mk).length+' pagos')}
      ${kpi('Al día', alDia.length, Math.round(100*alDia.length/(activos.length||1))+'% de activos', 'var(--success)')}
      ${kpi('Pendientes', pendientes.length, 'sin pago registrado aún', pendientes.length?'var(--warning)':null)}
      ${kpi('Morosos', morosos.length, 'requieren seguimiento', morosos.length?'var(--danger)':null)}
    </div>
    <div class="card">
      <div class="card-head"><h3>Estado por alumno — ${monthLabel(mk)}</h3></div>
      <div class="table-wrap"><table><thead><tr><th>Alumno</th><th>Grupo</th><th>Estado</th><th>Valor</th><th>Acción</th></tr></thead><tbody>
        ${activos.length? activos.sort((a,b)=>a.nombre.localeCompare(b.nombre)).map(s=>rowPago(s,mk)).join('') : '<tr><td colspan="5"><div class="empty">No hay alumnos activos.</div></td></tr>'}
      </tbody></table></div>
    </div>
  `;
  bindMonthYearPicker('pagosMes', ()=>{ state._pagosMes = readMonthYearPicker('pagosMes'); viewPagos(el); });
}
function lastNMonths(n){
  const arr = []; const d = new Date();
  for(let i=0;i<n;i++){ arr.push(monthKey(d)); d.setMonth(d.getMonth()-1); }
  return arr;
}
function rowPago(s, mk){
  const status = paymentStatusForMonth(s.id, mk);
  const rec = state.payments.filter(p=>p.studentId===s.id && p.mes===mk && (p.tipo==='mensualidad'||p.tipo==='cortesia')).slice(-1)[0];
  const grupos = groupOfStudent(s).map(g=>g.dia.slice(0,3)).join(', ');
  return `<tr data-action="open-student" data-id="${s.id}">
    <td><div style="display:flex;align-items:center;gap:9px;"><div class="avatar" style="width:30px;height:30px;font-size:11px;">${initials(s.nombre)}</div><div class="cell-name">${escapeHtml(s.nombre)}</div></div></td>
    <td>${grupos||'—'}</td>
    <td>${statusBadge(status)}</td>
    <td>${rec?fmtMoney(rec.monto):'—'}</td>
    <td><button class="btn btn-sm" data-action="open-add-payment" data-id="${s.id}" onclick="event.stopPropagation()">Registrar pago</button></td>
  </tr>`;
}

function openPaymentModal(studentId, defaultMes){
  const s = state.students.find(x=>x.id===studentId);
  if(!s) return;
  const mk = defaultMes || state._pagosMes || monthKey();
  const html = `
    <div class="modal-head"><h3>Registrar pago — ${escapeHtml(s.nombre)}</h3><button class="icon-btn" data-action="close-modal"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6 6 18M6 6l12 12"/></svg></button></div>
    <div class="modal-body">
      <form id="paymentForm">
        <div class="field-row">
          <div class="field"><label>Tipo de pago</label><select name="tipo" id="paymentTipo">
            <option value="mensualidad">Mensualidad</option><option value="matricula">Matrícula</option>
            <option value="abono">Abono</option><option value="beca">Beca (100%)</option><option value="cortesia">Cortesía</option>
          </select></div>
          <div class="field"><label>Mes que cubre</label><div style="display:flex;gap:6px;">${monthYearPickerHTML('paymentMes', mk)}</div></div>
        </div>
        <div class="field-row">
          <div class="field"><label>Valor</label><input type="number" name="monto" id="paymentMonto" value="120000" min="0" step="1000"></div>
          <div class="field"><label>Método de pago</label><select name="metodo"><option>Transferencia</option><option>Efectivo</option><option>Tarjeta</option><option>Nequi/Daviplata</option></select></div>
        </div>
        <div class="field"><label>Fecha</label><input type="date" name="fecha" value="${todayISO()}"></div>
        <div class="field"><label>Nota / comprobante</label><textarea name="nota" rows="2" placeholder="Número de comprobante o nota interna"></textarea></div>
      </form>
    </div>
    <div class="modal-foot"><button class="btn" data-action="close-modal">Cancelar</button><button class="btn btn-primary" data-action="save-payment" data-id="${s.id}">Guardar pago</button></div>
  `;
  openModal(html);
  const tipoSel = document.getElementById('paymentTipo');
  const montoInp = document.getElementById('paymentMonto');
  tipoSel.addEventListener('change', ()=>{
    if(tipoSel.value==='cortesia'||tipoSel.value==='beca') montoInp.value = 0;
    else if(tipoSel.value==='matricula') montoInp.value = 50000;
    else montoInp.value = 120000;
  });
}
async function savePaymentFromForm(studentId){
  const fd = new FormData(document.getElementById('paymentForm'));
  const mes = readMonthYearPicker('paymentMes');
  const rec = {id:uid('pg'), studentId, tipo:fd.get('tipo'), mes, monto:Number(fd.get('monto'))||0, metodo:fd.get('metodo'), fecha:fd.get('fecha')||todayISO(), nota:fd.get('nota')||''};
  state.payments.push(rec);
  const ok = await saveKey('mantarayas:payments', state.payments);
  if(ok){ toast('Pago registrado'); closeModal(); renderCurrentView(); if(state.drawerStudentId===studentId) renderDrawerBody(); }
}

/* ============ ASISTENCIA VIEW ============ */
state._asist = {groupId:null, fecha: todayISO()};
function viewAsistencia(el){
  const groups = state.role==='profesor' ? state.groups.filter(g=>g.entrenador===state.profesorActual) : state.groups;
  if(!state._asist.groupId || !groups.find(g=>g.id===state._asist.groupId)) state._asist.groupId = groups[0]?.id || null;
  const g = groups.find(x=>x.id===state._asist.groupId);
  const roster = g ? studentsInGroup(g) : [];
  const existing = {};
  if(g) state.attendance.filter(a=>a.groupId===g.id && a.fecha===state._asist.fecha).forEach(a=>existing[a.studentId]=a);
  const isToday = state._asist.fecha === todayISO();
  const locked = state.role==='profesor' && !isToday;

  el.innerHTML = `
    <div class="view-header">
      <div><h1 class="view-title">Asistencia</h1><p class="view-desc">Marca la asistencia del grupo y guarda el registro del día.</p></div>
    </div>
    <div class="toolbar">
      <select id="asistGroupSelect">${groups.map(gr=>`<option value="${gr.id}" ${gr.id===g?.id?'selected':''}>${gr.dia} ${gr.hora} — ${gr.entrenador}</option>`).join('') || '<option>No hay grupos</option>'}</select>
      <input type="date" id="asistFecha" value="${state._asist.fecha}" max="${todayISO()}">
      <span class="cell-sub" style="margin-left:auto;">${roster.length} alumno${roster.length===1?'':'s'} en este grupo</span>
    </div>
    ${locked ? '<div class="login-error active" style="margin-bottom:12px;">Solo puedes editar la asistencia del día actual. Un Administrador puede modificar fechas anteriores.</div>' : ''}
    <div class="card">
      <div class="table-wrap">
        <table><thead><tr><th>Alumno</th><th>Debe mensualidad</th><th>Marcar asistencia</th><th>Nota</th></tr></thead>
        <tbody id="asistTbody">
        ${roster.length ? roster.sort((a,b)=>a.nombre.localeCompare(b.nombre)).map(s=>{
          const debe = ['pendiente','vencido'].includes(paymentStatusForMonth(s.id, monthKey()));
          const cur = existing[s.id];
          return `<tr>
            <td><div style="display:flex;align-items:center;gap:9px;"><div class="avatar" style="width:30px;height:30px;font-size:11px;">${initials(s.nombre)}</div><div class="cell-name">${escapeHtml(s.nombre)}</div></div></td>
            <td>${debe?'<span class="badge badge-warning">Sí</span>':'<span class="badge badge-success">No</span>'}</td>
            <td><div class="att-options" data-student="${s.id}" style="${locked?'pointer-events:none;opacity:.55;':''}">
              ${['asistio','tarde','falta','incapacidad','permiso'].map(v=>`<button type="button" class="att-opt sel-${v} ${cur&&cur.estado===v?'selected':''}" data-val="${v}">${attLabel(v).replace(/^\S+\s/,'')}</button>`).join('')}
            </div></td>
            <td><input type="text" class="att-note" data-student-note="${s.id}" placeholder="Opcional" value="${escapeHtml(cur?cur.observaciones||'':'')}" ${locked?'disabled':''} style="min-width:130px;"></td>
          </tr>`;
        }).join('') : '<tr><td colspan="4"><div class="empty">Este grupo no tiene alumnos activos asignados.</div></td></tr>'}
        </tbody></table>
      </div>
      ${roster.length && !locked? '<div style="padding:14px 18px;border-top:1px solid var(--border);display:flex;justify-content:flex-end;"><button class="btn btn-primary" data-action="save-attendance">Guardar asistencia</button></div>' : ''}
    </div>
  `;
  document.getElementById('asistGroupSelect')?.addEventListener('change', e=>{ state._asist.groupId = e.target.value; viewAsistencia(el); });
  document.getElementById('asistFecha')?.addEventListener('change', e=>{ state._asist.fecha = e.target.value; viewAsistencia(el); });
  if(!locked){
    el.querySelectorAll('.att-options').forEach(wrap=>{
      wrap.querySelectorAll('.att-opt').forEach(btn=>btn.addEventListener('click', ()=>{
        wrap.querySelectorAll('.att-opt').forEach(b=>b.classList.remove('selected'));
        btn.classList.add('selected');
      }));
    });
  }
}
async function saveAttendance(){
  const g = state.groups.find(x=>x.id===state._asist.groupId);
  if(!g) return;
  const fecha = state._asist.fecha;
  const rows = document.querySelectorAll('#asistTbody .att-options');
  const now = new Date().toISOString();
  const user = currentUser();
  let count = 0;
  const previous = state.attendance.filter(a=>a.groupId===g.id && a.fecha===fecha);
  state.attendance = state.attendance.filter(a=>!(a.groupId===g.id && a.fecha===fecha));
  rows.forEach(wrap=>{
    const sel = wrap.querySelector('.att-opt.selected');
    if(!sel) return;
    const studentId = wrap.dataset.student;
    const noteInput = document.querySelector('[data-student-note="'+studentId+'"]');
    const prev = previous.find(p=>p.studentId===studentId);
    state.attendance.push({
      id: prev ? prev.id : uid('at'), studentId, groupId:g.id, fecha, estado:sel.dataset.val,
      observaciones: noteInput ? noteInput.value : '',
      profesor:g.entrenador, registradoPor: user ? user.usuario : 'sistema',
      fechaCreacion: prev ? prev.fechaCreacion : now, fechaModificacion: now,
    });
    count++;
  });
  const ok = await saveKey('mantarayas:attendance', state.attendance);
  if(ok){
    toast('Asistencia registrada correctamente.');
    renderCurrentView();
    if(state.drawerStudentId) renderDrawerBody();
  }
}
function exportStudentAttendanceCSV(studentId){
  const s = state.students.find(x=>x.id===studentId);
  if(!s) return;
  const recs = state.attendance.filter(a=>a.studentId===studentId).sort((a,b)=>a.fecha.localeCompare(b.fecha));
  const rows = [['Fecha','Estado','Grupo','Profesor','Observaciones','Registrado por']];
  recs.forEach(r=>{
    const g = state.groups.find(x=>x.id===r.groupId);
    rows.push([r.fecha, attLabel(r.estado).replace(/^\S+\s/,''), g?(g.dia+' '+g.hora):'', r.profesor, r.observaciones||'', r.registradoPor||'']);
  });
  downloadCSV('asistencia_'+s.nombre.replace(/\s+/g,'_')+'.csv', rows);
  toast('Historial de asistencia exportado');
}

/* ============ HORARIOS VIEW ============ */
function viewHorarios(el){
  el.innerHTML = `
    <div class="view-header">
      <div><h1 class="view-title">Horarios y grupos</h1><p class="view-desc">Sedes, piscinas, carriles, entrenadores y cupos.</p></div>
      <div style="display:flex;gap:8px;">
        <button class="btn" data-action="open-move-students"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 8l4 4-4 4M3 12h18"/></svg>Mover alumnos</button>
        <button class="btn btn-primary" data-action="open-add-group"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg>Nuevo grupo</button>
      </div>
    </div>
    <div class="grid-2col">
      ${['Lunes','Martes','Miércoles','Viernes'].map(dia=>{
        const gs = state.groups.filter(g=>g.dia===dia);
        if(!gs.length) return '';
        return `<div class="card"><div class="card-head"><h3>${dia}</h3></div><div class="card-pad" style="display:flex;flex-direction:column;gap:10px;">
          ${gs.map(g=>{
            const n = studentsInGroup(g).length;
            const pct = Math.min(100, Math.round(100*n/g.cupoMax));
            const over = n>=g.cupoMax;
            const suspendido = g.estado==='suspendido';
            return `<div style="border:1px solid var(--border);border-radius:10px;padding:11px 13px;${suspendido?'opacity:.6;':''}">
              <div style="display:flex;justify-content:space-between;align-items:center;cursor:pointer;" data-action="open-edit-group" data-id="${g.id}">
                <div><div class="cell-name">${g.hora} ${g.nivel?('· '+escapeHtml(g.nivel)):''} ${suspendido?'<span class="badge badge-neutral" style="margin-left:6px;">Suspendido</span>':''}</div><div class="cell-sub">${g.entrenador} · ${g.sede} · Carril ${g.carril}</div></div>
                <span class="badge ${over?'badge-danger':'badge-neutral'}">${n} / ${g.cupoMax}</span>
              </div>
              <div style="height:5px;background:var(--surface-2);border-radius:99px;margin-top:9px;overflow:hidden;"><div style="height:100%;width:${pct}%;background:${over?'var(--danger)':'var(--primary)'};"></div></div>
              <div style="display:flex;gap:6px;margin-top:9px;">
                <button class="btn btn-sm btn-ghost" data-action="duplicate-group" data-id="${g.id}">Duplicar</button>
                <button class="btn btn-sm btn-ghost" data-action="toggle-suspend-group" data-id="${g.id}">${suspendido?'Reactivar':'Suspender'}</button>
              </div>
            </div>`;
          }).join('')}
        </div></div>`;
      }).join('')}
    </div>
  `;
}
async function duplicateGroup(id){
  const g = state.groups.find(x=>x.id===id);
  if(!g) return;
  const copy = {...g, id:uid('g'), codigo:g.codigo+'-COPIA', hora:g.hora+' (copia)'};
  state.groups.push(copy);
  await saveKey('mantarayas:groups', state.groups);
  toast('Grupo duplicado'); renderCurrentView();
}
async function toggleSuspendGroup(id){
  const idx = state.groups.findIndex(g=>g.id===id);
  if(idx<0) return;
  state.groups[idx].estado = state.groups[idx].estado==='suspendido' ? 'activo' : 'suspendido';
  await saveKey('mantarayas:groups', state.groups);
  toast(state.groups[idx].estado==='suspendido' ? 'Grupo suspendido' : 'Grupo reactivado');
  renderCurrentView();
}
function openMoveStudentsModal(){
  const html = `
    <div class="modal-head"><h3>Mover alumnos entre horarios</h3><button class="icon-btn" data-action="close-modal"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6 6 18M6 6l12 12"/></svg></button></div>
    <div class="modal-body">
      <div class="field"><label>Grupo de origen</label><select id="moveFrom">${state.groups.map(g=>`<option value="${g.id}">${g.dia} ${g.hora} — ${g.entrenador}</option>`).join('')}</select></div>
      <div class="field" id="moveStudentsList"></div>
      <div class="field"><label>Grupo destino</label><select id="moveTo">${state.groups.map(g=>`<option value="${g.id}">${g.dia} ${g.hora} — ${g.entrenador}</option>`).join('')}</select></div>
    </div>
    <div class="modal-foot"><button class="btn" data-action="close-modal">Cancelar</button><button class="btn btn-primary" data-action="confirm-move-students">Mover seleccionados</button></div>
  `;
  openModal(html);
  const fromSel = document.getElementById('moveFrom');
  function renderList(){
    const g = state.groups.find(x=>x.id===fromSel.value);
    const ss = studentsInGroup(g);
    document.getElementById('moveStudentsList').innerHTML = '<label>Alumnos en este grupo</label>' +
      (ss.length ? ss.map(s=>`<label style="display:flex;align-items:center;gap:7px;padding:5px 0;font-size:13px;"><input type="checkbox" value="${s.id}" class="move-student-check" style="width:auto;">${escapeHtml(s.nombre)}</label>`).join('')
      : '<div class="hint">Este grupo no tiene alumnos.</div>');
  }
  fromSel.addEventListener('change', renderList);
  renderList();
}
async function confirmMoveStudents(){
  const fromId = document.getElementById('moveFrom').value;
  const toId = document.getElementById('moveTo').value;
  const fromG = state.groups.find(g=>g.id===fromId);
  const toG = state.groups.find(g=>g.id===toId);
  if(!fromG || !toG || fromId===toId){ toast('Selecciona dos grupos distintos', 'warning'); return; }
  const checked = Array.from(document.querySelectorAll('.move-student-check:checked')).map(c=>c.value);
  if(!checked.length){ toast('Selecciona al menos un alumno', 'warning'); return; }
  const nAfter = studentsInGroup(toG).length + checked.length;
  if(nAfter > toG.cupoMax){ toast('El grupo destino no tiene cupo suficiente', 'danger'); return; }
  checked.forEach(sid=>{
    const s = state.students.find(x=>x.id===sid);
    if(!s) return;
    s.horarios = (s.horarios||[]).filter(h=>normCode(h)!==fromG.codigo);
    if(!s.horarios.some(h=>normCode(h)===toG.codigo)) s.horarios.push(toG.codigo);
  });
  await saveKey('mantarayas:students', state.students);
  toast(checked.length+' alumno(s) movidos'); closeModal(); renderCurrentView();
}
function openGroupModal(groupId){
  const g = groupId ? state.groups.find(x=>x.id===groupId) : null;
  const d = g || {dia:'Lunes',hora:'',codigo:'',entrenador:state.teachers[0],sede:'Sede Principal',piscina:'Piscina 1',carril:'',cupoMax:20};
  const html = `
    <div class="modal-head"><h3>${g?'Editar grupo':'Nuevo grupo'}</h3><button class="icon-btn" data-action="close-modal"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6 6 18M6 6l12 12"/></svg></button></div>
    <div class="modal-body">
      <form id="groupForm">
        <div class="field-row">
          <div class="field"><label>Día</label><select name="dia">${['Lunes','Martes','Miércoles','Jueves','Viernes','Sábado'].map(d2=>`<option ${d2===d.dia?'selected':''}>${d2}</option>`).join('')}</select></div>
          <div class="field"><label>Horario (ej. 4:00 - 5:00 pm)</label><input name="hora" value="${escapeHtml(d.hora)}" required></div>
        </div>
        <div class="field-row">
          <div class="field"><label>Código interno (ej. L4-5)</label><input name="codigo" value="${escapeHtml(d.codigo)}" placeholder="L4-5"></div>
          <div class="field"><label>Entrenador</label><select name="entrenador">${state.teachers.concat(['Sin asignar']).map(t=>`<option ${t===d.entrenador?'selected':''}>${t}</option>`).join('')}</select></div>
        </div>
        <div class="field-row">
          <div class="field"><label>Nivel</label><input name="nivel" value="${escapeHtml(d.nivel||'')}" placeholder="Iniciación, intermedio…"></div>
          <div class="field"><label>Cupo máximo</label><input type="number" name="cupoMax" value="${d.cupoMax}" min="1"></div>
        </div>
        <div class="field-row3">
          <div class="field"><label>Sede</label><input name="sede" value="${escapeHtml(d.sede)}"></div>
          <div class="field"><label>Piscina</label><input name="piscina" value="${escapeHtml(d.piscina)}"></div>
          <div class="field"><label>Carril(es)</label><input name="carril" value="${escapeHtml(d.carril)}"></div>
        </div>
        <div class="field"><label>Observaciones</label><textarea name="observaciones" rows="2">${escapeHtml(d.observaciones||'')}</textarea></div>
        <div id="overlapWarning" class="login-error" style="margin-top:4px;"></div>
      </form>
    </div>
    <div class="modal-foot">
      ${g && state.role==='super' ? '<button class="btn btn-danger" data-action="delete-group" data-id="'+g.id+'" style="margin-right:auto;">Eliminar</button>' : ''}
      <button class="btn" data-action="close-modal">Cancelar</button>
      <button class="btn btn-primary" data-action="save-group" data-id="${g?g.id:''}">${g?'Guardar':'Crear grupo'}</button>
    </div>
  `;
  openModal(html);
}
async function saveGroupFromForm(existingId){
  const fd = new FormData(document.getElementById('groupForm'));
  const payload = {dia:fd.get('dia'), hora:fd.get('hora'), codigo:fd.get('codigo')||uid('c'), entrenador:fd.get('entrenador'), nivel:fd.get('nivel')||'', sede:fd.get('sede'), piscina:fd.get('piscina'), carril:fd.get('carril'), cupoMax:Number(fd.get('cupoMax'))||20, observaciones:fd.get('observaciones')||''};
  if(payload.entrenador!=='Sin asignar'){
    const clash = state.groups.some(g=>g.id!==existingId && g.entrenador===payload.entrenador && g.dia===payload.dia && g.hora===payload.hora);
    if(clash){
      document.getElementById('overlapWarning').textContent = payload.entrenador+' ya tiene un grupo asignado en '+payload.dia+' '+payload.hora+'. Elige otro horario o entrenador.';
      document.getElementById('overlapWarning').classList.add('active');
      return;
    }
  }
  if(existingId){
    const idx = state.groups.findIndex(g=>g.id===existingId);
    state.groups[idx] = {...state.groups[idx], ...payload};
  } else {
    payload.id = uid('g'); payload.estado='activo';
    state.groups.push(payload);
  }
  const ok = await saveKey('mantarayas:groups', state.groups);
  if(ok){ toast(existingId?'Grupo actualizado':'Grupo creado'); closeModal(); renderCurrentView(); }
}
async function deleteGroup(id){
  if(!confirm('¿Eliminar este grupo?')) return;
  state.groups = state.groups.filter(g=>g.id!==id);
  await saveKey('mantarayas:groups', state.groups);
  toast('Grupo eliminado'); closeModal(); renderCurrentView();
}
/* ============ USUARIOS VIEW ============ */
async function viewUsuarios(el){
  el.innerHTML = '<div class="empty">Cargando usuarios…</div>';
  try{
    const res = await apiFetch('/users');
    if(!res.ok){
      el.innerHTML = '<div class="access-denied"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="m8 8 8 8"/></svg><h3>Acceso denegado</h3><p>No tienes permiso para ver los usuarios.</p></div>';
      return;
    }
    state.users = await res.json();
  }catch(e){
    el.innerHTML = '<div class="empty">No se pudo cargar la lista de usuarios. Verifica tu conexión.</div>';
    return;
  }
  const list = state.users.slice().sort((a,b)=>a.nombre.localeCompare(b.nombre));
  el.innerHTML = `
    <div class="view-header">
      <div><h1 class="view-title">Usuarios</h1><p class="view-desc">Cuentas de acceso a la plataforma. Solo el Super Administrador puede gestionarlas.</p></div>
      <button class="btn btn-primary" data-action="open-add-user"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg>Nuevo usuario</button>
    </div>
    <div class="card" style="margin-bottom:14px;">
      <div class="card-head"><h3>Profesores vinculados</h3><span class="cell-sub">${state.teachers.length} registrados</span></div>
      <div class="card-pad">
        <p class="hint" style="margin-bottom:12px;">Esta lista alimenta el selector de "Entrenador" en Horarios y el de "Entrenador vinculado" al crear un usuario con rol Profesor.</p>
        <div style="display:flex; flex-wrap:wrap; gap:8px; margin-bottom:14px;">
          ${state.teachers.map(t=>{
            const enUso = state.groups.some(g=>g.entrenador===t) || state.users.some(u=>u.profesorNombre===t);
            return `<span class="badge badge-neutral" style="padding:6px 6px 6px 11px; gap:8px;">${escapeHtml(t)}${enUso?' <span class="cell-sub" style="font-weight:500;">(en uso)</span>':''}
              <button data-action="delete-teacher" data-teacher="${escapeHtml(t)}" style="border:none;background:none;cursor:pointer;color:var(--ink-faint);padding:0;display:inline-flex;"><svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.4"><path d="M18 6 6 18M6 6l12 12"/></svg></button>
            </span>`;
          }).join('') || '<span class="cell-sub">Aún no hay profesores registrados.</span>'}
        </div>
        <form id="addTeacherForm" style="display:flex; gap:8px;">
          <input name="nombre" placeholder="Nombre completo del nuevo profesor" style="max-width:280px;" required>
          <button class="btn btn-primary btn-sm" type="submit">Agregar profesor</button>
        </form>
      </div>
    </div>
    <div class="card">
      <div class="table-wrap">
        <table><thead><tr><th>Usuario</th><th>Rol</th><th>Correo</th><th>Último ingreso</th><th>Estado</th><th></th></tr></thead>
        <tbody>${list.map(rowUsuario).join('')}</tbody></table>
      </div>
    </div>
  `;
  document.getElementById('addTeacherForm').addEventListener('submit', async e=>{
    e.preventDefault();
    const input = e.target.elements.nombre;
    await addTeacher(input.value);
  });
}
async function addTeacher(nombre){
  nombre = (nombre||'').trim();
  if(!nombre){ toast('Escribe el nombre del profesor', 'warning'); return; }
  if(state.teachers.some(t=>t.toLowerCase()===nombre.toLowerCase())){ toast('Ese profesor ya está registrado', 'warning'); return; }
  state.teachers.push(nombre);
  const ok = await saveKey('mantarayas:teachers', state.teachers);
  if(ok){ toast('Profesor agregado'); renderCurrentView(); }
}
async function deleteTeacherName(nombre){
  const enUso = state.groups.some(g=>g.entrenador===nombre) || state.users.some(u=>u.profesorNombre===nombre);
  if(enUso){ toast('No se puede eliminar: está asignado a un horario o a un usuario. Reasígnalo primero.', 'danger'); return; }
  if(!confirm('¿Eliminar a '+nombre+' de la lista de profesores?')) return;
  state.teachers = state.teachers.filter(t=>t!==nombre);
  const ok = await saveKey('mantarayas:teachers', state.teachers);
  if(ok){ toast('Profesor eliminado'); renderCurrentView(); }
}
function rowUsuario(u){
  return `<tr>
    <td><div style="display:flex;align-items:center;gap:9px;"><div class="avatar" style="width:30px;height:30px;font-size:11px;">${initials(u.nombre+' '+u.apellido)}</div><div><div class="cell-name">${escapeHtml(u.nombre)} ${escapeHtml(u.apellido)}</div><div class="cell-sub">@${escapeHtml(u.usuario)}</div></div></div></td>
    <td><span class="badge badge-primary">${ROLE_LABELS[u.rol]||u.rol}</span>${u.profesorNombre?' <span class="cell-sub">'+escapeHtml(u.profesorNombre)+'</span>':''}</td>
    <td>${escapeHtml(u.correo)||'—'}</td>
    <td>${u.ultimoIngreso ? new Date(u.ultimoIngreso).toLocaleString('es-CO') : 'Nunca'}</td>
    <td>${u.estado==='activo'?'<span class="badge badge-success">Activo</span>':'<span class="badge badge-neutral">Inactivo</span>'}</td>
    <td style="text-align:right;white-space:nowrap;">
      <button class="btn btn-sm btn-ghost" data-action="edit-user" data-id="${u.id}">Editar</button>
      <button class="btn btn-sm btn-ghost" data-action="toggle-user-estado" data-id="${u.id}">${u.estado==='activo'?'Desactivar':'Activar'}</button>
    </td>
  </tr>`;
}
function openUserModal(userId){
  const u = userId ? state.users.find(x=>x.id===userId) : null;
  const d = u || {nombre:'',apellido:'',documento:'',correo:'',celular:'',usuario:'',password:'',rol:'admin',estado:'activo',profesorNombre:'',sedeAsignada:'Sede Principal',gruposAsignados:[]};
  const html = `
    <div class="modal-head"><h3>${u?'Editar usuario':'Nuevo usuario'}</h3><button class="icon-btn" data-action="close-modal"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6 6 18M6 6l12 12"/></svg></button></div>
    <div class="modal-body">
      <form id="userForm">
        <div class="field-row">
          <div class="field"><label>Nombre *</label><input required name="nombre" value="${escapeHtml(d.nombre)}"></div>
          <div class="field"><label>Apellido</label><input name="apellido" value="${escapeHtml(d.apellido)}"></div>
        </div>
        <div class="field-row">
          <div class="field"><label>Documento</label><input name="documento" value="${escapeHtml(d.documento)}"></div>
          <div class="field"><label>Celular</label><input name="celular" value="${escapeHtml(d.celular)}"></div>
        </div>
        <div class="field"><label>Correo</label><input type="email" name="correo" value="${escapeHtml(d.correo)}"></div>
        <div class="field-row">
          <div class="field"><label>Usuario (para ingresar) *</label><input required name="usuario" value="${escapeHtml(d.usuario)}" ${u?'':''}></div>
          <div class="field"><label>Contraseña ${u?'(dejar vacío para no cambiar)':'*'}</label><input type="text" name="password" placeholder="${u?'••••••••':'Contraseña inicial'}" ${u?'':'required'}></div>
        </div>
        <div class="field-row">
          <div class="field"><label>Rol *</label><select name="rol" id="userRolSelect">
            <option value="super" ${d.rol==='super'?'selected':''}>Super Administrador</option>
            <option value="admin" ${d.rol==='admin'?'selected':''}>Administrador</option>
            <option value="profesor" ${d.rol==='profesor'?'selected':''}>Profesor</option>
            <option value="recepcionista" ${d.rol==='recepcionista'?'selected':''}>Recepcionista</option>
          </select></div>
          <div class="field"><label>Sede asignada</label><input name="sedeAsignada" value="${escapeHtml(d.sedeAsignada||'Sede Principal')}"></div>
        </div>
        <div class="field" id="userProfesorWrap" style="${d.rol==='profesor'?'':'display:none;'}">
          <label>Entrenador vinculado</label>
          <select name="profesorNombre">${state.teachers.map(t=>`<option ${t===d.profesorNombre?'selected':''}>${t}</option>`).join('')}</select>
          <p class="hint">Determina qué grupos verá este profesor en Asistencia.</p>
        </div>
      </form>
    </div>
    <div class="modal-foot">
      ${u ? '<button class="btn btn-danger" data-action="delete-user" data-id="'+u.id+'" style="margin-right:auto;">Eliminar</button>' : ''}
      <button class="btn" data-action="close-modal">Cancelar</button>
      <button class="btn btn-primary" data-action="save-user" data-id="${u?u.id:''}">${u?'Guardar cambios':'Crear usuario'}</button>
    </div>
  `;
  openModal(html);
  document.getElementById('userRolSelect').addEventListener('change', e=>{
    document.getElementById('userProfesorWrap').style.display = e.target.value==='profesor' ? 'block':'none';
  });
}
async function saveUserFromForm(existingId){
  const fd = new FormData(document.getElementById('userForm'));
  const usuario = (fd.get('usuario')||'').trim().toLowerCase();
  if(!fd.get('nombre').trim() || !usuario){ toast('Nombre y usuario son obligatorios', 'danger'); return; }
  const payload = {
    nombre: fd.get('nombre').trim(), apellido: fd.get('apellido')||'', documento: fd.get('documento')||'',
    correo: fd.get('correo')||'', celular: fd.get('celular')||'', usuario, rol: fd.get('rol'),
    sedeAsignada: fd.get('sedeAsignada')||'', profesorNombre: fd.get('rol')==='profesor' ? fd.get('profesorNombre') : '',
  };
  const pw = fd.get('password');
  if(pw) payload.password = pw;
  if(!existingId && !pw){ toast('La contraseña es obligatoria para un usuario nuevo', 'danger'); return; }
  const res = await apiFetch(existingId ? '/users/'+existingId : '/users', {method: existingId?'PUT':'POST', body: JSON.stringify(payload)});
  if(!res.ok){
    const err = await res.json().catch(()=>({}));
    toast(err.error || 'No se pudo guardar el usuario', 'danger');
    return;
  }
  toast(existingId?'Usuario actualizado':'Usuario creado'); closeModal(); renderCurrentView();
}
async function toggleUserEstado(id){
  if(id===state.session){ toast('No puedes desactivar tu propia cuenta', 'warning'); return; }
  const res = await apiFetch('/users/'+id+'/toggle', {method:'POST'});
  if(!res.ok){ const err = await res.json().catch(()=>({})); toast(err.error||'No se pudo actualizar', 'danger'); return; }
  toast('Usuario actualizado'); renderCurrentView();
}
async function deleteUser(id){
  if(id===state.session){ toast('No puedes eliminar tu propia cuenta', 'warning'); return; }
  if(!confirm('¿Eliminar este usuario definitivamente?')) return;
  const res = await apiFetch('/users/'+id, {method:'DELETE'});
  if(!res.ok){ const err = await res.json().catch(()=>({})); toast(err.error||'No se pudo eliminar', 'danger'); return; }
  toast('Usuario eliminado'); closeModal(); renderCurrentView();
}
/* ============ CONTABILIDAD ============ */
const CATEGORIAS_COMPRA = ['Insumos y químicos','Dotación / uniformes','Mantenimiento de equipos','Implementos deportivos','Otros'];
const CATEGORIAS_EGRESO = ['Arriendo','Nómina / profesores','Servicios públicos','Seguros','Mantenimiento piscina','Publicidad','Administrativo','Otros'];
state._contaMes = monthKey();

function viewContabilidad(el){
  const mk = state._contaMes;
  const ingresos = state.payments.filter(p=>p.mes===mk).reduce((a,p)=>a+p.monto,0);
  const compras = state.purchases.filter(p=>p.mes===mk);
  const egresos = state.expenses.filter(e=>e.mes===mk);
  const totalCompras = compras.reduce((a,p)=>a+p.valor,0);
  const totalEgresos = egresos.reduce((a,e)=>a+e.valor,0);
  const utilidad = ingresos - totalCompras - totalEgresos;

  const egresosPorCategoria = {};
  egresos.forEach(e=>{ egresosPorCategoria[e.categoria] = (egresosPorCategoria[e.categoria]||0) + e.valor; });
  const comprasPorCategoria = {};
  compras.forEach(p=>{ comprasPorCategoria[p.categoria] = (comprasPorCategoria[p.categoria]||0) + p.valor; });

  el.innerHTML = `
    <div class="view-header">
      <div><h1 class="view-title">Contabilidad</h1><p class="view-desc">Compras, egresos fijos y cierre financiero automático por mes.</p></div>
      <div style="display:flex;gap:8px;align-items:center;">
        ${monthYearPickerHTML('contaMes', mk)}
        <button class="btn" data-action="export-cierre"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3v13m0 0-4-4m4 4 4-4M4 20h16"/></svg>Exportar cierre (CSV)</button>
      </div>
    </div>

    <div class="kpi-grid">
      ${kpi('Ingresos', fmtMoney(ingresos), monthLabel(mk), 'var(--success)')}
      ${kpi('Compras', fmtMoney(totalCompras), compras.length+' registros')}
      ${kpi('Egresos fijos', fmtMoney(totalEgresos), egresos.length+' registros')}
      ${kpi('Utilidad del mes', fmtMoney(utilidad), utilidad>=0?'Resultado positivo':'Resultado negativo', utilidad>=0?'var(--success)':'var(--danger)')}
    </div>

    <div class="card" style="margin-bottom:14px;">
      <div class="card-head"><h3>Cierre financiero — ${monthLabel(mk)}</h3></div>
      <div class="card-pad">
        <div class="kv"><span>Ingresos (mensualidades, matrículas y abonos)</span><span style="color:var(--success);">+ ${fmtMoney(ingresos)}</span></div>
        <div class="kv"><span>Compras del mes</span><span style="color:var(--danger);">− ${fmtMoney(totalCompras)}</span></div>
        <div class="kv"><span>Egresos fijos del mes</span><span style="color:var(--danger);">− ${fmtMoney(totalEgresos)}</span></div>
        <div class="kv" style="border-top:2px solid var(--border); margin-top:6px; padding-top:12px; font-size:15px;"><span style="font-weight:700;">Utilidad neta</span><span style="font-weight:700; color:${utilidad>=0?'var(--success)':'var(--danger)'};">${fmtMoney(utilidad)}</span></div>
      </div>
    </div>

    <div class="grid-2">
      <div class="card">
        <div class="card-head"><h3>Compras del mes</h3><button class="btn btn-sm btn-primary" data-action="open-add-purchase">+ Compra</button></div>
        <div class="table-wrap">
          <table><thead><tr><th>Concepto</th><th>Categoría</th><th>Valor</th><th></th></tr></thead><tbody>
          ${compras.length ? compras.sort((a,b)=>b.fecha.localeCompare(a.fecha)).map(rowCompra).join('') : '<tr><td colspan="4"><div class="empty">Sin compras registradas este mes.</div></td></tr>'}
          </tbody></table>
        </div>
        ${Object.keys(comprasPorCategoria).length ? `<div class="card-pad" style="border-top:1px solid var(--border);">${Object.keys(comprasPorCategoria).map(c=>`<div class="kv"><span>${escapeHtml(c)}</span><span>${fmtMoney(comprasPorCategoria[c])}</span></div>`).join('')}</div>` : ''}
      </div>
      <div class="card">
        <div class="card-head"><h3>Egresos fijos del mes</h3>
          <div style="display:flex; gap:6px;">
            <button class="btn btn-sm" data-action="duplicate-expenses">Duplicar mes anterior</button>
            <button class="btn btn-sm btn-primary" data-action="open-add-expense">+ Egreso</button>
          </div>
        </div>
        <div class="table-wrap">
          <table><thead><tr><th>Concepto</th><th>Categoría</th><th>Valor</th><th></th></tr></thead><tbody>
          ${egresos.length ? egresos.sort((a,b)=>b.fecha.localeCompare(a.fecha)).map(rowEgreso).join('') : '<tr><td colspan="4"><div class="empty">Sin egresos registrados este mes.</div></td></tr>'}
          </tbody></table>
        </div>
        ${Object.keys(egresosPorCategoria).length ? `<div class="card-pad" style="border-top:1px solid var(--border);">${Object.keys(egresosPorCategoria).map(c=>`<div class="kv"><span>${escapeHtml(c)}</span><span>${fmtMoney(egresosPorCategoria[c])}</span></div>`).join('')}</div>` : ''}
      </div>
    </div>
  `;
  bindMonthYearPicker('contaMes', ()=>{ state._contaMes = readMonthYearPicker('contaMes'); viewContabilidad(el); });
}
function rowCompra(p){
  return `<tr>
    <td><div class="cell-name">${escapeHtml(p.concepto)}</div><div class="cell-sub">${fmtDate(p.fecha)}${p.proveedor?' · '+escapeHtml(p.proveedor):''}</div></td>
    <td>${escapeHtml(p.categoria)}</td>
    <td>${fmtMoney(p.valor)}</td>
    <td style="text-align:right;"><button class="btn btn-sm btn-ghost" data-action="delete-purchase" data-id="${p.id}">Eliminar</button></td>
  </tr>`;
}
function rowEgreso(e){
  return `<tr>
    <td><div class="cell-name">${escapeHtml(e.concepto)}</div><div class="cell-sub">${fmtDate(e.fecha)}</div></td>
    <td>${escapeHtml(e.categoria)}</td>
    <td>${fmtMoney(e.valor)}</td>
    <td style="text-align:right;"><button class="btn btn-sm btn-ghost" data-action="delete-expense" data-id="${e.id}">Eliminar</button></td>
  </tr>`;
}

function openPurchaseModal(){
  const mk = state._contaMes;
  const html = `
    <div class="modal-head"><h3>Registrar compra</h3><button class="icon-btn" data-action="close-modal"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6 6 18M6 6l12 12"/></svg></button></div>
    <div class="modal-body">
      <form id="purchaseForm">
        <div class="field"><label>Concepto *</label><input name="concepto" required placeholder="Cloro y químicos piscina"></div>
        <div class="field-row">
          <div class="field"><label>Categoría</label><select name="categoria">${CATEGORIAS_COMPRA.map(c=>`<option>${c}</option>`).join('')}</select></div>
          <div class="field"><label>Valor *</label><input type="number" name="valor" required min="0" step="1000"></div>
        </div>
        <div class="field-row">
          <div class="field"><label>Proveedor</label><input name="proveedor"></div>
          <div class="field"><label>Fecha</label><input type="date" name="fecha" value="${mk+'-'+String(new Date().getDate()).padStart(2,'0')}"></div>
        </div>
        <div class="field"><label>Nota</label><textarea name="nota" rows="2"></textarea></div>
      </form>
    </div>
    <div class="modal-foot"><button class="btn" data-action="close-modal">Cancelar</button><button class="btn btn-primary" data-action="save-purchase">Guardar compra</button></div>
  `;
  openModal(html);
}
async function savePurchaseFromForm(){
  const fd = new FormData(document.getElementById('purchaseForm'));
  const fecha = fd.get('fecha') || todayISO();
  if(!fd.get('concepto').trim() || !fd.get('valor')){ toast('Completa concepto y valor', 'danger'); return; }
  state.purchases.push({id:uid('cp'), concepto:fd.get('concepto').trim(), categoria:fd.get('categoria'), valor:Number(fd.get('valor'))||0, proveedor:fd.get('proveedor')||'', fecha, mes:fecha.slice(0,7), nota:fd.get('nota')||''});
  const ok = await saveKey('mantarayas:purchases', state.purchases);
  if(ok){ toast('Compra registrada'); closeModal(); renderCurrentView(); }
}
async function deletePurchase(id){
  if(!confirm('¿Eliminar esta compra?')) return;
  state.purchases = state.purchases.filter(p=>p.id!==id);
  await saveKey('mantarayas:purchases', state.purchases);
  toast('Compra eliminada'); renderCurrentView();
}

function openExpenseModal(){
  const mk = state._contaMes;
  const html = `
    <div class="modal-head"><h3>Registrar egreso fijo</h3><button class="icon-btn" data-action="close-modal"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6 6 18M6 6l12 12"/></svg></button></div>
    <div class="modal-body">
      <form id="expenseForm">
        <div class="field"><label>Concepto *</label><input name="concepto" required placeholder="Arriendo sede principal"></div>
        <div class="field-row">
          <div class="field"><label>Categoría</label><select name="categoria">${CATEGORIAS_EGRESO.map(c=>`<option>${c}</option>`).join('')}</select></div>
          <div class="field"><label>Valor *</label><input type="number" name="valor" required min="0" step="1000"></div>
        </div>
        <div class="field"><label>Fecha</label><input type="date" name="fecha" value="${mk+'-'+String(new Date().getDate()).padStart(2,'0')}"></div>
        <div class="field"><label>Nota</label><textarea name="nota" rows="2"></textarea></div>
      </form>
    </div>
    <div class="modal-foot"><button class="btn" data-action="close-modal">Cancelar</button><button class="btn btn-primary" data-action="save-expense">Guardar egreso</button></div>
  `;
  openModal(html);
}
async function saveExpenseFromForm(){
  const fd = new FormData(document.getElementById('expenseForm'));
  const fecha = fd.get('fecha') || todayISO();
  if(!fd.get('concepto').trim() || !fd.get('valor')){ toast('Completa concepto y valor', 'danger'); return; }
  state.expenses.push({id:uid('eg'), concepto:fd.get('concepto').trim(), categoria:fd.get('categoria'), valor:Number(fd.get('valor'))||0, fecha, mes:fecha.slice(0,7), nota:fd.get('nota')||''});
  const ok = await saveKey('mantarayas:expenses', state.expenses);
  if(ok){ toast('Egreso registrado'); closeModal(); renderCurrentView(); }
}
async function deleteExpense(id){
  if(!confirm('¿Eliminar este egreso?')) return;
  state.expenses = state.expenses.filter(e=>e.id!==id);
  await saveKey('mantarayas:expenses', state.expenses);
  toast('Egreso eliminado'); renderCurrentView();
}
async function duplicateExpensesFromPreviousMonth(){
  const mk = state._contaMes;
  const [y,m] = mk.split('-').map(Number);
  const prevDate = new Date(y, m-2, 1);
  const prevMk = monthKey(prevDate);
  const prevExpenses = state.expenses.filter(e=>e.mes===prevMk);
  if(!prevExpenses.length){ toast('El mes anterior ('+monthLabel(prevMk)+') no tiene egresos para copiar', 'warning'); return; }
  const already = state.expenses.filter(e=>e.mes===mk).length;
  if(already && !confirm('Ya hay '+already+' egresos en '+monthLabel(mk)+'. ¿Agregar de todas formas los del mes anterior?')) return;
  const day = String(new Date().getDate()).padStart(2,'0');
  prevExpenses.forEach(e=>{
    state.expenses.push({...e, id:uid('eg'), fecha: mk+'-'+day, mes: mk});
  });
  const ok = await saveKey('mantarayas:expenses', state.expenses);
  if(ok){ toast(prevExpenses.length+' egresos copiados de '+monthLabel(prevMk)); renderCurrentView(); }
}
function exportCierreCSV(){
  const mk = state._contaMes;
  const ingresos = state.payments.filter(p=>p.mes===mk).reduce((a,p)=>a+p.monto,0);
  const compras = state.purchases.filter(p=>p.mes===mk);
  const egresos = state.expenses.filter(e=>e.mes===mk);
  const totalCompras = compras.reduce((a,p)=>a+p.valor,0);
  const totalEgresos = egresos.reduce((a,e)=>a+e.valor,0);
  const utilidad = ingresos - totalCompras - totalEgresos;
  const rows = [['Cierre financiero', monthLabel(mk)], [], ['Concepto','Valor'], ['Ingresos', ingresos], ['Compras', -totalCompras], ['Egresos fijos', -totalEgresos], ['Utilidad neta', utilidad], [], ['Detalle de compras'], ['Concepto','Categoría','Proveedor','Fecha','Valor']];
  compras.forEach(p=>rows.push([p.concepto,p.categoria,p.proveedor,p.fecha,p.valor]));
  rows.push([], ['Detalle de egresos fijos'], ['Concepto','Categoría','Fecha','Valor']);
  egresos.forEach(e=>rows.push([e.concepto,e.categoria,e.fecha,e.valor]));
  downloadCSV('cierre_'+mk+'.csv', rows);
  toast('Cierre financiero exportado');
}
/* ============ REPORTES VIEW ============ */
state._reportesAnio = new Date().getFullYear();
function viewReportes(el){
  const activos = state.students.filter(s=>s.estado==='activo');
  const anio = state._reportesAnio;
  const months = Array.from({length:12}, (_,i)=>anio+'-'+String(i+1).padStart(2,'0'));
  const ingresosPorMes = months.map(mk=>({label:MONTH_NAMES[parseInt(mk.split('-')[1],10)-1].slice(0,3), n: state.payments.filter(p=>p.mes===mk).reduce((a,p)=>a+p.monto,0)}));
  const maxIng = Math.max(1,...ingresosPorMes.map(m=>m.n));

  const buckets = {'0-8':0,'9-14':0,'15-20':0,'21-35':0,'36+':0};
  activos.forEach(s=>{
    const e = s.edad;
    if(e==null) return;
    if(e<=8) buckets['0-8']++; else if(e<=14) buckets['9-14']++; else if(e<=20) buckets['15-20']++; else if(e<=35) buckets['21-35']++; else buckets['36+']++;
  });

  el.innerHTML = `
    <div class="view-header">
      <div><h1 class="view-title">Reportes</h1><p class="view-desc">Indicadores generales del club para exportar o compartir.</p></div>
      <div style="display:flex;gap:8px;">
        <button class="btn" data-action="export-students"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3v13m0 0-4-4m4 4 4-4M4 20h16"/></svg>Alumnos (CSV)</button>
        <button class="btn" data-action="export-pagos"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3v13m0 0-4-4m4 4 4-4M4 20h16"/></svg>Pagos (CSV)</button>
      </div>
    </div>
    <div class="grid-2">
      <div class="card">
        <div class="card-head"><h3>Ingresos por mes</h3><input type="number" id="reportesAnio" value="${anio}" min="2015" max="2100" style="width:84px;"></div>
        <div class="card-pad">
          <div class="bar-chart" style="height:170px;">${ingresosPorMes.map(m=>`<div class="bar-col"><span class="bar-val">${m.n?fmtMoney(m.n).replace('$ ',''):'0'}</span><div class="bar" style="height:${Math.max(4,(m.n/maxIng)*130)}px"></div><span class="bar-label">${m.label}</span></div>`).join('')}</div>
        </div>
      </div>
      <div class="card">
        <div class="card-head"><h3>Alumnos por rango de edad</h3></div>
        <div class="card-pad">
          ${Object.keys(buckets).map(k=>{
            const max = Math.max(1,...Object.values(buckets));
            return `<div style="margin-bottom:11px;"><div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px;"><span>${k} años</span><b>${buckets[k]}</b></div><div style="height:7px;background:var(--surface-2);border-radius:99px;overflow:hidden;"><div style="height:100%;width:${buckets[k]/max*100}%;background:var(--accent);"></div></div></div>`;
          }).join('')}
        </div>
      </div>
    </div>
    <div class="grid-2" style="margin-top:14px;">
      <div class="card">
        <div class="card-head"><h3>Alumnos por grupo</h3></div>
        <div class="card-pad">${barChartGroups()}</div>
      </div>
      <div class="card">
        <div class="card-head"><h3>Resumen general</h3></div>
        <div class="card-pad">
          <div class="kv"><span>Alumnos activos</span><span>${activos.length}</span></div>
          <div class="kv"><span>Alumnos retirados</span><span>${state.students.filter(s=>s.estado==='retirado').length}</span></div>
          <div class="kv"><span>Alumnos suspendidos</span><span>${state.students.filter(s=>s.estado==='suspendido').length}</span></div>
          <div class="kv"><span>Grupos activos</span><span>${state.groups.length}</span></div>
          <div class="kv"><span>Entrenadores</span><span>${new Set(state.groups.map(g=>g.entrenador)).size}</span></div>
          <div class="kv"><span>Registros de asistencia totales</span><span>${state.attendance.length}</span></div>
        </div>
      </div>
    </div>
  `;
  document.getElementById('reportesAnio').addEventListener('change', e=>{ state._reportesAnio = parseInt(e.target.value,10)||anio; renderCurrentView(); });
}
function exportStudentsCSV(){
  const rows = [['Nombre','Documento','Fecha nacimiento','Edad','Sexo','EPS','RH','Alergias','Celular','Acudiente','Tel. acudiente','Correo','Contacto emergencia','Dirección','Barrio','Municipio','Grupos','Estado','Estado pago']];
  const mk = monthKey();
  state.students.forEach(s=>{
    rows.push([s.nombre,s.documento,s.fechaNacimiento,s.edad,s.sexo,s.eps,s.rh,s.alergias,s.celular,s.acudiente,s.telefonoAcudiente,s.correo,s.contactoEmergencia,s.direccion,s.barrio,s.municipio,groupOfStudent(s).map(g=>g.dia+' '+g.hora).join(' | '),s.estado,paymentStatusForMonth(s.id,mk)]);
  });
  downloadCSV('mantarayas_alumnos.csv', rows);
  toast('CSV de alumnos descargado');
}
function exportPagosCSV(){
  const rows = [['Alumno','Mes','Tipo','Valor','Método','Fecha','Nota']];
  state.payments.slice().sort((a,b)=>b.fecha.localeCompare(a.fecha)).forEach(p=>{
    const s = state.students.find(x=>x.id===p.studentId);
    rows.push([s?s.nombre:p.studentId, monthLabel(p.mes), p.tipo, p.monto, p.metodo, p.fecha, p.nota]);
  });
  downloadCSV('mantarayas_pagos.csv', rows);
  toast('CSV de pagos descargado');
}

/* ============ MODAL / DRAWER PLUMBING ============ */
function openModal(html){
  document.getElementById('modalRoot').innerHTML = html;
  document.getElementById('modalOverlay').classList.add('active');
}
function closeModal(){
  document.getElementById('modalOverlay').classList.remove('active');
  document.getElementById('modalRoot').innerHTML = '';
}

/* ============ GLOBAL SEARCH ============ */
function bindGlobalSearch(){
  const input = document.getElementById('globalSearch');
  const results = document.getElementById('globalSearchResults');
  input.addEventListener('input', ()=>{
    const q = input.value.trim().toLowerCase();
    if(!q){ results.style.display='none'; return; }
    const matches = state.students.filter(s=>(s.nombre||'').toLowerCase().includes(q) || (s.documento||'').includes(q) || (s.celular||'').includes(q)).slice(0,8);
    if(!matches.length){ results.innerHTML = '<div class="empty" style="padding:20px;">Sin coincidencias</div>'; results.style.display='block'; return; }
    results.innerHTML = matches.map(s=>`<div data-action="open-student" data-id="${s.id}" style="display:flex;align-items:center;gap:10px;padding:10px 14px;cursor:pointer;border-bottom:1px solid var(--border);">
      <div class="avatar" style="width:30px;height:30px;font-size:11px;">${initials(s.nombre)}</div>
      <div><div class="cell-name">${escapeHtml(s.nombre)}</div><div class="cell-sub">${s.documento?('CC '+s.documento):''} ${s.celular?('· '+s.celular):''}</div></div>
    </div>`).join('');
    results.style.display='block';
  });
  document.addEventListener('click', e=>{
    if(!results.contains(e.target) && e.target!==input) results.style.display='none';
  });
}

/* ============ EVENT DELEGATION ============ */
function bindGlobalActions(){
  document.body.addEventListener('click', async (e)=>{
    const target = e.target.closest('[data-action]');
    const navBtn = e.target.closest('[data-nav]');
    if(navBtn){ setView(navBtn.dataset.nav); return; }
    if(!target) return;
    const action = target.dataset.action;
    const id = target.dataset.id;
    switch(action){
      case 'open-add-student': openStudentModal(); break;
      case 'edit-student': closeDrawer(); openStudentModal(id); break;
      case 'save-student': saveStudentFromForm(id||null); break;
      case 'delete-student': deleteStudent(id); break;
      case 'open-student': document.getElementById('globalSearchResults').style.display='none'; document.getElementById('globalSearch').value=''; openStudentDrawer(id); break;
      case 'close-drawer': closeDrawer(); break;
      case 'close-modal': closeModal(); break;
      case 'open-add-payment': openPaymentModal(id, state._pagosMes); break;
      case 'save-payment': savePaymentFromForm(id); break;
      case 'open-add-group': openGroupModal(); break;
      case 'open-edit-group': openGroupModal(id); break;
      case 'save-group': saveGroupFromForm(id||null); break;
      case 'delete-group': deleteGroup(id); break;
      case 'export-students': exportStudentsCSV(); break;
      case 'export-pagos': exportPagosCSV(); break;
      case 'goto-alumnos': setView('alumnos'); break;
      case 'goto-pagos': setView('pagos'); break;
      case 'goto-asistencia': setView('asistencia'); break;
      case 'goto-dashboard': setView('dashboard'); break;
      case 'save-attendance': saveAttendance(); break;
      case 'open-take-attendance': state._asist.groupId = target.dataset.group; setView('asistencia'); break;
      case 'export-student-attendance': exportStudentAttendanceCSV(id); break;
      case 'duplicate-group': duplicateGroup(id); break;
      case 'toggle-suspend-group': toggleSuspendGroup(id); break;
      case 'open-move-students': openMoveStudentsModal(); break;
      case 'confirm-move-students': confirmMoveStudents(); break;
      case 'open-add-user': openUserModal(); break;
      case 'edit-user': openUserModal(id); break;
      case 'save-user': saveUserFromForm(id||null); break;
      case 'delete-user': deleteUser(id); break;
      case 'toggle-user-estado': toggleUserEstado(id); break;
      case 'delete-teacher': deleteTeacherName(target.dataset.teacher); break;
      case 'open-add-purchase': openPurchaseModal(); break;
      case 'save-purchase': savePurchaseFromForm(); break;
      case 'delete-purchase': deletePurchase(id); break;
      case 'open-add-expense': openExpenseModal(); break;
      case 'save-expense': saveExpenseFromForm(); break;
      case 'delete-expense': deleteExpense(id); break;
      case 'duplicate-expenses': duplicateExpensesFromPreviousMonth(); break;
      case 'export-cierre': exportCierreCSV(); break;
    }
  });
  document.getElementById('modalOverlay').addEventListener('click', e=>{ if(e.target.id==='modalOverlay') closeModal(); });
  document.getElementById('drawerOverlay').addEventListener('click', closeDrawer);
}

/* ============ THEME ============ */
function applyTheme(){
  document.documentElement.classList.toggle('dark', state.theme==='dark');
  document.getElementById('themeIcon').innerHTML = state.theme==='dark'
    ? '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z"/>'
    : '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>';
}
document.getElementById('themeToggle').addEventListener('click', async ()=>{
  state.theme = state.theme==='dark' ? 'light' : 'dark';
  applyTheme();
  await saveTheme(state.theme);
});
/* ============ LOGIN SCREEN ============ */
function renderLoginScreen(){
  const screen = document.getElementById('loginScreen');
  screen.innerHTML = `
    <div class="login-wrap">
      <div class="login-card">
        <div class="login-logo">
          <div class="login-mark"><svg viewBox="0 0 34 34" fill="none" width="30" height="30"><path d="M4 20c4-9 10-13 13-13 2 0 2 2 0 3-6 3-9 8-9 12 0 3 2 4 4 2 3-3 4-9 8-9 3 0 4 3 2 5-2 2-2 4 1 4 4 0 8-4 10-8" stroke="white" stroke-width="1.6" stroke-linecap="round"/></svg></div>
          <div><div class="login-title">Mantarayas</div><div class="login-sub">Ingresa a tu panel del club</div></div>
        </div>
        <div class="login-error" id="loginError"></div>
        <form id="loginForm">
          <div class="field"><label>Usuario</label><input name="usuario" id="loginUser" autocomplete="username" required></div>
          <div class="field">
            <label>Contraseña</label>
            <div class="pw-wrap">
              <input type="password" name="password" id="loginPass" autocomplete="current-password" required>
              <button type="button" class="pw-toggle" id="pwToggle"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg></button>
            </div>
          </div>
          <div class="login-row">
            <label class="checkbox-line"><input type="checkbox" id="loginRemember" checked>Mantener sesión iniciada en este navegador</label>
            <button type="button" class="link-btn" id="forgotBtn">¿Olvidaste tu contraseña?</button>
          </div>
          <button type="submit" class="btn btn-primary" id="loginSubmitBtn" style="width:100%;justify-content:center;">Ingresar</button>
        </form>
        <details class="demo-creds">
          <summary>Credenciales de ejemplo (solo la primera vez)</summary>
          <table>
            <tr><td><b>Super Admin</b></td><td>admin</td><td>Mantarayas2026</td></tr>
            <tr><td><b>Recepción</b></td><td>recepcion</td><td>Recepcion2026</td></tr>
            <tr><td><b>Profesor</b></td><td>aarias</td><td>Profesor2026</td></tr>
          </table>
          <p class="hint" style="margin-top:8px;">Cámbialas desde Usuarios apenas ingreses. La contraseña se guarda con hash en el servidor — ni siquiera un Super Administrador puede verla.</p>
        </details>
      </div>
    </div>
  `;
  document.getElementById('pwToggle').addEventListener('click', ()=>{
    const inp = document.getElementById('loginPass');
    inp.type = inp.type==='password' ? 'text' : 'password';
  });
  document.getElementById('forgotBtn').addEventListener('click', ()=>{
    showLoginError('Contacta a un Super Administrador para restablecer tu contraseña desde el módulo de Usuarios.', true);
  });
  document.getElementById('loginForm').addEventListener('submit', handleLoginSubmit);
}
function showLoginError(msg, info){
  const el = document.getElementById('loginError');
  el.textContent = msg;
  el.style.background = info ? 'var(--primary-soft)' : 'var(--danger-soft)';
  el.style.color = info ? 'var(--primary-dark)' : 'var(--danger)';
  el.classList.add('active');
}
async function handleLoginSubmit(e){
  e.preventDefault();
  const usuario = document.getElementById('loginUser').value.trim();
  const pass = document.getElementById('loginPass').value;
  const remember = document.getElementById('loginRemember').checked;
  const btn = document.getElementById('loginSubmitBtn');
  btn.disabled = true; btn.textContent = 'Ingresando…';
  try{
    const res = await apiFetch('/auth/login', {method:'POST', body: JSON.stringify({usuario, password:pass, remember})});
    if(!res.ok){
      const err = await res.json().catch(()=>({}));
      showLoginError(err.error || 'Usuario o contraseña incorrectos.');
      return;
    }
    const user = await res.json();
    await enterApp(user);
  }catch(e2){
    showLoginError('No se pudo conectar con el servidor. Verifica tu conexión.');
  }finally{
    btn.disabled = false; btn.textContent = 'Ingresar';
  }
}
async function enterApp(user){
  state.session = user.id;
  state.sessionUser = user;
  state.role = user.rol;
  if(user.rol==='profesor') state.profesorActual = user.profesorNombre || state.teachers[0];
  state.view = 'dashboard';
  document.getElementById('loginScreen').innerHTML = '';
  document.getElementById('appRoot').style.display = 'flex';
  await loadAll();
  if(user.rol==='super'){
    try{ const r = await apiFetch('/users'); if(r.ok) state.users = await r.json(); }catch(e){}
  }
  renderNav();
  renderCurrentView();
}
async function doLogout(){
  try{ await apiFetch('/auth/logout', {method:'POST'}); }catch(e){}
  state.session = null; state.sessionUser = null;
  document.getElementById('appRoot').style.display = 'none';
  renderLoginScreen();
}

/* ============ BOOTSTRAP ============ */
async function boot(){
  state.theme = await loadTheme();
  applyTheme();
  bindGlobalActions();
  bindGlobalSearch();
  document.getElementById('logoutBtn').addEventListener('click', doLogout);
  document.getElementById('resetBtn').addEventListener('click', async ()=>{
    if(!confirm('Esto reemplaza alumnos, pagos, horarios y asistencia por los datos de ejemplo originales. ¿Continuar?')) return;
    await resetDemoData();
  });
  document.getElementById('menuBtn').addEventListener('click', ()=>document.getElementById('sidebar').classList.toggle('open'));
  if(window.matchMedia('(max-width:860px)').matches) document.getElementById('menuBtn').style.display='flex';

  try{
    const res = await apiFetch('/auth/me');
    if(res.ok){
      const user = await res.json();
      await enterApp(user);
      return;
    }
  }catch(e){ /* fall through to login screen */ }
  renderLoginScreen();
}
boot();

</script>
</body>
</html>
"""

# ===========================================================================


init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port)


