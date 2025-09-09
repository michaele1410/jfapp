# -----------------------
# CORE Configuration
# -----------------------

import os
from flask import session,flash, abort, request
from sqlalchemy import text
from sqlalchemy.engine import Engine, create_engine


APP_BASE_URL = os.getenv("APP_BASE_URL") or "http://localhost:5000"

SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_hex(24)
DB_HOST = os.getenv("DB_HOST", "jfapp-db")
DB_NAME = os.getenv("DB_NAME", "jfapp")
DB_USER = os.getenv("DB_USER", "admin")
DB_PASS = os.getenv("DB_PASS", "admin")
DATABASE_URL = f"postgresql+psycopg2://{DB_USER}:{DB_PASS}@{DB_HOST}:5432/{DB_NAME}"

engine: Engine = create_engine(DATABASE_URL, future=True, pool_pre_ping=True)

# -----------------------
# Roles
# -----------------------
ROLES = {
    'Admin': {
        'entries:view', 'entries:add', 'entries:edit:any', 'entries:delete:any',
        'export:csv', 'export:pdf', 'import:csv', 'users:manage', 'audit:view'
    },
    'Manager': {
        'entries:view', 'entries:add', 'entries:edit:any', 'entries:delete:any',
        'export:csv', 'export:pdf', 'import:csv'
    },
    'Editor': {
        'entries:view', 'entries:add', 'entries:edit:own', 'entries:delete:own',
        'export:csv', 'export:pdf'
    },
    'Viewer': {
        'entries:view', 'export:csv', 'export:pdf'
    },
    'Auditor': {
        'entries:view', 'audit:view'
    }
}

# -----------------------
# Document Upload
# -----------------------
UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER") or "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {
    'pdf','png','jpg','jpeg','gif','webp','heic','heif','svg',
    'txt','csv','doc','docx','xls','xlsx','ppt','pptx','xml','json'
}

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

def allowed_file(filename: str) -> bool:
    if not filename or '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def validate_file(file):
    if file.content_length > MAX_FILE_SIZE:
        flash("Datei zu groß. Maximal erlaubt: 10 MB.", "danger")
        return False
    return True

# --- Verzeichnisse ---
def _entry_dir(entry_id: int) -> str:
    p = os.path.join(UPLOAD_FOLDER, str(entry_id))
    os.makedirs(p, exist_ok=True)
    return p

def _temp_dir(token: str) -> str:
    p = os.path.join(UPLOAD_FOLDER, "temp", token)
    os.makedirs(p, exist_ok=True)
    return p

def _require_temp_token(token: str):
    if not token or session.get('add_temp_token') != token:
        abort(403)

# --- Audit-Log ---
def log_action(user_id: int | None, action: str, entry_id: int | None, detail: str | None = None):
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO audit_log (user_id, action, entry_id, detail)
            VALUES (:u, :a, :e, :d)
        """), {'u': user_id, 'a': action, 'e': entry_id, 'd': detail})

def build_base_url():
    # bevorzuge APP_BASE_URL, fallback auf request.url_root
    try:
        base = os.getenv("APP_BASE_URL") or request.url_root
    except RuntimeError:
        base = os.getenv("APP_BASE_URL") or "http://localhost:5000/"
    return base.rstrip("/") + "/"
