# -----------------------
# Admin: Users & Audit
# -----------------------
import secrets
from datetime import datetime, timedelta
from flask import render_template, request, redirect, url_for, session, flash, abort, Blueprint
from flask_babel import gettext as _
from sqlalchemy import text, bindparam, Boolean
from werkzeug.security import generate_password_hash

from modules.auth_utils import (
    login_required,
    require_perms,
    require_csrf,
    current_user
)

from modules.core_utils import (
    engine,
    log_action
)

from modules.core_utils import (
    log_action,
    ROLES,
    engine,
    build_base_url,
    APP_BASE_URL
)

from modules.mail_utils import (
    SMTP_HOST,
    logger
)

from modules.mail_utils import (
    send_mail
)

user_routes = Blueprint('user_routes', __name__)

@user_routes.get('/admin/users')
@login_required
def users_list():
    with engine.begin() as conn:
        rows = conn.execute(text("""
            SELECT id, username, displayname, email, role, active, must_change_password, can_approve, chief, supervisor, unit, created_at, updated_at
            FROM users
            ORDER BY unit ASC, displayname ASC
        """)).mappings().all()

    return render_template('users.html', users=rows)

@user_routes.post('/admin/users/add')
@login_required
#@require_perms('users:manage')
@require_csrf
def users_add():
    username = (request.form.get('username') or '').strip()
    displayname = (request.form.get('displayname') or '').strip()
    email = (request.form.get('email') or '').strip() or None
    unit = (request.form.get('unit') or '').strip()
    role = (request.form.get('role') or 'Admin').strip()
    pwd = (request.form.get('password') or '').strip()
    #if not username:
    #    flash(_('Benutzername darf nicht leer sein.'))
    #    return redirect(url_for('user_routes.users_list'))
    if not displayname:
        flash(_('Displayname darf nicht leer sein.'))
        return redirect(url_for('user_routes.users_list'))
    if role not in ROLES:
        flash(_('Ungültige Rolle.'))
        return redirect(url_for('user_routes.users_list'))
    #if len(pwd) < 8:
    #    flash(_('Passwort muss mindestens 8 Zeichen haben.'))
    #    return redirect(url_for('user_routes.users_list'))
    try:
        with engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO users (username, displayname, email, password_hash, role, active, must_change_password, theme_preference, unit)
                VALUES (:u, :dn, :e, :ph, :r, TRUE, TRUE, 'system', :unit)
            """), {
                'u': username,
                'dn': displayname,
                'e': email,
                'ph': generate_password_hash(pwd),
                'r': role,
                'unit': unit
            })
        flash(_('Benutzer angelegt.'))
    except Exception as e:
        #flash(f"{_('Fehler:')} {e}")
        flash(f"{_('Fehler beim Anlegen des Mitglieds. Username muss entweder leer sein oder darf nicht doppelt vorkommen. Displayname darf nicht doppelt vorkommen und muss gefüllt sein.')}", 'danger')
    return redirect(url_for('user_routes.users_list'))

@user_routes.route('/admin/users/<int:uid>/edit', methods=['GET', 'POST'])
@login_required
#@require_perms('users:manage')
def edit_user(uid):
    if request.method == 'POST':
        role = request.form.get('role')
        email = (request.form.get('email') or '').strip() or None
        username = (request.form.get('username') or '').strip() or None
        displayname = (request.form.get('displayname') or '').strip() or None
        unit = (request.form.get('unit') or '').strip()

        # Checkboxen -> bool (Checkbox sendet nur, wenn angehakt)
        active = request.form.get('active') is not None
        can_approve = request.form.get('can_approve') is not None
        chief = request.form.get('chief') is not None
        supervisor = request.form.get('supervisor') is not None

        # Optionales Passwort
        password = (request.form.get('password') or '').strip()

        #if role not in ROLES.keys():
        #    flash('Ungültige Rolle.')
        #    return redirect(url_for('edit_user', uid=uid))
        
        # Nur eines darf True sein
        if chief and supervisor:
            flash(_('Es darf nur Chief ODER Supervisor aktiv sein, nicht beides.'), 'danger')
            return redirect(url_for('edit_user', uid=uid))

        with engine.begin() as conn:
            if password:
                hashed = generate_password_hash(password)
                stmt = text("""
                    UPDATE users
                    SET email=:email,
                        username=:username,
                        displayname=:displayname,
                        active=:active,
                        can_approve=:can_approve,
                        chief=:chief,
                        supervisor=:supervisor,
                        password_hash=:pwd,
                        unit=:unit,
                        updated_at=NOW()
                    WHERE id=:id
                """).bindparams(
                    bindparam('active', type_=Boolean()),
                    bindparam('can_approve', type_=Boolean()),
                    bindparam('chief', type_=Boolean()),
                    bindparam('supervisor', type_=Boolean()),
                )
                conn.execute(stmt, {
                    'email': email,
                    'username': username,
                    'displayname': displayname,
                    'active': active,
                    'can_approve': can_approve,
                    'chief': chief,
                    'supervisor': supervisor,
                    'pwd': hashed,
                    'unit': unit,
                    'id': uid
                })
            else:
                stmt = text("""
                    UPDATE users
                    SET email=:email,
                        username=:username,
                        displayname=:displayname,
                        active=:active,
                        can_approve=:can_approve,
                        chief=:chief,
                        supervisor=:supervisor,
                        unit=:unit,
                        updated_at=NOW()
                    WHERE id=:id
                """).bindparams(
                    bindparam('active', type_=Boolean()),
                    bindparam('can_approve', type_=Boolean()),
                    bindparam('chief', type_=Boolean()),
                    bindparam('supervisor', type_=Boolean()),
                )
                conn.execute(stmt, {
                    'email': email,
                    'username': username,
                    'displayname': displayname,
                    'active': active,
                    'can_approve': can_approve,
                    'chief': chief,
                    'unit': unit,
                    'supervisor': supervisor,
                    'id': uid
                })

        flash('Benutzer aktualisiert.')
        return redirect(url_for('user_routes.users_list'))

    # GET-Teil
    with engine.begin() as conn:
        user = conn.execute(text("""
            SELECT id, username, displayname, email, role, active, can_approve, chief, supervisor, unit
            FROM users
            WHERE id=:id
        """), {'id': uid}).mappings().first()
    if not user:
        abort(404)
    roles = ROLES.keys()
    return render_template('edit_user.html', user=user, roles=roles)

@user_routes.post('/admin/users/<int:uid>/delete')
@login_required
#@require_perms('users:manage')
@require_csrf
def users_delete(uid: int):
    current_uid = session.get('user_id')
    if uid == current_uid:
        flash(_('Du kannst dich nicht selbst löschen.'))
        return redirect(url_for('user_routes.users_list'))

    with engine.begin() as conn:
        conn.execute(text("DELETE FROM users WHERE id=:id"), {'id': uid})
    log_action(current_uid, 'users:delete', None, f"user_id={uid}")
    flash(_('Benutzer gelöscht.'))
    return redirect(url_for('user_routes.users_list'))

@user_routes.post('/admin/users/<int:uid>/resetpw')
@login_required
#@require_perms('users:manage')
@require_csrf
def users_reset_pw(uid: int):
    newpw = (request.form.get('password') or '').strip()
    #if len(newpw) < 8:
    #    flash(_('Neues Passwort muss mindestens 8 Zeichen haben.'))
    #    return redirect(url_for('user_routes.users_list'))
    with engine.begin() as conn:
        conn.execute(text("UPDATE users SET password_hash=:ph, must_change_password=FALSE, updated_at=NOW() WHERE id=:id"),
                     {'ph': generate_password_hash(newpw), 'id': uid})
    flash(_('Passwort gesetzt.'))
    return redirect(url_for('user_routes.users_list'))

@user_routes.post('/admin/users/<int:uid>/resetlink')
@login_required
#@require_perms('users:manage')
@require_csrf
def users_reset_link(uid: int):
    token = secrets.token_urlsafe(32)
    expires = datetime.utcnow() + timedelta(minutes=30)
    base = build_base_url()
    reset_url = f"{base}reset/{token}"
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (:u,:t,:e)"),
                     {'u': uid, 't': token, 'e': expires})
        email = conn.execute(text("SELECT email FROM users WHERE id=:id"), {'id': uid}).scalar_one()
    body = f"""
    Dein Passwort-Reset-Token lautet:

    {token}

    Dieser Token ist 30 Minuten gültig.
    Bitte gib ihn auf der Reset-Seite ein: {APP_BASE_URL}/reset
    """
    if email and SMTP_HOST:
        sent = send_mail(email, 'Passwort zurücksetzen', body)
        if sent:
            flash(_('Reset-Link per E-Mail versendet.'))
        else:
            flash(f"{_('Reset-Link:')} {reset_url}")
            logger.warning("E-Mail-Versand fehlgeschlagen – Token im UI angezeigt (user_id=%s).", uid)
    else:
        flash(f"{_('Reset-Link:')} {reset_url}")
        logger.warning("Keine E-Mail-Adresse oder kein SMTP_HOST – Token im UI angezeigt (user_id=%s).", uid)
    return redirect(url_for('user_routes.users_list'))

@user_routes.post('/admin/users/<int:uid>/toggle')
@login_required
#@require_perms('users:manage')
@require_csrf
def users_toggle(uid: int):
    current_uid = session.get('user_id')
    if uid == current_uid:
        flash(_('Du kannst dich nicht selbst deaktivieren.'))
        return redirect(url_for('user_routes.users_list'))

    with engine.begin() as conn:
        conn.execute(text("UPDATE users SET active = NOT active, updated_at=NOW() WHERE id=:id"), {'id': uid})
    return redirect(url_for('user_routes.users_list'))


@user_routes.post('/admin/users/<int:uid>/role')
@login_required
#@require_perms('users:manage')
@require_csrf
def users_change_role(uid: int):
    role = (request.form.get('role') or 'Admin').strip()
    if role not in ROLES:
        flash(_('Ungültige Rolle.'))
        return redirect(url_for('user_routes.users_list'))
    with engine.begin() as conn:
        conn.execute(text("UPDATE users SET role=:r, updated_at=NOW() WHERE id=:id"), {'r': role, 'id': uid})
    return redirect(url_for('user_routes.users_list'))
