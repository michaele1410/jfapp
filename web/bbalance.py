# -----------------------
# BottleBalance
# -----------------------
import os
import io
from flask import render_template, request, redirect, url_for, session, send_file, flash, abort, Blueprint, jsonify
from flask_babel import gettext as _
from sqlalchemy import text
import json

from datetime import datetime, date
import csv

from decimal import Decimal, InvalidOperation

from modules.utils import (
    parse_money
)
from modules.core_utils import (
    _entry_dir, 
    _temp_dir,
    log_action,
    ROLES,
    engine
)
from modules.auth_utils import (
    login_required,
    require_csrf,
    require_perms,
    current_user
) 
from modules.bbalance_utils import (
    _build_index_context,
    fetch_entries
) 

from modules.csv_utils import (
    today_ddmmyyyy,
    parse_date_de_or_none
)

from modules.payment_utils import (
    get_bemerkungsoptionen
)

from modules.csv_utils import (
    parse_date_de_or_today,
    format_date_de
)

bbalance_routes = Blueprint('bbalance_routes', __name__)



@bbalance_routes.get('/')
@login_required
def index():
    try:
        # Basis-Kontext laden
        ctx = _build_index_context(default_date=today_ddmmyyyy())
        ctx['bemerkungsoptionen'] = get_bemerkungsoptionen()

        entries = list(ctx.get('entries') or [])

        # A/E/U je Eintrag aggregieren (dynamisch aus anwesenheit)
        if entries:
            with engine.begin() as conn:
                for item in entries:
                    eid = item['id'] if isinstance(item, dict) else getattr(item, 'id')
                    res = conn.execute(text("""
                        SELECT
                          COALESCE(SUM(CASE WHEN anwesend THEN 1 ELSE 0 END), 0) AS a,
                          COALESCE(SUM(CASE WHEN entschuldigt THEN 1 ELSE 0 END), 0) AS e,
                          COALESCE(SUM(CASE WHEN unentschuldigt THEN 1 ELSE 0 END), 0) AS u
                        FROM anwesenheit
                        WHERE entry_id = :eid
                    """), {'eid': eid}).mappings().first()

                    a = res['a'] if res and 'a' in res else 0
                    e = res['e'] if res and 'e' in res else 0
                    u = res['u'] if res and 'u' in res else 0

                    if isinstance(item, dict):
                        item['a'], item['e'], item['u'] = a, e, u
                    else:
                        setattr(item, 'a', a)
                        setattr(item, 'e', e)
                        setattr(item, 'u', u)

        ctx['entries'] = entries

        # falls Jinja den Helfer direkt aufruft
        ctx.setdefault('format_date_de', format_date_de)

        return render_template('index.html', **ctx)

    except Exception as ex:
        # Niemals ohne Response rausgehen
        logging.exception("index() failed")
        flash(_("Fehler beim Laden der Übersicht: ") + str(ex), "danger")
        return render_template(
            'index.html',
            entries=[],
            bemerkungsoptionen=get_bemerkungsoptionen(),
            format_date_de=format_date_de
        ), 500

@bbalance_routes.post('/add')
@login_required
@require_csrf
@require_perms('entries:add')
def add():
    user = current_user()

    # Rohwerte für sauberes Re-Render bei Fehlern merken
    datum_s   = (request.form.get('datum') or '').strip()
    temp_token = (request.form.get('temp_token') or '').strip()

    try:
        datum    = parse_date_de_or_today(datum_s)
        # Alternativ stricte Parser: parse_int_strict(...) or 0
        vollgut  = int((request.form.get('vollgut') or '0').strip() or '0')
        leergut  = int((request.form.get('leergut') or '0').strip() or '0')
        einnahme = parse_money(request.form.get('einnahme') or '0')
        ausgabe  = parse_money(request.form.get('ausgabe') or '0')
        bemerkung = (request.form.get('bemerkung') or '').strip()
        titel = (request.form.get('titel') or '').strip()
    except Exception as e:
        flash(f"{_('Eingabefehler:')} {e}", "danger")
        # ⬇️ bei Fehler: gleiche Seite rendern, temp_token beibehalten
        ctx = _build_index_context(default_date=(datum_s or today_ddmmyyyy()),
                                   temp_token=temp_token)
        return render_template('index.html', **ctx), 400

    # 🔐 Optional: Härtung gegen DevTools-Manipulation (Front-End min=0 serverseitig durchsetzen)
    vollgut  = max(0, vollgut)
    leergut  = max(0, leergut)
    if einnahme < 0:
        einnahme = Decimal('0')
    if ausgabe < 0:
        ausgabe = Decimal('0')

    # Mindestbedingung: mind. eines der Felder > 0
    any_filled = any([
        titel != '',
        bemerkung != ''
    ])
    if not any_filled:
        flash(_('Bitte Tiel, Datum und Bemerkung angeben.'), 'danger')
        # ⬇️ KEIN redirect – render mit identischem temp_token, sonst gehen Tempfiles verloren
        ctx = _build_index_context(default_date=(datum_s or today_ddmmyyyy()),
                                   temp_token=temp_token)
        return render_template('index.html', **ctx), 400

    # Datensatz speichern
    with engine.begin() as conn:
        res = conn.execute(text("""
            INSERT INTO entries (datum, titel, bemerkung, created_by)
            VALUES (:datum,:titel,:bemerkung,:cb)
            RETURNING id
        """), {
            'datum': datum,
            'titel': titel,
            'bemerkung': bemerkung,
            'cb': user['id']
        })
        new_id = res.scalar_one()

        flash(_('Dienst wurde gespeichert.'), 'success')

    # Token für diese Seite invalidieren (One-shot)
    session.pop('add_temp_token', None)

    return redirect(url_for('bbalance_routes.index'))

@bbalance_routes.get('/edit/<int:entry_id>')
@login_required
def edit(entry_id: int):
    with engine.begin() as conn:
        # 1) Eintrag OHNE 'unit' selektieren (gibt es nicht in entries)
        row = conn.execute(text("""
            SELECT id, datum, vollgut, leergut, einnahme, ausgabe, bemerkung, titel, interessenten, created_by
            FROM entries
            WHERE id = :id
        """), {'id': entry_id}).mappings().first()

        # 2) Attachments
        attachments = conn.execute(text("""
            SELECT id, original_name, content_type, size_bytes, created_at
            FROM attachments
            WHERE entry_id = :id
            ORDER BY created_at DESC
        """), {'id': entry_id}).mappings().all()

        # 3) Audit
        audit = conn.execute(text("""
            SELECT a.id, a.user_id, u.username, a.action, a.created_at, a.detail
            FROM audit_log a
            LEFT JOIN users u ON u.id = a.user_id
            WHERE a.entry_id = :id
            ORDER BY a.created_at ASC, a.id ASC
        """), {'id': entry_id}).mappings().all()

        # 4) Users + Anwesenheit  ✅ hier u.unit selektieren
        users = conn.execute(text("""
        SELECT u.id,
            u.username,
            u.unit,
            u.supervisor,
            u.chief,
            a.anwesend,
            a.entschuldigt,
            a.unentschuldigt,
            a.bemerkung
        FROM users u
        LEFT JOIN anwesenheit a
        ON a.user_id = u.id AND a.entry_id = :eid
        WHERE u.active = TRUE
    """), {'eid': entry_id}).mappings().all()

    # Gruppieren in Python
    jugendliche = sorted(
        [u for u in users if not u.supervisor and not u.chief],
        key=lambda x: (x.unit or '', x.username or '')
    )
    betreuer = sorted(
        [u for u in users if u.supervisor or u.chief],
        key=lambda x: (x.unit or '', x.username or '')
    )


    if not row:
        flash(_('Eintrag nicht gefunden.'))
        return redirect(url_for('bbalance_routes.index'))

    # Eintragsdaten fürs Formular
    data = {
        'id': row['id'],
        'datum': row['datum'],
        'vollgut': row['vollgut'],
        'leergut': row['leergut'],
        'einnahme': row['einnahme'],
        'ausgabe': row['ausgabe'],
        'bemerkung': row['bemerkung'],
        'titel': row['titel'],
        'interessenten': row.get('interessenten') or [] 
    }

    # Anhänge
    att_data = [{
        'id': r['id'],
        'name': r['original_name'],
        'size': r['size_bytes'],
        'content_type': r['content_type'],
        'url': url_for('attachments_routes.attachments_download', att_id=r['id']),
        'view_url': url_for('attachments_view', att_id=r['id'])
    } for r in attachments]

    bemerkungsoptionen = get_bemerkungsoptionen()

    return render_template(
    'edit.html',
        data=data,
        attachments=att_data,
        audit=audit,
        bemerkungsoptionen=bemerkungsoptionen,
        jugendliche=jugendliche,
        betreuer=betreuer
    )

@bbalance_routes.post('/edit/<int:entry_id>')
@login_required
@require_perms('entries:edit:any')
@require_csrf
def edit_post(entry_id: int):
    # 1) Altwerte laden
    with engine.begin() as conn:
        row = conn.execute(text("""
            SELECT id, datum, vollgut, leergut, einnahme, ausgabe, bemerkung, titel, interessenten, created_by
            FROM entries
            WHERE id=:id
        """), {'id': entry_id}).mappings().first()
    if not row:
        abort(404)

    # 2) RBAC prüfen
    allowed = ROLES.get(session.get('role'), set())
    if 'entries:edit:any' not in allowed:
        user = current_user()
        if not user or row['created_by'] != user['id'] or 'entries:edit:own' not in allowed:
            abort(403)

    # 3) Neue Werte parsen
    try:
        parsed_date = parse_date_de_or_none(request.form.get('datum'))
        datum = parsed_date if parsed_date else (row['datum'].date() if isinstance(row['datum'], datetime) else row['datum'])
        vollgut = int((request.form.get('vollgut') or '0').strip() or '0')
        leergut = int((request.form.get('leergut') or '0').strip() or '0')
        einnahme = parse_money(request.form.get('einnahme') or '0')
        ausgabe = parse_money(request.form.get('ausgabe') or '0')
        bemerkung = (request.form.get('bemerkung') or '').strip()
        titel = (request.form.get('titel') or '').strip()
    except Exception as e:
        flash(f"{_('Eingabefehler:')} {e}", 'danger')
        return redirect(url_for('bbalance_routes.edit', entry_id=entry_id))

    # 4) Anwesenheitsdaten auslesen
    anwesenheit_data = []
    user_ids = set()

    # Alle relevanten Anwesenheitsfelder durchgehen
    for key in request.form.keys():
        if key.startswith('anwesenheit_') and key.count('_') == 2:
            user_ids.add(int(key.split('_')[1]))

    for user_id in user_ids:
        anwesend = f'anwesenheit_{user_id}_A' in request.form
        entschuldigt = f'anwesenheit_{user_id}_E' in request.form
        unentschuldigt = f'anwesenheit_{user_id}_U' in request.form
        user_bem = request.form.get(f'bemerkung_{user_id}', '').strip()
        anwesenheit_data.append({
            'user_id': user_id,
            'anwesend': anwesend,
            'entschuldigt': entschuldigt,
            'unentschuldigt': unentschuldigt,
            'bemerkung': user_bem
        })

    # Summen berechnen
    sum_a = sum(1 for d in anwesenheit_data if d['anwesend'])
    sum_e = sum(1 for d in anwesenheit_data if d['entschuldigt'])
    sum_u = sum(1 for d in anwesenheit_data if d['unentschuldigt'])

    # 5) Änderungen ermitteln (wie gehabt)
    changes = []
    # ... (bestehende Diff-Logik bleibt)

    
# 6) Speichern
    with engine.begin() as conn:
        conn.execute(text("""
            UPDATE entries
            SET datum=:datum,
                vollgut=:vollgut,
                leergut=:leergut,
                einnahme=:einnahme,
                ausgabe=:ausgabe,
                bemerkung=:bemerkung,
                titel=:titel,
                updated_at=NOW()
            WHERE id=:id
        """), {
            'id': entry_id,
            'datum': datum,
            'vollgut': vollgut,
            'leergut': leergut,
            'einnahme': str(einnahme) if einnahme is not None else None,
            'ausgabe':  str(ausgabe)  if ausgabe  is not None else None,
            'bemerkung': bemerkung,
            'titel': titel
        })

        # Anwesenheit neu speichern (bereits vorhanden)
        conn.execute(text("DELETE FROM anwesenheit WHERE entry_id=:eid"), {'eid': entry_id})
        for d in anwesenheit_data:
            conn.execute(text("""
                INSERT INTO anwesenheit (entry_id, user_id, anwesend, entschuldigt, unentschuldigt, bemerkung)
                VALUES (:eid, :uid, :a, :e, :u, :bem)
            """), {
                'eid': entry_id,
                'uid': d['user_id'],
                'a': d['anwesend'],
                'e': d['entschuldigt'],
                'u': d['unentschuldigt'],
                'bem': d['bemerkung']
            })

       # 👉 Interessenten aus dem Formular sammeln
        interessenten = []
        indices = set()
        for k in request.form.keys():
            if k.startswith('interessent_name_'):
                indices.add(k.split('_')[-1])

        for idx in sorted(indices, key=lambda x: int(x) if str(x).isdigit() else 0):
            name = (request.form.get(f"interessent_name_{idx}") or '').strip()
            unit = (request.form.get(f"interessent_unit_{idx}") or '').strip()
            a = bool(request.form.get(f"interessent_a_{idx}"))
            e = bool(request.form.get(f"interessent_e_{idx}"))
            u = bool(request.form.get(f"interessent_u_{idx}"))
            bem = (request.form.get(f"interessent_bemerkung_{idx}") or '').strip()

            # Leerzeilen überspringen
            if not (name or unit or bem or a or e or u):
                continue

            interessenten.append({
                "name": name,
                "loescheinheit": unit,
                "a": a,
                "e": e,
                "u": u,
                "bemerkung": bem
            })

        # JSONB sauber in entries schreiben
        conn.execute(text("""
            UPDATE entries
            SET interessenten = CAST(:data AS JSONB)
            WHERE id = :id
        """), {'data': json.dumps(interessenten), 'id': entry_id})

        # Audit-Log zuletzt
        now_str = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
        detail_text = f"Bearbeitet am {now_str}\n" + ("\n".join([f"- {lbl}: {old} → {new}" for _, lbl, old, new in changes]) if changes else "(keine Feldänderungen)")
        conn.execute(text("""
            INSERT INTO audit_log (user_id, action, entry_id, detail)
            VALUES (:uid, 'edit', :eid, :detail)
        """), {'uid': session.get('user_id'), 'eid': entry_id, 'detail': detail_text})


    # Interessenten aus dem Formular sammeln
        interessenten = []
        for key in request.form:
            if key.startswith('interessent_name_'):
                idx = key.split('_')[-1]
                interessenten.append({
                    "name": request.form.get(f"interessent_name_{idx}"),
                    "loescheinheit": request.form.get(f"interessent_unit_{idx}"),
                    "a": bool(request.form.get(f"interessent_a_{idx}")),
                    "e": bool(request.form.get(f"interessent_e_{idx}")),
                    "u": bool(request.form.get(f"interessent_u_{idx}")),
                    "bemerkung": request.form.get(f"interessent_bemerkung_{idx}")
                })

    flash(_('Dienst wurde gespeichert.'), 'success')
    return redirect(url_for('bbalance_routes.index'))

@bbalance_routes.post('/delete/<int:entry_id>')
@login_required
@require_csrf
def delete(entry_id: int):
    with engine.begin() as conn:
        row = conn.execute(text('SELECT created_by FROM entries WHERE id=:id'), {'id': entry_id}).mappings().first()
    if not row:
        abort(404)
    allowed = ROLES.get(session.get('role'), set())
    if 'entries:delete:any' not in allowed:
        user = current_user()
        if not user or row['created_by'] != user['id'] or 'entries:delete:own' not in allowed:
            abort(403)
    with engine.begin() as conn:
        conn.execute(text('DELETE FROM entries WHERE id=:id'), {'id': entry_id})
    log_action(session.get('user_id'), 'entries:delete', entry_id, None)
    return redirect(url_for('bbalance_routes.index'))

@bbalance_routes.route('/entry/<int:id>/interessenten', methods=['POST'])
def update_interessenten(id: int):
    payload = request.get_json(silent=True) or {}
    interessenten = payload.get('interessenten', [])
    with engine.begin() as conn:
        conn.execute(text("""
            UPDATE entries
            SET interessenten = CAST(:data AS JSONB),
                updated_at = NOW()
            WHERE id = :id
        """), {"data": json.dumps(interessenten), "id": id})
    return jsonify({"status": "ok"})


# -----------------------
# Export/Import
# -----------------------
@bbalance_routes.get('/export')
@login_required
@require_perms('export:csv')
def export_csv():
    q = (request.args.get('q') or '').strip()
    df = request.args.get('from')
    dt = request.args.get('to')
    attachments_filter = request.args.get('attachments')  # 'only' | 'none' | None

    date_from = datetime.strptime(df, '%Y-%m-%d').date() if df else None
    date_to   = datetime.strptime(dt, '%Y-%m-%d').date() if dt else None

    entries = fetch_entries(q or None, date_from, date_to, attachments_filter=attachments_filter)

    output = io.StringIO()
    writer = csv.writer(output, delimiter=';', lineterminator='\n')
    writer.writerow(['Datum','Vollgut','Leergut','Inventar','Einnahme','Ausgabe','Kassenbestand','Bemerkung','Titel'])
    for e in entries:
        writer.writerow([
            format_date_de(e['datum']), e['vollgut'], e['leergut'], e['inventar'],
            str(e['einnahme']).replace('.', ','), str(e['ausgabe']).replace('.', ','),
            str(e['kassenbestand']).replace('.', ','), e['bemerkung']
        ])
    mem = io.BytesIO()
    mem.write(output.getvalue().encode('utf-8-sig'))
    mem.seek(0)
    filename = f"bottlebalance_export_{date.today().strftime('%Y%m%d')}.csv"
    return send_file(mem, as_attachment=True, download_name=filename, mimetype='text/csv')

@bbalance_routes.post('/import')
@login_required
@require_perms('import:csv')
@require_csrf
def import_csv():
    file = request.files.get('file')
    replace_all = request.form.get('replace_all') == 'on'
    if not file or file.filename == '':
        flash(_('Bitte eine CSV-Datei auswählen.'))
        return redirect(url_for('bbalance_routes.index'))
    try:
        content = file.read().decode('utf-8-sig')
        reader = csv.reader(io.StringIO(content), delimiter=';')
        headers = next(reader, None)
        # Robustheit: Header-Zeile prüfen und ggf. splitten
        if headers and len(headers) == 1 and ';' in headers[0]:
            headers = headers[0].split(';')
        # Validierung
        validation_errors = []

        if len(set(headers)) != len(headers):
            validation_errors.append("Doppelte Spaltennamen in CSV.")

        if any(h.strip() == "" for h in headers):
            validation_errors.append("Leere Spaltennamen in CSV.")

        required_fields = {"Datum", "Vollgut", "Leergut"}
        if not required_fields.issubset(set(headers)):
            validation_errors.append("Pflichtfelder fehlen: Datum, Vollgut, Leergut.")

        if validation_errors:
            for err in validation_errors:
                flash(err)
            return redirect(url_for('bbalance_routes.index'))
        expected = ['Datum','Vollgut','Leergut','Inventar','Einnahme','Ausgabe','Kassenbestand','Bemerkung']
        alt_expected = ['Datum','Vollgut','Leergut','Einnahme','Ausgabe','Bemerkung']
        if headers is None or [h.strip() for h in headers] not in (expected, alt_expected):
            raise ValueError('CSV-Header entspricht nicht dem erwarteten Format.')
        rows_to_insert = []
        for row in reader:
            if len(row) == 8:
                datum_s, voll_s, leer_s, _inv, ein_s, aus_s, _kas, bem = row
            else:
                datum_s, voll_s, leer_s, ein_s, aus_s, bem = row
            datum = parse_date_de_or_today(datum_s)
            vollgut = int((voll_s or '0').strip() or 0)
            leergut = int((leer_s or '0').strip() or 0)
            einnahme = parse_money(ein_s or '0')
            ausgabe = parse_money(aus_s or '0')
            bemerkung = (bem or '').strip()
            rows_to_insert.append({'datum': datum, 'vollgut': vollgut, 'leergut': leergut,
                                   'einnahme': str(einnahme), 'ausgabe': str(ausgabe), 'bemerkung': bemerkung})
        with engine.begin() as conn:
            if replace_all:
                conn.execute(text('DELETE FROM entries'))
            for r in rows_to_insert:
                conn.execute(text("""
                    INSERT INTO entries (datum, vollgut, leergut, einnahme, ausgabe, bemerkung, titel)
                    VALUES (:datum,:vollgut,:leergut,:einnahme,:ausgabe,:bemerkung,:titel)
                """), r)
        flash(f"{_('Import successfull:')} {len(rows_to_insert)} {_('rows adopted.')}")
    except Exception as e:
        flash(f"{_('Import fehlgeschlagen:')} {e}")
    return redirect(url_for('bbalance_routes.index'))