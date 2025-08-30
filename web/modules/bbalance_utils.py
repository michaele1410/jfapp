# -----------------------
# Data Access
# -----------------------
from decimal import Decimal
from flask import request, session
from flask_babel import gettext as _
from sqlalchemy import text
from datetime import datetime, date
from uuid import uuid4

from modules.core_utils import (
    engine
)

from modules.csv_utils import (
    today_ddmmyyyy,
    format_eur_de,
    format_date_de
)
from modules.core_utils import (
    engine, 
    ROLES
)
from modules.auth_utils import (
    current_user
)

def fetch_entries(
    search: str | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
    attachments_filter: str | None = None  # 'only' | 'none' | None
):
    """
    Holt Einträge inkl. fortlaufend berechnetem Inventar/Kassenbestand.
    - Zählt Attachments via LEFT JOIN auf eine Aggregation (performanter als korrelierte Subqueries).
    - attachments_filter:
        'only'  -> nur Einträge mit mind. 1 Anhang
        'none'  -> nur Einträge ohne Anhang
        None    -> keine Einschränkung
    """
    where = []
    params: dict[str, object] = {}

    if search:
        where.append("(e.bemerkung ILIKE :q OR to_char(e.datum, 'DD.MM.YYYY') ILIKE :q)")
        params['q'] = f"%{search}%"
    if date_from:
        where.append("e.datum >= :df")
        params['df'] = date_from
    if date_to:
        where.append("e.datum <= :dt")
        params['dt'] = date_to

    # Anhangsfilter direkt in WHERE aufnehmen (Alias 'a' ist durch den JOIN vorhanden)
    if attachments_filter == 'only':
        where.append("COALESCE(a.cnt, 0) > 0")
    elif attachments_filter == 'none':
        where.append("COALESCE(a.cnt, 0) = 0")


    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    # Aggregation für Attachments einmalig bilden und joinen
    
    sql = f"""
         WITH att AS (
             SELECT entry_id, COUNT(*) AS cnt
             FROM attachments
             GROUP BY entry_id
         )
         SELECT
             e.id,
             e.datum,
             e.vollgut,
             e.leergut,
             e.einnahme,
             e.ausgabe,
             e.bemerkung,
             e.titel,
             e.created_by,
             COALESCE(a.cnt, 0) AS attachment_count
         FROM entries e
         LEFT JOIN att a ON a.entry_id = e.id
         {where_sql}

        ORDER BY e.datum ASC, e.id ASC
    """

    with engine.begin() as conn:
        rows = conn.execute(text(sql), params).mappings().all()

    inventar = 0
    kassenbestand = Decimal('0.00')
    result = []
    for r in rows:
        voll = r['vollgut'] or 0
        leer = r['leergut'] or 0
        ein = Decimal(r['einnahme'] or 0)
        aus = Decimal(r['ausgabe'] or 0)

        inventar += (voll - leer)
        kassenbestand = (kassenbestand + ein - aus).quantize(Decimal('0.01'))

        result.append({
            'id': r['id'],
            'datum': r['datum'],
            'vollgut': voll,
            'leergut': leer,
            'einnahme': ein,
            'ausgabe': aus,
            'bemerkung': r['bemerkung'] or '',
            'titel': r['titel'] or '',
            'inventar': inventar,
            'kassenbestand': kassenbestand,
            'created_by': r['created_by'],
            'attachment_count': r['attachment_count'],
        })
    return result

def current_totals():
    with engine.begin() as conn:
        rows = conn.execute(text("SELECT vollgut, leergut, einnahme, ausgabe FROM entries ORDER BY datum ASC, id ASC")).fetchall()
    inv = 0
    kas = Decimal('0.00')
    for (voll, leer, ein, aus) in rows:
        inv += (voll or 0) - (leer or 0)
        kas = (kas + Decimal(ein or 0) - Decimal(aus or 0)).quantize(Decimal('0.01'))
    return inv, kas

def _user_can_edit_entry(entry_id: int) -> bool:
    """RBAC-Check: edit:any oder edit:own wenn created_by = current_user."""
    allowed = ROLES.get(session.get('role'), set())
    if 'entries:edit:any' in allowed:
        return True
    if 'entries:edit:own' in allowed:
        user = current_user()
        if not user: return False
        with engine.begin() as conn:
            owner = conn.execute(text("SELECT created_by FROM entries WHERE id=:id"), {'id': entry_id}).scalar_one_or_none()
        return owner == user['id']
    return False

def _user_can_view_entry(entry_id: int) -> bool:
    allowed = ROLES.get(session.get('role'), set())
    return 'entries:view' in allowed

def _build_index_context(default_date: str | None = None, temp_token: str | None = None):
    """
    Bereitet alle Variablen für index.html auf – mit stabilem temp_token.
    - totals-Modus via ?totals=filtered | all
      * 'filtered': inv_aktuell/kas_aktuell aus der gefilterten Liste
      * 'all' (Default): Gesamtstände aus der gesamten Tabelle
    """
    # Filter aus Query
    q = (request.args.get('q') or '').strip()
    date_from_s = request.args.get('from')
    date_to_s = request.args.get('to')
    df = datetime.strptime(date_from_s, '%Y-%m-%d').date() if date_from_s else None
    dt = datetime.strptime(date_to_s, '%Y-%m-%d').date() if date_to_s else None

    # Anhänge: 'only' | 'none' | None
    filter_attachments = request.args.get('attachments')

    # Einträge DB-seitig mit allen Filtern holen
    entries = fetch_entries(q or None, df, dt, attachments_filter=filter_attachments)

    # Totals-Modus: 'all' (Default) oder 'filtered'
    totals_mode = (request.args.get('totals') or 'all').strip().lower()
    if totals_mode not in ('all', 'filtered'):
        totals_mode = 'all'

    if totals_mode == 'filtered':
        # Aus gefilterten Daten ableiten
        if entries:
            inv_aktuell = entries[-1]['inventar']
            kas_aktuell = entries[-1]['kassenbestand']
        else:
            inv_aktuell = 0
            kas_aktuell = Decimal('0.00')
    else:
        # Gesamtsystemstände
        inv_aktuell, kas_aktuell = current_totals()

    # Serien für Sparklines (bewusst auf Basis der gefilterten Liste)
    series_inv = [e['inventar'] for e in entries]
    series_kas = [float(e['kassenbestand']) for e in entries]

    finv = entries[-1]['inventar'] if entries else 0
    fkas = entries[-1]['kassenbestand'] if entries else Decimal('0')

    role = session.get('role')
    allowed = ROLES.get(role, set())

    # temp_token beibehalten oder anlegen (NICHT überschreiben, wenn übergeben)
    token = temp_token or session.get('add_temp_token') or uuid4().hex
    session['add_temp_token'] = token  # Session soll denselben Token kennen

    return {
        'entries': entries,
        'inv_aktuell': inv_aktuell,
        'kas_aktuell': kas_aktuell,
        'filter_inv': finv,
        'filter_kas': fkas,
        'default_date': default_date or today_ddmmyyyy(),
        'format_eur_de': format_eur_de,
        'format_date_de': format_date_de,
        'can_add': ('entries:add' in allowed),
        'can_export_csv': ('export:csv' in allowed),
        'can_export_pdf': ('export:pdf' in allowed),
        'can_import': ('import:csv' in allowed),
        'role': role,
        'series_inv': series_inv,
        'series_kas': series_kas,
        'temp_token': token,
        # Optional im Template verwenden, falls du den Modus anzeigen willst:
        'totals_mode': totals_mode,
    }
    