"""Borrado de snapshots, conexiones y reinicio completo de datos SAP."""

from sqlalchemy import func, select

from conftest import extract, fixture_data


def _setup(monkeypatch):  # type: ignore[no-untyped-def]
    import sapsec.services as sv
    engine, db, snap, _ = extract(fixture_data())
    monkeypatch.setattr(sv, "get_engine", lambda: engine)
    sv.analyze_snapshot(db, snap.id)
    return sv, engine, db, snap


def test_delete_snapshot_removes_everything(monkeypatch):
    from sapsec.storage.orm import SAP_TABLES, Finding, Snapshot
    sv, engine, db, snap = _setup(monkeypatch)
    assert db.scalar(select(func.count()).select_from(Finding)) > 0
    counts = sv.delete_snapshot(db, snap.id)
    assert counts["ust12"] > 0 and counts["hallazgos"] > 0
    assert db.get(Snapshot, snap.id) is None
    for t in SAP_TABLES.values():
        assert db.scalar(select(func.count()).select_from(t)) == 0
    assert db.scalar(select(func.count()).select_from(Finding)) == 0


def test_delete_connection_removes_snapshots_system_and_password(monkeypatch):
    from sapsec.security import secrets
    from sapsec.storage.orm import SapConnection, SapSystem, Snapshot
    sv, engine, db, snap = _setup(monkeypatch)
    conn = db.get(SapConnection, snap.connection_id)
    conn.credential_ref = "DMO-100-SECX-1"
    db.commit()
    deleted = []
    monkeypatch.setattr(secrets, "delete_password", lambda ref: deleted.append(ref) or True)
    res = sv.delete_connection(db, conn.id)
    assert res["snapshots"] == 1 and res["sistema_borrado"] and res["credencial_borrada"]
    assert deleted == ["DMO-100-SECX-1"]
    assert db.scalar(select(func.count()).select_from(Snapshot)) == 0
    assert db.scalar(select(func.count()).select_from(SapSystem)) == 0


def test_reset_keeps_app_users_and_audit(monkeypatch):
    from sapsec.security.auth import hash_password
    from sapsec.storage.orm import AppUser, AuditLog, SapConnection, Snapshot
    sv, engine, db, snap = _setup(monkeypatch)
    db.add(AppUser(username="admin", password_hash=hash_password("Clave-de-prueba-123"), role="administrador"))
    db.add(AuditLog(username="admin", action="prueba"))
    db.commit()
    sv.reset_sap_data(db)
    assert db.scalar(select(func.count()).select_from(Snapshot)) == 0
    assert db.scalar(select(func.count()).select_from(SapConnection)) == 0
    assert db.scalar(select(func.count()).select_from(AppUser)) == 1
    assert db.scalar(select(func.count()).select_from(AuditLog)) >= 1
