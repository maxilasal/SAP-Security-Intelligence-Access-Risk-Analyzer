"""La recomendación de cada pantalla: una frase clara, por qué, pasos y dónde (sistema ficticio DMO)."""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from conftest import ROOT, fixture_data
from sapsec.connectors.base import ConnectionParams, LoadLimits
from sapsec.connectors.fixture_connector import FixtureConnector
from sapsec.extraction.extractor import Extractor
from sapsec.storage.db import make_engine
from sapsec.storage.orm import Base, SapConnection, SapSystem


@pytest.fixture(scope="module")
def env():  # type: ignore[no-untyped-def]
    import sapsec.services as sv
    from sapsec.actions import _CACHE, build_tasks
    from sapsec.engine.rules import load_rules
    engine = make_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    orig = sv.get_engine
    sv.get_engine = lambda: engine  # type: ignore[assignment]
    db = Session(engine, expire_on_commit=False)
    system = SapSystem(sid="DMO", name="PRD", environment="PRD", productive=True)
    db.add(system)
    db.flush()
    conn = SapConnection(system_id=system.id, client="100", name="t", backend="fixture", rfc_user="X")
    db.add(conn)
    db.commit()
    c = FixtureConnector(ConnectionParams(client="100", user="X"),
                         LoadLimits(pause_between_calls_ms=0, max_calls_per_minute=10 ** 6), data=fixture_data())
    snap = Extractor(c, db, conn, "pytest").run()
    db.commit()
    sv.analyze_snapshot(db, snap.id)
    _CACHE.clear()
    rules = load_rules(ROOT / "config" / "rules")
    tasks = build_tasks(db, snap, rules)
    yield db, snap, rules, tasks, sv.data_for(snap), sv.context_for(db, snap)
    sv.get_engine = orig  # type: ignore[assignment]


def _task(tasks, title):  # type: ignore[no-untyped-def]
    return next(t for t in tasks if t.title == title)


def test_task_recommendations_are_one_clear_sentence(env):
    from sapsec.advice import home_advice, task_advice
    db, snap, rules, tasks, data, ctx = env
    a = task_advice(_task(tasks, "Quitar el perfil SAP_ALL"), data, "PRD")
    assert a.headline == "Quitar el perfil SAP_ALL a ADMIN_BASIS y asignarle solo los roles que necesita."
    assert a.level == "critico" and any("SU01" in s.text and "SAP_ALL" in s.text for s in a.steps)
    assert "desaparecen también" in a.why
    a = task_advice(_task(tasks, "Separar los roles Z_FI_PAGOS y Z_FI_PROVEEDORES"), data, "PRD")
    assert a.headline.startswith("No dejar los roles Z_FI_PAGOS y Z_FI_PROVEEDORES juntos")
    assert a.where.startswith("SU01 / SU10")
    a = task_advice(_task(tasks, "Corregir el rol Z_BC_DESARROLLO"), data, "PRD")
    assert a.headline == ("Quitar o restringir en el rol Z_BC_DESARROLLO el permiso de riesgo que se detalla abajo.")
    assert any("transportarlo a producción" in s.text for s in a.steps)  # en PRD: corregir en DEV y transportar
    a = task_advice(_task(tasks, "Corregir el rol Z_MM_COMPRADOR_C"), data, "PRD")  # rol compuesto
    assert a.headline.startswith("Dividir el rol Z_MM_COMPRADOR_C: por sí solo permite")
    assert "compuesto" in a.steps[0].text and "Roles" in a.where
    home = home_advice(tasks[0], None, "PRD")
    assert home.action and home.action[1] == f"/acciones/{tasks[0].key}" and not home.steps
    assert home_advice(None).level == "ok"


def test_user_role_and_simulation_recommendations(env):
    from sapsec.actions import _key, role_fix_items, user_fix_items
    from sapsec.advice import role_advice, simulation_advice, user_advice
    from sapsec.engine.analysis import analyze_role, analyze_user
    from sapsec.engine.simulator import Scenario, simulate
    db, snap, rules, tasks, data, ctx = env

    a = analyze_user(ctx, data, "USUARIO_BLOQ")
    adv = user_advice("USUARIO_BLOQ", a.eff.user, user_fix_items(rules, a), [], 300, 90)
    assert adv.headline.startswith("Quitarle uno de estos roles: Z_FI_PAGOS o Z_FI_PROVEEDORES")
    assert "bloqueado" in adv.note and adv.steps[0].link.startswith("/acciones/")
    a = analyze_user(ctx, data, "USUARIO_TEST")
    assert user_advice("USUARIO_TEST", a.eff.user, user_fix_items(rules, a), [], 3, 90).level == "ok"

    ra = analyze_role(ctx, data, "Z_BC_ADMIN_TOTAL")
    adv = role_advice("Z_BC_ADMIN_TOTAL", ra.role_type, role_fix_items(rules, ra), "", len(ra.users), "PRD",
                      _key("rol", "Z_BC_ADMIN_TOTAL"))
    assert adv.headline.startswith("Corregir este rol:") and adv.action
    ra = analyze_role(ctx, data, "Z_FI_DESACTUALIZADO")
    adv = role_advice("Z_FI_DESACTUALIZADO", ra.role_type, role_fix_items(rules, ra), "", 1, "PRD", None)
    assert "PFCG" in adv.headline and "PFUD" in adv.headline  # sin romper las siglas

    res = simulate(ctx, data, "USUARIO_TEST", Scenario(add_roles=["Z_FI_PAGOS"]))
    adv = simulation_advice(res)
    assert adv.headline == "No asignar Z_FI_PAGOS a USUARIO_TEST." and adv.verdict == "NO RECOMENDADO"
    assert adv.why.startswith("Le permitiría «") and adv.steps
    res = simulate(ctx, data, "SEG_ADMIN", Scenario(remove_roles=["Z_SEC_USUARIOS"]))
    adv = simulation_advice(res)
    assert adv.headline.startswith("Se puede quitar Z_SEC_USUARIOS a SEG_ADMIN: elimina") and adv.level == "ok"
