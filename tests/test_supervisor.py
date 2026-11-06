"""Funcionamiento continuo (``sapsec servicio``): reabre la aplicación si se cae o deja de responder."""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import pytest

from sapsec.supervisor import Policy, SingleInstance, Status, Supervisor, child_command, read_status

FAST = Policy(check_every=0.05, probe_timeout=0.1, failures_to_restart=2, startup_grace=0.0, backoff=(0.05,),
              stable_after=60.0, stop_timeout=5.0)


def _run(sup: Supervisor, until, timeout: float = 20.0) -> None:  # type: ignore[no-untyped-def]
    t = threading.Thread(target=sup.run, daemon=True)
    t.start()
    end = time.monotonic() + timeout
    while time.monotonic() < end and not until():
        time.sleep(0.05)
    sup.stop()
    t.join(15)
    assert not t.is_alive(), "el servicio no se detuvo"


def test_reopens_the_app_after_a_crash(tmp_path: Path):
    status = Status(tmp_path / "servicio.json")
    sup = Supervisor([sys.executable, "-c", "import sys; sys.exit(3)"], lambda: False, FAST, status)
    _run(sup, lambda: sup.restarts >= 3)
    data = read_status(tmp_path)
    assert data is not None and data["reinicios"] >= 3
    assert data["ultimo_reinicio"]["motivo"] == "se cerró (código 3)"
    assert data["estado"] == "detenido" and not data["reciente"]


def test_restarts_the_app_when_it_stops_responding(tmp_path: Path):
    answers = iter([False, True, True] + [False] * 1000)  # responde un rato y después se cuelga
    started: list = []
    sup = Supervisor([sys.executable, "-c", "import time; time.sleep(120)"], lambda: next(answers), FAST,
                     Status(tmp_path / "servicio.json"))
    orig = sup._start_child

    def spy():  # type: ignore[no-untyped-def]
        p = orig()
        started.append(p)
        return p
    sup._start_child = spy  # type: ignore[method-assign]
    _run(sup, lambda: sup.restarts >= 1)
    data = read_status(tmp_path)
    assert data["ultimo_reinicio"]["motivo"] == "no respondía"
    assert started and started[0].poll() is not None  # la copia colgada se cerró antes de abrir otra
    assert all(p.poll() is not None for p in started)  # al detener el servicio no queda ninguna abierta


def test_does_not_open_a_second_copy_when_the_app_is_already_open(tmp_path: Path):
    sup = Supervisor([sys.executable, "-c", "raise SystemExit('no debería abrirse')"], lambda: True, FAST,
                     Status(tmp_path / "servicio.json"))
    _run(sup, lambda: (read_status(tmp_path) or {}).get("estado") == "otra_instancia")
    assert sup.restarts == 0 and sup.child is None


def test_stopping_the_service_closes_the_app(tmp_path: Path):
    sup = Supervisor([sys.executable, "-c", "import time; time.sleep(120)"], lambda: True, FAST,
                     Status(tmp_path / "servicio.json"))
    sup.probe = lambda: sup.child is not None  # «responde» solo la copia del servicio  # type: ignore[method-assign]
    holder: dict = {}

    def until() -> bool:
        if sup.child is not None:
            holder["p"] = sup.child
        return "p" in holder and (read_status(tmp_path) or {}).get("estado") == "funcionando"
    _run(sup, until)
    assert holder["p"].poll() is not None
    assert read_status(tmp_path)["estado"] == "detenido"


def test_only_one_service_per_installation(tmp_path: Path):
    a, b = SingleInstance(tmp_path / "servicio.lock"), SingleInstance(tmp_path / "servicio.lock")
    assert a.acquire()
    assert not b.acquire()
    a.release()
    assert b.acquire()
    b.release()


def test_child_command_and_stale_status(tmp_path: Path):
    assert child_command(True, True, 8443, None)[-4:] == ["serve", "--red", "--port", "8443"]
    assert "--sin-https" in child_command(True, False, None, None)
    assert "--red" not in child_command(False, True, None, None)
    assert read_status(tmp_path) is None
    (tmp_path / "servicio.json").write_text('{"estado": "funcionando", "actualizado": "2020-01-01T00:00:00"}',
                                            encoding="utf-8")
    assert read_status(tmp_path)["reciente"] is False  # sin novedades hace años: el servicio no está activo


@pytest.mark.skipif(sys.platform != "win32", reason="Job Object: solo Windows")
def test_windows_job_object_is_created():
    from sapsec.supervisor import _KillOnCloseJob
    assert _KillOnCloseJob().handle


def test_windows_exit_codes_are_shown_signed(tmp_path: Path):
    """Windows informa 0xFFFFFFFF (proceso terminado a la fuerza) como 4294967295: se muestra como -1."""
    class Fake:
        pid = 1

        def wait(self, timeout=None):  # type: ignore[no-untyped-def]
            return 0xFFFFFFFF

        def poll(self):  # type: ignore[no-untyped-def]
            return 0xFFFFFFFF
    sup = Supervisor(["x"], lambda: False, FAST, Status(tmp_path / "servicio.json"))
    assert sup._watch(Fake()) == "se cerró (código -1)"  # type: ignore[arg-type]
