"""Funcionamiento continuo: mantiene la aplicación web siempre disponible (``sapsec servicio``).

Lo inicia el Programador de tareas de Windows al encender el servidor (``scripts/iniciar_con_windows.ps1``), aunque
nadie inicie sesión. Abre la aplicación web en un proceso hijo y la vigila:

* si el proceso termina (una caída), la vuelve a abrir enseguida; si falla seguido, espera cada vez un poco más
  (5 s, 15 s, 30 s, 1 min, 2 min, 5 min) para no saturar el equipo, y vuelve al mínimo cuando funcionó un rato;
* si deja de responder (varias sondas seguidas sin respuesta, unos 2 minutos), la cierra y la vuelve a abrir;
* si el vigilante se cierra (o lo detiene la tarea de Windows, por ejemplo para actualizar), la aplicación se
  cierra con él (en Windows, con un *Job Object*): nunca queda una copia huérfana ocupando el puerto;
* si la aplicación ya está abierta por otro medio (por ejemplo, ``run.ps1 -Red`` en una ventana), no abre otra:
  la vigila y, si esa se cierra, abre la suya;
* deja su estado en ``data/servicio.json`` (lo muestra «Configuración y acceso») y su registro en
  ``data/logs/servicio.log``.

No toca SAP ni la base de datos: solo vigila el proceso local de la aplicación.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger("sapsec.servicio")

STATUS_FILE = "servicio.json"
LOCK_FILE = "servicio.lock"


@dataclass
class Policy:
    check_every: float = 30.0         # segundos entre sondas de salud
    probe_timeout: float = 15.0       # cuánto se espera cada respuesta
    failures_to_restart: int = 4      # sondas seguidas sin respuesta antes de reiniciar (~2 minutos)
    startup_grace: float = 120.0      # al abrir, tiempo de carga antes de empezar a sondear
    backoff: tuple[float, ...] = (5, 15, 30, 60, 120, 300)
    stable_after: float = 600.0       # si funcionó 10 minutos, la próxima espera vuelve al mínimo
    stop_timeout: float = 20.0        # al detener: espera para que cierre solo antes de forzarlo


@dataclass
class Status:
    path: Path | None
    data: dict[str, Any] = field(default_factory=dict)

    def update(self, **kw: Any) -> None:
        self.data.update(kw)
        self.data["actualizado"] = _now()
        if self.path is None:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.data, ensure_ascii=False, indent=1), encoding="utf-8")
            os.replace(tmp, self.path)
        except OSError as exc:  # el estado es informativo: nunca frena la vigilancia
            log.warning("No se pudo escribir el estado del servicio: %s", exc)


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


# --------------------------------------------------------------------------------------- Windows: Job Object
class _KillOnCloseJob:
    """Job Object de Windows con «matar al cerrar»: si el vigilante muere (o lo detiene la tarea), Windows cierra
    también la aplicación y lo que ella haya abierto. En otros sistemas no hace nada."""

    def __init__(self) -> None:
        self.handle = None
        if sys.platform != "win32":
            return
        try:
            import ctypes
            from ctypes import wintypes

            class IoCounters(ctypes.Structure):
                _fields_ = [(n, ctypes.c_ulonglong) for n in (
                    "ReadOperationCount", "WriteOperationCount", "OtherOperationCount", "ReadTransferCount",
                    "WriteTransferCount", "OtherTransferCount")]

            class BasicLimits(ctypes.Structure):
                _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                            ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                            ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                            ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                            ("SchedulingClass", wintypes.DWORD)]

            class ExtendedLimits(ctypes.Structure):
                _fields_ = [("BasicLimitInformation", BasicLimits), ("IoInfo", IoCounters),
                            ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                            ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.CreateJobObjectW.restype = wintypes.HANDLE
            k32.CreateJobObjectW.argtypes = (wintypes.LPVOID, wintypes.LPCWSTR)
            k32.SetInformationJobObject.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD)
            k32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
            job = k32.CreateJobObjectW(None, None)
            if not job:
                raise OSError(ctypes.get_last_error(), "CreateJobObjectW")
            info = ExtendedLimits()
            info.BasicLimitInformation.LimitFlags = 0x00002000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if not k32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):  # Extended = 9
                raise OSError(ctypes.get_last_error(), "SetInformationJobObject")
            self.handle, self._k32 = job, k32
        except Exception as exc:  # noqa: BLE001 - sin Job Object el servicio funciona igual (menos protegido)
            log.warning("No se pudo crear el Job Object de Windows: %s", exc)

    def assign(self, proc: subprocess.Popen) -> None:
        if self.handle is None:
            return
        import ctypes
        if not self._k32.AssignProcessToJobObject(self.handle, int(proc._handle)):  # type: ignore[attr-defined]
            log.warning("No se pudo asociar la aplicación al Job Object (error %s)", ctypes.get_last_error())


# ------------------------------------------------------------------------------------------- una sola copia
class SingleInstance:
    """Impide dos vigilantes a la vez sobre la misma instalación (bloqueo de archivo; se libera solo si muere)."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._fh: Any = None

    def acquire(self) -> bool:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fh = open(self.path, "a+b")  # noqa: SIM115
        try:
            if sys.platform == "win32":
                import msvcrt
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            fh.close()
            return False
        self._fh = fh
        return True

    def release(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            finally:
                self._fh = None


# ----------------------------------------------------------------------------------------------- vigilante
class Supervisor:
    def __init__(self, cmd: list[str], probe: Callable[[], bool], policy: Policy | None = None,
                 status: Status | None = None, env: dict[str, str] | None = None) -> None:
        self.cmd, self.probe, self.policy = cmd, probe, policy or Policy()
        self.status = status or Status(None)
        self.env = env
        self.stop_event = threading.Event()
        self.child: subprocess.Popen | None = None
        self.restarts = 0
        self.job = _KillOnCloseJob()

    # -- ciclo de vida del proceso de la aplicación
    def _start_child(self) -> subprocess.Popen:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.stdout is None else 0
        proc = subprocess.Popen(self.cmd, env=self.env, creationflags=flags,
                                stdin=subprocess.DEVNULL)
        self.job.assign(proc)
        log.info("Aplicación iniciada (proceso %s): %s", proc.pid, " ".join(self.cmd[1:]))
        return proc

    def _stop_child(self, reason: str) -> None:
        proc, self.child = self.child, None
        if proc is None or proc.poll() is not None:
            return
        log.info("Cerrando la aplicación (proceso %s): %s", proc.pid, reason)
        proc.terminate()
        try:
            proc.wait(timeout=self.policy.stop_timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)

    def stop(self) -> None:
        self.stop_event.set()

    def _sleep(self, seconds: float) -> bool:
        """Espera; devuelve True si pidieron detener el servicio."""
        return self.stop_event.wait(seconds)

    # -- vigilancia
    def _wait_exit(self, proc: subprocess.Popen, seconds: float) -> int | None:
        """Espera hasta ``seconds`` a que el proceso termine, en tramos cortos para atender un pedido de detener."""
        end = time.monotonic() + seconds
        while not self.stop_event.is_set():
            left = end - time.monotonic()
            if left <= 0:
                return None
            try:
                return proc.wait(timeout=min(1.0, left))
            except subprocess.TimeoutExpired:
                continue
        return None

    def _watch(self, proc: subprocess.Popen) -> str | None:
        """Vigila la aplicación hasta que se caiga o deje de responder. Devuelve el motivo (None = se detiene)."""
        p = self.policy
        started = time.monotonic()
        failures = 0
        while not self.stop_event.is_set():
            code = self._wait_exit(proc, p.check_every)
            if self.stop_event.is_set():
                return None
            if code is not None:
                return f"se cerró (código {code})"
            if self.probe():
                if failures:
                    log.info("La aplicación volvió a responder")
                failures = 0
                self.status.update(estado="funcionando", ultima_respuesta=_now(), sondas_fallidas=0)
                continue
            if time.monotonic() - started < p.startup_grace:
                continue  # todavía está cargando
            failures += 1
            log.warning("La aplicación no respondió (%s de %s)", failures, p.failures_to_restart)
            self.status.update(estado="sin_respuesta", sondas_fallidas=failures)
            if failures >= p.failures_to_restart:
                self._stop_child("no respondía")
                return "no respondía"
        return None

    def run(self) -> int:
        p = self.policy
        attempt = 0
        self.status.update(estado="iniciando", pid=os.getpid(), inicio=_now(), reinicios=0)
        log.info("Servicio iniciado (proceso %s)", os.getpid())
        while not self.stop_event.is_set():
            if self.probe():  # ya hay una copia abierta (otra ventana): se vigila sin abrir otra
                self.status.update(estado="otra_instancia", pid_app=None)
                if self._sleep(p.check_every):
                    break
                continue
            self.child = self._start_child()
            started = time.monotonic()
            self.status.update(estado="iniciando", pid_app=self.child.pid, app_desde=_now())
            reason = self._watch(self.child)
            if reason is None:
                break
            uptime = time.monotonic() - started
            if uptime >= p.stable_after:
                attempt = 0
            delay = p.backoff[min(attempt, len(p.backoff) - 1)]
            attempt += 1
            self.restarts += 1
            log.warning("La aplicación %s después de %.0f s; se vuelve a abrir en %.0f s", reason, uptime, delay)
            self.status.update(estado="reiniciando", pid_app=None, reinicios=self.restarts,
                               ultimo_reinicio={"fecha": _now(), "motivo": reason})
            if self._sleep(delay):
                break
        self._stop_child("se detuvo el servicio")
        self.status.update(estado="detenido", pid_app=None)
        log.info("Servicio detenido")
        return 0


# --------------------------------------------------------------------------------------------- punto de entrada
def _setup_logging(log_dir: Path) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    fh = logging.handlers.RotatingFileHandler(log_dir / "servicio.log", maxBytes=2_000_000, backupCount=5,
                                              encoding="utf-8")
    fh.setFormatter(fmt)
    log.handlers = [fh]
    log.setLevel(logging.INFO)
    log.propagate = False
    if sys.stderr is not None:
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        log.addHandler(sh)


def child_command(network: bool, https: bool, port: int | None, host: str | None) -> list[str]:
    cmd = [sys.executable, "-m", "sapsec.cli", "serve"]
    if network:
        cmd.append("--red")
    if network and not https:
        cmd.append("--sin-https")
    if host:
        cmd += ["--host", host]
    if port:
        cmd += ["--port", str(port)]
    return cmd


def read_status(data_dir: Path) -> dict[str, Any] | None:
    """Estado que dejó el servicio (None si nunca se usó). ``reciente`` = actualizado en los últimos 3 minutos."""
    f = data_dir / STATUS_FILE
    try:
        data = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    try:
        age = (datetime.now() - datetime.fromisoformat(data.get("actualizado", ""))).total_seconds()
    except ValueError:
        age = None
    data["reciente"] = age is not None and age < 180 and data.get("estado") != "detenido"
    return data


def run_service(network: bool = True, https: bool = True, port: int | None = None, host: str | None = None,
                policy: Policy | None = None) -> int:
    from .config import data_dir, get_settings
    from .webserver import LOCAL_PORT, _our_app_at
    s = get_settings()
    d = data_dir()
    _setup_logging(Path(s.log_dir))
    lock = SingleInstance(d / LOCK_FILE)
    if not lock.acquire():
        log.info("Ya hay un servicio vigilando esta instalación: no se abre otro.")
        return 0
    port = port or (s.network.port if network else LOCAL_PORT)
    scheme = "https" if network and https else "http"
    url = f"{scheme}://127.0.0.1:{port}"
    status = Status(d / STATUS_FILE, {"modo": "red" if network else "local", "puerto": port})
    pol = policy or Policy()
    sup = Supervisor(child_command(network, https, port, host),
                     lambda: _our_app_at(url, timeout=pol.probe_timeout), pol, status)

    def _on_signal(signum: int, _frame: Any) -> None:
        log.info("Señal %s recibida: deteniendo", signum)
        sup.stop()
    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        if hasattr(signal, name):
            try:
                signal.signal(getattr(signal, name), _on_signal)
            except (ValueError, OSError):
                pass
    try:
        return sup.run()
    finally:
        lock.release()


STATE_LABEL = {"funcionando": "funcionando", "iniciando": "abriendo la aplicación", "sin_respuesta": "la aplicación no responde",
               "reiniciando": "reabriendo la aplicación", "otra_instancia": "la aplicación está abierta desde otra ventana",
               "detenido": "detenido"}


def _fmt(iso: str | None) -> str:
    try:
        return datetime.fromisoformat(iso or "").strftime("%d/%m/%Y %H:%M:%S")
    except ValueError:
        return iso or "—"


def describe_status(data: dict[str, Any] | None) -> tuple[bool, list[str]]:
    """Texto para la consola (``sapsec estado-servicio``): (activo, líneas)."""
    if not data:
        return False, ["El servicio nunca se inició en esta instalación (scripts\\iniciar_con_windows.ps1 lo instala)."]
    active = bool(data.get("reciente"))
    lines = [f"Servicio: {STATE_LABEL.get(data.get('estado', ''), data.get('estado', ''))}"
             + (f" · vigila desde {_fmt(data.get('inicio'))}" if active else
                f" · sin novedades desde {_fmt(data.get('actualizado'))}: no está activo")]
    if active and data.get("pid_app"):
        lines.append(f"Aplicación: abierta desde {_fmt(data.get('app_desde'))} · modo {data.get('modo', '')} · "
                     f"puerto {data.get('puerto', '')}")
    last = data.get("ultimo_reinicio") or {}
    lines.append(f"Reinicios automáticos: {data.get('reinicios', 0)}"
                 + (f" (último: {_fmt(last.get('fecha'))}, {last.get('motivo', '')})" if last else ""))
    if data.get("ultima_respuesta"):
        lines.append(f"Última comprobación correcta: {_fmt(data.get('ultima_respuesta'))}")
    return active, lines

