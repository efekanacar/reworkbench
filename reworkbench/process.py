"""Bounded, cancellable subprocess execution. Never invokes a shell."""

import os
import selectors
import signal
import subprocess
import threading
import time


class Cancelled(Exception):
    pass


def run(argv, cancel=None, timeout=20, limit=2_000_000):
    cancel = cancel or threading.Event()
    if cancel.is_set():
        raise Cancelled("İş iptal edildi.")
    proc = subprocess.Popen(
        argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        start_new_session=True,
        env={**{k: v for k, v in os.environ.items() if k in (
            "PATH", "HOME", "USER", "LOGNAME", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS",
            "LANG", "TERM", "TMPDIR")}, "LC_ALL": "C"},
    )
    output = bytearray()
    reason = None
    started = time.monotonic()
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ)
    try:
        while selector.get_map():
            if cancel.is_set():
                raise Cancelled("İş iptal edildi.")
            if time.monotonic() - started > timeout:
                reason = "Süre sınırı"
                break
            for key, _ in selector.select(0.05):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                room = limit - len(output)
                output.extend(chunk[:room])
                if len(chunk) > room:
                    reason = "Çıktı sınırı"
                    break
            if reason:
                break
    finally:
        selector.close()
        proc.poll()
        # Kill the entire process group, including children surviving their parent.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
        proc.stdout.close()
    return {"command": argv, "returncode": proc.returncode,
            "text": output.decode("utf-8", errors="replace"), "limited": reason}
