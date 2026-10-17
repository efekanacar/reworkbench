"""Single-worker bounded queue with resource-limited analysis processes."""

import multiprocessing as mp
import queue
import resource
import threading
import time

from .engine import analyze
from .process import Cancelled
from .storage import Store


def worker(connection, root, source, modules, cancel):
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
        resource.setrlimit(resource.RLIMIT_AS, (1024**3, 1024**3))
        resource.setrlimit(resource.RLIMIT_FSIZE, (32 * 1024**2, 32 * 1024**2))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        result = analyze(Store(root), source, modules, cancel,
                         lambda n, text: connection.send(("progress", (n, text))))
        connection.send(("result", result))
    except Cancelled:
        connection.send(("cancelled", "Analiz iptal edildi."))
    except Exception:
        connection.send(("error", "Analiz tamamlanamadı. Dosya izinlerini, boyutunu ve kaynak sınırlarını kontrol edin."))
    finally:
        connection.close()


class Jobs:
    def __init__(self, root, publish):
        self.root, self.publish = str(root), publish
        self.queue = queue.Queue(maxsize=3)
        self.ctx = mp.get_context("spawn")
        self.cancel_event = None
        self.closed = False
        self._lock = threading.RLock()
        self._generation = 0
        threading.Thread(target=self._loop, daemon=True).start()

    def submit(self, source, modules):
        if self.closed:
            raise ValueError("İş kuyruğu kapalı.")
        try:
            with self._lock:
                self.queue.put_nowait((str(source), list(modules), self._generation))
        except queue.Full:
            raise ValueError("Kuyruk dolu; en fazla üç bekleyen analiz.") from None
        self.publish("queued", "Dosya analiz kuyruğuna eklendi.")

    def cancel(self):
        removed = False
        with self._lock:
            self._generation += 1
            if self.cancel_event:
                self.cancel_event.set()
            while True:
                try:
                    self.queue.get_nowait()
                    removed = True
                except queue.Empty:
                    break
            notify = removed and not self.cancel_event
        if notify:
            self.publish("cancelled", "Bekleyen analiz iptal edildi.")

    def _loop(self):
        while not self.closed:
            try:
                source, modules, generation = self.queue.get(timeout=0.1)
            except queue.Empty:
                continue
            with self._lock:
                stale = self.closed or generation != self._generation
                if not stale:
                    self.cancel_event = self.ctx.Event()
            if stale:
                self.publish("cancelled", "Bekleyen analiz iptal edildi.")
                continue
            recv, send = self.ctx.Pipe(duplex=False)
            proc = self.ctx.Process(target=worker, args=(send, self.root, source, modules, self.cancel_event))
            try:
                proc.start()
            except Exception:
                recv.close()
                send.close()
                with self._lock:
                    self.cancel_event = None
                self.publish("error", "Analiz süreci başlatılamadı; sistem kaynaklarını kontrol edin.")
                continue
            send.close()
            started, cancelled_at, terminal = time.monotonic(), None, False
            while proc.is_alive() or recv.poll():
                if recv.poll(0.05):
                    try:
                        kind, value = recv.recv()
                    except EOFError:
                        break
                    self.publish(kind, value)
                    terminal |= kind in ("result", "error", "cancelled")
                if self.cancel_event.is_set() and cancelled_at is None:
                    cancelled_at = time.monotonic()
                if (cancelled_at and time.monotonic() - cancelled_at > 2) or time.monotonic() - started > 90:
                    proc.kill()
                    break
            proc.join(timeout=2)
            recv.close()
            if not terminal:
                self.publish("error", "Analiz durduruldu: iptal veya kaynak/süre sınırı.")
            with self._lock:
                self.cancel_event = None

    def close(self):
        self.closed = True
        self.cancel()
