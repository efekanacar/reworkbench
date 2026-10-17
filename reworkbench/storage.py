"""Private immutable input snapshots and hash-linked analysis history."""

import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import uuid
from datetime import datetime, timezone

from .process import Cancelled

MAX_FILE = 64 * 1024 * 1024


class Store:
    def __init__(self, root=None):
        self.root = Path(root or Path.home() / ".local/share/reworkbench")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        for sub in ("quarantine", "reports"):
            (self.root / sub).mkdir(exist_ok=True, mode=0o700)

    def capacity(self):
        total, count = 0, 0
        for directory, _, files in os.walk(self.root, followlinks=False):
            for name in files:
                count += 1
                total += (Path(directory) / name).lstat().st_size
                if count > 5000 or total > 1024**3 - 128 * 1024**2:
                    raise ValueError("Yerel depo kapasite sınırı: geçmiş/karantinayı gözden geçirip yer açın.")
        if __import__("shutil").disk_usage(self.root).free < 128 * 1024**2:
            raise ValueError("Analiz için en az 128 MiB boş disk gerekli.")

    def snapshot(self, source, cancel):
        self.capacity()
        fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        hashes = {name: hashlib.new(name) for name in ("sha256", "sha1", "md5")}
        tmp = None
        try:
            with os.fdopen(fd, "rb") as src:
                info = os.fstat(src.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE:
                    raise ValueError("Normal bir dosya seçin; boyut sınırı 64 MiB.")
                with tempfile.NamedTemporaryFile(dir=self.root / "quarantine", delete=False) as out:
                    tmp = Path(out.name)
                    size = 0
                    while chunk := src.read(1024 * 1024):
                        if cancel.is_set():
                            raise Cancelled("İş iptal edildi.")
                        size += len(chunk)
                        if size > MAX_FILE:
                            raise ValueError("Dosya boyutu 64 MiB sınırını aştı.")
                        for h in hashes.values():
                            h.update(chunk)
                        out.write(chunk)
            values = {k: v.hexdigest() for k, v in hashes.items()}
            target = self.root / "quarantine" / values["sha256"]
            os.chmod(tmp, 0o400)
            os.replace(tmp, target)
            return target, {"name": Path(source).name, "size": size, "hashes": values}
        finally:
            if tmp and tmp.exists():
                tmp.unlink()

    def save(self, result):
        digest = result["file"]["hashes"]["sha256"]
        directory = self.root / "reports" / digest
        directory.mkdir(exist_ok=True, mode=0o700)
        self.capacity()
        result["run_id"] = uuid.uuid4().hex
        result["created_at"] = datetime.now(timezone.utc).isoformat()
        path = directory / (result["run_id"] + ".json")
        data = json.dumps(result, ensure_ascii=False, indent=2)
        if len(data.encode("utf-8")) > 24 * 1024**2:
            raise ValueError("Rapor boyutu 24 MiB sınırını aştı; daha az modül seçin.")
        temp = None
        try:
            with tempfile.NamedTemporaryFile(dir=directory, mode="w", encoding="utf-8", delete=False) as out:
                temp = Path(out.name)
                out.write(data)
            os.replace(temp, path)
        finally:
            if temp and temp.exists():
                temp.unlink()
        return path


def markdown(result):
    # All untrusted content stays in a fence longer than any fence in the input.
    body = json.dumps(result, ensure_ascii=False, indent=2)
    longest = max((len(x) for x in __import__("re").findall(r"`+", body)), default=0)
    fence = "`" * max(3, longest + 1)
    return "# RE Workbench analiz raporu\n\nVeriler güvenilmeyen girdidir.\n\n" + fence + "json\n" + body + "\n" + fence + "\n"
