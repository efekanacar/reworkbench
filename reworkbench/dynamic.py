"""Opt-in rootless Podman sandbox. No fallback to host execution."""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import threading
import uuid

from .process import run

# Trusted collector, not sample supplied code. strace records process lineage,
# filesystem operations, system calls, stdout and stderr inside bounded tmpfs.
COLLECTOR = r'''
import glob, os, resource, shutil, subprocess
resource.setrlimit(resource.RLIMIT_FSIZE, (4*1024*1024, 4*1024*1024))
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
shutil.copyfile('/input/sample', '/work/sample')
os.chmod('/work/sample', 0o500)
p = subprocess.run(['/usr/bin/strace', '-ff', '-tt', '-s', '256', '-o', '/work/trace', '/work/sample'], cwd='/work')
print('\nCOLLECTOR exit:', p.returncode, flush=True)
for name in sorted(glob.glob('/work/trace*'))[:64]:
    print('\nTRACE', os.path.basename(name), flush=True)
    with open(name, 'r', errors='replace') as f:
        print(f.read(262144), flush=True)
'''


class Sandbox:
    def __init__(self):
        self.runtime = shutil.which("podman")
        self.image = os.environ.get("REWB_SANDBOX_IMAGE", "")
        self.pending = {}

    def availability(self):
        if not self.runtime:
            return False, "Podman kurulu değil; dinamik analiz kapalı."
        if os.geteuid() == 0:
            return False, "Root kullanıcısında dinamik analiz kapalı; ayrıcalıksız oturum gerekli."
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", self.image):
            return False, "REWB_SANDBOX_IMAGE yerel, sabit sha256 image ID olmalı; otomatik imaj indirilmez."
        try:
            result = run([self.runtime, "--remote=false", "info", "--format", "json"], timeout=10)
            data = json.loads(result["text"])
            if not data["host"]["security"]["rootless"]:
                return False, "Rootless Podman gerekli."
            if data["host"].get("cgroupVersion") != "v2" or not {"cpu", "memory", "pids"}.issubset(set(data["host"].get("cgroupControllers", []))):
                return False, "CPU/bellek/PID limitleri için cgroup v2 ve yetkilendirilmiş controller'lar gerekli."
            version = run([self.runtime, "--remote=false", "version", "--format", "{{.Client.Version}}"], timeout=10)
            numbers = re.match(r"(\d+)\.(\d+)", version["text"])
            if not numbers or tuple(map(int, numbers.groups())) < (4, 6):
                return False, "Dinamik analiz Podman >=4.6 gerektirir; Ubuntu 22.04 varsayılan Podman sürümü yeterli olmayabilir."
            image = run([self.runtime, "--remote=false", "image", "inspect", self.image], timeout=10)
            if image["returncode"]:
                return False, "Sabit analiz imajı yerelde bulunamadı."
        except Exception:
            return False, "Podman ortamı doğrulanamadı."
        return True, "Rootless Podman hazır; dinamik analiz için ayrıca onay gerekli."

    def prepare(self, snapshot):
        ok, reason = self.availability()
        if not ok:
            raise ValueError(reason)
        path = Path(snapshot).resolve(strict=True)
        if not re.fullmatch(r"[0-9a-f]{64}", path.name):
            raise ValueError("Yalnızca hash isimli karantina girdisi kullanılabilir.")
        if hashlib.sha256(path.read_bytes()).hexdigest() != path.name:
            raise ValueError("Karantina bütünlüğü doğrulanamadı.")
        name = "rewb-" + uuid.uuid4().hex
        command = [self.runtime, "--remote=false", "run", "--name", name, "--rm", "--pull=never",
                   "--network=none", "--read-only", "--userns=keep-id:uid=65534,gid=65534", "--user=65534:65534",
                   "--cap-drop=all", "--security-opt=no-new-privileges",
                   "--pids-limit=64", "--cpus=1", "--memory=256m", "--memory-swap=256m",
                   "--ulimit=core=0:0", "--ulimit=fsize=4194304:4194304",
                   "--tmpfs=/work:rw,exec,nosuid,nodev,size=32m,mode=1777",
                   "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=8m,mode=1777",
                   "--mount", f"type=bind,src={path},dst=/input/sample,ro=true",
                   "--workdir=/work", "--env=HOME=/work", "--http-proxy=false",
                   "--log-driver=none", "--entrypoint=/usr/bin/python3",
                   self.image, "-I", "-c", COLLECTOR]
        ticket = uuid.uuid4().hex
        self.pending[ticket] = (name, command, path)
        return ticket, {"command": list(command), "timeout_seconds": 20,
                        "output_limit_bytes": 2_000_000, "network": "none",
                        "warning": "Container host çekirdeğini paylaşır; yüksek riskli örnekler için çevrimdışı VM kullanın."}

    def execute(self, ticket, cancel=None):
        if ticket not in self.pending:
            raise ValueError("Açık onay gerekli.")
        name, command, path = self.pending.pop(ticket)
        if hashlib.sha256(path.read_bytes()).hexdigest() != path.name:
            raise ValueError("Karantina girdisi değişti.")
        try:
            return run(command, cancel or threading.Event(), timeout=20, limit=2_000_000)
        finally:
            # Remove container even when client was cancelled or killed on timeout.
            cleanup = run([self.runtime, "--remote=false", "rm", "--force", "--ignore", "--time=1", name], timeout=10)
            if cleanup["returncode"] or cleanup["limited"]:
                raise ValueError("Konteyner temizliği doğrulanamadı; yerel Podman ile denetleyin: " + name)
