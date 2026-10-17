"""Analysis modules consume only private snapshots; no sample is executed."""

import ipaddress
import re
import shutil
import threading
from pathlib import Path

from .process import Cancelled, run

ROWS = 20000
MODULES = {}


def module(name):
    def register(fn):
        MODULES[name] = fn
        return fn
    return register


def identify(path, cancel):
    with open(path, "rb") as stream:
        head = stream.read(8192)
    kind = "unknown"
    if head.startswith(b"\x7fELF"):
        kind = "ELF"
    elif head.startswith(b"MZ"):
        kind = "unknown (DOS/MZ)"
        with open(path, "rb") as stream:
            if len(head) >= 64:
                stream.seek(int.from_bytes(head[60:64], "little"))
                if stream.read(4) == b"PE\0\0":
                    kind = "PE"
    elif head[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
                       b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
        kind = "Mach-O"
    elif head.startswith(b"%PDF-"):
        kind = "PDF"
    elif head.startswith(b"{\\rtf"):
        kind = "document (RTF)"
    elif head.startswith(b"\xd0\xcf\x11\xe0"):
        kind = "document (OLE)"
    elif head.startswith(b"#!"):
        kind = "script"
    elif head.startswith((b"PK\x03\x04", b"\x1f\x8b", b"7z\xbc\xaf\x27\x1c", b"Rar!", b"BZh", b"\xfd7zXZ")) or head[257:262] == b"ustar":
        kind = "archive"
    detail = run([shutil.which("file"), "-b", "--", str(path)], cancel) if shutil.which("file") else {"status": "unavailable", "reason": "file yok"}
    description = detail.get("text", "")
    if kind == "Mach-O" and "Java" in description:
        kind = "unknown (Java class)"
    if head.startswith(b"PK\x03\x04"):
        try:
            import zipfile
            with zipfile.ZipFile(path) as archive:
                if any(item.filename.startswith(("word/", "xl/", "ppt/")) or item.filename == "mimetype" for item in archive.infolist()[:10000]):
                    kind = "document (ZIP candidate)"
        except (ValueError, OSError, zipfile.BadZipFile):
            pass
    if kind == "unknown" and "script" in description.lower():
        kind = "script"
    if kind == "archive" and any(x in description for x in ("Microsoft", "OpenDocument", "Office")):
        kind = "document (ZIP)"
    return {"format": kind, "description": detail}


@module("strings")
def strings(path, cancel):
    data = path.read_bytes()
    found = []
    # UTF-8 includes ASCII. UTF-16 handles printable ASCII and non-ASCII BMP text.
    for encoding, pattern in (("utf-8", rb"[\x20-\x7e\xc2-\xf4\x80-\xbf]{4,}"),
                              ("utf-16-le", rb"(?:[\x20-\x7e]\x00){4,}"),
                              ("utf-16-be", rb"(?:\x00[\x20-\x7e]){4,}")):
        for match in re.finditer(pattern, data):
            if cancel.is_set():
                raise Cancelled()
            try:
                text = match.group()[:4096].decode(encoding)
            except UnicodeDecodeError:
                continue
            found.append({"offset": match.start(), "encoding": encoding, "text": text})
            if len(found) >= ROWS:
                return {"rows": found, "truncated": True}
    return {"rows": found, "truncated": False}


@module("elf")
def elf(path, cancel):
    with path.open("rb") as header_stream:
        magic = header_stream.read(4)
    if magic != b"\x7fELF":
        return {"status": "unsupported", "reason": "Ayrıntılı yapısal analiz yalnızca ELF için."}
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection
        from elftools.elf.dynamic import DynamicSection
    except ImportError:
        if not shutil.which("readelf"):
            return {"status": "unavailable", "reason": "pyelftools ve readelf yok"}
        header = run([shutil.which("readelf"), "-h", "--", str(path)], cancel)
        if header["returncode"]:
            return {"status": "error", "reason": "ELF başlığı ayrıştırılamadı.", "header": header}
        fields = dict(line.strip().split(":", 1) for line in header["text"].splitlines() if ":" in line)
        raw = {}
        for label, option in (("sections", "-SW"), ("segments", "-lW"), ("symbols", "-sW"),
                              ("dependencies", "-dW"), ("build_notes", "-n")):
            raw[label] = run([shutil.which("readelf"), option, "--", str(path)], cancel)
        from .binary_views import readelf_tables
        return {**readelf_tables(raw), "backend": "readelf", "architecture": fields.get("Machine", "").strip(),
                "bits": fields.get("Class", "").strip(), "abi": fields.get("OS/ABI", "").strip(),
                "entry": fields.get("Entry point address", "").strip(), "header": header,
                "raw": raw, "scope": "Yapısal Python ayrıştırıcısı yok; gerçek readelf çıktıları sunulur. GNU tablo çıktıları yapılandırılmış görünüme dönüştürülür; ham çıktı da saklanır."}
    with path.open("rb") as stream:
        binary = ELFFile(stream)
        sections, symbols, dependencies = [], [], []
        for section in binary.iter_sections():
            if cancel.is_set():
                raise Cancelled()
            if len(sections) >= ROWS:
                raise ValueError("ELF bölüm sınırı aşıldı.")
            sections.append({"name": section.name, "address": hex(section["sh_addr"]),
                             "offset": section["sh_offset"], "size": section["sh_size"],
                             "flags": int(section["sh_flags"]),
                             "permissions": ("W" if section["sh_flags"] & 1 else "") + ("A" if section["sh_flags"] & 2 else "") + ("X" if section["sh_flags"] & 4 else "")})
            if isinstance(section, SymbolTableSection):
                for symbol in section.iter_symbols():
                    if len(symbols) >= ROWS:
                        break
                    symbols.append({"name": symbol.name, "address": hex(symbol["st_value"]),
                                    "size": symbol["st_size"], "type": symbol["st_info"]["type"],
                                    "binding": symbol["st_info"]["bind"],
                                    "direction": "import" if symbol["st_shndx"] == "SHN_UNDEF" else "defined/export candidate"})
            if isinstance(section, DynamicSection):
                for tag in section.iter_tags():
                    if tag.entry.d_tag == "DT_NEEDED":
                        dependencies.append(tag.needed)
                    if len(dependencies) >= ROWS:
                        break
        segments = []
        for seg in binary.iter_segments():
            if len(segments) >= ROWS:
                raise ValueError("ELF segment sınırı aşıldı.")
            segments.append({"type": seg["p_type"], "address": hex(seg["p_vaddr"]),
                             "offset": seg["p_offset"], "file_size": seg["p_filesz"],
                             "memory_size": seg["p_memsz"], "flags": seg["p_flags"],
                             "permissions": "".join(c for bit, c in ((4, "R"), (2, "W"), (1, "X")) if seg["p_flags"] & bit)})
        notes = run([shutil.which("readelf"), "-n", "--", str(path)], cancel) if shutil.which("readelf") else {"status": "unavailable", "reason": "readelf yok"}
        return {"architecture": binary["e_machine"], "bits": binary.elfclass,
                "abi": str(binary["e_ident"]["EI_OSABI"]), "entry": hex(binary["e_entry"]),
                "sections": sections, "segments": segments, "symbols": symbols,
                "symbol_limit": ROWS, "dependencies": dependencies, "build_notes": notes}


@module("disassembly")
def disassembly(path, cancel):
    try:
        import capstone as cs
        from elftools.elf.elffile import ELFFile
    except ImportError:
        if not shutil.which("objdump"):
            return {"status": "unavailable", "reason": "Capstone/pyelftools ve objdump yok"}
        with path.open("rb") as header:
            if header.read(4) != b"\x7fELF":
                return {"status": "unsupported", "reason": "Disassembly yalnızca ELF için destekleniyor."}
        output = run([shutil.which("objdump"), "-d", "-w", "-C", "--", str(path)], cancel, timeout=20)
        from .binary_views import objdump_rows
        if output["returncode"] and not output["limited"]:
            return {"status": "unavailable", "reason": "Yerel objdump bu dosya mimarisini desteklemiyor.", "raw": output}
        rows = objdump_rows(output["text"])
        return {"backend": "objdump", "rows": rows, "raw": output,
                "limits": "20000 komut, 2 MB araç çıktısı, 20 saniye. ObjDump mimari desteği yerel binutils kurulumuna bağlıdır."}
    if path.read_bytes()[:4] != b"\x7fELF":
        return {"status": "unsupported", "reason": "Bu sürümde ELF kod bölümleri destekleniyor."}
    with path.open("rb") as stream:
        binary = ELFFile(stream)
        endian = cs.CS_MODE_LITTLE_ENDIAN if binary.little_endian else cs.CS_MODE_BIG_ENDIAN
        modes = {"EM_X86_64": (cs.CS_ARCH_X86, cs.CS_MODE_64), "EM_386": (cs.CS_ARCH_X86, cs.CS_MODE_32),
                 "EM_ARM": (cs.CS_ARCH_ARM, cs.CS_MODE_ARM | endian), "EM_AARCH64": (cs.CS_ARCH_ARM64, endian)}
        if binary["e_machine"] not in modes:
            return {"status": "unsupported", "reason": "Mimari desteklenmiyor."}
        decoder = cs.Cs(*modes[binary["e_machine"]])
        rows = []
        for section in binary.iter_sections():
            if section["sh_flags"] & 4 and section["sh_type"] != "SHT_NOBITS":
                # Bound section reads as well as decoded instructions.
                stream.seek(section["sh_offset"])
                data = stream.read(min(section["sh_size"], 262144))
                for ins in decoder.disasm(data, section["sh_addr"], count=ROWS - len(rows)):
                    if cancel.is_set():
                        raise Cancelled()
                    rows.append({"address": hex(ins.address), "bytes": ins.bytes.hex(),
                                 "mnemonic": ins.mnemonic, "operands": ins.op_str, "section": section.name})
                if len(rows) >= ROWS:
                    break
        return {"rows": rows, "limits": "20000 komut; bölüm başına ilk 256 KiB; ARM modu (Thumb otomatik seçilmez)."}


def indicators(rows):
    results = []
    patterns = {"url": r"https?://[^\s<>\"']+", "domain": r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,24}\b",
                "path": r"(?:/[A-Za-z0-9_.-]+){2,}", "error": r"(?i)\b(?:error|failed|denied|exception)\b.{0,100}"}
    for row in rows:
        for kind, pattern in patterns.items():
            for match in re.finditer(pattern, row["text"]):
                results.append({"kind": kind, "evidence": match.group()[:512], "offset": row["offset"]})
        for match in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", row["text"]):
            try:
                ipaddress.ip_address(match.group())
                results.append({"kind": "ip", "evidence": match.group(), "offset": row["offset"]})
            except ValueError:
                pass
        if len(results) >= ROWS:
            return results[:ROWS]
    return results


@module("metrics")
def metrics(path, cancel):
    from collections import Counter
    import math
    histogram = Counter()
    blocks = []
    size = 0
    def entropy(counts, length):
        return round(-sum((n / length) * math.log2(n / length) for n in counts.values()), 4) if length else 0
    with path.open("rb") as stream:
        while data := stream.read(262144):
            if cancel.is_set():
                raise Cancelled()
            counts = Counter(data)
            blocks.append({"offset": size, "entropy": entropy(counts, len(data))})
            histogram.update(counts)
            size += len(data)
    return {"size": size, "entropy": entropy(histogram, size), "blocks": blocks,
            "histogram": [histogram.get(n, 0) for n in range(256)],
            "note": "Entropi 0–8 arasındadır; yüksek değer sıkıştırılmış veya şifreli veriyle de görülebilir, zararlılık hükmü değildir."}


def analyze(store, source, selected=None, cancel=None, progress=lambda *x: None):
    cancel = cancel or threading.Event()
    selected = list(selected if selected is not None else MODULES)
    if any(name not in MODULES for name in selected):
        raise ValueError("Bilinmeyen analiz modülü.")
    progress(0, "Karantina kopyası ve hash hesaplama")
    path, info = store.snapshot(source, cancel)
    result = {"file": info, "identification": identify(path, cancel), "modules": {},
              "scope": {"max_file_bytes": 67108864, "max_rows": ROWS,
                        "execution": "static only", "verdict": "Göstergeler zararlılık hükmü değildir."}}
    for index, name in enumerate(selected):
        if cancel.is_set():
            raise Cancelled("İş iptal edildi.")
        progress(int(100 * index / max(1, len(selected))), name)
        try:
            result["modules"][name] = {"status": "ok", **MODULES[name](path, cancel)}
        except Cancelled:
            raise
        except Exception:
            result["modules"][name] = {"status": "error", "reason": "Modül dosyayı ayrıştıramadı; bozuk veya desteklenmeyen girdi."}
    result["indicators"] = indicators(result["modules"].get("strings", {}).get("rows", []))
    segments = result["modules"].get("elf", {}).get("segments", [])
    result["observations"] = [{"kind": "writable_executable_segment", "evidence": seg,
                               "interpretation": "Yazılabilir ve çalıştırılabilir segment; tek başına zararlılık kanıtı değildir."}
                              for seg in segments if seg["flags"] & 3 == 3]
    store.save(result)
    progress(100, "Tamamlandı")
    return result


def hex_page(path, offset=0, length=4096):
    if offset < 0 or length > 65536 or length < 0:
        raise ValueError("Geçersiz hex aralığı.")
    with Path(path).open("rb") as stream:
        stream.seek(offset)
        data = stream.read(length)
    return "\n".join(f"{offset+i:08x}  {data[i:i+16].hex(' '):47}  " +
                     "".join(chr(c) if 32 <= c < 127 else "." for c in data[i:i+16])
                     for i in range(0, len(data), 16))
