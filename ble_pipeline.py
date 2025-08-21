#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BLE End‑to‑End Pipeline (capture → convert → parse → filter → audit)
==================================================================

Questo *unico file* esegue l'intera catena per l'analisi della sicurezza BLE:

- Step 1 – Cattura: usa SnifferAPI (Nordic) per catturare traffico BLE in `.pcap`.
- Step 2 – Conversione: converte automaticamente in `.pcapng` tramite `editcap` (Wireshark).
- Step 3 – Parsing: usa PyShark per iterare i pacchetti e serializzare l'equivalente di `pkt.show()`
  in JSON con un parser robusto ai layout.
- Step 4 – Filtro: applica un filtro integrato per rimuovere advertising generici, scan response ed
  eventuali PDU vuote (mantiene i CONNECT_IND/REQ). Output: `*_Filt.json`.
- Step 5 – Audit (avanzato): esegue un *BLE Pairing & Security Audit* sui JSON filtrati e produce:
  • report Markdown (Mode 1 L1–L4, metodo/association model, SC/MITM, bonding, key size),
  • opzionalmente JSON/CSV riassuntivi, 
  • elenco ATT/GATT prima/dopo la cifratura con mappatura handle→UUID nota.

Requisiti
---------
- Python 3.8+
- Dipendenze: `pyshark`, `SnifferAPI` (Nordic), `editcap` (Wireshark, per pcap→pcapng)
- Hardware: sniffer Nordic nRF52840 Dongle (o compatibile con SnifferAPI)

Esempi d'uso
------------
1) Pipeline completa (cattura 60s, base "lab_test") + audit con report:
    python3 ble_pipeline.py --dur 60 --base lab_test --scan 5 --report lab_test_audit.md

2) Solo audit su JSON già filtrati (accetta più file) con export extra:
    python3 ble_pipeline.py --only-audit lab_Filt.json other_Filt.json \
        --report audit.md --json-out audit.json --csv-out audit.csv

3) Pipeline completa senza seguire un device specifico:
    python3 ble_pipeline.py --skip-follow

Note
----
- Se `editcap` non è disponibile, il tool prova ad usare direttamente il `.pcap` per PyShark.
- Il filtro integrato produce `*_Filt.json`, che è l'input preferito per l'audit.
- L'audit è progettato per essere *tollerante* a variazioni nei campi dei layer.

Autore / Corso
--------------
- Progetto tesi – Università degli Studi di Milano
- Corso: Sicurezza dei sistemi e delle reti informatiche
"""

# ==========================================
#                IMPORTS
# ==========================================
import argparse
import csv
import io
import json
import logging
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional, List, Tuple, Iterable, Union

# --- Sniffer / PCAP ---
try:
    from SnifferAPI import Sniffer, UART, Pcap
except Exception:  # pragma: no cover
    Sniffer = None  # type: ignore
    UART = None  # type: ignore
    Pcap = None  # type: ignore

# --- PyShark ---
try:
    import pyshark
    import contextlib
except Exception:  # pragma: no cover
    pyshark = None  # type: ignore
    contextlib = None  # type: ignore


# ==========================================
#         STEP 1: CATTURA PCAP
# ==========================================

def setup_sniffer():
    """Inizializza lo sniffer Nordic via SnifferAPI e avvia la scansione."""
    if UART is None or Sniffer is None:
        print("[!] SnifferAPI non disponibile. Installa i pacchetti Nordic.")
        sys.exit(1)
    ports = UART.find_sniffer()
    if not ports:
        print("Nessuno sniffer trovato.")
        sys.exit(1)
    sniffer = Sniffer.Sniffer(portnum=ports[0], baudrate=1000000)
    sniffer.start()
    sniffer.scan()
    print(f"[Sniffer] Avviato su {ports[0]} e in scansione...")
    return sniffer


def list_advertisers(sniffer, scan_time=3):
    """Durante 'scan_time' secondi lista i broadcaster/advertiser visti dallo sniffer."""
    print("\n[Scan] Cerco dispositivi BLE in advertising...\n")
    seen = {}
    start = time.time()
    while time.time() - start < scan_time:
        devlist = sniffer.getDevices()
        for dev in devlist.devices:
            addr_str = ':'.join(format(x, '02X') for x in dev.address)
            if addr_str not in seen:
                seen[addr_str] = dev
                print(f"- {dev.name} @ {addr_str} RSSI: {dev.RSSI}")
        time.sleep(1)
    print("\n[Scan] Completata.\n")
    return list(seen.values())


def select_device(devices):
    """Prompt CLI per scegliere un dispositivo da seguire (follow)."""
    print("Seleziona un dispositivo da seguire:")
    for i, dev in enumerate(devices):
        addr_str = ':'.join(format(x, '02X') for x in dev.address)
        print(f"[{i}] {dev.name} @ {addr_str} RSSI: {dev.RSSI}")
    while True:
        choice = input("Inserisci il numero: ")
        try:
            idx = int(choice)
            if 0 <= idx < len(devices):
                return devices[idx]
        except ValueError:
            pass
        print("Selezione non valida. Riprova.")


def run_capture(sniffer, duration_sec: int, pcap_path: Path):
    """Cattura i pacchetti BLE e scrive un file .pcap con header Pcap della SnifferAPI."""
    if Pcap is None:
        print("[!] Pcap helper non disponibile (SnifferAPI).")
        sys.exit(1)
    pcap_path = Path(pcap_path)
    with open(pcap_path, 'wb') as pcap_file:
        pcap_file.write(Pcap.get_global_header())
        print(f"[*] Cattura BLE per {duration_sec}s -> {pcap_path}")
        start_time = time.time()
        try:
            while time.time() - start_time < duration_sec:
                packets = sniffer.getPackets()
                for pkt in packets:
                    pcap_data = Pcap.create_packet(bytes([pkt.boardId] + pkt.getList()), pkt.time)
                    pcap_file.write(pcap_data)
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\n[!] Interrotto dall'utente.")
    print("[*] Cattura terminata.")

# ==========================================
# STEP 2: PCAP  --> PCAPNG CONVERSIONE
# ==========================================
def convert_to_pcapng(src_pcap: Path, dst_pcapng: Path) -> bool:
    """Converte .pcap in .pcapng con editcap (se presente)."""
    try:
        subprocess.run(["editcap", "-F", "pcapng", str(src_pcap), str(dst_pcapng)], check=True)
        print(f"[+] Convertito in PCAPNG: {dst_pcapng}")
        return True
    except FileNotFoundError:
        print("[!] 'editcap' non trovato: salto conversione.")
        return False
    except subprocess.CalledProcessError as e:
        print(f"[!] Errore conversione PCAP->PCAPNG: {e}")
        return False

# =========================
#   STEP 2.5: INTEGRAZIONE CRACKLE
# =========================
def _run_cmd_capture_stdout(args: list) -> Tuple[int, str, str]:
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = p.communicate()
    return p.returncode, out, err

CRACKLE_BIN = os.environ.get("CRACKLE_BIN", "crackle")

def run_crackle(input_pcap: Path, out_pcap: Path, ltk_hex: Optional[str] = None) -> Dict[str, Any]:
    """
    Esegue crackle in:
      - modalità 'Crack TK' se ltk_hex è None
      - modalità 'Decrypt with LTK' se ltk_hex è fornito (stringa es. '81b0...').
    Ritorna un dizionario con: {'ok': bool, 'ltk': str|None, 'tk': str|None, 'stdout': str, 'stderr': str}
    """
    args = [CRACKLE_BIN, "-i", str(input_pcap), "-o", str(out_pcap)]
    if ltk_hex:
        args += ["-l", ltk_hex]

    code, out, err = _run_cmd_capture_stdout(args)

    # Estrarre TK/LTK dall'output
    tk = None
    ltk = None
    for line in out.splitlines():
        m = re.search(r"TK found:\s*(\d+)", line)
        if m: tk = m.group(1)
        m = re.search(r"LTK found:\s*([0-9a-fA-F]{32})", line)
        if m: ltk = m.group(1)

    ok = (code == 0) and out_pcap.exists() and out_pcap.stat().st_size > 0
    return {"ok": ok, "ltk": ltk, "tk": tk, "stdout": out, "stderr": err}


# ==========================================
#  STEP 3: PARSING show() → JSON (robusto)
# ==========================================
INDENT_SPACES = 2
BOOL_MAP = {"true": True, "false": False}
NONE_SET = {"none", "null", ""}

def coerce_scalar(s: str):
    """Converte stringhe in bool/int/float/null quando riconoscibili."""
    t = s.strip()
    if not t:
        return ""
    low = t.lower()
    if low in BOOL_MAP:
        return BOOL_MAP[low]
    if low in NONE_SET:
        return None
    try:
        if re.fullmatch(r"[+-]?\d+", t):
            return int(t)
    except Exception:
        pass
    try:
        if re.fullmatch(r"[+-]?\d+\.\d+", t):
            return float(t)
    except Exception:
        pass
    return t

def indent_level(line: str) -> int:
    """Stima livello d’indentazione di una riga di show()."""
    count = 0
    for ch in line:
        if ch == "\t":
            count += 1
        elif ch == " ":
            count += 0.25
        else:
            break
    return int(count)

def normalize_layer_header(line: str) -> Optional[str]:
    """Riconosce intestazioni tipo 'Layer XYZ:'."""
    m = re.match(r"\s*Layer\s+(.+?)(?::\s*)?$", line.strip())
    if m:
        return m.group(1).strip()
    return None

def parse_show_text(raw_text: str) -> dict:
    """Parser generico del testo prodotto da pkt.show()."""
    root: dict = {}
    current_layer_dict: Optional[dict] = None
    stack: List[Tuple[int, dict]] = []
    lines = [ln for ln in raw_text.splitlines() if ln.strip() != ":"]

    for raw_line in lines:
        maybe_layer = normalize_layer_header(raw_line)
        if maybe_layer is not None:
            layer_key = f"Layer {maybe_layer}"
            current_layer_dict = {}
            root[layer_key] = current_layer_dict
            stack = [(0, current_layer_dict)]
            continue

        if current_layer_dict is None:
            if not stack:
                stack = [(0, root)]

        lvl = indent_level(raw_line)
        tmp = raw_line.lstrip("\t ")
        if tmp.startswith(":"):
            tmp = tmp.lstrip(":").lstrip()
        line = tmp.rstrip()
        if not line:
            continue

        if ":" in line:
            key, val = line.split(":", 1)
            key = key.strip()
            val = val.strip()
        else:
            key, val = line.strip(), ""

        while stack and stack[-1][0] > lvl:
            stack.pop()
        if not stack:
            base = current_layer_dict if current_layer_dict is not None else root
            stack = [(0, base)]

        parent = stack[-1][1]

        if val == "":
            node = parent.get(key)
            if not isinstance(node, dict):
                node = {}
                parent[key] = node
            stack.append((lvl + 1, node))
        else:
            parent[key] = coerce_scalar(val)

    return root

def pcap_to_json(pcapng_path: Path, out_json_path: Path):
    """Itera i pacchetti con PyShark, cattura show() e serializza un JSON per pacchetto."""
    if pyshark is None:
        print("[!] PyShark non disponibile. Installa il pacchetto 'pyshark'.")
        sys.exit(1)
    packets: List[Dict[str, Any]] = []
    with pyshark.FileCapture(str(pcapng_path), use_ek=True) as cap:
        for i, pkt in enumerate(cap, start=1):
            buf = io.StringIO()
            import contextlib as _ctx  # alias sicuro
            with _ctx.redirect_stdout(buf):
                pkt.show()
            raw_text = buf.getvalue().rstrip("\n")
            parsed_layers = parse_show_text(raw_text)
            packet_dict: Dict[str, Any] = {"packet_number": i}
            packet_dict.update(parsed_layers)
            packets.append(packet_dict)

    with open(out_json_path, "w", encoding="utf-8") as f:
        json.dump(packets, f, ensure_ascii=False, indent=INDENT_SPACES)
    print(f"[+] Salvati {len(packets)} pacchetti in JSON: {out_json_path}")


# ==========================================
#        STEP 4: FILTRO INTEGRATO
# ==========================================
FILTER_INDENT_SPACES = 2
EXCLUDE_REGEX: List[str] = [
    # Esempi opzionali per escludere ulteriormente:
    # r'(?i)"channel"\s*:\s*39',
    # r'(?i)"addr"\s*:\s*"c0:48:ff:f5:9d:b8"'
]
_EXCLUDE_COMPILED = [re.compile(p) for p in EXCLUDE_REGEX]

# ---- Utility comuni al filtro ----
def _norm(s: Any) -> str:
    return re.sub(r"[\s_\-]+", " ", str(s)).strip().lower()

def _iter_keyvals(obj: Any) -> Iterable[Tuple[str, Any]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k, v
            yield from _iter_keyvals(v)
    elif isinstance(obj, list):
        for x in obj:
            yield from _iter_keyvals(x)

def _iter_subdicts_by_key(obj: Any, key_regex: re.Pattern) -> Iterable[Dict[str, Any]]:
    for k, v in _iter_keyvals(obj):
        if isinstance(v, dict) and key_regex.fullmatch(_norm(k)):
            yield v

def _deep_has_key(obj: Any, key_regex: re.Pattern) -> bool:
    for k, _ in _iter_keyvals(obj):
        if key_regex.fullmatch(_norm(k)):
            return True
    return False

def _deep_find_first(obj: Any, key_regex: re.Pattern) -> Any:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if key_regex.fullmatch(_norm(k)):
                return v
        for v in obj.values():
            found = _deep_find_first(v, key_regex)
            if found is not None:
                return found
    elif isinstance(obj, list):
        for x in obj:
            found = _deep_find_first(x, key_regex)
            if found is not None:
                return found
    return None

def _to_int(val: Any) -> Optional[int]:
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        s = val.strip()
        if re.fullmatch(r"[+-]?\d+", s):
            try:
                return int(s)
            except Exception:
                return None
    return None

# ---- Riconoscimento nel Layer BTLE ----
def _find_btle_layer(packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    for k, v in packet.items():
        if isinstance(v, dict):
            nk = _norm(k)
            if "layer" in nk and "btle" in nk:
                return v
    return None

def _adv_pdu_types(btle: Dict[str, Any]) -> List[Optional[int]]:
    types: List[Optional[int]] = []
    for adv in _iter_subdicts_by_key(btle, re.compile(r"advertising")):
        pdu = _deep_find_first(adv, re.compile(r"pdu"))
        if isinstance(pdu, dict):
            t = _deep_find_first(pdu, re.compile(r"type"))
            ti = _to_int(t)
            if ti is not None:
                types.append(ti); continue
            if isinstance(t, str):
                s = _norm(t)
                if "connect" in s and ("ind" in s or "req" in s):
                    types.append(5)
                elif "scan" in s and ("rsp" in s or "response" in s or "responce" in s):
                    types.append(4)
                else:
                    types.append(None)
            else:
                types.append(None)
        else:
            types.append(None)
    return types

def _is_advertising_anywhere(btle: Dict[str, Any]) -> bool:
    return any(True for _ in _iter_subdicts_by_key(btle, re.compile(r"advertising")))

def _is_scan_response(btle: Dict[str, Any]) -> bool:
    if 4 in [t for t in _adv_pdu_types(btle) if t is not None]:
        return True
    for scan in _iter_subdicts_by_key(btle, re.compile(r"scan")):
        if _deep_has_key(scan, re.compile(r"respon[sc]e")):
            return True
    return False

def _is_connect_ind(btle: Dict[str, Any]) -> bool:
    return 5 in [t for t in _adv_pdu_types(btle) if t is not None]

def _has_zero_length_outside_advertising(obj: Any, in_adv: bool = False) -> bool:
    if isinstance(obj, dict):
        for k, v in obj.items():
            nk = _norm(k)
            next_in_adv = in_adv or (nk == "advertising")
            if nk == "length" and _to_int(v) == 0 and not next_in_adv:
                return True
            if _has_zero_length_outside_advertising(v, next_in_adv):
                return True
    elif isinstance(obj, list):
        for x in obj:
            if _has_zero_length_outside_advertising(x, in_adv):
                return True
    return False

def _is_empty_pdu(btle: Dict[str, Any]) -> bool:
    if _to_int(btle.get("length")) == 0:
        return True
    return _has_zero_length_outside_advertising(btle)

def should_exclude_packet(packet: Dict[str, Any]) -> Tuple[bool, Optional[str], bool]:
    """
    Regole di esclusione:
      - scan response
      - PDU con length==0 (fuori da advertising)
      - advertising generici (MA NON i CONNECT_IND/REQ)
    Restituisce (exclude, reason, connect_kept)
    """
    btle = _find_btle_layer(packet)
    is_connect = False

    if isinstance(btle, dict):
        if _is_scan_response(btle):
            return True, "scan_response", False
        if _is_empty_pdu(btle):
            return True, "empty_pdu", False
        is_connect = _is_connect_ind(btle)
        if _is_advertising_anywhere(btle) and not is_connect:
            return True, "advertising", False

    if _EXCLUDE_COMPILED:
        blob = json.dumps(packet, ensure_ascii=False)
        if any(p.search(blob) for p in _EXCLUDE_COMPILED):
            return True, "regex", False

    return False, None, bool(is_connect)

def _extract_packet_list(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("packets"), list):
        return data["packets"]
    raise ValueError("Formato JSON non riconosciuto: attesa una lista o un oggetto con chiave 'packets'.")

def apply_filter_to_json(in_path: Path) -> Path:
    """Applica il filtro integrato e salva <stem>_Filt.json."""
    out_path = in_path.with_name(in_path.stem + "_Filt.json")

    with open(in_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    packets = _extract_packet_list(data)

    stats = {
        "total_in": len(packets),
        "kept": 0,
        "excluded": 0,
        "reasons": {"advertising": 0, "scan_response": 0, "empty_pdu": 0, "regex": 0},
        "connect_ind_kept": 0,
    }

    out_packets: List[Dict[str, Any]] = []
    for pkt in packets:
        exclude, reason, connect_kept = should_exclude_packet(pkt)
        if exclude:
            stats["excluded"] += 1
            if reason in stats["reasons"]:
                stats["reasons"][reason] += 1
            continue
        if connect_kept:
            stats["connect_ind_kept"] += 1
        out_packets.append(pkt)

    stats["kept"] = len(out_packets)

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out_packets, f, ensure_ascii=False, indent=FILTER_INDENT_SPACES)

    print(f"[OK] Input: {in_path}")
    print(f"[OK] Output: {out_path}")
    print(f"[OK] Pacchetti in input:  {stats['total_in']}")
    print(f"[OK] Pacchetti tenuti:    {stats['kept']}")
    print(f"[OK] Pacchetti esclusi:   {stats['excluded']}")
    for k, v in stats["reasons"].items():
        print(f"      - esclusi per {k}: {v}")
    print(f"[OK] CONNECT_IND/REQ tenuti: {stats['connect_ind_kept']}")

    return out_path


# ==========================================
#   STEP 5: AUDIT SICUREZZA (avanzato)
#   (integra il tuo "BLE Pairing Auditor – sez. 4.2")
# ==========================================

# ---- Costanti / mappe usate nell’audit ----
LL_CTRL_NAMES = {
    0x03: "LL_ENC_REQ",
    0x04: "LL_ENC_RSP",
    0x05: "LL_START_ENC_REQ",
    0x06: "LL_START_ENC_RSP",
    0x07: "LL_PAUSE_ENC_REQ",
    0x08: "LL_PAUSE_ENC_RSP",
    0x0C: "LL_VERSION_IND",
}
LL_FEATURE_NAMES = {0x08: "LL_FEATURE_REQ", 0x09: "LL_FEATURE_RSP"}

SMP_NAMES = {
    0x01: "PAIRING_REQ",
    0x02: "PAIRING_RSP",
    0x03: "PAIRING_CONFIRM",
    0x04: "PAIRING_RANDOM",
    0x05: "PAIRING_FAILED",
    0x06: "ENCRYPTION_INFORMATION",     # LTK (legacy)
    0x07: "MASTER_IDENTIFICATION",      # EDIV/Rand (legacy)
    0x08: "IDENTITY_INFORMATION",       # IRK
    0x09: "IDENTITY_ADDRESS_INFORMATION",
    0x0A: "SIGNING_INFORMATION",        # CSRK
    0x0B: "SECURITY_REQUEST",
    0x0C: "PAIRING_PUBLIC_KEY",         # LESC
    0x0D: "PAIRING_DHKEY_CHECK",        # LESC
    0x0E: "KEYPRESS_NOTIFICATION",
}

AUTHREQ_BIT_BONDING_FLAG0 = 0x01
AUTHREQ_BIT_BONDING_FLAG1 = 0x02
AUTHREQ_BIT_MITM        = 0x04
AUTHREQ_BIT_SC          = 0x08
AUTHREQ_BIT_KEYPRESS    = 0x10

IO_CAP_NAMES = {
    0x00: "DisplayOnly",
    0x01: "DisplayYesNo",
    0x02: "KeyboardOnly",
    0x03: "NoInputNoOutput",
    0x04: "KeyboardDisplay",
}

ATT_OPS = {
    0x01: "Error Response",
    0x02: "Exchange MTU Request",
    0x03: "Exchange MTU Response",
    0x04: "Find Information Request",
    0x05: "Find Information Response",
    0x06: "Find By Type Value Request",
    0x07: "Find By Type Value Response",
    0x08: "Read By Type Request",
    0x09: "Read By Type Response",
    0x0A: "Read Request",
    0x0B: "Read Response",
    0x0C: "Read Blob Request",
    0x0D: "Read Blob Response",
    0x0E: "Read Multiple Request",
    0x0F: "Read Multiple Response",
    0x10: "Read By Group Type Request",
    0x11: "Read By Group Type Response",
    0x12: "Write Request",
    0x13: "Write Response",
    0x16: "Prepare Write Request",
    0x17: "Execute Write Request",
    0x1B: "Handle Value Notification",
    0x1D: "Handle Value Indication",
    0x1E: "Handle Value Confirmation",
}

GATT_UUID16_NAMES = {
    0x2800: "Primary Service",
    0x2801: "Secondary Service",
    0x2803: "Characteristic Declaration",
    0x2901: "Characteristic User Description",
    0x2902: "Client Characteristic Configuration (CCCD)",
    0x2904: "Characteristic Presentation Format",
}

SECURITY_LEVEL_EXPLANATION = {
    1: "Nessuna cifratura, nessuna autenticazione (Mode 1 Level 1).",
    2: "Cifratura senza autenticazione (es. Just Works) (Mode 1 Level 2).",
    3: "Cifratura con autenticazione MITM (es. Passkey/OOB legacy) (Mode 1 Level 3).",
    4: "LE Secure Connections con autenticazione (NC/Passkey/OOB) (Mode 1 Level 4).",
}

# ---- Utility comuni per l’audit ----
def _safe_get(d: Dict, path: List[str], default=None):
    cur = d
    for p in path:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return default
    return cur

def _is_true(x: Any) -> bool:
    return str(x).lower() in ("1", "true", "yes")

def _hex_to_int_byte(hex_byte: str) -> int:
    return int(hex_byte, 16)

def _as_int(v: Any) -> Optional[int]:
    try:
        if isinstance(v, bool):
            return int(v)
        if isinstance(v, int):
            return v
        s = str(v).strip()
        if s.lower().startswith("0x"):
            return int(s, 16)
        return int(s)
    except Exception:
        return None

def _as_bool(v: Any) -> Optional[bool]:
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in ("true", "yes", "1"):
        return True
    if s in ("false", "no", "0"):
        return False
    return None

def _iter_kv(obj: Any, path: List[str] = None):
    if path is None:
        path = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            nk = str(k).strip().lower()
            cur = path + [nk]
            yield cur, nk, v
            yield from _iter_kv(v, cur)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            cur = path + [f"[{i}]"]
            yield cur, f"[{i}]", v
            yield from _iter_kv(v, cur)

def find_layers_by_name(pkt: Dict[str, Any], candidates: Iterable[str]) -> List[Dict[str, Any]]:
    wanted = [s.strip().lower() for s in candidates]
    found: List[Dict[str, Any]] = []
    for path, _, val in _iter_kv(pkt):
        if not isinstance(val, dict):
            continue
        last = path[-1]
        if any(w in last for w in wanted):
            found.append(val)
    return found

def _first_int_by_suffix(d: Dict[str, Any], suffixes: Iterable[str]) -> Optional[int]:
    sufs = [s.strip().lower() for s in suffixes]
    for p, _, v in _iter_kv(d):
        if isinstance(v, (dict, list)):
            continue
        leaf = ".".join(p).replace("_", ".")
        if any(leaf.endswith(s) for s in sufs):
            iv = _as_int(v)
            if iv is not None:
                return iv
    return None

def _first_bool_by_path_contains(d: Dict[str, Any], parts: Iterable[str]) -> Optional[bool]:
    parts = [x.strip().lower() for x in parts]
    for p, _, v in _iter_kv(d):
        if isinstance(v, (dict, list)):
            continue
        joined = ".".join(p)
        if all(pt in joined for pt in parts):
            bv = _as_bool(v)
            if bv is not None:
                return bv
    return None

def _first_hexstr_by_suffix(d: Dict[str, Any], suffixes: Iterable[str]) -> Optional[str]:
    sufs = [s.strip().lower() for s in suffixes]
    for p, _, v in _iter_kv(d):
        if isinstance(v, (dict, list)):
            continue
        leaf = ".".join(p).replace("_", ".")
        if any(leaf.endswith(s) for s in sufs):
            s = str(v).strip()
            if s.lower().startswith("0x"):
                s = s[2:]
            return s
    return None

def _parse_uuid16(hexstr: Optional[str]) -> Optional[int]:
    if not hexstr:
        return None
    try:
        if "-" in hexstr and hexstr.endswith("00805f9b34fb"):
            part = hexstr.split("-")[0]
            return int(part[-4:], 16)
        return int(hexstr, 16)
    except Exception:
        return None

# ---- Parser di campo/indicatori ----
def detect_ll_encryption_signals(pkt: Dict) -> Optional[str]:
    opcode = _safe_get(pkt, ["Layer BTLE", "data", "control", "opcode"])
    if opcode is None:
        return None
    try:
        op = int(opcode)
    except Exception:
        try:
            op = int(str(opcode), 0)
        except Exception:
            return None
    return LL_CTRL_NAMES.get(op) or LL_FEATURE_NAMES.get(op)

def is_packet_encrypted(pkt: Dict) -> Optional[bool]:
    """
    Determina se un pacchetto BLE è cifrato.
    True  -> pacchetto cifrato
    False -> pacchetto in chiaro
    None  -> informazione non disponibile
    """
    enc = _safe_get(pkt, ["Layer NORDIC_BLE", "encrypted"])
    if enc is None:
        enc = _safe_get(pkt, ["Layer NORDIC_BLE", "event", "encrypted"])
    if enc is not None:
        return bool(enc)

    mic_not_relevant = _safe_get(pkt, ["Layer NORDIC_BLE", "mic", "not", "relevant"])
    if mic_not_relevant is None:
        mic_not_relevant = _safe_get(pkt, ["Layer NORDIC_BLE", "event", "mic", "not", "relevant"])
    if mic_not_relevant is not None:
        try:
            return not bool(int(mic_not_relevant))
        except Exception:
            return None
    return None

def extract_addresses(pkt: Dict) -> List[Tuple[str, str]]:
    out = []
    ini = _safe_get(pkt, ["Layer BTLE", "access", "initiator", "address"]) or _safe_get(pkt, ["Layer BTLE", "initiator", "address"])
    if ini: out.append(("initiator", ini))
    adv = _safe_get(pkt, ["Layer BTLE", "access", "advertising", "address"]) or _safe_get(pkt, ["Layer BTLE", "advertising", "address"])
    if adv: out.append(("advertiser", adv))
    m = _safe_get(pkt, ["Layer BTLE", "data", "master", "bd", "addr"])
    if m: out.append(("master", m))
    s = _safe_get(pkt, ["Layer BTLE", "data", "slave", "bd", "addr"])
    if s: out.append(("slave", s))
    return out

def classify_ble_address_type(addr: str, randomized_flags: Optional[Dict[str, Any]] = None) -> str:
    try:
        first = addr.split(":")[0]
        b0 = _hex_to_int_byte(first)
        msb2 = (b0 >> 6) & 0b11
    except Exception:
        msb2 = None

    is_random = None
    if isinstance(randomized_flags, dict):
        tx = randomized_flags.get("tx")
        rx = randomized_flags.get("rx")
        is_random = _is_true(tx) or _is_true(rx)

    if msb2 is None:
        return "unknown"
    if msb2 == 0b11:
        return "static_random"
    elif msb2 == 0b01:
        return "private_resolvable"
    elif msb2 == 0b00:
        return "private_non_resolvable" if is_random else "public_or_non_resolvable"
    else:
        return "unknown"

def _render_att_pretty(layer: Dict[str, Any]) -> Tuple[Optional[int], Optional[str]]:
    op = _first_int_by_suffix(layer, ["opcode", "op", "code", "att.opcode"])
    if op is None:
        return None, None

    base = ATT_OPS.get(op, f"ATT 0x{op:02X}")

    handle = _first_int_by_suffix(layer, ["handle", "attr.handle", "attribute.handle", "att.handle", "gatt.handle"])
    mtu = _first_int_by_suffix(layer, ["mtu", "exchange.mtu", "client.rx.mtu", "server.rx.mtu"])
    uuid_hex = _first_hexstr_by_suffix(layer, ["uuid", "type.uuid", "attribute.uuid", "group.type", "att.type"])
    uuid16 = _parse_uuid16(uuid_hex)
    uuid_name = GATT_UUID16_NAMES.get(uuid16)

    extra = []
    if op in (0x02, 0x03) and mtu is not None:
        extra.append(f"MTU={mtu}")
    if handle is not None and op not in (0x02, 0x03):
        extra.append(f"handle 0x{handle:04X}")
    if uuid16 is not None:
        tag = f"UUID 0x{uuid16:04X}"
        if uuid_name:
            tag += f" ({uuid_name})"
        extra.append(tag)

    if op == 0x12:  # Write Request: prova a capire CCCD enable/disable
        val_hex = _first_hexstr_by_suffix(layer, ["value", "write.value", "att.value", "payload"])
        if val_hex:
            try:
                v = int(val_hex[0:4], 16)  # primi 2 byte LE
                if uuid16 == 0x2902:
                    if v == 0x0001:
                        extra.append("CCCD: Notifications ENABLE")
                    elif v == 0x0002:
                        extra.append("CCCD: Indications ENABLE")
                    elif v == 0x0000:
                        extra.append("CCCD: Notifications/Indications DISABLE")
            except Exception:
                pass

    label = base
    if extra:
        label += " (" + ", ".join(extra) + ")"
    return op, label

def detect_att(pkt: Dict, handle_uuid_map: Dict[int, int]) -> Optional[Tuple[int, str]]:
    att_layers = find_layers_by_name(pkt, candidates=("btatt", "att", "attribute"))
    if not att_layers:
        att = _safe_get(pkt, ["Layer BTLE", "att"]) or _safe_get(pkt, ["Layer BTATT"]) or _safe_get(pkt, ["ATT"])
        if isinstance(att, dict):
            att_layers = [att]

    for layer in att_layers:
        if not isinstance(layer, dict):
            continue

        op, label = _render_att_pretty(layer)
        if op is None:
            continue

        h = _first_int_by_suffix(layer, ["handle", "attr.handle", "attribute.handle", "att.handle", "gatt.handle"])
        uuid_hex = _first_hexstr_by_suffix(layer, ["uuid", "type.uuid", "attribute.uuid", "group.type", "att.type"])
        uuid16 = _parse_uuid16(uuid_hex)
        if h is not None and uuid16 is not None:
            handle_uuid_map[h] = uuid16

        if h is not None and (uuid16 is None) and (h in handle_uuid_map):
            known_uuid16 = handle_uuid_map[h]
            known_name = GATT_UUID16_NAMES.get(known_uuid16)
            extra = f"handle 0x{h:04X} → UUID 0x{known_uuid16:04X}"
            if known_name:
                extra += f" ({known_name})"
            if "(" in label:
                label = label[:-1] + ", " + extra + ")"
            else:
                label += " (" + extra + ")"

        return op, label

    return None

# ---- Inferenza pairing da REQ/RSP ----
def _pairing_method_from_both(
    io_i: Optional[int], io_r: Optional[int],
    oob_i: bool, oob_r: bool,
    mitm_i: bool, mitm_r: bool,
    sc_i: bool, sc_r: bool
) -> str:
    def can_yes_no(x):   return x in (0x01, 0x04)        # DisplayYesNo / KeyboardDisplay
    def has_keyboard(x): return x in (0x02, 0x04)        # KeyboardOnly / KeyboardDisplay
    def has_display(x):  return x in (0x00, 0x01, 0x04)  # Qualsiasi display
    def any_noio(x, y):  return x == 0x03 or y == 0x03   # NoInputNoOutput

    sc = bool(sc_i and sc_r)

    if oob_i and oob_r:
        return "Out of Band (LESC)" if sc else "Out of Band (Legacy)"

    mitm = bool(mitm_i or mitm_r)
    if not mitm:
        return "Just Works (LESC)" if sc else "Just Works (Legacy)"

    if sc:
        if any_noio(io_i, io_r):                     return "Just Works (LESC)"
        if can_yes_no(io_i) and can_yes_no(io_r):    return "Numeric Comparison (LESC)"
        if (has_keyboard(io_i) and has_display(io_r)) or (has_keyboard(io_r) and has_display(io_i)):
                                                     return "Passkey Entry (LESC)"
        return "Just Works (LESC)"
    else:
        if any_noio(io_i, io_r):                     return "Just Works (Legacy)"
        if (has_keyboard(io_i) and has_display(io_r)) or (has_keyboard(io_r) and has_display(io_i)):
                                                     return "Passkey Entry (Legacy)"
        return "Just Works (Legacy)"

def _association_model_from_method(method: str) -> str:
    if "Numeric Comparison" in method: return "Numeric Comparison"
    if "Passkey" in method:           return "Passkey Entry"
    if "Out of Band" in method:       return "Out of Band (OOB)"
    return "Just Works"

def decide_security_level(encryption_active: bool, seen_lesc: bool, authenticated: bool) -> Tuple[int, str]:
    if not encryption_active:
        return 1, SECURITY_LEVEL_EXPLANATION[1]
    if seen_lesc and authenticated:
        return 4, SECURITY_LEVEL_EXPLANATION[4]
    if authenticated:
        return 3, SECURITY_LEVEL_EXPLANATION[3]
    return 2, SECURITY_LEVEL_EXPLANATION[2]

# ---- Caricamento file (JSON array o NDJSON) ----
def _load_packets(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        text = f.read().strip()
    if not text:
        return []
    if text[0] == "[":
        return json.loads(text)
    # NDJSON
    pkts = []
    for line in text.splitlines():
        line=line.strip()
        if not line:
            continue
        try:
            pkts.append(json.loads(line))
        except Exception:
            continue
    return pkts

# ---- Analisi principale per file JSON filtrato ----
def analyze_file_pairing(path: str, skip_att: bool=False) -> Dict[str, Any]:
    data = _load_packets(path)

    seen_ll_encryption: List[Tuple[int, str]] = []
    any_encrypted_flag = False
    first_encrypted_pkt = None

    # SMP
    smp_trace: List[Tuple[int, str]] = []
    seen_lesc = False
    authenticated = False
    method_label: Optional[str] = None
    association_model: Optional[str] = None

    # dettagli REQ/RSP
    req_info: Dict[str, Any] = {}
    rsp_info: Dict[str, Any] = {}
    pairing_exchange: Dict[str, Any] = {"request": None, "response": None, "decision": None}

    # key size (min dei due)
    req_max_key_size: Optional[int] = None
    rsp_max_key_size: Optional[int] = None
    eff_key_size: Optional[int] = None

    bonded_reencrypt = False
    att_unencrypted: List[Tuple[int, str]] = []
    att_encrypted: List[Tuple[int, str]] = []
    handle_uuid: Dict[int, int] = {}   # es. 0x0015 -> 0x2902

    # indirizzi
    addresses: Dict[str, str] = {}
    addr_types: Dict[str, str] = {}

    for pkt in data if isinstance(data, list) else []:
        pkt_no = pkt.get("packet_number")

        # encryption on?
        enc_flag = is_packet_encrypted(pkt)
        if enc_flag is True:
            if not any_encrypted_flag:
                bonded_reencrypt = bonded_reencrypt or (not smp_trace)  # nessuno SMP prima
            any_encrypted_flag = True
            if first_encrypted_pkt is None:
                first_encrypted_pkt = pkt_no

        # LL events
        ll_evt = detect_ll_encryption_signals(pkt)
        if ll_evt in ("LL_ENC_REQ","LL_ENC_RSP","LL_START_ENC_REQ","LL_START_ENC_RSP","LL_PAUSE_ENC_REQ","LL_PAUSE_ENC_RSP"):
            seen_ll_encryption.append((pkt_no, ll_evt))

        # SMP parsing
        smp_layers = find_layers_by_name(pkt, candidates=("btsmp", "smp", "security_manager"))
        smp_info: Optional[Dict[str, Any]] = None
        if smp_layers:
            # Unisci info dai layer presenti
            out: Dict[str, Any] = {}
            seen_any = False
            for smp in smp_layers:
                if not isinstance(smp, dict):
                    continue
                op = _first_int_by_suffix(smp, ["opcode", "code", "smp_opcode", "reserved.opcode"])
                if op is not None:
                    out["opcode"] = op
                    out["opcode_name"] = SMP_NAMES.get(op); seen_any = True
                io_cap = _first_int_by_suffix(smp, ["io.capability", "io_caps", "iocapability", "io_caps.value"])
                if io_cap is not None:
                    out["io_capability"] = io_cap
                    out["io_capability_name"] = IO_CAP_NAMES.get(io_cap, "Unknown"); seen_any = True
                oob_num = _first_int_by_suffix(smp, ["oob", "oob_flag", "oob.data.flags", "reserved.oob", "reserved.oob.data.flags"])
                if oob_num is not None:
                    out["oob"] = bool(oob_num); seen_any = True
                else:
                    oob_flag = _first_bool_by_path_contains(smp, ["oob", "flag"])
                    if oob_flag is not None:
                        out["oob"] = bool(oob_flag); seen_any = True
                auth = _first_int_by_suffix(smp, ["authreq", "reserved.authreq"])
                if auth is not None:
                    out["authReq"] = auth
                    out["mitm"] = bool(auth & AUTHREQ_BIT_MITM)
                    out["sc"] = bool(auth & AUTHREQ_BIT_SC)
                    out["keypress"] = bool(auth & AUTHREQ_BIT_KEYPRESS)
                    out["bonding"] = bool(auth & (AUTHREQ_BIT_BONDING_FLAG0 | AUTHREQ_BIT_BONDING_FLAG1))
                    seen_any = True
                mks = _first_int_by_suffix(smp, ["max.enc.key.size", "max_key_size", "max.encryption.key.size"])
                if mks is not None:
                    out["max_key_size"] = mks; seen_any = True
                for role, key in (("initiator", "initiator.key.distribution"), ("responder", "responder.key.distribution")):
                    enc = _first_int_by_suffix(smp, [f"{key}.enc", f"{key}.enc_key", f"{key}.ltk"])
                    idk = _first_int_by_suffix(smp, [f"{key}.id", f"{key}.id_key", f"{key}.irk"])
                    sig = _first_int_by_suffix(smp, [f"{key}.sign", f"{key}.sign_key", f"{key}.csrk"])
                    lnk = _first_int_by_suffix(smp, [f"{key}.link", f"{key}.link_key"])
                    if any(v is not None for v in (enc, idk, sig, lnk)):
                        out.setdefault("keydist", {})[role] = {
                            "enc": bool(_as_int(enc) or 0),
                            "id":  bool(_as_int(idk) or 0),
                            "sign":bool(_as_int(sig) or 0),
                            "link":bool(_as_int(lnk) or 0),
                        }
                        seen_any = True
            if out:
                # LESC markers
                if out.get("opcode") == 0x0C:
                    out["public_key_seen"] = True; out["sc"] = True
                if out.get("opcode") == 0x0D:
                    out["dhkey_check_seen"] = True; out["sc"] = True
                smp_info = out if seen_any else None

        if isinstance(smp_info, dict):
            smp_trace.append((pkt_no, smp_info.get("opcode_name") or "SMP"))

            if smp_info.get("public_key_seen") or smp_info.get("dhkey_check_seen") or smp_info.get("sc"):
                seen_lesc = True

            if smp_info.get("opcode") in (0x01, 0x02):
                side = "req" if smp_info["opcode"] == 0x01 else "rsp"
                target = req_info if side == "req" else rsp_info
                io_val = smp_info.get("io_capability")

                target.update({
                    "pkt": pkt_no,
                    "io": int(io_val) if io_val is not None else None,
                    "io_name": IO_CAP_NAMES.get(int(io_val), "Unknown") if io_val is not None else None,
                    "oob": bool(smp_info.get("oob", False)),
                    "mitm": bool(smp_info.get("mitm", False)),
                    "sc": bool(smp_info.get("sc", False) or smp_info.get("public_key_seen", False) or smp_info.get("dhkey_check_seen", False)),
                    "authReq": smp_info.get("authReq"),
                    "keypress": bool(smp_info.get("keypress", False)),
                    "bonding": bool(smp_info.get("bonding", False)),
                })

                mks = smp_info.get("max_key_size")
                if mks is not None:
                    if side == "req": req_max_key_size = int(mks)
                    else:             rsp_max_key_size = int(mks)

                if "keydist" in smp_info:
                    target["keydist"] = smp_info["keydist"]

                if req_info and side == "rsp":
                    io_i, io_r  = req_info.get("io"), rsp_info.get("io")
                    oob_i, oob_r = bool(req_info.get("oob", False)), bool(rsp_info.get("oob", False))
                    mitm_i, mitm_r = bool(req_info.get("mitm", False)), bool(rsp_info.get("mitm", False))
                    sc_i, sc_r = bool(req_info.get("sc", False)), bool(rsp_info.get("sc", False))

                    method_label = _pairing_method_from_both(io_i, io_r, oob_i, oob_r, mitm_i, mitm_r, sc_i, sc_r)
                    association_model = _association_model_from_method(method_label)

                    authenticated = (oob_i and oob_r) or ("Numeric Comparison" in method_label or "Passkey" in method_label)

                    pairing_exchange["request"] = {
                        "packet": req_info.get("pkt"),
                        "io_capability": req_info.get("io_name"),
                        "oob": req_info.get("oob"),
                        "mitm": req_info.get("mitm"),
                        "sc": req_info.get("sc"),
                        "authReq": req_info.get("authReq"),
                        "keypress": req_info.get("keypress"),
                        "bonding": req_info.get("bonding"),
                        "keydist": req_info.get("keydist"),
                        "max_key_size": req_max_key_size,
                    }
                    pairing_exchange["response"] = {
                        "packet": rsp_info.get("pkt"),
                        "io_capability": rsp_info.get("io_name"),
                        "oob": rsp_info.get("oob"),
                        "mitm": rsp_info.get("mitm"),
                        "sc": rsp_info.get("sc"),
                        "authReq": rsp_info.get("authReq"),
                        "keypress": rsp_info.get("keypress"),
                        "bonding": rsp_info.get("bonding"),
                        "keydist": rsp_info.get("keydist"),
                        "max_key_size": rsp_max_key_size,
                    }
                    left  = req_max_key_size if req_max_key_size is not None else 16
                    right = rsp_max_key_size if rsp_max_key_size is not None else 16
                    eff_key_size = max(1, min(left, right))

                    pairing_exchange["decision"] = {
                        "method": method_label,
                        "association_model": association_model,
                        "sc_both": bool(sc_i and sc_r),
                        "oob_both": bool(oob_i and oob_r),
                        "effective_key_size": eff_key_size,
                        "notes": "Decisione secondo workflow SC→OOB→MITM→IO",
                    }

        # ATT visibilità (opzionale)
        if not skip_att:
            att = detect_att(pkt, handle_uuid)
            if att:
                op, name = att
                if any_encrypted_flag:
                    att_encrypted.append((pkt_no, name))
                else:
                    att_unencrypted.append((pkt_no, name))

        # Indirizzi
        for role, addr in extract_addresses(pkt):
            if role not in addresses:
                addresses[role] = addr
                rand_flags = _safe_get(pkt, ["Layer BTLE", "advertising", "randomized"]) or _safe_get(pkt, ["Layer BTLE", "access", "advertising", "randomized"])
                addr_types[role] = classify_ble_address_type(addr, rand_flags)

    # Livello sicurezza
    level, level_text = decide_security_level(
        encryption_active=any_encrypted_flag,
        seen_lesc=seen_lesc,
        authenticated=authenticated
    )

    # Warning key size
    key_warnings = []
    if eff_key_size is not None and eff_key_size < 7:
        key_warnings.append(f"Key size effettiva {eff_key_size} (<7): forza debole.")

    return {
        "file": os.path.basename(path),
        "records": len(data) if isinstance(data, list) else 0,
        "encryption_active": any_encrypted_flag,
        "first_encrypted_packet": first_encrypted_pkt,
        "ll_encryption_events": seen_ll_encryption,
        "security_level": level,
        "security_level_text": level_text,
        "warnings": key_warnings,
        "pairing_exchange": pairing_exchange,
        "pairing_method": (pairing_exchange.get("decision") or {}).get("method") if pairing_exchange.get("decision") else (method_label or ("Indeterminato" if any_encrypted_flag else None)),
        "association_model": association_model,
        "lesc": seen_lesc,
        "authenticated": authenticated,
        "bonded_reencrypt_suspected": (not smp_trace) and any_encrypted_flag,
        "smp_trace": smp_trace[:40],
        "addresses": addresses,
        "address_types": addr_types,
        "att_unencrypted": att_unencrypted[:50] if not skip_att else [],
        "att_encrypted": att_encrypted[:50] if not skip_att else [],
        "effective_key_size": eff_key_size,
    }

# ---- Formattazione del report Markdown ----
def format_report_pairing(res: Dict[str, Any]) -> str:
    lines = []
    lines.append(f"# BLE Pairing Report – {res['file']}")
    lines.append(f"- Record totali: {res['records']}")
    lines.append(f"- Cifratura attiva: {'Sì' if res['encryption_active'] else 'No'}")
    if res["first_encrypted_packet"]:
        lines.append(f"- Primo pacchetto cifrato: #{res['first_encrypted_packet']}")
    if res["ll_encryption_events"]:
        ev = ", ".join([f"#{n}:{name}" for n, name in res["ll_encryption_events"][:12]])
        lines.append(f"- Eventi LL legati alla cifratura (prime occorrenze): {ev}")
    if res.get("smp_trace"):
        st = ", ".join([f"#{n}:{name}" for n, name in res["smp_trace"]])
        lines.append(f"- Traccia SMP (prime occorrenze): {st}")
    lines.append("")

    lines.append(f"## Livello di Sicurezza Stimato: Mode 1 Level {res['security_level']}")
    lines.append(f"> {res['security_level_text']}")
    crit = []
    if res["encryption_active"]:
        crit.append("cifratura osservata")
    if res.get("lesc"):
        crit.append("LE Secure Connections")
    if res.get("authenticated"):
        crit.append("autenticazione MITM/metodo autenticato")
    if res.get("bonded_reencrypt_suspected"):
        crit.append("ri-cifratura senza scambio SMP (sospetto bonding)")
    if res.get("effective_key_size") is not None:
        crit.append(f"key size effettiva={res['effective_key_size']}")
    if crit:
        lines.append(f"_Criteri:_ {', '.join(crit)}")
    if res.get("warnings"):
        for w in res["warnings"]:
            lines.append(f"⚠️ {w}")
    lines.append("")

    lines.append("## Pairing (REQ/RSP, sez. 4.2)")
    px = res.get("pairing_exchange") or {}
    rq = px.get("request"); rs = px.get("response"); dec = px.get("decision")

    if rq:
        lines.append(f"- Richiesta  #{rq.get('packet')}: IO={rq.get('io_capability')}, "
                     f"OOB={'Sì' if rq.get('oob') else 'No'}, MITM={'Sì' if rq.get('mitm') else 'No'}, "
                     f"SC={'Sì' if rq.get('sc') else 'No'}, KeySizeMax={rq.get('max_key_size')}, "
                     f"Bonding={'Sì' if rq.get('bonding') else 'No'}, Keypress={'Sì' if rq.get('keypress') else 'No'}")
        if rq.get("keydist"):
            lines.append(f"  • KeyDist (initiator): {rq['keydist'].get('initiator')}")
            lines.append(f"  • KeyDist (responder): {rq['keydist'].get('responder')}")
    else:
        lines.append("- Richiesta: non osservata")

    if rs:
        lines.append(f"- Risposta   #{rs.get('packet')}: IO={rs.get('io_capability')}, "
                     f"OOB={'Sì' if rs.get('oob') else 'No'}, MITM={'Sì' if rs.get('mitm') else 'No'}, "
                     f"SC={'Sì' if rs.get('sc') else 'No'}, KeySizeMax={rs.get('max_key_size')}, "
                     f"Bonding={'Sì' if rs.get('bonding') else 'No'}, Keypress={'Sì' if rs.get('keypress') else 'No'}")
        if rs.get("keydist"):
            lines.append(f"  • KeyDist (initiator): {rs['keydist'].get('initiator')}")
            lines.append(f"  • KeyDist (responder): {rs['keydist'].get('responder')}")
    else:
        lines.append("- Risposta: non osservata")

    if dec and dec.get("method"):
        lines.append(f"→ **Metodo di pairing**: {dec.get('method')}  "
                     f"(Association model: {dec.get('association_model')}; "
                     f"SC entrambi: {'Sì' if dec.get('sc_both') else 'No'}, "
                     f"OOB entrambi: {'Sì' if dec.get('oob_both') else 'No'}, "
                     f"Key size effettiva: {dec.get('effective_key_size')})")
    lines.append("")

    lines.append("## Indirizzi e Tipologia")
    if res["addresses"]:
        for role, addr in res["addresses"].items():
            t = res["address_types"].get(role, "unknown")
            lines.append(f"- {role}: {addr}  →  {t}")
    else:
        lines.append("- Non rilevati.")
    lines.append("")

    if res.get("att_unencrypted") or res.get("att_encrypted"):
        lines.append("## ATT/GATT visibili")
        if res["att_unencrypted"]:
            lines.append("### In chiaro (prima della cifratura)")
            lines.extend([f"- #{n}: {name}" for n, name in res["att_unencrypted"]])
        if res["att_encrypted"]:
            lines.append("### Dopo l'attivazione della cifratura")
            lines.extend([f"- #{n}: {name}" for n, name in res["att_encrypted"]])
        lines.append("")

    lines.append("---")
    return "\n".join(lines)

# ---- Runner audit (multi-file, con export) ----
def run_audit(json_inputs: List[Path], report_path: Optional[Path],
              json_out: Optional[Path] = None, csv_out: Optional[Path] = None,
              skip_att: bool = False):
    reports: List[str] = []
    all_results: List[Dict[str, Any]] = []

    for p in json_inputs:
        try:
            res = analyze_file_pairing(str(p), skip_att=skip_att)
            all_results.append(res)
            reports.append(format_report_pairing(res))
        except Exception as e:
            reports.append(f"# ERRORE con {p.name}\n{e}\n")

    out_text = "\n\n".join(reports)

    if report_path:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(out_text)
        print(f"Report scritto in {report_path}")
    else:
        print(out_text)

    if json_out:
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump(all_results, f, ensure_ascii=False, indent=2)
        print(f"JSON scritto in {json_out}")

    if csv_out:
        with open(csv_out, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "file","records","enc_active","security_level","lesc","authenticated",
                "pairing_method","association_model","effective_key_size",
                "bonded_reencrypt","first_encrypted_pkt"
            ])
            writer.writeheader()
            for r in all_results:
                writer.writerow({
                    "file": r["file"],
                    "records": r["records"],
                    "enc_active": r["encryption_active"],
                    "security_level": r["security_level"],
                    "lesc": r["lesc"],
                    "authenticated": r["authenticated"],
                    "pairing_method": r.get("pairing_method"),
                    "association_model": r.get("association_model"),
                    "effective_key_size": r.get("effective_key_size"),
                    "bonded_reencrypt": r.get("bonded_reencrypt_suspected"),
                    "first_encrypted_pkt": r.get("first_encrypted_packet"),
                })
        print(f"CSV scritto in {csv_out}")


# ==========================================
# CLI / MAIN
# ==========================================
def main():
    parser = argparse.ArgumentParser(
        description="Pipeline BLE: cattura -> pcap -> pcapng -> json -> filtro -> audit (pairing avanzato)"
    )
    # Pipeline options
    parser.add_argument("--dur", type=int, default=30, help="Durata cattura (s). Default: 30")
    parser.add_argument("--base", type=str, default="capture", help="Base name output (senza est.). Default: capture")
    parser.add_argument("--scan", type=int, default=5, help="Tempo scansione advertising (s). Default: 5")
    parser.add_argument("--skip-follow", action="store_true", help="Non chiedere il device (solo scan/cattura broadcast)")
    """
    # Crackle options
    parser.add_argument("--crackle", action="store_true", help="Prova a decifrare con crackle (Legacy Pairing).")
    parser.add_argument("--ltk", type=str, default=None, help="LTK esadecimale (32 hex) per modalità 'Decrypt with LTK'.")
    parser.add_argument("--save-keys", action="store_true", help="Salva TK/LTK trovati in <base>_crackle_keys.json.")
    """
    # Crackle options (commentate per ora, da implementare)
    
    # Audit options
    parser.add_argument("--report", type=str, help="Percorso file di output per il report (txt/md)")
    parser.add_argument("--json-out", type=str, default=None, help="Esporta risultati audit anche in JSON")
    parser.add_argument("--csv-out", type=str, default=None, help="Esporta riepilogo audit in CSV")
    parser.add_argument("--skip-att", action="store_true", help="Salta analisi ATT/GATT")
    parser.add_argument("--no-audit", action="store_true", help="Disabilita l'audit automatico a fine pipeline")
    parser.add_argument("--only-audit", nargs="+", help="Salta la pipeline ed esegue solo l'audit su JSON (accetta più file)")

    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)

    # Modalità: SOLO AUDIT
    if args.only_audit:
        inputs = [Path(p) for p in args.only_audit]
        report_path = Path(args.report) if args.report else None
        json_out = Path(args.json_out) if args.json_out else None
        csv_out = Path(args.csv_out) if args.csv_out else None
        run_audit(inputs, report_path, json_out=json_out, csv_out=csv_out, skip_att=args.skip_att)
        return

    # Pipeline completa
    base = Path(args.base)
    pcap_path = base.with_suffix(".pcap")
    pcapng_path = base.with_suffix(".pcapng")
    json_path = base.with_suffix(".json")

    # Step 1: cattura
    sniffer = setup_sniffer()
    devices = list_advertisers(sniffer, scan_time=args.scan)

    if not args.skip_follow:
        if not devices:
            print("Nessun dispositivo trovato.")
            return
        selected = select_device(devices)
        addr_str = ':'.join(format(x, '02X') for x in selected.address)
        print(f"\n[+] Seguendo: {selected.name} @ {addr_str} RSSI: {selected.RSSI}\n")
        sniffer.follow(selected)

    run_capture(sniffer, duration_sec=args.dur, pcap_path=pcap_path)

    # Step 2: converti a pcapng
    converted = convert_to_pcapng(pcap_path, pcapng_path)
    if not converted and not pcapng_path.exists():
        pcapng_path = pcap_path  # usa direttamente il pcap

    """
    # Step 2.5 (opzionale): crackle
    crackled_pcap = base.with_suffix("_decrypted.pcap")  # crackle scrive pcap (va bene per pyshark)
    found_keys = None
    use_for_parsing = pcapng_path  # default: file originale

    if args.crackle:
        ck = run_crackle(pcapng_path, crackled_pcap, ltk_hex=args.ltk)
        found_keys = ck
        # Se crackle ha prodotto qualcosa, usiamo il pcap decifrato
        if ck.get("ok"):
            print("[+] Crackle OK: uso output decifrato per il parsing.")
            use_for_parsing = crackled_pcap
        else:
            print("[!] Crackle non ha decifrato il traffico (vedi stdout/stderr).")
        # Salva chiavi se richiesto
        if args.save_keys:
            with open(base.with_suffix("_crackle_keys.json"), "w", encoding="utf-8") as f:
                json.dump({
                    "tk": ck.get("tk"),
                    "ltk": ck.get("ltk"),
                    "stdout": ck.get("stdout"),
                    "stderr": ck.get("stderr"),
                }, f, ensure_ascii=False, indent=2)
    """
    # Step 2.5 (opzionale): crackle (commentato per ora, da implementare)
    
    # Step 3: PyShark -> JSON (parsing custom)
    pcap_to_json(pcapng_path, json_path)

    # Step 4: filtro AUTOMATICO integrato
    filtered_json = apply_filter_to_json(json_path)

    # Step 5: audit (di default attivo)
    if not args.no_audit:
        # Percorsi export
        report_path = Path(args.report) if getattr(args, "report", None) else (base.parent / f"{base.stem}_audit.md")
        json_out = Path(args.json_out) if args.json_out else None
        csv_out = Path(args.csv_out) if args.csv_out else None
        run_audit([filtered_json], report_path, json_out=json_out, csv_out=csv_out, skip_att=args.skip_att)


if __name__ == "__main__":
    main()
