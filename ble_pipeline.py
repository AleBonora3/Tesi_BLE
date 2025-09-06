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
  • opzionalmente JSON riassuntivi, 
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
        --report audit.md --json-out audit.json

3) Pipeline completa senza seguire un device specifico:
    python3 ble_pipeline.py --skip-follow

Note
----
- Se `editcap` non è disponibile, il tool prova ad usare direttamente il `.pcap` per PyShark.
- Il filtro integrato produce `*_Filt.json`, che è l'input preferito per l'audit.
- L'audit è progettato per essere *tollerante* a variazioni nei campi dei layer.

Alessio Bonora
--------------
- Progetto tesi – Università degli Studi di Milano
- Corso: Sicurezza dei sistemi e delle reti informatiche
"""

# ==========================================
#                IMPORTS
# ==========================================
import argparse
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

# --- Audit ---
from audit import analyze_file as audit_analyze_file, format_report as audit_format_report

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
#   STEP 5: AUDIT SICUREZZA
# ==========================================
def run_audit(json_inputs: List[Path], report_path: Optional[Path],
              json_out: Optional[Path] = None,
              skip_att: bool = False):
    reports: List[str] = []
    all_results: List[Dict[str, Any]] = []

    for p in json_inputs:
        try:
            res = audit_analyze_file(str(p), skip_att=skip_att)
            all_results.append(res)
            reports.append(audit_format_report(res))
        except Exception as e:
            reports.append(f"# ERRORE con {p.name}\n{e}\n")

    out_text = "\n\n".join(reports)

    # --- Report Markdown ---
    if report_path:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(out_text)
        print(f"Report scritto in {report_path}")
    else:
        print(out_text)

    # --- Export JSON opzionale ---
    if json_out:
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump(all_results, f, ensure_ascii=False, indent=2)
        print(f"JSON scritto in {json_out}")

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
        run_audit(inputs, report_path, json_out=json_out, skip_att=args.skip_att)
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
        run_audit([filtered_json], report_path, json_out=json_out, skip_att=args.skip_att)


if __name__ == "__main__":
    main()
