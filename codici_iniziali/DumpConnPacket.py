#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Filtro BLE su JSON (no PCAP):
- Esclude:
  1) Advertising generici (presenza di "advertising" nel Layer BTLE) MA NON i CONNECT_IND/REQ
  2) Scan Response (qualsiasi advertising con pdu.type == 4 O presenza di 'scan.response/responce' ovunque)
  3) PDU vuota (Layer BTLE.length == 0, cioè la length del layer, non quelle annidate)
- Mantiene i CONNECT_IND / CONNECT_REQ (qualsiasi advertising con pdu.type == 5 oppure stringhe/chiavi equivalenti),
  anche se annidati (es. BTLE -> link -> advertising -> pdu -> type).

Uso:
    python filtro_ble_json.py Livello2.json
(oppure senza argomenti: usa "Livello2.json" di default)
"""

import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Optional, List, Tuple, Iterable

# === Config di default ===
DEFAULT_IN_JSON = "hr.json"  # cambia se vuoi un default diverso
INDENT_SPACES = 2

# Regex extra facoltative: se una di queste matcha il pacchetto (stringa JSON), il pacchetto viene escluso
EXCLUDE_REGEX: List[str] = [
    # Esempi:
    # r'(?i)"channel"\s*:\s*39',
    # r'(?i)"addr"\s*:\s*"c0:48:ff:f5:9d:b8"'
]
_EXCLUDE_COMPILED = [re.compile(p) for p in EXCLUDE_REGEX]


# ---------- Utility ----------
def _norm(s: Any) -> str:
    """Normalizza chiavi/testi: minuscolo, spazi/underscore/trattini compressi."""
    return re.sub(r"[\s_\-]+", " ", str(s)).strip().lower()


def _iter_keyvals(obj: Any) -> Iterable[Tuple[str, Any]]:
    """Itera ricorsivamente tutte le (chiave, valore) nei dizionari annidati."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k, v
            # ricorsione su v
            yield from _iter_keyvals(v)
    elif isinstance(obj, list):
        for x in obj:
            yield from _iter_keyvals(x)


def _iter_subdicts_by_key(obj: Any, key_regex: re.Pattern) -> Iterable[Dict[str, Any]]:
    """Ritorna tutti i sotto-dizionari il cui nome-chiave (normalizzato) matcha la regex."""
    for k, v in _iter_keyvals(obj):
        if isinstance(v, dict) and key_regex.fullmatch(_norm(k)):
            yield v


def _deep_has_key(obj: Any, key_regex: re.Pattern) -> bool:
    """True se esiste una chiave (normalizzata) che matcha la regex in un dict/list annidato."""
    for k, _ in _iter_keyvals(obj):
        if key_regex.fullmatch(_norm(k)):
            return True
    return False


def _deep_find_first(obj: Any, key_regex: re.Pattern) -> Any:
    """Trova il primo valore associato a una chiave (normalizzata) che matcha la regex, cercando in profondità."""
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
    """Tenta di convertire a int (utile per 'type' o 'length' arrivati come stringhe)."""
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


# ---------- Riconoscimento nel Layer BTLE ----------
def _find_btle_layer(packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Trova il dict che rappresenta il layer BTLE (tollerante al nome, es. 'Layer BTLE')."""
    for k, v in packet.items():
        if isinstance(v, dict):
            nk = _norm(k)
            if "layer" in nk and "btle" in nk:
                return v
    return None


def _adv_pdu_types(btle: Dict[str, Any]) -> List[Optional[int]]:
    """
    Ritorna tutti i valori (convertiti a int se possibile) di 'pdu.type'
    sotto qualsiasi sotto-dizionario chiamato 'advertising' (annidato ovunque).
    """
    types: List[Optional[int]] = []
    for adv in _iter_subdicts_by_key(btle, re.compile(r"advertising")):
        pdu = _deep_find_first(adv, re.compile(r"pdu"))
        if isinstance(pdu, dict):
            t = _deep_find_first(pdu, re.compile(r"type"))
            # prova come int; se stringa tipo "CONNECT_IND" gestiamo dopo
            ti = _to_int(t)
            if ti is not None:
                types.append(ti)
                continue
            if isinstance(t, str):
                s = _norm(t)
                # es. "connect ind" o "connect req"
                if "connect" in s and ("ind" in s or "req" in s):
                    types.append(5)  # normalizziamo a 5
                elif "scan" in s and ("rsp" in s or "response" in s or "responce" in s):
                    types.append(4)  # normalizziamo a 4
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
    # a) Qualsiasi advertising con pdu.type == 4
    if 4 in [t for t in _adv_pdu_types(btle) if t is not None]:
        return True
    # b) Presenza di 'scan.response' o 'scan.responce' ovunque
    for scan in _iter_subdicts_by_key(btle, re.compile(r"scan")):
        if _deep_has_key(scan, re.compile(r"respon[sc]e")):
            return True
    return False


def _is_connect_ind(btle: Dict[str, Any]) -> bool:
    # Qualsiasi advertising con pdu.type == 5 (o stringhe equivalenti normalizzate a 5)
    return 5 in [t for t in _adv_pdu_types(btle) if t is not None]


def _has_zero_length_outside_advertising(obj: Any, in_adv: bool = False) -> bool:
    """
    True se esiste una chiave 'length' == 0 in BTLE al di fuori di 'advertising',
    anche se annidata (es. data.header.length, data.length, link.layer.data.header.length, ...).
    """
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
    """
    Empty PDU in connessione:
    - BTLE.length == 0 al top-level, OPPURE
    - qualunque 'length == 0' annidato fuori da 'advertising' (es. data.header.length).
    """
    # top-level
    if _to_int(btle.get("length")) == 0:
        return True
    # annidato (ma non dentro 'advertising')
    return _has_zero_length_outside_advertising(btle)


# ---------- Filtro principale ----------
def should_exclude_packet(packet: Dict[str, Any]) -> Tuple[bool, Optional[str], bool]:
    """
    Ritorna (exclude_bool, reason, is_connect_ind_kept_flag).
    'reason' = 'scan_response' | 'empty_pdu' | 'advertising' | 'regex' | None
    'is_connect_ind_kept_flag' = True se il pacchetto è CONNECT_IND/REQ e viene tenuto.
    """
    btle = _find_btle_layer(packet)
    is_connect = False

    if isinstance(btle, dict):
        # 1) Scan Response (sempre da escludere)
        if _is_scan_response(btle):
            return True, "scan_response", False

        # 2) PDU vuota (sempre da escludere)
        if _is_empty_pdu(btle):
            return True, "empty_pdu", False

        # 3) Advertising: escludi TUTTO tranne i CONNECT_IND / CONNECT_REQ
        is_connect = _is_connect_ind(btle)
        if _is_advertising_anywhere(btle) and not is_connect:
            return True, "advertising", False

    # 4) Regex extra (se configurate) sull'intero pacchetto
    if _EXCLUDE_COMPILED:
        blob = json.dumps(packet, ensure_ascii=False)
        if any(p.search(blob) for p in _EXCLUDE_COMPILED):
            return True, "regex", False

    # Non escluso
    return False, None, bool(is_connect)


# ---------- Input/Output ----------
def _extract_packet_list(data: Any) -> List[Dict[str, Any]]:
    """Accetta sia una lista pura di pacchetti, sia un wrapper {"packets": [...]}."""
    if isinstance(data, list):
        return data  # type: ignore[return-value]
    if isinstance(data, dict) and isinstance(data.get("packets"), list):
        return data["packets"]  # type: ignore[return-value]
    raise ValueError("Formato JSON non riconosciuto: attesa una lista o un oggetto con chiave 'packets'.")


def main():
    # Argomenti: input (opzionale) e output (derivato)
    in_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(DEFAULT_IN_JSON)
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
        json.dump(out_packets, f, ensure_ascii=False, indent=INDENT_SPACES)

    # Report finale
    print(f"[OK] Input: {in_path}")
    print(f"[OK] Output: {out_path}")
    print(f"[OK] Pacchetti in input:  {stats['total_in']}")
    print(f"[OK] Pacchetti tenuti:    {stats['kept']}")
    print(f"[OK] Pacchetti esclusi:   {stats['excluded']}")
    for k, v in stats["reasons"].items():
        print(f"      - esclusi per {k}: {v}")
    print(f"[OK] CONNECT_IND/REQ tenuti: {stats['connect_ind_kept']}")


if __name__ == "__main__":
    main()
