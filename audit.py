#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BLE Pairing Auditor 
Analizza JSON/NDJSON di traffico BLE filtrato e produce un report
sul pairing: metodo, association model, chiavi distribuite, key size,
SC/MITM/bonding e livello di sicurezza (Mode 1 Level 1..4).

Uso:
  python3 ble_pairing_audit.py file1.json [file2.json ...] \
      --out report.md --json-out report.json --csv-out report.csv \
      [--skip-att] [--debug]

Note:
- Accetta JSON array e NDJSON.
- Il calcolo del metodo segue il workflow SC→OOB→MITM→IO
  usando *entrambi* i lati (REQ/RSP).
"""

import argparse
import csv
import json
import os
import sys
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

# === Config di default ===
DEFAULT_IN_JSON = "capture_Filt.json"

# -------------------------- Utility --------------------------

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
            # accettiamo "0xXXXX", "XXXX", "xx:xx:..." o 128-bit uuid stringhe
            if s.lower().startswith("0x"):
                s = s[2:]
            return s
    return None

def _parse_uuid16(hexstr: Optional[str]) -> Optional[int]:
    if not hexstr:
        return None
    try:
        # accetta anche "2800" o "00002800-0000-1000-8000-00805f9b34fb"
        if "-" in hexstr and hexstr.endswith("00805f9b34fb"):
            # Bluetooth Base UUID → estrai 16 bit
            part = hexstr.split("-")[0]
            return int(part[-4:], 16)
        return int(hexstr, 16)
    except Exception:
        return None

# -------------------------- Maps & constants --------------------------

LL_CTRL_NAMES = {
    0x03: "LL_ENC_REQ",
    0x04: "LL_ENC_RSP",
    0x05: "LL_START_ENC_REQ",
    0x06: "LL_START_ENC_RSP",
    0x0A: "LL_PAUSE_ENC_REQ",
    0x0B: "LL_PAUSE_ENC_RSP",
    0x0C: "LL_VERSION_IND",
}

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
    1: "Nessuna cifratura, nessuna autenticazione",
    2: "Cifratura senza autenticazione",
    3: "Cifratura con autenticazione MITM",
    4: "LE Secure Connections con autenticazione",
}

# -------------------------- Parsers --------------------------

def detect_connection(pkt: Dict[str, Any]) -> Optional[str]:
    """
    Prova a riconoscere l'evento di connessione sul canale advertising.
    Ritorna una label (es. 'CONNECT_IND' o 'CONNECT_REQ') oppure None.
    """
    # Tentativi diretti via suffix noti
    pdu_t = _first_int_by_suffix(pkt, [
        "access.advertising.pdu.type", "advertising.pdu.type", "pdu.type"
    ])
    if pdu_t is not None:
        # Nello standard BLE, CONNECT_IND è pdu.type == 5
        if int(pdu_t) == 5:
            return "CONNECT_IND"

    # fallback euristico su qualunque chiave contenente 'connect' + 'ind/req'
    for path, key, val in _iter_kv(pkt):
        if isinstance(val, (dict, list)):
            continue
        joined = ".".join(path).lower()
        if "connect" in joined:
            if "ind" in joined:
                return "CONNECT_IND"
            if "req" in joined:
                return "CONNECT_REQ"

    return None

def detect_ll_encryption_signals(pkt: Dict[str, Any]) -> Optional[str]:
    """
    Cerca SOLO nel Layer BTLE la chiave 'opcode' e restituisce il nome
    corrispondente in LL_CTRL_NAMES (es. 'LL_ENC_REQ'), altrimenti None.
    """
    # isola i layer BTLE (accettiamo alias comuni)
    btle_layers = find_layers_by_name(pkt, candidates=("btle", "bluetooth_le", "bluetooth_low_energy", "ble"))
    if not btle_layers:
        return None

    for btle in btle_layers:
        if not isinstance(btle, dict):
            continue

        # come in detect_smp_info, ma qui guardiamo solo 'opcode'
        op = _first_int_by_suffix(btle, ["opcode"])
        if op is None:
            continue

        name = LL_CTRL_NAMES.get(op)
        if name:
            return name  # es. "LL_ENC_REQ"

    return None

def is_packet_encrypted(pkt: Dict) -> Optional[bool]:
    """
    Determina se un pacchetto BLE è cifrato.
    Restituisce:
        True  -> pacchetto cifrato
        False -> pacchetto in chiaro
        None  -> informazione non disponibile
    """
    # 1) Prova a leggere direttamente il flag "encrypted"
    enc = _safe_get(pkt, ["Layer NORDIC_BLE", "encrypted"])
    if enc is None:
        enc = _safe_get(pkt, ["Layer NORDIC_BLE", "event", "encrypted"])

    if enc is not None:
        return bool(enc)

    # 2) Se non troviamo il campo, usiamo il MIC (Message Integrity Check)
    #    Quando "mic.not.relevant" = 0 -> MIC rilevante => pacchetto cifrato
    #    Quando "mic.not.relevant" = 1 -> MIC non rilevante => pacchetto NON cifrato
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
    """
    Estrae indirizzi BLE in modo robusto usando i finder generici definiti nel file.
    Ritorna [(ruolo, indirizzo), ...] con ruoli: initiator, advertiser, master, slave.
    """
    out: List[Tuple[str, str]] = []

    def _add(role: str, addr: Optional[str]):
        if not addr:
            return
        s = str(addr).strip()
        if not s:
            return
        # evita duplicati identici
        if (role, s) not in out:
            out.append((role, s))

    # 1) Ricerca mirata per suffissi comuni (indipendente dalla struttura)
    suffix_map = {
        "initiator": [
            "access.initiator.address", "initiator.address", "initiator.addr",
            "access.initiator.bd.addr", "initiator.bd.addr"
        ],
        "advertiser": [
            "access.advertising.address", "advertising.address", "advertiser.address",
            "advertising.addr", "advertiser.addr", "adv.address", "adv.addr"
        ],
        "master": [
            "data.master.bd.addr", "master.bd.addr", "master.address",
            "link.master.address", "ll.master.address"
        ],
        "slave": [
            "data.slave.bd.addr", "slave.bd.addr", "slave.address",
            "link.slave.address", "ll.slave.address"
        ],
    }

    for role, sufs in suffix_map.items():
        _add(role, _first_hexstr_by_suffix(pkt, sufs))

    # 2) Fallback euristico: qualsiasi campo che sembri un address/addr, classificato dal path
    for path, _, val in _iter_kv(pkt):
        if isinstance(val, (dict, list)):
            continue
        leaf = ".".join(path).lower()
        if leaf.endswith(".address") or leaf.endswith(".addr"):
            s = str(val).strip()
            if not s:
                continue
            p = leaf  # alias

            # Classificazione per parole chiave nel path
            if "initiator" in p or ".init" in p:
                _add("initiator", s)
            elif "advertis" in p or ".adv" in p or "advertiser" in p:
                _add("advertiser", s)
            elif "master" in p or "central" in p:
                _add("master", s)
            elif "slave" in p or "peripheral" in p:
                _add("slave", s)

    return out

def classify_ble_address_type(addr: str, randomized_flags: Optional[Dict[str, Any]] = None) -> str:
    # 1) Determina se l’indirizzo è random o public dai bit TxAdd/RxAdd (se disponibili)
    is_random: Optional[bool] = None
    if isinstance(randomized_flags, dict):
        tx = randomized_flags.get("tx")
        rx = randomized_flags.get("rx")
        # True se uno dei due indica "random"
        is_random = (_is_true(tx) or _is_true(rx))

    # 2) Prova a leggere i 2 MSB del primo byte dell'indirizzo (formato "AA:BB:CC:DD:EE:FF")
    try:
        first = addr.split(":")[0]
        b0 = _hex_to_int_byte(first)
        msb2 = (b0 >> 6) & 0b11
    except Exception:
        return "unknown"

    # 3) Se sappiamo che NON è random → è sicuramente PUBLIC
    if is_random is False:
        return "public"

    # 4) Se sappiamo che è random → classifica con i 2 MSB
    if is_random is True:
        if msb2 == 0b11:
            return "static_random"
        elif msb2 == 0b01:
            return "private_resolvable"
        elif msb2 == 0b00:
            return "private_non_resolvable"
        else:  # 0b10 è riservato/inesistente
            return "unknown"

    # 5) Se NON sappiamo se sia random, facciamo il meglio possibile:
    if msb2 == 0b11:
        return "static_random"          # certo
    elif msb2 == 0b01:
        return "private_resolvable"     # certo
    elif msb2 == 0b00:
        return "public_or_non_resolvable"  # ambiguo senza TxAdd/RxAdd
    else:
        return "unknown"

def detect_smp_info(pkt: Dict) -> Optional[Dict[str, Any]]:
    smp_layers = find_layers_by_name(pkt, candidates=("btsmp", "smp", "security_manager"))
    if not smp_layers:
        return None
    out: Dict[str, Any] = {}
    seen = False

    for smp in smp_layers:
        if not isinstance(smp, dict):
            continue

        op = _first_int_by_suffix(smp, ["opcode", "code", "smp_opcode", "reserved.opcode"])
        if op is not None:
            out["opcode"] = op
            out["opcode_name"] = SMP_NAMES.get(op); seen = True

        # IO/OOB/AUTHREQ
        io_cap = _first_int_by_suffix(smp, ["io.capability", "io_caps", "iocapability", "io_caps.value"])
        if io_cap is not None:
            out["io_capability"] = io_cap
            out["io_capability_name"] = IO_CAP_NAMES.get(io_cap, "Unknown"); seen = True

        oob_num = _first_int_by_suffix(smp, ["oob", "oob_flag", "oob.data.flags", "reserved.oob", "reserved.oob.data.flags"])
        if oob_num is not None:
            out["oob"] = bool(oob_num); seen = True
        else:
            oob_flag = _first_bool_by_path_contains(smp, ["oob", "flag"])
            if oob_flag is not None:
                out["oob"] = bool(oob_flag); seen = True

        # dentro detect_smp_info(), dopo aver letto 'auth'
        auth = _first_int_by_suffix(smp, ["authreq", "reserved.authreq"])
        if auth is not None:
            out["authReq"] = auth
            out["mitm"] = bool(auth & AUTHREQ_BIT_MITM)
            # SC puro dai flag AuthReq (questo è ciò che la richiesta/risposta dichiara)
            out["sc_flag"] = bool(auth & AUTHREQ_BIT_SC)
            out["keypress"] = bool(auth & AUTHREQ_BIT_KEYPRESS)
            out["bonding"] = bool(auth & (AUTHREQ_BIT_BONDING_FLAG0 | AUTHREQ_BIT_BONDING_FLAG1))
            seen = True

        # marcatori LESC "visti sul filo"
        if out.get("opcode") == 0x0C:  # PAIRING_PUBLIC_KEY
            out["public_key_seen"] = True
        if out.get("opcode") == 0x0D:  # PAIRING_DHKEY_CHECK
            out["dhkey_check_seen"] = True
        # comodo alias: qualcosa di LESC è stato visto (runtime)
        if out.get("public_key_seen") or out.get("dhkey_check_seen"):
            out["sc_seen"] = True

        # Max key size (1..16), key distribution flags (ini/rsp)
        mks = _first_int_by_suffix(smp, ["max.enc.key.size", "max_key_size", "max.encryption.key.size"])
        if mks is not None:
            out["max_key_size"] = mks; seen = True

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
                seen = True

    # LESC markers
    if out.get("opcode") == 0x0C:
        out["public_key_seen"] = True; out["sc"] = True
    if out.get("opcode") == 0x0D:
        out["dhkey_check_seen"] = True; out["sc"] = True

    return out if seen else None

def _render_att_pretty(layer: Dict[str, Any]) -> Tuple[int, str]:
    op = _first_int_by_suffix(layer, ["opcode", "op", "code", "att.opcode"])
    if op is None:
        return None, None

    base = ATT_OPS.get(op, f"ATT 0x{op:02X}")

    # prova ad estrarre dettagli comuni
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

    # specifiche utili
    if op == 0x12:  # Write Request
        # prova a capire se è CCCD enable/disable
        # spesso il valore 0001 -> Notify, 0002 -> Indicate, 0000 -> disable
        val_hex = _first_hexstr_by_suffix(layer, ["value", "write.value", "att.value", "payload"])
        if val_hex:
            try:
                # prendi solo primi 2 byte little-endian
                v = int(val_hex[0:4], 16)
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

        # prova ad aggiornare la mappa handle->uuid se troviamo entrambi
        h = _first_int_by_suffix(layer, ["handle", "attr.handle", "attribute.handle", "att.handle", "gatt.handle"])
        uuid_hex = _first_hexstr_by_suffix(layer, ["uuid", "type.uuid", "attribute.uuid", "group.type", "att.type"])
        uuid16 = _parse_uuid16(uuid_hex)
        if h is not None and uuid16 is not None:
            handle_uuid_map[h] = uuid16

        # se il renderer non ha avuto UUID ma abbiamo la mappa, arricchisci la label
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

# -------------------------- Pairing inference --------------------------

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

def decide_security_level(encryption_active: bool,
                          sc_both_flag: bool,
                          authenticated: bool) -> Tuple[int, str]:
    # Regola richiesta: se entrambi i flag SC (REQ/RSP) sono a 1 => LV4
    if sc_both_flag:
        return 4, SECURITY_LEVEL_EXPLANATION[4]
    # Altrimenti usa la mappa classica osservando la cifratura/autenticazione
    if not encryption_active:
        return 1, SECURITY_LEVEL_EXPLANATION[1]
    if authenticated:
        return 3, SECURITY_LEVEL_EXPLANATION[3]
    return 2, SECURITY_LEVEL_EXPLANATION[2]

# -------------------------- Core analysis --------------------------

def _load_packets(path: str) -> List[Dict[str, Any]]:
    # Supporta JSON array e NDJSON
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
            # ignora righe non JSON
            continue
    return pkts

def analyze_file(path: str, skip_att: bool=False) -> Dict[str, Any]:
    data = _load_packets(path)

    seen_ll_encryption: List[Tuple[int, str]] = []
    any_encrypted_flag = False
    first_encrypted_pkt = None

    connection_packet: Optional[int] = None
    connection_event: Optional[str] = None

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

    # key size e distribuzioni
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

        # Rilevamento pacchetto di connessione (prima occorrenza)
        if connection_packet is None:
            conn_label = detect_connection(pkt)
            if conn_label:
                connection_packet = pkt_no
                connection_event = conn_label

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
        smp_info = detect_smp_info(pkt)
        if isinstance(smp_info, dict):
            smp_trace.append((pkt_no, smp_info.get("opcode_name") or "SMP"))

            if smp_info.get("public_key_seen") or smp_info.get("dhkey_check_seen") or smp_info.get("sc"):
                seen_lesc = True

            # REQ / RSP
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
                    # 'sc' = vero anche se ho visto public_key/dhkey (utile per metodo),
                    # 'sc_flag' = SOLO il bit SC in AuthReq (utile per "SC di req e rsp")
                    "sc": bool(
                        smp_info.get("sc_flag", False)
                        or smp_info.get("public_key_seen", False)
                        or smp_info.get("dhkey_check_seen", False)
                    ),
                    "sc_flag": bool(smp_info.get("sc_flag", False)),
                    "authReq": smp_info.get("authReq"),
                    "keypress": bool(smp_info.get("keypress", False)),
                    "bonding": bool(smp_info.get("bonding", False)),
                })

                # key size per lato
                mks = smp_info.get("max_key_size")
                if mks is not None:
                    if side == "req": req_max_key_size = int(mks)
                    else:             rsp_max_key_size = int(mks)

                # key distribution flags
                if "keydist" in smp_info:
                    target["keydist"] = smp_info["keydist"]

                # decisione quando abbiamo la risposta
                if req_info and side == "rsp":
                    sc_i_flag = bool(req_info.get("sc_flag", False))
                    sc_r_flag = bool(rsp_info.get("sc_flag", False))
                    sc_both_flag = sc_i_flag and sc_r_flag
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
                    # key size effettiva (min dei due, default 16 se uno manca)
                    left  = req_max_key_size if req_max_key_size is not None else 16
                    right = rsp_max_key_size if rsp_max_key_size is not None else 16
                    eff_key_size = max(1, min(left, right))

                    pairing_exchange["decision"] = {
                        "method": method_label,
                        "association_model": association_model,
                        "sc_both": sc_both_flag,   # << nuovo: SC dichiarato da entrambi in REQ/RSP
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
    # recupera sc_both_flag (se presente) dalla decisione del pairing
    px = pairing_exchange
    dec = px.get("decision") if px else None
    sc_both_flag = bool(dec.get("sc_both")) if dec else False

    level, level_text = decide_security_level(
        encryption_active=any_encrypted_flag,
        sc_both_flag=sc_both_flag,
        authenticated=authenticated
    )
    
    # Warning key size
    key_warnings = []
    if eff_key_size is not None and eff_key_size < 7:
        key_warnings.append(f"Key size effettiva {eff_key_size} (<7): forza debole.")

    return {
        "file": os.path.basename(path),
        "records": len(data) if isinstance(data, list) else 0,
        "connection_packet": connection_packet,
        "connection_event": connection_event,
        "encryption_active": any_encrypted_flag,
        "first_encrypted_packet": first_encrypted_pkt,
        "ll_encryption_events": seen_ll_encryption,  # tutte le occorrenze
        "security_level": level,
        "security_level_text": level_text,
        "warnings": key_warnings,
        "pairing_exchange": pairing_exchange,
        "pairing_method": method_label or ("Indeterminato" if any_encrypted_flag else None),
        "association_model": association_model,
        "lesc": seen_lesc,
        "authenticated": authenticated,
        "bonded_reencrypt_suspected": bonded_reencrypt and any_encrypted_flag,
        "smp_trace": smp_trace,                      # tutte le occorrenze
        "addresses": addresses,
        "address_types": addr_types,
        "att_unencrypted": att_unencrypted[:50] if not skip_att else [],
        "att_encrypted": att_encrypted[:50] if not skip_att else [],
        "effective_key_size": eff_key_size,
    }

# -------------------------- Reporting --------------------------

def format_report(res: Dict[str, Any]) -> str:
    lines = []
    lines.append(f"# BLE Pairing Report – {res['file']}")
    lines.append(f"- Record totali: {res['records']}")
    lines.append(f"- Cifratura attiva: {'Sì' if res['encryption_active'] else 'No'}")

    # Connessione
    if res.get("connection_packet"):
        ce = res.get("connection_event") or "CONNECT_IND/REQ"
        lines.append(f"- Connessione: #{res['connection_packet']} ({ce})")

    # Primo pacchetto cifrato
    if res.get("first_encrypted_packet"):
        lines.append(f"- Primo pacchetto cifrato: #{res['first_encrypted_packet']}")
    lines.append("")
    
    # Indirizzi
    lines.append("## Indirizzi e Tipologia")
    if res.get("addresses"):
        for role, addr in res["addresses"].items():
            t = res["address_types"].get(role, "unknown")
            lines.append(f"- {role}: {addr}  →  {t}")
    else:
        lines.append("- Non rilevati.")
    lines.append("")
    
    # Traccia SMP (tutta, una per riga)
    if res.get("smp_trace"):
        lines.append("## Traccia SMP")
        for n, name in res["smp_trace"]:
            lines.append(f"- #{n}: {name}")
    lines.append("")

    # Eventi LL legati alla cifratura (tutti, uno per riga)
    if res.get("ll_encryption_events"):
        lines.append("## Eventi LL legati alla cifratura")
        for n, name in res["ll_encryption_events"]:
            lines.append(f"- #{n}: {name}")
    lines.append("")
    
    # Pairing (REQ/RSP)
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

    # Livello di sicurezza
    lines.append(f"## Livello di Sicurezza Stimato: Mode 1 Level {res['security_level']}")
    lines.append(f"> {res['security_level_text']}")
    crit = []
    if res.get("encryption_active"):
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

    # ATT/GATT (come prima, con elenchi su righe separate)
    if res.get("att_unencrypted") or res.get("att_encrypted"):
        lines.append("## ATT/GATT visibili")
        if res.get("att_unencrypted"):
            lines.append("### In chiaro (prima della cifratura)")
            for n, name in res["att_unencrypted"]:
                lines.append(f"- #{n}: {name}")
        if res.get("att_encrypted"):
            lines.append("### Dopo l'attivazione della cifratura")
            for n, name in res["att_encrypted"]:
                lines.append(f"- #{n}: {name}")
        lines.append("")

    lines.append("---")
    return "\n".join(lines)

# -------------------------- CLI & exports --------------------------

def _write_csv_row(writer, res: Dict[str, Any]):
    px = res.get("pairing_exchange") or {}
    dec = px.get("decision") or {}
    writer.writerow({
        "file": res["file"],
        "records": res["records"],
        "enc_active": res["encryption_active"],
        "security_level": res["security_level"],
        "lesc": res["lesc"],
        "authenticated": res["authenticated"],
        "pairing_method": res.get("pairing_method"),
        "association_model": res.get("association_model"),
        "effective_key_size": res.get("effective_key_size"),
        "bonded_reencrypt": res.get("bonded_reencrypt_suspected"),
        "first_encrypted_pkt": res.get("first_encrypted_packet"),
    })

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Analisi Pairing BLE (sez. 4.2).")
    parser.add_argument("inputs", nargs="*", help="File JSON da analizzare")
    parser.add_argument("--out", default="report.md", help="Report Markdown")
    parser.add_argument("--json-out", default=None, help="Esporta risultati anche in JSON")
    parser.add_argument("--csv-out", default=None, help="Esporta riepilogo CSV")
    parser.add_argument("--skip-att", action="store_true", help="Salta analisi ATT/GATT")
    parser.add_argument("--debug", action="store_true", help="Debug breakpoint su errore")
    args = parser.parse_args(argv)

    inputs = args.inputs if args.inputs else [DEFAULT_IN_JSON]
    inputs = [str(p) for p in inputs]

    reports: List[str] = []
    all_results: List[Dict[str, Any]] = []

    for path in inputs:
        try:
            res = analyze_file(path, skip_att=args.skip_att)
            all_results.append(res)
            reports.append(format_report(res))
        except Exception as e:
            if args.debug:
                import traceback
                traceback.print_exc()
            reports.append(f"# ERRORE con {path}\n{e}\n")

    out_text = "\n\n".join(reports)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(out_text)
        print(f"Report scritto in {args.out}")
    else:
        print(out_text)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(all_results, f, ensure_ascii=False, indent=2)
        print(f"JSON scritto in {args.json_out}")

    if args.csv_out:
        with open(args.csv_out, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "file","records","enc_active","security_level","lesc","authenticated",
                "pairing_method","association_model","effective_key_size",
                "bonded_reencrypt","first_encrypted_pkt"
            ])
            writer.writeheader()
            for r in all_results:
                _write_csv_row(writer, r)
        print(f"CSV scritto in {args.csv_out}")

    return 0

if __name__ == "__main__":
    sys.exit(main())
