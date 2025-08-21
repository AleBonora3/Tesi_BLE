import pyshark
import io
import json
import contextlib
import re
from pathlib import Path

# === Config ===
PCAP = "hr.pcapng"
OUT_JSON = Path(PCAP).with_suffix(".json")

# --- in cima (config) ---
INDENT_SPACES = 2
OUT_SHOWTXT = Path(PCAP).with_suffix(".show.txt")

BOOL_MAP = {"true": True, "false": False}
NONE_SET = {"none", "null", ""}

def coerce_scalar(s: str):
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
    except:
        pass
    try:
        if re.fullmatch(r"[+-]?\d+\.\d+", t):
            return float(t)
    except:
        pass
    return t

def indent_level(line: str) -> int:
    count = 0
    for ch in line:
        if ch == "\t":
            count += 1
        elif ch == " ":
            count += 0.25
        else:
            break
    return int(count)

def normalize_layer_header(line: str) -> str | None:
    m = re.match(r"\s*Layer\s+(.+?)(?::\s*)?$", line.strip())
    if m:
        return m.group(1).strip()
    return None

def parse_show_text(raw_text: str) -> dict:
    root: dict = {}
    current_layer_dict: dict | None = None
    stack: list[tuple[int, dict]] = []
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

        # Normalizza la riga: togli tab/spazi a sinistra, poi rimuovi un eventuale ":" iniziale (e lo spazio dopo)
        tmp = raw_line.lstrip("\t ")
        if tmp.startswith(":"):
            tmp = tmp.lstrip(":").lstrip()
        line = tmp.rstrip()
        if not line:
            continue


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

def main():
    packets = []
    show_texts = []

    with pyshark.FileCapture(PCAP, use_ek=True) as cap:
        for i, pkt in enumerate(cap, start=1):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                pkt.show()
            raw_text = buf.getvalue().rstrip("\n")
            show_texts.append(f"# packet {i}\n{raw_text}\n")

            parsed_layers = parse_show_text(raw_text)

            packet_dict = {"packet_number": i}
            packet_dict.update(parsed_layers)
            packets.append(packet_dict)

    # JSON "show-like" (8 spazi per livello, ordine preservato)
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(packets, f, ensure_ascii=False, indent=INDENT_SPACES)

    # Dump identico allo show(), utile per confronto visivo
    #with open(OUT_SHOWTXT, "w", encoding="utf-8") as f:
     #   f.write("\n".join(show_texts))

    print(f"[OK] Salvati {len(packets)} pacchetti in {OUT_JSON}")
    #print(f"[OK] Salvato dump show() in {OUT_SHOWTXT}")


if __name__ == "__main__":
    main()
