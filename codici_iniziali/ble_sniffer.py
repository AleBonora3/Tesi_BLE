#!/usr/bin/env python3
import logging
import sys
import time
import argparse
import subprocess
from SnifferAPI import Sniffer, UART, Pcap

def setup_sniffer():
    ports = UART.find_sniffer()
    if not ports:
        print("Nessun sniffer trovato.")
        sys.exit(1)
    sniffer = Sniffer.Sniffer(portnum=ports[0], baudrate=1000000)
    sniffer.start()
    sniffer.scan()
    print(f"Sniffer avviato sulla porta {ports[0]} e in scansione...")
    return sniffer

def list_advertisers(sniffer, scan_time=3):
    print("\nScansione dei dispositivi BLE in advertising...\n")
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
    print("\nScansione completata.\n")
    return list(seen.values())

def select_device(devices):
    print("Seleziona un dispositivo da seguire:")
    for i, dev in enumerate(devices):
        addr_str = ':'.join(format(x, '02X') for x in dev.address)
        print(f"[{i}] {dev.name} @ {addr_str} RSSI: {dev.RSSI}")
    while True:
        choice = input("Inserisci il numero: ")
        try:
            index = int(choice)
            if 0 <= index < len(devices):
                return devices[index]
        except ValueError:
            pass
        print("Selezione non valida. Riprova.")

def run_capture(sniffer, duration=30, pcap_path="capture.pcap"):
    # Scrive il global header del PCAP
    with open(pcap_path, 'wb') as pcap_file:
        pcap_file.write(Pcap.get_global_header())
        print(f"[*] Cattura BLE in corso per {duration} secondi... Salvataggio in: {pcap_path}\n")
        start_time = time.time()
        try:
            while time.time() - start_time < duration:
                packets = sniffer.getPackets()
                for pkt in packets:
                    pcap_data = Pcap.create_packet(bytes([pkt.boardId] + pkt.getList()), pkt.time)
                    pcap_file.write(pcap_data)
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\n[!] Interrotto dall'utente.")
    print("\n[*] Cattura terminata.")

def maybe_convert_to_pcapng(src_pcap, dst_pcapng):
    # Richiede tshark/editcap (Wireshark) installati
    try:
        subprocess.run(["editcap", "-F", "pcapng", src_pcap, dst_pcapng], check=True)
        print(f"[+] Convertito in .pcapng: {dst_pcapng}")
    except FileNotFoundError:
        print("[!] 'editcap' non trovato. Salto la conversione a .pcapng.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Errore nella conversione a .pcapng: {e}")

def main():
    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description="Cattura BLE e salva solo in PCAP.")
    parser.add_argument("--dur", type=int, default=30, help="Durata cattura in secondi (default: 30)")
    parser.add_argument("--pcap", type=str, default="capture.pcap", help="Percorso file .pcap di output")
    parser.add_argument("--pcapng", type=str, default=None,
                        help="(Opzionale) Se impostato, converte anche in questo .pcapng")
    args = parser.parse_args()

    sniffer = setup_sniffer()
    devices = list_advertisers(sniffer)
    if not devices:
        print("Nessun dispositivo trovato.")
        return

    selected = select_device(devices)
    addr_str = ':'.join(format(x, '02X') for x in selected.address)
    print(f"\n[+] Seguendo il dispositivo: {selected.name} @ {addr_str} RSSI: {selected.RSSI}\n")

    sniffer.follow(selected)
    run_capture(sniffer, duration=args.dur, pcap_path=args.pcap)

    if args.pcapng:
        maybe_convert_to_pcapng(args.pcap, args.pcapng)

if __name__ == "__main__":
    main()
