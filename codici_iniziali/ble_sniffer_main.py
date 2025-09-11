import logging
from SnifferAPI import Sniffer, UART, Pcap
import sys, time
import subprocess

def setup_sniffer():
    ports = UART.find_sniffer()
    if not ports:
        print("No sniffer found.")
        sys.exit(1)
    sniffer = Sniffer.Sniffer(portnum=ports[0], baudrate=1000000)
    sniffer.start()
    sniffer.scan()
    print(f"Sniffer started on port {ports[0]} and scanning...")
    return sniffer

def list_advertisers(sniffer, scan_time=3):
    print("\nScanning for BLE advertising devices...\n")
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
    print("\nScan complete.\n")
    return list(seen.values())

def select_device(devices):
    print("Select a device to follow:")
    for i, dev in enumerate(devices):
        addr_str = ':'.join(format(x, '02X') for x in dev.address)
        print(f"[{i}] {dev.name} @ {addr_str} RSSI: {dev.RSSI}")
    while True:
        choice = input("Enter number: ")
        try:
            index = int(choice)
            if 0 <= index < len(devices):
                return devices[index]
        except ValueError:
            pass
        print("Invalid selection. Try again.")

def run_live_analysis(sniffer, duration=30, save_pcap=True, pcap_path="live_capture_temp.pcap"):
    pcap_file = open(pcap_path, 'wb') if save_pcap else None
    if pcap_file:
        pcap_file.write(Pcap.get_global_header())

    print(f"[*] Analisi BLE in corso per {duration} secondi...\n")
    start_time = time.time()
    try:
        while time.time() - start_time < duration:
            packets = sniffer.getPackets()
            for pkt in packets:
                if pcap_file:
                    pcap_data = Pcap.create_packet(bytes([pkt.boardId] + pkt.getList()), pkt.time)
                    pcap_file.write(pcap_data)
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\n[!] Interrotto dall'utente.")
    finally:
        if pcap_file:
            pcap_file.close()
        print("\n[*] Analisi completata.")
        subprocess.run(["editcap", "-F", "pcapng", "live_capture_temp.pcap", "live_capture.pcapng"])
        print("[+] File convertito in formato .pcapng")

def main():
    logging.basicConfig(level=logging.INFO)
    
    sniffer = setup_sniffer()
    devices = list_advertisers(sniffer)
    if not devices:
        print("Nessun dispositivo trovato.")
        return

    selected = select_device(devices)
    addr_str = ':'.join(format(x, '02X') for x in selected.address)
    print(f"\n[+] Seguendo il dispositivo: {selected.name} @ {addr_str} RSSI: {selected.RSSI}\n")

    sniffer.follow(selected)
    run_live_analysis(sniffer, duration=30)

if __name__ == "__main__":
    main()
