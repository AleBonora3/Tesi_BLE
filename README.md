# BLE End-to-End Security Pipeline  
*(capture → convert → parse → filter → audit)*

Questo progetto implementa una pipeline automatizzata completa per l’**analisi della sicurezza delle connessioni Bluetooth Low Energy (BLE)**.  
Il file principale da eseguire è **`ble_pipeline.py`**, che copre l’intero flusso end-to-end.

---

##  Funzionalità della pipeline

1. **Cattura**  
   Usa **SnifferAPI** (estratta dalla cartella `extcap` del pacchetto ufficiale) per acquisire traffico BLE e salvarlo in `.pcap`.

2. **Conversione**  
   Converte automaticamente in `.pcapng` tramite `editcap` (parte di Wireshark) per garantire compatibilità con i tool di analisi.

3. **Parsing**  
   Utilizza **PyShark** per analizzare i pacchetti e serializzarli in JSON (equivalente di `pkt.show()`), con un parser robusto ai cambiamenti di layout.

4. **Filtro**  
   Scarta:
   - advertising generici  
   - scan response  
   - PDU vuote  
   e mantiene i pacchetti **CONNECT_IND/REQ**.  
   Output: `*_Filt.json`.

5. **Audit (avanzato)**  
   Applica un *BLE Pairing & Security Audit* sui JSON filtrati, generando:
   - un **report Markdown** (Mode 1 L1–L4, metodo/association model, SC/MITM, bonding, key size)  
   - **JSON/CSV opzionali** di riepilogo  
   - una mappa ATT/GATT (handle → UUID) prima e dopo cifratura.

---

##  Requisiti

- **Python** ≥ 3.8  
- **Dipendenze Python**: `pyshark` (vedi `requirements.txt`)  
- **SnifferAPI**: disponibile nella cartella `extcap` del pacchetto ufficiale “nRF Sniffer for Bluetooth LE” disponibile sul sito di Nordic :contentReference[oaicite:1]{index=1}  
- **Tool esterni**: `editcap` (incluso in Wireshark)  
- **Hardware**: dongle o board compatibile con SnifferAPI (es. **nRF52840 Dongle**) :contentReference[oaicite:2]{index=2}

---

##  Setup ambiente

### 1. Scarica il pacchetto ufficiale Sniffer
Vai qui e scarica l’ultima versione ZIP:
- [Download nRF Sniffer for Bluetooth LE] :contentReference[oaicite:3]{index=3}

All’interno del ZIP troverai una cartella `extcap` contenente la libreria **SnifferAPI**.

### 2. Ambiente virtuale Python
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
