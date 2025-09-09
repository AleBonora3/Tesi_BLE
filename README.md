# BLE End-to-End Security Pipeline  
*(capture → convert → parse → filter → audit)*

## 🇮🇹 Descrizione (Italiano)

Questo repository contiene il codice sviluppato per la mia **tesi triennale in Sicurezza dei Sistemi e delle Reti Informatiche** presso l’Università degli Studi di Milano.  

L’obiettivo del progetto è realizzare una **pipeline automatizzata** per l’analisi della sicurezza delle connessioni **Bluetooth Low Energy (BLE)**.  

### File principali
- **`ble_pipeline.py`** → avvia l’intera pipeline: cattura → conversione → parsing → filtro → audit.  
- **`audit.py`** → esegue l’audit su file JSON già filtrati.  

Per funzionare, nella stessa cartella deve essere presente la directory:  
```
./SnifferAPI/
```
contenente la libreria ufficiale **SnifferAPI** estratta dal pacchetto *nRF Sniffer for Bluetooth LE* fornito da Nordic Semiconductor.

### Altri file nel repository
Gli altri file e cartelle presenti servono come **evidenze e materiali di supporto alla tesi** (report, esempi di catture, documentazione).  
Non sono necessari per l’esecuzione della pipeline.

## 🔍 Funzionalità principali

La pipeline (`ble_pipeline.py`) implementa cinque step sequenziali:

1. **Cattura**  
   - Usa la **SnifferAPI Nordic** per acquisire traffico BLE tramite dongle nRF52840.  
   - Output: file `.pcap`.

2. **Conversione**  
   - Converte automaticamente `.pcap` → `.pcapng` con `editcap` (Wireshark).  
   - Garantisce compatibilità con `tshark`/PyShark.

3. **Parsing**  
   - Analizza i pacchetti con **PyShark**.  
   - Serializza in JSON robusto (equivalente a `pkt.show()` di Wireshark).  
   - Output: `<trace>.json`.

4. **Filtro**  
   - Scarta advertising generici, scan response e PDU vuote.  
   - Mantiene solo eventi chiave (CONNECT_IND/REQ, SMP, cifratura, ATT).  
   - Output: `<trace>_Filt.json`.

5. **Audit (avanzato)**  
   - Implementato in `audit.py`.  
   - Genera un report completo:  
     - Metodo di pairing e *association model* (Just Works, Passkey, Numeric Comparison, OOB)  
     - Security Mode 1 Level (L1–L4)  
     - Flag Secure Connections, MITM, bonding  
     - Dimensione chiavi  
     - Privacy degli indirizzi (public/static/random/RPA)  
     - Visibilità ATT/GATT pre e post cifratura  
   - Output: report **Markdown** + esportazioni opzionali JSON/CSV.

---

## ⚙️ Requisiti

- **Python** ≥ 3.8  
- **Dipendenze Python**: installare manualmente `pyshark`  
  ```bash
  pip install pyshark
  ```
- **Strumenti esterni**:  
  - `editcap` (parte di Wireshark)  
  - **SnifferAPI** (cartella `extcap` dal pacchetto ufficiale [nRF Sniffer for Bluetooth LE](https://www.nordicsemi.com/Products/Development-tools/nRF-Sniffer-for-Bluetooth-LE))  
- **Hardware richiesto**:  
  - **nRF52840 Dongle** (Nordic) – necessario per avviare la pipeline e catturare il traffico BLE  
  - Qualsiasi dispositivo BLE (mouse, fascia cardio, DK nRF54L15, ciclocomputer, ecc.) per i test sperimentali

---

## 🖥️ Setup ambiente

### 1. Preparazione
Scarica dal sito Nordic il pacchetto **nRF Sniffer for Bluetooth LE** e copia la cartella `extcap` (contenente SnifferAPI) nella root del progetto.

### 2. Ambiente virtuale
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install pyshark
```

---

## ▶️ Esempi d’uso

1. **Eseguire la pipeline completa** (cattura di 60s, base `test1`, output report `test1_audit.md`):  
```bash
python ble_pipeline.py --dur 60 --base test1 --report test1_audit.md
```

2. **Audit su file filtrati già disponibili** (`*_Filt.json`):  
```bash
python audit.py --input test1_Filt.json --md test1_audit.md
```

---

## 🇬🇧 Description (English)

This repository contains the code developed for my **Bachelor’s Thesis in Computer and Network Security** at the University of Milan.  

The goal of the project is to build an **automated pipeline** to analyze the security of **Bluetooth Low Energy (BLE)** connections.  

### Main files
- **`ble_pipeline.py`** → runs the full pipeline: capture → convert → parse → filter → audit.  
- **`audit.py`** → runs the audit on pre-filtered JSON files.  

To work properly, the following directory must be present in the same folder:  
```
./SnifferAPI/
```
containing the official **SnifferAPI** library extracted from the *nRF Sniffer for Bluetooth LE* package provided by Nordic Semiconductor.

### Other files in the repository
Other files and folders are included as **evidence and supporting material for the thesis** (reports, capture examples, documentation).  
They are **not required** to run the pipeline.

## 🔍 Key features

The pipeline (`ble_pipeline.py`) consists of five steps:

1. **Capture**  
   - Uses the **Nordic SnifferAPI** to capture BLE traffic with an nRF52840 dongle.  
   - Output: `.pcap` file.

2. **Conversion**  
   - Automatically converts `.pcap` → `.pcapng` with `editcap` (Wireshark).  
   - Ensures compatibility with `tshark`/PyShark.

3. **Parsing**  
   - Analyzes packets with **PyShark**.  
   - Serializes robust JSON (equivalent to Wireshark `pkt.show()`).  
   - Output: `<trace>.json`.

4. **Filtering**  
   - Removes generic advertising, scan responses, and empty PDUs.  
   - Keeps only relevant events (CONNECT_IND/REQ, SMP, encryption, ATT).  
   - Output: `<trace>_Filt.json`.

5. **Audit (advanced)**  
   - Implemented in `audit.py`.  
   - Produces a detailed report including:  
     - Pairing method and association model (Just Works, Passkey, Numeric Comparison, OOB)  
     - Security Mode 1 Level (L1–L4)  
     - Secure Connections, MITM, bonding  
     - Key size  
     - BLE address privacy (public/static/random/RPA)  
     - ATT/GATT visibility before and after encryption  
   - Output: **Markdown report** + optional JSON/CSV exports.

---

## ⚙️ Requirements

- **Python** ≥ 3.8  
- **Python dependencies**: install `pyshark` manually  
  ```bash
  pip install pyshark
  ```
- **External tools**:  
  - `editcap` (part of Wireshark)  
  - **SnifferAPI** (from the official [nRF Sniffer for Bluetooth LE](https://www.nordicsemi.com/Products/Development-tools/nRF-Sniffer-for-Bluetooth-LE))  
- **Hardware required**:  
  - **nRF52840 Dongle** (Nordic) – required to start the pipeline and capture BLE traffic  
  - Any BLE device (mouse, heart rate strap, nRF54L15 DK, bike computer, etc.) for testing

---

## 🖥️ Environment setup

### 1. Preparation
Download the official **nRF Sniffer for Bluetooth LE** package from Nordic and copy the `extcap` folder (with SnifferAPI) into the project root.

### 2. Virtual environment
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install pyshark
```

---

## ▶️ Usage examples

1. **Run full pipeline** (60s capture, base `test1`, output report `test1_audit.md`):  
```bash
python ble_pipeline.py --dur 60 --base test1 --report test1_audit.md
```

2. **Audit only** on pre-filtered JSON (`*_Filt.json`):  
```bash
python audit.py --input test1_Filt.json --md test1_audit.md
```

