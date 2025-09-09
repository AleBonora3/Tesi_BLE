# BLE End-to-End Security Pipeline  
*(capture → convert → parse → filter → audit)*

## 🇮🇹 Descrizione (Italiano)

Questo repository contiene il codice sviluppato per la mia **tesi triennale in Sicurezza dei Sistemi e delle Reti Informatiche** presso l’Università degli Studi di Milano.  

L’obiettivo del progetto è realizzare una **pipeline automatizzata** per l’analisi della sicurezza delle connessioni **Bluetooth Low Energy (BLE)**.  

### File principali
- **`ble_pipeline.py`** → avvia l’intera pipeline: cattura → conversione → parsing → filtro → audit.  
- **`audit.py`** → esegue l’audit su file JSON già filtrati.  

⚠️ Per funzionare, nella stessa cartella deve essere presente la directory:  
```
./SnifferAPI/
```
contenente la libreria ufficiale **SnifferAPI** estratta dal pacchetto *nRF Sniffer for Bluetooth LE* fornito da Nordic Semiconductor.

### Altri file nel repository
Gli altri file e cartelle presenti servono come **evidenze e materiali di supporto alla tesi** (report, esempi di catture, documentazione).  
Non sono necessari per l’esecuzione della pipeline.

### Requisiti
- **Hardware**: dongle **nRF52840** con firmware *nRF Sniffer*  
- **Software**:  
  - Python ≥ 3.8  
  - Dipendenze Python: `pyshark`  
  - Wireshark (per `editcap`/`tshark`)  
  - Cartella **SnifferAPI** nella root del progetto  

### Avvio rapido

# Ambiente virtuale Python (opzionale ma consigliato)
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Avvio pipeline (cattura + analisi completa)
python ble_pipeline.py --dur 60 --base test1 --report test1_audit.md

# Audit su file JSON già filtrato
python audit.py --input test1_Filt.json --md test1_audit.md

---

## 🇬🇧 Description (English)

This repository contains the code developed for my **Bachelor’s Thesis in Computer and Network Security** at the University of Milan.  

The project implements an **automated pipeline** for analyzing the security of **Bluetooth Low Energy (BLE)** connections.  

### Main files
- **`ble_pipeline.py`** → runs the full pipeline: capture → convert → parse → filter → audit.  
- **`audit.py`** → performs the audit on pre-filtered JSON files.  

⚠️ To work correctly, the project folder must include:  
```
./SnifferAPI/
```
which contains the official **SnifferAPI** library extracted from the *nRF Sniffer for Bluetooth LE* package by Nordic Semiconductor.

### Other files in the repository
All other files and folders are provided as **supporting evidence for the thesis** (reports, capture examples, documentation).  
They are **not required** to run the pipeline.

### Requirements
- **Hardware**: **nRF52840 dongle** with *nRF Sniffer* firmware  
- **Software**:  
  - Python ≥ 3.8  
  - Python dependencies: `pyshark`  
  - Wireshark (for `editcap`/`tshark`)  
  - **SnifferAPI** folder in the project root  

### Quick start

# Python virtual environment (optional but recommended)
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run the full pipeline (capture + analysis)
python ble_pipeline.py --dur 60 --base test1 --report test1_audit.md

# Run audit only on filtered JSON file
python audit.py --input test1_Filt.json --md test1_audit.md
```
