# Tesi_BLE

## Setup ambiente

### Requisiti di sistema (Ubuntu/Debian)
- Python 3.10+ consigliato
- **tshark** (necessario per pyshark):
  ```bash
  sudo apt update
  sudo apt install -y tshark
  # (opzionale) permette a tshark di catturare senza sudo
  sudo dpkg-reconfigure wireshark-common
  sudo usermod -aG wireshark $USER
  # poi fai logout/login
