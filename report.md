# BLE Pairing Report – capture_Filt.json
- Record totali: 80
- Cifratura attiva: Sì
- Connessione: #526 (CONNECT_IND)
- Primo pacchetto cifrato: #1178

## Indirizzi e Tipologia
- initiator: 51:d1:b9:0c:ac:f7  →  private_resolvable
- advertiser: c0:48:ff:f5:9d:b8  →  static_random
- master: 51:d1:b9:0c:ac:f7  →  private_resolvable
- slave: c0:48:ff:f5:9d:b8  →  static_random

## Traccia SMP
- #1114: PAIRING_REQ
- #1117: PAIRING_RSP
- #1154: PAIRING_PUBLIC_KEY
- #1157: PAIRING_PUBLIC_KEY
- #1159: PAIRING_CONFIRM
- #1160: PAIRING_RANDOM
- #1163: PAIRING_RANDOM
- #1164: PAIRING_DHKEY_CHECK
- #1167: PAIRING_DHKEY_CHECK

## Eventi LL legati alla cifratura
- #1170: LL_ENC_REQ
- #1173: LL_ENC_RSP
- #1177: LL_START_ENC_REQ

## Pairing (REQ/RSP, sez. 4.2)
- Richiesta  #1114: IO=KeyboardDisplay, OOB=No, MITM=Sì, SC=Sì, KeySizeMax=16, Bonding=Sì, Keypress=No
- Risposta   #1117: IO=NoInputNoOutput, OOB=No, MITM=No, SC=Sì, KeySizeMax=16, Bonding=Sì, Keypress=No
→ **Metodo di pairing**: Just Works (LESC)  (Association model: Just Works; SC entrambi: Sì, OOB entrambi: No, Key size effettiva: 16)

## Livello di Sicurezza Stimato: Mode 1 Level 4
> LE Secure Connections con autenticazione
_Criteri:_ cifratura osservata, LE Secure Connections, key size effettiva=16

## ATT/GATT visibili
### In chiaro (prima della cifratura)
- #563: Exchange MTU Request (MTU=527)
- #566: Exchange MTU Response (MTU=65)
- #567: Read By Group Type Request (handle 0xFFFF)
- #570: Read By Group Type Response
- #571: Read By Group Type Request (handle 0xFFFF)
- #574: Read By Group Type Response (handle 0x0010)
- #575: Read By Group Type Request (handle 0xFFFF)
- #578: Error Response (handle 0x0016)
- #579: Read By Type Request (handle 0x0008)
- #582: Read By Type Response
- #583: Find Information Request (handle 0x0008)
- #586: Find Information Response
- #587: Write Request (handle 0x0004)
- #590: Write Response (handle 0x0004)
- #591: Read By Type Request (handle 0x0015)
- #594: Read By Type Response
- #595: Find Information Request (handle 0x0013)
- #598: Find Information Response (handle 0x0013)
- #701: Read By Type Request (handle 0x000F)
- #704: Read By Type Response (handle 0x000B)
- #717: Write Request (handle 0x0013)
- #720: Write Response (handle 0x0013)
- #879: Handle Value Notification (handle 0x0012)
- #905: Handle Value Notification (handle 0x0012)
- #937: Handle Value Notification (handle 0x0012)
- #981: Handle Value Notification (handle 0x0012)
- #1110: Write Request (handle 0x0015)
- #1113: Error Response (handle 0x0015)

---