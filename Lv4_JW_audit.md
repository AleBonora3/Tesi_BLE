# BLE Pairing Report – Lv4_JW_Filt.json
- Record totali: 83
- Cifratura attiva: No
- Connessione: #192 (CONNECT_IND)

## Indirizzi e Tipologia
- initiator: 62:d2:e2:e5:2b:28  →  private_resolvable
- advertiser: 15:17:fe:9f:03:03  →  public_or_non_resolvable
- master: 7a:94:51:c5:49:f9  →  private_resolvable
- slave: c0:48:ff:f5:9d:b8  →  static_random

## Traccia SMP
- #1307: PAIRING_REQ
- #1310: PAIRING_RSP
- #1353: PAIRING_PUBLIC_KEY
- #1356: PAIRING_PUBLIC_KEY
- #1358: PAIRING_CONFIRM
- #1359: PAIRING_RANDOM
- #1362: PAIRING_RANDOM
- #1363: PAIRING_DHKEY_CHECK
- #1366: PAIRING_DHKEY_CHECK

## Eventi LL legati alla cifratura
- #1369: LL_ENC_REQ
- #1372: LL_ENC_RSP
- #1376: LL_START_ENC_REQ

## Pairing (REQ/RSP, sez. 4.2)
- Richiesta  #1307: IO=KeyboardDisplay, OOB=No, MITM=Sì, SC=Sì, KeySizeMax=16, Bonding=Sì, Keypress=No
- Risposta   #1310: IO=NoInputNoOutput, OOB=No, MITM=No, SC=Sì, KeySizeMax=16, Bonding=Sì, Keypress=No
→ **Metodo di pairing**: Just Works (LESC)  (Association model: Just Works; SC entrambi: Sì, OOB entrambi: No, Key size effettiva: 16)

## Livello di Sicurezza Stimato: Mode 1 Level 4
> LE Secure Connections con autenticazione
_Criteri:_ LE Secure Connections, key size effettiva=16

## ATT/GATT visibili
### In chiaro (prima della cifratura)
- #846: Exchange MTU Request (MTU=527)
- #849: Exchange MTU Response (MTU=65)
- #850: Read By Group Type Request (handle 0xFFFF)
- #853: Read By Group Type Response
- #854: Read By Group Type Request (handle 0xFFFF)
- #857: Read By Group Type Response (handle 0x0010)
- #858: Read By Group Type Request (handle 0xFFFF)
- #861: Read Request (handle 0x0016)
- #862: Read By Type Request (handle 0x0008)
- #865: Read By Type Response
- #866: Find Information Request (handle 0x0008)
- #869: Find Information Response
- #870: Write Request (handle 0x0004)
- #873: Write Response (handle 0x0004)
- #874: Read By Type Request (handle 0x0015)
- #877: Read By Type Response
- #878: Find Information Request (handle 0x0013)
- #881: Find Information Response (handle 0x0013)
- #956: Write Request (handle 0x0013)
- #959: Write Response (handle 0x0013)
- #1048: Read By Type Request (handle 0x000F)
- #1051: Read By Type Response (handle 0x000B)
- #1055: Handle Value Notification (handle 0x0012)
- #1089: Handle Value Notification (handle 0x0012)
- #1113: Handle Value Notification (handle 0x0012)
- #1129: Handle Value Notification (handle 0x0012)
- #1160: Handle Value Notification (handle 0x0012)
- #1190: Handle Value Notification (handle 0x0012)
- #1303: Write Request (handle 0x0015)
- #1306: Find Information Response (handle 0x0015)

---