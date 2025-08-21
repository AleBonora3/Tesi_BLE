# BLE Pairing Report – capture_Filt.json
- Record totali: 79
- Cifratura attiva: No
- Eventi LL legati alla cifratura (prime occorrenze): #653:LL_PAUSE_ENC_RSP, #1094:LL_ENC_REQ, #1097:LL_ENC_RSP, #1101:LL_START_ENC_REQ
- Traccia SMP (prime occorrenze): #1036:PAIRING_REQ, #1039:PAIRING_RSP, #1078:PAIRING_PUBLIC_KEY, #1081:PAIRING_PUBLIC_KEY, #1083:PAIRING_CONFIRM, #1084:PAIRING_RANDOM, #1087:PAIRING_RANDOM, #1088:PAIRING_DHKEY_CHECK, #1091:PAIRING_DHKEY_CHECK

## Livello di Sicurezza Stimato: Mode 1 Level 1
> Nessuna cifratura, nessuna autenticazione (Mode 1 Level 1).
_Criteri:_ LE Secure Connections, key size effettiva=16

## Pairing (REQ/RSP, sez. 4.2)
- Richiesta  #1036: IO=KeyboardDisplay, OOB=No, MITM=Sì, SC=Sì, KeySizeMax=16, Bonding=Sì, Keypress=No
- Risposta   #1039: IO=NoInputNoOutput, OOB=No, MITM=No, SC=Sì, KeySizeMax=16, Bonding=Sì, Keypress=No
→ **Metodo di pairing**: Just Works (LESC)  (Association model: Just Works; SC entrambi: Sì, OOB entrambi: No, Key size effettiva: 16)

## Indirizzi e Tipologia
- initiator: 40:f1:98:b9:d1:03  →  private_resolvable
- master: 40:f1:98:b9:d1:03  →  private_resolvable
- slave: c0:48:ff:f5:9d:b8  →  static_random

## ATT/GATT visibili
### In chiaro (prima della cifratura)
- #685: Exchange MTU Request (MTU=527)
- #688: Exchange MTU Response (MTU=65)
- #689: Read By Group Type Request (handle 0x0001)
- #692: Read By Group Type Response
- #693: Read By Group Type Request (handle 0x0010)
- #696: Read By Group Type Response (handle 0x0010)
- #697: Read By Group Type Request (handle 0x0016)
- #700: Read Request (handle 0x0016)
- #701: Read By Type Request (handle 0x0001)
- #704: Read By Type Response
- #705: Find Information Request (handle 0x0004)
- #708: Find Information Response
- #709: Write Request (handle 0x0004)
- #712: Write Response (handle 0x0004)
- #713: Read By Type Request (handle 0x0010)
- #716: Read By Type Response
- #717: Find Information Request (handle 0x0013)
- #720: Find Information Response (handle 0x0013)
- #821: Read By Type Request (handle 0x0009)
- #824: Read By Type Response (handle 0x000B)
- #825: Write Request (handle 0x0013)
- #828: Write Response (handle 0x0013)
- #1032: Write Request (handle 0x0015)
- #1035: Find Information Response (handle 0x0015)

---