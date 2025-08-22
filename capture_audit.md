# BLE Pairing Report – capture_Filt.json
- Record totali: 74
- Cifratura attiva: Sì
- Connessione: #1591 (CONNECT_IND)
- Primo pacchetto cifrato: #1592

## Indirizzi e Tipologia
- initiator: 50:f1:88:88:29:27  →  private_resolvable
- advertiser: c0:48:ff:f5:9d:b8  →  static_random
- master: 50:f1:88:88:29:27  →  private_resolvable
- slave: c0:48:ff:f5:9d:b8  →  static_random

## Traccia SMP
- #2221: PAIRING_REQ
- #2224: PAIRING_RSP
- #2277: PAIRING_PUBLIC_KEY
- #2280: PAIRING_PUBLIC_KEY
- #2282: PAIRING_CONFIRM
- #2283: PAIRING_RANDOM
- #2286: PAIRING_RANDOM
- #2287: PAIRING_DHKEY_CHECK
- #2290: PAIRING_DHKEY_CHECK

## Eventi LL legati alla cifratura
- #2293: LL_ENC_REQ
- #2296: LL_ENC_RSP
- #2300: LL_START_ENC_REQ

## Pairing (REQ/RSP, sez. 4.2)
- Richiesta  #2221: IO=KeyboardDisplay, OOB=No, MITM=Sì, SC=Sì, KeySizeMax=16, Bonding=Sì, Keypress=No
- Risposta   #2224: IO=NoInputNoOutput, OOB=No, MITM=No, SC=Sì, KeySizeMax=16, Bonding=Sì, Keypress=No
→ **Metodo di pairing**: Just Works (LESC)  (Association model: Just Works; SC entrambi: Sì, OOB entrambi: No, Key size effettiva: 16)

## Livello di Sicurezza Stimato: Mode 1 Level 4
> LE Secure Connections con autenticazione
_Criteri:_ cifratura osservata, LE Secure Connections, ri-cifratura senza scambio SMP (sospetto bonding), key size effettiva=16

## ATT/GATT visibili
### Dopo l'attivazione della cifratura
- #1628: Exchange MTU Request (MTU=527)
- #1631: Exchange MTU Response (MTU=65)
- #1632: Read By Group Type Request (handle 0xFFFF)
- #1635: Read By Group Type Response
- #1636: Read By Group Type Request (handle 0xFFFF)
- #1639: Read By Group Type Response (handle 0x0010)
- #1640: Read By Group Type Request (handle 0xFFFF)
- #1643: Error Response (handle 0x0016)
- #1644: Read By Type Request (handle 0x0008)
- #1647: Read By Type Response
- #1648: Find Information Request (handle 0x0008)
- #1651: Find Information Response
- #1652: Write Request (handle 0x0004)
- #1655: Write Response (handle 0x0004)
- #1656: Read By Type Request (handle 0x0015)
- #1659: Read By Type Response
- #1660: Find Information Request (handle 0x0013)
- #1663: Find Information Response (handle 0x0013)
- #1766: Read By Type Request (handle 0x000F)
- #1769: Read By Type Response (handle 0x000B)
- #1770: Write Request (handle 0x0013)
- #1773: Write Response (handle 0x0013)
- #1863: Handle Value Notification (handle 0x0012)
- #1934: Handle Value Notification (handle 0x0012)
- #1976: Handle Value Notification (handle 0x0012)
- #2020: Handle Value Notification (handle 0x0012)
- #2217: Write Request (handle 0x0015)
- #2220: Error Response (handle 0x0015)

---