# BLE Pairing Report – capture_Filt.json
- Record totali: 80
- Cifratura attiva: No
- Traccia SMP (prime occorrenze): #2346:PAIRING_REQ, #2349:PAIRING_RSP, #2385:PAIRING_PUBLIC_KEY, #2388:PAIRING_PUBLIC_KEY, #2390:PAIRING_CONFIRM, #2391:PAIRING_RANDOM, #2394:PAIRING_RANDOM, #2395:PAIRING_DHKEY_CHECK, #2398:PAIRING_DHKEY_CHECK

## Livello di Sicurezza Stimato: Mode 1 Level 1
> Nessuna cifratura, nessuna autenticazione (Mode 1 Level 1).
_Criteri:_ LE Secure Connections, key size effettiva=16

## Pairing (REQ/RSP, sez. 4.2)
- Richiesta  #2346: IO=KeyboardDisplay, OOB=No, MITM=Sì, SC=Sì, KeySizeMax=16, Bonding=Sì, Keypress=No
- Risposta   #2349: IO=NoInputNoOutput, OOB=No, MITM=No, SC=Sì, KeySizeMax=16, Bonding=Sì, Keypress=No
→ **Metodo di pairing**: Just Works (LESC)  (Association model: Just Works; SC entrambi: Sì, OOB entrambi: No, Key size effettiva: 16)

## Indirizzi e Tipologia
- initiator: 69:3d:a9:5a:e6:30  →  private_resolvable

## ATT/GATT visibili
### In chiaro (prima della cifratura)
- #1966: Exchange MTU Request (MTU=527)
- #1969: Exchange MTU Response (MTU=65)
- #1970: Read By Group Type Request (handle 0xFFFF)
- #1973: Read By Group Type Response
- #1974: Read By Group Type Request (handle 0xFFFF)
- #1977: Read By Group Type Response (handle 0x0010)
- #1978: Read By Group Type Request (handle 0xFFFF)
- #1981: Read Request (handle 0x0016)
- #1982: Read By Type Request (handle 0x0008)
- #1985: Read By Type Response
- #1986: Find Information Request (handle 0x0008)
- #1989: Find Information Response
- #1990: Write Request (handle 0x0004)
- #1993: Write Response (handle 0x0004)
- #1994: Read By Type Request (handle 0x0015)
- #1997: Read By Type Response
- #1998: Find Information Request (handle 0x0013)
- #2097: Read By Type Request (handle 0x000F)
- #2100: Read By Type Response (handle 0x000B)
- #2125: Write Request (handle 0x0013)
- #2128: Write Response (handle 0x0013)
- #2184: Handle Value Notification (handle 0x0012)
- #2202: Handle Value Notification (handle 0x0012)
- #2210: Handle Value Notification (handle 0x0012)
- #2228: Handle Value Notification (handle 0x0012)
- #2342: Write Request (handle 0x0015)
- #2345: Find Information Response (handle 0x0015)

---