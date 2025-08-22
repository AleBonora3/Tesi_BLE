# BLE Pairing Report – Lv2_SC_Filt.json
- Record totali: 77
- Cifratura attiva: Sì
- Primo pacchetto cifrato: #5848
- Traccia SMP (prime occorrenze): #5776:PAIRING_REQ, #5779:PAIRING_RSP, #5824:PAIRING_PUBLIC_KEY, #5827:PAIRING_PUBLIC_KEY, #5829:PAIRING_CONFIRM, #5830:PAIRING_RANDOM, #5833:PAIRING_RANDOM, #5834:PAIRING_DHKEY_CHECK, #5837:PAIRING_DHKEY_CHECK

## Livello di Sicurezza Stimato: Mode 1 Level 2
> Cifratura senza autenticazione (es. Just Works) (Mode 1 Level 2).
_Criteri:_ cifratura osservata, LE Secure Connections, key size effettiva=16

## Pairing (REQ/RSP, sez. 4.2)
- Richiesta  #5776: IO=KeyboardDisplay, OOB=No, MITM=Sì, SC=Sì, KeySizeMax=16, Bonding=Sì, Keypress=No
- Risposta   #5779: IO=NoInputNoOutput, OOB=No, MITM=No, SC=Sì, KeySizeMax=16, Bonding=Sì, Keypress=No
→ **Metodo di pairing**: Just Works (LESC)  (Association model: Just Works; SC entrambi: Sì, OOB entrambi: No, Key size effettiva: 16)

## Indirizzi e Tipologia
- Non rilevati.

## ATT/GATT visibili
### In chiaro (prima della cifratura)
- #5193: Exchange MTU Request (MTU=527)
- #5196: Exchange MTU Response (MTU=65)
- #5197: Read By Group Type Request (handle 0xFFFF)
- #5200: Read By Group Type Response
- #5201: Read By Group Type Request (handle 0xFFFF)
- #5204: Read By Group Type Response (handle 0x0010)
- #5205: Read By Group Type Request (handle 0xFFFF)
- #5208: Error Response (handle 0x0016)
- #5209: Read By Type Request (handle 0x0008)
- #5212: Read By Type Response
- #5213: Find Information Request (handle 0x0008)
- #5216: Find Information Response
- #5217: Write Request (handle 0x0004)
- #5220: Write Response (handle 0x0004)
- #5221: Read By Type Request (handle 0x0015)
- #5224: Read By Type Response
- #5225: Find Information Request (handle 0x0013)
- #5228: Find Information Response (handle 0x0013)
- #5329: Read By Type Request (handle 0x000F)
- #5332: Read By Type Response (handle 0x000B)
- #5528: Write Request (handle 0x0013)
- #5531: Write Response (handle 0x0013)
- #5639: Handle Value Notification (handle 0x0012)
- #5653: Handle Value Notification (handle 0x0012)
- #5659: Handle Value Notification (handle 0x0012)
- #5673: Handle Value Notification (handle 0x0012)
- #5772: Write Request (handle 0x0015)
- #5775: Error Response (handle 0x0015)

---