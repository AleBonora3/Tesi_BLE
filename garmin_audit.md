# BLE Pairing Report – garmin_Filt.json
- Record totali: 174
- Cifratura attiva: Sì
- Connessione: #3479 (CONNECT_IND)
- Primo pacchetto cifrato: #4698

## Indirizzi e Tipologia
- master: 40:63:de:11:1c:3d  →  private_resolvable
- slave: d1:5c:f0:ee:02:8f  →  static_random

## Traccia SMP
- #4485: SECURITY_REQUEST
- #4486: PAIRING_REQ
- #4493: PAIRING_RSP
- #4496: PAIRING_PUBLIC_KEY
- #4502: PAIRING_PUBLIC_KEY
- #4504: PAIRING_CONFIRM
- #4507: PAIRING_RANDOM
- #4512: PAIRING_RANDOM
- #4684: PAIRING_DHKEY_CHECK
- #4687: PAIRING_DHKEY_CHECK

## Eventi LL legati alla cifratura
- #4690: LL_ENC_REQ
- #4693: LL_ENC_RSP
- #4697: LL_START_ENC_REQ

## Pairing (REQ/RSP, sez. 4.2)
- Richiesta  #4486: IO=KeyboardDisplay, OOB=No, MITM=Sì, SC=Sì, KeySizeMax=16, Bonding=Sì, Keypress=No
- Risposta   #4493: IO=DisplayYesNo, OOB=No, MITM=Sì, SC=Sì, KeySizeMax=16, Bonding=Sì, Keypress=No
→ **Metodo di pairing**: Numeric Comparison (LESC)  (Association model: Numeric Comparison; SC entrambi: Sì, OOB entrambi: No, Key size effettiva: 16)

## Livello di Sicurezza Stimato: Mode 1 Level 4
> LE Secure Connections con autenticazione
_Criteri:_ cifratura osservata, LE Secure Connections, autenticazione MITM/metodo autenticato, key size effettiva=16

## ATT/GATT visibili
### In chiaro (prima della cifratura) [tot: 45]
- #4425: (2, 'Exchange MTU Request (MTU=226)')
- #4450: (3, 'Exchange MTU Response (MTU=226)')
- #4452: (16, 'Read By Group Type Request (handle 0xFFFF)')
- #4455: (17, 'Read By Group Type Response')
- #4457: (16, 'Read By Group Type Request (handle 0xFFFF)')
- #4458: (16, 'Read By Group Type Request (handle 0xFFFF)')
- #4460: (17, 'Read By Group Type Response')
- #4463: (17, 'Read By Group Type Response (handle 0x000E)')
- #4465: (16, 'Read By Group Type Request (handle 0xFFFF)')
- #4466: (16, 'Read By Group Type Request (handle 0xFFFF)')
- #4468: (17, 'Read By Group Type Response')
- #4471: (17, 'Read By Group Type Response (handle 0x0014)')
- #4473: (16, 'Read By Group Type Request (handle 0xFFFF)')
- #4475: (10, 'Read Request (handle 0x002B)')
- #4477: (16, 'Read By Group Type Request (handle 0xFFFF)')
- #4478: (17, 'Read By Group Type Response')
- #4480: (8, 'Read By Type Request (handle 0x0009)')
- #4483: (9, 'Read By Type Response (handle 0x0003)')
- #4488: (8, 'Read By Type Request (handle 0x000D)')
- #4491: (9, 'Read By Type Response')
- #4494: (4, 'Find Information Request (handle 0x000D)')
- #4500: (5, 'Find Information Response (handle 0x000D)')
- #4505: (18, 'Write Request (handle 0x000D)')
- #4510: (19, 'Write Response (handle 0x000D)')
- #4513: (8, 'Read By Type Request (handle 0x002A)')
- #4516: (9, 'Read By Type Response')
- #4517: (8, 'Read By Type Request (handle 0x002A)')
- #4520: (9, 'Read By Type Response')
- #4521: (8, 'Read By Type Request (handle 0x002A)')
- #4524: (9, 'Read By Type Response')
- #4525: (8, 'Read By Type Request (handle 0x002A)')
- #4528: (9, 'Read By Type Response')
- #4529: (8, 'Read By Type Request (handle 0x002A)')
- #4532: (9, 'Read By Type Response')
- #4533: (8, 'Read By Type Request (handle 0x002A)')
- #4536: (9, 'Read By Type Response')
- #4537: (8, 'Read By Type Request (handle 0x002A)')
- #4540: (9, 'Read By Type Response')
- #4541: (8, 'Read By Type Request (handle 0x002A)')
- #4544: (9, 'Read By Type Response')
- #4545: (8, 'Read By Type Request (handle 0x002A)')
- #4548: (9, 'Read By Type Response')
- #4549: (4, 'Find Information Request (handle 0x0019)')
- #4552: (5, 'Find Information Response (handle 0x0019)')
- #4553: (18, 'Write Request (handle 0x0019)')
### Dopo l'attivazione della cifratura [ATT visibili: 0]
- Pacchetti cifrati totali: 101
- Pacchetti cifrati non decifrati: 101
- Range cifratura: #4698 → #4878


---