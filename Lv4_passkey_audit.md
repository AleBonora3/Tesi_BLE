# BLE Pairing Report – Lv4_passkey_Filt.json
- Record totali: 152
- Cifratura attiva: Sì
- Connessione: #2725 (CONNECT_IND)
- Primo pacchetto cifrato: #3724

## Indirizzi e Tipologia
- initiator: 69:9d:fc:24:53:0f  →  private_resolvable
- advertiser: c0:48:ff:f5:9d:b8  →  static_random
- master: 69:9d:fc:24:53:0f  →  private_resolvable
- slave: c0:48:ff:f5:9d:b8  →  static_random

## Traccia SMP
- #3239: PAIRING_REQ
- #3242: PAIRING_RSP
- #3243: PAIRING_PUBLIC_KEY
- #3246: PAIRING_PUBLIC_KEY
- #3550: PAIRING_CONFIRM
- #3553: PAIRING_CONFIRM
- #3554: PAIRING_RANDOM
- #3557: PAIRING_RANDOM
- #3558: PAIRING_CONFIRM
- #3561: PAIRING_CONFIRM
- #3562: PAIRING_RANDOM
- #3565: PAIRING_RANDOM
- #3566: PAIRING_CONFIRM
- #3569: PAIRING_CONFIRM
- #3570: PAIRING_RANDOM
- #3573: PAIRING_RANDOM
- #3574: PAIRING_CONFIRM
- #3577: PAIRING_CONFIRM
- #3578: PAIRING_RANDOM
- #3581: PAIRING_RANDOM
- #3582: PAIRING_CONFIRM
- #3585: PAIRING_CONFIRM
- #3586: PAIRING_RANDOM
- #3589: PAIRING_RANDOM
- #3590: PAIRING_CONFIRM
- #3593: PAIRING_CONFIRM
- #3594: PAIRING_RANDOM
- #3597: PAIRING_RANDOM
- #3598: PAIRING_CONFIRM
- #3601: PAIRING_CONFIRM
- #3602: PAIRING_RANDOM
- #3605: PAIRING_RANDOM
- #3606: PAIRING_CONFIRM
- #3609: PAIRING_CONFIRM
- #3610: PAIRING_RANDOM
- #3613: PAIRING_RANDOM
- #3614: PAIRING_CONFIRM
- #3617: PAIRING_CONFIRM
- #3618: PAIRING_RANDOM
- #3621: PAIRING_RANDOM
- #3622: PAIRING_CONFIRM
- #3625: PAIRING_CONFIRM
- #3626: PAIRING_RANDOM
- #3629: PAIRING_RANDOM
- #3630: PAIRING_CONFIRM
- #3633: PAIRING_CONFIRM
- #3634: PAIRING_RANDOM
- #3637: PAIRING_RANDOM
- #3638: PAIRING_CONFIRM
- #3641: PAIRING_CONFIRM
- #3642: PAIRING_RANDOM
- #3645: PAIRING_RANDOM
- #3646: PAIRING_CONFIRM
- #3649: PAIRING_CONFIRM
- #3650: PAIRING_RANDOM
- #3653: PAIRING_RANDOM
- #3654: PAIRING_CONFIRM
- #3657: PAIRING_CONFIRM
- #3658: PAIRING_RANDOM
- #3661: PAIRING_RANDOM
- #3662: PAIRING_CONFIRM
- #3665: PAIRING_CONFIRM
- #3666: PAIRING_RANDOM
- #3669: PAIRING_RANDOM
- #3670: PAIRING_CONFIRM
- #3673: PAIRING_CONFIRM
- #3674: PAIRING_RANDOM
- #3677: PAIRING_RANDOM
- #3678: PAIRING_CONFIRM
- #3681: PAIRING_CONFIRM
- #3682: PAIRING_RANDOM
- #3685: PAIRING_RANDOM
- #3686: PAIRING_CONFIRM
- #3689: PAIRING_CONFIRM
- #3690: PAIRING_RANDOM
- #3693: PAIRING_RANDOM
- #3694: PAIRING_CONFIRM
- #3697: PAIRING_CONFIRM
- #3698: PAIRING_RANDOM
- #3701: PAIRING_RANDOM
- #3702: PAIRING_CONFIRM
- #3705: PAIRING_CONFIRM
- #3706: PAIRING_RANDOM
- #3709: PAIRING_RANDOM
- #3710: PAIRING_DHKEY_CHECK
- #3713: PAIRING_DHKEY_CHECK

## Eventi LL legati alla cifratura
- #3716: LL_ENC_REQ
- #3719: LL_ENC_RSP
- #3723: LL_START_ENC_REQ
- #3724: LL_START_ENC_RSP

## Pairing (REQ/RSP, sez. 4.2)
- Richiesta  #3239: IO=KeyboardDisplay, OOB=No, MITM=Sì, SC=Sì, KeySizeMax=16, Bonding=Sì, Keypress=No
- Risposta   #3242: IO=DisplayOnly, OOB=No, MITM=Sì, SC=Sì, KeySizeMax=16, Bonding=Sì, Keypress=No
→ **Metodo di pairing**: Passkey Entry (LESC)  (Association model: Passkey Entry; SC entrambi: Sì, OOB entrambi: No, Key size effettiva: 16)

## Livello di Sicurezza Stimato: Mode 1 Level 4
> LE Secure Connections con autenticazione
_Criteri:_ cifratura osservata, LE Secure Connections, autenticazione MITM/metodo autenticato, key size effettiva=16

## ATT/GATT visibili
### In chiaro (prima della cifratura)
- #2760: Exchange MTU Request (MTU=527)
- #2763: Exchange MTU Response (MTU=65)
- #2764: Read By Group Type Request (handle 0x0001)
- #2767: Read By Group Type Response
- #2768: Read By Group Type Request (handle 0x0010)
- #2771: Read By Group Type Response (handle 0x0015)
- #2772: Read By Group Type Request (handle 0x0016)
- #2775: Read Request (handle 0x0016)
- #2776: Read By Type Request (handle 0x0001)
- #2779: Read By Type Response
- #2780: Find Information Request (handle 0x0004)
- #2783: Find Information Response
- #2784: Write Request (handle 0x0004)
- #2787: Write Response (handle 0x0004)
- #2788: Read By Type Request (handle 0x0010)
- #2791: Read By Type Response
- #2792: Find Information Request (handle 0x0013)
- #2795: Find Information Response (handle 0x0013)
- #2892: Read By Type Request (handle 0x0009)
- #2895: Read By Type Response (handle 0x000B)
- #2898: Write Request (handle 0x0013)
- #2901: Write Response (handle 0x0013)
- #2980: Handle Value Notification (handle 0x0012)
- #3028: Handle Value Notification (handle 0x0012)
- #3080: Handle Value Notification (handle 0x0012)
- #3112: Handle Value Notification (handle 0x0012)
- #3235: Write Request (handle 0x0015)
- #3238: Find Information Response (handle 0x0015)

---