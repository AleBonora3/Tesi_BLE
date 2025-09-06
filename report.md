# BLE Pairing Report – mouse_Filt.json
- Record totali: 220
- Cifratura attiva: Sì
- Connessione: #953 (CONNECT_IND)
- Primo pacchetto cifrato: #1181

## Indirizzi e Tipologia
- master: 70:bd:85:30:35:56  →  private_resolvable
- slave: e2:e0:6b:31:00:54  →  static_random

## Traccia SMP
- #1075: PAIRING_REQ
- #1078: PAIRING_RSP
- #1165: PAIRING_CONFIRM
- #1168: PAIRING_CONFIRM
- #1169: PAIRING_RANDOM
- #1172: PAIRING_RANDOM
- #1186: ENCRYPTION_INFORMATION
- #1188: MASTER_IDENTIFICATION
- #1190: IDENTITY_INFORMATION
- #1192: IDENTITY_ADDRESS_INFORMATION
- #1193: IDENTITY_INFORMATION
- #1195: IDENTITY_ADDRESS_INFORMATION

## Eventi LL legati alla cifratura
- #1175: LL_ENC_REQ
- #1178: LL_ENC_RSP
- #1180: LL_START_ENC_REQ
- #1181: LL_START_ENC_RSP
- #1184: LL_START_ENC_RSP

## Pairing (REQ/RSP, sez. 4.2)
- Richiesta  #1075: IO=KeyboardDisplay, OOB=No, MITM=Sì, SC=Sì, KeySizeMax=16, Bonding=Sì, Keypress=No
- Risposta   #1078: IO=NoInputNoOutput, OOB=No, MITM=No, SC=No, KeySizeMax=16, Bonding=Sì, Keypress=No
→ **Metodo di pairing**: Just Works (Legacy)  (Association model: Just Works; SC entrambi: No, OOB entrambi: No, Key size effettiva: 16)

## Livello di Sicurezza Stimato: Mode 1 Level 2
> Cifratura senza autenticazione
_Criteri:_ cifratura osservata, key size effettiva=16

## ATT/GATT visibili
### In chiaro (prima della cifratura) [tot: 42]
- #991: (2, 'Exchange MTU Request (MTU=527)')
- #994: (3, 'Exchange MTU Response (MTU=23)')
- #995: (16, 'Read By Group Type Request (handle 0xFFFF)')
- #998: (17, 'Read By Group Type Response')
- #999: (16, 'Read By Group Type Request (handle 0xFFFF)')
- #1002: (17, 'Read By Group Type Response')
- #1003: (16, 'Read By Group Type Request (handle 0xFFFF)')
- #1006: (1, 'Error Response (handle 0x003B)')
- #1007: (8, 'Read By Type Request (handle 0x0007)')
- #1010: (9, 'Read By Type Response (handle 0x0003)')
- #1011: (8, 'Read By Type Request (handle 0x000B)')
- #1014: (9, 'Read By Type Response')
- #1016: (9, 'Read By Type Response')
- #1017: (4, 'Find Information Request (handle 0x000B)')
- #1020: (5, 'Find Information Response (handle 0x000B)')
- #1021: (18, 'Write Request (handle 0x000B)')
- #1024: (19, 'Write Response (handle 0x000B)')
- #1025: (8, 'Read By Type Request (handle 0x0016)')
- #1028: (9, 'Read By Type Response')
- #1029: (8, 'Read By Type Request (handle 0x0016)')
- #1032: (9, 'Read By Type Response')
- #1033: (8, 'Read By Type Request (handle 0x0016)')
- #1036: (9, 'Read By Type Response')
- #1037: (8, 'Read By Type Request (handle 0x0016)')
- #1040: (9, 'Read By Type Response (handle 0x000E)')
- #1041: (8, 'Read By Type Request (handle 0x0016)')
- #1043: (8, 'Read By Type Request (handle 0x0016)')
- #1046: (9, 'Read By Type Response (handle 0x0012)')
- #1047: (8, 'Read By Type Request (handle 0x0016)')
- #1050: (9, 'Read By Type Response (handle 0x0014)')
- #1051: (8, 'Read By Type Request (handle 0x0016)')
- #1054: (9, 'Read By Type Response (handle 0x0016)')
- #1055: (8, 'Read By Type Request (handle 0x0031)')
- #1058: (9, 'Read By Type Response')
- #1059: (8, 'Read By Type Request (handle 0x0031)')
- #1062: (9, 'Read By Type Response')
- #1063: (8, 'Read By Type Request (handle 0x0031)')
- #1066: (9, 'Read By Type Response')
- #1067: (8, 'Read By Type Request (handle 0x0031)')
- #1070: (9, 'Read By Type Response')
- #1071: (10, 'Read Request (handle 0x0020)')
- #1074: (1, 'Error Response (handle 0x0020)')
### Dopo l'attivazione della cifratura [ATT visibili: 50]
- Pacchetti cifrati totali: 159
- Range cifratura: #1181 → #3073

- #1197: (10, 'Read Request (handle 0x0020)')
- #1201: (6, 'Find By Type Value Request (handle 0xFFFF)')
- #1203: (11, 'Read Response (handle 0x0020)')
- #1204: (7, 'Find By Type Value Response (handle 0x0048)')
- #1206: (12, 'Read Blob Request (handle 0x0020)')
- #1209: (8, 'Read By Type Request (handle 0x0051)')
- #1211: (13, 'Read Blob Response (handle 0x0020)')
- #1212: (9, 'Read By Type Response')
- #1214: (12, 'Read Blob Request (handle 0x0020)')
- #1217: (8, 'Read By Type Request (handle 0x0051)')
- #1219: (13, 'Read Blob Response (handle 0x0020)')
- #1220: (9, 'Read By Type Response')
- #1222: (12, 'Read Blob Request (handle 0x0020)')
- #1225: (8, 'Read By Type Request (handle 0x0051)')
- #1227: (13, 'Read Blob Response (handle 0x0020)')
- #1228: (9, 'Read By Type Response')
- #1230: (12, 'Read Blob Request (handle 0x0020)')
- #1233: (8, 'Read By Type Request (handle 0x0051)')
- #1235: (13, 'Read Blob Response (handle 0x0020)')
- #1236: (1, 'Error Response (handle 0x0051)')
- #1238: (4, 'Find Information Request (handle 0x0024)')
- #1241: (4, 'Find Information Request (handle 0x004B)')
- #1243: (5, 'Find Information Response')
- #1244: (5, 'Find Information Response (handle 0x004B)')
- #1246: (4, 'Find Information Request (handle 0x0028)')
- #1249: (4, 'Find Information Request (handle 0x004E)')
- #1251: (5, 'Find Information Response')
- #1252: (5, 'Find Information Response (handle 0x004E)')
- #1254: (10, 'Read Request (handle 0x002F)')
- #1257: (4, 'Find Information Request (handle 0x0051)')
- #1259: (0, 'ATT 0x00 (handle 0x002F)')
- #1260: (5, 'Find Information Response (handle 0x0051)')
- #1262: (10, 'Read Request (handle 0x0024)')
- #1265: (6, 'Find By Type Value Request (handle 0xFFFF)')
- #1267: (11, 'Read Response (handle 0x0024)')
- #1268: (7, 'Find By Type Value Response (handle 0x0043)')
- #1270: (10, 'Read Request (handle 0x0028)')
- #1273: (8, 'Read By Type Request (handle 0x0047)')
- #1275: (11, 'Read Response (handle 0x0028)')
- #1278: (9, 'Read By Type Response')
- #1280: (18, 'Write Request (handle 0x0023)')
- #1283: (6, 'Find By Type Value Request (handle 0xFFFF)')
- #1285: (7, 'Find By Type Value Response (handle 0x0001)')
- #1287: (18, 'Write Request (handle 0x0027)')
- #1290: (8, 'Read By Type Request (handle 0x0005)')
- #1292: (19, 'Write Response (handle 0x0027)')
- #1293: (9, 'Read By Type Response')
- #1295: (8, 'Read By Type Request (handle 0x001D)')
- #1298: (10, 'Read Request (handle 0x0045)')
- #1300: (9, 'Read By Type Response')

---