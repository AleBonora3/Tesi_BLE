# BLE Pairing Report – mouse_Filt.json
- Record totali: 220
- Cifratura attiva: Sì
- Connessione: #953 (CONNECT_IND)
- Primo pacchetto cifrato: #1181

## Indirizzi e Tipologia
- initiator: 70:bd:85:30:35:56  →  private_resolvable
- advertiser: e2:e0:6b:31:00:54  →  static_random
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
### In chiaro (prima della cifratura)
- #991: Exchange MTU Request (MTU=527)
- #994: Exchange MTU Response (MTU=23)
- #995: Read By Group Type Request (handle 0xFFFF)
- #998: Read By Group Type Response
- #999: Read By Group Type Request (handle 0xFFFF)
- #1002: Read By Group Type Response
- #1003: Read By Group Type Request (handle 0xFFFF)
- #1006: Error Response (handle 0x003B)
- #1007: Read By Type Request (handle 0x0007)
- #1010: Read By Type Response (handle 0x0003)
- #1011: Read By Type Request (handle 0x000B)
- #1014: Read By Type Response
- #1016: Read By Type Response
- #1017: Find Information Request (handle 0x000B)
- #1020: Find Information Response (handle 0x000B)
- #1021: Write Request (handle 0x000B)
- #1024: Write Response (handle 0x000B)
- #1025: Read By Type Request (handle 0x0016)
- #1028: Read By Type Response
- #1029: Read By Type Request (handle 0x0016)
- #1032: Read By Type Response
- #1033: Read By Type Request (handle 0x0016)
- #1036: Read By Type Response
- #1037: Read By Type Request (handle 0x0016)
- #1040: Read By Type Response (handle 0x000E)
- #1041: Read By Type Request (handle 0x0016)
- #1043: Read By Type Request (handle 0x0016)
- #1046: Read By Type Response (handle 0x0012)
- #1047: Read By Type Request (handle 0x0016)
- #1050: Read By Type Response (handle 0x0014)
- #1051: Read By Type Request (handle 0x0016)
- #1054: Read By Type Response (handle 0x0016)
- #1055: Read By Type Request (handle 0x0031)
- #1058: Read By Type Response
- #1059: Read By Type Request (handle 0x0031)
- #1062: Read By Type Response
- #1063: Read By Type Request (handle 0x0031)
- #1066: Read By Type Response
- #1067: Read By Type Request (handle 0x0031)
- #1070: Read By Type Response
- #1071: Read Request (handle 0x0020)
- #1074: Error Response (handle 0x0020)
### Dopo l'attivazione della cifratura
- #1197: Read Request (handle 0x0020)
- #1201: Find By Type Value Request (handle 0xFFFF)
- #1203: Read Response (handle 0x0020)
- #1204: Find By Type Value Response (handle 0x0048)
- #1206: Read Blob Request (handle 0x0020)
- #1209: Read By Type Request (handle 0x0051)
- #1211: Read Blob Response (handle 0x0020)
- #1212: Read By Type Response
- #1214: Read Blob Request (handle 0x0020)
- #1217: Read By Type Request (handle 0x0051)
- #1219: Read Blob Response (handle 0x0020)
- #1220: Read By Type Response
- #1222: Read Blob Request (handle 0x0020)
- #1225: Read By Type Request (handle 0x0051)
- #1227: Read Blob Response (handle 0x0020)
- #1228: Read By Type Response
- #1230: Read Blob Request (handle 0x0020)
- #1233: Read By Type Request (handle 0x0051)
- #1235: Read Blob Response (handle 0x0020)
- #1236: Error Response (handle 0x0051)
- #1238: Find Information Request (handle 0x0024)
- #1241: Find Information Request (handle 0x004B)
- #1243: Find Information Response
- #1244: Find Information Response (handle 0x004B)
- #1246: Find Information Request (handle 0x0028)
- #1249: Find Information Request (handle 0x004E)
- #1251: Find Information Response
- #1252: Find Information Response (handle 0x004E)
- #1254: Read Request (handle 0x002F)
- #1257: Find Information Request (handle 0x0051)
- #1259: ATT 0x00 (handle 0x002F)
- #1260: Find Information Response (handle 0x0051)
- #1262: Read Request (handle 0x0024)
- #1265: Find By Type Value Request (handle 0xFFFF)
- #1267: Read Response (handle 0x0024)
- #1268: Find By Type Value Response (handle 0x0043)
- #1270: Read Request (handle 0x0028)
- #1273: Read By Type Request (handle 0x0047)
- #1275: Read Response (handle 0x0028)
- #1278: Read By Type Response
- #1280: Write Request (handle 0x0023)
- #1283: Find By Type Value Request (handle 0xFFFF)
- #1285: Find By Type Value Response (handle 0x0001)
- #1287: Write Request (handle 0x0027)
- #1290: Read By Type Request (handle 0x0005)
- #1292: Write Response (handle 0x0027)
- #1293: Read By Type Response
- #1295: Read By Type Request (handle 0x001D)
- #1298: Read Request (handle 0x0045)
- #1300: Read By Type Response

---