/**
 * proto-codec.js
 * Tesla vehicle-command 공식 Protobuf 규격 100% 준수 인코더/디코더 [v13]:
 * - universal_message.proto (RoutableMessage, SessionInfoRequest, MessageStatus, Flags=FLAG_ENCRYPT_RESPONSE)
 * - signatures.proto (SignatureData, AES_GCM_Personalized_Signature_Data, AES_GCM_Response_Signature_Data, SessionInfo)
 * - vcsec.proto (ToVCSECMessage, UnsignedMessage, FromVCSECMessage, ClosureMoveRequest, RKEAction, WhitelistInfo)
 * - car_server.proto & vehicle.proto (Action, GetVehicleData 단일 카테고리 순환 요청, Response, VehicleData)
 */

// Wire Types
export const WIRE_VARINT = 0;
export const WIRE_FIXED64 = 1;
export const WIRE_LENGTH_DELIMITED = 2;
export const WIRE_FIXED32 = 5;

// SignatureType (vcsec.proto)
export const SIGNATURE_TYPE_NONE = 0;
export const SIGNATURE_TYPE_PRESENT_KEY = 2;

// Role (keys.proto)
export const ROLE_NONE = 0;
export const ROLE_SERVICE = 1;
export const ROLE_OWNER = 2;
export const ROLE_DRIVER = 3;

// KeyFormFactor (vcsec.proto)
export const KEY_FORM_FACTOR_UNKNOWN = 0;
export const KEY_FORM_FACTOR_NFC_CARD = 1;
export const KEY_FORM_FACTOR_IOS_DEVICE = 6;
export const KEY_FORM_FACTOR_ANDROID_DEVICE = 7;
export const KEY_FORM_FACTOR_CLOUD_KEY = 9;

// UniversalMessage Domain (universal_message.proto)
export const DOMAIN_BROADCAST = 0;
export const DOMAIN_VEHICLE_SECURITY = 2;
export const DOMAIN_INFOTAINMENT = 3;

// UniversalMessage Flags (universal_message.proto)
export const FLAG_ENCRYPT_RESPONSE_BIT = 2; // (1 << 1)

// ClosureMoveType_E (vcsec.proto)
export const CLOSURE_MOVE_TYPE_NONE = 0;
export const CLOSURE_MOVE_TYPE_MOVE = 1;
export const CLOSURE_MOVE_TYPE_STOP = 2;
export const CLOSURE_MOVE_TYPE_OPEN = 3;
export const CLOSURE_MOVE_TYPE_CLOSE = 4;

// RKEAction_E (vcsec.proto)
export const RKE_ACTION_UNLOCK = 0;
export const RKE_ACTION_LOCK = 1;
export const RKE_ACTION_REMOTE_DRIVE = 20;
export const RKE_ACTION_AUTO_SECURE_VEHICLE = 29;
export const RKE_ACTION_WAKE_VEHICLE = 30;

// InformationRequestType (vcsec.proto)
export const INFORMATION_REQUEST_TYPE_GET_STATUS = 0;
export const INFORMATION_REQUEST_TYPE_GET_WHITELIST_INFO = 5;
export const INFORMATION_REQUEST_TYPE_GET_WHITELIST_ENTRY_INFO = 6;

// OperationStatus_E (vcsec.proto / universal_message.proto)
export const OPERATIONSTATUS_OK = 0;
export const OPERATIONSTATUS_WAIT = 1;
export const OPERATIONSTATUS_ERROR = 2;

// GetVehicleData Category Tags (car_server.proto)
export const VEHICLE_DATA_CHARGE_STATE = 2;
export const VEHICLE_DATA_CLIMATE_STATE = 3;
export const VEHICLE_DATA_DRIVE_STATE = 4;
export const VEHICLE_DATA_CLOSURES_STATE = 8;
export const VEHICLE_DATA_TIRE_PRESSURE_STATE = 14;

/**
 * 1. Protobuf 저수준 와이어 포맷 인코더/디코더
 */

export function encodeVarint(value) {
  let val = Math.floor(Number(value));
  if (val < 0) {
    val = val >>> 0;
  }
  const bytes = [];
  while (val >= 0x80) {
    bytes.push((val & 0x7f) | 0x80);
    val = Math.floor(val / 128);
  }
  bytes.push(val & 0x7f);
  return new Uint8Array(bytes);
}

export function encodeVarintField(fieldNumber, value) {
  const key = (fieldNumber << 3) | WIRE_VARINT;
  const keyBytes = encodeVarint(key);
  const valBytes = encodeVarint(value);
  const out = new Uint8Array(keyBytes.length + valBytes.length);
  out.set(keyBytes, 0);
  out.set(valBytes, keyBytes.length);
  return out;
}

export function encodeFixed32Field(fieldNumber, value) {
  const key = (fieldNumber << 3) | WIRE_FIXED32;
  const keyBytes = encodeVarint(key);
  const valBytes = new Uint8Array(4);
  new DataView(valBytes.buffer).setUint32(0, value >>> 0, true); // Protobuf fixed32는 Little-Endian
  const out = new Uint8Array(keyBytes.length + 4);
  out.set(keyBytes, 0);
  out.set(valBytes, keyBytes.length);
  return out;
}

export function encodeLengthDelimitedField(fieldNumber, payloadBytes) {
  const safePayload = payloadBytes || new Uint8Array(0);
  const key = (fieldNumber << 3) | WIRE_LENGTH_DELIMITED;
  const keyBytes = encodeVarint(key);
  const lenBytes = encodeVarint(safePayload.length);
  const out = new Uint8Array(keyBytes.length + lenBytes.length + safePayload.length);
  out.set(keyBytes, 0);
  out.set(lenBytes, keyBytes.length);
  out.set(safePayload, keyBytes.length + lenBytes.length);
  return out;
}

export function concatBytes(...arrays) {
  const totalLength = arrays.reduce((acc, curr) => acc + (curr ? curr.length : 0), 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    if (arr && arr.length > 0) {
      result.set(arr, offset);
      offset += arr.length;
    }
  }
  return result;
}

export function bytesToHex(uint8Array) {
  if (!uint8Array || uint8Array.length === 0) return '';
  return Array.from(uint8Array)
    .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
    .join(' ');
}

export function bytesToCompactHex(uint8Array) {
  if (!uint8Array || uint8Array.length === 0) return '';
  return Array.from(uint8Array)
    .map((b) => b.toString(16).padStart(2, '0').toLowerCase())
    .join('');
}

/**
 * 테슬라 차량 VIN(차대번호 17자리) 기반 BLE 비콘 이름 계산기 (구형 & 신형 동시 반환)
 */
export async function computeTeslaBLEBeaconName(vin) {
  if (!vin || typeof vin !== 'string') return '';
  const cleanVin = vin.trim().toUpperCase();
  if (cleanVin.length !== 17) return '';
  const encoder = new TextEncoder();
  const vinBytes = encoder.encode(cleanVin);
  const hashBuffer = await crypto.subtle.digest('SHA-1', vinBytes);
  const hashBytes = new Uint8Array(hashBuffer);
  let hex = '';
  for (let i = 0; i < 8; i++) {
    hex += hashBytes[i].toString(16).padStart(2, '0');
  }
  const oldName = `S${hex}C`;
  const newName = `Tesla ${cleanVin.slice(-6)}`;
  return `${oldName} 또는 ${newName}`;
}

export function decodeVarint(buffer, offset = 0) {
  let result = 0;
  let shift = 0;
  let bytesRead = 0;

  while (offset + bytesRead < buffer.length) {
    const byte = buffer[offset + bytesRead];
    bytesRead++;
    result += (byte & 0x7f) * Math.pow(2, shift);
    if ((byte & 0x80) === 0) {
      break;
    }
    shift += 7;
  }
  return { value: result, bytesRead };
}

export function parseFields(buffer) {
  const fields = [];
  let offset = 0;

  while (offset < buffer.length) {
    const keyInfo = decodeVarint(buffer, offset);
    if (keyInfo.bytesRead === 0) break;
    offset += keyInfo.bytesRead;

    const fieldNumber = keyInfo.value >>> 3;
    const wireType = keyInfo.value & 0x07;
    if (fieldNumber === 0) break;

    if (wireType === WIRE_VARINT) {
      const valInfo = decodeVarint(buffer, offset);
      offset += valInfo.bytesRead;
      fields.push({ fieldNumber, wireType, value: valInfo.value });
    } else if (wireType === WIRE_LENGTH_DELIMITED) {
      const lenInfo = decodeVarint(buffer, offset);
      offset += lenInfo.bytesRead;
      const end = Math.min(buffer.length, offset + lenInfo.value);
      const data = buffer.slice(offset, end);
      offset = end;
      fields.push({ fieldNumber, wireType, data });
    } else if (wireType === WIRE_FIXED32) {
      if (offset + 4 > buffer.length) break;
      const view = new DataView(buffer.buffer, buffer.byteOffset + offset, 4);
      const val = view.getUint32(0, true);
      const floatVal = view.getFloat32(0, true);
      offset += 4;
      fields.push({ fieldNumber, wireType, value: val, floatValue: floatVal });
    } else if (wireType === WIRE_FIXED64) {
      if (offset + 8 > buffer.length) break;
      offset += 8;
      fields.push({ fieldNumber, wireType, value: 0 });
    } else {
      break;
    }
  }

  return fields;
}

function toSignedInt32(val) {
  return (val > 0x7fffffff) ? (val - 0x100000000) : val;
}

/**
 * 2. 공식 UniversalMessage.RoutableMessage & Session Handshake 빌더
 */

export function wrapToVCSECMessage(signedMessageBytes) {
  return encodeLengthDelimitedField(1, signedMessageBytes);
}

/**
 * RoutableMessage 래퍼 (평문 요청용)
 * - tag 6 (to_destination): Destination { tag 1 (domain): domain }
 * - tag 7 (from_destination): Destination { tag 2 (routing_address): 16B }
 * - tag 10 (protobuf_message_as_bytes): payloadBytes
 * - tag 51 (uuid): 16B random UUID (universal_message.proto 공식 규격: 요청은 tag 51, 응답이 tag 50)
 */
export function wrapToRoutableMessage(payloadBytes, domain = DOMAIN_VEHICLE_SECURITY, routingAddress = null) {
  const toDest = encodeLengthDelimitedField(6, encodeVarintField(1, domain));

  let addr = routingAddress;
  if (!addr || addr.length !== 16) {
    addr = new Uint8Array(16);
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      crypto.getRandomValues(addr);
    }
  }
  const fromDest = encodeLengthDelimitedField(7, encodeLengthDelimitedField(2, addr));

  const payloadField = encodeLengthDelimitedField(10, payloadBytes);

  const uuid = new Uint8Array(16);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(uuid);
  }
  const uuidField = encodeLengthDelimitedField(51, uuid);

  return concatBytes(toDest, fromDest, payloadField, uuidField);
}

/**
 * 세션 핸드셰이크 요청 빌더 (SessionInfoRequest)
 * RoutableMessage:
 * - tag 6 (to_destination): { tag 1: domain }
 * - tag 7 (from_destination): { tag 2: routingAddress (16B) }
 * - tag 14 (session_info_request): SessionInfoRequest { tag 1 (public_key): 65B }
 * - tag 51 (uuid): 16B
 */
export function buildSessionInfoRequest(publicKeyBytes, domain = DOMAIN_VEHICLE_SECURITY, routingAddress = null) {
  const toDest = encodeLengthDelimitedField(6, encodeVarintField(1, domain));

  let addr = routingAddress;
  if (!addr || addr.length !== 16) {
    addr = new Uint8Array(16);
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      crypto.getRandomValues(addr);
    }
  }
  const fromDest = encodeLengthDelimitedField(7, encodeLengthDelimitedField(2, addr));

  // SessionInfoRequest: tag 1 = public_key (65 bytes)
  const sessionInfoReqMsg = encodeLengthDelimitedField(1, publicKeyBytes);
  const sessionInfoReqField = encodeLengthDelimitedField(14, sessionInfoReqMsg);

  const uuid = new Uint8Array(16);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(uuid);
  }
  const uuidField = encodeLengthDelimitedField(51, uuid);

  return concatBytes(toDest, fromDest, sessionInfoReqField, uuidField);
}

/**
 * AES-128-GCM 암호화 및 SignatureData가 포함된 공식 RoutableMessage 생성기
 * (teslamotors/vehicle-command 및 yoziru/tesla-ble build_universal_message_with_payload 동일 규격)
 */
export async function buildEncryptedRoutableMessage(plaintextBytes, domain, cryptoStore) {
  if (!cryptoStore || !cryptoStore.publicKeyRaw) {
    throw new Error('가상키가 생성되지 않았습니다.');
  }

  // 세션이 아직 수립되지 않은 경우
  if (!cryptoStore.hasValidSession(domain)) {
    const s = cryptoStore.sessions?.[domain];
    if (s && s.status === 1) {
      throw new Error('차량에 현재 가상키가 아직 등록(승인)되지 않았습니다. 상단 배너의 [차량에 키 등록 요청]을 먼저 진행해 주세요.');
    }
    throw new Error(`차량 보안 세션(도메인 ${domain}) 연결 중입니다. 잠시 후 다시 시도해 주세요.`);
  }

  const uuid = new Uint8Array(16);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(uuid);
  }
  const uuidHex = bytesToCompactHex(uuid);

  const session = cryptoStore.sessions[domain];
  const flags = (session && session.useEncryptResponse === false) ? 0 : FLAG_ENCRYPT_RESPONSE_BIT;

  // 1. ECDH 유도 AES-128-GCM 키로 암호화 및 16바이트 GCM 태그 생성
  const enc = await cryptoStore.encryptPayload(domain, plaintextBytes, flags, uuidHex);

  // 2. Signatures.KeyIdentity: tag 1 = public_key (65B)
  const signerIdentity = encodeLengthDelimitedField(1, cryptoStore.publicKeyRaw);
  const signerIdentityField = encodeLengthDelimitedField(1, signerIdentity);

  // 3. Signatures.AES_GCM_Personalized_Signature_Data:
  //    tag 1 = epoch (16B)
  //    tag 2 = nonce (12B)
  //    tag 3 = counter (uint32 varint)
  //    tag 4 = expires_at (fixed32 little-endian)
  //    tag 5 = tag (16B GCM auth tag)
  const aesGcmData = concatBytes(
    encodeLengthDelimitedField(1, enc.epoch),
    encodeLengthDelimitedField(2, enc.nonce),
    encodeVarintField(3, enc.counter),
    encodeFixed32Field(4, enc.expiresAt),
    encodeLengthDelimitedField(5, enc.tag)
  );
  const aesGcmDataField = encodeLengthDelimitedField(5, aesGcmData);

  // 4. Signatures.SignatureData: tag 1 = signer_identity, tag 5 = AES_GCM_Personalized_data
  const signatureData = concatBytes(signerIdentityField, aesGcmDataField);
  const signatureDataField = encodeLengthDelimitedField(13, signatureData);

  // 5. RoutableMessage 패킹 (uuid = tag 51, flags = tag 52)
  const toDest = encodeLengthDelimitedField(6, encodeVarintField(1, domain));
  const fromDest = encodeLengthDelimitedField(7, encodeLengthDelimitedField(2, cryptoStore.routingAddress));
  const payloadField = encodeLengthDelimitedField(10, enc.ciphertext);
  const uuidField = encodeLengthDelimitedField(51, uuid);
  const flagsField = flags > 0 ? encodeVarintField(52, flags) : new Uint8Array(0);

  return concatBytes(toDest, fromDest, payloadField, signatureDataField, uuidField, flagsField);
}

/**
 * 3. 키 등록 및 차량 제어 액션 빌더
 */

/**
 * 키 등록용 AddKeyRequest 빌더 (teslamotors/vehicle-command security.go & yoziru/tesla-ble 동일 규격)
 * 주의: 이 패킷을 전송한 뒤 사용자가 먼저 센터콘솔 NFC 리더기에 카드키를 태그해야 차량 모니터에 승인 팝업이 나타남!
 */
export function buildAddKeyRequest(publicKeyBytes) {
  const publicKeyMsg = encodeLengthDelimitedField(1, publicKeyBytes);

  const keyField = encodeLengthDelimitedField(1, publicKeyMsg);
  const roleField = encodeVarintField(4, ROLE_OWNER);
  const permissionChange = concatBytes(keyField, roleField);

  const isAndroid = typeof navigator !== 'undefined' && /Android/i.test(navigator.userAgent);
  const formFactor = isAndroid ? KEY_FORM_FACTOR_ANDROID_DEVICE : KEY_FORM_FACTOR_IOS_DEVICE;
  const keyMetadataField = encodeLengthDelimitedField(1, encodeVarintField(1, formFactor));

  const permChangeField = encodeLengthDelimitedField(5, permissionChange);
  const metadataField = encodeLengthDelimitedField(6, keyMetadataField);
  const whitelistOp = concatBytes(permChangeField, metadataField);

  const unsignedMessage = encodeLengthDelimitedField(16, whitelistOp);

  const msgBytesField = encodeLengthDelimitedField(2, unsignedMessage);
  const sigTypeField = encodeVarintField(3, SIGNATURE_TYPE_PRESENT_KEY);
  const signedMessage = concatBytes(msgBytesField, sigTypeField);

  return wrapToVCSECMessage(signedMessage);
}

/**
 * RoutableMessage 형태로 감싼 AddKeyRequest 빌더 (최신 VCSEC 라우터 호환용)
 */
export function buildRoutableAddKeyRequest(publicKeyBytes, routingAddress = null) {
  const publicKeyMsg = encodeLengthDelimitedField(1, publicKeyBytes);
  const keyField = encodeLengthDelimitedField(1, publicKeyMsg);
  const roleField = encodeVarintField(4, ROLE_OWNER);
  const permissionChange = concatBytes(keyField, roleField);

  const isAndroid = typeof navigator !== 'undefined' && /Android/i.test(navigator.userAgent);
  const formFactor = isAndroid ? KEY_FORM_FACTOR_ANDROID_DEVICE : KEY_FORM_FACTOR_IOS_DEVICE;
  const keyMetadataField = encodeLengthDelimitedField(1, encodeVarintField(1, formFactor));

  const permChangeField = encodeLengthDelimitedField(5, permissionChange);
  const metadataField = encodeLengthDelimitedField(6, keyMetadataField);
  const whitelistOp = concatBytes(permChangeField, metadataField);

  const unsignedMessage = encodeLengthDelimitedField(16, whitelistOp);
  return wrapToRoutableMessage(unsignedMessage, DOMAIN_VEHICLE_SECURITY, routingAddress);
}

/**
 * 도어 언래치(물리 개방) 액션 (VCSEC ClosureMoveRequest)
 * - vcsec.proto 규격: 도어(frontDriverDoor=1, frontPassengerDoor=2, rearDriverDoor=3, rearPassengerDoor=4) 개방은
 *   반드시 CLOSURE_MOVE_TYPE_OPEN (3) 값을 사용해야 도어 액추에이터(래치)가 작동함
 */
export async function buildOpenDoorAction(doorIndex, cryptoStore, moveType = CLOSURE_MOVE_TYPE_OPEN) {
  const closureFieldTag = doorIndex + 1; // 1: FL, 2: FR, 3: RL, 4: RR
  const doorMoveField = encodeVarintField(closureFieldTag, moveType);
  const unsignedMessage = encodeLengthDelimitedField(4, doorMoveField);
  return await buildEncryptedRoutableMessage(unsignedMessage, DOMAIN_VEHICLE_SECURITY, cryptoStore);
}

/**
 * 차량 도어 잠금 해제 액션 (VCSEC RKE_ACTION_UNLOCK = 0)
 */
export async function buildUnlockVehicleAction(cryptoStore) {
  const unsignedMessage = encodeVarintField(2, RKE_ACTION_UNLOCK);
  return await buildEncryptedRoutableMessage(unsignedMessage, DOMAIN_VEHICLE_SECURITY, cryptoStore);
}

/**
 * 비상등 점멸 액션
 * - Infotainment 세션이 수립되어 있으면 정식 VehicleControlFlashLightsAction (tag 26) 전송
 * - 미수립 시 VCSEC RKE_ACTION_WAKE_VEHICLE (tag 30) 폴백 전송
 */
export async function buildFlashLightsAction(cryptoStore) {
  if (cryptoStore && cryptoStore.hasValidSession(DOMAIN_INFOTAINMENT)) {
    return await buildCarServerFlashLightsAction(cryptoStore);
  }
  const unsignedMessage = encodeLengthDelimitedField(2, RKE_ACTION_WAKE_VEHICLE);
  return await buildEncryptedRoutableMessage(unsignedMessage, DOMAIN_VEHICLE_SECURITY, cryptoStore);
}

export async function buildCarServerFlashLightsAction(cryptoStore) {
  const flashActionMsg = new Uint8Array(0);
  const vehicleActionField = encodeLengthDelimitedField(26, flashActionMsg);
  const actionMsg = encodeLengthDelimitedField(2, vehicleActionField);
  return await buildEncryptedRoutableMessage(actionMsg, DOMAIN_INFOTAINMENT, cryptoStore);
}

/**
 * 충전 중지 및 포트 잠금 해제 액션
 */
export async function buildStopChargeAction(cryptoStore) {
  if (cryptoStore && cryptoStore.hasValidSession(DOMAIN_INFOTAINMENT)) {
    const stopVoid = encodeLengthDelimitedField(5, new Uint8Array(0));
    const vehicleAction = encodeLengthDelimitedField(6, stopVoid);
    const actionMsg = encodeLengthDelimitedField(2, vehicleAction);
    return await buildEncryptedRoutableMessage(actionMsg, DOMAIN_INFOTAINMENT, cryptoStore);
  }
  const chargePortField = encodeVarintField(7, CLOSURE_MOVE_TYPE_STOP);
  const unsignedMessage = encodeLengthDelimitedField(4, chargePortField);
  return await buildEncryptedRoutableMessage(unsignedMessage, DOMAIN_VEHICLE_SECURITY, cryptoStore);
}

export async function buildChargePortUnlockAction(cryptoStore) {
  const chargePortField = encodeVarintField(7, CLOSURE_MOVE_TYPE_OPEN);
  const unsignedMessage = encodeLengthDelimitedField(4, chargePortField);
  return await buildEncryptedRoutableMessage(unsignedMessage, DOMAIN_VEHICLE_SECURITY, cryptoStore);
}

/**
 * VCSEC 상태 조회 요청 (도어/트렁크/잠금/슬립 상태 - 암호화 불필요)
 */
export function buildStatusRequest(routingAddress = null) {
  const infoTypeField = encodeVarintField(1, INFORMATION_REQUEST_TYPE_GET_STATUS);
  const unsignedMessage = encodeLengthDelimitedField(1, infoTypeField);
  return wrapToRoutableMessage(unsignedMessage, DOMAIN_VEHICLE_SECURITY, routingAddress);
}

/**
 * VCSEC 화이트리스트 키 목록 조회 요청 (무인증 조회 가능 - 현재 앱 키가 등록되었는지 확인용)
 */
export function buildWhitelistInfoRequest(routingAddress = null) {
  const infoTypeField = encodeVarintField(1, INFORMATION_REQUEST_TYPE_GET_WHITELIST_INFO);
  const unsignedMessage = encodeLengthDelimitedField(1, infoTypeField);
  return wrapToRoutableMessage(unsignedMessage, DOMAIN_VEHICLE_SECURITY, routingAddress);
}

/**
 * CarServer(DOMAIN_INFOTAINMENT) 보조 계기판 텔레메트리 요청 빌더 (공식 car_server.proto GetVehicleData)
 * 중요: 테슬라 BLE MTU(1024B) 초과 방지를 위해 공식 SDK(state.go / client.cpp)와 동일하게
 *       1회 요청당 반드시 1개의 카테고리만 요청한다!
 * - categoryTag = 4 (getDriveState: 기어, 속도, 출력/회생제동)
 * - categoryTag = 2 (getChargeState: 배터리 %, 주행가능거리, 충전전력/전압/전류)
 * - categoryTag = 3 (getClimateState: 실내/실외 온도)
 * - categoryTag = 14 (getTirePressureState: 4륜 TPMS 공기압)
 * - categoryTag = 8 (getClosuresState: 도어/트렁크 상태)
 */
export async function buildGetVehicleDataRequest(cryptoStore, categoryTag = VEHICLE_DATA_DRIVE_STATE) {
  const empty = new Uint8Array(0);
  const validTag = [2, 3, 4, 8, 14].includes(categoryTag) ? categoryTag : VEHICLE_DATA_DRIVE_STATE;
  const getVehicleData = encodeLengthDelimitedField(validTag, empty);

  // VehicleAction: tag 1 = getVehicleData
  const vehicleAction = encodeLengthDelimitedField(1, getVehicleData);
  // Action: tag 2 = vehicleAction
  const action = encodeLengthDelimitedField(2, vehicleAction);

  return await buildEncryptedRoutableMessage(action, DOMAIN_INFOTAINMENT, cryptoStore);
}

/**
 * 4. 수신 패킷 정밀 파서 (RoutableMessage / FromVCSECMessage / CarServer.Response)
 * - AES_GCM_Response_Signature_Data 암호화 응답 복호화 완벽 지원
 * - proto3 기본값 0(닫힘) 생략 시에도 도어 닫힘 상태가 100% 반영되도록 수정
 */
export async function parseIncomingMessageAsync(uint8Array, cryptoStore = null) {
  const result = {
    rawLength: uint8Array ? uint8Array.length : 0,
    domain: null,
    whitelistOperationStatus: null, // 'OK' | 'WAITING_FOR_CARD' | 'ERROR'
    whitelistErrorCode: null,
    whitelistKeyIds: null,          // Array<Uint8Array(4)>
    signedMessageFault: 0,          // universal_message.proto MessageFault_E
    sessionInfo: null,              // { counter, publicKey, epoch, clockTime, status }
    reportedCounter: null,
    vehicleSleepStatus: null,       // 1: AWAKE, 2: ASLEEP
    responseFlags: 0,
    requestUuidHex: '',
    aesGcmResponseData: null,       // { nonce, counter, tag }
    decrypted: false,
    decryptError: null,
    telemetry: {}
  };

  if (!uint8Array || uint8Array.length === 0) return result;

  try {
    let payloadBytes = uint8Array;
    let rootFields = parseFields(payloadBytes);

    let isRoutable = false;
    for (const f of rootFields) {
      // tag 7: from_destination { tag 1: domain }
      if (f.fieldNumber === 7 && f.wireType === WIRE_LENGTH_DELIMITED && f.data) {
        const destFields = parseFields(f.data);
        const domField = destFields.find((df) => df.fieldNumber === 1 && df.wireType === WIRE_VARINT);
        if (domField) {
          result.domain = domField.value;
          isRoutable = true;
        }
      }
      // tag 12: signedMessageStatus (MessageStatus)
      if (f.fieldNumber === 12 && f.wireType === WIRE_LENGTH_DELIMITED && f.data) {
        isRoutable = true;
        const msFields = parseFields(f.data);
        for (const ms of msFields) {
          if (ms.fieldNumber === 2 && ms.wireType === WIRE_VARINT && ms.value !== 0) {
            result.signedMessageFault = ms.value;
          }
        }
      }
      // tag 13: signature_data (Signatures.SignatureData)
      if (f.fieldNumber === 13 && f.wireType === WIRE_LENGTH_DELIMITED && f.data) {
        isRoutable = true;
        const sigFields = parseFields(f.data);
        for (const sf of sigFields) {
          // tag 9: AES_GCM_Response_data (AES_GCM_Response_Signature_Data)
          if (sf.fieldNumber === 9 && sf.wireType === WIRE_LENGTH_DELIMITED && sf.data) {
            const respGcmFields = parseFields(sf.data);
            const gcmResp = { nonce: null, counter: 0, tag: null };
            for (const rf of respGcmFields) {
              if (rf.fieldNumber === 1 && rf.wireType === WIRE_LENGTH_DELIMITED) gcmResp.nonce = rf.data;
              if (rf.fieldNumber === 2 && rf.wireType === WIRE_VARINT) gcmResp.counter = rf.value;
              if (rf.fieldNumber === 3 && rf.wireType === WIRE_LENGTH_DELIMITED) gcmResp.tag = rf.data;
            }
            result.aesGcmResponseData = gcmResp;
          }
        }
      }
      // tag 15: session_info (Signatures.SessionInfo)
      if (f.fieldNumber === 15 && f.wireType === WIRE_LENGTH_DELIMITED && f.data) {
        isRoutable = true;
        const siFields = parseFields(f.data);
        const sessionInfo = {
          counter: 0,
          publicKey: null,
          epoch: null,
          clockTime: 0,
          status: 0
        };
        for (const si of siFields) {
          if (si.fieldNumber === 1 && si.wireType === WIRE_VARINT) sessionInfo.counter = si.value;
          if (si.fieldNumber === 2 && si.wireType === WIRE_LENGTH_DELIMITED) sessionInfo.publicKey = si.data;
          if (si.fieldNumber === 3 && si.wireType === WIRE_LENGTH_DELIMITED) sessionInfo.epoch = si.data;
          if (si.fieldNumber === 4 && (si.wireType === WIRE_FIXED32 || si.wireType === WIRE_VARINT)) {
            sessionInfo.clockTime = si.value;
          }
          if (si.fieldNumber === 5 && si.wireType === WIRE_VARINT) sessionInfo.status = si.value;
        }
        result.sessionInfo = sessionInfo;
        result.reportedCounter = sessionInfo.counter;
      }
      // tag 50: request_uuid (16B)
      if (f.fieldNumber === 50 && f.wireType === WIRE_LENGTH_DELIMITED && f.data) {
        isRoutable = true;
        result.requestUuidHex = bytesToCompactHex(f.data);
      }
      // tag 52: flags (uint32)
      if (f.fieldNumber === 52 && f.wireType === WIRE_VARINT) {
        isRoutable = true;
        result.responseFlags = f.value;
      }
    }

    // RoutableMessage 내부 tag 10 (protobuf_message_as_bytes) 추출
    const routablePayloadField = rootFields.find((f) => f.fieldNumber === 10 && f.wireType === WIRE_LENGTH_DELIMITED);
    if (routablePayloadField && routablePayloadField.data) {
      payloadBytes = routablePayloadField.data;

      // 만약 signature_data.AES_GCM_Response_data (tag 9)가 존재하면 암호화된 응답이므로 복호화 수행
      if (result.aesGcmResponseData && cryptoStore) {
        try {
          const decryptedBytes = await cryptoStore.decryptResponsePayload(
            result.domain || DOMAIN_INFOTAINMENT,
            payloadBytes,
            result.aesGcmResponseData,
            result.responseFlags,
            result.signedMessageFault || 0,
            result.requestUuidHex
          );
          payloadBytes = decryptedBytes;
          result.decrypted = true;
        } catch (decErr) {
          result.decryptError = decErr?.message || String(decErr);
          console.warn('[proto-codec] Response decryption failed:', result.decryptError);
          return result;
        }
      }

      rootFields = parseFields(payloadBytes);
    } else if (isRoutable) {
      return result;
    }

    // 2. 도메인별 내부 페이로드 파싱
    if (result.domain === DOMAIN_INFOTAINMENT) {
      parseCarServerResponse(rootFields, result);
    } else {
      parseFromVCSEC(rootFields, result);
      parseCarServerResponse(rootFields, result);
    }
  } catch (err) {
    console.warn('[proto-codec] parse error:', err);
  }

  return result;
}

/**
 * 동기 파서 호환 래퍼 (평문 VCSEC 패킷용)
 */
export function parseIncomingMessage(uint8Array) {
  const result = {
    rawLength: uint8Array ? uint8Array.length : 0,
    domain: null,
    whitelistOperationStatus: null,
    whitelistErrorCode: null,
    whitelistKeyIds: null,
    signedMessageFault: 0,
    sessionInfo: null,
    reportedCounter: null,
    vehicleSleepStatus: null,
    telemetry: {}
  };
  if (!uint8Array || uint8Array.length === 0) return result;
  try {
    let payloadBytes = uint8Array;
    let rootFields = parseFields(payloadBytes);
    let isRoutable = false;
    for (const f of rootFields) {
      if (f.fieldNumber === 7 && f.wireType === WIRE_LENGTH_DELIMITED && f.data) {
        const destFields = parseFields(f.data);
        const domField = destFields.find((df) => df.fieldNumber === 1 && df.wireType === WIRE_VARINT);
        if (domField) {
          result.domain = domField.value;
          isRoutable = true;
        }
      }
      if (f.fieldNumber === 12 && f.wireType === WIRE_LENGTH_DELIMITED && f.data) {
        isRoutable = true;
        const msFields = parseFields(f.data);
        for (const ms of msFields) {
          if (ms.fieldNumber === 2 && ms.wireType === WIRE_VARINT && ms.value !== 0) {
            result.signedMessageFault = ms.value;
          }
        }
      }
      if (f.fieldNumber === 15 && f.wireType === WIRE_LENGTH_DELIMITED && f.data) {
        isRoutable = true;
        const siFields = parseFields(f.data);
        const sessionInfo = { counter: 0, publicKey: null, epoch: null, clockTime: 0, status: 0 };
        for (const si of siFields) {
          if (si.fieldNumber === 1 && si.wireType === WIRE_VARINT) sessionInfo.counter = si.value;
          if (si.fieldNumber === 2 && si.wireType === WIRE_LENGTH_DELIMITED) sessionInfo.publicKey = si.data;
          if (si.fieldNumber === 3 && si.wireType === WIRE_LENGTH_DELIMITED) sessionInfo.epoch = si.data;
          if (si.fieldNumber === 4 && (si.wireType === WIRE_FIXED32 || si.wireType === WIRE_VARINT)) {
            sessionInfo.clockTime = si.value;
          }
          if (si.fieldNumber === 5 && si.wireType === WIRE_VARINT) sessionInfo.status = si.value;
        }
        result.sessionInfo = sessionInfo;
        result.reportedCounter = sessionInfo.counter;
      }
    }
    const routablePayloadField = rootFields.find((f) => f.fieldNumber === 10 && f.wireType === WIRE_LENGTH_DELIMITED);
    if (routablePayloadField && routablePayloadField.data) {
      payloadBytes = routablePayloadField.data;
      rootFields = parseFields(payloadBytes);
    } else if (isRoutable) {
      return result;
    }
    if (result.domain === DOMAIN_INFOTAINMENT) {
      parseCarServerResponse(rootFields, result);
    } else {
      parseFromVCSEC(rootFields, result);
      parseCarServerResponse(rootFields, result);
    }
  } catch (_) {}
  return result;
}

/**
 * VCSEC 도메인 (FromVCSECMessage) 파서 - 공식 vcsec.proto 규격
 */
function parseFromVCSEC(fields, result) {
  for (const field of fields) {
    // tag 1: VehicleStatus
    if (field.fieldNumber === 1 && field.wireType === WIRE_LENGTH_DELIMITED && field.data) {
      const vsFields = parseFields(field.data);
      // 핵심 버그 수정: proto3에서는 모든 도어가 닫히면(CLOSURESTATE_CLOSED = 0)
      // 하위 ClosureStatuses(vs.fieldNumber === 1) 필드 자체가 생략되어 전송됨!
      // 따라서 VehicleStatus 수신 즉시 모든 도어를 기본값 false(닫힘)로 초기화한 뒤,
      // ClosureStatuses에 남아 있는 열린 도어만 true로 덮어써야 문 닫힘이 100% 즉시 인식됨!
      const doors = {
        df: false, pf: false, dr: false, pr: false, ft: false, rt: false, charge_port: false
      };
      result.telemetry.doors = doors;

      // proto3에서 vehicleLockState = 0 (UNLOCKED)이면 필드 자체가 생략되므로 기본값 false(열림)
      result.telemetry.locked = false;

      for (const vs of vsFields) {
        // tag 1: ClosureStatuses
        if (vs.fieldNumber === 1 && vs.wireType === WIRE_LENGTH_DELIMITED && vs.data) {
          const closureFields = parseFields(vs.data);
          for (const c of closureFields) {
            const isOpen = (c.value === 1 || c.value === 2 || c.value === 5); // OPEN(1), AJAR(2), OPENING(5)
            if (c.fieldNumber === 1) doors.df = isOpen;
            if (c.fieldNumber === 2) doors.pf = isOpen;
            if (c.fieldNumber === 3) doors.dr = isOpen;
            if (c.fieldNumber === 4) doors.pr = isOpen;
            if (c.fieldNumber === 5) doors.rt = isOpen;
            if (c.fieldNumber === 6) doors.ft = isOpen;
            if (c.fieldNumber === 7) doors.charge_port = isOpen;
          }
        }
        // tag 2: vehicleLockState (0=UNLOCKED, 1=LOCKED, 2=INTERNAL_LOCKED, 3=SELECTIVE_UNLOCKED)
        if (vs.fieldNumber === 2 && vs.wireType === WIRE_VARINT) {
          result.telemetry.locked = (vs.value === 1 || vs.value === 2);
        }
        // tag 3: vehicleSleepStatus (1 = AWAKE, 2 = ASLEEP)
        if (vs.fieldNumber === 3 && vs.wireType === WIRE_VARINT) {
          result.vehicleSleepStatus = vs.value;
        }
      }
    }

    // tag 4: CommandStatus
    if (field.fieldNumber === 4 && field.wireType === WIRE_LENGTH_DELIMITED && field.data) {
      const cmdStatusFields = parseFields(field.data);
      let opStatus = OPERATIONSTATUS_OK;
      for (const cs of cmdStatusFields) {
        if (cs.fieldNumber === 1 && cs.wireType === WIRE_VARINT) {
          opStatus = cs.value;
        }
        // tag 2: signedMessageStatus (counter = 1, signedMessageInformation = 2)
        if (cs.fieldNumber === 2 && cs.wireType === WIRE_LENGTH_DELIMITED && cs.data) {
          const smsFields = parseFields(cs.data);
          result.domain = DOMAIN_VEHICLE_SECURITY;
          for (const sms of smsFields) {
            if (sms.fieldNumber === 1 && sms.wireType === WIRE_VARINT) {
              result.reportedCounter = sms.value;
            }
            if (sms.fieldNumber === 2 && sms.wireType === WIRE_VARINT && sms.value !== 0) {
              result.vcsecSignedMessageFault = sms.value;
            }
          }
        }
        // tag 3: whitelistOperationStatus
        if (cs.fieldNumber === 3 && cs.wireType === WIRE_LENGTH_DELIMITED && cs.data) {
          const wlFields = parseFields(cs.data);
          let wlInfo = 0;
          let wlOpStatus = opStatus;
          for (const wf of wlFields) {
            if (wf.fieldNumber === 1 && wf.wireType === WIRE_VARINT) wlInfo = wf.value;
            if (wf.fieldNumber === 3 && wf.wireType === WIRE_VARINT) wlOpStatus = wf.value;
          }
          if (wlInfo === 0 && wlOpStatus === OPERATIONSTATUS_OK) {
            result.whitelistOperationStatus = 'OK';
          } else if (wlOpStatus === OPERATIONSTATUS_WAIT) {
            result.whitelistOperationStatus = 'WAITING_FOR_CARD';
          } else {
            result.whitelistOperationStatus = 'ERROR';
            result.whitelistErrorCode = wlInfo;
          }
        }
      }
    }

    // tag 16: WhitelistInfo (numberOfEntries = 1, repeated KeyIdentifier whitelistEntries = 2)
    if (field.fieldNumber === 16 && field.wireType === WIRE_LENGTH_DELIMITED && field.data) {
      const wlInfoFields = parseFields(field.data);
      const keyIds = [];
      for (const wf of wlInfoFields) {
        if (wf.fieldNumber === 2 && wf.wireType === WIRE_LENGTH_DELIMITED && wf.data) {
          const kidFields = parseFields(wf.data);
          for (const kf of kidFields) {
            if (kf.fieldNumber === 1 && kf.wireType === WIRE_LENGTH_DELIMITED && kf.data) {
              keyIds.push(kf.data);
            }
          }
        }
      }
      result.whitelistKeyIds = keyIds;
    }
  }
}

/**
 * CarServer 도메인 (car_server.proto Response -> vehicle.proto VehicleData) 정밀 파서
 */
function parseCarServerResponse(fields, result) {
  for (const field of fields) {
    // CarServer.Response: tag 2 = vehicleData (VehicleData)
    if (field.fieldNumber === 2 && field.wireType === WIRE_LENGTH_DELIMITED && field.data) {
      const vdFields = parseFields(field.data);
      parseVehicleDataFields(vdFields, result.telemetry);
    }
  }
}

function parseVehicleDataFields(vdFields, telemetry) {
  for (const vf of vdFields) {
    if (vf.wireType !== WIRE_LENGTH_DELIMITED || !vf.data) continue;

    // 1. ChargeState (VehicleData tag 3)
    if (vf.fieldNumber === 3) {
      const csFields = parseFields(vf.data);
      for (const cf of csFields) {
        if (cf.fieldNumber === 1 && cf.wireType === WIRE_LENGTH_DELIMITED && cf.data) {
          const stateOneof = parseFields(cf.data);
          if (stateOneof.length > 0) {
            const stateMap = {
              1: 'Disconnected',
              2: 'Disconnected',
              3: 'Disconnected',
              4: 'Starting',
              5: 'Charging',
              6: 'Complete',
              7: 'Stopped',
              8: 'Calibrating'
            };
            telemetry.charging_state = stateMap[stateOneof[0].fieldNumber] || 'Disconnected';
          }
        }
        if (cf.fieldNumber === 104 && cf.wireType === WIRE_VARINT) {
          telemetry.charge_limit_soc = cf.value;
        }
        if (cf.fieldNumber === 111 && cf.wireType === WIRE_FIXED32 && typeof cf.floatValue === 'number') {
          if (!telemetry.ideal_battery_range_km) {
            telemetry.ideal_battery_range_km = Math.round(cf.floatValue * 1.60934);
          }
        }
        if (cf.fieldNumber === 113 && cf.wireType === WIRE_FIXED32 && typeof cf.floatValue === 'number') {
          telemetry.ideal_battery_range_km = Math.round(cf.floatValue * 1.60934);
        }
        if (cf.fieldNumber === 114 && cf.wireType === WIRE_VARINT) {
          telemetry.battery_level = Math.min(100, Math.max(0, cf.value));
        }
        if (cf.fieldNumber === 119 && cf.wireType === WIRE_VARINT) {
          telemetry.charger_voltage = cf.value;
        }
        if (cf.fieldNumber === 121 && cf.wireType === WIRE_VARINT) {
          telemetry.charger_actual_current = cf.value;
        }
        if (cf.fieldNumber === 122 && cf.wireType === WIRE_VARINT) {
          telemetry.charger_power = cf.value;
        }
        if (cf.fieldNumber === 123 && cf.wireType === WIRE_VARINT) {
          telemetry.time_to_full_charge = cf.value;
        }
      }
    }

    // 2. ClimateState (VehicleData tag 4)
    if (vf.fieldNumber === 4) {
      const climFields = parseFields(vf.data);
      for (const clf of climFields) {
        if (clf.fieldNumber === 101 && clf.wireType === WIRE_FIXED32 && typeof clf.floatValue === 'number') {
          telemetry.inside_temp = Number(clf.floatValue.toFixed(1));
        }
        if (clf.fieldNumber === 102 && clf.wireType === WIRE_FIXED32 && typeof clf.floatValue === 'number') {
          telemetry.outside_temp = Number(clf.floatValue.toFixed(1));
        }
      }
    }

    // 3. DriveState (VehicleData tag 5)
    if (vf.fieldNumber === 5) {
      const dsFields = parseFields(vf.data);
      let speedFound = false;
      let powerFound = false;
      for (const df of dsFields) {
        if (df.fieldNumber === 1 && df.wireType === WIRE_LENGTH_DELIMITED && df.data) {
          const shiftOneof = parseFields(df.data);
          if (shiftOneof.length > 0) {
            const gearMap = { 1: 'P', 2: 'P', 3: 'R', 4: 'N', 5: 'D', 6: 'P' };
            telemetry.gear = gearMap[shiftOneof[0].fieldNumber] || 'P';
          }
        }
        if (df.fieldNumber === 102 && df.wireType === WIRE_VARINT) {
          telemetry.speed = Math.round(df.value * 1.60934);
          speedFound = true;
        }
        if (df.fieldNumber === 106 && df.wireType === WIRE_FIXED32 && typeof df.floatValue === 'number') {
          telemetry.speed = Math.round(df.floatValue * 1.60934);
          speedFound = true;
        }
        if (df.fieldNumber === 103 && df.wireType === WIRE_VARINT) {
          telemetry.power = toSignedInt32(df.value);
          powerFound = true;
        }
      }
      if (!speedFound) telemetry.speed = 0;
      if (!powerFound) telemetry.power = 0;
    }

    // 4. ClosuresState (VehicleData tag 9) - proto3 생략 시 닫힘(false) 처리
    if (vf.fieldNumber === 9) {
      const clFields = parseFields(vf.data);
      const doors = {
        df: false, pf: false, dr: false, pr: false, ft: false, rt: false, charge_port: false
      };
      for (const cf of clFields) {
        if (cf.fieldNumber === 101 && cf.wireType === WIRE_VARINT) doors.df = !!cf.value;
        if (cf.fieldNumber === 102 && cf.wireType === WIRE_VARINT) doors.dr = !!cf.value;
        if (cf.fieldNumber === 103 && cf.wireType === WIRE_VARINT) doors.pf = !!cf.value;
        if (cf.fieldNumber === 104 && cf.wireType === WIRE_VARINT) doors.pr = !!cf.value;
        if (cf.fieldNumber === 105 && cf.wireType === WIRE_VARINT) doors.ft = !!cf.value;
        if (cf.fieldNumber === 106 && cf.wireType === WIRE_VARINT) doors.rt = !!cf.value;
      }
      telemetry.doors = doors;
    }

    // 5. TirePressureState (VehicleData tag 19) -> Bar(float)를 psi로 변환 (1 Bar = 14.5037738 psi)
    if (vf.fieldNumber === 19) {
      const tpFields = parseFields(vf.data);
      const tpms = {};
      for (const tf of tpFields) {
        if (tf.wireType === WIRE_FIXED32 && typeof tf.floatValue === 'number') {
          const psi = Math.round(tf.floatValue * 14.5037738);
          if (tf.fieldNumber === 2) tpms.fl = psi;
          if (tf.fieldNumber === 3) tpms.fr = psi;
          if (tf.fieldNumber === 4) tpms.rl = psi;
          if (tf.fieldNumber === 5) tpms.rr = psi;
        }
      }
      if (Object.keys(tpms).length > 0) {
        telemetry.tpms = tpms;
      }
    }
  }
}
