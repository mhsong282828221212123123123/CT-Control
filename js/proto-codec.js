/**
 * proto-codec.js
 * Tesla vehicle-command 공식 Protobuf 규격 100% 준수 인코더/디코더 [v11]:
 * - universal_message.proto (RoutableMessage, SessionInfoRequest, MessageStatus)
 * - signatures.proto (SignatureData, AES_GCM_Personalized_Signature_Data, SessionInfo)
 * - vcsec.proto (ToVCSECMessage, UnsignedMessage, FromVCSECMessage, ClosureMoveRequest, RKEAction)
 * - car_server.proto & vehicle.proto (Action, GetVehicleData, Response, VehicleData, DriveState, ChargeState, ClimateState, TirePressureState)
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

/**
 * 1. Protobuf 저수준 와이어 포맷 인코더/디코더
 */

export function encodeVarint(value) {
  let val = Math.floor(Number(value));
  if (val < 0) {
    // 음수 int32의 경우 부호 없는 32비트 정수로 변환
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

// 부호 있는 32비트 정수 변환 헬퍼 (음수 회생제동 출력 및 영하 온도 처리)
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
 * - tag 50 (request_uuid): 16B random UUID
 */
export function wrapToRoutableMessage(payloadBytes, domain = DOMAIN_VEHICLE_SECURITY, routingAddress = null) {
  const toDest = encodeLengthDelimitedField(6, encodeVarintField(1, domain));

  let fromDest = new Uint8Array(0);
  if (routingAddress && routingAddress.length === 16) {
    fromDest = encodeLengthDelimitedField(7, encodeLengthDelimitedField(2, routingAddress));
  }

  const payloadField = encodeLengthDelimitedField(10, payloadBytes);

  const uuid = new Uint8Array(16);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(uuid);
  }
  const uuidField = encodeLengthDelimitedField(50, uuid);

  return concatBytes(toDest, fromDest, payloadField, uuidField);
}

/**
 * 세션 핸드셰이크 요청 빌더 (SessionInfoRequest)
 * RoutableMessage:
 * - tag 6 (to_destination): { tag 1: domain }
 * - tag 7 (from_destination): { tag 2: routingAddress (16B) }
 * - tag 14 (session_info_request): SessionInfoRequest { tag 1 (public_key): 65B }
 * - tag 50 (request_uuid): 16B
 * - tag 51 (uuid): 16B
 */
export function buildSessionInfoRequest(publicKeyBytes, domain = DOMAIN_VEHICLE_SECURITY, routingAddress = null) {
  const toDest = encodeLengthDelimitedField(6, encodeVarintField(1, domain));

  const addr = (routingAddress && routingAddress.length === 16) ? routingAddress : new Uint8Array(16);
  const fromDest = encodeLengthDelimitedField(7, encodeLengthDelimitedField(2, addr));

  // SessionInfoRequest: tag 1 = public_key (65 bytes)
  const sessionInfoReqMsg = encodeLengthDelimitedField(1, publicKeyBytes);
  const sessionInfoReqField = encodeLengthDelimitedField(14, sessionInfoReqMsg);

  const uuid = new Uint8Array(16);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(uuid);
  }
  const reqUuidField = encodeLengthDelimitedField(50, uuid);
  const uuidField = encodeLengthDelimitedField(51, uuid);

  return concatBytes(toDest, fromDest, sessionInfoReqField, reqUuidField, uuidField);
}

/**
 * AES-128-GCM 암호화 및 SignatureData가 포함된 공식 RoutableMessage 생성기
 * (teslamotors/vehicle-command 및 yoziru/tesla-ble build_universal_message_with_payload 동일 규격)
 */
export async function buildEncryptedRoutableMessage(plaintextBytes, domain, cryptoStore) {
  if (!cryptoStore || !cryptoStore.publicKeyRaw) {
    throw new Error('가상키가 생성되지 않았습니다.');
  }

  // 세션이 아직 수립되지 않은 경우: VCSEC 도메인은 평문 RoutableMessage 폴백, Infotainment는 에러 반환
  if (!cryptoStore.hasValidSession(domain)) {
    if (domain === DOMAIN_VEHICLE_SECURITY) {
      return wrapToRoutableMessage(plaintextBytes, domain, cryptoStore.routingAddress);
    }
    throw new Error(`차량 보안 세션(도메인 ${domain}) 핸드셰이크 대기 중입니다.`);
  }

  // 1. ECDH 유도 AES-128-GCM 키로 암호화 및 16바이트 GCM 태그 생성
  const enc = await cryptoStore.encryptPayload(domain, plaintextBytes, 0);

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

  // 5. RoutableMessage 패킹
  const toDest = encodeLengthDelimitedField(6, encodeVarintField(1, domain));
  const fromDest = encodeLengthDelimitedField(7, encodeLengthDelimitedField(2, cryptoStore.routingAddress));
  const payloadField = encodeLengthDelimitedField(10, enc.ciphertext);

  const uuid = new Uint8Array(16);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(uuid);
  }
  const reqUuidField = encodeLengthDelimitedField(50, uuid);

  return concatBytes(toDest, fromDest, payloadField, signatureDataField, reqUuidField);
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
 * 도어 언래치(물리 개방) 액션 (VCSEC ClosureMoveRequest)
 */
export async function buildOpenDoorAction(doorIndex, cryptoStore) {
  const closureFieldTag = doorIndex + 1; // 1: FL, 2: FR, 3: RL, 4: RR
  const doorMoveField = encodeVarintField(closureFieldTag, CLOSURE_MOVE_TYPE_MOVE);
  const unsignedMessage = encodeLengthDelimitedField(4, doorMoveField);
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
    // CarServer ChargingStartStopAction { stop (tag 5): Void } -> VehicleAction (tag 6) -> Action (tag 2)
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
 * CarServer(DOMAIN_INFOTAINMENT) 보조 계기판 텔레메트리 요청 빌더 (공식 car_server.proto GetVehicleData)
 * - getChargeState = 2
 * - getClimateState = 3
 * - getDriveState = 4
 * - getClosuresState = 8
 * - getTirePressureState = 14
 */
export async function buildGetVehicleDataRequest(cryptoStore) {
  const empty = new Uint8Array(0);
  const getVehicleData = concatBytes(
    encodeLengthDelimitedField(2, empty),  // getChargeState
    encodeLengthDelimitedField(3, empty),  // getClimateState
    encodeLengthDelimitedField(4, empty),  // getDriveState
    encodeLengthDelimitedField(8, empty),  // getClosuresState
    encodeLengthDelimitedField(14, empty)  // getTirePressureState
  );
  // VehicleAction: tag 1 = getVehicleData
  const vehicleAction = encodeLengthDelimitedField(1, getVehicleData);
  // Action: tag 2 = vehicleAction
  const action = encodeLengthDelimitedField(2, vehicleAction);

  return await buildEncryptedRoutableMessage(action, DOMAIN_INFOTAINMENT, cryptoStore);
}

/**
 * 4. 수신 패킷 정밀 파서 (RoutableMessage / FromVCSECMessage / CarServer.Response)
 * - 수신된 필드만 delta 형태로 telemetry 객체에 기록하여 기존 캐시 덮어쓰기 버그 원천 차단
 */
export function parseIncomingMessage(uint8Array) {
  const result = {
    rawLength: uint8Array ? uint8Array.length : 0,
    domain: null,
    whitelistOperationStatus: null, // 'OK' | 'WAITING_FOR_CARD' | 'ERROR'
    whitelistErrorCode: null,
    signedMessageFault: null,       // universal_message.proto MessageFault_E
    sessionInfo: null,              // { counter, publicKey, epoch, clockTime, status }
    reportedCounter: null,
    vehicleSleepStatus: null,       // 1: AWAKE, 2: ASLEEP
    telemetry: {}                   // 실제로 패킷에서 파싱된 텔레메트리 필드만 담음
  };

  if (!uint8Array || uint8Array.length === 0) return result;

  try {
    let payloadBytes = uint8Array;
    let rootFields = parseFields(payloadBytes);

    // 1. RoutableMessage 봉투(Envelope) 파싱
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
    }

    // RoutableMessage 내부 tag 10 (protobuf_message_as_bytes) 추출
    const routablePayloadField = rootFields.find((f) => f.fieldNumber === 10 && f.wireType === WIRE_LENGTH_DELIMITED);
    if (routablePayloadField && routablePayloadField.data) {
      payloadBytes = routablePayloadField.data;
      rootFields = parseFields(payloadBytes);
    } else if (isRoutable) {
      // session_info 또는 상태만 있는 RoutableMessage면 여기서 반환
      return result;
    }

    // 2. 도메인별 내부 페이로드 파싱
    if (result.domain === DOMAIN_INFOTAINMENT) {
      parseCarServerResponse(rootFields, result);
    } else {
      // 기본값: VCSEC (FromVCSECMessage) 파싱 시도 후, CarServer VehicleData 필드가 있으면 함께 파싱
      parseFromVCSEC(rootFields, result);
      parseCarServerResponse(rootFields, result);
    }
  } catch (err) {
    console.warn('[proto-codec] parse error:', err);
  }

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
      for (const vs of vsFields) {
        // tag 1: ClosureStatuses
        if (vs.fieldNumber === 1 && vs.wireType === WIRE_LENGTH_DELIMITED && vs.data) {
          const closureFields = parseFields(vs.data);
          // VCSEC ClosureStatuses가 오면 기본 닫힘(false)에서 열린 문만 true로 세팅 (proto3 기본값 0 생략 대응)
          const doors = {
            df: false, pf: false, dr: false, pr: false, ft: false, rt: false, charge_port: false
          };
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
          result.telemetry.doors = doors;
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
      // proto3에서 기본값 0(OPERATIONSTATUS_OK)은 생략됨
      let opStatus = OPERATIONSTATUS_OK;
      for (const cs of cmdStatusFields) {
        if (cs.fieldNumber === 1 && cs.wireType === WIRE_VARINT) {
          opStatus = cs.value;
          if (opStatus === OPERATIONSTATUS_WAIT) {
            result.whitelistOperationStatus = 'WAITING_FOR_CARD';
          } else if (opStatus === OPERATIONSTATUS_ERROR) {
            result.whitelistOperationStatus = 'ERROR';
          }
        }
        // tag 2: signedMessageStatus
        if (cs.fieldNumber === 2 && cs.wireType === WIRE_LENGTH_DELIMITED && cs.data) {
          const smsFields = parseFields(cs.data);
          for (const sms of smsFields) {
            if (sms.fieldNumber === 1 && sms.wireType === WIRE_VARINT) {
              result.reportedCounter = sms.value;
            }
          }
        }
        // tag 3: whitelistOperationStatus (teslamotors/vehicle-command vcsec.go L132-142 규격)
        if (cs.fieldNumber === 3 && cs.wireType === WIRE_LENGTH_DELIMITED && cs.data) {
          const wlFields = parseFields(cs.data);
          let wlInfo = 0; // WHITELISTOPERATION_INFORMATION_NONE = 0 (proto3 생략 시 0)
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
        // tag 1: charging_state (ChargingState submessage oneof: 1=Unknown, 2=Disconnected, 3=NoPower, 4=Starting, 5=Charging, 6=Complete, 7=Stopped)
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
        // tag 104: charge_limit_soc (int32)
        if (cf.fieldNumber === 104 && cf.wireType === WIRE_VARINT) {
          telemetry.charge_limit_soc = cf.value;
        }
        // tag 111: battery_range (float, miles -> km)
        if (cf.fieldNumber === 111 && cf.wireType === WIRE_FIXED32 && typeof cf.floatValue === 'number') {
          if (!telemetry.ideal_battery_range_km) {
            telemetry.ideal_battery_range_km = Math.round(cf.floatValue * 1.60934);
          }
        }
        // tag 113: ideal_battery_range (float, miles -> km)
        if (cf.fieldNumber === 113 && cf.wireType === WIRE_FIXED32 && typeof cf.floatValue === 'number') {
          telemetry.ideal_battery_range_km = Math.round(cf.floatValue * 1.60934);
        }
        // tag 114: battery_level (int32, %)
        if (cf.fieldNumber === 114 && cf.wireType === WIRE_VARINT) {
          telemetry.battery_level = Math.min(100, Math.max(0, cf.value));
        }
        // tag 119: charger_voltage (int32, V)
        if (cf.fieldNumber === 119 && cf.wireType === WIRE_VARINT) {
          telemetry.charger_voltage = cf.value;
        }
        // tag 121: charger_actual_current (int32, A)
        if (cf.fieldNumber === 121 && cf.wireType === WIRE_VARINT) {
          telemetry.charger_actual_current = cf.value;
        }
        // tag 122: charger_power (int32, kW)
        if (cf.fieldNumber === 122 && cf.wireType === WIRE_VARINT) {
          telemetry.charger_power = cf.value;
        }
        // tag 123: minutes_to_full_charge (int32)
        if (cf.fieldNumber === 123 && cf.wireType === WIRE_VARINT) {
          telemetry.time_to_full_charge = cf.value;
        }
      }
    }

    // 2. ClimateState (VehicleData tag 4)
    if (vf.fieldNumber === 4) {
      const climFields = parseFields(vf.data);
      for (const clf of climFields) {
        // tag 101: inside_temp_celsius (float)
        if (clf.fieldNumber === 101 && clf.wireType === WIRE_FIXED32 && typeof clf.floatValue === 'number') {
          telemetry.inside_temp = Number(clf.floatValue.toFixed(1));
        }
        // tag 102: outside_temp_celsius (float)
        if (clf.fieldNumber === 102 && clf.wireType === WIRE_FIXED32 && typeof clf.floatValue === 'number') {
          telemetry.outside_temp = Number(clf.floatValue.toFixed(1));
        }
      }
    }

    // 3. DriveState (VehicleData tag 5)
    if (vf.fieldNumber === 5) {
      const dsFields = parseFields(vf.data);
      // DriveState 응답에 speed 필드가 생략(proto3 0mph)된 경우 0km/h로 반영
      let speedFound = false;
      let powerFound = false;
      for (const df of dsFields) {
        // tag 1: shift_state (ShiftState oneof: 1=Invalid, 2=P, 3=R, 4=N, 5=D, 6=SNA)
        if (df.fieldNumber === 1 && df.wireType === WIRE_LENGTH_DELIMITED && df.data) {
          const shiftOneof = parseFields(df.data);
          if (shiftOneof.length > 0) {
            const gearMap = { 1: 'P', 2: 'P', 3: 'R', 4: 'N', 5: 'D', 6: 'P' };
            telemetry.gear = gearMap[shiftOneof[0].fieldNumber] || 'P';
          }
        }
        // tag 102: speed (uint32, mph -> km/h 변환)
        if (df.fieldNumber === 102 && df.wireType === WIRE_VARINT) {
          telemetry.speed = Math.round(df.value * 1.60934);
          speedFound = true;
        }
        // tag 106: speed_float (float, mph -> km/h 변환)
        if (df.fieldNumber === 106 && df.wireType === WIRE_FIXED32 && typeof df.floatValue === 'number') {
          telemetry.speed = Math.round(df.floatValue * 1.60934);
          speedFound = true;
        }
        // tag 103: power (int32, kW - 음수 회생제동 포함)
        if (df.fieldNumber === 103 && df.wireType === WIRE_VARINT) {
          telemetry.power = toSignedInt32(df.value);
          powerFound = true;
        }
      }
      if (!speedFound) telemetry.speed = 0;
      if (!powerFound) telemetry.power = 0;
    }

    // 4. ClosuresState (VehicleData tag 9)
    if (vf.fieldNumber === 9) {
      const clFields = parseFields(vf.data);
      const doors = telemetry.doors || {};
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

    // 5. TirePressureState (VehicleData tag 19)
    if (vf.fieldNumber === 19) {
      const tpFields = parseFields(vf.data);
      const tpms = {};
      for (const tf of tpFields) {
        if (tf.wireType === WIRE_FIXED32 && typeof tf.floatValue === 'number') {
          const bar = Number(tf.floatValue.toFixed(2));
          if (tf.fieldNumber === 2) tpms.fl = bar;
          if (tf.fieldNumber === 3) tpms.fr = bar;
          if (tf.fieldNumber === 4) tpms.rl = bar;
          if (tf.fieldNumber === 5) tpms.rr = bar;
        }
      }
      if (Object.keys(tpms).length > 0) {
        telemetry.tpms = tpms;
      }
    }
  }
}
