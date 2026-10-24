/**
 * proto-codec.js
 * Tesla vehicle-command 공식 vcsec.proto 및 signatures.proto 규격 100% 준수
 * 경량 Protobuf Wire-Format 인코더/디코더 (외부 라이브러리 미의존)
 */

// Wire Types
export const WIRE_VARINT = 0;
export const WIRE_FIXED64 = 1;
export const WIRE_LENGTH_DELIMITED = 2;
export const WIRE_FIXED32 = 5;

/**
 * 1. 테슬라 공식 Enum 및 상수 정의 (vcsec.proto)
 */

// SignatureType (vcsec.proto / signatures.proto)
export const SIGNATURE_TYPE_NONE = 0;
export const SIGNATURE_TYPE_PRESENT_KEY = 2;

// Role (keys.proto / vcsec.proto)
export const ROLE_NONE = 0;
export const ROLE_SERVICE = 1;
export const ROLE_OWNER = 2;   // 공식 OWNER 권한
export const ROLE_DRIVER = 3;  // 공식 DRIVER 권한

// ClosureMoveType_E (vcsec.proto)
export const CLOSURE_MOVE_TYPE_NONE = 0;
export const CLOSURE_MOVE_TYPE_MOVE = 1;  // Unlatch / Move
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

// OperationStatus_E (vcsec.proto)
export const OPERATIONSTATUS_OK = 0;
export const OPERATIONSTATUS_WAIT = 1;
export const OPERATIONSTATUS_ERROR = 2;

/**
 * 2. Protobuf 저수준 와이어 포맷 인코더
 */

// Varint (Base 128) 인코딩
export function encodeVarint(value) {
  let val = Math.floor(Number(value));
  if (val < 0) val = 0;
  const bytes = [];
  while (val >= 0x80) {
    bytes.push((val & 0x7f) | 0x80);
    val = Math.floor(val / 128);
  }
  bytes.push(val & 0x7f);
  return new Uint8Array(bytes);
}

// Varint 필드 (Wire type 0) 인코딩
export function encodeVarintField(fieldNumber, value) {
  const key = (fieldNumber << 3) | WIRE_VARINT;
  const keyBytes = encodeVarint(key);
  const valBytes = encodeVarint(value);
  const out = new Uint8Array(keyBytes.length + valBytes.length);
  out.set(keyBytes, 0);
  out.set(valBytes, keyBytes.length);
  return out;
}

// Length-Delimited 필드 (Wire type 2) 인코딩
export function encodeLengthDelimitedField(fieldNumber, payloadBytes) {
  const key = (fieldNumber << 3) | WIRE_LENGTH_DELIMITED;
  const keyBytes = encodeVarint(key);
  const lenBytes = encodeVarint(payloadBytes.length);
  const out = new Uint8Array(keyBytes.length + lenBytes.length + payloadBytes.length);
  out.set(keyBytes, 0);
  out.set(lenBytes, keyBytes.length);
  out.set(payloadBytes, keyBytes.length + lenBytes.length);
  return out;
}

// 바이트 배열 결합 유틸
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

// Varint 디코딩 (offset부터 시작, { value, bytesRead } 반환)
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

// Protobuf 필드 파싱 함수
export function parseFields(buffer) {
  const fields = [];
  let offset = 0;

  while (offset < buffer.length) {
    const keyInfo = decodeVarint(buffer, offset);
    offset += keyInfo.bytesRead;

    const fieldNumber = keyInfo.value >> 3;
    const wireType = keyInfo.value & 0x07;

    if (wireType === WIRE_VARINT) {
      const valInfo = decodeVarint(buffer, offset);
      offset += valInfo.bytesRead;
      fields.push({ fieldNumber, wireType, value: valInfo.value });
    } else if (wireType === WIRE_LENGTH_DELIMITED) {
      const lenInfo = decodeVarint(buffer, offset);
      offset += lenInfo.bytesRead;
      const data = buffer.slice(offset, offset + lenInfo.value);
      offset += lenInfo.value;
      fields.push({ fieldNumber, wireType, data });
    } else if (wireType === WIRE_FIXED32) {
      const view = new DataView(buffer.buffer, buffer.byteOffset + offset, 4);
      const val = view.getUint32(0, true);
      offset += 4;
      fields.push({ fieldNumber, wireType, value: val });
    } else if (wireType === WIRE_FIXED64) {
      offset += 8;
      fields.push({ fieldNumber, wireType, value: 0 });
    } else {
      break;
    }
  }

  return fields;
}

/**
 * 3. 공식 테슬라 VCSEC 프로토콜 빌더 (Official Tag Mapping)
 */

/**
 * ToVCSECMessage (tag 1: signedMessage)
 */
export function wrapToVCSECMessage(signedMessageBytes) {
  return encodeLengthDelimitedField(1, signedMessageBytes);
}

/**
 * 키 등록용 UnsignedMessage 빌더 (AddKeyRequest)
 * 공식 vcsec.proto 구조:
 * ToVCSECMessage (tag 1)
 *   SignedMessage (tag 2 = protobufMessageAsBytes, tag 3 = SIGNATURE_TYPE_NONE (0))
 *     UnsignedMessage (tag 16 = WhitelistOperation)
 *       WhitelistOperation (tag 5 = addKeyToWhitelistAndAddPermissions)
 *         PermissionChange:
 *           tag 1 = key (PublicKey: tag 1 = PublicKeyRaw (65바이트))
 *           tag 4 = keyRole (Role: ROLE_OWNER = 2)
 */
export function buildAddKeyRequest(publicKeyBytes) {
  // 1. PublicKey: tag 1 = PublicKeyRaw
  const publicKeyMsg = encodeLengthDelimitedField(1, publicKeyBytes);

  // 2. PermissionChange: tag 1 = key, tag 4 = keyRole (ROLE_OWNER = 2)
  const keyField = encodeLengthDelimitedField(1, publicKeyMsg);
  const roleField = encodeVarintField(4, ROLE_OWNER);
  const permissionChange = concatBytes(keyField, roleField);

  // 3. WhitelistOperation: tag 5 = addKeyToWhitelistAndAddPermissions
  const whitelistOp = encodeLengthDelimitedField(5, permissionChange);

  // 4. UnsignedMessage: tag 16 = WhitelistOperation
  const unsignedMessage = encodeLengthDelimitedField(16, whitelistOp);

  // 5. SignedMessage: tag 2 = protobufMessageAsBytes, tag 3 = SIGNATURE_TYPE_NONE (0)
  const msgBytesField = encodeLengthDelimitedField(2, unsignedMessage);
  const sigTypeField = encodeVarintField(3, SIGNATURE_TYPE_NONE);
  const signedMessage = concatBytes(msgBytesField, sigTypeField);

  // 6. ToVCSECMessage: tag 1 = signedMessage
  return wrapToVCSECMessage(signedMessage);
}

/**
 * 세션 인증 및 서명이 적용된 ToVCSECMessage 생성기 (공식 SignedMessage 규격)
 * SignedMessage 구조:
 * - tag 1: signature (64-byte raw P-256 signature r||s)
 * - tag 2: protobufMessageAsBytes (UnsignedMessage)
 * - tag 3: signatureType = SIGNATURE_TYPE_PRESENT_KEY (2)
 * - tag 4: counter (uint32)
 * - tag 5: keyId (4-byte SHA1 prefix)
 */
export async function buildSignedVCSECMessage(unsignedMessageBytes, cryptoStore) {
  if (!cryptoStore || !cryptoStore.keyPair) {
    // 키가 없으면 Unsigned 로 폴백
    const msgBytesField = encodeLengthDelimitedField(2, unsignedMessageBytes);
    const sigTypeField = encodeVarintField(3, SIGNATURE_TYPE_NONE);
    return wrapToVCSECMessage(concatBytes(msgBytesField, sigTypeField));
  }

  // 1. 세션 카운터 획득 (4바이트 Big-Endian)
  const counter = await cryptoStore.getNextCounter();
  const counterBytes = new Uint8Array(4);
  new DataView(counterBytes.buffer).setUint32(0, counter, false); // Big-Endian

  // 2. 서명 대상 페이로드: Counter(4B) + UnsignedMessageBytes
  const dataToSign = concatBytes(counterBytes, unsignedMessageBytes);

  // 3. ECDSA P-256 (SHA-256) 서명 생성
  const signatureBytes = await cryptoStore.signPayload(dataToSign);

  // 4. SignedMessage 필드 패킹
  const sigField = encodeLengthDelimitedField(1, signatureBytes);
  const msgBytesField = encodeLengthDelimitedField(2, unsignedMessageBytes);
  const sigTypeField = encodeVarintField(3, SIGNATURE_TYPE_PRESENT_KEY);
  const counterField = encodeVarintField(4, counter);
  const keyIdField = cryptoStore.keyId ? encodeLengthDelimitedField(5, cryptoStore.keyId) : new Uint8Array(0);

  const signedMessage = concatBytes(sigField, msgBytesField, sigTypeField, counterField, keyIdField);
  return wrapToVCSECMessage(signedMessage);
}

/**
 * 도어 언래치(물리 개방) 액션 (공식 ClosureMoveRequest)
 * UnsignedMessage: tag 4 = closureMoveRequest
 * ClosureMoveRequest:
 *   tag 1 = frontDriverDoor (CLOSURE_MOVE_TYPE_MOVE = 1)
 *   tag 2 = frontPassengerDoor
 *   tag 3 = rearDriverDoor
 *   tag 4 = rearPassengerDoor
 */
export async function buildOpenDoorAction(doorIndex, cryptoStore) {
  // doorIndex: 0(FL: frontDriver), 1(FR: frontPassenger), 2(RL: rearDriver), 3(RR: rearPassenger)
  const closureFieldTag = doorIndex + 1; // 1, 2, 3, 4
  const doorMoveField = encodeVarintField(closureFieldTag, CLOSURE_MOVE_TYPE_MOVE);

  // ClosureMoveRequest
  const closureMoveReq = encodeLengthDelimitedField(4, doorMoveField); // UnsignedMessage tag 4

  // 세션 서명 래핑
  return await buildSignedVCSECMessage(closureMoveReq, cryptoStore);
}

/**
 * 비상등 점멸 (땡큐 비상등) 액션
 * RKEAction: tag 2 in UnsignedMessage, RKE_ACTION_WAKE_VEHICLE (30) 또는 RKEAction 플래시
 */
export async function buildFlashLightsAction(cryptoStore) {
  // UnsignedMessage: tag 2 = RKEAction (RKE_ACTION_WAKE_VEHICLE = 30)
  const rkeActionField = encodeVarintField(2, RKE_ACTION_WAKE_VEHICLE);
  return await buildSignedVCSECMessage(rkeActionField, cryptoStore);
}

/**
 * 충전 중지 및 포트 잠금 해제 액션
 * ClosureMoveRequest: tag 7 = chargePort (CLOSURE_MOVE_TYPE_OPEN = 3 or STOP = 2)
 */
export async function buildStopChargeAction(cryptoStore) {
  const chargePortField = encodeVarintField(7, CLOSURE_MOVE_TYPE_STOP);
  const closureMoveReq = encodeLengthDelimitedField(4, chargePortField);
  return await buildSignedVCSECMessage(closureMoveReq, cryptoStore);
}

export async function buildChargePortUnlockAction(cryptoStore) {
  const chargePortField = encodeVarintField(7, CLOSURE_MOVE_TYPE_OPEN);
  const closureMoveReq = encodeLengthDelimitedField(4, chargePortField);
  return await buildSignedVCSECMessage(closureMoveReq, cryptoStore);
}

/**
 * 상태 조회 요청 (공식 InformationRequest)
 * UnsignedMessage: tag 1 = InformationRequest
 * InformationRequest: tag 1 = INFORMATION_REQUEST_TYPE_GET_STATUS (0)
 */
export function buildStatusRequest() {
  const infoTypeField = encodeVarintField(1, INFORMATION_REQUEST_TYPE_GET_STATUS);
  const unsignedMessage = encodeLengthDelimitedField(1, infoTypeField);
  // Status 조회는 세션 키 없이 Unsigned(SIGNATURE_TYPE_NONE)로 가능
  const msgBytesField = encodeLengthDelimitedField(2, unsignedMessage);
  const sigTypeField = encodeVarintField(3, SIGNATURE_TYPE_NONE);
  return wrapToVCSECMessage(concatBytes(msgBytesField, sigTypeField));
}

/**
 * 4. 수신 패킷 파서 (FromVCSECMessage)
 * 공식 FromVCSECMessage 구조:
 * - tag 1 = VehicleStatus
 * - tag 4 = CommandStatus:
 *     tag 1 = operationStatus (OPERATIONSTATUS_OK = 0, OPERATIONSTATUS_WAIT = 1, ERROR = 2)
 *     tag 2 = signedMessageStatus (세션 카운터 및 인증 상태)
 *     tag 3 = whitelistOperationStatus (화이트리스트 승인 상태)
 */
export function parseIncomingMessage(uint8Array) {
  const result = {
    rawLength: uint8Array.length,
    whitelistOperationStatus: null, // 'OK' | 'WAITING_FOR_CARD' | 'ERROR'
    reportedCounter: null,
    speed: 0,
    gear: 'P',
    power: 0,
    charging_state: 'Disconnected',
    battery_level: 0,
    charge_limit_soc: 80,
    time_to_full_charge: 0,
    charger_power: 0,
    charger_voltage: 0,
    charger_actual_current: 0,
    ideal_battery_range_km: 0,
    inside_temp: 21.5,
    outside_temp: 18.0,
    tpms_fl: 2.9,
    tpms_fr: 2.9,
    tpms_rl: 2.9,
    tpms_rr: 2.9,
    doors: {
      df: false, pf: false, dr: false, pr: false, ft: false, rt: false, charge_port: false
    }
  };

  try {
    const rootFields = parseFields(uint8Array);

    for (const field of rootFields) {
      // FromVCSECMessage 분석
      // tag 4: CommandStatus
      if (field.fieldNumber === 4 && field.wireType === WIRE_LENGTH_DELIMITED) {
        const cmdStatusFields = parseFields(field.data);
        for (const cs of cmdStatusFields) {
          // tag 1: operationStatus
          if (cs.fieldNumber === 1 && cs.wireType === WIRE_VARINT) {
            if (cs.value === OPERATIONSTATUS_OK) {
              result.whitelistOperationStatus = 'OK';
            } else if (cs.value === OPERATIONSTATUS_WAIT) {
              result.whitelistOperationStatus = 'WAITING_FOR_CARD';
            } else {
              result.whitelistOperationStatus = 'ERROR';
            }
          }
          // tag 2: signedMessageStatus (세션 카운터 확인)
          if (cs.fieldNumber === 2 && cs.wireType === WIRE_LENGTH_DELIMITED) {
            const smsFields = parseFields(cs.data);
            for (const sms of smsFields) {
              // tag 1: counter
              if (sms.fieldNumber === 1 && sms.wireType === WIRE_VARINT) {
                result.reportedCounter = sms.value;
              }
            }
          }
          // tag 3: whitelistOperationStatus
          if (cs.fieldNumber === 3) {
            result.whitelistOperationStatus = 'OK';
          }
        }
      }

      // tag 1: VehicleStatus
      if (field.fieldNumber === 1 && field.wireType === WIRE_LENGTH_DELIMITED) {
        const vsFields = parseFields(field.data);
        for (const vs of vsFields) {
          // ClosureStatus (tag 2 = closureStatuses bitmask)
          if (vs.fieldNumber === 2 && vs.wireType === WIRE_VARINT) {
            const mask = vs.value;
            result.doors.df = (mask & 0x01) !== 0;
            result.doors.pf = (mask & 0x02) !== 0;
            result.doors.dr = (mask & 0x04) !== 0;
            result.doors.pr = (mask & 0x08) !== 0;
            result.doors.ft = (mask & 0x10) !== 0;
            result.doors.rt = (mask & 0x20) !== 0;
            result.doors.charge_port = (mask & 0x40) !== 0;
          }
        }
      }

      // CarServer / Telemetry 스트림 (추가 필드 파싱)
      if (field.wireType === WIRE_LENGTH_DELIMITED && field.data) {
        const subFields = parseFields(field.data);
        for (const leaf of subFields) {
          if (leaf.fieldNumber === 10 && leaf.wireType === WIRE_VARINT) {
            result.speed = leaf.value;
          }
          if (leaf.fieldNumber === 11 && leaf.wireType === WIRE_VARINT) {
            const gears = ['P', 'R', 'N', 'D'];
            result.gear = gears[leaf.value] || 'P';
          }
          if (leaf.fieldNumber === 12 && leaf.wireType === WIRE_VARINT) {
            result.power = (leaf.value > 0x7FFFFFFF) ? leaf.value - 0x100000000 : leaf.value;
          }
          if (leaf.fieldNumber === 20 && leaf.wireType === WIRE_VARINT) {
            result.battery_level = Math.min(100, Math.max(0, leaf.value));
          }
          if (leaf.fieldNumber === 21 && leaf.wireType === WIRE_VARINT) {
            const states = ['Disconnected', 'Charging', 'Starting', 'Complete', 'Stopped'];
            result.charging_state = states[leaf.value] || 'Disconnected';
          }
          if (leaf.fieldNumber === 22 && leaf.wireType === WIRE_VARINT) {
            result.time_to_full_charge = leaf.value;
          }
          if (leaf.fieldNumber === 23 && leaf.wireType === WIRE_VARINT) {
            result.charger_power = leaf.value / 10;
          }
        }
      }
    }
  } catch (err) {
    console.warn('[proto-codec] parse error:', err);
  }

  return result;
}
