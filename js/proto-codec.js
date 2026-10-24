/**
 * proto-codec.js
 * 경량 Protobuf Wire-Format 인코더 및 디코더 (외부 라이브러리 미의존)
 * 테슬라 VCSEC 및 CarServer 프로토콜 지원
 */

// Wire Types
export const WIRE_VARINT = 0;
export const WIRE_FIXED64 = 1;
export const WIRE_LENGTH_DELIMITED = 2;
export const WIRE_FIXED32 = 5;

/**
 * 1. 기본 Protobuf 저수준 프리미티브
 */

// Varint (Base 128) 인코딩
export function encodeVarint(value) {
  let val = Math.floor(Number(value));
  if (val < 0) val = 0; // Protobuf unsigned varint
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

// 바이트 배열들 합치기
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

// Length-Delimited 또는 서브메시지 필드 파싱 헬퍼
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
      // 8 바이트 스킵
      offset += 8;
      fields.push({ fieldNumber, wireType, value: 0 });
    } else {
      // 알 수 없는 wire type 발생 시 안전 탈출
      break;
    }
  }

  return fields;
}

/**
 * 2. 테슬라 VCSEC 및 CarServer Protobuf 빌더
 */

// VCSEC Role & FormFactor 상수
export const ROLE_OWNER = 1;
export const ROLE_DRIVER = 2;
export const KEY_FORM_FACTOR_ANDROID_DEVICE = 7;

/**
 * [빌더 1] 화이트리스트 키 등록 요청 (AddKeyRequest / WhitelistOperation)
 * Structure:
 * UnsignedMessage (tag 2 = WhitelistOperation)
 *   WhitelistOperation (tag 1 = addKeyToWhitelistAndAddPermissions)
 *     PermissionChange:
 *       tag 1: PublicKey (raw 65B)
 *       tag 2: Role (ROLE_OWNER = 1)
 *       tag 3: FormFactor (KEY_FORM_FACTOR_ANDROID_DEVICE = 7)
 */
export function buildAddKeyRequest(publicKeyBytes) {
  // PermissionChange payload
  const pubKeyField = encodeLengthDelimitedField(1, publicKeyBytes);
  const roleField = encodeVarintField(2, ROLE_OWNER);
  const formFactorField = encodeVarintField(3, KEY_FORM_FACTOR_ANDROID_DEVICE);
  const permissionChange = concatBytes(pubKeyField, roleField, formFactorField);

  // WhitelistOperation (tag 1 = addKeyToWhitelistAndAddPermissions)
  const addKeyField = encodeLengthDelimitedField(1, permissionChange);

  // UnsignedMessage (tag 2 = WhitelistOperation)
  const unsignedMessage = encodeLengthDelimitedField(2, addKeyField);

  // ToVCSEC Message Wrapper (tag 1 = unsignedMessage)
  return encodeLengthDelimitedField(1, unsignedMessage);
}

/**
 * [빌더 2] 도어 언래치(물리 개방) 액션 (RKEAction / ClosureMoveRequest)
 * doorIndex: 0 = FrontLeft(운전석), 1 = FrontRight(조수석), 2 = RearLeft, 3 = RearRight
 */
export function buildOpenDoorAction(doorIndex) {
  // Tesla ClosureMoveRequest:
  // doorIndex 매핑 (1-based: 1=FrontDriver, 2=FrontPassenger, 3=RearDriver, 4=RearPassenger)
  const closureIndex = doorIndex + 1;
  
  // ClosureMoveRequest (tag 1: closure = closureIndex, tag 2: action = 1: MOVE_OPEN / UNLATCH)
  const closureField = encodeVarintField(1, closureIndex);
  const actionField = encodeVarintField(2, 1); // 1 = UNLATCH
  const closureMove = concatBytes(closureField, actionField);

  // RKEAction (tag 3 = closureMoveRequest)
  const rkePayload = encodeLengthDelimitedField(3, closureMove);

  // UnsignedMessage (tag 1 = rkeAction)
  const unsignedMessage = encodeLengthDelimitedField(1, rkePayload);

  // ToVCSEC (tag 1 = unsignedMessage)
  return encodeLengthDelimitedField(1, unsignedMessage);
}

/**
 * [빌더 3] 비상등 점멸 (땡큐 비상등 / Flash Lights)
 */
export function buildFlashLightsAction() {
  // RKEAction: tag 1 = actionEnum (7 = FLASH_LIGHTS)
  const actionEnumField = encodeVarintField(1, 7);
  const rkeAction = encodeLengthDelimitedField(1, actionEnumField);

  // UnsignedMessage (tag 1 = rkeAction)
  const unsignedMessage = encodeLengthDelimitedField(1, rkeAction);

  // ToVCSEC (tag 1 = unsignedMessage)
  return encodeLengthDelimitedField(1, unsignedMessage);
}

/**
 * [빌더 4] 충전 중지 및 충전 포트 잠금 해제 액션
 */
export function buildStopChargeAction() {
  // RKEAction: tag 1 = actionEnum (12 = CHARGE_PORT_STOP_CHARGING)
  const actionEnumField = encodeVarintField(1, 12);
  const unsignedMessage = encodeLengthDelimitedField(1, encodeLengthDelimitedField(1, actionEnumField));
  return encodeLengthDelimitedField(1, unsignedMessage);
}

export function buildChargePortUnlockAction() {
  // RKEAction: tag 1 = actionEnum (5 = CHARGE_PORT_UNLOCK / OPEN)
  const actionEnumField = encodeVarintField(1, 5);
  const unsignedMessage = encodeLengthDelimitedField(1, encodeLengthDelimitedField(1, actionEnumField));
  return encodeLengthDelimitedField(1, unsignedMessage);
}

/**
 * [빌더 5] 상태 조회 요청 (StatusRequest)
 */
export function buildStatusRequest() {
  // InformationRequest: tag 1 = type (1 = GET_STATUS)
  const infoReq = encodeVarintField(1, 1);
  const unsignedMessage = encodeLengthDelimitedField(3, infoReq); // tag 3 = informationRequest
  return encodeLengthDelimitedField(1, unsignedMessage);
}

/**
 * 3. 수신 패킷 파서 (parseIncomingMessage)
 */
export function parseIncomingMessage(uint8Array) {
  const result = {
    rawLength: uint8Array.length,
    whitelistOperationStatus: null, // 'OK', 'PENDING', 'ERROR'
    speed: 0,
    gear: 'P',
    power: 0,
    charging_state: 'Disconnected', // 'Disconnected', 'Starting', 'Charging', 'Complete', 'Stopped'
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
      df: false, // Driver Front
      pf: false, // Passenger Front
      dr: false, // Driver Rear
      pr: false, // Passenger Rear
      ft: false, // Front Trunk (Frunk)
      rt: false, // Rear Trunk
      charge_port: false
    }
  };

  try {
    const rootFields = parseFields(uint8Array);

    for (const field of rootFields) {
      // FromVCSEC 또는 CarServer 응답 분석
      if (field.wireType === WIRE_LENGTH_DELIMITED && field.data) {
        const subFields = parseFields(field.data);

        for (const sub of subFields) {
          // 1. Whitelist Operation Status (화이트리스트 승인 응답)
          if (sub.fieldNumber === 1 && sub.wireType === WIRE_VARINT) {
            // 0: OPERATION_STATUS_OK, 1: WAIT_FOR_KEY_CONFIRMATION
            if (sub.value === 0) {
              result.whitelistOperationStatus = 'OK';
            } else if (sub.value === 1) {
              result.whitelistOperationStatus = 'WAITING_FOR_CARD';
            } else {
              result.whitelistOperationStatus = 'ERROR';
            }
          }

          // 2. Closure Status (도어 상태 비트마스크)
          if (sub.fieldNumber === 2 && sub.wireType === WIRE_VARINT) {
            const mask = sub.value;
            result.doors.df = (mask & 0x01) !== 0;
            result.doors.pf = (mask & 0x02) !== 0;
            result.doors.dr = (mask & 0x04) !== 0;
            result.doors.pr = (mask & 0x08) !== 0;
            result.doors.ft = (mask & 0x10) !== 0;
            result.doors.rt = (mask & 0x20) !== 0;
            result.doors.charge_port = (mask & 0x40) !== 0;
          }

          // 3. Vehicle State / Telemetry 서브 필드
          if (sub.wireType === WIRE_LENGTH_DELIMITED && sub.data) {
            const leafFields = parseFields(sub.data);
            for (const leaf of leafFields) {
              // Speed (km/h)
              if (leaf.fieldNumber === 10 && leaf.wireType === WIRE_VARINT) {
                result.speed = leaf.value;
              }
              // Gear: 0=P, 1=R, 2=N, 3=D
              if (leaf.fieldNumber === 11 && leaf.wireType === WIRE_VARINT) {
                const gears = ['P', 'R', 'N', 'D'];
                result.gear = gears[leaf.value] || 'P';
              }
              // Power (kW) - signed
              if (leaf.fieldNumber === 12 && leaf.wireType === WIRE_VARINT) {
                // ZigZag 또는 raw int 변환
                result.power = (leaf.value > 0x7FFFFFFF) ? leaf.value - 0x100000000 : leaf.value;
              }
              // Battery Level (%)
              if (leaf.fieldNumber === 20 && leaf.wireType === WIRE_VARINT) {
                result.battery_level = Math.min(100, Math.max(0, leaf.value));
              }
              // Charging State (1=Charging, 2=Starting, 3=Complete, 4=Stopped, 0=Disconnected)
              if (leaf.fieldNumber === 21 && leaf.wireType === WIRE_VARINT) {
                const states = ['Disconnected', 'Charging', 'Starting', 'Complete', 'Stopped'];
                result.charging_state = states[leaf.value] || 'Disconnected';
              }
              // Time to full charge (minutes)
              if (leaf.fieldNumber === 22 && leaf.wireType === WIRE_VARINT) {
                result.time_to_full_charge = leaf.value;
              }
              // Charger Power (kW)
              if (leaf.fieldNumber === 23 && leaf.wireType === WIRE_VARINT) {
                result.charger_power = leaf.value / 10;
              }
            }
          }
        }
      }
    }
  } catch (err) {
    console.warn('[proto-codec] parse error:', err);
  }

  return result;
}
