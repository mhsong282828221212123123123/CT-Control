/**
 * ble-manager.js
 * Web Bluetooth GATT 통신, 2바이트 빅엔디안 길이 헤더 프레이밍,
 * MTU 안전 청크(20B) 분할 전송 및 우선순위 큐 관리자 [v11]
 *
 * Tesla vehicle-command 및 yoziru/tesla-ble 공식 BLE 규격 준수:
 * - Advertisement Service UUID (스캔 필터용): 0x1122 (00001122-0000-1000-8000-00805f9b34fb)
 * - BLE Beacon Name 규격:
 *   1) 구형: 'S' + SHA1(VIN)[0..7] 16자리 hex + 'C'/'R'/'D'/'P' (예: S1a87a5a75f3df858C)
 *   2) 신형(2023+): 'Tesla ' + VIN 뒤 6자리 (예: Tesla 130307)
 * - GATT Primary Service (연결 후 내부 서비스): 00000211-b2d1-43f0-9b88-960cebf8b91e
 * - TX Characteristic (To Vehicle / Write): 00000212-b2d1-43f0-9b88-960cebf8b91e
 * - RX Characteristic (From Vehicle / Notify): 00000213-b2d1-43f0-9b88-960cebf8b91e
 */

import { parseIncomingMessage } from './proto-codec.js?v=11';

export const TESLA_ADV_SERVICE_UUID = 0x1122; // 공중 광고 패킷(ADV_IND)에 포함되는 16비트 UUID
export const TESLA_SERVICE_UUID = '00000211-b2d1-43f0-9b88-960cebf8b91e'; // GATT 연결 후 오픈되는 서비스 UUID
export const TESLA_TX_CHAR_UUID = '00000212-b2d1-43f0-9b88-960cebf8b91e'; // To VCSEC / CarServer (Write)
export const TESLA_RX_CHAR_UUID = '00000213-b2d1-43f0-9b88-960cebf8b91e'; // From VCSEC / CarServer (Notify)

// Web Bluetooth는 JS에서 ExchangeMTU 호출을 지원하지 않으므로,
// teslamotors/vehicle-command 폴백 규격(DefaultMTU 23 - 3 = 20B)에 맞춰 20바이트 단위로 안전 분할 전송
export const CHUNK_SIZE = 20;

class BLEManager {
  constructor() {
    this.device = null;
    this.server = null;
    this.service = null;
    this.txChar = null;
    this.rxChar = null;

    this.connectionState = 'disconnected'; // 'disconnected' | 'connecting' | 'connected'
    this.commandQueue = []; // Priority queue items: { payload, isPriority, resolve, reject }
    this.isProcessingQueue = false;

    // 수신 패킷 버퍼 (2바이트 Big-Endian 길이 기반 조립)
    this.rxBuffer = new Uint8Array(0);
    this.expectedPacketLength = null;

    // 콜백
    this.onStateChangeCallback = null;
    this.onMessageCallback = null;
    this.onTxCallback = null;
    this.onRxCallback = null;
    this.onLogCallback = null;

    // 시뮬레이션 플래그
    this.isSimulation = false;
  }

  setCallbacks({ onStateChange, onMessage, onTx, onRx, onLog }) {
    this.onStateChangeCallback = onStateChange;
    this.onMessageCallback = onMessage;
    this.onTxCallback = onTx;
    this.onRxCallback = onRx;
    this.onLogCallback = onLog;
  }

  log(message, level = 'info') {
    const formatted = `[BLEManager] ${message}`;
    if (level === 'warn') {
      console.warn(formatted);
    } else if (level === 'error') {
      console.error(formatted);
    } else {
      console.log(formatted);
    }
    if (this.onLogCallback) {
      this.onLogCallback(message, level);
    }
  }

  updateState(newState) {
    this.connectionState = newState;
    this.log(`State -> ${newState}`);
    if (this.onStateChangeCallback) {
      this.onStateChangeCallback(newState);
    }
  }

  /**
   * 테슬라 BLE 비콘 기기명 판별 헬퍼
   * - 구형: S + 16 hex + C/R/D/P (18자)
   * - 신형(2023+): "Tesla " + VIN 끝 6자리 (12자)
   */
  isTeslaBLEBeaconName(name) {
    if (!name || typeof name !== 'string') return false;
    const oldScheme = /^S[0-9a-fA-F]{16}[CRDP]?$/;
    const newScheme = /^Tesla [A-HJ-NPR-Z0-9]{6}$/i;
    return oldScheme.test(name) || newScheme.test(name);
  }

  /**
   * 클래식 오디오 블루투스 판별 헬퍼
   */
  isClassicAudioDeviceName(name) {
    if (!name || typeof name !== 'string') return false;
    if (this.isTeslaBLEBeaconName(name)) return false;
    return (
      name.includes('Tesla Model') ||
      name.includes('동행터렛') ||
      name.toLowerCase().includes('audio')
    );
  }

  /**
   * Web Bluetooth 장치 검색 및 GATT 연결 [v11: 실제 광고 UUID 0x1122 및 신/구형 비콘 필터 적용]
   * @param {Object} options - { mode: 'standard' | 'all' }
   */
  async connect(options = {}) {
    const mode = options.mode || 'standard';

    if (this.isSimulation) {
      this.updateState('connecting');
      setTimeout(() => this.updateState('connected'), 600);
      return true;
    }

    if (!navigator.bluetooth || typeof navigator.bluetooth.requestDevice !== 'function') {
      throw new Error('이 브라우저는 Web Bluetooth를 지원하지 않습니다. (Android Chrome 또는 iOS Bluefy 브라우저를 사용해 주세요)');
    }

    this.updateState('connecting');

    try {
      if (mode === 'all') {
        this.log('전체 BLE 기기 검색을 시작합니다 (필터 해제 모드)...');
        this.device = await navigator.bluetooth.requestDevice({
          acceptAllDevices: true,
          optionalServices: [
            TESLA_SERVICE_UUID,
            TESLA_ADV_SERVICE_UUID
          ]
        });
      } else {
        this.log('테슬라 BLE 비콘 검색 시작 (광고 UUID 0x1122 / S...C / Tesla + VIN6 필터)...');
        // [v11 핵심 수정]
        // 00000211-...은 광고 패킷에 없으므로 절대 filters에 넣지 않고 optionalServices에만 배치!
        // filters에는 실제 광고 패킷에 실리는 0x1122 UUID와 구형('S') 및 신형('Tesla') 프리픽스를 OR 조건으로 설정
        this.device = await navigator.bluetooth.requestDevice({
          filters: [
            { services: [TESLA_ADV_SERVICE_UUID] },
            { namePrefix: 'S' },
            { namePrefix: 'Tesla' }
          ],
          optionalServices: [
            TESLA_SERVICE_UUID,
            TESLA_ADV_SERVICE_UUID
          ]
        });
      }

      const devName = this.device.name || '(이름 없는 기기)';
      this.log(`기기 선택 완료: ${devName} (${this.device.id})`);

      // 사용자가 클래식 오디오 블루투스를 선택했을 경우 안내 및 차단
      if (this.isClassicAudioDeviceName(devName)) {
        this.log(`⚠️ 클래식 오디오 블루투스 선택 감지: ${devName}`, 'warn');
        throw new Error(
          `선택하신 '${devName}' 기기는 음악/통화용 클래식 오디오 블루투스입니다.\n\n` +
          `[가상키 BLE 노드가 목록에 안 보이는 이유]\n` +
          `테슬라 차량은 최대 3개의 BLE 연결만 허용합니다. 현재 스마트폰의 공식 Tesla 앱이나 워치/보조기기가 이미 연결되어 있으면 차량이 BLE 비콘을 숨깁니다.\n` +
          `👉 스마트폰의 공식 Tesla 앱을 '강제 종료'하거나 폰 블루투스 설정에서 기존 차량 오디오 연결을 잠시 해제한 뒤 다시 검색해 주세요.`
        );
      }

      if (this.isTeslaBLEBeaconName(devName)) {
        this.log(`[식별 성공] 테슬라 BLE 가상키 노드 확인: ${devName}`);
      } else {
        this.log(`선택된 기기명: ${devName}`);
      }

      // 기기 선택 직후 안드로이드 블루투스 스택 안정화를 위한 350ms 대기
      await new Promise((r) => setTimeout(r, 350));

      // 이전 잔여 GATT 세션이 있다면 사전 disconnect
      try {
        if (this.device.gatt && this.device.gatt.connected) {
          this.device.gatt.disconnect();
          await new Promise((r) => setTimeout(r, 200));
        }
      } catch (_) {}

      // GATT 연결 끊김 핸들러 등록
      this.device.addEventListener('gattserverdisconnected', () => {
        if (this.connectionState !== 'connected') {
          return;
        }
        this.log('GATT 서버 연결이 해제되었습니다.', 'warn');
        this.cleanup();
        this.updateState('disconnected');
      });

      // 안드로이드 Web Bluetooth GATT Error 133 방어: 최대 4회 재시도 루프
      const MAX_RETRIES = 4;
      let connectedServer = null;

      for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
        try {
          this.log(`Connecting to GATT Server (${this.device.name || this.device.id})... (시도 ${attempt}/${MAX_RETRIES})`);

          const connectPromise = this.device.gatt.connect();
          const timeoutPromise = new Promise((_, reject) =>
            setTimeout(() => reject(new Error('GATT 연결 시도 타임아웃 (8초)')), 8000)
          );

          connectedServer = await Promise.race([connectPromise, timeoutPromise]);
          this.log(`GATT 서버 연결 성공! [${this.device.name || this.device.id}]`);
          break;
        } catch (gattErr) {
          this.log(`GATT 연결 실패 (${attempt}/${MAX_RETRIES}): ${gattErr?.message || gattErr}`, 'warn');

          try {
            if (this.device.gatt) {
              this.device.gatt.disconnect();
            }
          } catch (dcErr) {
            console.warn('[BLEManager] gatt.disconnect() cleanup error:', dcErr);
          }

          if (attempt < MAX_RETRIES) {
            this.log(`GATT 연결 재시도 (${attempt}/${MAX_RETRIES})...`);
            const backoffMs = 600 + (attempt * 250);
            await new Promise((r) => setTimeout(r, backoffMs));
          } else {
            this.log(`GATT 연결 최대 재시도(${MAX_RETRIES}회) 초과 실패: ${gattErr?.message || gattErr}`, 'error');
            throw gattErr;
          }
        }
      }

      this.server = connectedServer;
      await new Promise((r) => setTimeout(r, 250));

      this.log('Getting Tesla Primary Service (0x0211)...');
      this.service = await this.server.getPrimaryService(TESLA_SERVICE_UUID);

      this.log('Getting TX (0x0212) and RX (0x0213) Characteristics...');
      this.txChar = await this.service.getCharacteristic(TESLA_TX_CHAR_UUID);
      this.rxChar = await this.service.getCharacteristic(TESLA_RX_CHAR_UUID);

      // RX 알림(Notification / Indication) 활성화
      await this.rxChar.startNotifications();
      this.rxChar.addEventListener('characteristicvaluechanged', (event) => {
        this.handleIncomingChunk(event.target.value);
      });

      this.updateState('connected');
      this.log(`차량 BLE GATT 채널 연결 완료: ${this.device.name || this.device.id}`);
      return true;
    } catch (error) {
      this.log(`Connection error: ${error?.message || error}`, 'error');
      this.cleanup();
      this.updateState('disconnected');
      throw error;
    }
  }

  /**
   * 수신된 BLE 청크 조립 (2바이트 Big-Endian 길이 헤더)
   */
  handleIncomingChunk(dataView) {
    const chunk = new Uint8Array(dataView.buffer, dataView.byteOffset, dataView.byteLength);

    // 1바이트 이상의 유효 청크 누적
    const newBuffer = new Uint8Array(this.rxBuffer.length + chunk.length);
    newBuffer.set(this.rxBuffer, 0);
    newBuffer.set(chunk, this.rxBuffer.length);
    this.rxBuffer = newBuffer;

    while (this.rxBuffer.length >= 2) {
      if (this.expectedPacketLength === null) {
        this.expectedPacketLength = (this.rxBuffer[0] << 8) | this.rxBuffer[1];
        // 비정상적인 길이 헤더 방어 (최대 4096바이트 초과 시 버퍼 리셋)
        if (this.expectedPacketLength === 0 || this.expectedPacketLength > 4096) {
          this.rxBuffer = this.rxBuffer.slice(2);
          this.expectedPacketLength = null;
          continue;
        }
      }

      const totalRequired = 2 + this.expectedPacketLength;
      if (this.rxBuffer.length >= totalRequired) {
        const fullPayload = this.rxBuffer.slice(2, totalRequired);
        this.rxBuffer = this.rxBuffer.slice(totalRequired);
        this.expectedPacketLength = null;

        const parsed = parseIncomingMessage(fullPayload);
        if (this.onRxCallback) {
          this.onRxCallback(fullPayload, parsed);
        }
        if (this.onMessageCallback) {
          this.onMessageCallback(parsed, fullPayload);
        }
      } else {
        break;
      }
    }
  }

  /**
   * 시뮬레이션용 수신 인젝터
   */
  injectSimulatedMessage(data) {
    const wrapped = { telemetry: data };
    if (this.onRxCallback) {
      this.onRxCallback(new Uint8Array([0x08, 0x01]), wrapped);
    }
    if (this.onMessageCallback) {
      this.onMessageCallback(wrapped, new Uint8Array(0));
    }
  }

  /**
   * 패킷 전송 요청 (2바이트 길이 헤더 프레이밍 + 우선순위 큐)
   */
  async sendPacket(protobufBytes, isPriority = false) {
    if (this.onTxCallback) {
      this.onTxCallback(protobufBytes, isPriority);
    }

    if (this.isSimulation) {
      console.log(`[BLE SIM] Sent ${isPriority ? '[PRIORITY]' : '[NORMAL]'} payload length: ${protobufBytes.length}`);
      return true;
    }

    if (this.connectionState !== 'connected' || !this.txChar) {
      throw new Error('BLE 차량에 연결되어 있지 않습니다.');
    }

    return new Promise((resolve, reject) => {
      const item = {
        payload: protobufBytes,
        isPriority,
        resolve,
        reject
      };

      if (isPriority) {
        this.commandQueue.unshift(item);
      } else {
        this.commandQueue.push(item);
      }

      this.processQueue();
    });
  }

  /**
   * 비동기 뮤텍스 큐 프로세서
   */
  async processQueue() {
    if (this.isProcessingQueue) return;
    this.isProcessingQueue = true;

    while (this.commandQueue.length > 0) {
      const task = this.commandQueue.shift();

      try {
        await this.transmitFramedPacket(task.payload);
        task.resolve(true);
      } catch (err) {
        console.error('[BLEManager] Transmission failed:', err);
        task.reject(err);
      }
      await new Promise((r) => setTimeout(r, 25));
    }

    this.isProcessingQueue = false;
  }

  /**
   * 2바이트 빅엔디안 헤더 부착 및 안전 MTU(20바이트) 청크 분할 송신
   */
  async transmitFramedPacket(payloadBytes) {
    const len = payloadBytes.length;
    const framed = new Uint8Array(2 + len);
    framed[0] = (len >> 8) & 0xff;
    framed[1] = len & 0xff;
    framed.set(payloadBytes, 2);

    let offset = 0;
    while (offset < framed.length) {
      const chunk = framed.slice(offset, offset + CHUNK_SIZE);
      if (typeof this.txChar.writeValueWithResponse === 'function') {
        await this.txChar.writeValueWithResponse(chunk);
      } else if (typeof this.txChar.writeValue === 'function') {
        await this.txChar.writeValue(chunk);
      } else if (typeof this.txChar.writeValueWithoutResponse === 'function') {
        await this.txChar.writeValueWithoutResponse(chunk);
      } else {
        throw new Error('GATT 특성에 write 메서드가 존재하지 않습니다.');
      }
      offset += CHUNK_SIZE;
      if (offset < framed.length) {
        await new Promise((r) => setTimeout(r, 12));
      }
    }
  }

  /**
   * 연결 해제 및 리소스 정리
   */
  disconnect() {
    if (this.device && this.device.gatt && this.device.gatt.connected) {
      this.device.gatt.disconnect();
    }
    this.cleanup();
    this.updateState('disconnected');
  }

  cleanup() {
    this.device = null;
    this.server = null;
    this.service = null;
    this.txChar = null;
    this.rxChar = null;
    this.commandQueue = [];
    this.rxBuffer = new Uint8Array(0);
    this.expectedPacketLength = null;
    this.isProcessingQueue = false;
  }
}

export const bleManager = new BLEManager();
