/**
 * ble-manager.js
 * Web Bluetooth GATT 통신, 2바이트 빅엔디안 길이 헤더 프레이밍,
 * MTU 청크 분할 전송 및 우선순위 큐 관리자
 * 
 * Tesla vehicle-command 공식 BLE 규격 준수:
 * - Service: 00000211-b2d1-43f0-9b88-960cebf8b91e (Short: 0x0211)
 * - TX: 00000212-b2d1-43f0-9b88-960cebf8b91e (To VCSEC / Write)
 * - RX: 00000213-b2d1-43f0-9b88-960cebf8b91e (From VCSEC / Notify)
 */

import { parseIncomingMessage } from './proto-codec.js?v=5';

export const TESLA_SERVICE_UUID = '00000211-b2d1-43f0-9b88-960cebf8b91e';
export const TESLA_TX_CHAR_UUID = '00000212-b2d1-43f0-9b88-960cebf8b91e'; // To VCSEC (Write)
export const TESLA_RX_CHAR_UUID = '00000213-b2d1-43f0-9b88-960cebf8b91e'; // From VCSEC (Notify)

export const CHUNK_SIZE = 240; // 안드로이드 BLE 안전 청크 바이트 크기


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

    // 수신 패킷 버퍼 (2바이트 길이 기반 조립)
    this.rxBuffer = new Uint8Array(0);
    this.expectedPacketLength = null;

    // 콜백
    this.onStateChangeCallback = null;
    this.onMessageCallback = null;
    this.onTxCallback = null;
    this.onRxCallback = null;

    // 시뮬레이션 플래그
    this.isSimulation = false;
  }

  setCallbacks({ onStateChange, onMessage, onTx, onRx }) {
    this.onStateChangeCallback = onStateChange;
    this.onMessageCallback = onMessage;
    this.onTxCallback = onTx;
    this.onRxCallback = onRx;
  }


  updateState(newState) {
    this.connectionState = newState;
    console.log(`[BLEManager] State -> ${newState}`);
    if (this.onStateChangeCallback) {
      this.onStateChangeCallback(newState);
    }
  }

  /**
   * Web Bluetooth 장치 검색 및 GATT 연결 시작 [v5 Bluefy 완벽 호환]
   * acceptAllDevices 완전 배제, 표준 filters 배열 적용
   */
  async connect() {
    if (this.isSimulation) {
      this.updateState('connecting');
      setTimeout(() => this.updateState('connected'), 600);
      return true;
    }

    if (!navigator.bluetooth || typeof navigator.bluetooth.requestDevice !== 'function') {
      throw new Error('이 브라우저는 Web Bluetooth를 지원하지 않습니다. (iOS: Bluefy 브라우저 설치 필요)');
    }

    this.updateState('connecting');

    try {
      try {
        // [v5 핵심] Bluefy가 지원하는 표준 filters 배열로 호출 (acceptAllDevices 배제)
        this.device = await navigator.bluetooth.requestDevice({
          filters: [
            { services: ['00000211-b2d1-43f0-9b88-960cebf8b91e'] },
            { namePrefix: 'S' }
          ],
          optionalServices: ['00000211-b2d1-43f0-9b88-960cebf8b91e']
        });
      } catch (primaryErr) {
        console.warn('[BLEManager v5] Primary filters failed, trying fallback namePrefix filter...', primaryErr);
        // 폴백 시도: acceptAllDevices를 쓰지 않고 namePrefix 필터만 적용
        this.device = await navigator.bluetooth.requestDevice({
          filters: [
            { namePrefix: 'S' }
          ],
          optionalServices: ['00000211-b2d1-43f0-9b88-960cebf8b91e']
        });
      }

      this.device.addEventListener('gattserverdisconnected', () => {
        console.warn('[BLEManager] GATT Server Disconnected!');
        this.cleanup();
        this.updateState('disconnected');
      });

      console.log(`[BLEManager] Connecting to GATT Server (${this.device.name || this.device.id})...`);
      this.server = await this.device.gatt.connect();

      console.log('[BLEManager] Getting Tesla Primary Service...');
      this.service = await this.server.getPrimaryService(TESLA_SERVICE_UUID);

      console.log('[BLEManager] Getting TX and RX Characteristics...');
      this.txChar = await this.service.getCharacteristic(TESLA_TX_CHAR_UUID);
      this.rxChar = await this.service.getCharacteristic(TESLA_RX_CHAR_UUID);

      // Start Notifications for RX
      await this.rxChar.startNotifications();
      this.rxChar.addEventListener('characteristicvaluechanged', (event) => {
        this.handleIncomingChunk(event.target.value);
      });

      this.updateState('connected');
      return true;
    } catch (error) {
      console.error('[BLEManager] Connection error:', error);
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

    // 버퍼에 누적
    const newBuffer = new Uint8Array(this.rxBuffer.length + chunk.length);
    newBuffer.set(this.rxBuffer, 0);
    newBuffer.set(chunk, this.rxBuffer.length);
    this.rxBuffer = newBuffer;

    // 패킷 완성 검사 루프
    while (this.rxBuffer.length >= 2) {
      if (this.expectedPacketLength === null) {
        // 첫 2바이트 빅엔디안 길이 추출
        this.expectedPacketLength = (this.rxBuffer[0] << 8) | this.rxBuffer[1];
      }

      const totalRequired = 2 + this.expectedPacketLength;
      if (this.rxBuffer.length >= totalRequired) {
        // 완전한 패킷 추출
        const fullPayload = this.rxBuffer.slice(2, totalRequired);
        // 버퍼 슬라이스 갱신
        this.rxBuffer = this.rxBuffer.slice(totalRequired);
        this.expectedPacketLength = null;

        // Protobuf 파싱 및 콜백 실행
        const parsed = parseIncomingMessage(fullPayload);
        if (this.onRxCallback) {
          this.onRxCallback(fullPayload, parsed);
        }
        if (this.onMessageCallback) {
          this.onMessageCallback(parsed, fullPayload);
        }
      } else {
        // 추가 청크 대기
        break;
      }
    }
  }

  /**
   * 시뮬레이션용 수신 인젝터
   */
  injectSimulatedMessage(data) {
    if (this.onRxCallback) {
      this.onRxCallback(new Uint8Array([0x08, 0x01]), data);
    }
    if (this.onMessageCallback) {
      this.onMessageCallback(data, new Uint8Array(0));
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
        // 긴급 제어 명령: 큐 최우선 배치 (Unshift)
        this.commandQueue.unshift(item);
      } else {
        // 일반 상태 조회: 큐 뒤에 추가 (Push)
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
      // 청크 간 안정적 전송 간격 보장
      await new Promise(r => setTimeout(r, 20));
    }

    this.isProcessingQueue = false;
  }

  /**
   * 2바이트 빅엔디안 헤더 부착 및 240바이트 청크 분할 송신
   */
  async transmitFramedPacket(payloadBytes) {
    const len = payloadBytes.length;
    // 2바이트 빅엔디안 프리픽스 프레이밍
    const framed = new Uint8Array(2 + len);
    framed[0] = (len >> 8) & 0xff;
    framed[1] = len & 0xff;
    framed.set(payloadBytes, 2);

    let offset = 0;
    while (offset < framed.length) {
      const chunk = framed.slice(offset, offset + CHUNK_SIZE);
      // iOS Bluefy / 구형 WebKit 호환을 위한 writeValue 폴백
      if (typeof this.txChar.writeValueWithResponse === 'function') {
        await this.txChar.writeValueWithResponse(chunk);
      } else if (typeof this.txChar.writeValueWithoutResponse === 'function') {
        await this.txChar.writeValueWithoutResponse(chunk);
      } else if (typeof this.txChar.writeValue === 'function') {
        await this.txChar.writeValue(chunk);
      } else {
        throw new Error('GATT 특성에 write 메서드가 존재하지 않습니다.');
      }
      offset += CHUNK_SIZE;
      if (offset < framed.length) {
        await new Promise(r => setTimeout(r, 15)); // 청크간 짧은 딜레이
      }
    }

  }

  /**
   * 연결 해제 및 리소스 정리
   */
  disconnect() {
    if (this.device && this.device.gatt.connected) {
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
