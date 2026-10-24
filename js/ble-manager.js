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

import { parseIncomingMessage } from './proto-codec.js?v=7';

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
   * Web Bluetooth 장치 검색 및 GATT 연결 [v7: 필터링 완전 배제 및 안드로이드 GATT 133 극복]
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
      this.log('BLE 장치 검색을 시작합니다 (필터링 없이 모든 기기 즉시 검색)...');

      // [v7 핵심] 필터링 완전 배제 (acceptAllDevices: true):
      // 차량 광고 패킷 지연 없이 주변의 모든 BLE 기기(테슬라 포함)를 0초 만에 목록에 표시
      this.device = await navigator.bluetooth.requestDevice({
        acceptAllDevices: true,
        optionalServices: [
          TESLA_SERVICE_UUID,
          '00000211-b2d1-43f0-9b88-960cebf8b91e'
        ]
      });

      const devName = this.device.name || '(이름 없는 기기)';
      this.log(`기기 선택 완료: ${devName} (${this.device.id})`);
      if (devName.endsWith('C')) {
        this.log(`[식별 성공] 메인 컨트롤러(C) 노드가 선택되었습니다: ${devName}`);
      } else {
        this.log(`[식별 안내] 선택된 기기명이 'C'로 끝나지 않습니다 (${devName}). 차량에 여러 노드가 보일 경우 끝에 'C'가 붙은 기기가 메인 컨트롤러입니다.`);
      }

      // 기기 선택 직후 안드로이드 블루투스 스택 안정화를 위한 350ms 대기
      await new Promise((r) => setTimeout(r, 350));

      // 혹시 이전 잔여 GATT 세션이 있다면 사전 disconnect
      try {
        if (this.device.gatt && this.device.gatt.connected) {
          this.device.gatt.disconnect();
          await new Promise((r) => setTimeout(r, 200));
        }
      } catch (_) {}

      // GATT 연결 끊김 핸들러 등록 (연결 완료 상태일 때만 cleanup 동작)
      this.device.addEventListener('gattserverdisconnected', () => {
        if (this.connectionState !== 'connected') {
          return; // 재시도 루프 중의 disconnect() 호출은 무시
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

          // 안드로이드 행 방지를 위한 8초 타임아웃
          const connectPromise = this.device.gatt.connect();
          const timeoutPromise = new Promise((_, reject) =>
            setTimeout(() => reject(new Error('GATT 연결 시도 타임아웃 (8초)')), 8000)
          );

          connectedServer = await Promise.race([connectPromise, timeoutPromise]);
          this.log(`GATT 서버 연결 성공! [${this.device.name || this.device.id}]`);
          break;
        } catch (gattErr) {
          this.log(`GATT 연결 실패 (${attempt}/${MAX_RETRIES}): ${gattErr?.message || gattErr}`, 'warn');

          // 세션 정리 (disconnect 호출)
          try {
            if (this.device.gatt) {
              this.device.gatt.disconnect();
            }
          } catch (dcErr) {
            console.warn('[BLEManager] gatt.disconnect() cleanup error:', dcErr);
          }

          if (attempt < MAX_RETRIES) {
            this.log(`GATT 연결 재시도 (${attempt}/4)...`);
            // 안드로이드 네이티브 스택 쿨다운 (점진적 백오프)
            const backoffMs = 600 + (attempt * 200);
            await new Promise((r) => setTimeout(r, backoffMs));
          } else {
            this.log(`GATT 연결 최대 재시도(${MAX_RETRIES}회) 초과 실패: ${gattErr?.message || gattErr}`, 'error');
            throw gattErr;
          }
        }
      }

      this.server = connectedServer;
      // 서비스 디스커버리 안정화를 위한 200ms 대기
      await new Promise((r) => setTimeout(r, 200));

      this.log('Getting Tesla Primary Service...');
      this.service = await this.server.getPrimaryService(TESLA_SERVICE_UUID);

      this.log('Getting TX and RX Characteristics...');
      this.txChar = await this.service.getCharacteristic(TESLA_TX_CHAR_UUID);
      this.rxChar = await this.service.getCharacteristic(TESLA_RX_CHAR_UUID);

      // Start Notifications for RX
      await this.rxChar.startNotifications();
      this.rxChar.addEventListener('characteristicvaluechanged', (event) => {
        this.handleIncomingChunk(event.target.value);
      });

      this.updateState('connected');
      this.log(`차량 BLE 보안 세션 연결 완료: ${this.device.name}`);
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
