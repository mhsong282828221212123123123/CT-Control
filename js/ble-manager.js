/**
 * ble-manager.js
 * 하이브리드 BLE 매니저 [v12]:
 * 1) Android 전용 네이티브 APK 브릿지 (window.AndroidBLE)
 *    - Android 12+ neverForLocation(iBeacon 차단) 완벽 우회
 *    - 테슬라 고정 Apple iBeacon UUID (74278bda-b644-4520-8f0c-720eaf059935),
 *      광고 UUID (0x1122), 기기명 (S...C / Tesla ...) 3중 통합 감지
 *    - 네이티브 GATT requestMtu(517) 협상 및 CCCD Indication(0x0002)/Notification 자동 활성화
 * 2) 데스크톱 Chrome / iOS Bluefy 용 Web Bluetooth API 폴백
 */

import { parseIncomingMessage, bytesToHex } from './proto-codec.js?v=12';

export const TESLA_ADV_SERVICE_UUID = 0x1122; // 공중 광고 패킷(SCAN_RSP)에 포함되는 16비트 UUID
export const TESLA_SERVICE_UUID = '00000211-b2d1-43f0-9b88-960cebf8b91e'; // GATT 연결 후 오픈되는 서비스 UUID
export const TESLA_TX_CHAR_UUID = '00000212-b2d1-43f0-9b88-960cebf8b91e'; // To VCSEC / CarServer (Write)
export const TESLA_RX_CHAR_UUID = '00000213-b2d1-43f0-9b88-960cebf8b91e'; // From VCSEC / CarServer (Indicate/Notify)

export const DEFAULT_CHUNK_SIZE = 20;

function hexToUint8Array(hex) {
  if (!hex || typeof hex !== 'string') return new Uint8Array(0);
  const clean = hex.replace(/[^0-9a-fA-F]/g, '');
  const out = new Uint8Array(Math.floor(clean.length / 2));
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.substring(i * 2, i * 2 + 2), 16);
  }
  return out;
}

class BLEManager {
  constructor() {
    this.device = null;
    this.server = null;
    this.service = null;
    this.txChar = null;
    this.rxChar = null;

    this.connectionState = 'disconnected'; // 'disconnected' | 'connecting' | 'connected'
    this.commandQueue = [];
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

    // 네이티브 안드로이드 APK 브릿지 상태
    this.negotiatedMtu = 23;
    this.nativeScanItems = new Map(); // address -> scanResult
    this.nativeScanFilterMode = 'standard'; // 'standard' | 'all'
    this.nativeConnectPending = null; // { resolve, reject, timeoutId }
    this.nativeWritePending = null; // { resolve, reject, timeoutId }

    this.setupNativeBridgeCallbacks();
  }

  /**
   * 현재 실행 환경이 Android 전용 APK(window.AndroidBLE)인지 확인
   */
  isNativeApp() {
    return (
      typeof window !== 'undefined' &&
      Boolean(window.AndroidBLE) &&
      typeof window.AndroidBLE.isNativeApp === 'function'
    );
  }

  /**
   * Android APK의 Java 브릿지(MainActivity.java)에서 호출하는 전역 콜백 등록
   */
  setupNativeBridgeCallbacks() {
    if (typeof window === 'undefined') return;

    window.__onNativeBleLog = (msg, level) => {
      this.log(`[NativeBLE] ${msg}`, level || 'info');
    };

    window.__onNativeBleMtu = (mtu) => {
      if (typeof mtu === 'number' && mtu >= 23) {
        this.negotiatedMtu = mtu;
        this.log(`[NativeBLE] 협상된 MTU 적용: ${mtu}B (최대 청크 ${Math.min(240, mtu - 3)}B)`);
      }
    };

    window.__onNativeBleScanState = (isScanning) => {
      const statusEl = document.getElementById('native-scan-status-text');
      if (statusEl) {
        statusEl.textContent = isScanning
          ? '📡 주변 BLE 및 Apple iBeacon(0x004C) 신호 실시간 스캔 중...'
          : '⏸️ 스캔 일시 중지됨';
      }
    };

    window.__onNativeBleScanResult = (item) => {
      if (!item || !item.address) return;
      const prev = this.nativeScanItems.get(item.address);
      const merged = {
        address: item.address,
        name: item.name || (prev ? prev.name : ''),
        rssi: item.rssi,
        isTesla: Boolean(item.isTesla || (prev && prev.isTesla)),
        isTeslaIBeacon: Boolean(item.isTeslaIBeacon || (prev && prev.isTeslaIBeacon)),
        hasTeslaService: Boolean(item.hasTeslaService || (prev && prev.hasTeslaService)),
        hasTeslaName: Boolean(item.hasTeslaName || (prev && prev.hasTeslaName)),
        isClassicAudio: Boolean(item.isClassicAudio || (prev && prev.isClassicAudio)),
        meta: item.meta || (prev ? prev.meta : ''),
        updatedAt: Date.now()
      };
      this.nativeScanItems.set(item.address, merged);
      this.renderNativeScanList();
    };

    window.__onNativeBleState = (state, status) => {
      if (state === 'connected') {
        this.closeNativeScanModal();
        this.updateState('connected');
        if (this.nativeConnectPending) {
          clearTimeout(this.nativeConnectPending.timeoutId);
          const { resolve } = this.nativeConnectPending;
          this.nativeConnectPending = null;
          resolve(true);
        }
      } else if (state === 'disconnected') {
        if (this.nativeConnectPending) {
          clearTimeout(this.nativeConnectPending.timeoutId);
          const { reject } = this.nativeConnectPending;
          this.nativeConnectPending = null;
          this.updateState('disconnected');
          reject(new Error(`네이티브 GATT 연결 실패 또는 해제됨 (status=${status})`));
          return;
        }
        this.cleanup();
        this.updateState('disconnected');
      }
    };

    window.__onNativeBleWriteDone = (status) => {
      if (this.nativeWritePending) {
        clearTimeout(this.nativeWritePending.timeoutId);
        const { resolve, reject } = this.nativeWritePending;
        this.nativeWritePending = null;
        if (status === 0) {
          resolve(true);
        } else {
          reject(new Error(`GATT Write 실패 (status=${status})`));
        }
      }
    };

    window.__onNativeBleRxHex = (hex) => {
      const bytes = hexToUint8Array(hex);
      if (bytes.length > 0) {
        const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
        this.handleIncomingChunk(dv);
      }
    };
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

  isTeslaBLEBeaconName(name) {
    if (!name || typeof name !== 'string') return false;
    const oldScheme = /^S[0-9a-fA-F]{16}[CRDP]?$/;
    const newScheme = /^Tesla [A-HJ-NPR-Z0-9]{6}$/i;
    return oldScheme.test(name) || newScheme.test(name);
  }

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
   * 네이티브 안드로이드 스캔 모달 열기 및 스캔 시작
   */
  async connectViaNativeAndroid(mode = 'standard') {
    this.nativeScanFilterMode = mode;
    this.nativeScanItems.clear();
    this.negotiatedMtu = 23;
    this.updateState('connecting');

    this.openNativeScanModal(mode);

    try {
      const envJson = window.AndroidBLE.getEnvStatusJson();
      const env = JSON.parse(envJson || '{}');
      const gpsWarnEl = document.getElementById('native-gps-warning');
      if (gpsWarnEl) {
        gpsWarnEl.style.display = env.locationEnabled === false ? 'block' : 'none';
      }
    } catch (_) {}

    window.AndroidBLE.startScan(mode);

    return new Promise((resolve, reject) => {
      if (this.nativeConnectPending) {
        clearTimeout(this.nativeConnectPending.timeoutId);
      }
      this.nativeConnectPending = {
        resolve,
        reject,
        timeoutId: null
      };
    });
  }

  openNativeScanModal(mode) {
    const modal = document.getElementById('native-ble-modal');
    if (!modal) return;
    modal.classList.add('active');

    const filterBtn = document.getElementById('btn-native-toggle-filter');
    if (filterBtn) {
      filterBtn.textContent = mode === 'all'
        ? '🔍 현재: 모든 기기 표시 중 (클릭 시 테슬라만 필터)'
        : '🚗 현재: 테슬라 신호 우선 표시 (클릭 시 전체 기기 보기)';
    }

    this.renderNativeScanList();
  }

  closeNativeScanModal() {
    const modal = document.getElementById('native-ble-modal');
    if (modal) {
      modal.classList.remove('active');
    }
    if (this.isNativeApp()) {
      try {
        window.AndroidBLE.stopScan();
      } catch (_) {}
    }
  }

  cancelNativeScanModal() {
    this.closeNativeScanModal();
    if (this.nativeConnectPending) {
      clearTimeout(this.nativeConnectPending.timeoutId);
      const { reject } = this.nativeConnectPending;
      this.nativeConnectPending = null;
      this.updateState('disconnected');
      reject(new Error('사용자가 BLE 기기 선택을 취소했습니다.'));
    }
  }

  renderNativeScanList() {
    const listEl = document.getElementById('native-ble-device-list');
    const countEl = document.getElementById('native-scan-count');
    if (!listEl) return;

    const allItems = Array.from(this.nativeScanItems.values());
    const teslaCount = allItems.filter((d) => d.isTesla).length;
    if (countEl) {
      countEl.textContent = `감지된 BLE 기기: 총 ${allItems.length}개 (테슬라 신호: ${teslaCount}개)`;
    }

    // 필터 모드에 따라 표시할 목록 결정 (단, standard 모드에서도 테슬라 기기가 아직 없으면 안내 표시)
    let displayItems = allItems;
    if (this.nativeScanFilterMode === 'standard') {
      displayItems = allItems.filter((d) => d.isTesla);
    }

    // 정렬: 테슬라 기기 최상단 -> RSSI 신호 강도 내림차순
    displayItems.sort((a, b) => {
      if (a.isTesla !== b.isTesla) return a.isTesla ? -1 : 1;
      return (b.rssi || -100) - (a.rssi || -100);
    });

    if (displayItems.length === 0) {
      listEl.innerHTML = `
        <div style="text-align: center; padding: 24px 12px; color: var(--text-secondary); font-size: 13px; line-height: 1.6;">
          <div style="font-size: 28px; margin-bottom: 8px;">📡</div>
          ${this.nativeScanFilterMode === 'standard'
            ? `테슬라 BLE 비콘(iBeacon <code>74278bda...</code> / <code>0x1122</code> / <code>S...C</code>)을 탐색 중입니다...<br>
               <span style="font-size: 11px; color: #ffcc00;">현재 주변 일반 BLE 기기 ${allItems.length}개가 수신되고 있습니다. 아래 [전체 기기 보기]를 누르면 모든 패킷을 볼 수 있습니다.</span>`
            : `주변 BLE 패킷을 수신 중입니다... (휴대폰 위치/GPS가 켜져 있는지 확인해 주세요)`}
        </div>
      `;
      return;
    }

    listEl.innerHTML = '';
    for (const item of displayItems) {
      const row = document.createElement('button');
      row.type = 'button';
      row.style.cssText = `
        display: flex;
        flex-direction: column;
        gap: 4px;
        width: 100%;
        text-align: left;
        padding: 12px;
        border-radius: 10px;
        cursor: pointer;
        background: ${item.isTesla ? 'rgba(0, 230, 118, 0.14)' : 'rgba(255, 255, 255, 0.05)'};
        border: 1px solid ${item.isTesla ? '#00e676' : 'rgba(255, 255, 255, 0.12)'};
        color: #fff;
      `;

      const badges = [];
      if (item.isTeslaIBeacon) badges.push('🍎 Tesla iBeacon(0x004C)');
      if (item.hasTeslaService) badges.push('UUID 0x1122');
      if (item.hasTeslaName) badges.push('S...C 비콘명');
      if (item.isClassicAudio) badges.push('⚠️ 오디오 블루투스');

      const displayName = item.name
        ? item.name
        : (item.isTesla ? '🚗 Tesla VCSEC (이름 없는 iBeacon 비콘)' : '(이름 없는 BLE 기기)');

      row.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; width: 100%;">
          <strong style="font-size: 14px; color: ${item.isTesla ? '#00ff88' : '#fff'};">${displayName}</strong>
          <span style="font-size: 12px; font-weight: 700; color: ${item.rssi > -70 ? '#00e676' : '#ffcc00'};">${item.rssi} dBm</span>
        </div>
        <div style="font-size: 11px; color: #b0b0b8; display: flex; justify-content: space-between; gap: 6px; flex-wrap: wrap;">
          <span>MAC: <code>${item.address}</code></span>
          <span>${badges.join(' · ') || item.meta || '일반 BLE'}</span>
        </div>
      `;

      row.addEventListener('click', () => {
        this.selectNativeDevice(item);
      });

      listEl.appendChild(row);
    }
  }

  selectNativeDevice(item) {
    if (item.isClassicAudio) {
      alert(
        `선택하신 '${item.name}' 기기는 음악/통화용 클래식 오디오 블루투스입니다.\n` +
        `테슬라 가상키(VCSEC) 비콘을 선택해 주세요.`
      );
      return;
    }

    this.device = {
      id: item.address,
      name: item.name || (item.isTesla ? `Tesla-VCSEC (${item.address})` : item.address)
    };

    const statusEl = document.getElementById('native-scan-status-text');
    if (statusEl) {
      statusEl.textContent = `🔗 연결 중: ${this.device.name} (MTU 517 협상 및 0x0211 탐색 중)...`;
    }

    if (this.nativeConnectPending) {
      clearTimeout(this.nativeConnectPending.timeoutId);
      this.nativeConnectPending.timeoutId = setTimeout(() => {
        if (this.nativeConnectPending) {
          const { reject } = this.nativeConnectPending;
          this.nativeConnectPending = null;
          this.updateState('disconnected');
          reject(new Error('네이티브 GATT 연결 타임아웃 (15초)'));
        }
      }, 15000);
    }

    window.AndroidBLE.connectDevice(item.address);
  }

  /**
   * 장치 검색 및 GATT 연결 (네이티브 APK 우선 -> Web Bluetooth 폴백)
   */
  async connect(options = {}) {
    const mode = options.mode || 'standard';

    if (this.isSimulation) {
      this.updateState('connecting');
      setTimeout(() => this.updateState('connected'), 600);
      return true;
    }

    // 1. Android 전용 APK (window.AndroidBLE) 환경이면 네이티브 스캐너로 즉시 실행
    if (this.isNativeApp()) {
      return this.connectViaNativeAndroid(mode);
    }

    // 2. 일반 웹 브라우저 (Web Bluetooth API) 폴백
    if (!navigator.bluetooth || typeof navigator.bluetooth.requestDevice !== 'function') {
      throw new Error('이 브라우저는 Web Bluetooth를 지원하지 않습니다. 화면의 [안드로이드 전용 APK 다운로드] 버튼을 눌러 전용 앱을 설치해 주세요.');
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
        this.log('테슬라 BLE 비콘 검색 시작 (광고 UUID 0x1122 / S...C / Tesla 필터)...');
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

      if (this.isClassicAudioDeviceName(devName)) {
        this.log(`⚠️ 클래식 오디오 블루투스 선택 감지: ${devName}`, 'warn');
        throw new Error(
          `선택하신 '${devName}' 기기는 음악/통화용 클래식 오디오 블루투스입니다.\n\n` +
          `안드로이드 Chrome 브라우저는 OS 보안 정책(neverForLocation)으로 인해 테슬라의 iBeacon(S...C) 신호를 차단합니다.\n` +
          `👉 화면 상단의 [📲 안드로이드 전용 앱(APK) 다운로드] 버튼을 눌러 전용 앱으로 실행해 주세요.`
        );
      }

      await new Promise((r) => setTimeout(r, 350));

      try {
        if (this.device.gatt && this.device.gatt.connected) {
          this.device.gatt.disconnect();
          await new Promise((r) => setTimeout(r, 200));
        }
      } catch (_) {}

      this.device.addEventListener('gattserverdisconnected', () => {
        if (this.connectionState !== 'connected') {
          return;
        }
        this.log('GATT 서버 연결이 해제되었습니다.', 'warn');
        this.cleanup();
        this.updateState('disconnected');
      });

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
          } catch (_) {}

          if (attempt < MAX_RETRIES) {
            const backoffMs = 600 + (attempt * 250);
            await new Promise((r) => setTimeout(r, backoffMs));
          } else {
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

    const newBuffer = new Uint8Array(this.rxBuffer.length + chunk.length);
    newBuffer.set(this.rxBuffer, 0);
    newBuffer.set(chunk, this.rxBuffer.length);
    this.rxBuffer = newBuffer;

    while (this.rxBuffer.length >= 2) {
      if (this.expectedPacketLength === null) {
        this.expectedPacketLength = (this.rxBuffer[0] << 8) | this.rxBuffer[1];
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

  injectSimulatedMessage(data) {
    const wrapped = { telemetry: data };
    if (this.onRxCallback) {
      this.onRxCallback(new Uint8Array([0x08, 0x01]), wrapped);
    }
    if (this.onMessageCallback) {
      this.onMessageCallback(wrapped, new Uint8Array(0));
    }
  }

  async sendPacket(protobufBytes, isPriority = false) {
    if (this.onTxCallback) {
      this.onTxCallback(protobufBytes, isPriority);
    }

    if (this.isSimulation) {
      console.log(`[BLE SIM] Sent ${isPriority ? '[PRIORITY]' : '[NORMAL]'} payload length: ${protobufBytes.length}`);
      return true;
    }

    if (this.connectionState !== 'connected' || (!this.txChar && !this.isNativeApp())) {
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

  async writeNativeChunk(chunkBytes) {
    const hex = bytesToHex(chunkBytes).replace(/\s+/g, '');
    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        if (this.nativeWritePending) {
          this.nativeWritePending = null;
          reject(new Error('Native GATT Write 타임아웃 (4초)'));
        }
      }, 4000);

      this.nativeWritePending = { resolve, reject, timeoutId };
      const ok = window.AndroidBLE.writeChunkHex(hex);
      if (!ok) {
        clearTimeout(timeoutId);
        this.nativeWritePending = null;
        reject(new Error('window.AndroidBLE.writeChunkHex 호출 실패'));
      }
    });
  }

  /**
   * 2바이트 빅엔디안 헤더 부착 및 협상된 MTU(또는 20B) 청크 분할 송신
   */
  async transmitFramedPacket(payloadBytes) {
    const len = payloadBytes.length;
    const framed = new Uint8Array(2 + len);
    framed[0] = (len >> 8) & 0xff;
    framed[1] = len & 0xff;
    framed.set(payloadBytes, 2);

    if (this.isNativeApp()) {
      const chunkSize = Math.max(DEFAULT_CHUNK_SIZE, Math.min(240, (this.negotiatedMtu || 23) - 3));
      let offset = 0;
      while (offset < framed.length) {
        const chunk = framed.slice(offset, offset + chunkSize);
        await this.writeNativeChunk(chunk);
        offset += chunkSize;
        if (offset < framed.length) {
          await new Promise((r) => setTimeout(r, 10));
        }
      }
      return;
    }

    let offset = 0;
    while (offset < framed.length) {
      const chunk = framed.slice(offset, offset + DEFAULT_CHUNK_SIZE);
      if (typeof this.txChar.writeValueWithResponse === 'function') {
        await this.txChar.writeValueWithResponse(chunk);
      } else if (typeof this.txChar.writeValue === 'function') {
        await this.txChar.writeValue(chunk);
      } else if (typeof this.txChar.writeValueWithoutResponse === 'function') {
        await this.txChar.writeValueWithoutResponse(chunk);
      } else {
        throw new Error('GATT 특성에 write 메서드가 존재하지 않습니다.');
      }
      offset += DEFAULT_CHUNK_SIZE;
      if (offset < framed.length) {
        await new Promise((r) => setTimeout(r, 12));
      }
    }
  }

  disconnect() {
    if (this.isNativeApp()) {
      try {
        window.AndroidBLE.disconnect();
      } catch (_) {}
    } else if (this.device && this.device.gatt && this.device.gatt.connected) {
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
