/**
 * app.js
 * 메인 상태 머신 (State Machine), UI 바인딩,
 * ECDH + AES-128-GCM 양방향 세션 핸드셰이크, 단일 카테고리 순환 폴링 및 급감속 감지 연동 [v13]
 */

import { cryptoStore } from './crypto-store.js?v=13';
import { bleManager } from './ble-manager.js?v=13';
import {
  DOMAIN_VEHICLE_SECURITY,
  DOMAIN_INFOTAINMENT,
  VEHICLE_DATA_DRIVE_STATE,
  VEHICLE_DATA_CHARGE_STATE,
  VEHICLE_DATA_CLIMATE_STATE,
  VEHICLE_DATA_TIRE_PRESSURE_STATE,
  buildAddKeyRequest,
  buildRoutableAddKeyRequest,
  buildSessionInfoRequest,
  buildOpenDoorAction,
  buildFlashLightsAction,
  buildStopChargeAction,
  buildChargePortUnlockAction,
  buildStatusRequest,
  buildWhitelistInfoRequest,
  buildGetVehicleDataRequest,
  bytesToHex
} from './proto-codec.js?v=13';

export function formatError(err) {
  if (err === undefined) return 'undefined (User Gesture 만료 또는 스캔 권한 미허용)';
  if (err === null) return 'null (장치 선택 취소됨)';
  if (typeof err === 'string') return err;
  if (err.name) return `${err.name}: ${err.message || ''}`;
  if (err.message) return err.message;
  try {
    const json = JSON.stringify(err);
    if (json && json !== '{}') return json;
  } catch (_) {}
  return String(err);
}

class AppStateMachine {
  constructor() {
    this.currentView = null; // 'wizard' | 'disconnected' | 'charging' | 'main'
    this.activeTab = 'display'; // 'display' | 'control'
    this.isTempChargingBypass = false;

    // 차량 텔레메트리 캐시 (초기 미수신 값은 null로 두어 더미값 혼동 방지)
    this.telemetry = {
      speed: 0,
      gear: 'P',
      power: 0,
      charging_state: 'Disconnected',
      battery_level: null,
      charge_limit_soc: 80,
      time_to_full_charge: 0,
      charger_power: 0,
      charger_voltage: 0,
      charger_actual_current: 0,
      ideal_battery_range_km: null,
      inside_temp: null,
      outside_temp: null,
      tpms: { fl: null, fr: null, rl: null, rr: null },
      doors: { df: false, pf: false, dr: false, pr: false, ft: false, rt: false, charge_port: false },
      locked: false
    };

    this.vehicleSleepStatus = 1; // 1: AWAKE, 2: ASLEEP
    this.pollTickCount = 0;

    // 공식 SDK 규격: BLE MTU(1024B) 초과 방지를 위해 GetVehicleData는 1회당 1개 카테고리만 순환 요청
    // 속도는 스마트폰 GPS로 실시간(0.4~1.0초) 정밀 측정하므로, BLE는 기어/출력/배터리/온도/공기압을 고르게 조회
    this.vehicleDataCategories = [
      VEHICLE_DATA_DRIVE_STATE,
      VEHICLE_DATA_CHARGE_STATE,
      VEHICLE_DATA_CLIMATE_STATE,
      VEHICLE_DATA_TIRE_PRESSURE_STATE
    ];
    this.vehicleDataCategoryIdx = 0;
    this.initialBurstSent = false;
    this.vinMismatchDetected = false;
    this.lastGpsSpeedAt = 0;
    this.gpsWatchId = null;

    // 급감속 감지 상태 추적기
    this.autoHazardEnabled = true;
    this.speedHistory = [];
    this.lastHazardTriggerTime = 0;
    this.HAZARD_COOLDOWN_MS = 8000;

    this.wakeLockSentinel = null;
    this.pollingTimer = null;

    // 실시간 BLE 패킷 디버그 로그
    this.debugLogs = [];
    this.MAX_DEBUG_LOGS = 150;

    this.cachedPublicKeyRaw = null;
  }

  /**
   * 실시간 BLE 패킷 디버그 로그 추가 및 렌더링
   */
  logPacket(direction, rawBytes, parsedOrSummary = null) {
    const timestamp = new Date();
    const timeStr = timestamp.toTimeString().split(' ')[0] + '.' + String(timestamp.getMilliseconds()).padStart(3, '0');
    const hex = rawBytes ? bytesToHex(rawBytes) : '';

    const logEntry = {
      id: Date.now() + Math.random(),
      timeStr,
      direction,
      rawHex: hex,
      bytesLength: rawBytes ? rawBytes.length : 0,
      parsed: parsedOrSummary
    };

    this.debugLogs.push(logEntry);
    if (this.debugLogs.length > this.MAX_DEBUG_LOGS) {
      this.debugLogs.shift();
    }

    const headerBadge = document.getElementById('header-log-count');
    if (headerBadge) headerBadge.textContent = this.debugLogs.length;

    const listEl = document.getElementById('debug-log-list');
    if (listEl) {
      const itemEl = document.createElement('div');
      itemEl.className = `debug-log-item ${direction.toLowerCase()}`;

      const tagClass = direction.toLowerCase();
      let summaryText = '';
      if (typeof parsedOrSummary === 'string') {
        summaryText = parsedOrSummary;
      } else if (parsedOrSummary && typeof parsedOrSummary === 'object') {
        const parts = [];
        if (parsedOrSummary.domain) parts.push(`Dom:${parsedOrSummary.domain}`);
        if (parsedOrSummary.decrypted) parts.push('🔓AES-Decrypted');
        if (parsedOrSummary.decryptError) parts.push(`❌DecErr:${parsedOrSummary.decryptError}`);
        if (parsedOrSummary.whitelistOperationStatus) parts.push(`WL:${parsedOrSummary.whitelistOperationStatus}`);
        if (parsedOrSummary.whitelistKeyIds) parts.push(`WLKeys:${parsedOrSummary.whitelistKeyIds.length}`);
        if (parsedOrSummary.sessionInfo) {
          parts.push(`Session(cnt=${parsedOrSummary.sessionInfo.counter},st=${parsedOrSummary.sessionInfo.status})`);
        }
        if (parsedOrSummary.signedMessageFault) parts.push(`Fault:${parsedOrSummary.signedMessageFault}`);
        const t = parsedOrSummary.telemetry || {};
        if (t.speed !== undefined) parts.push(`Spd:${t.speed}km/h`);
        if (t.gear) parts.push(`Gear:${t.gear}`);
        if (t.battery_level !== undefined && t.battery_level !== null) parts.push(`Bat:${t.battery_level}%`);
        if (t.doors) {
          const openList = Object.entries(t.doors).filter(([, v]) => v).map(([k]) => k.toUpperCase());
          parts.push(openList.length > 0 ? `DoorsOpen:${openList.join(',')}` : 'Doors:AllClosed');
        }
        summaryText = parts.length > 0 ? parts.join(' | ') : JSON.stringify(parsedOrSummary);
      }

      let tagLabel = 'ERR ⚠️';
      if (direction === 'TX') tagLabel = 'TX 📤';
      else if (direction === 'RX') tagLabel = 'RX 📥';
      else if (direction === 'INFO') tagLabel = 'INFO ℹ️';
      else if (direction === 'WARN') tagLabel = 'WARN ⚠️';

      itemEl.innerHTML = `
        <div class="debug-log-meta">
          <div><span class="debug-log-tag ${tagClass}">${tagLabel}</span> [${timeStr}] (${logEntry.bytesLength}B)</div>
          <div>${summaryText ? `<span>${summaryText}</span>` : ''}</div>
        </div>
        <div class="debug-hex-view">${hex || '(No bytes)'}</div>
      `;
      listEl.appendChild(itemEl);
      listEl.scrollTop = listEl.scrollHeight;
    }
  }

  async copyDebugLogs() {
    if (this.debugLogs.length === 0) {
      alert('복사할 로그가 없습니다.');
      return;
    }

    const logText = this.debugLogs.map((l) => {
      let str = `[${l.timeStr}] [${l.direction}] (${l.bytesLength} bytes)\nHEX: ${l.rawHex}\n`;
      if (l.parsed) {
        str += `PARSED: ${typeof l.parsed === 'object' ? JSON.stringify(l.parsed, null, 2) : l.parsed}\n`;
      }
      return str + '----------------------------------------';
    }).join('\n');

    try {
      await navigator.clipboard.writeText(logText);
      const copyBtn = document.getElementById('btn-copy-debug-logs');
      if (copyBtn) {
        const originalText = copyBtn.textContent;
        copyBtn.textContent = '✅ 복사됨';
        setTimeout(() => copyBtn.textContent = originalText, 1500);
      }
    } catch (e) {
      alert('클립보드 복사 실패: ' + formatError(e));
    }
  }

  clearDebugLogs() {
    this.debugLogs = [];
    const headerBadge = document.getElementById('header-log-count');
    if (headerBadge) headerBadge.textContent = '0';
    const listEl = document.getElementById('debug-log-list');
    if (listEl) listEl.innerHTML = '';
  }

  /**
   * 앱 초기화
   */
  async init() {
    console.log('[App] Initializing CT-Control App [v13]...');

    this.registerServiceWorker();

    if (bleManager.isNativeApp()) {
      const badgeEl = document.getElementById('build-version-badge');
      if (badgeEl) {
        badgeEl.textContent = 'v13·APK';
      }
      document.querySelectorAll('.apk-only-web-banner').forEach((el) => {
        el.style.display = 'none';
      });
    }

    await cryptoStore.init();
    this.cachedPublicKeyRaw = cryptoStore.publicKeyRaw;

    this.syncVinInputs();

    bleManager.setCallbacks({
      onStateChange: (state) => this.handleBLEStateChange(state),
      onMessage: (parsedData, raw) => this.handleIncomingTelemetry(parsedData, raw),
      onTx: (bytes, isPriority) => this.logPacket('TX', bytes, isPriority ? '[PRIORITY CMD]' : '[POLL/HANDSHAKE]'),
      onRx: (rawBytes, parsed) => this.logPacket('RX', rawBytes, parsed),
      onLog: (msg, level) => {
        this.logPacket(level === 'error' ? 'ERR' : (level === 'warn' ? 'WARN' : 'INFO'), null, msg);
      }
    });

    this.bindDOMEvents();
    this.setupWakeLock();
    this.setupMotionFallback();
    this.renderTelemetryUI();
    this.evaluateViewState();
  }

  syncVinInputs() {
    const vinCtrlInput = document.getElementById('input-control-vin');
    const vinMainInput = document.getElementById('input-main-vin');
    if (vinCtrlInput && cryptoStore.vin) vinCtrlInput.value = cryptoStore.vin;
    if (vinMainInput && cryptoStore.vin) vinMainInput.value = cryptoStore.vin;
  }

  registerServiceWorker() {
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.getRegistrations().then((regs) => {
        for (const reg of regs) {
          reg.unregister();
        }
      });
    }
  }

  async requestWakeLock() {
    if (typeof navigator !== 'undefined' && 'wakeLock' in navigator && typeof navigator.wakeLock?.request === 'function' && !this.wakeLockSentinel) {
      try {
        this.wakeLockSentinel = await navigator.wakeLock.request('screen');
        this.wakeLockSentinel?.addEventListener('release', () => {
          this.wakeLockSentinel = null;
        });
      } catch (_) {}
    }
  }

  async releaseWakeLock() {
    if (this.wakeLockSentinel) {
      try {
        await this.wakeLockSentinel.release();
        this.wakeLockSentinel = null;
      } catch (_) {}
    }
  }

  setupWakeLock() {
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible' && bleManager.connectionState === 'connected') {
        this.requestWakeLock();
      }
    });
  }

  triggerHaptic(duration = 80) {
    if (typeof navigator !== 'undefined' && typeof navigator.vibrate === 'function') {
      try {
        navigator.vibrate(duration);
      } catch (_) {}
    }
  }

  evaluateViewState() {
    if (!cryptoStore.keyPair || !cryptoStore.isRegistered) {
      this.switchView('wizard');
      this.updateWizardStep();
      return;
    }

    if (bleManager.connectionState === 'disconnected') {
      this.switchView('disconnected');
      return;
    }

    const isCharging = (this.telemetry.charging_state === 'Charging' || this.telemetry.charging_state === 'Starting');
    if (bleManager.connectionState === 'connected' && isCharging && !this.isTempChargingBypass) {
      this.switchView('charging');
      return;
    }

    this.switchView('main');
    this.updateDiagnosticBanners();
  }

  switchView(viewName) {
    this.currentView = viewName;

    const views = {
      wizard: document.getElementById('view-wizard'),
      disconnected: document.getElementById('view-disconnected'),
      charging: document.getElementById('view-charging'),
      main: document.getElementById('view-main')
    };

    const bottomNav = document.getElementById('bottom-nav-bar');

    Object.keys(views).forEach((k) => {
      if (views[k]) {
        views[k].classList.toggle('active', k === viewName);
      }
    });

    if (bottomNav) {
      bottomNav.style.display = (viewName === 'main') ? 'flex' : 'none';
    }

    this.updateHeaderBadges();
  }

  /**
   * 메인 화면 상단 진단 배너 (키 화이트리스트 등록 여부, VIN 설정 여부, 세션 상태) 갱신
   */
  async updateDiagnosticBanners() {
    const keyBanner = document.getElementById('banner-key-unregistered');
    const vinBanner = document.getElementById('banner-vin-setup');
    const vcsecPill = document.getElementById('status-vcsec-pill');
    const infoPill = document.getElementById('status-info-pill');
    const vinVerifyText = document.getElementById('main-vin-verify-text');

    const vcsecReady = cryptoStore.hasValidSession(DOMAIN_VEHICLE_SECURITY);
    const infoReady = cryptoStore.hasValidSession(DOMAIN_INFOTAINMENT);
    const keyNotWhitelisted = (
      cryptoStore.keyConfirmedOnVehicle === false ||
      cryptoStore.sessions[2]?.status === 1 ||
      cryptoStore.sessions[3]?.status === 1
    );

    if (keyBanner) {
      keyBanner.style.display = keyNotWhitelisted ? 'flex' : 'none';
    }

    const needVin = !cryptoStore.vin || cryptoStore.vin.length !== 17 || this.vinMismatchDetected;
    if (vinBanner) {
      vinBanner.style.display = needVin ? 'flex' : 'none';
    }

    if (cryptoStore.vin && cryptoStore.vin.length === 17 && bleManager.device?.name) {
      const check = await cryptoStore.verifyVinWithDeviceName(cryptoStore.vin, bleManager.device.name);
      if (check.matched === false) {
        this.vinMismatchDetected = true;
        if (vinBanner) vinBanner.style.display = 'flex';
        if (vinVerifyText) {
          vinVerifyText.style.color = '#ff6b6b';
          vinVerifyText.textContent = `⚠️ 입력된 VIN의 비콘명(${check.computedBeacon})이 현재 연결된 차량(${check.deviceBeacon})과 다릅니다.`;
        }
      } else if (check.matched === true && vinVerifyText) {
        vinVerifyText.style.color = '#00ff88';
        vinVerifyText.textContent = `✅ 연결된 차량(${check.deviceBeacon})과 차대번호가 일치합니다.`;
      }
    }

    if (vcsecPill) {
      if (keyNotWhitelisted) {
        vcsecPill.className = 'session-pill warn';
        vcsecPill.textContent = 'VCSEC: ⚠️ 키 미등록';
      } else if (vcsecReady) {
        vcsecPill.className = 'session-pill ok';
        vcsecPill.textContent = 'VCSEC(제어): 🟢 활성';
      } else {
        vcsecPill.className = 'session-pill';
        vcsecPill.textContent = 'VCSEC(제어): 🟡 연결중';
      }
    }

    if (infoPill) {
      if (this.vehicleSleepStatus === 2) {
        infoPill.className = 'session-pill warn';
        infoPill.textContent = '계기판: 💤 차량 절전중';
      } else if (infoReady && !needVin) {
        infoPill.className = 'session-pill ok';
        infoPill.textContent = '계기판(데이터): 🟢 수신중';
      } else if (needVin) {
        infoPill.className = 'session-pill warn';
        infoPill.textContent = '계기판: ⚠️ VIN 필요';
      } else {
        infoPill.className = 'session-pill';
        infoPill.textContent = '계기판: 🟡 핸드셰이크중';
      }
    }
  }

  /**
   * BLE 연결 상태 변경 시 ECDH 세션 핸드셰이크 및 폴링 시작
   */
  handleBLEStateChange(state) {
    const indicator = document.getElementById('connection-indicator');
    this.initialBurstSent = false;

    if (state === 'connected') {
      if (indicator) {
        indicator.innerHTML = '<span class="status-dot">🟢</span><span id="connection-text">연결됨</span>';
      }
      this.requestWakeLock();

      // 연결 즉시 VCSEC 상태 조회 + 화이트리스트 확인 + ECDH 세션 핸드셰이크 수행
      this.initiateSessionHandshake();
      this.startTelemetryPolling();
    } else if (state === 'connecting') {
      if (indicator) {
        indicator.innerHTML = '<span class="status-dot">🟡</span><span id="connection-text">연결중...</span>';
      }
      this.stopTelemetryPolling();
    } else {
      if (indicator) {
        indicator.innerHTML = '<span class="status-dot">🔴</span><span id="connection-text">미연결</span>';
      }
      cryptoStore.resetSessions();
      this.releaseWakeLock();
      this.stopTelemetryPolling();
    }

    this.evaluateViewState();
  }

  /**
   * VCSEC(도메인 2) 및 Infotainment(도메인 3)에 상태 조회 + 화이트리스트 확인 + SessionInfoRequest 전송
   */
  async initiateSessionHandshake() {
    if (bleManager.connectionState !== 'connected' || !cryptoStore.publicKeyRaw) return;
    try {
      this.logPacket('INFO', null, '차량 상태 및 ECDH 보안 세션 핸드셰이크(VCSEC & Infotainment) 시작...');

      // 1. 무인증 VCSEC 도어/슬립 상태 즉시 조회
      const statusReq = buildStatusRequest(cryptoStore.routingAddress);
      await bleManager.sendPacket(statusReq, false);

      await new Promise((r) => setTimeout(r, 150));

      // 2. 무인증 VCSEC 화이트리스트 키 목록 조회 (현재 앱의 키가 차량에 등록되어 있는지 확인)
      const wlReq = buildWhitelistInfoRequest(cryptoStore.routingAddress);
      await bleManager.sendPacket(wlReq, false);

      await new Promise((r) => setTimeout(r, 180));

      // 3. VCSEC(도메인 2) ECDH SessionInfoRequest
      const vcsecHandshake = buildSessionInfoRequest(
        cryptoStore.publicKeyRaw,
        DOMAIN_VEHICLE_SECURITY,
        cryptoStore.routingAddress
      );
      await bleManager.sendPacket(vcsecHandshake, false);

      await new Promise((r) => setTimeout(r, 220));

      // 4. Infotainment(도메인 3) ECDH SessionInfoRequest
      const infoHandshake = buildSessionInfoRequest(
        cryptoStore.publicKeyRaw,
        DOMAIN_INFOTAINMENT,
        cryptoStore.routingAddress
      );
      await bleManager.sendPacket(infoHandshake, false);
    } catch (err) {
      console.warn('[App] Session handshake error:', err);
    }
  }

  /**
   * 차량에 키 등록 요청(AddKeyRequest) 전송 (ToVCSECMessage + RoutableMessage 이중 전송)
   */
  async sendAddKeyRequestToVehicle() {
    const pubKey = this.cachedPublicKeyRaw || cryptoStore.publicKeyRaw;
    if (!pubKey) {
      throw new Error('가상키가 아직 생성되지 않았습니다.');
    }
    const rawVcsecPkt = buildAddKeyRequest(pubKey);
    await bleManager.sendPacket(rawVcsecPkt, true);

    await new Promise((r) => setTimeout(r, 220));
    const routablePkt = buildRoutableAddKeyRequest(pubKey, cryptoStore.routingAddress);
    await bleManager.sendPacket(routablePkt, true);
  }

  /**
   * Infotainment 세션 수립 직후 초기 4대 카테고리(주행/배터리/온도/공기압) 연속 조회
   */
  async triggerInitialVehicleDataBurst() {
    if (this.initialBurstSent) return;
    if (!cryptoStore.hasValidSession(DOMAIN_INFOTAINMENT)) return;
    if (!cryptoStore.vin || cryptoStore.vin.length !== 17) return;

    this.initialBurstSent = true;
    const initialCats = [
      VEHICLE_DATA_DRIVE_STATE,
      VEHICLE_DATA_CHARGE_STATE,
      VEHICLE_DATA_CLIMATE_STATE,
      VEHICLE_DATA_TIRE_PRESSURE_STATE
    ];

    for (const cat of initialCats) {
      if (bleManager.connectionState !== 'connected' || !cryptoStore.hasValidSession(DOMAIN_INFOTAINMENT)) break;
      try {
        const pkt = await buildGetVehicleDataRequest(cryptoStore, cat);
        await bleManager.sendPacket(pkt, false);
        await new Promise((r) => setTimeout(r, 260));
      } catch (e) {
        console.warn('[App] Initial burst request error:', e);
        break;
      }
    }
  }

  updateHeaderBadges() {
    const gearBadge = document.getElementById('badge-gear');
    const batteryBadge = document.getElementById('badge-battery');

    if (bleManager.connectionState === 'connected') {
      if (gearBadge) {
        gearBadge.style.display = 'block';
        gearBadge.textContent = this.telemetry.gear || 'P';
      }
      if (batteryBadge) {
        batteryBadge.style.display = 'block';
        batteryBadge.textContent = this.telemetry.battery_level !== null
          ? `${this.telemetry.battery_level}%`
          : '--%';
      }
    } else {
      if (gearBadge) gearBadge.style.display = 'none';
      if (batteryBadge) batteryBadge.style.display = 'none';
    }
  }

  async updateWizardStep() {
    const step1Node = document.getElementById('step-node-1');
    const step2Node = document.getElementById('step-node-2');
    const step3Node = document.getElementById('step-node-3');

    const step1Body = document.getElementById('wizard-step-1');
    const step2Body = document.getElementById('wizard-step-2');
    const step3Body = document.getElementById('wizard-step-3');

    if (!cryptoStore.keyPair) {
      step1Node.className = 'step-item active';
      step2Node.className = 'step-item';
      step3Node.className = 'step-item';
      step1Body.style.display = 'flex';
      step2Body.style.display = 'none';
      step3Body.style.display = 'none';

      await cryptoStore.generateKeyPair();
      this.cachedPublicKeyRaw = cryptoStore.publicKeyRaw;
      setTimeout(() => this.updateWizardStep(), 350);
      return;
    }

    step1Node.className = 'step-item completed';
    step1Body.style.display = 'none';

    if (bleManager.connectionState !== 'connected') {
      step2Node.className = 'step-item active';
      step3Node.className = 'step-item';
      step2Body.style.display = 'flex';
      step3Body.style.display = 'none';
    } else {
      step2Node.className = 'step-item completed';
      step3Node.className = 'step-item active';
      step2Body.style.display = 'none';
      step3Body.style.display = 'flex';
    }
  }

  /**
   * 주기적 상태/텔레메트리 폴링 루프 (1300ms 간격)
   */
  startTelemetryPolling() {
    if (this.pollingTimer) return;
    this.pollTickCount = 0;

    this.pollingTimer = setInterval(async () => {
      if (bleManager.connectionState !== 'connected') return;
      if (bleManager.commandQueue.length > 1) return;

      this.pollTickCount++;

      try {
        // 1. 온보딩 Step 3 (키 등록 대기 중)일 때: 2틱마다 화이트리스트 및 세션 등록 완료 여부를 자동 확인
        if (!cryptoStore.isRegistered) {
          if (this.pollTickCount % 2 === 1) {
            const wlReq = buildWhitelistInfoRequest(cryptoStore.routingAddress);
            await bleManager.sendPacket(wlReq, false);
          } else {
            const siReq = buildSessionInfoRequest(
              cryptoStore.publicKeyRaw,
              DOMAIN_VEHICLE_SECURITY,
              cryptoStore.routingAddress
            );
            await bleManager.sendPacket(siReq, false);
          }
          return;
        }

        // 2. 메인 화면: 홀수 틱마다 VCSEC 도어/잠금/슬립 상태 요청 (무인증 즉시 응답)
        if (this.pollTickCount % 2 === 1) {
          const vcsecReq = buildStatusRequest(cryptoStore.routingAddress);
          await bleManager.sendPacket(vcsecReq, false);
          return;
        }

        // 3. 짝수 틱: 세션 미수립 시 핸드셰이크 요청, 수립 완료 시 단일 카테고리 GetVehicleData 순환 요청
        if (!cryptoStore.hasValidSession(DOMAIN_VEHICLE_SECURITY) && this.pollTickCount % 4 === 0) {
          const req = buildSessionInfoRequest(
            cryptoStore.publicKeyRaw,
            DOMAIN_VEHICLE_SECURITY,
            cryptoStore.routingAddress
          );
          await bleManager.sendPacket(req, false);
        } else if (!cryptoStore.hasValidSession(DOMAIN_INFOTAINMENT) && this.vehicleSleepStatus !== 2) {
          const req = buildSessionInfoRequest(
            cryptoStore.publicKeyRaw,
            DOMAIN_INFOTAINMENT,
            cryptoStore.routingAddress
          );
          await bleManager.sendPacket(req, false);
        } else if (
          cryptoStore.hasValidSession(DOMAIN_INFOTAINMENT) &&
          this.vehicleSleepStatus !== 2 &&
          cryptoStore.vin &&
          cryptoStore.vin.length === 17
        ) {
          const catTag = this.vehicleDataCategories[this.vehicleDataCategoryIdx % this.vehicleDataCategories.length];
          this.vehicleDataCategoryIdx++;
          const vdReq = await buildGetVehicleDataRequest(cryptoStore, catTag);
          await bleManager.sendPacket(vdReq, false);
        }
      } catch (_) {
        // 일시적 폴링 오류 무시
      }
    }, 1300);
  }

  stopTelemetryPolling() {
    if (this.pollingTimer) {
      clearInterval(this.pollingTimer);
      this.pollingTimer = null;
    }
  }

  /**
   * 수신된 패킷 처리 (SessionInfo 갱신, 화이트리스트 확인, 텔레메트리 병합)
   */
  async handleIncomingTelemetry(parsed) {
    if (!parsed) return;

    // 1. 차량 슬립 상태 업데이트
    if (parsed.vehicleSleepStatus) {
      this.vehicleSleepStatus = parsed.vehicleSleepStatus;
    }

    // 2. WhitelistInfo(화이트리스트 키 목록) 수신 시 현재 앱의 keyId가 등록되었는지 자동 검증
    if (Array.isArray(parsed.whitelistKeyIds)) {
      const isEnrolled = cryptoStore.checkWhitelistEntries(parsed.whitelistKeyIds);
      if (isEnrolled) {
        this.logPacket('INFO', null, '✅ 차량 화이트리스트(WhitelistInfo)에 현재 가상키 등록이 확인되었습니다!');
        if (!cryptoStore.isRegistered) {
          await cryptoStore.setRegistered(true);
          this.evaluateViewState();
          this.initiateSessionHandshake();
        }
      } else if (parsed.whitelistKeyIds.length > 0) {
        this.logPacket('WARN', null, `차량 화이트리스트(총 ${parsed.whitelistKeyIds.length}개 키)에 아직 현재 앱 키가 없습니다.`);
      }
      this.updateDiagnosticBanners();
    }

    // 3. ECDH SessionInfo 수신 시 공유 비밀키 유도 및 세션 상태 갱신
    if (parsed.sessionInfo) {
      const targetDomain = parsed.domain || DOMAIN_VEHICLE_SECURITY;
      try {
        const session = await cryptoStore.updateSessionInfo(targetDomain, parsed.sessionInfo);
        if (session.status === 1) {
          this.logPacket(
            'WARN',
            null,
            `⚠️ 도메인(${targetDomain}) 응답: 차량 화이트리스트에 아직 키가 등록되지 않았습니다 (KEY_NOT_ON_WHITELIST).`
          );
        } else if (session.ready) {
          this.logPacket(
            'INFO',
            null,
            `🔐 [보안 세션 수립 완료] 도메인 ${targetDomain === 3 ? 'Infotainment(3)' : 'VCSEC(2)'} (Counter: ${session.counter})`
          );
          if (!cryptoStore.isRegistered) {
            await cryptoStore.setRegistered(true);
            this.evaluateViewState();
          }
          if (targetDomain === DOMAIN_INFOTAINMENT) {
            this.triggerInitialVehicleDataBurst();
          }
        }
        this.updateDiagnosticBanners();
      } catch (siErr) {
        this.logPacket('WARN', null, `세션 키 유도 실패: ${formatError(siErr)}`);
      }
    }

    // 4. 차량에서 보고된 카운터 동기화
    if (parsed.reportedCounter !== null && typeof parsed.reportedCounter === 'number') {
      await cryptoStore.syncCounter(parsed.reportedCounter);
    }

    // 5. 서명/메타데이터 Fault 감지 및 자동 복구
    if (parsed.signedMessageFault) {
      const fault = parsed.signedMessageFault;
      const dom = parsed.domain || DOMAIN_INFOTAINMENT;

      if (fault === 3) {
        // MESSAGEFAULT_ERROR_UNKNOWN_KEY_ID = 3
        cryptoStore.keyConfirmedOnVehicle = false;
        this.logPacket('WARN', null, '⚠️ 차량에 현재 가상키가 등록되어 있지 않습니다 (UNKNOWN_KEY_ID=3).');
      } else if (fault === 5 || fault === 12) {
        // 5 = INVALID_SIGNATURE, 12 = WRONG_PERSONALIZATION (VIN 누락 또는 불일치)
        this.vinMismatchDetected = true;
        this.logPacket('WARN', null, `⚠️ 차량 서명 검증 실패 (Fault=${fault}): 17자리 차대번호(VIN)가 정확한지 확인해 주세요.`);
      } else if (fault === 20 || fault === 21) {
        // BAD_PARAMETER: 구형 펌웨어에서 FLAG_ENCRYPT_RESPONSE 미지원 시 평문 응답 모드로 자동 전환
        if (cryptoStore.sessions[dom] && cryptoStore.sessions[dom].useEncryptResponse) {
          cryptoStore.sessions[dom].useEncryptResponse = false;
          this.logPacket('INFO', null, `도메인(${dom}) 응답 암호화 플래그 비활성화(평문 호환 모드) 전환`);
        }
      } else if (fault === 28) {
        // REQUIRES_RESPONSE_ENCRYPTION = 28
        if (cryptoStore.sessions[dom]) {
          cryptoStore.sessions[dom].useEncryptResponse = true;
        }
      } else if (fault === 4 || fault === 7 || fault === 15 || fault === 17) {
        // 토큰/카운터/만료시간 오차 발생 시 세션 핸드셰이크 자동 재수행
        this.logPacket('INFO', null, `세션 시간/카운터 재동기화 요청 (Fault=${fault})`);
        const req = buildSessionInfoRequest(cryptoStore.publicKeyRaw, dom, cryptoStore.routingAddress);
        bleManager.sendPacket(req, false).catch(() => {});
      }
      this.updateDiagnosticBanners();
    }

    // 6. 화이트리스트 키 등록 승인 상태 처리
    if (parsed.whitelistOperationStatus === 'OK') {
      this.logPacket('INFO', null, '✅ 차량에서 가상키 등록(Whitelist AddKey) 승인이 완료되었습니다!');
      cryptoStore.keyConfirmedOnVehicle = true;
      await cryptoStore.setRegistered(true);
      this.evaluateViewState();
      this.initiateSessionHandshake();
    } else if (parsed.whitelistOperationStatus === 'WAITING_FOR_CARD') {
      this.logPacket('INFO', null, '💳 차량이 센터콘솔 NFC 카드키 태그를 대기 중입니다! 지금 카드를 태그해 주세요.');
      const step3Status = document.getElementById('wizard-step3-status');
      if (step3Status) {
        step3Status.innerHTML = '💳 <strong>차량이 NFC 카드 태그를 대기 중입니다!</strong><br>지금 센터콘솔 컵홀더 뒤편에 카드를 태그하고 차량 화면에서 [승인]을 눌러주세요.';
      }
    } else if (parsed.whitelistOperationStatus === 'ERROR') {
      this.logPacket('WARN', null, `⚠️ 키 등록 응답 알림 (코드: ${parsed.whitelistErrorCode ?? '확인 필요'})`);
    }

    // 7. 수신된 텔레메트리 필드 병합
    const incomingTel = parsed.telemetry || {};
    if (incomingTel.doors) {
      this.telemetry.doors = { ...incomingTel.doors };
    }
    if (incomingTel.tpms) {
      Object.assign(this.telemetry.tpms, incomingTel.tpms);
    }

    // GPS 속도가 최근 4초 이내에 수신되고 있다면 속도는 실시간 GPS 값을 우선 유지하고(터널 등 GPS 음영 지역에서만 BLE 속도 폴백)
    const isGpsActive = (Date.now() - this.lastGpsSpeedAt) < 4000;

    const scalarKeys = [
      'gear', 'power', 'charging_state', 'battery_level',
      'charge_limit_soc', 'time_to_full_charge', 'charger_power',
      'charger_voltage', 'charger_actual_current', 'ideal_battery_range_km',
      'inside_temp', 'outside_temp', 'locked'
    ];
    if (!isGpsActive) {
      scalarKeys.push('speed');
    }
    for (const k of scalarKeys) {
      if (incomingTel[k] !== undefined && incomingTel[k] !== null) {
        this.telemetry[k] = incomingTel[k];
      }
    }

    // 만약 인포테인먼트 텔레메트리가 정상 복호화/수신되었다면 VIN 불일치 경고 해제
    if (parsed.decrypted) {
      this.vinMismatchDetected = false;
      this.updateDiagnosticBanners();
    }

    // 8. 급감속 감지 알고리즘 실행 (GPS 미수신 음영 지역이거나 시뮬레이션 모드일 때 BLE 속도 폴백)
    if (!isGpsActive && incomingTel.speed !== undefined) {
      this.detectRapidDeceleration(this.telemetry.speed);
    }

    // 9. UI 갱신
    this.renderTelemetryUI();
    this.updateHeaderBadges();

    // 10. 충전 화면 전환 재평가
    const isCharging = (this.telemetry.charging_state === 'Charging' || this.telemetry.charging_state === 'Starting');
    if (isCharging && this.currentView === 'main' && !this.isTempChargingBypass) {
      this.evaluateViewState();
    } else if (!isCharging && this.currentView === 'charging') {
      this.isTempChargingBypass = false;
      this.evaluateViewState();
    }
  }

  /**
   * 고속도로 정체구간 급감속 감지 알고리즘:
   * 최근 5초(5000ms) 이내에 시속 90km/h 이상으로 주행하다가
   * 현재 속도가 10km/h 미만으로 떨어진 경우 비상등 점멸 자동 발동
   */
  detectRapidDeceleration(currentSpeed) {
    if (!this.autoHazardEnabled || typeof currentSpeed !== 'number') return;

    const now = Date.now();
    this.speedHistory.push({ speed: currentSpeed, timestamp: now });
    // 최근 5.5초(5500ms) 동안의 속도 이력 유지
    this.speedHistory = this.speedHistory.filter((item) => now - item.timestamp <= 5500);

    if (this.speedHistory.length < 2) return;

    // 현재 속도가 10km/h 미만으로 떨어졌을 때, 최근 5초(5000ms) 이내에 90km/h 이상이었던 기록이 있는지 확인
    if (currentSpeed < 10) {
      const highSpeedEntry = this.speedHistory.find((item) => {
        const dt = now - item.timestamp;
        return dt <= 5000 && item.speed >= 90;
      });

      if (highSpeedEntry) {
        if (now - this.lastHazardTriggerTime >= this.HAZARD_COOLDOWN_MS) {
          const elapsedSec = ((now - highSpeedEntry.timestamp) / 1000).toFixed(1);
          this.logPacket(
            'WARN',
            null,
            `🚨 [고속도로 정체 급감속 감지] ${highSpeedEntry.speed}km/h → ${currentSpeed}km/h (${elapsedSec}초 내 감속)! 비상등 자동 발동`
          );
          this.lastHazardTriggerTime = now;
          this.triggerAutoHazardFlash();
        }
      }
    }
  }

  setupMotionFallback() {
    // 스마트폰 고정밀 GPS(네이티브 LocationManager + Web Geolocation watchPosition)로
    // 차량 BLE 지연 없이 실시간 주행 속도(km/h) 갱신 및 고속도로 급감속(5초 내 90->10km/h 미만) 감지 수행
    const applyGpsSpeedKmh = (rawKmh) => {
      if (typeof rawKmh !== 'number' || Number.isNaN(rawKmh) || rawKmh < 0) return;
      const kmh = rawKmh < 2 ? 0 : Math.round(rawKmh);
      this.lastGpsSpeedAt = Date.now();
      this.telemetry.speed = kmh;

      const speedEl = document.getElementById('cluster-speed-val');
      if (speedEl) speedEl.textContent = kmh;

      this.updateDoorSafetyLocks();
      this.detectRapidDeceleration(kmh);
    };

    // 1. Android 네이티브 APK GPS 속도 브릿지 콜백
    if (typeof window !== 'undefined') {
      window.__onNativeGpsSpeed = (kmh) => {
        applyGpsSpeedKmh(Number(kmh));
      };
    }

    // 2. HTML5 High-Accuracy Geolocation watchPosition (웹 & 하이브리드 동시 지원)
    if (typeof navigator !== 'undefined' && navigator.geolocation && typeof navigator.geolocation.watchPosition === 'function') {
      try {
        this.gpsWatchId = navigator.geolocation.watchPosition(
          (pos) => {
            if (pos && pos.coords && typeof pos.coords.speed === 'number' && pos.coords.speed >= 0) {
              applyGpsSpeedKmh(pos.coords.speed * 3.6);
            }
          },
          () => {
            // GPS 일시 미수신(지하주차장/터널) 시 자동으로 BLE DriveState 속도로 폴백됨
          },
          {
            enableHighAccuracy: true,
            maximumAge: 0,
            timeout: 5000
          }
        );
      } catch (_) {}
    }
  }

  async triggerAutoHazardFlash() {
    this.triggerHaptic(150);
    const flashBtn = document.getElementById('btn-hazard-flash');
    if (flashBtn) {
      flashBtn.classList.add('flash-effect');
      setTimeout(() => flashBtn.classList.remove('flash-effect'), 500);
    }

    try {
      const pkt = await buildFlashLightsAction(cryptoStore);
      await bleManager.sendPacket(pkt, true);
    } catch (err) {
      console.error('[App] Failed to send auto hazard packet:', err);
    }
  }

  renderTelemetryUI() {
    const t = this.telemetry;

    const speedEl = document.getElementById('cluster-speed-val');
    if (speedEl) speedEl.textContent = Math.round(t.speed || 0);

    const gearItems = document.querySelectorAll('.gear-item');
    gearItems.forEach((el) => {
      el.classList.toggle('active', el.getAttribute('data-gear') === (t.gear || 'P'));
    });

    const powerBar = document.getElementById('power-gauge-fill');
    const powerText = document.getElementById('power-numeric-val');
    if (powerBar && powerText) {
      const pVal = t.power || 0;
      powerText.textContent = `${Math.round(pVal)} kW`;
      const maxPower = 100;
      const pct = Math.min(50, Math.abs(pVal) / maxPower * 50);

      if (pVal >= 0) {
        powerBar.className = 'power-bar-fill power';
        powerBar.style.left = '50%';
        powerBar.style.width = `${pct}%`;
      } else {
        powerBar.className = 'power-bar-fill regen';
        powerBar.style.left = `${50 - pct}%`;
        powerBar.style.width = `${pct}%`;
      }
    }

    const doors = t.doors || {};
    const doorMap = [
      { id: 'door-pill-df', open: !!doors.df },
      { id: 'door-pill-pf', open: !!doors.pf },
      { id: 'door-pill-dr', open: !!doors.dr },
      { id: 'door-pill-pr', open: !!doors.pr },
      { id: 'door-pill-ft', open: !!doors.ft },
      { id: 'door-pill-rt', open: !!doors.rt }
    ];

    for (const d of doorMap) {
      const pill = document.getElementById(d.id);
      if (pill) {
        pill.className = `door-status-pill ${d.open ? 'open' : ''}`;
        const strongEl = pill.querySelector('strong');
        if (strongEl) strongEl.textContent = d.open ? '열림' : '닫힘';
      }
    }

    const hasAnyDoorOpen = doorMap.some((d) => d.open);
    const doorsSummary = document.getElementById('doors-summary-badge');
    if (doorsSummary) {
      if (hasAnyDoorOpen) {
        doorsSummary.textContent = '열림 감지 ⚠️';
        doorsSummary.style.color = '#ff5252';
      } else {
        doorsSummary.textContent = t.locked ? '전체 닫힘 · 잠김 🔒' : '전체 닫힘 🟢';
        doorsSummary.style.color = 'var(--tesla-green)';
      }
    }

    if (t.tpms) {
      const fl = document.getElementById('tpms-fl');
      const fr = document.getElementById('tpms-fr');
      const rl = document.getElementById('tpms-rl');
      const rr = document.getElementById('tpms-rr');
      if (fl) fl.textContent = t.tpms.fl !== null ? `${t.tpms.fl} Bar` : '-- Bar';
      if (fr) fr.textContent = t.tpms.fr !== null ? `${t.tpms.fr} Bar` : '-- Bar';
      if (rl) rl.textContent = t.tpms.rl !== null ? `${t.tpms.rl} Bar` : '-- Bar';
      if (rr) rr.textContent = t.tpms.rr !== null ? `${t.tpms.rr} Bar` : '-- Bar';
    }

    const tempIn = document.getElementById('temp-in');
    const tempOut = document.getElementById('temp-out');
    const batPct = document.getElementById('cluster-battery-pct');
    const batRange = document.getElementById('cluster-range-km');

    if (tempIn) tempIn.textContent = t.inside_temp !== null ? t.inside_temp : '--';
    if (tempOut) tempOut.textContent = t.outside_temp !== null ? t.outside_temp : '--';
    if (batPct) batPct.textContent = t.battery_level !== null ? `${t.battery_level}%` : '--%';
    if (batRange) {
      const rangeVal = t.ideal_battery_range_km !== null
        ? t.ideal_battery_range_km
        : (t.battery_level !== null ? Math.round(t.battery_level * 4.2) : null);
      batRange.textContent = rangeVal !== null ? `${rangeVal} km` : '-- km';
    }

    const chargeSoc = document.getElementById('charge-soc-text');
    const chargeProgress = document.getElementById('charge-progress-bar-fill');
    const chargeLimit = document.getElementById('charge-limit-text');
    const chargeRemTime = document.getElementById('charge-remaining-time');
    const chargePower = document.getElementById('charge-stat-power');
    const chargeVA = document.getElementById('charge-stat-va');
    const chargeRange = document.getElementById('charge-stat-range');
    const chargeTemp = document.getElementById('charge-stat-temp');

    if (chargeSoc) chargeSoc.textContent = t.battery_level !== null ? `${t.battery_level}%` : '--%';
    if (chargeProgress) chargeProgress.style.width = `${t.battery_level || 0}%`;
    if (chargeLimit) chargeLimit.textContent = `${t.charge_limit_soc}%`;

    if (chargeRemTime) {
      const hrs = Math.floor(t.time_to_full_charge / 60);
      const mins = t.time_to_full_charge % 60;
      chargeRemTime.textContent = (hrs > 0) ? `${hrs}시간 ${mins}분` : `${mins}분`;
    }

    if (chargePower) chargePower.textContent = `${Number(t.charger_power || 0).toFixed(1)} kW`;
    if (chargeVA) chargeVA.textContent = `${t.charger_voltage} V / ${t.charger_actual_current} A`;
    if (chargeRange) {
      const rVal = t.ideal_battery_range_km || (t.battery_level !== null ? Math.round(t.battery_level * 4.2) : null);
      chargeRange.textContent = rVal !== null ? `${rVal} km` : '-- km';
    }
    if (chargeTemp) chargeTemp.textContent = t.inside_temp !== null ? `${t.inside_temp} °C` : '-- °C';

    this.updateDoorSafetyLocks();
  }

  updateDoorSafetyLocks() {
    const forceUnlock = document.getElementById('chk-force-unlock')?.checked;
    const isVehicleSafe = (this.telemetry.gear === 'P' && (this.telemetry.speed || 0) === 0);
    const shouldLock = !isVehicleSafe && !forceUnlock;

    const doorButtons = document.querySelectorAll('.door-tile-btn');
    doorButtons.forEach((btn) => {
      btn.disabled = shouldLock;
    });

    const msg = document.getElementById('safety-status-msg');
    if (msg) {
      if (forceUnlock) {
        msg.textContent = '⚠️ 강제 잠금 해제 활성화됨';
        msg.style.color = '#ff9f0a';
      } else if (shouldLock) {
        msg.textContent = '🔒 주행 중 도어 개방 잠금';
        msg.style.color = 'var(--text-secondary)';
      } else {
        msg.textContent = '🔓 P단 정차 상태: 개방 가능';
        msg.style.color = 'var(--tesla-green)';
      }
    }
  }

  async handleSaveVin(rawVinInput) {
    const val = (rawVinInput || '').trim().toUpperCase();
    if (val && val.length !== 17) {
      alert('차대번호(VIN)는 정확히 17자리여야 합니다.');
      return;
    }

    if (val && bleManager.device?.name) {
      const check = await cryptoStore.verifyVinWithDeviceName(val, bleManager.device.name);
      if (check.matched === false) {
        const proceed = confirm(
          `입력하신 VIN(${val})으로 계산된 비콘 이름(${check.computedBeacon})이 현재 연결된 차량(${check.deviceBeacon})과 다릅니다.\n` +
          `오타가 없는지 확인해 주세요. 그래도 저장하시겠습니까?`
        );
        if (!proceed) return;
      }
    }

    await cryptoStore.setVin(val);
    this.vinMismatchDetected = false;
    this.initialBurstSent = false;
    this.syncVinInputs();
    await this.updateDiagnosticBanners();

    if (val && bleManager.connectionState === 'connected') {
      await this.initiateSessionHandshake();
      setTimeout(() => this.triggerInitialVehicleDataBurst(), 600);
    }
  }

  bindDOMEvents() {
    document.getElementById('btn-create-key')?.addEventListener('click', async () => {
      this.triggerHaptic(40);
      await cryptoStore.generateKeyPair();
      this.cachedPublicKeyRaw = cryptoStore.publicKeyRaw;
      this.updateWizardStep();
    });

    const startPairingFlow = async (mode = 'standard') => {
      try {
        await bleManager.connect({ mode });
        this.triggerHaptic(60);

        const devName = bleManager.device?.name || '';
        this.logPacket('INFO', null, `페어링 요청 전송 중... (연결 기기: ${devName})`);

        await this.sendAddKeyRequestToVehicle();
        this.updateWizardStep();
      } catch (err) {
        console.error('[App] Pairing error:', err);
        alert('BLE 스캔/연결 실패:\n' + formatError(err));
      }
    };

    // 네이티브 BLE 스캐너 모달 제어
    document.getElementById('btn-native-close-modal')?.addEventListener('click', () => {
      this.triggerHaptic(30);
      bleManager.cancelNativeScanModal();
    });

    document.getElementById('btn-native-open-gps')?.addEventListener('click', () => {
      this.triggerHaptic(40);
      if (bleManager.isNativeApp()) {
        window.AndroidBLE.openLocationSettings();
      }
    });

    document.getElementById('btn-native-rescan')?.addEventListener('click', () => {
      this.triggerHaptic(40);
      if (bleManager.isNativeApp()) {
        bleManager.nativeScanItems.clear();
        bleManager.renderNativeScanList();
        try {
          const env = JSON.parse(window.AndroidBLE.getEnvStatusJson() || '{}');
          const gpsWarnEl = document.getElementById('native-gps-warning');
          if (gpsWarnEl) {
            gpsWarnEl.style.display = env.locationEnabled === false ? 'block' : 'none';
          }
        } catch (_) {}
        window.AndroidBLE.startScan(bleManager.nativeScanFilterMode);
      }
    });

    document.getElementById('btn-native-toggle-filter')?.addEventListener('click', (e) => {
      this.triggerHaptic(30);
      bleManager.nativeScanFilterMode = bleManager.nativeScanFilterMode === 'standard' ? 'all' : 'standard';
      e.currentTarget.textContent = bleManager.nativeScanFilterMode === 'all'
        ? '🔍 현재: 모든 기기 표시 중 (클릭 시 테슬라만 필터)'
        : '🚗 현재: 테슬라 신호 우선 표시 (클릭 시 전체 기기 보기)';
      bleManager.renderNativeScanList();
    });

    document.getElementById('btn-request-pairing')?.addEventListener('click', async () => {
      await startPairingFlow('standard');
    });

    document.getElementById('btn-request-pairing-all')?.addEventListener('click', async () => {
      await startPairingFlow('all');
    });

    // Step 3 및 메인 화면에서 AddKeyRequest 전송 버튼
    const handleResendAddKey = async () => {
      this.triggerHaptic(60);
      try {
        await this.sendAddKeyRequestToVehicle();
        alert('차량에 키 등록 요청 패킷을 전송했습니다!\n지금 센터콘솔 리더기에 NFC 카드키를 태그하고 차량 모니터에서 [승인]을 눌러주세요.');
      } catch (err) {
        alert('키 등록 요청 전송 실패: ' + formatError(err));
      }
    };

    document.getElementById('btn-resend-addkey')?.addEventListener('click', handleResendAddKey);
    document.getElementById('btn-main-send-addkey')?.addEventListener('click', handleResendAddKey);
    document.getElementById('btn-ctrl-send-addkey')?.addEventListener('click', handleResendAddKey);

    document.getElementById('btn-confirm-registration')?.addEventListener('click', async () => {
      this.triggerHaptic(60);
      await cryptoStore.setRegistered(true);
      this.evaluateViewState();
      this.initiateSessionHandshake();
    });

    // 메인 배너 및 제어 탭 VIN 저장
    document.getElementById('btn-save-main-vin')?.addEventListener('click', async () => {
      this.triggerHaptic(50);
      const val = document.getElementById('input-main-vin')?.value || '';
      await this.handleSaveVin(val);
    });

    document.getElementById('btn-save-vin')?.addEventListener('click', async () => {
      this.triggerHaptic(50);
      const val = document.getElementById('input-control-vin')?.value || '';
      await this.handleSaveVin(val);
      if (cryptoStore.vin) {
        alert(`차대번호(${cryptoStore.vin})가 저장되어 암호화 세션에 적용되었습니다.`);
      }
    });

    // 세션 재동기화 버튼
    document.getElementById('btn-resync-session')?.addEventListener('click', async () => {
      this.triggerHaptic(40);
      this.initialBurstSent = false;
      await this.initiateSessionHandshake();
    });

    // 키 초기화 모달 핸들러
    const resetModal = document.getElementById('reset-confirm-modal');

    const executePurgeAndRestart = async () => {
      this.triggerHaptic(60);
      resetModal?.classList.remove('active');

      try {
        await cryptoStore.clearAll();
      } catch (_) {}

      try {
        bleManager.disconnect();
      } catch (_) {}

      if ('caches' in window) {
        try {
          const cacheKeys = await caches.keys();
          await Promise.all(cacheKeys.map((k) => caches.delete(k)));
        } catch (_) {}
      }

      try {
        const url = new URL(window.location.href);
        url.searchParams.set('t', Date.now().toString());
        window.location.replace(url.toString());
      } catch (_) {
        window.location.reload(true);
      }
    };

    const openResetModal = () => {
      this.triggerHaptic(40);
      resetModal?.classList.add('active');
    };

    document.getElementById('btn-reset-key')?.addEventListener('click', openResetModal);
    document.getElementById('btn-disconnected-reset')?.addEventListener('click', openResetModal);
    document.getElementById('btn-ctrl-reset-key')?.addEventListener('click', openResetModal);

    document.getElementById('btn-modal-cancel-reset')?.addEventListener('click', () => {
      this.triggerHaptic(30);
      resetModal?.classList.remove('active');
    });

    document.getElementById('btn-modal-confirm-reset')?.addEventListener('click', async () => {
      await executePurgeAndRestart();
    });

    // 미연결 화면 연결 버튼
    document.getElementById('btn-hero-connect')?.addEventListener('click', async () => {
      try {
        await bleManager.connect({ mode: 'standard' });
        this.triggerHaptic(80);
      } catch (err) {
        console.error('[App] Hero connect error:', err);
        alert('BLE 스캔/연결 실패:\n' + formatError(err));
      }
    });

    document.getElementById('btn-hero-connect-all')?.addEventListener('click', async () => {
      try {
        await bleManager.connect({ mode: 'all' });
        this.triggerHaptic(80);
      } catch (err) {
        console.error('[App] Hero connect all error:', err);
        alert('BLE 스캔/연결 실패:\n' + formatError(err));
      }
    });

    // 충전 전용 화면 이벤트
    document.getElementById('btn-stop-charge')?.addEventListener('click', async () => {
      this.triggerHaptic(100);
      try {
        const stopPkt = await buildStopChargeAction(cryptoStore);
        await bleManager.sendPacket(stopPkt, true);
        await new Promise((r) => setTimeout(r, 350));
        const unlockPkt = await buildChargePortUnlockAction(cryptoStore);
        await bleManager.sendPacket(unlockPkt, true);
        alert('충전 중지 및 포트 잠금 해제 명령을 전송했습니다.');
      } catch (e) {
        alert('명령 전송 실패: ' + formatError(e));
      }
    });

    document.getElementById('btn-toggle-charging-view')?.addEventListener('click', () => {
      this.triggerHaptic(40);
      this.isTempChargingBypass = true;
      this.switchView('main');
    });

    // 하단 탭 바 전환
    const tabBtnDisplay = document.getElementById('tab-btn-display');
    const tabBtnControl = document.getElementById('tab-btn-control');
    const tabContentDisplay = document.getElementById('tab-content-display');
    const tabContentControl = document.getElementById('tab-content-control');

    tabBtnDisplay?.addEventListener('click', () => {
      this.triggerHaptic(30);
      this.activeTab = 'display';
      tabBtnDisplay.classList.add('active');
      tabBtnControl.classList.remove('active');
      tabContentDisplay.style.display = 'flex';
      tabContentControl.style.display = 'none';
    });

    tabBtnControl?.addEventListener('click', () => {
      this.triggerHaptic(30);
      this.activeTab = 'control';
      tabBtnControl.classList.add('active');
      tabBtnDisplay.classList.remove('active');
      tabContentDisplay.style.display = 'none';
      tabContentControl.style.display = 'flex';
    });

    document.getElementById('switch-auto-hazard')?.addEventListener('change', (e) => {
      this.triggerHaptic(30);
      this.autoHazardEnabled = e.target.checked;
    });

    document.getElementById('chk-force-unlock')?.addEventListener('change', () => {
      this.triggerHaptic(40);
      this.updateDoorSafetyLocks();
    });

    // 비상등 점멸
    const hazardBtn = document.getElementById('btn-hazard-flash');
    hazardBtn?.addEventListener('click', async () => {
      this.triggerHaptic(80);
      hazardBtn.classList.add('flash-effect');
      setTimeout(() => hazardBtn.classList.remove('flash-effect'), 400);

      try {
        if (!cryptoStore.vin || cryptoStore.vin.length !== 17) {
          alert('비상등 및 도어 제어 명령을 보내려면 화면 상단(또는 하단)에 차량의 17자리 차대번호(VIN)를 먼저 1회 저장해 주세요.');
          return;
        }
        const pkt = await buildFlashLightsAction(cryptoStore);
        await bleManager.sendPacket(pkt, true);
      } catch (err) {
        console.error('Hazard packet error:', err);
        alert('비상등 명령 전송 실패: ' + formatError(err));
      }
    });

    // 4개 도어 래치 물리 개방
    const doorBtns = document.querySelectorAll('.door-tile-btn');
    doorBtns.forEach((btn) => {
      btn.addEventListener('click', async () => {
        if (btn.disabled) return;
        this.triggerHaptic(80);
        btn.classList.add('flash-effect');
        setTimeout(() => btn.classList.remove('flash-effect'), 400);

        const doorIndex = parseInt(btn.getAttribute('data-door'), 10);
        try {
          if (!cryptoStore.vin || cryptoStore.vin.length !== 17) {
            alert('도어 개방 명령을 보내려면 화면 상단(또는 하단)에 차량의 17자리 차대번호(VIN)를 먼저 1회 저장해 주세요.');
            return;
          }
          const pkt = await buildOpenDoorAction(doorIndex, cryptoStore);
          await bleManager.sendPacket(pkt, true);
        } catch (err) {
          console.error(`Door ${doorIndex} unlatch failed:`, err);
          alert('도어 개방 명령 실패: ' + formatError(err));
        }
      });
    });

    // 디버그 로그 시트 이벤트 (상단 헤더 버튼으로 통합)
    const headerDebugBtn = document.getElementById('btn-header-debug');
    const debugSheet = document.getElementById('debug-log-sheet');
    const closeDebugBtn = document.getElementById('btn-close-debug-sheet');
    const copyDebugBtn = document.getElementById('btn-copy-debug-logs');
    const clearDebugBtn = document.getElementById('btn-clear-debug-logs');

    headerDebugBtn?.addEventListener('click', () => {
      this.triggerHaptic(40);
      debugSheet?.classList.toggle('active');
    });

    closeDebugBtn?.addEventListener('click', () => {
      debugSheet?.classList.remove('active');
    });

    copyDebugBtn?.addEventListener('click', () => {
      this.triggerHaptic(40);
      this.copyDebugLogs();
    });

    clearDebugBtn?.addEventListener('click', () => {
      this.triggerHaptic(40);
      this.clearDebugLogs();
    });

    this.setupDemoModeTrigger();
  }

  setupDemoModeTrigger() {
    const logo = document.getElementById('brand-logo');
    const modal = document.getElementById('demo-modal');
    const closeBtn = document.getElementById('btn-close-demo');

    let pressTimer = null;

    const startPress = () => {
      pressTimer = setTimeout(() => {
        this.triggerHaptic(120);
        modal.classList.add('active');
        bleManager.isSimulation = true;
      }, 5000);
    };

    const cancelPress = () => {
      if (pressTimer) {
        clearTimeout(pressTimer);
        pressTimer = null;
      }
    };

    logo?.addEventListener('mousedown', startPress);
    logo?.addEventListener('touchstart', startPress);
    logo?.addEventListener('mouseup', cancelPress);
    logo?.addEventListener('mouseleave', cancelPress);
    logo?.addEventListener('touchend', cancelPress);

    closeBtn?.addEventListener('click', () => {
      modal.classList.remove('active');
    });

    document.getElementById('btn-sim-driving')?.addEventListener('click', () => {
      modal.classList.remove('active');
      bleManager.updateState('connected');
      bleManager.injectSimulatedMessage({
        speed: 60,
        gear: 'D',
        power: 28,
        battery_level: 74,
        charging_state: 'Disconnected',
        doors: { df: false, pf: false, dr: false, pr: false, ft: false, rt: false, charge_port: false },
        inside_temp: 21.0,
        outside_temp: 16.5,
        tpms: { fl: 2.9, fr: 2.9, rl: 2.8, rr: 2.8 }
      });
    });

    document.getElementById('btn-sim-hard-brake')?.addEventListener('click', () => {
      modal.classList.remove('active');
      bleManager.updateState('connected');
      bleManager.injectSimulatedMessage({
        speed: 95,
        gear: 'D',
        power: -45,
        battery_level: 74,
        charging_state: 'Disconnected'
      });
      setTimeout(() => {
        bleManager.injectSimulatedMessage({
          speed: 8,
          gear: 'D',
          power: -80,
          battery_level: 74,
          charging_state: 'Disconnected'
        });
      }, 1200);
    });

    document.getElementById('btn-sim-charging')?.addEventListener('click', () => {
      modal.classList.remove('active');
      this.isTempChargingBypass = false;
      bleManager.updateState('connected');
      bleManager.injectSimulatedMessage({
        speed: 0,
        gear: 'P',
        power: 0,
        battery_level: 42,
        charge_limit_soc: 80,
        time_to_full_charge: 35,
        charger_power: 11.5,
        charger_voltage: 230,
        charger_actual_current: 48,
        charging_state: 'Charging',
        inside_temp: 20.0,
        outside_temp: 15.0
      });
    });

    document.getElementById('btn-sim-disconnect')?.addEventListener('click', () => {
      modal.classList.remove('active');
      bleManager.disconnect();
    });
  }
}

window.addEventListener('DOMContentLoaded', () => {
  const app = new AppStateMachine();
  app.init();
});
