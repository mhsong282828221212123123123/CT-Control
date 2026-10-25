/**
 * app.js
 * 메인 상태 머신 (State Machine), UI 바인딩,
 * ECDH + AES-128-GCM 세션 핸드셰이크, VCSEC/CarServer 폴링 및 급감속 감지 연동 [v11]
 */

import { cryptoStore } from './crypto-store.js?v=11';
import { bleManager } from './ble-manager.js?v=11';
import {
  DOMAIN_VEHICLE_SECURITY,
  DOMAIN_INFOTAINMENT,
  buildAddKeyRequest,
  buildSessionInfoRequest,
  buildOpenDoorAction,
  buildFlashLightsAction,
  buildStopChargeAction,
  buildChargePortUnlockAction,
  buildStatusRequest,
  buildGetVehicleDataRequest,
  bytesToHex,
  computeTeslaBLEBeaconName
} from './proto-codec.js?v=11';

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

    // 차량 텔레메트리 캐시
    this.telemetry = {
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
      tpms: { fl: 2.9, fr: 2.9, rl: 2.9, rr: 2.9 },
      doors: { df: false, pf: false, dr: false, pr: false, ft: false, rt: false, charge_port: false }
    };

    this.vehicleSleepStatus = 1; // 1: AWAKE, 2: ASLEEP
    this.pollTickCount = 0;

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

    // User Gesture 보존을 위한 사전 캐시 공개키
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

    const badge = document.getElementById('debug-log-badge');
    if (badge) badge.textContent = this.debugLogs.length;
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
        if (parsedOrSummary.whitelistOperationStatus) parts.push(`Whitelist:${parsedOrSummary.whitelistOperationStatus}`);
        if (parsedOrSummary.sessionInfo) parts.push(`SessionInfo(cnt=${parsedOrSummary.sessionInfo.counter})`);
        if (parsedOrSummary.signedMessageFault) parts.push(`Fault:${parsedOrSummary.signedMessageFault}`);
        const t = parsedOrSummary.telemetry || {};
        if (t.speed !== undefined) parts.push(`Spd:${t.speed}km/h`);
        if (t.gear) parts.push(`Gear:${t.gear}`);
        if (t.battery_level !== undefined) parts.push(`Bat:${t.battery_level}%`);
        if (t.doors) parts.push('DoorsUpdated');
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
        copyBtn.textContent = '✅ 복사됨!';
        setTimeout(() => copyBtn.textContent = originalText, 1500);
      }
    } catch (e) {
      alert('클립보드 복사 실패: ' + formatError(e));
    }
  }

  clearDebugLogs() {
    this.debugLogs = [];
    const badge = document.getElementById('debug-log-badge');
    if (badge) badge.textContent = '0';
    const headerBadge = document.getElementById('header-log-count');
    if (headerBadge) headerBadge.textContent = '0';
    const listEl = document.getElementById('debug-log-list');
    if (listEl) listEl.innerHTML = '';
  }

  /**
   * 앱 초기화
   */
  async init() {
    console.log('[App] Initializing CT-Control App [v11]...');

    this.registerServiceWorker();

    await cryptoStore.init();
    this.cachedPublicKeyRaw = cryptoStore.publicKeyRaw;

    // 저장된 VIN을 제어 탭 입력창에 반영
    const vinCtrlInput = document.getElementById('input-control-vin');
    if (vinCtrlInput && cryptoStore.vin) {
      vinCtrlInput.value = cryptoStore.vin;
    }

    bleManager.setCallbacks({
      onStateChange: (state) => this.handleBLEStateChange(state),
      onMessage: (parsedData, raw) => this.handleIncomingTelemetry(parsedData, raw),
      onTx: (bytes, isPriority) => this.logPacket('TX', bytes, isPriority ? '[PRIORITY CMD]' : '[POLL/HANDSHAKE]'),
      onRx: (rawBytes, parsed) => this.logPacket('RX', rawBytes, parsed),
      onLog: (msg, level) => {
        this.logPacket(level === 'error' ? 'ERR' : (level === 'warn' ? 'WARN' : 'INFO'), null, msg);
        if (bleManager.connectionState === 'connecting') {
          const connText = document.getElementById('connection-text');
          if (connText) {
            connText.textContent = msg.length > 25 ? msg.substring(0, 25) + '...' : msg;
          }
        }
      }
    });

    this.bindDOMEvents();
    this.setupWakeLock();
    this.setupMotionFallback();
    this.evaluateViewState();
  }

  registerServiceWorker() {
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.getRegistrations().then((regs) => {
        for (const reg of regs) {
          reg.unregister();
          console.log('[v11] Unregistered SW:', reg.scope);
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
      } catch (err) {
        console.warn('[App] Wake Lock request error:', formatError(err));
      }
    }
  }

  async releaseWakeLock() {
    if (this.wakeLockSentinel) {
      try {
        await this.wakeLockSentinel.release();
        this.wakeLockSentinel = null;
      } catch (err) {
        console.warn('[App] Wake Lock release error:', formatError(err));
      }
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
   * BLE 연결 상태 변경 시 ECDH 세션 핸드셰이크 및 폴링 시작
   */
  handleBLEStateChange(state) {
    const indicator = document.getElementById('connection-indicator');

    if (state === 'connected') {
      indicator.innerHTML = '<span class="status-dot">🟢</span><span id="connection-text">차량 연결됨</span>';
      this.requestWakeLock();

      // 등록 완료된 키가 있으면 즉시 VCSEC & Infotainment ECDH 세션 핸드셰이크 수행
      if (cryptoStore.isRegistered && cryptoStore.publicKeyRaw) {
        this.initiateSessionHandshake();
      }
      this.startTelemetryPolling();
    } else if (state === 'connecting') {
      indicator.innerHTML = '<span class="status-dot">🟡</span><span id="connection-text">보안 세션 연결 중...</span>';
      this.stopTelemetryPolling();
    } else {
      indicator.innerHTML = '<span class="status-dot">🔴</span><span id="connection-text">차량 연결 끊김</span>';
      cryptoStore.resetSessions();
      this.releaseWakeLock();
      this.stopTelemetryPolling();
    }

    this.evaluateViewState();
  }

  /**
   * VCSEC(도메인 2) 및 Infotainment(도메인 3)에 SessionInfoRequest 전송
   */
  async initiateSessionHandshake() {
    if (bleManager.connectionState !== 'connected' || !cryptoStore.publicKeyRaw) return;
    try {
      this.logPacket('INFO', null, '차량 ECDH 보안 세션 핸드셰이크(SessionInfoRequest) 요청 중...');
      const vcsecHandshake = buildSessionInfoRequest(
        cryptoStore.publicKeyRaw,
        DOMAIN_VEHICLE_SECURITY,
        cryptoStore.routingAddress
      );
      await bleManager.sendPacket(vcsecHandshake, false);

      await new Promise((r) => setTimeout(r, 250));
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

  updateHeaderBadges() {
    const gearBadge = document.getElementById('badge-gear');
    const batteryBadge = document.getElementById('badge-battery');

    if (bleManager.connectionState === 'connected') {
      gearBadge.style.display = 'block';
      gearBadge.textContent = this.telemetry.gear || 'P';

      batteryBadge.style.display = 'block';
      batteryBadge.textContent = `${this.telemetry.battery_level}%`;
    } else {
      gearBadge.style.display = 'none';
      batteryBadge.style.display = 'none';
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
      setTimeout(() => this.updateWizardStep(), 400);
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
   * 주기적 상태/텔레메트리 폴링 루프 (1500ms 간격 - 20B 청크 분할 전송 큐 부하 방지)
   */
  startTelemetryPolling() {
    if (this.pollingTimer) return;
    this.pollTickCount = 0;

    this.pollingTimer = setInterval(async () => {
      if (bleManager.connectionState !== 'connected') return;
      // 큐에 이미 패킷이 밀려 있으면 이번 틱은 건너뜀
      if (bleManager.commandQueue.length > 1) return;

      this.pollTickCount++;

      try {
        // 1. VCSEC 도어/잠금/슬립 상태 요청 (짝수 틱 또는 미등록 시)
        if (!cryptoStore.isRegistered || this.pollTickCount % 2 === 1) {
          const vcsecReq = buildStatusRequest(cryptoStore.routingAddress);
          await bleManager.sendPacket(vcsecReq, false);
        }

        // 2. 키 등록 완료 상태에서 세션이 아직 없으면 4틱마다 핸드셰이크 재요청
        if (cryptoStore.isRegistered) {
          if (!cryptoStore.hasValidSession(DOMAIN_VEHICLE_SECURITY) && this.pollTickCount % 4 === 0) {
            const req = buildSessionInfoRequest(cryptoStore.publicKeyRaw, DOMAIN_VEHICLE_SECURITY, cryptoStore.routingAddress);
            await bleManager.sendPacket(req, false);
          } else if (
            cryptoStore.hasValidSession(DOMAIN_INFOTAINMENT) &&
            this.vehicleSleepStatus !== 2 &&
            this.pollTickCount % 2 === 0
          ) {
            // 3. 차량이 깨어있고 Infotainment 세션이 수립되어 있으면 주행/배터리/공기압 데이터 폴링
            const vdReq = await buildGetVehicleDataRequest(cryptoStore);
            await bleManager.sendPacket(vdReq, false);
          } else if (
            !cryptoStore.hasValidSession(DOMAIN_INFOTAINMENT) &&
            this.vehicleSleepStatus !== 2 &&
            this.pollTickCount % 4 === 2
          ) {
            const req = buildSessionInfoRequest(cryptoStore.publicKeyRaw, DOMAIN_INFOTAINMENT, cryptoStore.routingAddress);
            await bleManager.sendPacket(req, false);
          }
        }
      } catch (e) {
        // 일시적 폴링 오류 무시
      }
    }, 1500);
  }

  stopTelemetryPolling() {
    if (this.pollingTimer) {
      clearInterval(this.pollingTimer);
      this.pollingTimer = null;
    }
  }

  /**
   * 수신된 패킷 처리 (SessionInfo 갱신, 화이트리스트 승인 확인, 텔레메트리 병합)
   */
  async handleIncomingTelemetry(parsed) {
    if (!parsed) return;

    // 1. 차량 슬립 상태 업데이트
    if (parsed.vehicleSleepStatus) {
      this.vehicleSleepStatus = parsed.vehicleSleepStatus;
    }

    // 2. ECDH SessionInfo 수신 시 공유 비밀키(SHA1(ECDH)[:16]) 및 세션 정보 업데이트
    if (parsed.sessionInfo) {
      const targetDomain = parsed.domain || DOMAIN_VEHICLE_SECURITY;
      try {
        await cryptoStore.updateSessionInfo(targetDomain, parsed.sessionInfo);
        this.logPacket(
          'INFO',
          null,
          `[보안 세션 수립 완료] 도메인 ${targetDomain === 3 ? 'Infotainment(3)' : 'VCSEC(2)'} (Counter: ${parsed.sessionInfo.counter})`
        );
      } catch (siErr) {
        this.logPacket('WARN', null, `세션 키 유도 실패: ${formatError(siErr)}`);
      }
    }

    // 3. 차량에서 보고된 카운터 동기화
    if (parsed.reportedCounter !== null && typeof parsed.reportedCounter === 'number') {
      await cryptoStore.syncCounter(parsed.reportedCounter);
    }

    // 4. 서명/메타데이터 Fault 감지 안내
    if (parsed.signedMessageFault) {
      // 12 = MESSAGEFAULT_ERROR_WRONG_PERSONALIZATION (VIN 불일치/누락)
      if (parsed.signedMessageFault === 12) {
        this.logPacket('WARN', null, '⚠️ 차량이 명령 인증을 위해 17자리 차대번호(VIN) 설정을 요구합니다 (제어 탭 하단에서 VIN 저장 필요).');
      } else if (parsed.signedMessageFault === 3) {
        this.logPacket('WARN', null, '⚠️ 차량에 현재 가상키가 등록되어 있지 않습니다 (UNKNOWN_KEY_ID).');
      }
    }

    // 5. 화이트리스트 키 등록 승인 완료 확인
    if (parsed.whitelistOperationStatus === 'OK') {
      this.logPacket('INFO', null, '✅ 차량에서 가상키 등록(Whitelist AddKey) 승인이 확인되었습니다!');
      await cryptoStore.setRegistered(true);
      this.evaluateViewState();
      this.initiateSessionHandshake();
    } else if (parsed.whitelistOperationStatus === 'WAITING_FOR_CARD') {
      this.logPacket('INFO', null, '💳 차량이 센터콘솔 NFC 카드키 태그를 대기 중입니다 (지금 카드를 태그해 주세요).');
    } else if (parsed.whitelistOperationStatus === 'ERROR') {
      this.logPacket('WARN', null, `⚠️ 키 등록 응답 오류 (코드: ${parsed.whitelistErrorCode ?? '알 수 없음'})`);
    }

    // 6. 실제로 수신된 텔레메트리 필드만 안전하게 병합 (기존 값 0 초기화 방지)
    const incomingTel = parsed.telemetry || {};
    if (incomingTel.doors) {
      Object.assign(this.telemetry.doors, incomingTel.doors);
    }
    if (incomingTel.tpms) {
      Object.assign(this.telemetry.tpms, incomingTel.tpms);
    }

    const scalarKeys = [
      'speed', 'gear', 'power', 'charging_state', 'battery_level',
      'charge_limit_soc', 'time_to_full_charge', 'charger_power',
      'charger_voltage', 'charger_actual_current', 'ideal_battery_range_km',
      'inside_temp', 'outside_temp'
    ];
    for (const k of scalarKeys) {
      if (incomingTel[k] !== undefined && incomingTel[k] !== null) {
        this.telemetry[k] = incomingTel[k];
      }
    }

    // 7. 급감속 감지 알고리즘 실행 (실제 속도 필드가 수신되었을 때만)
    if (incomingTel.speed !== undefined) {
      this.detectRapidDeceleration(this.telemetry.speed);
    }

    // 8. UI 갱신
    this.renderTelemetryUI();
    this.updateHeaderBadges();

    // 9. 충전 화면 전환 재평가
    const isCharging = (this.telemetry.charging_state === 'Charging' || this.telemetry.charging_state === 'Starting');
    if (isCharging && this.currentView === 'main' && !this.isTempChargingBypass) {
      this.evaluateViewState();
    } else if (!isCharging && this.currentView === 'charging') {
      this.isTempChargingBypass = false;
      this.evaluateViewState();
    }
  }

  detectRapidDeceleration(currentSpeed) {
    if (!this.autoHazardEnabled || typeof currentSpeed !== 'number') return;

    const now = Date.now();
    this.speedHistory.push({ speed: currentSpeed, timestamp: now });
    this.speedHistory = this.speedHistory.filter((item) => now - item.timestamp <= 1500);

    if (this.speedHistory.length < 2) return;

    const baseline = this.speedHistory.find((item) => {
      const dt = now - item.timestamp;
      return dt >= 300 && dt <= 700;
    });

    if (baseline && baseline.speed >= 40) {
      const drop = baseline.speed - currentSpeed;
      if (drop >= 15) {
        if (now - this.lastHazardTriggerTime >= this.HAZARD_COOLDOWN_MS) {
          console.warn(`[App] 🚨 RAPID DECELERATION DETECTED: -${drop} km/h! Triggering Hazard Lights.`);
          this.lastHazardTriggerTime = now;
          this.triggerAutoHazardFlash();
        }
      }
    }
  }

  setupMotionFallback() {
    if (window.DeviceMotionEvent) {
      window.addEventListener('devicemotion', (event) => {
        if (!this.autoHazardEnabled) return;
        const acc = event.accelerationIncludingGravity || event.acceleration;
        if (!acc) return;

        const forwardG = acc.y;
        if (forwardG && forwardG < -7.8) {
          const now = Date.now();
          if (now - this.lastHazardTriggerTime >= this.HAZARD_COOLDOWN_MS) {
            this.lastHazardTriggerTime = now;
            this.triggerAutoHazardFlash();
          }
        }
      });
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
    if (speedEl) speedEl.textContent = Math.round(t.speed);

    const gearItems = document.querySelectorAll('.gear-item');
    gearItems.forEach((el) => {
      el.classList.toggle('active', el.getAttribute('data-gear') === t.gear);
    });

    const powerBar = document.getElementById('power-gauge-fill');
    const powerText = document.getElementById('power-numeric-val');
    if (powerBar && powerText) {
      powerText.textContent = `${Math.round(t.power)} kW`;
      const maxPower = 100;
      const pct = Math.min(50, Math.abs(t.power) / maxPower * 50);

      if (t.power >= 0) {
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
      { id: 'door-pill-df', open: doors.df },
      { id: 'door-pill-pf', open: doors.pf },
      { id: 'door-pill-dr', open: doors.dr },
      { id: 'door-pill-pr', open: doors.pr },
      { id: 'door-pill-ft', open: doors.ft },
      { id: 'door-pill-rt', open: doors.rt }
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
        doorsSummary.textContent = '열림 ⚠️';
        doorsSummary.style.color = '#ff6b6b';
      } else {
        doorsSummary.textContent = '전체 닫힘 🟢';
        doorsSummary.style.color = 'var(--tesla-green)';
      }
    }

    if (t.tpms) {
      const fl = document.getElementById('tpms-fl');
      const fr = document.getElementById('tpms-fr');
      const rl = document.getElementById('tpms-rl');
      const rr = document.getElementById('tpms-rr');
      if (fl) fl.textContent = `${t.tpms.fl} Bar`;
      if (fr) fr.textContent = `${t.tpms.fr} Bar`;
      if (rl) rl.textContent = `${t.tpms.rl} Bar`;
      if (rr) rr.textContent = `${t.tpms.rr} Bar`;
    }

    const tempIn = document.getElementById('temp-in');
    const tempOut = document.getElementById('temp-out');
    const batPct = document.getElementById('cluster-battery-pct');
    const batRange = document.getElementById('cluster-range-km');
    if (tempIn) tempIn.textContent = t.inside_temp;
    if (tempOut) tempOut.textContent = t.outside_temp;
    if (batPct) batPct.textContent = `${t.battery_level}%`;
    if (batRange) batRange.textContent = `${t.ideal_battery_range_km || Math.round(t.battery_level * 4.2)} km`;

    const chargeSoc = document.getElementById('charge-soc-text');
    const chargeProgress = document.getElementById('charge-progress-bar-fill');
    const chargeLimit = document.getElementById('charge-limit-text');
    const chargeRemTime = document.getElementById('charge-remaining-time');
    const chargePower = document.getElementById('charge-stat-power');
    const chargeVA = document.getElementById('charge-stat-va');
    const chargeRange = document.getElementById('charge-stat-range');
    const chargeTemp = document.getElementById('charge-stat-temp');

    if (chargeSoc) chargeSoc.textContent = `${t.battery_level}%`;
    if (chargeProgress) chargeProgress.style.width = `${t.battery_level}%`;
    if (chargeLimit) chargeLimit.textContent = `${t.charge_limit_soc}%`;

    if (chargeRemTime) {
      const hrs = Math.floor(t.time_to_full_charge / 60);
      const mins = t.time_to_full_charge % 60;
      chargeRemTime.textContent = (hrs > 0) ? `${hrs}시간 ${mins}분` : `${mins}분`;
    }

    if (chargePower) chargePower.textContent = `${Number(t.charger_power || 0).toFixed(1)} kW`;
    if (chargeVA) chargeVA.textContent = `${t.charger_voltage} V / ${t.charger_actual_current} A`;
    if (chargeRange) chargeRange.textContent = `${t.ideal_battery_range_km || Math.round(t.battery_level * 4.2)} km`;
    if (chargeTemp) chargeTemp.textContent = `${t.inside_temp} °C`;

    this.updateDoorSafetyLocks();
  }

  updateDoorSafetyLocks() {
    const forceUnlock = document.getElementById('chk-force-unlock')?.checked;
    const isVehicleSafe = (this.telemetry.gear === 'P' && this.telemetry.speed === 0);
    const shouldLock = !isVehicleSafe && !forceUnlock;

    const doorButtons = document.querySelectorAll('.door-tile-btn');
    doorButtons.forEach((btn) => {
      btn.disabled = shouldLock;
    });

    const msg = document.getElementById('safety-status-msg');
    if (msg) {
      if (forceUnlock) {
        msg.textContent = '⚠️ 강제 잠금 해제 활성화됨 (비상)';
        msg.style.color = '#ff9f0a';
      } else if (shouldLock) {
        msg.textContent = '🔒 주행 중(D/R/N 또는 속도>0) 개방 잠금';
        msg.style.color = 'var(--text-secondary)';
      } else {
        msg.textContent = '🔓 P단 정차 상태: 개방 가능';
        msg.style.color = 'var(--tesla-green)';
      }
    }
  }

  bindDOMEvents() {
    document.getElementById('btn-create-key')?.addEventListener('click', async () => {
      this.triggerHaptic(40);
      await cryptoStore.generateKeyPair();
      this.cachedPublicKeyRaw = cryptoStore.publicKeyRaw;
      this.updateWizardStep();
    });

    // 페어링 연결 공통 함수
    const startPairingFlow = async (mode = 'standard') => {
      try {
        await bleManager.connect({ mode });
        this.triggerHaptic(60);

        // 만약 기기명이 "Tesla XXXXXX" 형식이면 끝 6자리 힌트 기록
        const devName = bleManager.device?.name || '';
        this.logPacket('INFO', null, `페어링 요청 전송 중... (연결 기기: ${devName})`);

        const pubKey = this.cachedPublicKeyRaw || cryptoStore.publicKeyRaw;
        const addKeyPacket = buildAddKeyRequest(pubKey);
        await bleManager.sendPacket(addKeyPacket, true);
        this.updateWizardStep();
      } catch (err) {
        console.error('[App] Pairing error:', err);
        alert('BLE 스캔/연결 실패 [v11]:\n' + formatError(err));
      }
    };

    document.getElementById('btn-request-pairing')?.addEventListener('click', async () => {
      await startPairingFlow('standard');
    });

    document.getElementById('btn-request-pairing-all')?.addEventListener('click', async () => {
      await startPairingFlow('all');
    });

    // Step 3에서 AddKeyRequest 재전송 버튼
    document.getElementById('btn-resend-addkey')?.addEventListener('click', async () => {
      this.triggerHaptic(50);
      try {
        const pubKey = this.cachedPublicKeyRaw || cryptoStore.publicKeyRaw;
        const addKeyPacket = buildAddKeyRequest(pubKey);
        await bleManager.sendPacket(addKeyPacket, true);
        this.logPacket('INFO', null, '키 등록 요청(AddKeyRequest)을 차량에 재전송했습니다. 지금 NFC 카드를 태그하세요.');
      } catch (err) {
        alert('재전송 실패: ' + formatError(err));
      }
    });

    document.getElementById('btn-confirm-registration')?.addEventListener('click', async () => {
      this.triggerHaptic(60);
      await cryptoStore.setRegistered(true);
      this.evaluateViewState();
      this.initiateSessionHandshake();
    });

    // 제어 탭 내 VIN 저장 버튼 (최신 펌웨어 AES-GCM AAD Personalization 용)
    document.getElementById('btn-save-vin')?.addEventListener('click', async () => {
      this.triggerHaptic(40);
      const vinInput = document.getElementById('input-control-vin');
      const val = (vinInput?.value || '').trim().toUpperCase();
      if (val && val.length !== 17) {
        alert('차대번호(VIN)는 정확히 17자리여야 합니다.');
        return;
      }
      await cryptoStore.setVin(val);
      alert(val ? `차대번호(${val})가 저장되었습니다.` : '차대번호 설정이 해제되었습니다.');
    });

    // 키 초기화 & 캐시 강제 삭제 후 리로드 핸들러
    const resetModal = document.getElementById('reset-confirm-modal');

    const executePurgeAndRestart = async () => {
      this.triggerHaptic(60);
      resetModal?.classList.remove('active');

      try {
        await cryptoStore.clearAll();
      } catch (e) {
        console.warn('[Purge] Crypto clear error:', e);
      }

      try {
        bleManager.disconnect();
      } catch (e) {
        console.warn('[Purge] BLE disconnect error:', e);
      }

      if ('caches' in window) {
        try {
          const cacheKeys = await caches.keys();
          await Promise.all(cacheKeys.map((k) => caches.delete(k)));
        } catch (e) {
          console.warn('[Purge] Cache delete error:', e);
        }
      }

      if ('serviceWorker' in navigator) {
        try {
          const regs = await navigator.serviceWorker.getRegistrations();
          await Promise.all(regs.map((r) => r.unregister()));
        } catch (e) {
          console.warn('[Purge] SW unregister error:', e);
        }
      }

      try {
        const url = new URL(window.location.href);
        url.searchParams.set('t', Date.now().toString());
        window.location.replace(url.toString());
      } catch (_) {
        window.location.reload(true);
      }
    };

    document.getElementById('btn-reset-key')?.addEventListener('click', () => {
      this.triggerHaptic(40);
      resetModal?.classList.add('active');
    });

    document.getElementById('btn-modal-cancel-reset')?.addEventListener('click', () => {
      this.triggerHaptic(30);
      resetModal?.classList.remove('active');
    });

    document.getElementById('btn-modal-confirm-reset')?.addEventListener('click', async () => {
      await executePurgeAndRestart();
    });

    // 미연결 화면 [차량 블루투스 연결하기] 버튼
    document.getElementById('btn-hero-connect')?.addEventListener('click', async () => {
      try {
        await bleManager.connect({ mode: 'standard' });
        this.triggerHaptic(80);
      } catch (err) {
        console.error('[App] Hero connect error:', err);
        alert('BLE 스캔/연결 실패 [v11]:\n' + formatError(err));
      }
    });

    document.getElementById('btn-hero-connect-all')?.addEventListener('click', async () => {
      try {
        await bleManager.connect({ mode: 'all' });
        this.triggerHaptic(80);
      } catch (err) {
        console.error('[App] Hero connect all error:', err);
        alert('BLE 스캔/연결 실패 [v11]:\n' + formatError(err));
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
          const pkt = await buildOpenDoorAction(doorIndex, cryptoStore);
          await bleManager.sendPacket(pkt, true);
        } catch (err) {
          console.error(`Door ${doorIndex} unlatch failed:`, err);
          alert('도어 개방 명령 실패: ' + formatError(err));
        }
      });
    });

    // 디버그 로그 시트 이벤트
    const debugBtn = document.getElementById('btn-toggle-debug');
    const headerDebugBtn = document.getElementById('btn-header-debug');
    const wizardDebugBtn = document.getElementById('btn-open-debug-wizard');
    const disconnectedDebugBtn = document.getElementById('btn-open-debug-disconnected');
    const debugSheet = document.getElementById('debug-log-sheet');
    const closeDebugBtn = document.getElementById('btn-close-debug-sheet');
    const copyDebugBtn = document.getElementById('btn-copy-debug-logs');
    const clearDebugBtn = document.getElementById('btn-clear-debug-logs');

    const openDebugSheet = () => {
      this.triggerHaptic(40);
      debugSheet?.classList.add('active');
    };

    debugBtn?.addEventListener('click', () => {
      this.triggerHaptic(40);
      debugSheet?.classList.toggle('active');
    });

    headerDebugBtn?.addEventListener('click', openDebugSheet);
    wizardDebugBtn?.addEventListener('click', openDebugSheet);
    disconnectedDebugBtn?.addEventListener('click', openDebugSheet);

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

    logo.addEventListener('mousedown', startPress);
    logo.addEventListener('touchstart', startPress);
    logo.addEventListener('mouseup', cancelPress);
    logo.addEventListener('mouseleave', cancelPress);
    logo.addEventListener('touchend', cancelPress);

    closeBtn.addEventListener('click', () => {
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
        speed: 60,
        gear: 'D',
        power: -45,
        battery_level: 74,
        charging_state: 'Disconnected'
      });
      setTimeout(() => {
        bleManager.injectSimulatedMessage({
          speed: 10,
          gear: 'D',
          power: -80,
          battery_level: 74,
          charging_state: 'Disconnected'
        });
      }, 400);
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
