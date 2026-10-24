/**
 * app.js
 * 메인 상태 머신 (State Machine), UI 바인딩,
 * Screen WakeLock, 급감속 감지 로직 및 세션 서명 연동
 */

import { cryptoStore } from './crypto-store.js?v=4';
import { bleManager } from './ble-manager.js?v=4';
import {
  buildAddKeyRequest,
  buildOpenDoorAction,
  buildFlashLightsAction,
  buildCarServerFlashLightsAction,
  buildStopChargeAction,
  buildChargePortUnlockAction,
  buildStatusRequest,
  bytesToHex
} from './proto-codec.js?v=4';

// iOS Bluefy / Safari WebKit 안전 에러 메시지 추출 헬퍼 [v4]
export function formatError(err) {
  if (err === undefined) return 'undefined (User Gesture 만료 또는 Bluefy 스캔 권한 미허용)';
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
    // 앱 전역 상태
    this.currentView = null; // 'wizard' | 'disconnected' | 'charging' | 'main'
    this.activeTab = 'display'; // 'display' | 'control'
    this.isTempChargingBypass = false; // 충전 중 일반 화면 임시 전환 여부

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
      inside_temp: 21.5,
      outside_temp: 18.0,
      tpms: { fl: 2.9, fr: 2.9, rl: 2.9, rr: 2.9 },
      doors: { df: false, pf: false, dr: false, pr: false, ft: false, rt: false, charge_port: false }
    };

    // 급감속 감지 상태 추적기
    this.autoHazardEnabled = true;
    this.speedHistory = []; // { speed, timestamp }
    this.lastHazardTriggerTime = 0;
    this.HAZARD_COOLDOWN_MS = 8000; // 8초 쿨다운

    // Screen Wake Lock 참조
    this.wakeLockSentinel = null;

    // 주기적 상태 폴링 타이머
    this.pollingTimer = null;

    // 실시간 BLE 패킷 디버그 로그
    this.debugLogs = [];
    this.MAX_DEBUG_LOGS = 150;

    // [v4 핵심] User Gesture 보존을 위한 사전 캐시 공개키
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
      direction, // 'TX' | 'RX' | 'ERR'
      rawHex: hex,
      bytesLength: rawBytes ? rawBytes.length : 0,
      parsed: parsedOrSummary
    };

    this.debugLogs.push(logEntry);
    if (this.debugLogs.length > this.MAX_DEBUG_LOGS) {
      this.debugLogs.shift();
    }

    // 뱃지 업데이트
    const badge = document.getElementById('debug-log-badge');
    if (badge) {
      badge.textContent = this.debugLogs.length;
    }

    // 시트 뷰어에 즉시 아이템 추가
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
        if (parsedOrSummary.whitelistOperationStatus) parts.push(`Whitelist: ${parsedOrSummary.whitelistOperationStatus}`);
        if (parsedOrSummary.reportedCounter !== null && parsedOrSummary.reportedCounter !== undefined) parts.push(`Counter: ${parsedOrSummary.reportedCounter}`);
        if (parsedOrSummary.speed !== undefined) parts.push(`Speed: ${parsedOrSummary.speed}km/h, Gear: ${parsedOrSummary.gear}`);
        if (parsedOrSummary.charging_state && parsedOrSummary.charging_state !== 'Disconnected') parts.push(`Charge: ${parsedOrSummary.charging_state}`);
        summaryText = parts.length > 0 ? parts.join(' | ') : JSON.stringify(parsedOrSummary);
      }

      itemEl.innerHTML = `
        <div class="debug-log-meta">
          <div><span class="debug-log-tag ${tagClass}">${direction === 'TX' ? 'TX 📤' : (direction === 'RX' ? 'RX 📥' : 'ERR ⚠️')}</span> [${timeStr}] (${logEntry.bytesLength}B)</div>
          <div>${summaryText ? `<span>${summaryText}</span>` : ''}</div>
        </div>
        <div class="debug-hex-view">${hex || '(No bytes)'}</div>
      `;
      listEl.appendChild(itemEl);
      listEl.scrollTop = listEl.scrollHeight;
    }
  }

  /**
   * 전체 디버그 로그 클립보드 복사
   */
  async copyDebugLogs() {
    if (this.debugLogs.length === 0) {
      alert('복사할 로그가 없습니다.');
      return;
    }

    const logText = this.debugLogs.map(l => {
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

  /**
   * 디버그 로그 비우기
   */
  clearDebugLogs() {
    this.debugLogs = [];
    const badge = document.getElementById('debug-log-badge');
    if (badge) badge.textContent = '0';
    const listEl = document.getElementById('debug-log-list');
    if (listEl) listEl.innerHTML = '';
  }


  /**
   * 앱 부트스트랩 및 이벤트 바인딩
   */
  async init() {
    console.log('[App] Initializing CT-Control App...');

    // 1. Service Worker 등록
    this.registerServiceWorker();

    // 2. IndexedDB 및 키 저장소 초기화
    await cryptoStore.init();
    this.cachedPublicKeyRaw = cryptoStore.publicKeyRaw;


    // 3. BLE 매니저 콜백 연동 (디버그 패킷 로깅 포함)
    bleManager.setCallbacks({
      onStateChange: (state) => this.handleBLEStateChange(state),
      onMessage: (parsedData, raw) => this.handleIncomingTelemetry(parsedData, raw),
      onTx: (bytes, isPriority) => this.logPacket('TX', bytes, isPriority ? '[PRIORITY COMMAND]' : '[POLLING]'),
      onRx: (rawBytes, parsed) => this.logPacket('RX', rawBytes, parsed)
    });


    // 4. UI 돔 요소 이벤트 바인딩
    this.bindDOMEvents();

    // 5. Wake Lock 및 화면 복귀 리스너 설정
    this.setupWakeLock();

    // 6. 가속도 센서 폴백 초기화
    this.setupMotionFallback();

    // 7. 초기 뷰 결정 및 상태 평가
    this.evaluateViewState();
  }

  /**
   * PWA Service Worker 강제 해제 (v4 캐시 무효화)
   */
  registerServiceWorker() {
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.getRegistrations().then((regs) => {
        for (const reg of regs) {
          reg.unregister();
          console.log('[v4] Unregistered SW:', reg.scope);
        }
      });
    }
  }


  /**
   * Screen Wake Lock API 설정 (iOS 등 미지원 브라우저 안전 처리)
   */
  async requestWakeLock() {
    if (typeof navigator !== 'undefined' && 'wakeLock' in navigator && typeof navigator.wakeLock?.request === 'function' && !this.wakeLockSentinel) {
      try {
        this.wakeLockSentinel = await navigator.wakeLock.request('screen');
        this.wakeLockSentinel?.addEventListener('release', () => {
          this.wakeLockSentinel = null;
        });
        console.log('[App] Screen Wake Lock acquired.');
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
        console.log('[App] Screen Wake Lock released.');
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

  /**
   * 햅틱 피드백 헬퍼 (iOS 등 미지원 환경 방어)
   */
  triggerHaptic(duration = 80) {
    if (typeof navigator !== 'undefined' && typeof navigator.vibrate === 'function') {
      try {
        navigator.vibrate(duration);
      } catch (_) {}
    }
  }


  /**
   * 상태 머신 뷰 전환 평가 (Core State Machine)
   */
  evaluateViewState() {
    // 1. 키 미생성 또는 미등록 상태 -> [뷰 1: 온보딩 위저드]
    if (!cryptoStore.keyPair || !cryptoStore.isRegistered) {
      this.switchView('wizard');
      this.updateWizardStep();
      return;
    }

    // 2. 키 등록 완료되었으나 BLE 미연결 -> [뷰 2: 미연결 대기 화면]
    if (bleManager.connectionState === 'disconnected') {
      this.switchView('disconnected');
      return;
    }

    // 3. BLE 연결됨 + 충전 중 -> [뷰 3: 충전 화면] (임시 바이패스 토글 제외)
    const isCharging = (this.telemetry.charging_state === 'Charging' || this.telemetry.charging_state === 'Starting');
    if (bleManager.connectionState === 'connected' && isCharging && !this.isTempChargingBypass) {
      this.switchView('charging');
      return;
    }

    // 4. BLE 연결됨 + 일반 주행/대기 -> [뷰 4: 일반/주행 화면]
    this.switchView('main');
  }

  /**
   * 화면 뷰 섹션 DOM 활성화 교체
   */
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
   * 상단 Sticky Header 연결 인디케이터 및 뱃지 업데이트
   */
  handleBLEStateChange(state) {
    const indicator = document.getElementById('connection-indicator');

    if (state === 'connected') {
      indicator.innerHTML = '<span class="status-dot">🟢</span><span>차량 연결됨</span>';
      this.requestWakeLock();
      this.startTelemetryPolling();
    } else if (state === 'connecting') {
      indicator.innerHTML = '<span class="status-dot">🟡</span><span>보안 세션 연결 중...</span>';
      this.stopTelemetryPolling();
    } else {
      indicator.innerHTML = '<span class="status-dot">🔴</span><span>차량 연결 끊김</span>';
      this.releaseWakeLock();
      this.stopTelemetryPolling();
    }

    this.evaluateViewState();
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

  /**
   * 온보딩 마법사 단계 관리
   */
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
      setTimeout(() => this.updateWizardStep(), 500);

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
   * 주기적 텔레메트리 폴링 루프 (250ms ~ 500ms)
   */
  startTelemetryPolling() {
    if (this.pollingTimer) return;
    this.pollingTimer = setInterval(async () => {
      if (bleManager.connectionState === 'connected') {
        try {
          const req = buildStatusRequest();
          await bleManager.sendPacket(req, false);
        } catch (e) {
          // 일시적 오류 무시
        }
      }
    }, 450);
  }

  stopTelemetryPolling() {
    if (this.pollingTimer) {
      clearInterval(this.pollingTimer);
      this.pollingTimer = null;
    }
  }

  /**
   * 수신된 텔레메트리 데이터 처리 및 렌더링
   */
  handleIncomingTelemetry(data) {
    if (!data) return;

    // 1. 화이트리스트 승인 상태 확인
    if (data.whitelistOperationStatus === 'OK') {
      console.log('[App] Whitelist AddKey OK confirmed!');
      cryptoStore.setRegistered(true);
      this.evaluateViewState();
    }

    // 2. 차량에서 보고된 세션 카운터 동기화 (Session Handshake Sync)
    if (data.reportedCounter !== null && typeof data.reportedCounter === 'number') {
      cryptoStore.syncCounter(data.reportedCounter);
    }

    // 3. 텔레메트리 캐시 갱신
    Object.assign(this.telemetry, data);

    // 4. 급감속 감지 알고리즘 실행
    this.detectRapidDeceleration(data.speed);

    // 5. UI 렌더링 갱신
    this.renderTelemetryUI();
    this.updateHeaderBadges();

    // 6. 충전 상태 변화에 따른 뷰 전환 재평가
    const isCharging = (this.telemetry.charging_state === 'Charging' || this.telemetry.charging_state === 'Starting');
    if (isCharging && this.currentView === 'main' && !this.isTempChargingBypass) {
      this.evaluateViewState();
    } else if (!isCharging && this.currentView === 'charging') {
      this.isTempChargingBypass = false;
      this.evaluateViewState();
    }
  }

  /**
   * 급감속 감지 로직:
   * 40km/h 이상 주행 중 0.5초 내 15km/h 이상 급감속 감지 시 긴급 비상등 자동 송출 (8초 쿨다운)
   */
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
            console.warn('[App] 🚨 Inertial Rapid Deceleration detected via accelerometer!');
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
      // 세션 서명이 적용된 패킷 생성
      const pkt = await buildFlashLightsAction(cryptoStore);
      await bleManager.sendPacket(pkt, true); // 최우선 큐 전송
      console.log('[App] Auto hazard flash command sent with session signature.');
    } catch (err) {
      console.error('[App] Failed to send auto hazard packet:', err);
    }
  }

  /**
   * 텔레메트리 UI 반영 렌더링
   */
  renderTelemetryUI() {
    const t = this.telemetry;

    // 1. [클러스터 카드] 속도 및 기어
    const speedEl = document.getElementById('cluster-speed-val');
    if (speedEl) speedEl.textContent = Math.round(t.speed);

    const gearItems = document.querySelectorAll('.gear-item');
    gearItems.forEach((el) => {
      el.classList.toggle('active', el.getAttribute('data-gear') === t.gear);
    });

    // 파워 게이지 바
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

    // 2. [도어 상태 카드]
    const doors = t.doors || {};
    const pillDF = document.getElementById('door-pill-df');
    const pillPF = document.getElementById('door-pill-pf');
    const pillDR = document.getElementById('door-pill-dr');
    const pillPR = document.getElementById('door-pill-pr');
    const pillFT = document.getElementById('door-pill-ft');
    const pillRT = document.getElementById('door-pill-rt');

    if (pillDF) pillDF.className = `door-status-pill ${doors.df ? 'open' : ''}`;
    if (pillPF) pillPF.className = `door-status-pill ${doors.pf ? 'open' : ''}`;
    if (pillDR) pillDR.className = `door-status-pill ${doors.dr ? 'open' : ''}`;
    if (pillPR) pillPR.className = `door-status-pill ${doors.pr ? 'open' : ''}`;
    if (pillFT) pillFT.className = `door-status-pill ${doors.ft ? 'open' : ''}`;
    if (pillRT) pillRT.className = `door-status-pill ${doors.rt ? 'open' : ''}`;

    const hasAnyDoorOpen = Object.values(doors).some(Boolean);
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

    // 3. [TPMS 카드]
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

    // 4. [환경 및 배터리 카드]
    const tempIn = document.getElementById('temp-in');
    const tempOut = document.getElementById('temp-out');
    const batPct = document.getElementById('cluster-battery-pct');
    const batRange = document.getElementById('cluster-range-km');
    if (tempIn) tempIn.textContent = t.inside_temp;
    if (tempOut) tempOut.textContent = t.outside_temp;
    if (batPct) batPct.textContent = `${t.battery_level}%`;
    if (batRange) batRange.textContent = `${t.ideal_battery_range_km || Math.round(t.battery_level * 4.2)} km`;

    // 5. [충전 화면]
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

    if (chargePower) chargePower.textContent = `${t.charger_power.toFixed(1)} kW`;
    if (chargeVA) chargeVA.textContent = `${t.charger_voltage} V / ${t.charger_actual_current} A`;
    if (chargeRange) chargeRange.textContent = `${t.ideal_battery_range_km || Math.round(t.battery_level * 4.2)} km`;
    if (chargeTemp) chargeTemp.textContent = `${t.inside_temp} °C`;

    this.updateDoorSafetyLocks();
  }

  /**
   * 도어 안전 잠금 처리
   */
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

  /**
   * UI DOM 이벤트 바인딩
   */
  bindDOMEvents() {
    // 1. 위저드 관련 이벤트
    document.getElementById('btn-create-key')?.addEventListener('click', async () => {
      this.triggerHaptic(40);
      await cryptoStore.generateKeyPair();
      this.updateWizardStep();
    });

    document.getElementById('btn-request-pairing')?.addEventListener('click', async () => {
      // [v4 핵심] iOS Bluefy User Gesture 보존: 그 어떤 await도 없이 첫 줄에서 바로 connect() 호출!
      try {
        await bleManager.connect();
        this.triggerHaptic(60);

        // 연결 완료 후 캐시된 공개키로 AddKeyRequest 전송
        const pubKey = this.cachedPublicKeyRaw || cryptoStore.publicKeyRaw;
        const addKeyPacket = buildAddKeyRequest(pubKey);
        await bleManager.sendPacket(addKeyPacket, true);
        this.updateWizardStep();
      } catch (err) {
        console.error('[App] Pairing error:', err);
        alert('BLE 스캔/연결 실패 [v4]: ' + formatError(err));
      }
    });

    document.getElementById('btn-confirm-registration')?.addEventListener('click', async () => {
      this.triggerHaptic(60);
      await cryptoStore.setRegistered(true);
      this.evaluateViewState();
    });

    // 1-1. 키 초기화 커스텀 모달 바인딩 (Bluefy 기본 confirm 버그 방지)
    const resetModal = document.getElementById('reset-confirm-modal');
    document.getElementById('btn-reset-key')?.addEventListener('click', () => {
      this.triggerHaptic(40);
      resetModal?.classList.add('active');
    });

    document.getElementById('btn-modal-cancel-reset')?.addEventListener('click', () => {
      this.triggerHaptic(30);
      resetModal?.classList.remove('active');
    });

    document.getElementById('btn-modal-confirm-reset')?.addEventListener('click', async () => {
      this.triggerHaptic(60);
      resetModal?.classList.remove('active');
      await cryptoStore.clearAll();
      bleManager.disconnect();
      this.evaluateViewState();
    });


    // 2. 미연결 화면 [차량 블루투스 연결하기] 대형 버튼
    document.getElementById('btn-hero-connect')?.addEventListener('click', async () => {
      // [v4 핵심] iOS Bluefy User Gesture 보존: 첫 줄에서 바로 connect() 호출!
      try {
        await bleManager.connect();
        this.triggerHaptic(80);
      } catch (err) {
        console.error('[App] Hero connect error:', err);
        alert('BLE 스캔/연결 실패 [v4]: ' + formatError(err));
      }
    });


    // 3. 충전 전용 화면 이벤트
    document.getElementById('btn-stop-charge')?.addEventListener('click', async () => {
      this.triggerHaptic(100);
      try {
        const stopPkt = await buildStopChargeAction(cryptoStore);
        await bleManager.sendPacket(stopPkt, true);
        await new Promise(r => setTimeout(r, 300));
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

    // 4. 하단 탭 바 전환
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

    // 5. 제어 탭 옵션
    document.getElementById('switch-auto-hazard')?.addEventListener('change', (e) => {
      this.triggerHaptic(30);
      this.autoHazardEnabled = e.target.checked;
    });

    document.getElementById('chk-force-unlock')?.addEventListener('change', () => {
      this.triggerHaptic(40);
      this.updateDoorSafetyLocks();
    });

    // 6. 제어 탭: 비상등 점멸 (땡큐 비상등 - 서명 적용)
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
      }
    });

    // 7. 제어 탭: 4개 도어 래치 물리 개방 (Unlatch - 서명 적용)
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
        }
      });
    });

    // 8. 실시간 BLE 패킷 디버그 로그 시트 이벤트
    const debugBtn = document.getElementById('btn-toggle-debug');
    const debugSheet = document.getElementById('debug-log-sheet');
    const closeDebugBtn = document.getElementById('btn-close-debug-sheet');
    const copyDebugBtn = document.getElementById('btn-copy-debug-logs');
    const clearDebugBtn = document.getElementById('btn-clear-debug-logs');

    debugBtn?.addEventListener('click', () => {
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

    // 9. 5초 롱프레스 데모 모드
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
