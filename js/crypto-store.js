/**
 * crypto-store.js
 * Web Crypto API (ECDSA P-256) 키 관리, SHA-1 KeyId 계산,
 * ECDSA P-256 서명 생성 및 IndexedDB 영구 저장소
 */

const DB_NAME = 'TeslaBLEKeyDB';
const DB_VERSION = 1;
const STORE_NAME = 'KeyStore';

class CryptoStore {
  constructor() {
    this.db = null;
    this.keyPair = null;
    this.publicKeyRaw = null; // 65-byte uncompressed point
    this.keyId = null;        // 4-byte Key Identifier (SHA-1 prefix)
    this.isRegistered = false;
    this.sessionCounter = 0;
  }

  /**
   * IndexedDB 및 저장소 초기화
   */
  async init() {
    await this.requestPersistentStorage();
    await this.openDB();
    await this.loadStoredKey();
  }

  /**
   * 안드로이드 크롬 캐시 정리에 의한 키 삭제 방지
   */
  async requestPersistentStorage() {
    if (navigator.storage && navigator.storage.persist) {
      try {
        const isPersisted = await navigator.storage.persist();
        console.log(`[CryptoStore] Persistent storage granted: ${isPersisted}`);
      } catch (e) {
        console.warn('[CryptoStore] Failed to request persistent storage', e);
      }
    }
  }

  /**
   * IndexedDB 연결 생성
   */
  openDB() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, DB_VERSION);

      request.onupgradeneeded = (event) => {
        const db = event.target.result;
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          db.createObjectStore(STORE_NAME, { keyPath: 'id' });
        }
      };

      request.onsuccess = (event) => {
        this.db = event.target.result;
        resolve(this.db);
      };

      request.onerror = (event) => {
        console.error('[CryptoStore] IndexedDB error:', event.target.error);
        reject(event.target.error);
      };
    });
  }

  /**
   * 공개키로부터 테슬라 표준 4바이트 KeyIdentifier (SHA-1 앞 4바이트) 계산
   */
  async computeKeyId(publicKeyBytes) {
    const hashBuffer = await window.crypto.subtle.digest('SHA-1', publicKeyBytes);
    return new Uint8Array(hashBuffer).slice(0, 4);
  }

  /**
   * 저장된 키 쌍 및 등록 상태 로드
   */
  async loadStoredKey() {
    return new Promise((resolve, reject) => {
      if (!this.db) {
        return resolve(false);
      }

      const tx = this.db.transaction(STORE_NAME, 'readonly');
      const store = tx.objectStore(STORE_NAME);
      const req = store.get('primary_key');

      req.onsuccess = async () => {
        const record = req.result;
        if (record && record.publicKey && record.privateKey) {
          this.keyPair = {
            publicKey: record.publicKey,
            privateKey: record.privateKey
          };
          this.publicKeyRaw = record.publicKeyRaw ? new Uint8Array(record.publicKeyRaw) : null;
          this.isRegistered = !!record.isRegistered;
          this.sessionCounter = record.sessionCounter || 0;

          if (this.publicKeyRaw) {
            this.keyId = await this.computeKeyId(this.publicKeyRaw);
          }

          console.log('[CryptoStore] Existing key loaded. Registered:', this.isRegistered, 'Counter:', this.sessionCounter);
          resolve(true);
        } else {
          this.keyPair = null;
          this.publicKeyRaw = null;
          this.keyId = null;
          this.isRegistered = false;
          this.sessionCounter = 0;
          resolve(false);
        }
      };

      req.onerror = () => reject(req.error);
    });
  }

  /**
   * ECDSA P-256 키 쌍 생성 및 65바이트 Uncompressed Public Key 추출
   */
  async generateKeyPair() {
    const subtle = window.crypto.subtle;
    
    // ECDSA P-256 키 쌍 생성 (서명용)
    const keyPair = await subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-256'
      },
      false, // non-extractable private key for security
      ['sign', 'verify']
    );

    // 공개키를 raw (Uncompressed Point format: 0x04 + X 32B + Y 32B = 65B)로 내보내기
    const rawPublicKeyBuffer = await subtle.exportKey('raw', keyPair.publicKey);
    const publicKeyRaw = new Uint8Array(rawPublicKeyBuffer);
    const keyId = await this.computeKeyId(publicKeyRaw);

    this.keyPair = keyPair;
    this.publicKeyRaw = publicKeyRaw;
    this.keyId = keyId;
    this.isRegistered = false;
    this.sessionCounter = 1;

    // IndexedDB에 저장
    await this.saveRecord({
      id: 'primary_key',
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
      publicKeyRaw: Array.from(publicKeyRaw),
      keyId: Array.from(keyId),
      isRegistered: false,
      createdAt: Date.now(),
      sessionCounter: 1
    });

    console.log('[CryptoStore] Generated new ECDSA P-256 key pair, raw length:', publicKeyRaw.length);
    return {
      keyPair,
      publicKeyRaw,
      keyId
    };
  }

  /**
   * ECDSA P-256 서명 생성 (SHA-256, IEEE P1363 64-byte r||s 포맷)
   */
  async signPayload(payloadBytes) {
    if (!this.keyPair || !this.keyPair.privateKey) {
      throw new Error('서명용 개인키가 존재하지 않습니다.');
    }

    const subtle = window.crypto.subtle;
    const signatureBuffer = await subtle.sign(
      {
        name: 'ECDSA',
        hash: { name: 'SHA-256' }
      },
      this.keyPair.privateKey,
      payloadBytes
    );

    // Web Crypto API는 ECDSA P-256 서명 시 64바이트 raw IEEE P1363(r[32] + s[32])을 반환합니다.
    return new Uint8Array(signatureBuffer);
  }

  /**
   * 화이트리스트 등록 완료 상태 플래그 갱신
   */
  async setRegistered(isRegistered, vehicleMeta = {}) {
    this.isRegistered = isRegistered;
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(STORE_NAME, 'readwrite');
      const store = tx.objectStore(STORE_NAME);
      const req = store.get('primary_key');

      req.onsuccess = () => {
        const record = req.result || { id: 'primary_key' };
        record.isRegistered = isRegistered;
        record.vehicleMeta = Object.assign(record.vehicleMeta || {}, vehicleMeta);
        record.registeredAt = Date.now();

        const updateReq = store.put(record);
        updateReq.onsuccess = () => resolve(true);
        updateReq.onerror = () => reject(updateReq.error);
      };

      req.onerror = () => reject(req.error);
    });
  }

  /**
   * 세션 카운터 증가 및 반환 (차량 세션 인증용)
   */
  async getNextCounter() {
    this.sessionCounter += 1;
    await this.updateRecordField('sessionCounter', this.sessionCounter);
    return this.sessionCounter;
  }

  /**
   * 차량 응답에 맞춰 세션 카운터 동기화
   */
  async syncCounter(vehicleReportedCounter) {
    this.sessionCounter = Math.max(this.sessionCounter, vehicleReportedCounter + 1);
    await this.updateRecordField('sessionCounter', this.sessionCounter);
    console.log(`[CryptoStore] Synchronized session counter to: ${this.sessionCounter}`);
    return this.sessionCounter;
  }

  updateRecordField(field, value) {
    return new Promise((resolve, reject) => {
      if (!this.db) return resolve();
      const tx = this.db.transaction(STORE_NAME, 'readwrite');
      const store = tx.objectStore(STORE_NAME);
      const req = store.get('primary_key');

      req.onsuccess = () => {
        const record = req.result;
        if (record) {
          record[field] = value;
          store.put(record);
        }
        resolve();
      };
      req.onerror = () => reject(req.error);
    });
  }

  saveRecord(record) {
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(STORE_NAME, 'readwrite');
      const store = tx.objectStore(STORE_NAME);
      const req = store.put(record);
      req.onsuccess = () => resolve(true);
      req.onerror = () => reject(req.error);
    });
  }

  /**
   * 모든 가상키 및 등록 정보 초기화
   */
  async clearAll() {
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(STORE_NAME, 'readwrite');
      const store = tx.objectStore(STORE_NAME);
      const req = store.clear();

      req.onsuccess = () => {
        this.keyPair = null;
        this.publicKeyRaw = null;
        this.keyId = null;
        this.isRegistered = false;
        this.sessionCounter = 0;
        console.log('[CryptoStore] All keys and registration data cleared.');
        resolve(true);
      };

      req.onerror = () => reject(req.error);
    });
  }
}

export const cryptoStore = new CryptoStore();
