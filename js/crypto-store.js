/**
 * crypto-store.js
 * Web Crypto API (ECDSA P-256) 키 관리 및 IndexedDB 영구 저장소
 */

const DB_NAME = 'TeslaBLEKeyDB';
const DB_VERSION = 1;
const STORE_NAME = 'KeyStore';

class CryptoStore {
  constructor() {
    this.db = null;
    this.keyPair = null;
    this.publicKeyRaw = null;
    this.isRegistered = false;
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
          console.log('[CryptoStore] Existing key loaded. Registered:', this.isRegistered);
          resolve(true);
        } else {
          this.keyPair = null;
          this.publicKeyRaw = null;
          this.isRegistered = false;
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

    this.keyPair = keyPair;
    this.publicKeyRaw = publicKeyRaw;
    this.isRegistered = false;

    // IndexedDB에 저장
    await this.saveRecord({
      id: 'primary_key',
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
      publicKeyRaw: Array.from(publicKeyRaw),
      isRegistered: false,
      createdAt: Date.now(),
      sessionCounter: 0
    });

    console.log('[CryptoStore] Generated new ECDSA P-256 key pair, raw length:', publicKeyRaw.length);
    return {
      keyPair,
      publicKeyRaw
    };
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
   * 세션 카운터 증가 및 반환
   */
  async getNextCounter() {
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(STORE_NAME, 'readwrite');
      const store = tx.objectStore(STORE_NAME);
      const req = store.get('primary_key');

      req.onsuccess = () => {
        const record = req.result || { id: 'primary_key', sessionCounter: 0 };
        const counter = (record.sessionCounter || 0) + 1;
        record.sessionCounter = counter;
        store.put(record);
        resolve(counter);
      };

      req.onerror = () => reject(req.error);
    });
  }

  /**
   * 저장된 레코드 저장 유틸
   */
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
        this.isRegistered = false;
        console.log('[CryptoStore] All keys and registration data cleared.');
        resolve(true);
      };

      req.onerror = () => reject(req.error);
    });
  }
}

export const cryptoStore = new CryptoStore();
