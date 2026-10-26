/**
 * crypto-store.js
 * Tesla vehicle-command 및 yoziru/tesla-ble 공식 암호화 규격 구현 [v13]:
 * - Web Crypto API ECDH P-256 키 쌍 생성 및 JWK/IndexedDB 영구 저장
 * - KeyId 계산: SHA-1(uncompressed_public_key_65B)[0..3]
 * - 세션 공유키 유도: K = SHA-1(ECDH_P256(client_priv, vehicle_pub))[0..15] (128-bit AES 키)
 * - 요청 암호화: AES-128-GCM (12B nonce, 16B tag, SHA-256(TLV Request Metadata) AAD)
 * - 응답 복호화: AES-128-GCM (AES_GCM_Response_Signature_Data, SHA-256(TLV Response Metadata) AAD)
 * - 도메인별(VCSEC=2, INFOTAINMENT=3) 독립 세션 및 화이트리스트 상태 관리
 */

const DB_NAME = 'TeslaBLEKeyDB';
const DB_VERSION = 1;
const STORE_NAME = 'KeyStore';

// Signatures.Tag (signatures.proto)
const TAG_SIGNATURE_TYPE = 0x00;
const TAG_DOMAIN = 0x01;
const TAG_PERSONALIZATION = 0x02;
const TAG_EPOCH = 0x03;
const TAG_EXPIRES_AT = 0x04;
const TAG_COUNTER = 0x05;
const TAG_CHALLENGE = 0x06;
const TAG_FLAGS = 0x07;
const TAG_REQUEST_HASH = 0x08;
const TAG_FAULT = 0x09;
const TAG_END = 0xff;

// Signatures.SignatureType (signatures.proto)
export const SIG_TYPE_AES_GCM = 0;
export const SIG_TYPE_AES_GCM_PERSONALIZED = 5;
export const SIG_TYPE_HMAC = 6;
export const SIG_TYPE_HMAC_PERSONALIZED = 8;
export const SIG_TYPE_AES_GCM_RESPONSE = 9;

// UniversalMessage.Flags (universal_message.proto)
export const FLAG_USER_COMMAND = 0;
export const FLAG_ENCRYPT_RESPONSE = 1;
export const DEFAULT_REQUEST_FLAGS = (1 << FLAG_ENCRYPT_RESPONSE); // 2

class CryptoStore {
  constructor() {
    this.db = null;
    this.keyPair = null;
    this.publicKeyRaw = null; // 65-byte uncompressed point (0x04 + X32 + Y32)
    this.keyId = null;        // 4-byte Key Identifier (SHA-1 prefix)
    this.isRegistered = false;
    this.vin = '';            // 17-character VIN (TLV TAG_PERSONALIZATION 용)
    this.sessionCounter = 0;
    this.keyConfirmedOnVehicle = null; // null: 확인전, true: 차량 화이트리스트 확인됨, false: 미등록 확인됨

    // 클라이언트 라우팅 주소 (16바이트 랜덤 고정값)
    this.routingAddress = new Uint8Array(16);
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      crypto.getRandomValues(this.routingAddress);
    }

    // 도메인별 세션 상태: 2 (DOMAIN_VEHICLE_SECURITY), 3 (DOMAIN_INFOTAINMENT)
    this.sessions = {
      2: this.createEmptySession(2),
      3: this.createEmptySession(3)
    };
  }

  createEmptySession(domain) {
    return {
      domain,
      ready: false,
      status: 0,             // 0: OK, 1: KEY_NOT_ON_WHITELIST
      counter: 0,
      epoch: null,           // Uint8Array(16)
      publicKey: null,       // Uint8Array(65)
      clockTime: 0,          // uint32 seconds
      syncedAtMs: 0,         // timestamp when clockTime was synced
      sharedSecretSha1: null,// Uint8Array(16) AES-128 key raw bytes
      aesKey: null,          // CryptoKey (AES-GCM 128-bit)
      useEncryptResponse: true,
      lastRequestHash: null, // Uint8Array(17): [0x05, ...16B GCM tag]
      requestHashesByUuid: new Map() // uuidHex -> Uint8Array(17)
    };
  }

  /**
   * IndexedDB 및 저장소 초기화
   */
  async init() {
    await this.requestPersistentStorage();
    await this.openDB();
    await this.loadStoredKey();
  }

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
   * 입력된 17자리 VIN이 연결된 차량 비콘 이름(S<16hex>C 또는 Tesla <6자리>)과 일치하는지 검증
   */
  async verifyVinWithDeviceName(vinStr, deviceName) {
    const cleanVin = (vinStr || '').trim().toUpperCase();
    if (cleanVin.length !== 17) {
      return { validLength: false, matched: false, computedBeacon: '', reason: '17자리가 아닙니다.' };
    }

    const vinBytes = new TextEncoder().encode(cleanVin);
    const hashBuf = await window.crypto.subtle.digest('SHA-1', vinBytes);
    const hashBytes = new Uint8Array(hashBuf);
    let hex8 = '';
    for (let i = 0; i < 8; i++) {
      hex8 += hashBytes[i].toString(16).padStart(2, '0');
    }
    const computedBeacon = `S${hex8}C`;

    if (!deviceName || typeof deviceName !== 'string') {
      return { validLength: true, matched: null, computedBeacon };
    }

    const sMatch = deviceName.match(/^S([0-9a-fA-F]{16})[CRDP]?$/);
    if (sMatch) {
      const deviceHex = sMatch[1].toLowerCase();
      return {
        validLength: true,
        matched: deviceHex === hex8.toLowerCase(),
        computedBeacon,
        deviceBeacon: deviceName
      };
    }

    const tMatch = deviceName.match(/^Tesla\s+([A-HJ-NPR-Z0-9]{6})$/i);
    if (tMatch) {
      const last6 = tMatch[1].toUpperCase();
      return {
        validLength: true,
        matched: cleanVin.slice(-6) === last6,
        computedBeacon,
        deviceBeacon: deviceName
      };
    }

    return { validLength: true, matched: null, computedBeacon, deviceBeacon: deviceName };
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
        try {
          const record = req.result;
          if (!record) {
            this.keyPair = null;
            this.publicKeyRaw = null;
            this.keyId = null;
            this.isRegistered = false;
            this.sessionCounter = 0;
            return resolve(false);
          }

          const subtle = window.crypto?.subtle;
          let pubKey = null;
          let privKey = null;

          if (record.publicKeyJwk && record.privateKeyJwk && subtle) {
            const cleanPubJwk = { ...record.publicKeyJwk };
            delete cleanPubJwk.key_ops;
            delete cleanPubJwk.alg;

            const cleanPrivJwk = { ...record.privateKeyJwk };
            delete cleanPrivJwk.key_ops;
            delete cleanPrivJwk.alg;

            pubKey = await subtle.importKey(
              'jwk',
              cleanPubJwk,
              { name: 'ECDH', namedCurve: 'P-256' },
              true,
              []
            );
            privKey = await subtle.importKey(
              'jwk',
              cleanPrivJwk,
              { name: 'ECDH', namedCurve: 'P-256' },
              true,
              ['deriveKey', 'deriveBits']
            );
          } else if (record.publicKey instanceof CryptoKey && record.privateKey instanceof CryptoKey) {
            pubKey = record.publicKey;
            privKey = record.privateKey;
          }

          if (pubKey && privKey) {
            this.keyPair = { publicKey: pubKey, privateKey: privKey };
            if (record.publicKeyRaw) {
              this.publicKeyRaw = new Uint8Array(record.publicKeyRaw);
            } else {
              const rawBuf = await subtle.exportKey('raw', pubKey);
              this.publicKeyRaw = new Uint8Array(rawBuf);
            }
            this.isRegistered = !!record.isRegistered;
            this.sessionCounter = record.sessionCounter || 0;
            this.vin = record.vin || '';

            if (this.publicKeyRaw) {
              this.keyId = await this.computeKeyId(this.publicKeyRaw);
            }

            console.log('[CryptoStore] ECDH P-256 key loaded. Registered:', this.isRegistered, 'VIN:', this.vin || '(none)');
            resolve(true);
          } else {
            resolve(false);
          }
        } catch (loadErr) {
          console.warn('[CryptoStore] Key parsing error, resetting key:', loadErr);
          resolve(false);
        }
      };

      req.onerror = () => reject(req.error);
    });
  }

  /**
   * ECDH P-256 키 쌍 생성 및 65바이트 Uncompressed Public Key (0x04...) 추출
   */
  async generateKeyPair() {
    const subtle = window.crypto?.subtle;
    if (!subtle) {
      throw new Error('이 브라우저는 Web Crypto API를 지원하지 않습니다.');
    }

    const keyPair = await subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-256'
      },
      true,
      ['deriveKey', 'deriveBits']
    );

    const rawPublicKeyBuffer = await subtle.exportKey('raw', keyPair.publicKey);
    const publicKeyRaw = new Uint8Array(rawPublicKeyBuffer);
    const keyId = await this.computeKeyId(publicKeyRaw);

    const publicKeyJwk = await subtle.exportKey('jwk', keyPair.publicKey);
    const privateKeyJwk = await subtle.exportKey('jwk', keyPair.privateKey);

    this.keyPair = keyPair;
    this.publicKeyRaw = publicKeyRaw;
    this.keyId = keyId;
    this.isRegistered = false;
    this.keyConfirmedOnVehicle = null;
    this.sessionCounter = 1;
    this.resetSessions();

    const record = {
      id: 'primary_key',
      publicKeyRaw: Array.from(publicKeyRaw),
      publicKeyJwk,
      privateKeyJwk,
      keyId: Array.from(keyId),
      isRegistered: false,
      vin: this.vin || '',
      createdAt: Date.now(),
      sessionCounter: 1
    };

    try {
      await this.saveRecord({
        ...record,
        publicKey: keyPair.publicKey,
        privateKey: keyPair.privateKey
      });
    } catch (saveErr) {
      await this.saveRecord(record);
    }

    console.log('[CryptoStore] Generated new ECDH P-256 key pair, raw length:', publicKeyRaw.length);
    return { keyPair, publicKeyRaw, keyId };
  }

  /**
   * 차량 VIN(17자리) 저장
   */
  async setVin(vinStr) {
    const clean = (vinStr || '').trim().toUpperCase();
    this.vin = clean;
    await this.updateRecordField('vin', clean);
  }

  /**
   * 모든 도메인 세션 초기화 (연결 해제 시)
   */
  resetSessions() {
    this.sessions[2] = this.createEmptySession(2);
    this.sessions[3] = this.createEmptySession(3);
    this.keyConfirmedOnVehicle = null;
  }

  hasValidSession(domain) {
    const s = this.sessions[domain];
    return !!(s && s.ready && s.status === 0 && s.aesKey && s.epoch);
  }

  /**
   * 차량의 WhitelistInfo(4바이트 KeyId 배열)에 현재 앱의 keyId가 존재하는지 확인
   */
  checkWhitelistEntries(keyIdList) {
    if (!this.keyId || !Array.isArray(keyIdList)) return false;
    for (const entry of keyIdList) {
      if (entry && entry.length === 4) {
        if (
          entry[0] === this.keyId[0] &&
          entry[1] === this.keyId[1] &&
          entry[2] === this.keyId[2] &&
          entry[3] === this.keyId[3]
        ) {
          this.keyConfirmedOnVehicle = true;
          return true;
        }
      }
    }
    if (keyIdList.length > 0) {
      this.keyConfirmedOnVehicle = false;
    }
    return false;
  }

  /**
   * 차량으로부터 수신한 SessionInfo(publicKey, epoch, clock_time, counter, status)로
   * ECDH 공유 비밀키 유도 및 AES-128-GCM 세션 키 설정
   */
  async updateSessionInfo(domain, sessionInfo) {
    if (!this.keyPair || !this.keyPair.privateKey) {
      throw new Error('클라이언트 개인키가 초기화되지 않았습니다.');
    }

    const session = this.sessions[domain] || this.createEmptySession(domain);
    const subtle = window.crypto.subtle;

    session.status = typeof sessionInfo.status === 'number' ? sessionInfo.status : 0;

    // status === 1 (SESSION_INFO_STATUS_KEY_NOT_ON_WHITELIST)
    if (session.status === 1) {
      session.ready = false;
      this.keyConfirmedOnVehicle = false;
      this.sessions[domain] = session;
      console.warn(`[CryptoStore] Domain ${domain} reported KEY_NOT_ON_WHITELIST (status=1)`);
      return session;
    }

    if (sessionInfo.publicKey && sessionInfo.publicKey.length >= 64) {
      let pubBytes = sessionInfo.publicKey;
      if (pubBytes.length === 64) {
        const prefixed = new Uint8Array(65);
        prefixed[0] = 0x04;
        prefixed.set(pubBytes, 1);
        pubBytes = prefixed;
      }

      if (pubBytes.length === 65 && pubBytes[0] === 0x04) {
        const vehiclePubKey = await subtle.importKey(
          'raw',
          pubBytes,
          { name: 'ECDH', namedCurve: 'P-256' },
          false,
          []
        );

        const sharedBits = await subtle.deriveBits(
          { name: 'ECDH', public: vehiclePubKey },
          this.keyPair.privateKey,
          256
        );

        const sha1Hash = await subtle.digest('SHA-1', sharedBits);
        const aesKeyBytes = new Uint8Array(sha1Hash).slice(0, 16);

        const aesKey = await subtle.importKey(
          'raw',
          aesKeyBytes,
          { name: 'AES-GCM' },
          false,
          ['encrypt', 'decrypt']
        );

        session.publicKey = pubBytes;
        session.sharedSecretSha1 = aesKeyBytes;
        session.aesKey = aesKey;
      }
    }

    if (sessionInfo.epoch && sessionInfo.epoch.length > 0) {
      session.epoch = new Uint8Array(sessionInfo.epoch);
    }

    if (typeof sessionInfo.clockTime === 'number' && sessionInfo.clockTime > 0) {
      session.clockTime = sessionInfo.clockTime;
      session.syncedAtMs = Date.now();
    }

    if (typeof sessionInfo.counter === 'number') {
      session.counter = Math.max(session.counter, sessionInfo.counter);
      this.sessionCounter = Math.max(this.sessionCounter, session.counter);
      await this.updateRecordField('sessionCounter', this.sessionCounter);
    }

    session.ready = !!(session.status === 0 && session.aesKey && session.epoch && session.epoch.length > 0);
    if (session.ready) {
      this.keyConfirmedOnVehicle = true;
    }
    this.sessions[domain] = session;

    console.log(
      `[CryptoStore] Session updated for domain ${domain}: ready=${session.ready}, status=${session.status}, counter=${session.counter}, clock=${session.clockTime}`
    );
    return session;
  }

  /**
   * 요청용 TLV 메타데이터 버퍼(AD Buffer) 생성 및 SHA-256 해시 반환 (peer.go extractMetadata 동일 규격)
   */
  async computeMetadataHash(domain, expiresAt, counter, flags = 0) {
    const session = this.sessions[domain];
    const parts = [];

    const appendTlv = (tag, valueBytes) => {
      const len = valueBytes ? valueBytes.length : 0;
      const entry = new Uint8Array(2 + len);
      entry[0] = tag & 0xff;
      entry[1] = len & 0xff;
      if (len > 0) {
        entry.set(valueBytes, 2);
      }
      parts.push(entry);
    };

    const writeUint32BE = (val) => {
      const buf = new Uint8Array(4);
      new DataView(buf.buffer).setUint32(0, val >>> 0, false);
      return buf;
    };

    // 1. TAG_SIGNATURE_TYPE (0x00) = SIGNATURE_TYPE_AES_GCM_PERSONALIZED (5)
    appendTlv(TAG_SIGNATURE_TYPE, new Uint8Array([SIG_TYPE_AES_GCM_PERSONALIZED]));

    // 2. TAG_DOMAIN (0x01) = domain (2 or 3)
    appendTlv(TAG_DOMAIN, new Uint8Array([domain & 0xff]));

    // 3. TAG_PERSONALIZATION (0x02) = VIN (17 bytes ASCII)
    const vinBytes = new TextEncoder().encode((this.vin || '').slice(0, 17));
    appendTlv(TAG_PERSONALIZATION, vinBytes);

    // 4. TAG_EPOCH (0x03) = 16-byte session epoch
    appendTlv(TAG_EPOCH, session.epoch || new Uint8Array(16));

    // 5. TAG_EXPIRES_AT (0x04) = 4-byte Big-Endian expires_at
    appendTlv(TAG_EXPIRES_AT, writeUint32BE(expiresAt));

    // 6. TAG_COUNTER (0x05) = 4-byte Big-Endian counter
    appendTlv(TAG_COUNTER, writeUint32BE(counter));

    // 7. TAG_FLAGS (0x07) - 요청 시에는 flags > 0 일 때만 포함
    if (flags > 0) {
      appendTlv(TAG_FLAGS, writeUint32BE(flags));
    }

    // 8. TAG_END (0xFF)
    parts.push(new Uint8Array([TAG_END]));

    const totalLen = parts.reduce((acc, p) => acc + p.length, 0);
    const adBuffer = new Uint8Array(totalLen);
    let offset = 0;
    for (const p of parts) {
      adBuffer.set(p, offset);
      offset += p.length;
    }

    const hashBuf = await window.crypto.subtle.digest('SHA-256', adBuffer);
    return new Uint8Array(hashBuf);
  }

  /**
   * 응답 복호화용 TLV 메타데이터 버퍼(responseMetadata) 생성 및 SHA-256 해시 반환 (peer.go responseMetadata 동일 규격)
   */
  async computeResponseMetadataHash(domain, counter, flags, requestHashBytes, signedMessageFault = 0) {
    const parts = [];

    const appendTlv = (tag, valueBytes) => {
      const len = valueBytes ? valueBytes.length : 0;
      const entry = new Uint8Array(2 + len);
      entry[0] = tag & 0xff;
      entry[1] = len & 0xff;
      if (len > 0) {
        entry.set(valueBytes, 2);
      }
      parts.push(entry);
    };

    const writeUint32BE = (val) => {
      const buf = new Uint8Array(4);
      new DataView(buf.buffer).setUint32(0, val >>> 0, false);
      return buf;
    };

    // 1. TAG_SIGNATURE_TYPE (0x00) = SIGNATURE_TYPE_AES_GCM_RESPONSE (9)
    appendTlv(TAG_SIGNATURE_TYPE, new Uint8Array([SIG_TYPE_AES_GCM_RESPONSE]));

    // 2. TAG_DOMAIN (0x01) = from_destination.domain (2 or 3)
    appendTlv(TAG_DOMAIN, new Uint8Array([domain & 0xff]));

    // 3. TAG_PERSONALIZATION (0x02) = VIN (17 bytes ASCII)
    const vinBytes = new TextEncoder().encode((this.vin || '').slice(0, 17));
    appendTlv(TAG_PERSONALIZATION, vinBytes);

    // 4. TAG_COUNTER (0x05) = 4-byte Big-Endian response counter
    appendTlv(TAG_COUNTER, writeUint32BE(counter));

    // 5. TAG_FLAGS (0x07) = 4-byte Big-Endian message.Flags (항상 포함)
    appendTlv(TAG_FLAGS, writeUint32BE(flags >>> 0));

    // 6. TAG_REQUEST_HASH (0x08) = 17-byte request_hash (0x05 + 16B request GCM tag)
    appendTlv(TAG_REQUEST_HASH, requestHashBytes || new Uint8Array(17));

    // 7. TAG_FAULT (0x09) = 4-byte Big-Endian signed_message_fault
    appendTlv(TAG_FAULT, writeUint32BE(signedMessageFault >>> 0));

    // 8. TAG_END (0xFF)
    parts.push(new Uint8Array([TAG_END]));

    const totalLen = parts.reduce((acc, p) => acc + p.length, 0);
    const adBuffer = new Uint8Array(totalLen);
    let offset = 0;
    for (const p of parts) {
      adBuffer.set(p, offset);
      offset += p.length;
    }

    const hashBuf = await window.crypto.subtle.digest('SHA-256', adBuffer);
    return new Uint8Array(hashBuf);
  }

  /**
   * 도메인 세션 키로 요청 페이로드 AES-128-GCM 암호화 수행
   */
  async encryptPayload(domain, plaintextBytes, flags = DEFAULT_REQUEST_FLAGS, requestUuidHex = '') {
    const session = this.sessions[domain];
    if (!session || !session.ready || !session.aesKey) {
      throw new Error(`도메인(${domain}) 보안 세션이 아직 수립되지 않았습니다.`);
    }

    session.counter += 1;
    this.sessionCounter = Math.max(this.sessionCounter, session.counter);
    await this.updateRecordField('sessionCounter', this.sessionCounter);

    const counter = session.counter;
    const elapsedSec = session.syncedAtMs > 0 ? Math.floor((Date.now() - session.syncedAtMs) / 1000) : 0;
    // 만료 시간: 차량 시계 기준 +15초 여유
    const expiresAt = (session.clockTime + Math.max(0, elapsedSec) + 15) >>> 0;

    // AAD = SHA-256(TLV Metadata)
    const aadHash = await this.computeMetadataHash(domain, expiresAt, counter, flags);

    // 12바이트 랜덤 Nonce(IV) 생성
    const nonce = new Uint8Array(12);
    window.crypto.getRandomValues(nonce);

    // Web Crypto AES-128-GCM 암호화
    const encryptedBuffer = await window.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: nonce,
        additionalData: aadHash,
        tagLength: 128
      },
      session.aesKey,
      plaintextBytes
    );

    const encryptedBytes = new Uint8Array(encryptedBuffer);
    const ciphertext = encryptedBytes.slice(0, encryptedBytes.length - 16);
    const tag = encryptedBytes.slice(encryptedBytes.length - 16);

    // 응답 복호화 시 필요한 17바이트 RequestHash = [0x05, ...16B tag] 저장 (peer.go RequestID 동일 규격)
    const reqHash = new Uint8Array(17);
    reqHash[0] = SIG_TYPE_AES_GCM_PERSONALIZED;
    reqHash.set(tag, 1);
    session.lastRequestHash = reqHash;

    if (requestUuidHex) {
      session.requestHashesByUuid.set(requestUuidHex, reqHash);
      if (session.requestHashesByUuid.size > 24) {
        const oldestKey = session.requestHashesByUuid.keys().next().value;
        session.requestHashesByUuid.delete(oldestKey);
      }
    }

    return {
      ciphertext,
      nonce,
      counter,
      expiresAt,
      epoch: session.epoch,
      tag,
      flags
    };
  }

  /**
   * 차량이 보낸 암호화 응답(AES_GCM_Response_Signature_Data)을 복호화하여 평문 Protobuf 바이트 반환
   */
  async decryptResponsePayload(
    domain,
    ciphertextBytes,
    aesGcmResponseData,
    responseFlags = 0,
    signedMessageFault = 0,
    requestUuidHex = ''
  ) {
    const session = this.sessions[domain] || this.sessions[3] || this.sessions[2];
    if (!session || !session.aesKey) {
      throw new Error(`도메인(${domain}) 복호화 세션 키가 없습니다.`);
    }

    const { nonce, counter, tag } = aesGcmResponseData;
    if (!nonce || !tag || !ciphertextBytes) {
      throw new Error('암호화된 응답의 Nonce 또는 Tag가 누락되었습니다.');
    }

    // request_uuid에 매칭되는 requestHash 우선 조회, 없으면 마지막 전송 requestHash 사용
    let reqHash = null;
    if (requestUuidHex && session.requestHashesByUuid.has(requestUuidHex)) {
      reqHash = session.requestHashesByUuid.get(requestUuidHex);
    } else {
      reqHash = session.lastRequestHash;
    }

    const aadHash = await this.computeResponseMetadataHash(
      domain,
      counter || 0,
      responseFlags || 0,
      reqHash,
      signedMessageFault || 0
    );

    const combined = new Uint8Array(ciphertextBytes.length + tag.length);
    combined.set(ciphertextBytes, 0);
    combined.set(tag, ciphertextBytes.length);

    const decryptedBuffer = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: nonce,
        additionalData: aadHash,
        tagLength: 128
      },
      session.aesKey,
      combined
    );

    return new Uint8Array(decryptedBuffer);
  }

  /**
   * 화이트리스트 등록 완료 상태 플래그 갱신
   */
  async setRegistered(isRegistered, vehicleMeta = {}) {
    this.isRegistered = isRegistered;
    return new Promise((resolve, reject) => {
      if (!this.db) return resolve(true);
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

  async getNextCounter() {
    this.sessionCounter += 1;
    await this.updateRecordField('sessionCounter', this.sessionCounter);
    return this.sessionCounter;
  }

  async syncCounter(vehicleReportedCounter) {
    this.sessionCounter = Math.max(this.sessionCounter, vehicleReportedCounter);
    if (this.sessions[2]) {
      this.sessions[2].counter = Math.max(this.sessions[2].counter, vehicleReportedCounter);
    }
    await this.updateRecordField('sessionCounter', this.sessionCounter);
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
        this.keyConfirmedOnVehicle = null;
        this.sessionCounter = 0;
        this.resetSessions();
        console.log('[CryptoStore] All keys and registration data cleared.');
        resolve(true);
      };

      req.onerror = () => reject(req.error);
    });
  }
}

export const cryptoStore = new CryptoStore();
