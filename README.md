# CT-Control

Android Chrome 전용 Tesla BLE 가상키 컨트롤러 및 서브 클러스터 PWA (Static Web)

## 📌 주요 특징
- **No Bundler, No Node.js Backend**: 순수 Vanilla JS (ES6 Modules) + HTML5 + CSS3 정적 호스팅 (GitHub Pages 호환)
- **Web Bluetooth GATT**: 테슬라 VCSEC BLE 규격 (`0x0211`), 2바이트 Big-Endian 길이 헤더 프레이밍 및 청크 분할 송수신
- **자체 내장 Protobuf 코덱**: 외부 무거운 라이브러리 없이 순수 Wire-format 파서 및 인코더 구현
- **Web Crypto API & IndexedDB**: ECDSA P-256 키 쌍 영구 저장 (`TeslaBLEKeyDB`), `navigator.storage.persist()`
- **급감속 비상등 자동 점멸**: 주행 중 0.5초 내 15km/h 이상 급감속 감지 시 최우선(Priority) 큐로 땡큐 비상등 자동 송출
- **Screen Wake Lock & PWA**: 주행 중 화면 꺼짐 방지 및 오프라인 지하 주차장 완벽 구동
- **시뮬레이션 모드**: 상단 헤더 로고를 5초간 길게 누르면 차량 미연결 상태에서도 주행/급감속/충전 모드 테스트 가능

## 📁 디렉터리 구조
```text
CT-Control/
├── index.html          # 메인 엔트리 및 상태 머신 뷰 컨테이너
├── style.css           # Tesla UI 스타일 다크 테마
├── manifest.json       # PWA Standalone 설정
├── sw.js               # Cache-First 오프라인 Service Worker
└── js/
    ├── app.js          # 메인 상태 머신, UI 바인딩, WakeLock, 급감속 감지
    ├── crypto-store.js # ECDSA P-256 키 생성, Uncompressed Point, IndexedDB
    ├── ble-manager.js  # Web Bluetooth 통신, 2바이트 길이 프레이밍, 우선순위 큐
    └── proto-codec.js  # 경량 Protobuf 인코더/디코더 (VCSEC & CarServer)
```
