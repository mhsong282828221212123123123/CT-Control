package com.tesla.ctcontrol;

import android.Manifest;
import android.annotation.SuppressLint;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCallback;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattDescriptor;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothManager;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.le.BluetoothLeScanner;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanRecord;
import android.bluetooth.le.ScanResult;
import android.bluetooth.le.ScanSettings;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.location.LocationManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelUuid;
import android.provider.Settings;
import android.util.SparseArray;
import android.view.WindowManager;
import android.webkit.JavascriptInterface;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import androidx.webkit.WebViewAssetLoader;

import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@SuppressLint({"SetJavaScriptEnabled", "MissingPermission"})
public class MainActivity extends AppCompatActivity {

    private static final int REQ_BLE_PERMISSIONS = 1001;

    private static final UUID TESLA_SERVICE_UUID = UUID.fromString("00000211-b2d1-43f0-9b88-960cebf8b91e");
    private static final UUID TESLA_TX_CHAR_UUID = UUID.fromString("00000212-b2d1-43f0-9b88-960cebf8b91e");
    private static final UUID TESLA_RX_CHAR_UUID = UUID.fromString("00000213-b2d1-43f0-9b88-960cebf8b91e");
    private static final UUID CCCD_UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb");

    // Tesla VCSEC 고정 Apple iBeacon Proximity UUID: 74278bda-b644-4520-8f0c-720eaf059935
    private static final byte[] TESLA_IBEACON_UUID = new byte[]{
        (byte) 0x74, (byte) 0x27, (byte) 0x8b, (byte) 0xda,
        (byte) 0xb6, (byte) 0x44, (byte) 0x45, (byte) 0x20,
        (byte) 0x8f, (byte) 0x0c, (byte) 0x72, (byte) 0x0e,
        (byte) 0xaf, (byte) 0x05, (byte) 0x99, (byte) 0x35
    };

    private WebView webView;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    private BluetoothAdapter bluetoothAdapter;
    private BluetoothLeScanner bleScanner;
    private BluetoothGatt activeGatt;
    private BluetoothGattCharacteristic txCharacteristic;
    private BluetoothGattCharacteristic rxCharacteristic;

    private boolean isScanning = false;
    private String pendingScanMode = null;
    private String currentTargetAddress = null;
    private int connectAttempt = 0;
    private boolean isChannelReady = false;

    // 스캔 중 발견된 디바이스 및 병합 메타데이터 (ADV_IND + SCAN_RSP 통합용)
    private final ConcurrentHashMap<String, BluetoothDevice> discoveredDevices = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> mergedNames = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Boolean> mergedTeslaIBeacon = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Boolean> mergedTeslaService = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> mergedBeaconMeta = new ConcurrentHashMap<>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        getWindow().setStatusBarColor(Color.parseColor("#0d0d0d"));
        getWindow().setNavigationBarColor(Color.parseColor("#0d0d0d"));

        BluetoothManager btManager = (BluetoothManager) getSystemService(Context.BLUETOOTH_SERVICE);
        if (btManager != null) {
            bluetoothAdapter = btManager.getAdapter();
        }

        webView = new WebView(this);
        webView.setBackgroundColor(Color.parseColor("#0d0d0d"));
        setContentView(webView);

        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setDatabaseEnabled(true);
        settings.setAllowFileAccess(false);
        settings.setAllowContentAccess(false);
        settings.setCacheMode(WebSettings.LOAD_NO_CACHE);
        settings.setMediaPlaybackRequiresUserGesture(false);

        WebView.setWebContentsDebuggingEnabled(true);

        final WebViewAssetLoader assetLoader = new WebViewAssetLoader.Builder()
            .setDomain("appassets.androidplatform.net")
            .addPathHandler("/assets/", new WebViewAssetLoader.AssetsPathHandler(this))
            .build();

        final long sessionTs = System.currentTimeMillis();
        final String remoteBaseUrl = "https://mhsong282828221212123123123.github.io/CT-Control/";

        webView.setWebChromeClient(new WebChromeClient());
        webView.setWebViewClient(new WebViewClient() {
            @Override
            public WebResourceResponse shouldInterceptRequest(WebView view, WebResourceRequest request) {
                Uri uri = request.getUrl();
                if (uri != null && "appassets.androidplatform.net".equals(uri.getHost())) {
                    String path = uri.getPath();
                    if (path != null && path.startsWith("/assets/")) {
                        String relPath = path.substring("/assets/".length());
                        if (relPath.endsWith(".html") || relPath.endsWith(".js") || relPath.endsWith(".css") || relPath.endsWith(".json")) {
                            HttpURLConnection conn = null;
                            try {
                                URL liveUrl = new URL(remoteBaseUrl + relPath + "?t=" + sessionTs);
                                conn = (HttpURLConnection) liveUrl.openConnection();
                                conn.setConnectTimeout(1800);
                                conn.setReadTimeout(2200);
                                conn.setUseCaches(false);
                                conn.setRequestProperty("Cache-Control", "no-cache, no-store, must-revalidate");
                                if (conn.getResponseCode() == 200) {
                                    InputStream is = conn.getInputStream();
                                    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                                    byte[] chunk = new byte[4096];
                                    int n;
                                    while ((n = is.read(chunk)) != -1) {
                                        buffer.write(chunk, 0, n);
                                    }
                                    is.close();

                                    String mime = "text/plain";
                                    if (relPath.endsWith(".html")) mime = "text/html";
                                    else if (relPath.endsWith(".js")) mime = "application/javascript";
                                    else if (relPath.endsWith(".css")) mime = "text/css";
                                    else if (relPath.endsWith(".json")) mime = "application/json";

                                    Map<String, String> headers = new HashMap<>();
                                    headers.put("Access-Control-Allow-Origin", "*");
                                    headers.put("Cache-Control", "no-cache, no-store, must-revalidate");

                                    return new WebResourceResponse(
                                        mime,
                                        "UTF-8",
                                        200,
                                        "OK",
                                        headers,
                                        new ByteArrayInputStream(buffer.toByteArray())
                                    );
                                }
                            } catch (Exception ignored) {
                                // 지하주차장 등 오프라인 환경에서는 즉시 APK 내장 에셋으로 폴백
                            } finally {
                                if (conn != null) {
                                    conn.disconnect();
                                }
                            }
                        }
                    }
                }
                return assetLoader.shouldInterceptRequest(uri);
            }
        });

        webView.addJavascriptInterface(new TeslaBleBridge(), "AndroidBLE");
        webView.loadUrl("https://appassets.androidplatform.net/assets/index.html");
    }

    private void emitJs(final String script) {
        mainHandler.post(() -> {
            if (webView != null) {
                webView.evaluateJavascript(script, null);
            }
        });
    }

    private void emitLog(String message, String level) {
        try {
            String escapedMsg = JSONObject.quote(message);
            String escapedLvl = JSONObject.quote(level);
            emitJs("window.__onNativeBleLog && window.__onNativeBleLog(" + escapedMsg + ", " + escapedLvl + ");");
        } catch (Exception ignored) {
        }
    }

    private boolean hasBlePermissions() {
        List<String> required = getRequiredPermissions();
        for (String perm : required) {
            if (ContextCompat.checkSelfPermission(this, perm) != PackageManager.PERMISSION_GRANTED) {
                return false;
            }
        }
        return true;
    }

    private List<String> getRequiredPermissions() {
        List<String> perms = new ArrayList<>();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            perms.add(Manifest.permission.BLUETOOTH_SCAN);
            perms.add(Manifest.permission.BLUETOOTH_CONNECT);
        }
        perms.add(Manifest.permission.ACCESS_FINE_LOCATION);
        perms.add(Manifest.permission.ACCESS_COARSE_LOCATION);
        return perms;
    }

    private boolean isLocationServiceEnabled() {
        LocationManager lm = (LocationManager) getSystemService(Context.LOCATION_SERVICE);
        if (lm == null) return true;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            return lm.isLocationEnabled();
        }
        return lm.isProviderEnabled(LocationManager.GPS_PROVIDER)
            || lm.isProviderEnabled(LocationManager.NETWORK_PROVIDER);
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == REQ_BLE_PERMISSIONS) {
            if (hasBlePermissions()) {
                emitLog("블루투스 및 정밀 위치(iBeacon 스캔) 권한 승인 완료", "info");
                if (pendingScanMode != null) {
                    String mode = pendingScanMode;
                    pendingScanMode = null;
                    startBleScanInternal(mode);
                }
            } else {
                emitLog("블루투스 또는 위치(정확한 위치) 권한이 거부되었습니다. 테슬라 iBeacon 신호 수신을 위해 권한을 허용해 주세요.", "error");
            }
        }
    }

    private void startBleScanInternal(String mode) {
        if (bluetoothAdapter == null || !bluetoothAdapter.isEnabled()) {
            emitLog("휴대폰의 블루투스가 꺼져 있습니다. 블루투스를 켜주세요.", "error");
            return;
        }

        if (!isLocationServiceEnabled()) {
            emitLog("⚠️ 휴대폰 상단바의 '위치(GPS)'가 꺼져 있습니다! 안드로이드에서 테슬라 iBeacon 패킷을 수신하려면 위치(GPS)가 켜져 있어야 합니다.", "warn");
        }

        bleScanner = bluetoothAdapter.getBluetoothLeScanner();
        if (bleScanner == null) {
            emitLog("BluetoothLeScanner를 초기화할 수 없습니다.", "error");
            return;
        }

        if (isScanning) {
            try {
                bleScanner.stopScan(scanCallback);
            } catch (Exception ignored) {
            }
            isScanning = false;
        }

        discoveredDevices.clear();
        mergedNames.clear();
        mergedTeslaIBeacon.clear();
        mergedTeslaService.clear();
        mergedBeaconMeta.clear();

        ScanSettings scanSettings = new ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .setCallbackType(ScanSettings.CALLBACK_TYPE_ALL_MATCHES)
            .setMatchMode(ScanSettings.MATCH_MODE_AGGRESSIVE)
            .build();

        try {
            bleScanner.startScan(null, scanSettings, scanCallback);
            isScanning = true;
            emitLog("네이티브 BLE 스캔 시작 (iBeacon 0x004C 차단 해제 + 0x1122 + S...C 통합 감시)", "info");
            emitJs("window.__onNativeBleScanState && window.__onNativeBleScanState(true);");
        } catch (Exception e) {
            emitLog("스캔 시작 오류: " + e.getMessage(), "error");
        }
    }

    private void stopBleScanInternal() {
        if (isScanning && bleScanner != null) {
            try {
                bleScanner.stopScan(scanCallback);
            } catch (Exception ignored) {
            }
        }
        isScanning = false;
        emitJs("window.__onNativeBleScanState && window.__onNativeBleScanState(false);");
    }

    private final ScanCallback scanCallback = new ScanCallback() {
        @Override
        public void onScanResult(int callbackType, ScanResult result) {
            if (result == null || result.getDevice() == null) return;

            BluetoothDevice device = result.getDevice();
            String address = device.getAddress();
            if (address == null) return;

            discoveredDevices.put(address, device);
            int rssi = result.getRssi();
            ScanRecord record = result.getScanRecord();

            // 1. 기기 이름 추출 및 이전 패킷(ADV_IND / SCAN_RSP)과 병합
            String name = null;
            if (record != null) {
                name = record.getDeviceName();
            }
            if (name == null || name.isEmpty()) {
                try {
                    name = device.getName();
                } catch (Exception ignored) {
                }
            }
            if (name != null && !name.isEmpty()) {
                mergedNames.put(address, name);
            } else {
                name = mergedNames.get(address);
            }

            // 2. Apple iBeacon (0x004C -> 02 15) 및 테슬라 전용 iBeacon UUID(74278bda-...) 판별
            boolean isTeslaIBeacon = Boolean.TRUE.equals(mergedTeslaIBeacon.get(address));
            String meta = mergedBeaconMeta.getOrDefault(address, "");

            if (record != null) {
                byte[] appleData = record.getManufacturerSpecificData(0x004C);
                if (appleData != null && appleData.length >= 18) {
                    if ((appleData[0] & 0xFF) == 0x02 && (appleData[1] & 0xFF) == 0x15) {
                        boolean uuidMatch = true;
                        for (int i = 0; i < 16; i++) {
                            if (appleData[2 + i] != TESLA_IBEACON_UUID[i]) {
                                uuidMatch = false;
                                break;
                            }
                        }
                        if (uuidMatch) {
                            isTeslaIBeacon = true;
                            mergedTeslaIBeacon.put(address, true);
                            if (appleData.length >= 22) {
                                int major = ((appleData[18] & 0xFF) << 8) | (appleData[19] & 0xFF);
                                int minor = ((appleData[20] & 0xFF) << 8) | (appleData[21] & 0xFF);
                                meta = String.format("Tesla iBeacon [Maj:%04X Min:%04X]", major, minor);
                                mergedBeaconMeta.put(address, meta);
                            } else {
                                meta = "Tesla iBeacon [74278bda...]";
                                mergedBeaconMeta.put(address, meta);
                            }
                        } else if (meta.isEmpty()) {
                            meta = "Apple iBeacon (0x004C)";
                        }
                    }
                }

                // 기타 제조사 데이터가 있으면 요약 기록
                if (meta.isEmpty()) {
                    SparseArray<byte[]> mfgList = record.getManufacturerSpecificData();
                    if (mfgList != null && mfgList.size() > 0) {
                        int mfgId = mfgList.keyAt(0);
                        meta = String.format("Mfg:0x%04X", mfgId);
                    }
                }
            }

            // 3. Service UUID (0x1122 또는 0x0211) 판별
            boolean hasTeslaService = Boolean.TRUE.equals(mergedTeslaService.get(address));
            if (record != null && record.getServiceUuids() != null) {
                for (ParcelUuid pu : record.getServiceUuids()) {
                    String u = pu.getUuid().toString().toLowerCase();
                    if (u.startsWith("00001122-") || u.startsWith("00000211-")) {
                        hasTeslaService = true;
                        mergedTeslaService.put(address, true);
                        break;
                    }
                }
            }

            // 4. 기기 이름 패턴 판별 (S + 16 hex + C/R/D/P 또는 Tesla + 6자리)
            boolean hasTeslaName = false;
            boolean isClassicAudio = false;
            if (name != null) {
                hasTeslaName = name.matches("^S[0-9a-fA-F]{16}[CRDP]?$")
                    || name.matches("(?i)^Tesla [A-HJ-NPR-Z0-9]{6}$");
                if (!hasTeslaName) {
                    String lower = name.toLowerCase();
                    isClassicAudio = name.contains("Tesla Model")
                        || name.contains("동행터렛")
                        || lower.contains("audio");
                }
            }

            boolean isTesla = isTeslaIBeacon || hasTeslaService || hasTeslaName;

            try {
                JSONObject obj = new JSONObject();
                obj.put("address", address);
                obj.put("name", name != null ? name : "");
                obj.put("rssi", rssi);
                obj.put("isTesla", isTesla);
                obj.put("isTeslaIBeacon", isTeslaIBeacon);
                obj.put("hasTeslaService", hasTeslaService);
                obj.put("hasTeslaName", hasTeslaName);
                obj.put("isClassicAudio", isClassicAudio);
                obj.put("meta", meta);

                emitJs("window.__onNativeBleScanResult && window.__onNativeBleScanResult(" + obj.toString() + ");");
            } catch (Exception ignored) {
            }
        }

        @Override
        public void onScanFailed(int errorCode) {
            emitLog("BLE 스캔 실패 (errorCode=" + errorCode + ")", "error");
            isScanning = false;
            emitJs("window.__onNativeBleScanState && window.__onNativeBleScanState(false);");
        }
    };

    private final BluetoothGattCallback gattCallback = new BluetoothGattCallback() {
        @Override
        public void onConnectionStateChange(final BluetoothGatt gatt, int status, int newState) {
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                emitLog("네이티브 GATT 물리 연결 성공! MTU 517 협상 요청 중...", "info");
                mainHandler.postDelayed(() -> {
                    if (activeGatt == null) return;
                    boolean mtuRequested = false;
                    try {
                        mtuRequested = activeGatt.requestMtu(517);
                    } catch (Exception ignored) {
                    }
                    if (!mtuRequested) {
                        activeGatt.discoverServices();
                    }
                }, 180);
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                cleanupGatt();
                if (!isChannelReady && currentTargetAddress != null && connectAttempt < 3) {
                    connectAttempt++;
                    final String retryAddr = currentTargetAddress;
                    emitLog("GATT 초기 연결 재시도 (" + connectAttempt + "/3, 이전 status=" + status + ")...", "warn");
                    mainHandler.postDelayed(() -> connectDeviceInternal(retryAddr, false), 650);
                    return;
                }
                isChannelReady = false;
                emitLog("GATT 연결 해제됨 (status=" + status + ")", "warn");
                emitJs("window.__onNativeBleState && window.__onNativeBleState('disconnected', " + status + ");");
            }
        }

        @Override
        public void onMtuChanged(final BluetoothGatt gatt, int mtu, int status) {
            emitLog("MTU 협상 완료: " + mtu + " bytes (status=" + status + ")", "info");
            emitJs("window.__onNativeBleMtu && window.__onNativeBleMtu(" + mtu + ");");
            mainHandler.postDelayed(() -> {
                if (activeGatt != null) {
                    activeGatt.discoverServices();
                }
            }, 150);
        }

        @Override
        public void onServicesDiscovered(BluetoothGatt gatt, int status) {
            if (status != BluetoothGatt.GATT_SUCCESS) {
                emitLog("GATT 서비스 검색 실패 (status=" + status + ")", "error");
                return;
            }

            BluetoothGattService service = gatt.getService(TESLA_SERVICE_UUID);
            if (service == null) {
                StringBuilder sb = new StringBuilder();
                for (BluetoothGattService s : gatt.getServices()) {
                    if (sb.length() > 0) sb.append(", ");
                    sb.append(s.getUuid().toString().substring(0, 8));
                }
                emitLog("선택한 기기에 테슬라 VCSEC 서비스(0x0211)가 없습니다. (발견된 서비스: " + sb + ")", "error");
                disconnectGattInternal();
                return;
            }

            txCharacteristic = service.getCharacteristic(TESLA_TX_CHAR_UUID);
            rxCharacteristic = service.getCharacteristic(TESLA_RX_CHAR_UUID);

            if (txCharacteristic == null || rxCharacteristic == null) {
                emitLog("테슬라 TX(0x0212) 또는 RX(0x0213) 특성을 찾을 수 없습니다.", "error");
                disconnectGattInternal();
                return;
            }

            gatt.setCharacteristicNotification(rxCharacteristic, true);
            BluetoothGattDescriptor cccd = rxCharacteristic.getDescriptor(CCCD_UUID);
            if (cccd != null) {
                int props = rxCharacteristic.getProperties();
                byte[] enableVal = ((props & BluetoothGattCharacteristic.PROPERTY_INDICATE) != 0)
                    ? BluetoothGattDescriptor.ENABLE_INDICATION_VALUE
                    : BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE;

                writeDescriptorCompat(gatt, cccd, enableVal);
            } else {
                isChannelReady = true;
                emitLog("RX 알림 활성화 완료 (CCCD 없음)", "info");
                emitJs("window.__onNativeBleState && window.__onNativeBleState('connected', 0);");
            }
        }

        @Override
        public void onDescriptorWrite(BluetoothGatt gatt, BluetoothGattDescriptor descriptor, int status) {
            isChannelReady = true;
            emitLog("테슬라 VCSEC RX(0x0213) 수신 채널 활성화 완료 (status=" + status + ")", "info");
            emitJs("window.__onNativeBleState && window.__onNativeBleState('connected', 0);");
        }

        @Override
        public void onCharacteristicWrite(BluetoothGatt gatt, BluetoothGattCharacteristic characteristic, int status) {
            emitJs("window.__onNativeBleWriteDone && window.__onNativeBleWriteDone(" + status + ");");
        }

        // Android 13+ (API 33+) 콜백
        @Override
        public void onCharacteristicChanged(@NonNull BluetoothGatt gatt, @NonNull BluetoothGattCharacteristic characteristic, @NonNull byte[] value) {
            handleRxBytes(value);
        }

        // Android 12 이하 (API <= 32) 콜백
        @SuppressWarnings("deprecation")
        @Override
        public void onCharacteristicChanged(BluetoothGatt gatt, BluetoothGattCharacteristic characteristic) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
                handleRxBytes(characteristic.getValue());
            }
        }
    };

    private void handleRxBytes(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return;
        String hex = bytesToHex(bytes);
        emitJs("window.__onNativeBleRxHex && window.__onNativeBleRxHex('" + hex + "');");
    }

    @SuppressWarnings("deprecation")
    private void writeDescriptorCompat(BluetoothGatt gatt, BluetoothGattDescriptor descriptor, byte[] value) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            gatt.writeDescriptor(descriptor, value);
        } else {
            descriptor.setValue(value);
            gatt.writeDescriptor(descriptor);
        }
    }

    @SuppressWarnings("deprecation")
    private boolean writeCharacteristicCompat(BluetoothGatt gatt, BluetoothGattCharacteristic characteristic, byte[] value) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            int res = gatt.writeCharacteristic(characteristic, value, BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT);
            return res == 0; // BluetoothStatusCodes.SUCCESS == 0
        } else {
            characteristic.setWriteType(BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT);
            characteristic.setValue(value);
            return gatt.writeCharacteristic(characteristic);
        }
    }

    private void connectDeviceInternal(String address, boolean resetAttempts) {
        stopBleScanInternal();
        cleanupGatt();

        if (resetAttempts) {
            connectAttempt = 1;
            isChannelReady = false;
            currentTargetAddress = address;
        }

        BluetoothDevice device = discoveredDevices.get(address);
        if (device == null && bluetoothAdapter != null) {
            try {
                device = bluetoothAdapter.getRemoteDevice(address);
            } catch (Exception ignored) {
            }
        }

        if (device == null) {
            emitLog("연결할 디바이스(" + address + ")를 찾을 수 없습니다.", "error");
            emitJs("window.__onNativeBleState && window.__onNativeBleState('disconnected', -1);");
            return;
        }

        String devName = mergedNames.getOrDefault(address, "");
        emitLog("네이티브 BLE GATT 연결 시도 중 (" + connectAttempt + "/3): " + (devName.isEmpty() ? address : devName + " (" + address + ")"), "info");

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            activeGatt = device.connectGatt(MainActivity.this, false, gattCallback, BluetoothDevice.TRANSPORT_LE);
        } else {
            activeGatt = device.connectGatt(MainActivity.this, false, gattCallback);
        }
    }

    private void disconnectGattInternal() {
        currentTargetAddress = null;
        isChannelReady = false;
        if (activeGatt != null) {
            try {
                activeGatt.disconnect();
            } catch (Exception ignored) {
            }
        }
        cleanupGatt();
        emitJs("window.__onNativeBleState && window.__onNativeBleState('disconnected', 0);");
    }

    private void cleanupGatt() {
        if (activeGatt != null) {
            try {
                activeGatt.close();
            } catch (Exception ignored) {
            }
            activeGatt = null;
        }
        txCharacteristic = null;
        rxCharacteristic = null;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    public class TeslaBleBridge {

        @JavascriptInterface
        public boolean isNativeApp() {
            return true;
        }

        @JavascriptInterface
        public String getEnvStatusJson() {
            try {
                JSONObject obj = new JSONObject();
                obj.put("btEnabled", bluetoothAdapter != null && bluetoothAdapter.isEnabled());
                obj.put("locationEnabled", isLocationServiceEnabled());
                obj.put("permissionsGranted", hasBlePermissions());
                obj.put("sdkInt", Build.VERSION.SDK_INT);
                return obj.toString();
            } catch (Exception e) {
                return "{}";
            }
        }

        @JavascriptInterface
        public void openLocationSettings() {
            try {
                Intent intent = new Intent(Settings.ACTION_LOCATION_SOURCE_SETTINGS);
                startActivity(intent);
            } catch (Exception e) {
                emitLog("위치 설정 화면 열기 실패: " + e.getMessage(), "error");
            }
        }

        @JavascriptInterface
        public void openAppSettings() {
            try {
                Intent intent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS);
                intent.setData(Uri.fromParts("package", getPackageName(), null));
                startActivity(intent);
            } catch (Exception e) {
                emitLog("앱 권한 설정 화면 열기 실패: " + e.getMessage(), "error");
            }
        }

        @JavascriptInterface
        public void startScan(String mode) {
            mainHandler.post(() -> {
                if (!hasBlePermissions()) {
                    pendingScanMode = mode != null ? mode : "standard";
                    List<String> req = getRequiredPermissions();
                    ActivityCompat.requestPermissions(
                        MainActivity.this,
                        req.toArray(new String[0]),
                        REQ_BLE_PERMISSIONS
                    );
                    return;
                }
                startBleScanInternal(mode != null ? mode : "standard");
            });
        }

        @JavascriptInterface
        public void stopScan() {
            mainHandler.post(MainActivity.this::stopBleScanInternal);
        }

        @JavascriptInterface
        public void connectDevice(String address) {
            mainHandler.post(() -> connectDeviceInternal(address, true));
        }

        @JavascriptInterface
        public boolean writeChunkHex(String hex) {
            if (activeGatt == null || txCharacteristic == null || hex == null) {
                return false;
            }
            try {
                byte[] bytes = hexToBytes(hex);
                return writeCharacteristicCompat(activeGatt, txCharacteristic, bytes);
            } catch (Exception e) {
                emitLog("패킷 전송 오류: " + e.getMessage(), "error");
                return false;
            }
        }

        @JavascriptInterface
        public void disconnect() {
            mainHandler.post(MainActivity.this::disconnectGattInternal);
        }
    }
}
