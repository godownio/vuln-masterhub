---
id: mobile-android-apk-ble-native-modified-rc4-vin
title: 车联网 APK 蓝牙 VIN 加密逆向：Java 预变换 + native 变种 RC4 + BLE 流量解密
type: scenario
domain: mobile
path: mobile/android
technique: apk-ble-native-modified-rc4
tags:
- android
- apk
- jni
- native
- rc4
- ble
- bluetooth
- iov
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V131
  verified_at: '2026-11-06T05:39:05+08:00'
  notes: 已对照原文 IOV 部分及 jadx/IDA 截图核对：Java a.a 的 (x+k)%256 ^ k 预变换（PMZPFVDM）、native KSA +3 与 PRGA 低字节取 S、BLE 特征值密文 3017284f2ed903814311c68d5149bf5c12 均与原文一致；按卡内 PoC 复算得 JYNkuvKA6G3RzzAkH（17字节），与截图 flag 一致。未在设备上抓包验证。
url: /docs/mobile/android/mobile-android-apk-ble-native-modified-rc4-vin/
draft: false
kb_aliases:
- IOV VIN 加密
- BLE 流量解密
- native 变种 RC4
- Java 层加钥异或预变换
- 车联网 APK 逆向
---

## 一句话结论

当车联网 APK 把 VIN 先经 Java 层“加密钥再异或”的预变换转成十六进制，再交给 native 层用改造过的 RC4（KSA 额外加常数、PRGA 取 32 位 S 盒低字节）加密，并通过 BLE GATT 写出时，抓到 BLE 写特征值密文后，按同样的 Java 预变换逆运算 + native 变种 RC4 即可离线还原 VIN。

## 原理

- **Java 层预变换**：`VinInputActivity` 取 17 位 VIN，调用 `encrypt(a.a(vin))`。`a.a` 使用固定密钥 `PMZPFVDM`，对每个字符做 `y = ((x + k) % 256) ^ k`（`k` 为密钥循环字符），再把结果按 `%02X` 转成十六进制字符串。
- **native 层加密**：`encrypt` 是 JNI 函数，加载 `native-lib`；它把 Java 传来的十六进制串解析成字节，用固定密钥 `SecretKey` 做变种 RC4：KSA 中 `j = (j + S[i] + key[i % L] + 3) & 255`；PRGA 保持标准交换，但 S 盒按 32 位数组存储，输出取 `S[(S[i] + S[j]) & 255]` 的低字节与数据异或。
- **BLE 传输**：加密结果通过 GATT 特征值写（`writeCharacteristic`）发给车机/设备；BLE 空口或 HCI 日志可抓到该特征值写入的十六进制密文。
- **为什么可逆**：RC4 是流加密，密钥流与数据异或自逆；Java 预变换是逐字符可逆的 `加-异或`，逆运算为 `x = ((y ^ k) - k) & 0xFF`。只要把两层的参数和顺序都复制到解密脚本，就能还原明文。
- **参数来源**：Java 密钥硬编码在 DEX；native 密钥与 KSA 常数在 SO 中；两者都可通过 jadx/IDA 静态定位，或 Frida hook JNI 函数直接取输入输出。

## 触发条件

- APK 使用 native `encrypt`/JNI 做业务加密，且加密结果经 BLE GATT 写出。
- 能抓到 BLE 写特征值的密文（HCI btsnoop、nRF Sniffer、Android HCI log 或设备侧日志）。
- 能反编译 APK（jadx）与 SO（IDA/Ghidra），或能 Frida hook。
- 加密密钥/常数硬编码或可从代码中恢复；预变换与 RC4 变种可逐行复刻。

## 利用步骤

1. jadx 打开 APK，定位 `VinInputActivity`：确认 VIN 长度校验（17 位）、`encrypt(a.a(trim))` 调用链与 BLE 特征值 UUID。
2. 还原 Java `a.a`：找到 `c(str, "PMZPFVDM")` 与 `b()` 的十六进制格式化，确认逐字符公式 `((x + k) % 256) ^ k`。
3. IDA/Ghidra 打开 `libnative-lib.so`，定位 `Java_..._VinInputActivity_encrypt`；确认它先解析十六进制、再执行 KSA/PRGA；记录 KSA 的 `+3`、PRGA 的取模/低字节细节与密钥 `SecretKey`。
4. 抓 BLE：用 HCI btsnoop/nRF Sniffer 抓 ATT Write，取出写入特征值的十六进制串（本题为 20 字节）。
5. 写解密脚本：先用变种 RC4 解密得到预变换后的字节，再对每个字节做 `((y ^ k) - k) & 0xFF` 逆变换，得到 VIN/flag。
6. 用同一脚本重新加密已知 VIN，或检查输出是否为可打印 ASCII/flag 格式，验证参数正确。

## PoC

```python
C  = "3017284f2ed903814311c68d5149bf5c12"  # BLE 抓到的密文
RK = b"SecretKey"                           # native RC4 密钥
PK = b"PMZPFVDM"                            # Java 预变换密钥

def ksa_plus3(k):
    S = list(range(256)); j = 0; L = len(k)
    for i in range(256):
        j = (j + S[i] + k[i % L] + 3) & 255
        S[i], S[j] = S[j], S[i]
    return S

def rc4_stream(S, data):
    i = j = 0; out = bytearray()
    for b in data:
        i = (i + 1) & 255
        j = (j + S[i]) & 255
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 255])
    return bytes(out)

def invert_pre(y, key):
    L = len(key)
    return bytes((((y[i] ^ key[i % L]) - key[i % L]) & 0xFF) for i in range(len(y)))

pre  = rc4_stream(ksa_plus3(RK), bytes.fromhex(C))
orig = invert_pre(pre, PK)
print(f"flag{{{orig.decode('ascii')}}}")
```

```javascript
// Java 层预变换（用于对照/重加密）
function preTransform(s, key) {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const x = s.charCodeAt(i);
    const k = key.charCodeAt(i % key.length);
    out += (((x + k) % 256) ^ k).toString(16).padStart(2, '0').toUpperCase();
  }
  return out;
}
```

## 变体与关联

- 变体：BLE 抓包可来自 Android HCI btsnoop、nRF Sniffer、Ellisys/Frontline 或设备侧串口日志；先确认 ATT Write 的 handle/UUID 与数据方向。
- 变体：native 层可能把密钥拆分、异或或从 Java 传入；用 Frida hook `Java_..._encrypt` 或 `encrypt` 直接打印入参/出参，避免静态还原全部常数。
- 变体：PRGA 若用 32 位数组，注意 `S[(S[i]+S[j]) & 255]` 只取低 8 位；若 KSA 的常数/轮数不同，按代码逐处同步。
- 变体：Java 预变换可能是 `加-异或`、`异或-加`、双密钥或多层 hex；逆运算顺序必须与加密相反。
- 关联：[[ctf-reverse-modified-rc4-rounds-sbox]]（魔改 RC4 的识别与同步）、[[iot-protocol-ble-android-hci-btsnoop-capture]]（Android BLE HCI 抓包）、[[iot-protocol-ble-smart-bulb-att-write-replay]]（BLE ATT Write 重放）、[[mobile-android-jni-native-unicorn-emulation-constant-extraction]]（JNI/native 常数提取）。

## 检测与防御

- 检测（逆向）：APK 中出现 `native-lib`、JNI `encrypt`、BLE `writeCharacteristic`、固定十六进制密钥；SO 中出现 256 项 S 盒与 `%256` 交换。
- 检测（防守）：BLE 特征值写入出现固定长度十六进制、重复密钥流特征；同一 VIN 的密文可重放。
- 防御：不要在客户端硬编码长期密钥；使用标准 AEAD（AES-GCM/ChaCha20-Poly1305）与每会话随机 nonce；密钥放入 TEE/Keystore 并做设备证明。
- 防御：BLE 配对/绑定后使用会话密钥与计数器，拒绝重放；不要把业务加密当作访问控制，服务端必须重新校验 VIN 与权限。
- 边界：若 native 层有反调试/加壳或密钥由服务端动态下发，静态还原成本上升，需结合动态 hook 与服务端协议分析。
