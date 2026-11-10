---
id: mobile-android-udid-3des-jni-key-hook-fixed-iv
title: App udid 逆向：IMEI|nanoTime|deviceId 拼接后 3DES-CBC（JNI 返回固定 key + 固定 IV appapich）Base64
type: scenario
domain: mobile
path: mobile/android
technique: android-udid-3des-jni-key-hook-fixed-iv
tags:
- android
- reverse
- 3des
- desede
- jni
- frida
- hook
- udid
- device-fingerprint
- parameter-encryption
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V454
  verified_at: '2026-11-10T02:25:39+08:00'
  notes: 已对照原文核对：图33/28 getUDID=SecurityUtil.encode3Des(context, getIMEI+REPORT_VAL_SEPARATOR+nanoTime+REPORT_VAL_SEPARATOR+getDeviceId)、图30 分隔符"|"、图34/35 desede/CBC/PKCS5Padding + iv="appapich"、图36/37 getDesKey→getSignDesKey→CheckSignUtil.get3desKey、图39 native-lib 静态块与 native get3desKey、图41 多次 hook getDesKey 均为 appapiche168comappapiche168comap、图31 regdevice.ashx 返回 deviceid 355686，均与卡一致；PyCryptodome 3DES-CBC 前 24 字节 key + 固定 IV + Base64 复现与原文 Python 一致。注意原文 Python 示例明文末段写 366586（与抓包 deviceid 355686 略异），卡用 355686 并标注按实际替换，处理合理。与既有 AES 随机 key、DES/ECB+MD5 派生 key、native 主动调用等候选算法/密钥来源均不同，dedup new 成立。原文 appversion/设备仅为环境，无受影响版本区间，affected_versions 已 --clear。未在本机复跑。
url: /docs/mobile/android/mobile-android-udid-3des-jni-key-hook-fixed-iv/
draft: false
kb_aliases:
- udid 3DES 加密
- encode3Des 逆向
- get3desKey hook
- desede/CBC/PKCS5Padding
- 固定 IV appapich
- IMEI 设备指纹拼接
- 汽车之家 udid
---

## 一句话结论

App 的 `udid` 由 `SecurityUtil.encode3Des(context, getIMEI(context) + "|" + System.nanoTime() + "|" + SPUtils.getDeviceId())` 生成：算法是 `desede/CBC/PKCS5Padding`（3DES），IV 硬编码为 `appapich`，密钥来自 `AHAPIHelper.getDesKey → CheckSignUtil.get3desKey`（JNI/`libnative-lib`）；不必逆向 so，Frida hook Java 层 `getDesKey` 即可发现 key 固定为 `appapiche168comappapiche168comap`，取前 24 字节配合固定 IV 与 Base64 就能离线复现 udid。

## 原理

- **udid 明文组成**：`getUDID(context)` 返回 `SecurityUtil.encode3Des(context, getIMEI(context) + HiAnalyticsConstant.REPORT_VAL_SEPARATOR + System.nanoTime() + HiAnalyticsConstant.REPORT_VAL_SEPARATOR + SPUtils.getDeviceId())`，分隔符常量为 `"|"`；即“IMEI | 开机纳秒时间 | 设备 ID”三段拼接。
- **三段来源**：
  - `getIMEI`：有 READ_PHONE_STATE 权限时先读 SharedPreferences 缓存，没有则 `TelephonyManager.getDeviceId()`；仍为空时用 Wi-Fi MAC 做 `UUID.nameUUIDFromBytes`，或走 AndroidID+UUID 兜底，生成后写入 SP 长期复用；无权限直接返回固定串 `"sssss"`。
  - `System.nanoTime()`：Android 上是从开机起的纳秒数（非墙上时间），每次调用不同；复现时需从抓包/hook 拿到该值或固定它。
  - `SPUtils.getDeviceId()`：SharedPreferences 中的 `device_id`，由服务端 `/push/regdevice.ashx` 返回的 `deviceid` 写入（示例 `355686`），同设备固定。
- **3DES 实现**：`SecretKeyFactory.getInstance("desede").generateSecret(new DESedeKeySpec(desKey.getBytes()))`；`Cipher.getInstance("desede/CBC/PKCS5Padding")`；`init(1, key, new IvParameterSpec(iv.getBytes()))`；`doFinal(str.getBytes("UTF-8"))` 后 `encode(...)` 输出 Base64 文本。`iv` 是类字段 `"appapich"`，`encoding="UTF-8"`。
- **key 的来源与提取**：`AHAPIHelper.getDesKey(context)` 为空时调用 `getSignDesKey`，最终 `mDesKey = CheckSignUtil.get3desKey(context)`；`CheckSignUtil` 在静态块 `System.loadLibrary("native-lib")`，`get3desKey` 是 native 方法。逆向 .so 成本高，但可以 hook Java 层 `getDesKey` 直接拿返回值——多次登录打印均为同一 32 字符 `appapiche168comappapiche168comap`，说明 key 固定；3DES 只使用前 24 字节（`DESedeKeySpec` 24 字节），后 8 字节可忽略。
- **为什么可行**：客户端必须持有对称密钥才能生成 udid，密钥虽然在 so 中产生/返回，但 Java 层要拿到明文字符串才能传给 `DESedeKeySpec`，hook 这个边界即可；密钥固定使历史/任意设备指纹都可离线复算，加密只是提高逆向成本。
- **边界**：nanoTime 与 IMEI/deviceId 是变量；无权限时 IMEI 为 `"sssss"`，不同设备可能相同；`encode()` 可能是自定义 Base64 字母表（类中有 `legalChars`），若标准 Base64 解不开需按该表替换；高版本 Android 限制 IMEI/MAC 获取，实际值可能退化为 UUID。

## 触发条件

- App 请求中带 `udid`/设备指纹字段，且为 Base64 文本；登录/公共参数会调用 `getUDID`。
- APK 可反编译（未加固或已脱壳），能定位 `SecurityUtil.encode3Des`/`AHAPIHelper.getDesKey`/`CheckSignUtil.get3desKey`。
- 有 Frida/可调试环境，且已绕过 SSL Pinning（如启用）。
- 需要复现/伪造设备指纹或解密 udid 字段（授权测试、协议分析）。

## 利用步骤

1. 抓包记录 `udid` 字段与同一请求的 `deviceid` 等参数；URL 解码后 Base64 解码得到 3DES 密文。
2. jadx 搜索 `getUDID`、`encode3Des`、`getDesKey`、`get3desKey`，确认明文拼接顺序与分隔符（`|`）、IV（`appapich`）、算法（desede/CBC/PKCS5Padding）与输出编码。
3. 启动 frida-server（adb shell → su → /data/local/tmp/frida-server）并 `adb forward tcp:27042/27043`。
4. 编写 hook：`Java.use("...AHAPIHelper").getDesKey.implementation` 打印返回值；多次登录确认 key 是否固定（示例固定为 `appapiche168comappapiche168comap`）。
5. 若 key 固定，用 Python 复现：key 取前 24 字节、IV `appapich`、PKCS#5/7 填充、`DES3.MODE_CBC`、Base64；明文按第 1 步的顺序拼接（IMEI 可用 hook `getIMEI` 获得，nanoTime 可从 hook 输出或取当前开机时间近似）。
6. 若 `encode()` 是自定义字母表，按类中的 `legalChars` 做 Base64 映射后再解码/编码；用 hook 的输入输出对拍验证。

## PoC

```python
import base64
from Crypto.Cipher import DES3

BS = 8
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)

key = b"appapiche168comappapiche168comap"[0:24]   # hook getDesKey 得到，3DES CBC 用前 24 字节
iv = b"appapich"

plaintext = pad("cf15599b-5e93-3be5-a705-a39403227dfd|13359325995159|355686").encode("utf-8")
cipher = DES3.new(key, DES3.MODE_CBC, iv)
print(base64.b64encode(cipher.encrypt(plaintext)).decode())
```

Frida hook 取 key：

```javascript
Java.perform(function () {
  var AHAPIHelper = Java.use("com.autohome.ahkit.AHAPIHelper");
  AHAPIHelper.getDesKey.implementation = function (ctx) {
    var res = this.getDesKey(ctx);
    console.log("DesKey:", res);
    return res;
  };
});
```

说明：明文三段来自 `getIMEI + "|" + System.nanoTime() + "|" + deviceId`，示例值按实际 hook 替换；标准 Base64 与自定义 encode 之间的差异需按样本验证。未在本机执行。

## 变体与关联

- [[mobile-android-aes-random-key-hook-fixed-iv-decrypt]]：同样用 hook key getter + 固定 IV 解密的思路，但算法是 AES、key 随机随包传输；本卡是 3DES + JNI 固定 key。
- [[mobile-android-param-encryption-des-md5-timewindow]]：DES/ECB + MD5 派生 key 的参数加密；本卡是 desede/CBC + 固定 key/IV。
- [[mobile-android-native-so-getsign-xor-devid-smiletozz-md5]]、[[mobile-android-native-sign-hash-identify-differential-md5-fixed-suffix]]：native 签名的其他逆向路径；本卡选择 hook Java 边界而非逆向 so。
- 变体：key 可能仅在首次生成后缓存、不同版本可能更换；IV 可能随版本变化；加密结果可能用自定义 Base64 字母表；明文可能增加 AndroidID/品牌/型号字段。
- 边界：无权限时 IMEI 固定 `"sssss"`；nanoTime 不可预测导致每次 udid 不同；服务端可能同时校验 deviceid/其他头；so 内 key 可能按设备/版本变化（hook 多次确认）。

## 检测与防御

- 检测（分析侧）：Frida hook `getDesKey`/`encode3Des` 的调用与固定返回值；对比多次请求 udid 的明文结构。
- 检测（防御侧）：客户端不应把固定对称密钥用于设备指纹/参数加密；服务端应把 udid 与设备证明/服务端签发绑定，而非仅信任客户端密文；监控异常高频的设备注册与 udid 复用。
- 防御：使用 Android Keystore/硬件密钥与服务端挑战签名替代硬编码 key；对请求做 HMAC/时间窗/nonce；检测 Frida/root 与 hook 框架。
- 响应：伪造 udid 可能导致设备伪造、薅羊毛/风控绕过；发现固定 key 后应评估历史数据可信度并轮换密钥。
