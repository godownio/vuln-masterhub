---
id: iot-vehicle-ota-handshake-session-key-aes-cbc-zero-iv
title: 车机 OTA 握手泄露 session_key：AES-CBC 前置 IV 解密 ota/init 双向流量读取 admin flag
type: scenario
domain: iot
path: iot/vehicle
technique: ota-handshake-session-key-aes-cbc-zero-iv
aliases:
- OTA 握手 session_key
- 车机 OTA 流量解密
- AES-CBC 前置 IV
- /api/v1/vehicle/handshake
- /api/v1/ota/init
- 车联网 OTA 取证
tags:
- iot
- vehicle
- ota
- handshake
- session-key
- aes-cbc
- traffic-decrypt
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V228
  verified_at: '2026-11-07T07:18:22+08:00'
  notes: 已对照原文与图04–06核对：handshake响应明文下发session_key=9dbbe057…，ota/init请求/响应为Base64(16字节IV||AES-CBC密文)。原文CyberChef用零IV解整段时首块乱码、其后为admin:true与flag{62173234ab6b0f3349ed89685fba5fff}，据此把卡内“IV全0”修正为“前置IV”，PoC改为blob[:16]作IV、blob[16:]作密文并去PKCS7；用原文抓包数据复算请求体亦可解出{nonce:…}（首块为IV）。未验证点：原始响应Base64在截图中被右边界裁掉约4字符（Content-Length=236但可见232），未在本机完整复跑；frontmatter无sources/source_url；原文未给组件版本。
---

## 一句话结论

车机 OTA 流程先调用 `/api/v1/vehicle/handshake`，响应 JSON 中直接下发 `session_key`（十六进制）；随后的 `/api/v1/ota/init` 请求体与响应体都是 Base64(16 字节 IV || AES-CBC 密文)，密钥就是该 `session_key`。截获握手与 OTA 流量后，用 `session_key` 与前置 IV 解密响应，即可读到包含 `"admin": true` 与 flag 的 JSON（原文 CyberChef 用零 IV 解密整段时首块为乱码，但后续 JSON 仍可读）。

## 原理

- **OTA 典型流程**：设备向服务器发起 handshake，携带 VIN/状态；服务器生成会话密钥 `session_key` 并通过 JSON 返回；后续固件包、授权信息等敏感数据用该会话密钥做对称加密（常见 AES-CBC/CTR）。
- **会话密钥明文下发**：本例 handshake 响应为 `{"message":"handshake ok","ok":true,"session_key":"9dbbe057...","vehicle_type":"admin"}`，`session_key` 直接以 hex 字符串返回；在 HTTP（或同一可截获通道）上传输时，任何能抓包的人都能拿到密钥。
- **AES-CBC 前置 IV**：`/api/v1/ota/init` 的请求体与响应体都是 Base64 字符串；解码后前 16 字节是随机 IV，其余是 AES-CBC 密文。用 `session_key` 与前 16 字节 IV 解密即可得到干净 JSON；原文在 CyberChef 中直接把整段（含 IV）当作密文、IV 填 0，等价于把前置 IV 当作首块密文，因此首块显示为乱码，但从第二块起即为正确明文。
- **X-Session-Token 与 session_key 的区别**：请求头 `X-Session-Token` 是另一个认证令牌（示例 `1d5173...`），不要误当作 AES 密钥；AES 密钥是 handshake 响应里的 `session_key`。
- **为什么能拿到 flag**：OTA init 的响应包含 `"ok": true, "nonce": 2, "admin": true, "flag": "flag{...}"` 等字段；只要解密响应即可直接读到。

## 触发条件

- 能抓到车机 OTA 流量的 pcap/HTTP 日志，包含 handshake 与 ota/init 两个请求/响应。
- handshake 响应中明文下发 `session_key`，且后续 OTA 数据用该密钥加密。
- OTA 数据以 Base64 传输，AES 模式为 CBC 且 IV 前置（原文用零 IV 解整段也能读出 JSON，但首块为乱码）。
- 目标未强制使用 TLS 双向认证/证书固定等阻止抓包与解密的机制（或已在设备侧取得密钥）。

## 利用步骤

1. 在流量中定位 `POST /api/v1/vehicle/handshake`，读取 JSON 请求（VIN、battery、timestamp）与响应中的 `session_key`（hex）。
2. 定位后续 `POST /api/v1/ota/init`，记录请求头 `X-Session-Token`、请求体 Base64 密文与响应体 Base64 密文。
3. 将 `session_key` 从 hex 转为字节（长度 16/24/32 字节对应 AES-128/192/256）；Base64 解码请求/响应，取前 16 字节作为 IV、其余作为密文。
4. 用该 IV 对密文做 AES-CBC 解密并去 PKCS#7 填充。
5. 解析 JSON，读取 `flag` 字段；若响应还有加密的固件包/授权信息，可用同一 session_key 继续解密。
6. 如需伪造 OTA 请求，用同一 key/IV 加密自己的 JSON 并 Base64 编码，带上 `X-Session-Token` 发送。

## PoC

```python
import base64, json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

session_key_hex = "9dbbe057c3b0c7e547701d5ccab3d676c0de24cdd49f2e4f34f5bc99e0e666a0"
key = bytes.fromhex(session_key_hex)

def dec(b64):
    blob = base64.b64decode(b64)
    iv, ct = blob[:16], blob[16:]
    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)

plain = dec("<ota/init 响应 Base64>")
print(json.loads(plain))
# {"ok": true, "nonce": 2, "admin": true, "flag": "flag{62173234ab6b0f3349ed89685fba5fff}", ...}
```

说明：原文用 CyberChef 的 `From Base64 → AES Decrypt (key=session_key, IV=00000000000000000000000000000000, CBC)` 直接解密整段，输出首块为乱码、其后为 `admin:true` 与 flag（这说明真实格式是前置 IV；按上文 `blob[:16]` 作 IV 可得到干净 JSON）。请求体同样可用该方式解密；`X-Session-Token` 是认证令牌，不是 AES key。未在本机复跑。

## 变体与关联

- **会话密钥派生**：若 handshake 只下发临时值、真正的 AES key 由 `session_key` 经 KDF/HMAC 派生，需要按设备端逻辑复算；本卡是直接使用 session_key 的最简情形。
- **AES-CBC 固定 key/IV**：[[code-analysis-reverse-obfuscation-aes-cbc-encryptcode-request-forge]] 覆盖前端固定 key/iv 的请求伪造；本卡是车机 OTA 服务端下发会话密钥的场景。
- **TLS/证书固定**：若 OTA 走 HTTPS 且无法解密，需要设备侧密钥、证书固定绕过或从固件中提取密钥。
- **边界**：session_key 每次会话不同、OTA 使用 AES-GCM/CTR 且带 nonce、或响应有签名/HMAC 校验时，仅按前置 IV 的 AES-CBC 解密不成立，需要按实际协议调整。

## 检测与防御

- 防御：OTA 会话密钥应通过 TLS 等安全信道下发，避免在 HTTP/可截获通道明文返回；使用一次性密钥、非零随机 IV 与 AEAD（AES-GCM）并加签名/HMAC。
- 防御：启用证书固定与双向认证，防止中间人抓包；对 OTA 请求做设备身份与权限校验（admin 标志不能仅由客户端声明）。
- 检测：监控明文 HTTP 的 OTA handshake、响应中出现 `session_key` 字段、同一密钥被用于大量 OTA 请求；检测异常的 admin/特权 `vehicle_type`。
- 响应：轮换泄露的会话密钥、修复 OTA 协议、排查是否可伪造 admin OTA 指令导致车辆被控制。
