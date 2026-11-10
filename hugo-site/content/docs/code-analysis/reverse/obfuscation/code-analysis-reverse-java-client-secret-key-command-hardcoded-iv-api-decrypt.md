---
id: code-analysis-reverse-java-client-secret-key-command-hardcoded-iv-api-decrypt
title: Java 客户端可查密钥 + 硬编码 IV：AES/CBC 保护的 API 敏感字段可被任意客户端解密
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: java-client-secret-key-fetch-hardcoded-iv-api-decrypt
tags:
- java
- reverse
- client
- aes-cbc
- hardcoded-iv
- key-management
- api-security
- traffic-decrypt
- pii
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V373
  verified_at: '2026-11-09T06:07:36+08:00'
  notes: 已对照原文全文与 16 张截图核对：img01 反编译代码 gsk()/gv() 发送 get_secret_key/get_version；img03 nc 取 key「ifiamdjyouleveme」(16 字节)、img05 WX.class 硬编码 IV「yyyouyouchecknow」与 AES/CBC/PKCS7Padding；img06 CyberChef 用该 key/IV 解出身份证号。放大复核 key/IV 均为 16 字符，与草稿一致。原文 get_secret_key/get_version 服务端口 22302、按用户名查询端口 24982，PoC 为通用化示例统一用单一 PORT，属正常简化；原文未给组件版本，affected_versions 已清除。PoC 未在目标执行。
url: /docs/code-analysis/reverse/obfuscation/code-analysis-reverse-java-client-secret-key-command-hardcoded-iv-api-decrypt/
draft: false
kb_aliases:
- Java 客户端密钥查询命令
- get_secret_key 泄露加密密钥
- jar 硬编码 IV
- AES/CBC 接口密文解密
- API 传输加密形同虚设
---

## 一句话结论

当服务端把 API 字段加密密钥通过客户端内置命令（如 `get_secret_key`）原样下发给任何连接者，且客户端代码里硬编码了 AES-CBC 的 IV 时，攻击者只要反编译客户端 jar、向服务端索取密钥，就能把截获或主动查询到的 `Base64` 密文（如身份证号）还原成明文，应用层传输加密对机密性保护完全失效。

## 原理

- **对称加密的机密性只来自密钥保密**：AES-CBC 的正确性不依赖算法隐藏，只要拿到 key、IV 和密文就能解密。IV 本身不需要保密，但它是解密的必要输入；把它和 key 一起放在客户端或下发接口中，攻击者就凑齐了全部解密要素。
- **客户端不是信任边界**：桌面客户端 jar 可被任意下载/解包/反编译（`jar tf` + CFR/JD-GUI/procyon），其中的 socket 命令封装方法会直接暴露服务端协议（如 `gsk()` 发送 `get_secret_key\n`、`gv()` 发送 `get_version\n`）。攻击者不需要逆向算法，只需照抄客户端行为。
- **服务端命令即密钥预言机**：如果服务端对 `get_secret_key` 这类命令不鉴权、不区分调用者，返回全局静态 key，那么"密钥在服务端"只是把密钥从客户端挪到了一个同样对所有客户端开放的位置；任何能连上服务的人都能取得它。
- **IV 硬编码在类中**：反编译加密类（示例为 `WX.class`）可直接读到 `ALGORITHM = "AES/CBC/PKCS7Padding"`、`INIT_VECTOR` 常量和 `SecretKeySpec(key.getBytes(), "AES")` 的密钥来源，从而确认填充方式与 IV。
- **API 还缺少对象级授权时危害叠加**：若服务端仅凭用户名/ID 返回该用户的加密身份证号，攻击者可以批量查询任意用户再本地解密，形成大规模 PII 泄露；加密只是把泄露延迟到"拿到 key 之后"。
- **为什么成立**：加密数据与解密材料走同一条对攻击者开放的信道；客户端的每一份副本都携带解密能力，服务端又把 key 交给任何自称客户端的人。因此该层加密只相当于编码。

## 触发条件

- 业务 API 对敏感字段（身份证号、手机号、地址等）做应用层 AES 加密，密文以 Base64/hex 形式出现在响应中。
- 存在可获取的客户端（jar/桌面程序/移动端），其中包含加密调用代码或协议命令。
- 服务端暴露密钥查询/下发命令或接口（如 `get_secret_key`），且无认证或认证可被普通用户通过；或密钥直接硬编码在客户端。
- 加密模式为 AES/CBC/PKCS7（或其他确定性分组模式），key 长度 16/24/32 字节，IV 固定或随密文传输。
- 查询接口缺少对象级授权，允许按用户名/编号查询他人数据（否则只能解密自己的数据，危害降级）。

## 利用步骤

1. 取得客户端 jar，`unzip -l`/`jar tf` 列出 class，反编译（CFR、JD-GUI、procyon）搜索 `AES`、`Cipher`、`SecretKeySpec`、`IvParameterSpec`、`getBytes`、`Socket`、`OutputStream` 等关键字。
2. 定位加密类，记录算法/模式/填充、IV 常量、key 的来源（硬编码字面量还是服务端命令/接口返回）。
3. 若存在 socket 命令封装，记录命令名与协议细节（换行结尾、host/port）；直接用 `nc` 或脚本复现：先 `get_version` 确认服务可达，再 `get_secret_key` 取得密钥。
4. 用普通用户身份或直接对用户名发起查询，获得该用户的 Base64 密文响应。
5. 本地 Base64 解码后用 key+IV 做 AES-CBC 解密并去 PKCS7 填充；CyberChef 可用 `From Base64 → AES Decrypt (CBC, key, IV)` 快速验证。
6. 自动化：对用户名字典循环执行"查询→解密"，汇总 PII；注意只应在授权测试环境执行。

## PoC

```python
import socket, base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

HOST, PORT = "target", 22302

def cmd(line: str) -> str:
    with socket.create_connection((HOST, PORT), timeout=5) as s:
        s.sendall(line.encode() + b"\n")
        s.shutdown(socket.SHUT_WR)
        return s.recv(65536).decode(errors="ignore").strip()

key = cmd("get_secret_key")            # 服务端对任意连接者下发的静态密钥（示例为 16 字节）
iv  = b"yyyouyouchecknow"              # 从反编译的客户端加密类中读到的 16 字节硬编码 IV
cipher_b64 = cmd("some_username")      # 查询目标用户返回的 Base64 密文
pt = unpad(AES.new(key.encode(), AES.MODE_CBC, iv).decrypt(base64.b64decode(cipher_b64)), 16)
print(pt.decode())                     # 明文敏感字段（示例为身份证号）
```

以上为按原文链路整理的最小复现；未在真实目标执行。密钥/IV 为示例值，实际以目标客户端与服务端返回为准。

## 变体与关联

- **key 直接硬编码在客户端**：无需服务端命令，反编译即可取 key；见 [[front-end-hardcoded-aes-ecb-traffic-decrypt]]（Web 前端 JS、AES/ECB）。
- **服务端按会话下发 key/IV**：仍可先请求密钥接口再加密/解密，属于同一根因；见 [[web-generic-auth-server-key-sign-oracle-replay-reproducible]]。
- **动态密钥前端加密接口**：页面每请求生成 key 时可断点固定并复用页面函数；见 [[code-analysis-reverse-dynamic-key-encrypted-api-idor]]。
- **IV 随密文传输**：常见做法是 `IV || ciphertext`，解密时切前 16 字节作 IV；若为 GCM 则取 nonce 并校验 tag。
- **编码差异**：响应可能是 hex、URL-safe Base64 或 Base64+URL 编码，先按客户端实现还原。
- **危害升级**：配合按用户名任意查询的授权缺失，可从单条 PII 解密升级为批量拖取。

## 检测与防御

- **不要把密钥查询能力暴露给客户端**：删除/鉴权 `get_secret_key` 类命令与调试接口；密钥下发只能面向强认证的会话，且下发短期、按会话派生的密钥，禁止全局静态 key。
- **客户端加密不等于数据安全**：key/IV 出现在客户端即视为公开；传输机密性应依赖 TLS，服务端按最小必要返回敏感字段并脱敏。
- **对象级授权**：查询接口必须校验当前用户对目标对象的访问权，禁止仅凭用户名/ID 返回他人 PII。
- **密钥管理**：支持轮换；一旦发现密钥可被客户端获取，轮换密钥并评估历史流量与已泄露数据。
- **检测**：审计发布包（jar/exe/APK/JS）中长度 16/24/32 的字符串常量与 `get_secret_key`、`get_version` 等调试命令；对自定义 TCP 协议做口令/命令鉴权与速率限制；在 API 网关注册并监控异常批量查询行为。
