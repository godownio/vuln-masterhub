---
id: code-analysis-reverse-obfuscation-rsa-oaep-dom-public-key-parameter-forge
title: 前端 RSA-OAEP 参数加密逆向：隐藏 DOM 公钥还原与任意 id 密文伪造
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: rsa-oaep-dom-public-key-parameter-forge
aliases:
- htccheck 伪造
- data-x/data-s 公钥还原
- __k 隐藏节点
- rsaEncryptWithPEM
- 好靶场 JS 对抗
- 前端 RSA 公钥加密参数
tags:
- javascript
- reverse
- frontend-encryption
- rsa-oaep
- sha256
- webcrypto
- node-forge
- pem
- idor
- parameter-forgery
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V197
  verified_at: '2026-11-06T23:01:42+08:00'
  notes: 已对照原文及图01-18核对：d()/__resolvePem从#__k的data-x/data-s去分隔符→反转→atob还原PEM的步骤与源码一致；WebCrypto/forge均为RSA-OAEP/SHA-256，后缀10086与明文规则一致；图08/18显示id=1并分别用明文1与110086重放均返回admin flag。原文未标注组件版本，未设affected_versions；未在目标复跑。
---

## 一句话结论

页面把 RSA 公钥拆成带分隔符、反转、Base64 的字符串藏在隐藏 DOM 节点 `#__k` 的 `data-x`/`data-s` 中，前端用该公钥对 `id`（或 `id + 固定后缀`）做 RSA-OAEP(SHA-256) 加密生成 `htccheck`；由于公钥本身不是秘密，攻击者按同样逆变换还原 PEM，再对任意 `id` 重新加密，即可伪造 `htccheck` 越权读取管理员数据。

## 原理

- **前端加密不是授权边界**：RSA 公钥可以公开，任何人都能用它加密；前端加密只保证传输内容的机密性/防篡改（且仅相对于没有浏览器的旁观者），不能证明“这个密文是服务端认可的某个用户/id”。如果服务端把解密后的明文直接当作身份/权限依据，就存在参数伪造空间。
- **公钥的隐藏方式**：页面在 `DOMContentLoaded` 时创建隐藏 `div#__k`，`data-x` 存放处理过的公钥，`data-s` 存放分隔符（示例 `::`）。处理流程是：把 PEM 公钥的字符序列插入分隔符 → 整体反转 → Base64 编码。还原函数 `d()`/`__resolvePem()` 做逆操作：
  1. `data-x.split(data-s).join("")` 去掉分隔符；
  2. `joined.split("").reverse().join("")` 反转；
  3. `atob(reversed)` 做 Base64 解码，得到 `-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----` 的 PEM。
- **加密算法**：`rsaEncryptWithPEM(pem, input)` 用 RSA-OAEP，哈希 SHA-256，MGF1 也是 SHA-256：
  - WebCrypto：`importKey("spki", derBytes, {name:"RSA-OAEP", hash:"SHA-256"}, false, ["encrypt"])`，`subtle.encrypt({name:"RSA-OAEP"}, key, new TextEncoder().encode(input))`，`btoa(String.fromCharCode(...new Uint8Array(ciphertext)))`；
  - 回退 node-forge：`forge.pki.publicKeyFromPem(pem)`，`publicKey.encrypt(forge.util.encodeUtf8(input), "RSA-OAEP", {md: forge.md.sha256.create(), mgf1: forge.mgf1.create(forge.md.sha256.create())})`，`forge.util.encode64(...)`。
  两条路径算法参数一致，输出都是 Base64 密文。
- **明文构造陷阱**：第一例中前端把固定字符串 `"2"` 加密成 `htccheck`，`id` 字段单独传 `2`，但加密函数没有把 `id` 绑定进去；服务端却用 `htccheck` 解密结果做身份校验，于是把 `id` 改成 `1`、同时用同一公钥加密 `"1"` 就能通过。第二例在明文后追加固定后缀 `"10086"`（默认 `"2"` → `"210086"`，传 `"1"` → `"110086"`），伪造时必须保留该后缀。
- **为什么能成功**：公钥、算法、填充、编码、后缀全部在前端可见/可复现；服务端只验证“密文能被私钥解开且内容符合预期”，没有把密文与当前会话、服务端 nonce、一次性挑战绑定；业务层又缺少对象级授权（id=1 的管理员数据对普通用户可读）。
- **反调试只是干扰**：页面禁用右键/F12、`setInterval(debugger)`、窗口尺寸检测 DevTools，但这些不影响“保存页面源码/本地替换/一律不在此处暂停”等绕过；即使不调试，直接从 DOM 读 `data-x` 也能还原公钥。

## 触发条件

- 目标接口的请求体/参数中有加密的身份/校验字段（示例 `htccheck`），且该字段由前端 JS 生成。
- 页面存在隐藏节点（示例 `#__k`）或 JS 常量中保存公钥的变形数据；公钥算法为 RSA-OAEP/PKCS1v15 等可复现的非对称加密。
- 服务端把解密结果直接当作 id/用户名/权限依据，而未与当前会话或服务端挑战绑定；业务接口存在对象级授权缺失。
- 攻击者能访问页面、读取 DOM/JS、使用 Python/Node 等工具重新加密；接口无严格频控/风控。
- 前端反调试可被绕过（保存页面、DevTools 忽略断点、本地替换等）。

## 利用步骤

1. **抓请求**：用 Burp 拦截正常请求，记录加密字段（`htccheck`）、明文 `id`、Cookie/Token、URL 与 Content-Type。
2. **定位公钥**：在页面 DOM 中查找隐藏节点（如 `#__k`），读取 `data-x`/`data-s`；或在 JS 中搜索 `BEGIN PUBLIC KEY`、`RSA-OAEP`、`data-x`、`rsaEncryptWithPEM`、`__resolvePem`。
3. **还原 PEM**：去掉 `data-s` 分隔符 → 反转字符串 → Base64 解码；确认得到合法 PEM（`-----BEGIN PUBLIC KEY-----` 开头）。若页面有 `__resolvePem()`，也可直接在 Console 调用它取值。
4. **确认算法与明文格式**：查看加密函数，确认 RSA-OAEP/PKCS1v15、哈希（SHA-256）、MGF1、输出编码（Base64/Hex）、明文是否带前缀/后缀（示例 `"10086"`）、是否 JSON 序列化。
5. **伪造密文**：用 Python `cryptography` 或 `PyCryptodome` 对目标 `id`（及必要后缀）做同样加密，输出 Base64。
6. **重放**：把请求中的 `id` 改为目标值（如 `1`），`htccheck` 替换为新密文，保持 Cookie/Headers 不变，发送。
7. **验证**：若返回管理员数据/flag，说明服务端信任了前端密文；若失败，检查后缀、编码、OAEP 哈希/MGF1、PEM 是否还原正确。
8. **扩大影响**：枚举其他 id/用户标识，确认是否为水平/垂直越权；评估是否可批量拉取敏感数据。

## PoC

从 DOM 还原 PEM（Console 或保存的 HTML 中执行）：

```javascript
const el = document.getElementById('__k');
const dataX = el.getAttribute('data-x');
const dataS = el.getAttribute('data-s') || '::';
const joined = dataX.split(dataS).join('');
const reversed = joined.split('').reverse().join('');
console.log(atob(reversed)); // PEM
```

Python 生成任意 id 的 `htccheck`（按原文脚本整理，未在目标上执行）：

```python
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

def resolve_pem(data_x: str, data_s: str = "::") -> str:
    joined = "".join(data_x.split(data_s))
    return base64.b64decode(joined[::-1]).decode("utf-8")

def rsa_oaep_sha256_b64(pem: str, plaintext: str) -> str:
    key = serialization.load_pem_public_key(pem.encode())
    ct = key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(ct).decode()

pem = resolve_pem(DATA_X, DATA_S)
# 第一例：明文就是 id 字符串
htccheck = rsa_oaep_sha256_b64(pem, "1")
# 第二例：明文 = 前缀 + 固定后缀 "10086"
# htccheck = rsa_oaep_sha256_b64(pem, "1" + "10086")
print(htccheck)
```

请求体示例：

```json
{"id": 1, "htccheck": "<上面生成的 Base64>"}
```

原文第一例把 `id` 从 2 改为 1、用同一公钥加密 `"1"` 后重放，成功返回管理员信息；第二例把 `h` 设为 `1`（明文 `"110086"`）生成 `htccheck`，重放后返回管理员 `flag`。PoC 未在本机执行；公钥、Cookie、flag 已脱敏。

## 变体与关联

- **公钥隐藏变体**：DOM 属性 `data-x`/`data-s`、JS 常量数组（`b[0]="-----BEGIN PUBLIC KEY-----"`）、字符串反转/分隔符/Base64 多层、CDN 动态加载 node-forge。
- **算法变体**：RSA-OAEP(SHA-256)、RSA-OAEP(SHA-1)、RSA PKCS#1 v1.5、RSA + AES 混合（RSA 加密 AES key，AES 加密 body）、ECDH/ECDSA。
- **明文变体**：纯 id、id+固定后缀（示例 `"10086"`）、JSON 字符串、时间戳/nonce 拼接；伪造时必须完全复现拼接顺序。
- **越权类型**：水平越权（改 id 读他人数据）、垂直越权（普通用户读 admin）、批量拉取（枚举 id/分页）。
- **关联**：[[code-analysis-reverse-frontend-request-response-encryption-automation]]（前端请求/响应加密逆向与 PyExecJS 自动化）、[[code-analysis-reverse-dynamic-key-encrypted-api-idor]]（动态密钥固定 + 越权）、[[code-analysis-reverse-obfuscation-js-aes-parameter-restore]]（AES 参数还原）、[[web-generic-auth-hybrid-rsa-aes-login-bruteforce]]（RSA+AES 登录爆破）、[[code-analysis-reverse-anti-debug-js-infinite-debugger-bypass]]（JS 反调试绕过）。
- **边界**：若服务端把密文与当前会话/一次性 nonce 绑定，或私钥解密后校验 id 必须等于会话用户，伪造失效；若使用服务端生成的挑战/时间窗口，需先获取挑战；前端反调试不影响公钥提取，但可能影响动态调试。

## 检测与防御

- **服务端授权**：不要用“前端加密的 id”作为身份/权限依据；身份必须来自会话（Cookie/Token 校验后的服务端状态），对象级授权在服务端按当前用户校验。
- **绑定与挑战**：若必须加密参数，把密文与当前会话、一次性 nonce、时间戳、请求签名绑定，服务端解密后校验绑定关系；不要让同一密文可跨用户/跨请求重放。
- **密钥管理**：公钥可以公开，但不要在前端放置可用于伪造身份的服务端密钥；私钥永远不出服务端；对加密参数做完整性签名。
- **检测信号**：同一会话短时间出现大量不同 id 的 `htccheck`、解密成功但 id 与会话不匹配、异常分页/枚举、前端加密字段格式变化；服务端记录解密失败/授权失败并告警。
- **前端加固**：反调试只能提高分析成本，不是安全边界；不要依赖禁用 F12/右键/debugger 保护公钥或算法。
- **测试建议**：对任何前端加密参数，先还原算法与密钥材料，再修改业务参数重放；把“加密”与“授权”分开评估，重点检查服务端是否真的按会话做对象级鉴权。
