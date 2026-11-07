---
id: web-generic-auth-api-signature-validation-differential-test
title: API 签名校验存在性三路对照检测
type: scenario
domain: web
path: web/generic/auth
technique: api-signature-validation-differential-test
aliases:
- 签名校验检测
- sign 校验绕过检测
- 三路对照测试
- 签名族指纹
- SignatureCheckPlugin
tags:
- api
- signature
- auth
- differential-testing
- md5
- hmac
- jwt
- idor
- pentest
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V5
  verified_at: '2026-11-04T21:39:54+08:00'
  notes: 已对照原文与8张图核对；六族指纹、置信度公式、三路对照与正反两案例一致；原文正文与截图的响应长度/权重小数存在轻微出入（116 vs 156、0.16 vs 0.15），不影响方法结论，卡片采用正文口径；无组件版本；未执行 PoC
---

## 一句话结论

面对带 `sign`、`timestamp`、`nonce` 的 API，不必先逆向前端签名算法：先用参数指纹判断签名族，再发送“正确签名 / 错误签名 / 去除签名”三路请求，比较状态码、响应体长度与响应体 MD5；若三路完全一致，即可判定后端没有实际校验签名，后续参数篡改、IDOR、Mass Assignment 可直接进行。

## 原理

- API 签名的生成逻辑在前端/客户端，算法、salt、密钥对能打开 F12 或反编译客户端的人都是透明的；签名的实际安全价值取决于后端是否对每个请求独立校验。
- 常见缺陷有三类：
  1. **从未实现**：前端按文档生成 sign，后端校验中间件没写、被注释或只在部分环境生效；
  2. **条件性跳过**：测试/预发布环境不校验，或 IP 白名单/内部网判定错误导致外网请求被当作内部请求；
  3. **只校验格式**：只检查 32 位 hex、长度或正则，不比对内容。
- 三类缺陷的共同表现是：错误签名、缺失签名、格式正确但内容随机的签名，都能获得与正确签名相同的业务响应。
- 因此判定不应基于单次请求，而应做对照实验：只改变签名相关字段，保持业务参数、Cookie、Header 不变，比较响应是否逐字节等价。
- 先做签名族指纹，是为了确定“哪些字段要改”。签名族由参数名/Header 名集合的交集识别，常见六族：
  - `md5_timestamp_random`：`sign/signature` + `timestamp/ts` + `random/nonce`；
  - `md5_body_hash`：`sign/hash/md5`，无时间戳/随机数；
  - `hmac_sha256`：`sign/hmac/mac` + `timestamp/ts` + `nonce/random`；
  - `jwt_bearer`：`Authorization: Bearer <JWT>`；
  - `api_key_header`：`X-API-Key`/`X-Key`；
  - `oauth2_token`：`Authorization: Bearer <token>`，token 不以 `eyJ` 开头。
- 置信度可用简单加权：`0.5 + 0.2×|sign_hits| + 0.15×|time_hits| + 0.15×|nonce_hits|`，上限 1.0。时间戳/随机数字段权重较低，因为它们也可能是普通业务字段。
- 时间戳字段存在通常意味着可能有防重放；随机数字段存在意味着可能有 nonce 一次性校验。对照测试时应同步更新这些字段，避免把“过期/重放拒绝”误判成“签名校验生效”。

## 触发条件

- 目标 API 请求中包含签名相关字段（`sign`/`signature`/`hash`/`hmac`/`mac`）或签名 Header（`Authorization`、`X-API-Key`）。
- 攻击者能重放请求并修改参数，且持有有效会话/Cookie（若接口需要登录）。
- 业务响应可区分成功/失败（状态码、业务 code、响应体），且响应体不是完全动态（否则 MD5 比较会失效）。
- 测试请求应使用与基线相同的 Cookie/Header/会话，避免 Session 绑定导致签名差异。

## 利用步骤

1. 抓取一个带签名的请求，列出所有参数名与 Header 名。
2. 指纹识别：用六族字段集合做交集，得到候选签名族、置信度、`anti_replay`、`nonce_check`。
3. 路 A（基线）：保持原请求不变，记录状态码、响应体长度、响应体 MD5、业务 code。
4. 路 B（错误签名）：把签名字段替换为明显错误值（如 `INVALID_SIGNATURE_TEST_sign`），时间戳改成明显过期值，随机数改成固定值；其余业务参数不变。
5. 路 C（去除签名）：删除签名字段、时间戳、随机数，只保留业务参数；其余不变。
6. 比较三路：状态码相同、响应体长度相同、响应体 MD5 相同 → 签名未被执行实际校验。
7. 若 B 被拒绝而 C 也失败，需区分是签名校验还是框架参数必填校验（400 且提示 required/missing → 可能是后者）。
8. 判定“未校验”后，直接对业务参数做篡改、越权、IDOR、Mass Assignment 测试；判定“已校验”则回退到前端 JS 逆向。

## PoC

```http
### 路 A：基线（正确签名）
POST /api/course/select HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Cookie: JSESSIONID=...

student_code=20240101&course_id=C205&term=2024_2
&sign=4a7b8c3d1e5f6a2b9c0d3e4f5a6b7c8d
&timestamp=1719500000&nonce=547291
```

```http
### 路 B：错误签名 + 过期时间戳 + 固定 nonce
student_code=20240101&course_id=C205&term=2024_2
&sign=INVALID_SIGNATURE_TEST_sign&timestamp=1719400001&nonce=99999
```

```http
### 路 C：去除所有签名字段
student_code=20240101&course_id=C205&term=2024_2
```

```python
# 三路等价判定（结构示意）
import hashlib, requests

def probe(body):
    r = requests.post(URL, data=body, headers=HEADERS, cookies=COOKIES, timeout=10)
    return r.status_code, len(r.content), hashlib.md5(r.content).hexdigest(), r.text

a = probe(base_body)
b = probe(bad_sign_body)
c = probe(no_sign_body)

print("A", a[:3])
print("B", b[:3])
print("C", c[:3])

if a[:3] == b[:3] == c[:3]:
    print("signature not enforced: proceed to parameter tampering / IDOR")
elif b[0] in (401, 403) and c[0] in (400, 401, 403):
    print("signature enforced: fall back to JS reverse engineering")
else:
    print("inconclusive: check response echo, required-param 400, WAF, nonce/timestamp rules")
```

说明：PoC 为结构示意，需替换 URL、Cookie、参数与签名值；未在目标环境执行。

## 变体与关联

- 变体（按签名族的启发式绕过，仅在签名确实被校验且实现有缺陷时尝试）：
  - `md5_timestamp_random`：固定 sign + 过期 timestamp，测试是否只校验时间窗而不校验 sign 内容；
  - `md5_body_hash`：空 body + `sign=md5('')`（`d41d8cd98f00b204e9800998ecf8427e`），测试是否只校验 body 是否为空；
  - `hmac_sha256`：在 sign 参数中声明/切换到 MD5，测试后端是否按客户端声明选择校验函数、残留已废弃算法分支；
  - `jwt_bearer`：解码 payload，尝试 `alg=none` 并去掉签名；
  - `api_key_header`：从前端 JS 中搜索硬编码 API Key，复用合法 Key 做越权；
  - `oauth2_token`：测试 `client_credentials` 是否能获取超出授权码流程的 scope。
- 关联：[[web-generic-auth-cookie-base64-identity-forgery]]（客户端身份可伪造的另一类认证缺陷）；[[web-generic-auth-qdrant-internal-grpc-auth-bypass]]（认证校验缺失/条件跳过）；[[pentest-recon-web-config-robots-credential-leak]]（前端/配置泄露凭据）。
- 不确定点：绕过矩阵是启发式规则，不是通用解法；成功率取决于后端实现缺陷。原文样本量有限（4 个教育系统），比例不构成统计结论。

## 检测与防御

- 检测：服务端日志中同一接口出现“签名错误/缺失签名但业务成功”的请求；响应体回显 sign/timestamp；WAF 规则命中异常 sign 格式。对 API 网关可统计签名失败率与业务成功率。
- 防御：后端对每个请求执行真实签名校验，不能只依赖前端生成；所有环境（测试/预发布/生产）一致启用。
- 防御：校验内容而不只校验格式；使用常量时间比较；签名覆盖方法、路径、业务参数、时间戳、nonce 与 body 哈希。
- 防御：时间戳窗口限制 + nonce 一次性校验（服务端缓存已用 nonce）；签名密钥不放在前端；API Key 不下发到客户端 JS。
- 防御：区分 400（参数缺失/框架校验）与 401/403（签名/鉴权失败），避免把框架行为误认为安全校验；对签名校验异常做告警而非吞掉。
- 防御：核心接口叠加服务端授权校验（对象级权限），即使签名被绕过也不能直接越权。
