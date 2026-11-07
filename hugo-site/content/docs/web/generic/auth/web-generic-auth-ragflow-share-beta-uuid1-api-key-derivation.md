---
id: web-generic-auth-ragflow-share-beta-uuid1-api-key-derivation
title: RAGFlow 分享 beta 泄露 uuid1 载体：枚举 time_low 推导 API key（CVE-2025-69286）
type: scenario
domain: web
path: web/generic/auth
technique: share-beta-uuid1-api-key-derivation
tags:
- auth
- api-key
- token-forgery
- uuid1
- predictable-random
- itsdangerous
- ragflow
- information-disclosure
- cve-2025-69286
cve:
- CVE-2025-69286
severity: high
confidence: high
affected_versions: RAGFlow < 0.22.0（0.22.0 修复）
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V105
  verified_at: '2026-11-05T22:57:21+08:00'
  notes: 已对照原文与图10核对beta解码、uuid1字段拆解、98万枚举与0.22.0 secrets修复；原文未展示候选token请求返回200的截图，属未完全验证点；CVE-2025-69286与<0.22.0版本标记与原文一致。
url: /docs/web/generic/auth/web-generic-auth-ragflow-share-beta-uuid1-api-key-derivation/
draft: false
kb_aliases:
- RAGFlow API key 推导
- CVE-2025-69286
- uuid1 可预测
- 分享链接 beta
- URLSafeTimedSerializer tenant_id
- API key 与分享 token 互推
---

## 一句话结论

RAGFlow 的 `generate_confirmation_token(tenant_id)` 用 `URLSafeTimedSerializer(tenant_id)` 把 `uuid.uuid1()` 签名后截取 `[2:34]` 作为 token；公开分享链接里的 `beta` 用同一函数生成，泄露了 uuid1 的 time_mid/version/clock_seq 和部分 time_low；攻击者用自己的 `user_id` 拿到 node（MAC），再枚举 time_low 首字符与相邻时间差（实测约 98 万次候选），即可推导出受害者的 API key，以受害者身份调用 API 拉取知识库数据。CVE-2025-69286 影响 0.22.0 之前，0.22.0 改为 `secrets.token_urlsafe(32)`。

## 原理

- **token 生成逻辑**：0.21.0 的 `api/utils/api_utils.py` 中，`serializer = URLSafeTimedSerializer(tenant_id)`，密钥直接使用 `tenant_id`；`get_uuid()` 返回 `uuid.uuid1()`；返回 `"ragflow-" + serializer.dumps(get_uuid(), salt=tenant_id)[2:34]`。三个问题叠加：密钥可预测（攻击者注册账号就有自己的 tenant_id）、uuid1 基于时间戳+MAC、序列化 payload 是 base64 明文（uuid 字符串直接可见）。
- **分享 beta 与 API key 同源**：分享链接 token（beta）也走这个函数，`beta = generate_confirmation_token(token).replace("ragflow-", "")[:32]`。分享链接公开、无需登录；beta 与 API key token 由相邻两次 `uuid1()` 调用生成，间隔微秒级，因此 beta 解码出的 uuid 主体与 API key 的 uuid 主体只差 time_low 的少量位。
- **截断没有保护作用**：`URLSafeTimedSerializer` 的完整输出是 `签名.时间戳.载荷` 三段点分隔 base64；`[2:34]` 从中间切，开头混着签名残留、尾部被截掉，直接解码是乱码。但载荷是明文 base64，用 `A` 填充对齐后 uuid 主体就露出来；签名被切掉后，作为密钥的 tenant_id 对恢复 payload 不再重要。
- **uuid1 字段拆解**：128 位分为 `time_low(32) - time_mid(16) - version(4) - clock_seq(14) - node(48)`；时间戳是 60 位、单位 100 纳秒，node 是 MAC。base64 明文暴露 time_mid、version、clock_seq，time_low 只缺首字符；node 可从攻击者自己账号的 `user_id`（也是 uuid1().hex）后 12 位拿到——同一台服务器上所有 uuid1 调用 node 相同。剩余只需枚举 time_low 首字符 16 种 × 相邻调用 delta 范围。
- **为什么能收敛**：同一进程内连续两次 uuid1 调用 time_low 相差很小；clock_seq 在同一进程内保持不变；实测命中 delta 为 -1380（微秒级），枚举量约 98 万，本地脚本可快速跑完。
- **验证方式**：RAGFlow 的 `_load_user` 中 API key 认证走 `Authorization` 头两段式，第二段直接查 `APIToken` 表；拿候选 token 拼 `Authorization` 调 API，200 即命中，401 继续。枚举脚本不必把 98 万候选全部请求一遍，delta 顺序扫描通常在某区间命中。
- **修复**：0.22.0 改为 `secrets.token_urlsafe(32)`，密码学安全随机，没有时间戳/MAC，推导路径断掉。

## 触发条件

- RAGFlow < 0.22.0（CVE-2025-69286）。
- 攻击者能拿到受害者的公开分享链接（`/chatbots/` 分享 bot、`/agentbots/` 分享链接等），即拿到 beta。
- 攻击者可自行注册账号，获得自己的 `tenant_id` 和 `user_id`（用于取 node 和构造候选）。
- API key 认证端点可达；token 校验没有严格速率限制（枚举验证需要一定请求量）。
- 受害者使用同一台服务器生成的 uuid1（同一 node）；若目标做了虚拟化/MAC 随机化，node 取法需按环境调整。

## 利用步骤

1. 注册自己的账号，记录 `tenant_id` 与 `user_id`；从 `user_id`（uuid1().hex）取后 12 位作为 node（MAC）。
2. 获取受害者公开分享链接中的 beta（无需登录）。
3. 对 beta 做 base64 解码/补齐：恢复 uuid 主体，得到 time_mid、version、clock_seq 和部分 time_low；确认 time_low 只缺首字符。
4. 枚举 time_low 首字符 16 种，并在相邻 uuid1 调用的 delta 范围内扫描（实测 delta -1380 附近，约 98 万候选）。
5. 对每个候选拼出 `ragflow-<候选>` 形式的 token，放入 `Authorization` 头调用任意 API；200 表示命中，401 继续。
6. 用命中的 API key 以受害者身份调用 API，拉取知识库/文档/会话数据；必要时结合其他漏洞扩大影响。

## PoC

原文未给出完整枚举脚本，以下为按文中逻辑构造的流程示意（未在本机执行）：

```python
import base64, uuid

# 1) 自己的 user_id 是 uuid1().hex，后 12 位是 node（MAC）
my_user_id = "<自己的 user_id>"
node = my_user_id[-12:]

# 2) 公开分享 beta（示例片段）
beta = "IzZGI3ODMwLTk1MmEtMTFmMS04MTZiLT"

# 3) URL-safe base64 补齐后解码，恢复 uuid 主体
#    itsdangerous 的 payload 是 base64 明文；beta 被截断，需按实际长度补 'A' 或 '='
raw = base64.urlsafe_b64decode(beta + "A" * ((4 - len(beta) % 4) % 4))
print(raw)  # 可看到 time_mid/version/clock_seq 和部分 time_low

# 4) 枚举 time_low 首字符（16 种）与相邻调用 delta，构造 uuid1 候选
#    time_low 已暴露后 7 个 hex 字符，仅首字符未知；delta 在微秒级范围内扫描
for first in "0123456789abcdef":
    for delta in range(-5000, 5001):
        # 组合 time_low / time_mid / version / clock_seq / node -> 候选 uuid
        # 生成候选 token 并请求 API 验证
        pass
```

```text
# 原文实测：
# token: ragflow-IzZGI3MmNjLTk1MmEtMTFmMS04MTZiLT
# beta :        IzZGI3ODMwLTk1MmEtMTFmMS04MTZiLT
# 解码后 token uuid 主体: 3db72cc-952a-11f1-816b-
# 解码后 beta  uuid 主体: 3db7830-952a-11f1-816b-
# time_mid/version/clock_seq 相同，time_low 仅少量差异；命中 delta = -1380
# 候选验证：Authorization 两段式，第二段查 APIToken 表；200 命中，401 继续
```

## 变体与关联

- **随机源变体**：uuid1（时间+MAC）、uuid4（随机但不应作密钥）、`time.time()` 拼接、`random`/`srand(time)`、自增 ID；审计时看到“时间/机器信息派生密钥”直接标红。
- **泄露载体变体**：公开分享链接、邀请码、密码重置 token、API key 前缀/后缀、日志中的 token 片段、前端配置；任何暴露 token 一部分的通道都可能把搜索空间缩小到可枚举。
- **token 结构变体**：itsdangerous `URLSafeTimedSerializer`、JWT 截断、base64 明文 payload、签名被截断；截断签名不等于安全，payload 仍可能泄露。
- **关联卡片**：[[crypto-prng-time-seeded-rand-rc4-auth-forge]]（时间种子弱随机伪造认证报文）、[[crypto-prng-srand-time-seed-2fa-code-prediction]]（时间种子验证码预测）、[[web-generic-auth-client-nonce-weak-sha1-signature-forgery]]（弱随机/弱签名伪造）。
- **边界**：原文在 RAGFlow 0.24.0 上做修复后对比、在旧版本逻辑上验证推导；PoC 未在本机执行。不同版本的 uuid 生成/截断位置、API key 认证头格式可能变化，需按目标调整。

## 检测与防御

- **随机源**：token/API key/会话密钥一律使用 `secrets.token_urlsafe` / `secrets.token_bytes` / CSPRNG；禁止 uuid1、uuid4、时间戳、MAC、自增 ID 参与密钥派生。
- **密钥管理**：不要用 `tenant_id` 等公开/可预测值作为签名密钥；使用服务端独立随机密钥 + HMAC，密钥不进客户端、不写日志。
- **token 设计**：不要在 token 中放明文 payload 后再截断签名；使用不可预测随机值作为 token，服务端存储哈希/映射；设置过期与撤销。
- **分享链接**：分享 beta 应是独立随机、可撤销的凭据，不能与 API key 同源；分享链接只授予最小范围，不泄露内部 uuid 结构。
- **检测**：监控 API key 认证的异常枚举（大量 401、短时间多候选）、分享链接高频访问、token 格式异常；审计 `uuid.uuid1()`/`time.time()` 拼接密钥的代码。
- **响应**：发现泄露后轮换 API key/分享 token，检查知识库访问日志，评估数据外带范围；升级到 0.22.0+。
