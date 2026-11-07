---
id: ctf-web-git-history-debug-secret-jwt-hmac-audit
title: .git 泄露旧提交调试密钥：伪造 HS256 auditor JWT + HMAC 签名调用内部审计接口
type: scenario
domain: ctf
path: ctf/web
technique: git-history-secret-jwt-hmac-internal-api
tags:
- ctf
- web
- git
- source-leak
- jwt
- hs256
- hmac
- signature-forgery
- privilege-escalation
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:12:30+08:00'
  notes: 已对照原文与图08-12核对：main.js 指向 /.git/HEAD、refs/heads/master 取 commit、index 404 改用 Git_Extract（图09 恢复出 legacy_probe_stub.py 及 .55cf35 备份）、auditor/audit2025 登录得 RS256 role=user JWT（图10）、jwt.io 用 INTERNAL_DEV_SECRET 伪造 HS256 role=auditor（图11）、审计页提交 node_id/timestamp/sign 并经服务端代理（图12），均与卡片一致；HMAC-SHA256(secret, node_id:ts) 与 60s 时间窗来自旧文件注释。未验证点：PoC 未在本机复跑；CTF 环境无组件版本；frontmatter 无 sources/source_url。
url: /docs/ctf/web/ctf-web-git-history-debug-secret-jwt-hmac-audit/
draft: false
kb_aliases:
- 夜班审计台
- .git 泄露
- Git_Extract
- .git/index 404
- JWT 调试密钥
- INTERNAL_DEV_SECRET
- HMAC-SHA256 node_id ts
- 内部审计接口签名伪造
---

## 一句话结论

Web 根目录暴露 `.git` 且 `.git/index` 缺失时，常规 GitHack 会失败，但用 Git_Extract 从 `HEAD`/`refs`/`objects` 仍能恢复仓库；历史提交与备份文件中保留了 JWT 调试密钥和内部接口 HMAC 密钥，攻击者用默认审计账号登录后，把 RS256 token 改成用泄露密钥签名的 HS256 token 伪造 `role=auditor`，再按泄露的签名规则生成 `HMAC-SHA256(secret, node_id:ts)`，经审计页代理调用内部接口拿到 flag。

## 原理

- **.git 暴露与恢复**：Git 的 dumb HTTP 协议把 `HEAD`、`refs/heads/*`、`objects/*` 暴露为静态文件。GitHack 等工具依赖 `/.git/index` 来还原工作区，目标若删除了 index（返回 404），就改用直接遍历 `HEAD`/`refs`/objects 的 Git_Extract 之类工具恢复完整提交历史。
- **密钥进入版本库**：开发者在旧提交或备份文件（如 `legacy_probe_stub.py` 及其带后缀的历史版本）中写过内部签名逻辑与密钥；后续提交虽然删除了当前文件中的密钥，但 Git 对象不可变，旧 blob 仍可从历史中取出。
- **JWT 算法白名单混用**：服务端解码逻辑对 `alg=RS256` 使用 `audit_rsa_pub.pem` 验签，对 `alg=HS256` 使用 `INTERNAL_DEV_SECRET` 验签；两种算法都接受，且 HS256 的对称密钥已在源码中泄露。HS256 是共享密钥 HMAC，知道密钥即可签发任意 claims，因此把普通用户 token 的 header 改为 HS256、payload 的 `role` 改为 `auditor`，用泄露密钥重新签名即可通过。
- **内部接口信任代理与共享 HMAC**：审计员页面由服务端代理向内部审计进程发请求，请求源是 localhost，满足内部接口的 `LOCAL_ONLY` 限制；页面只要求提交 `node_id`、`timestamp`、`sign` 三个字段，签名规则为 `HMAC-SHA256(SERVER_SECRET, f"{node_id}:{ts}")`，时间窗 60 秒。密钥与消息格式都已从旧提交泄露，攻击者可以离线计算合法签名。
- 这条链成立的关键不是单一漏洞，而是“源码泄露 → 密钥泄露 → 算法白名单混用 → 内部接口只依赖共享 HMAC”四层信任的叠加。

## 触发条件

- Web 站点根目录或子目录暴露 `.git`，`HEAD`/`refs`/`objects` 至少部分可读；`.git/index` 可能缺失。
- 仓库历史或备份文件中包含内部接口密钥、JWT 调试密钥、签名消息格式、默认账号等敏感信息。
- 服务端 JWT 校验同时接受 RS256 与 HS256，且 HS256 使用源码中的固定密钥；角色字段来自 token 且未在服务端二次校验。
- 存在可登录的审计/普通账号（示例为默认账号 `auditor/audit2025`），且审计员页面会代理调用内部接口。
- 内部接口只校验共享 HMAC 与 localhost 来源，没有额外的独立身份或 nonce 防重放。

## 利用步骤

1. 请求 `/.git/HEAD` 与 `/.git/refs/heads/master`，确认 `.git` 泄露并取得当前 commit 哈希；若 `/.git/index` 返回 404，放弃依赖 index 的 GitHack，改用 Git_Extract 遍历 refs/objects 恢复仓库。
2. 在恢复出的工作区与历史提交中搜索 `SECRET`、`JWT`、`HMAC`、`sign`、`password` 等关键字；重点查看旧版本文件和带后缀的备份文件，提取 `SERVER_SECRET`、`INTERNAL_DEV_SECRET`、JWT 接受算法列表、签名消息格式与默认审计账号。
3. 用默认审计账号登录，取得合法 JWT；解码 header/payload，确认签发算法为 RS256、`role=user`、`sub=auditor`，记录 `iss`、`iat`、`exp` 等字段格式。
4. 将 header 改为 `{"alg":"HS256","typ":"JWT"}`，payload 的 `role` 改为 `auditor`，保留 `sub`/`iss`/时间字段，用 `INTERNAL_DEV_SECRET` 做 HMAC-SHA256 签名，替换请求中的 token。
5. 访问审计员节点状态页面，填入目标节点（如 `core-storage-01`）、当前秒级时间戳和按泄露规则计算的签名，提交后由服务端代理请求内部接口，响应返回 flag 或节点状态数据。

## PoC

JWT 伪造（示例密钥来自目标源码/历史，实际使用时替换为恢复出的值）：

```python
import base64, hashlib, hmac, json, time

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
now = int(time.time())
payload = b64url(json.dumps({
    "sub": "auditor",
    "role": "auditor",
    "iat": now,
    "exp": now + 1800,
    "iss": "夜班审计台",
}, ensure_ascii=False, separators=(",", ":")).encode())

signing_input = f"{header}.{payload}".encode()
sig = b64url(hmac.new(b"ISCC_2026_JWT_DEBUG_KEY_#9527", signing_input, hashlib.sha256).digest())
print(f"{header}.{payload}.{sig}")
```

内部接口签名：

```python
import hashlib, hmac, time

node_id = "core-storage-01"
ts = str(int(time.time()))
sign = hmac.new(
    b"ISCC_SERVER_SECRET_REAL",
    f"{node_id}:{ts}".encode(),
    hashlib.sha256,
).hexdigest()
print(node_id, ts, sign)
```

```text
# 审计员页面提交
node_id   = core-storage-01
timestamp = <当前秒级时间戳>
sign      = <上述 HMAC-SHA256 十六进制串>
```

## 变体与关联

- `.git` 恢复变体：`.git/index` 存在时可用 GitHack/gitdumper 直接还原；index 缺失时用 Git_Extract 遍历 `HEAD`/`refs`/objects；目录 403 但子文件可读时同样可以逐个下载对象。
- JWT 变体：RS256 公钥当 HMAC 密钥的算法混淆（[[web-generic-jwt-rs256-hs256-confusion]]）、`alg:none`、`kid`/`jku` 注入；本例是“HS256 调试密钥随源码泄露”，与公钥混淆不同。
- 内部接口变体：签名消息可换成 `timestamp:path:body` 等格式；若存在 nonce/时间窗，需要先通过源码确认；localhost 限制可通过服务端代理、SSRF 或反向代理绕过。
- 关联：[[pentest-recon-git-directory-exposure-source-recovery]]（.git 目录暴露与 GitTools 恢复）、[[pentest-recon-github-repo-history-secret-mining]]（历史提交密钥挖掘）、[[web-generic-jwt-example-config-hardcoded-secret]]（硬编码/泄露 HS256 密钥伪造）、[[web-generic-auth-api-signature-method-scope-replay-bypass]]（API 签名规则绕过）。

## 检测与防御

- 检测：Web 访问日志出现 `/.git/HEAD`、`/.git/refs/`、`/.git/objects/`；同一账号的 JWT 算法从 RS256 突变为 HS256；审计接口的 `sign` 参数出现异常请求；源码仓库历史中包含 `SECRET`/`HMAC` 等关键字。
- 防御：部署产物排除 `.git` 目录，Web 服务器统一拒绝所有点文件；密钥不写入源码/历史，使用密钥管理服务并定期轮换，泄露后立即吊销。
- 防御：JWT 固定单一算法，不要把对称与非对称算法放进同一白名单；角色与权限从服务端存储读取，不信任 token 中的 `role`；内部接口使用独立身份（mTLS、服务账号）而不是共享 HMAC。
- 加固：默认账号强制修改或禁用；内部接口增加 nonce/请求 ID 与更短的时间窗，记录并告警来自代理的异常签名请求；定期扫描 Git 历史中的敏感信息。
