---
id: web-python-framework-debug-feedback-trace-pickle-leak
title: 调试反馈接口按 trace_id 回显序列化堆栈：hex 编码 pickle 对象内嵌 flag
type: scenario
domain: web
path: web/python/framework
technique: debug-feedback-trace-serialized-object-leak
aliases:
- trace_id 回显
- stack_trace 泄露
- pickle hex
- 灵感笔记
- 错误反馈接口
- 调试信息泄露
- 序列化对象泄露
tags:
- python
- flask
- debug
- information-disclosure
- trace
- pickle
- error-handling
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:16:08+08:00'
  notes: 已对照原文与图05核对：/api/v1/project/detail 拒绝后返回 trace_id，/feedback 的 stack_trace 为 hex pickle（8004...），解码得 type=FLAG_OBJECT、flag=ISCC{c4refu11_debug_tr4ce_l34k_1d0r}、project_id=flag-project-001、timestamp，与卡片一致。未验证点：PoC 未本机复跑；原文无受影响版本；frontmatter 无 sources/source_url。
---

## 一句话结论

应用在错误响应中返回 `trace_id`，并提供 `/feedback` 接口按该 ID 回显完整 `stack_trace`；当堆栈里包含内部对象的序列化结果（本题是 hex 编码的 Python pickle 字典）时，攻击者无需突破授权即可从序列化字节中还原出 flag、项目 ID、时间戳等内部数据。

## 原理

- 典型链路：请求受保护资源 → 服务端拒绝并返回错误 JSON，其中带 `trace_id`；前端提示“可凭 trace_id 到 `/feedback` 联系作者”；`/feedback` 把该 trace_id 对应的异常上下文/堆栈原样返回。
- 本题的 `stack_trace` 字段值是一段十六进制字符串：
  ```text
  80049591000000000000007d94288c0474797065948c0b464c41475f4f424a454354948c04666c6167948c24495343437b...7d942e
  ```
  以 `8004` 开头、包含 `7d`（空字典）、`8c`（短字符串）等 opcode，是 Python `pickle` 协议 4 的序列化字节；hex 解码后是一个字典，键为 `type`、`flag`、`project_id`、`timestamp`，值为 `FLAG_OBJECT`、flag 字符串、`flag-project-001`、时间戳。
- 也就是说，服务端在构造错误上下文时把内部对象（含 flag）`pickle.dumps()` 后 hex 编码，再塞进 `stack_trace` 返回给客户端；这不是 pickle 反序列化 RCE，而是**序列化数据泄露**：攻击者只需 hex 解码/`pickletools.dis` 或直接搜索可打印字符串，就能读到秘密。
- 前置信息泄露：`/api/admin/hint` 直接返回 `POST /api/v1/project/detail` 的请求格式；访问 `/project/flag-project-001` 后 Cookie 会变化，拿到可用于 `/feedback` 的会话；受保护接口返回的 `trace_id` 是反馈接口的查询键。
- 根因是“调试/反馈功能把异常上下文与内部对象序列化后返回给用户”，没有做字段白名单、脱敏或仅服务端留存。

## 触发条件

- 应用开启调试/详细错误模式，或自研的 `/feedback`、`/debug`、`/trace` 接口会把 `stack_trace`、异常上下文返回给客户端。
- 错误响应包含可用的 `trace_id`/`request_id`，且反馈接口按该 ID 查找并回显内部记录。
- 堆栈/上下文对象中包含敏感字段（flag、密钥、token、内部路径），且序列化时未脱敏。
- 攻击者能触发一个错误并获得 trace_id；部分实现还要求携带触发错误后的 Cookie/会话。

## 利用步骤

1. 枚举/泄露 API：本题 `/api/admin/hint` 返回了 `POST /api/v1/project/detail` 的 Host 与 JSON 格式。
2. 向受保护接口提交请求（如 `{"project_id":"flag-project-001"}`），拿到 `error`、`message`、`trace_id`。
3. 按提示访问 `/project/flag-project-001` 使 Cookie 更新，保留新会话。
4. 向 `/feedback` 提交 `trace_id=<上一步的 ID>`，获取 JSON 响应中的 `stack_trace`、`metadata`、`request_data` 等字段。
5. 对 `stack_trace` 做 hex 解码：`bytes.fromhex(...)`；用 `pickletools.dis` 查看结构，或直接 `strings`/正则搜索 `ISCC{`、`flag`。
6. 从反序列化结果或可打印字符串中提取 flag；继续检查 `request_data`、`metadata` 是否泄露其他内部字段。

## PoC

```http
POST /api/v1/project/detail HTTP/1.1
Host: target
Content-Type: application/json

{"project_id":"flag-project-001"}
```

```json
{
  "error": "访问被拒绝",
  "message": "您无权查看此笔记",
  "trace_id": "102cf740-0cb7-4247-81ca-d135bcf84d24"
}
```

```http
POST /feedback HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

trace_id=102cf740-0cb7-4247-81ca-d135bcf84d24
```

响应中的 `stack_trace` 为 hex；本地解析：

```python
import pickletools

h = "80049591000000000000007d94288c0474797065948c0b464c41475f4f424a454354948c04666c6167948c24495343437b...7d942e"
data = bytes.fromhex(h)
print(data)                 # b'\x80\x04\x95...'，pickle 协议 4
pickletools.dis(data)       # 查看字典键值
# 或直接提取可打印字符串
import re
print(re.findall(rb"[ -~]{6,}", data))
```

## 变体与关联

- **编码变体**：hex、base64、URL 编码、JSON 嵌套；`stack_trace` 可能是 Python `repr`、`traceback.format_exc()`、`pickle.dumps()`、`json.dumps()` 的结果。
- **入口变体**：`/feedback`、`/debug`、`/trace`、`/api/error`、Sentry/Django Debug Toolbar 等调试面板；`trace_id` 可能在响应头、错误 JSON 或前端日志中。
- **泄露内容变体**：flag、数据库连接串、JWT 密钥、内部服务 URL、源码路径、请求体中的凭据。
- **关联**：[[web-python-framework-flask-werkzeug-debug-pin-forgery]]（Flask 调试模式另一类风险）；[[web-python-ssti-jinja2-context-doc-get-chr-keyword-bypass]]（本题同场的模板上下文泄露）。
- **边界**：生产环境关闭调试、反馈接口只返回固定错误码、trace 记录只在服务端日志中保留、序列化前做字段脱敏时，本路径失效。

## 检测与防御

- **检测**：响应中出现 `trace_id`、`stack_trace`、`pickle`、`8004` 开头的 hex、`FLAG_OBJECT` 等特征；客户端对 `/feedback` 的异常高频查询；同一 trace_id 被非触发者访问。
- **防御**：生产环境关闭详细错误与调试接口；错误响应只返回通用错误码和随机 request_id，堆栈仅写服务端日志；反馈接口做鉴权、限流与字段白名单。
- **加固**：序列化内部对象前做敏感字段脱敏；不要把 flag/密钥放入异常上下文；日志访问最小权限；定期审计调试/反馈端点。
