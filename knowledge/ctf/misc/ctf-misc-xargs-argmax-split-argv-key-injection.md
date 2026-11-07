---
id: ctf-misc-xargs-argmax-split-argv-key-injection
title: xargs 超过 ARG_MAX 分批执行：第二批 argv[1] 被注入为 AES key，已知密钥解密 flag
type: scenario
domain: ctf
path: ctf/misc
technique: xargs-argmax-split-argv-key-injection
aliases:
- xargs ARG_MAX 拆分
- xargs 多批执行
- argv[1] 注入
- 已知 key 加密 flag
- Encryption Service
- xargs 参数注入
tags:
- ctf
- misc
- xargs
- argmax
- command-line
- aes-cbc
- argv-injection
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V161
  verified_at: '2026-11-06T09:57:55+08:00'
  notes: 已对照原文核对：cat OUTFILE | xargs enc.py、随机 key+用户输入+flag 布局、padding 触发分批、第二批 argv[1] 成为已知 AES key、取最后一段 IV+CT 解密均与原文一致。注意：实际先触发的是 GNU xargs 默认 --max-chars≈128KiB（原文笼统称 ARG_MAX≈2MB），但不影响 131KB padding 的利用；未复跑 PoC。
---

## 一句话结论

后端用 `cat "$OUTFILE" | xargs /app/enc.py` 把文件内容按空白拆成参数，而文件内容是“随机 hex key + 用户输入 + flag”。当输入超过 Linux `ARG_MAX` 时，xargs 会把参数拆成多批、多次 `execve`；第二批的第一个单词成为第二次执行的 `argv[1]`（AES key）。攻击者用大量 padding 让 flag 落到第二批，并把自己指定的 16 字节 hex key 放在第二批开头，就能拿到“用已知 key 加密的 flag 密文”，本地解密即可。

## 原理

- **xargs 的参数构造**：`xargs cmd` 从 stdin 读入按空白分隔的单词，尽可能多地把它们作为参数追加到 `cmd` 后执行。单次 `execve` 的参数+环境变量总大小受 `ARG_MAX`（Linux 常见 2MB 左右，受 `RLIMIT_STACK`/内核配置影响）限制；超过时 xargs 自动分批，每批重新执行一次命令。
- **key 的来源**：文件开头是随机 hex key（32 个 hex 字符 = 16 字节），随后是用户输入、最后是 flag。正常情况下第一批的第一个参数就是随机 key，`enc.py` 用它做 AES key。
- **分批后的错位**：攻击者发送 `"A " * 65500` 这样的长 padding，把第一批填满；紧跟一个已知的 16 字节 hex key（如 `00112233445566778899aabbccddeeff`）。xargs 在第一批装不下后，从该 key 开始新的一批，因此第二次执行 `enc.py` 的 `argv[1]` 就是攻击者已知的 key。
- **flag 落点**：flag 在文件末尾，必然落在最后一批；只要该批的 `argv[1]` 是已知 key，`enc.py` 就会用已知 key 加密 flag，输出 `IV + ciphertext` 的 hex。
- **解密**：从服务端输出中提取最后一段 hex（前 32 个 hex 字符为 IV，其余为密文），用已知 key 做 AES-CBC 解密，得到 flag。
- **为什么不是命令注入**：攻击者不需要注入 shell 元字符；利用的是 xargs 的“分批”语义与“argv 位置”错位，属于参数注入/逻辑漏洞。

## 触发条件

- 后端使用 `xargs` 把文件内容作为参数传给加密脚本，且脚本把 `argv[1]` 当作 key。
- 文件布局为“随机 key + 用户可控输入 + 敏感数据（flag）”，敏感数据在末尾。
- 用户输入长度可超过 xargs 单批上限，且服务端把每批输出都返回/记录。
- 加密脚本使用可预测的对称加密（AES-CBC），key 长度/格式明确（16 字节 hex）。

## 利用步骤

1. **确认分批判定**：发送超长输入，观察服务端是否返回多段加密结果；若只有一段，增大 padding。
2. **构造 payload**：`padding = "A " * 65500`（约 131KB），后接已知的 16 字节 hex key；发送后以 `EOF` 结束输入。
3. **收集输出**：服务端会输出每批 `IV+CT` 的 hex；用正则提取长度 ≥64 的 hex 段。
4. **选最后一段**：最后一段对应含 flag 的批次；前 32 hex 为 IV，其余为密文。
5. **本地解密**：`AES.new(bytes.fromhex(known_key), AES.MODE_CBC, iv).decrypt(ct)`，去除 PKCS#7 padding 即得 flag。
6. **调参**：不同环境 `ARG_MAX`/xargs 批次大小不同；若 key 没落在第二批开头，调整 padding 长度/单词数量。

## PoC

```python
from pwn import remote
from Crypto.Cipher import AES
import binascii, re

KNOWN_KEY_HEX = "00112233445566778899aabbccddeeff"
KNOWN_KEY = binascii.unhexlify(KNOWN_KEY_HEX)

io = remote(HOST, PORT)
io.sendlineafter(b"End with EOF", ("A " * 65500 + KNOWN_KEY_HEX).encode())
io.sendline(b"EOF")
out = io.recvall(timeout=20).decode()

hex_blocks = re.findall(r'[0-9a-fA-F]{64,}', out)
ct_hex = hex_blocks[-1]                    # 最后一批（含 flag）
iv = binascii.unhexlify(ct_hex[:32])
ct = binascii.unhexlify(ct_hex[32:])
pt = AES.new(KNOWN_KEY, AES.MODE_CBC, iv).decrypt(ct)
print(pt.rstrip(b'\x00').decode(errors='ignore'))
```

原文在 `"A "*65500` 下成功触发分批并解出 flag；不同 `ARG_MAX` 环境需调整 padding。本卡不执行 PoC。

## 变体与关联

- **其它分批工具**：`xargs -n`/`-L` 明确分批、`find -exec {} +`、`parallel`、`make` 参数列表都可能产生“第二批参数位置错位”。
- **其它参数注入**：把 `--`、`-f`、`--file` 等选项放在第二批开头，可改变脚本行为；与“文件名以 - 开头”类注入结合。
- **加密模式**：CBC/ECB/CTR 均可，只要 key 可控；CBC 需要 IV，通常随密文一起输出。
- **关联**：[[ctf-misc-short-circuit-expensive-expression-quaternary-timing]]（另一类服务端逻辑侧信道）、[[pentest-initial-access-redis-module-sed-filename-argument-injection]]（参数/文件名注入）、[[web-golang-unicode-casefold-json-field-curl-arg-injection]]（argv 注入）。
- **边界**：需要用户输入能进入 xargs 的参数流、敏感数据在末尾、输出可见；若服务端限制输入长度、使用 `xargs -0`/固定参数、或加密脚本从环境变量/文件读 key，利用失败。

## 检测与防御

- **不要用 xargs 拼参数**：改用 `execve` 参数数组/语言内读取文件，避免“单词拆分 + 分批”语义。
- **固定 key 来源**：key 从安全存储/环境变量读取，不要把它放在用户可控的文件/参数流中；对加密脚本做参数校验（key 必须来自可信通道）。
- **限制输入**：服务端限制用户输入长度/单词数，避免触发多批；对输出做分页/审计。
- **检测**：xargs 同一命令在短时间内多次执行、参数列表含超长 padding、加密脚本收到非预期 key 格式、输出多段密文；监控 `ARG_MAX` 附近的输入。
- **响应**：轮换 key、审计是否已有敏感数据被已知 key 加密外泄、修复参数构造逻辑。
