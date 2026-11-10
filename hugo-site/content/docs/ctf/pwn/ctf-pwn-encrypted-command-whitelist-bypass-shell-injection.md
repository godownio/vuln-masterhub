---
id: ctf-pwn-encrypted-command-whitelist-bypass-shell-injection
title: encrypt 白名单正则 vs run 只校验首命令 + shell=True：用泄露密钥伪造加密命令实现命令注入 RCE
type: scenario
domain: ctf
path: ctf/pwn
technique: encrypted-command-whitelist-bypass-shell-injection
tags:
- ctf
- pwn
- command-injection
- whitelist-bypass
- aes-ecb
- subprocess
- shell
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-12
  verified_at: '2026-11-08T07:15:35+08:00'
  notes: 已对照原文核对：原文实测 run 4411c07136a38c501609edae77d28f2a 回显 CTF{hmac_w0uld_h4ve_b33n_bett3r}，首 token ls 过白名单、分号后 cat /flag 被 shell=True 执行，链路真实打通；PoC 段占位仅出于保守。未验证点为未在本机复跑。
url: /docs/ctf/pwn/ctf-pwn-encrypted-command-whitelist-bypass-shell-injection/
draft: false
kb_aliases:
- encrypted runner
- 加密命令白名单绕过
- run 分支只校验首 token
- subprocess shell=True
- ls . ;cat /flag
- 伪造密文命令注入
---

## 一句话结论

当服务提供「加密命令」与「执行命令」两个分支，加密分支对整条输入做白名单正则 `re.fullmatch`，而执行分支解密后**只校验第一个 token** 是否在白名单、随后把整条解密结果交给 `subprocess.run(command, shell=True)` 时，攻击者只要能伪造合法密文（如先泄露 AES 密钥），就能把 `ls . ;cat /flag` 之类的注入命令加密后提交给 run：首命令 `ls` 通过校验，分号后的命令被 shell 执行，实现命令注入/读 flag。

## 原理

- 加密分支有严格校验：`whitelist = {"date": None, "echo": "[\\w. ]+", "ls": "[/\\w]+"}`，`cmd = rest.split(" ")[0]` 必须在白名单，且把 `cmd + 正则` 拼成 regex 对 `rest` 做 `re.fullmatch`，不满足则拒绝加密。因此**通过正常 encrypt 无法加密含 `;`、`|`、`&` 的命令**。
- 执行分支却弱得多：`command = helper("decrypt", rest).rstrip(b"\x00")`，`cmd = command.split(b" ")[0]`，只判断 `cmd in whiteset`（即首 token 是 date/echo/ls），**后面的部分完全不校验**。
- 随后 `subprocess.run(command, shell=True, ...)` 用 shell 解释整条字符串，于是 `;`、`&&`、`|`、反引号等在 shell 层都是命令分隔符，注入部分照常执行。
- 关键在于两条分支的信任边界不一致：加密时「整条输入」被校验，执行时只校验「解密结果的首 token」。若攻击者能绕过加密分支（自己用泄露/已知的密钥生成密文，或加密接口另有缺陷），就能构造任意解密结果。
- 本题密钥是 AES-ECB-128、本地 `key` 文件；通过另一处 AES 自实现缺陷泄露完整 key 后，本地用标准 AES-ECB 加密 `b"ls .  ;cat /flag"` 得到密文，直接 `run <密文>` 即可。ECB 无 IV、单块 16 字节，密文可直接复用。
- 命令块要满足 16 字节对齐/补零：`ls .  ;cat /flag` 恰好 16 字节，`rstrip(b"\x00")` 会去掉尾部填充。

## 触发条件

- 服务存在「解密后执行」的接口，且解密结果只按首 token 做白名单校验、用 `shell=True` 执行整条字符串。
- 攻击者能构造出会被服务端正确解密的密文：已知/泄露对称密钥，或存在加密预言机/密文篡改能力。
- 注入命令长度适配分组/补零规则，首 token 必须是白名单命令。

## 利用步骤

1. 审计 chal.py：确认 encrypt 分支正则白名单、run 分支只取首 token 校验、`shell=True`。
2. 取得加密密钥（本题由 AES 自实现类型误用缺陷泄露，见本批对应卡）。
3. 本地用该密钥 AES-ECB 加密注入命令 `b"ls .  ;cat /flag"`（首 token `ls` 合法，分号后为 `cat /flag`），得到 hex 密文。
4. 向服务发送 `run <hex 密文>`；服务端解密得 `ls .  ;cat /flag`，首 token `ls` 通过白名单，shell 执行到 `;cat /flag`。
5. 从 `Output:` 回显读取 flag。

## PoC

```python
# 前置：已通过密钥泄露得到 16 字节 key（占位）
from Crypto.Cipher import AES
key = bytes.fromhex("<16-byte-key>")
text = b"ls .  ;cat /flag"            # 首 token ls 合法；注入在 ; 之后
enc = AES.new(key, AES.MODE_ECB).encrypt(text)
print(enc.hex())
# nc 连接后：
# run <上面输出的 hex>
# Output: ... CTF{...}
```

（最小化示意，key/flag 为占位，未执行任何 PoC；注入命令仅作结构示意。）

## 变体与关联

- 变体：白名单首命令可换 `echo`/`date` 等；分隔符可用 `;`、`&&`、`|`、`` `...` ``；若长度超 16 字节需按 ECB 多块构造并注意 `\x00` 填充与 `rstrip`。
- 关联：前置是「AES 自实现 int 类型误用 → sbox 越界 → 密钥泄露」（本批另有对应卡）；也可用「加密预言机 + 密文拼接/重放」在未知密钥下达成类似效果（ECB 块可裁剪拼接）。
- 关联：与库内「raw 协议透传 + 弱派生 admin token + 命令注入」「各类 shell=True 参数拼接命令注入」同属命令注入族；本卡特有在「加密/执行两分支校验不对称 + 需先伪造合法密文」。
- 边界：危害是任意命令执行/读 flag；若无法伪造密文则该链不成立。

## 检测与防御

- 检测：审计「解密/反序列化后执行」路径是否只校验首 token、是否使用 `shell=True`；监控解密结果里出现 `; & | \`` 等元字符。
- 防御：对解密后的**整条命令**做与加密分支同等强度的白名单校验；避免 `shell=True`，改用参数列表 + 固定可执行程序；对命令做 HMAC/认证加密（AEAD，如 AES-GCM）防止密文伪造，题目总结亦指出 `hmac would have been better`；最小权限运行子进程。
