---
id: code-analysis-reverse-firmware-routeros-nova-message-ipc-debug
title: RouterOS Nova Message IPC 格式与进程逆向调试环境：x3 命名空间、JS/Winbox 入口、execute_milo 取 root 与 gdbserver attach
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: routeros-nova-message-ipc-reverse-debug
aliases:
- RouterOS Nova Message
- Nova 消息格式
- loader/system.x3
- x3_parse
- execute_milo
- RouterOS 取 root shell
- WinboxMessage 构造
- /nova/bin/snmp 调试
tags:
- routeros
- mikrotik
- firmware
- reverse
- ipc
- nova-message
- gdbserver
- winbox
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V688
  verified_at: '2026-11-13T16:08:31+08:00'
  notes: 已对照原文与3张图核对：Nova Message 类型/键编码/SYS命令、system.x3 进程映射(snmp=34)、JS(80)/Winbox(8291)入口、execute_milo 取root流程、gdbserver attach 与原文一致；已把防御行的 www/8291/8291 笔误改为 www/80、Winbox/8291、FTP。未验证点：未实际搭建 RouterOS 环境复跑（文章为不可信数据）
---

## 一句话结论

RouterOS 的内部服务（如 `/nova/bin/snmp`）通过自定义 Nova Message（Type-Key-Value 的进程间通信格式）接收 www(80)/mproxy(8291) 转发来的请求；做漏洞研究时可按“解析 `/nova/etc/loader/system.x3` 得到进程号 → 用 execute_milo 在虚拟机里取得 root shell → FTP 上传静态 gdbserver 附加到目标进程 → 用 WinboxMessage/JSON 构造 Nova 消息触发”的路径，在真实固件上完成逆向调试与崩溃定位。

## 原理

- **Nova Message 格式**：键值对形式 `{bff0005:1, uff0006:0x1, uff0007:0xfe000d, s1:'admin', Uff0001:[13,7]}`。每个 key 的首字母是类型：`b` bool、`u` 32 位整数、`q` 64 位整数、`s` string、`r` raw、`a` IPv6、`m` message，以及大写数组类型 `B/U/Q/S/R/A/M`。
- **Key 编码**：key 的低 24 位才是真正的 key，格式 `0xGGVVVV`（`GG`=group，`VVVV`=value）。group 例：`0xFF` SYS、`0xFE` STD、`0xFD` LOCAL、`0x01` NET 等。SYS group 的关键值包括 `SYS_REQID=0xFF0006`、`SYS_CMD=0xFF0007`、`SYS_USER=0xFF000A`、`SYS_POLICY=0xFF000B`、`SYS_TO=0xFF0001`、`SYS_FROM=0xFF0002` 等。
- **命令语义**：`SYS_CMD` 决定动作，如 `0xfe0001` getPolicies、`0xfe0002` getObj、`0xfe0003` setObj、`0xfe0004` getAll、`0xfe0005` addObj、`0xfe0006` removeObj、`0xfe000d` get、`0xfe000e` set 等；配合 `SYS_TO=[进程号, handler]` 即可把消息投递给指定服务。
- **传输入口**：RouterOS 的 JS 交互实际走 HTTP 80（www 进程解析请求后转发给目标进程），Winbox 交互走 8291（mproxy 进程解析转发）；两者最终都把用户请求转成 Nova Message 交给内部服务，因此构造攻击面时既可用 WinboxMessage，也可用对应的 JSON 形式。
- **进程命名空间**：init 只启动 loader，loader 管理其它进程；子进程映射写在 `/nova/etc/loader/system.x3`，可用 tenable/routeros 的 `x3_parse` 解析（例如 `/nova/bin/log -> 3`、`/nova/bin/snmp -> 34`）。消息中的 `SYS_TO` 进程号即来自该映射。
- **取得 root shell（仅虚拟机可行的 execute_milo）**：RouterOS 的 `/flash/bin` 下 milo 启动时不做完整性校验，可被覆盖。流程：FTP binary 模式上传 busybox/milo/gdb → 关机后挂载 Linux LiveCD → 对上传文件 chmod、把 milo 覆盖进 `/flash/bin`、用 busybox 提供 sh → 重启 RouterOS 后运行 `execute_milo` → telnet 1270 端口得到 root shell。较新版本（约 ≥6.44.6）Winbox 协议变化，execute_milo 应使用 JSProxySession 并改用 80 端口。
- **调试**：把目标程序（如 `/nova/bin/snmp`）复制到可访问目录并经 FTP 取回；上传静态 gdbserver 后 `gdbserver :12345 --attach $(pidof snmp)` 附加到运行中进程，再用伪造 Nova 消息触发路径；崩溃信息也可在 `/flash/rw/logs/` 查看。

## 触发条件

- 可运行 RouterOS 虚拟机（注意 Hyper-V 与 VMware Workstation 的兼容问题，必要时关闭 Hyper-V）并能通过 FTP/Winbox/JS 与设备交互。
- 需要 root shell 的调试场景可用 execute_milo（虚拟机）；实体机需换 netboot/FOISted 等其它 jailbreak 方式。
- 目标进程号可通过 system.x3 解析获得；构造消息需要能通过 www/mproxy 的会话（登录后）或直接投递到对应进程。

## 利用步骤

1. 启动 RouterOS（原文 7.1.1）并配置网络；按需开启 SNMP：`snmp set enabled=yes`、`snmp community print/add`。
2. 取 root：FTP 上传 busybox/milo/gdb，LiveCD 中 chmod 并把 milo 覆盖 `/flash/bin`，重启后运行 `execute_milo -i <ip> -p <port> -u <user> --password <pass>`，`telnet <ip> 1270` 获得 shell（新版本用 JSProxySession + 80 端口）。
3. 解析 `/nova/etc/loader/system.x3`（x3_parse）确认目标服务进程号（如 snmp=34）。
4. 复制目标二进制并用 FTP 取回分析；上传静态 gdbserver，`gdbserver :12345 --attach $(pidof snmp)` 附加。
5. 用 WinboxMessage 构造 Nova 消息（`set_to(34, 0x1)`、`set_command(0xfe0005)`、`add_u32(0x14, ...)`、`add_string(0x5, ...)`、`set_request_id(1)`），或等价 JSON `{u14:0xfffffffe,uff0006:1,uff0007:0xfe0005,s5:'a'*512,Uff0001:[34,1]}`，触发目标 handler 并在 gdb 中观察寄存器/栈。
6. 崩溃后结合 `/flash/rw/logs/` 与 gdbserver 回溯定位漏洞函数。

## PoC

```c
// WinboxMessage 构造 Nova 消息（示例：向 snmp 进程 handler 1 发 addObj）
char payload[513];
memset(payload, 'a', sizeof(char) * 512);
WinboxMessage msg;
msg.set_to(34, 0x1);          // 进程号来自 system.x3
msg.set_command(0xfe0005);    // SYS_CMD: addObj
msg.add_u32(0x14, 0xfffffffe);
msg.add_string(0x5, payload);
msg.set_request_id(1);
```

```text
等价 JSON：{u14:0xfffffffe,uff0006:1,uff0007:0xfe0005,s5:'a'*512,Uff0001:[34,1]}
```

```bash
# 调试环境
./gdbserver :12345 --attach $(pidof snmp)
```

## 变体与关联

- **关联 CVE 根因**：[[code-analysis-cve-2022-45315-routeros-nova-snmp-offset-oob-call]] 用本文消息格式构造触发 CVE-2022-45315 的越界读与间接调用。
- **关联固件仿真**：[[code-analysis-reverse-firmware-qemu-system-mipsel-router-httpd]]、[[code-analysis-reverse-firmware-qemu-user-mips-ldpreload-gdb]]（其它路由固件/服务的仿真与 gdb 调试）；[[binary-pwn-stack-mikrotik-routeros-smb-netbios-cve-2018-7445-vdso-ret2syscall]]（RouterOS 另一漏洞的利用）。
- **关联入口**：[[web-generic-file-inclusion-mikrotik-winbox-cve-2018-14847-traversal-read]]（Winbox 协议侧的另一类滥用）。
- **变体**：不同 RouterOS 版本的 Nova Message 键/命令可能增减，需以目标固件 `/nova/etc/loader/system.x3` 与二进制中的 handler 表为准；分析其它内部服务（radius、user 等）方法相同。
- **边界**：实体机无法用 execute_milo；Hyper-V 环境下 VM 可能无法启动；新版 RouterOS 对 milo/协议有变化，环境方法需按版本调整。

## 检测与防御

- **防御**：RouterOS 升级到官方修复版本；关闭不必要的 SNMP/管理服务并限制 www/80、Winbox/8291、FTP 等管理入口来源；不要把设备管理端口暴露到公网。
- **检测**：设备上出现非常规 FTP 上传（busybox/milo/gdb）、`/flash/bin/milo` 被替换、milo 启动、1270 端口监听/连接；进程被 gdbserver attach（调试端口）；`/flash/rw/logs/` 中目标服务异常崩溃。
- **审计**：对 RouterOS 固件做离线分析时优先解析 system.x3 与 Nova Message handler 表，建立“进程号→服务→消息命令”的映射，便于后续漏洞触发与回归验证。
