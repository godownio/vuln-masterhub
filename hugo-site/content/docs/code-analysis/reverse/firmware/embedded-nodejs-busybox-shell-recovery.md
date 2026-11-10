---
id: embedded-nodejs-busybox-shell-recovery
title: 利用嵌入式设备内置 node 执行 js 下载 busybox 赋权并恢复反弹 shell
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: 设备内置解释器滥用
tags:
- fortigate
- nodejs
- busybox
- limited-shell
- firmware
severity: medium
confidence: high
status: draft
created: '2026-11-08'
updated: '2026-11-08'
url: /docs/code-analysis/reverse/firmware/embedded-nodejs-busybox-shell-recovery/
draft: false
kb_aliases:
- nodejs busybox 提权
- 受限 shell 恢复
---

# 利用嵌入式设备内置 node 执行 js 下载 busybox 赋权并恢复反弹 shell

## 一句话结论

FortiOS 内置 Node.js（/bin/node，v16.14.2，仅能以 `node*` 通配搜索到）且 `node xx.js` 可直接执行；在仅有只读/受限命令执行的设备上，把下载+chmod+symlink+反弹 shell 的逻辑写进 js 由 node 渲染，可绕过"文件无执行权限、shell 被阉割"的双重限制，完成 busybox 落地、赋权（fs.chmodSync 0o755）、软链接与 net.connect 反弹 shell。

## 原理

设备 shell 被裁剪且漏洞利用写文件无 x 权限时，native 命令行难以完成 chmod；但 Node.js 运行时以 root 身份执行其 js，`fs.chmodSync` 是 node 进程内的系统调用、不依赖外部 chmod 程序，`fs.symlinkSync`/`net.Socket`/`child_process.execSync` 同理——解释器成为绕过文件权限与命令缺失的万能执行器。TFTP/HTTP 下载同样可由 js 内 execSync(`tftp ...`) 或 http.get 完成，规避 shellcode 传参长度限制（execl 第七参数会覆盖 shellcode 导致崩溃的问题）。

## 触发条件

- 已在某嵌入式/裁剪设备上获得命令执行（可运行 `/bin/node xx.js`）；
- 设备文件系统内置 node（FortiOS 在 /node-scripts/migadmin 目录伴生）；
- 允许下载文件（tftp/wget/http 均可）。

## 利用步骤

1. 命令执行原语下载 busy.js（tftp get octet）到 /tmp。
2. 执行 `/bin/node busy.js`（execve 传 argv=["/bin/node","/busy.js",NULL]）。
3. busy.js 内容：execSync 下载 busybox → `fs.chmodSync(path,0o755)` 赋权 → `fs.symlinkSync` 建 sh/ls/wget 等软链 → `child_process.spawn(busybox,['sh'])` 管道接 net.Socket 反弹到攻击者 4444。
4. 或用 down.js（http.get 写流下载 + chmod）代替 tftp；获得 /tmp/busybox 后回到带 sh 环境攻击流程（telnetd -l /tmp/sh -b 0.0.0.0 -p 22）。
5. 验证：攻击机 nc -lnvp 4444 收到回连，执行 ls 确认。

## PoC

无 PoC（js 逻辑如上；原文验证：node busy.js 无回显但成功落地 /tmp/busybox，反弹 shell 收到连接并可执行命令）。

## 变体与关联

- 变体：设备内置 python/lua/perl 等其他解释器时同思路（os.chmod/subprocess）；下载通道可换 ICMP/DNS 分片等隐蔽方式。
- 关联：FortiOS SSL-VPN 堆溢出未认证 RCE（命令执行来源）；FortiGate 固件 patch 与 smartctl（实验环境对照）；execve shellcode 布参技巧（argv/envp 数组入栈）。

## 检测与防御

- 检测：设备进程树出现 node 执行非 node-scripts 目录 js 文件、/tmp 出现新可执行文件、非常规出站连接（4444 等高位端口）。
- 防御：最小化内置解释器暴露、/tmp noexec 挂载、出口 ACL 白名单、对 node 执行路径做完整性审计。
