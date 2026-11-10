---
title: 调试
weight: 1
---

# 调试

## 这层是什么

断点、单步、内存与寄存器分析。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [CDP 读取 JS 调用栈局部变量：Debugger.paused 的 callFrames/scopeChain + Runtime.getProperties(objectId)](code-analysis-dynamic-debugging-cdp-callframe-scope-local-variables/) | verified | high | 2026-11-09 |
| [Delphi 注册对话框输入定位：DialogBoxParamW 回调 + GetDlgItem 条件断点 + GetWindowTextA](code-analysis-dynamic-debugging-delphi-dialog-getdlgitem-windowtext-locate/) | verified | high | 2026-11-07 |
| [OllyDbg 内存断点还原注册算法并写注册机：GetDlgItemTextA 定位输入缓冲，Name 大写 ASCII 累加 ^0x5678 与 Serial 十进制转整数 ^0x1234 比对](code-analysis-dynamic-debugging-ollydbg-memory-breakpoint-registration-keygen/) | verified | high | 2026-11-09 |
| [OllyDbg 爆破注册框：MessageBoxA 断点取栈返回地址定位关键跳转，je 改 jmp 后复制所有修改保存补丁](code-analysis-dynamic-debugging-ollydbg-messagebox-return-address-jcc-patch/) | verified | high | 2026-11-09 |
| [PHP 扩展 pwn 远程调试：gdbserver 附加 Apache mod_php 进程，等 vuln.so 加载后按 zif_ 符号下断](code-analysis-dynamic-debugging-php-extension-apache-gdbserver-zif-symbols/) | verified | medium | 2026-11-08 |
| [VEH 隐形断点与动态补丁：AddVectoredExceptionHandler 捕获异常后改 CONTEXT 控制程序流程](code-analysis-dynamic-debugging-veh-invisible-breakpoint-dynamic-patch/) | verified | high | 2026-11-07 |
| [VirtualProtect 运行时解密代码的 IDA 动态还原：断点执行解密后 U/C/P 重建函数](code-analysis-dynamic-debugging-virtualprotect-runtime-decrypt-ida/) | verified | high | 2026-11-05 |
| [Windows 消息断点：在 WndProc 分发处按 [ESP+8] 消息号拦截，定位按钮点击处理代码](code-analysis-dynamic-debugging-windows-message-breakpoint-wndproc-locate/) | verified | high | 2026-11-09 |
| [x64dbg 动态提取纤程 Loader 解密后的 shellcode：断点 ConvertThreadToFiber/VirtualAlloc/memcpy](code-analysis-dynamic-debugging-x64dbg-fiber-loader-shellcode-dump/) | verified | high | 2026-11-05 |
| [x64dbg 动态调试破解密码校验：改寄存器/ZF 与二进制补丁绕过本地及服务端验证](code-analysis-dynamic-debugging-crackme-password-check-patch/) | verified | medium | 2026-11-07 |
| [内存断点：VirtualProtectEx 改页保护（PAGE_NOACCESS/PAGE_EXECUTE_READ）实现页级读写执行监视](code-analysis-dynamic-debugging-memory-breakpoint-virtualprotectex-page-protection/) | verified | high | 2026-11-09 |
| [分片 shellcode 加载器：data_1..9.db 拼接 + 16 字节块 XOR 解密 + error.log 明文回退](code-analysis-dynamic-debugging-split-shellcode-file-loader-xor/) | verified | high | 2026-11-05 |
| [多层编码 shellcode 还原：hex→RC4→ASCII85 解码链与 VirtualAlloc 断点转储](code-analysis-dynamic-debugging-multi-layer-shellcode-decrypt-dump/) | verified | high | 2026-11-05 |
| [客户端软件加密配置还原：CreateFileA/ReadFile API 断点锁定密文缓冲区，内存访问断点定位逐字节 xor/add 解密循环（xor 0xBD + add 0x69）提取服务器地址](code-analysis-dynamic-debugging-ini-config-xor-add-decrypt-api-breakpoint/) | verified | high | 2026-11-08 |
| [序列号数据约束性搜索：在假注册码 ±0x90 内存范围用 WinHex/OllyDbg 找真序列号（TraceMe 12121212→2470）](code-analysis-dynamic-debugging-serial-data-constraint-memory-proximity/) | verified | high | 2026-11-08 |
| [异构架构二进制（PowerPC/ARM/AArch64/MIPS）的 QEMU user-mode 运行与 gdb-multiarch 远程调试环境搭建](code-analysis-dynamic-debugging-heterogeneous-arch-qemu-gdb-multiarch/) | verified | medium | 2026-11-09 |
| [抓包 DevTools 自身 WebSocket 反推 Chrome DevTools Protocol 调用：id/method/params 与 result 逐条复现 UI 操作](code-analysis-dynamic-debugging-devtools-websocket-cdp-traffic-reverse/) | verified | high | 2026-11-09 |
| [挖矿木马矿池地址提取：静态 IDA 字符串找 xmrig JSON 配置（algo/url 字段）+ 动态 x64dbg 对 ws2_32 网络 API 下断读 RCX](code-analysis-dynamic-debugging-miner-pool-address-extraction-static-xmrig-config-dynamic-getaddrinfow-breakpoint/) | verified | high | 2026-11-08 |
| [硬件断点命中判别：DR6 的 B0–B3 区分硬件断点单步异常与 EFLAGS.TF 单步](code-analysis-dynamic-debugging-hardware-breakpoint-dr6-single-step-source/) | verified | high | 2026-11-09 |
| [调试器里用 GetProcAddress 断点捕获动态解析的隐藏 API：读栈上函数名、Ctrl+F9 取 EAX 返回地址后下断](code-analysis-dynamic-debugging-getprocaddress-breakpoint-hidden-api/) | verified | high | 2026-11-09 |
| [软件断点（CC/INT3）实现：首字节改写 0xCC、命中后恢复单步再回写，API/条件/消息断点皆同源](code-analysis-dynamic-debugging-software-breakpoint-int3-byte-patch/) | verified | high | 2026-11-09 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
