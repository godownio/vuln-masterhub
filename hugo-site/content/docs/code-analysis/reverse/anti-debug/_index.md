---
title: 反调试
weight: 1
---

# 反调试

## 这层是什么

反调试检测与绕过、反反调试。

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
| [JS Function.prototype.toString 环境检测的干净 iframe 绕过](code-analysis-reverse-anti-debug-js-tostring-environment-bypass/) | verified | high | 2026-11-05 |
| [JS 字符串拼接/eval 动态 debugger 的 Hook 拦截绕过](code-analysis-reverse-anti-debug-js-dynamic-debugger-hook/) | verified | high | 2026-11-05 |
| [JS 定时 debugger 反调试的 DevTools 绕过](code-analysis-reverse-anti-debug-js-infinite-debugger-bypass/) | verified | high | 2026-11-05 |
| [JS 禁用 F12/右键/选择的前端限制绕过](code-analysis-reverse-anti-debug-js-devtools-shortcut-bypass/) | verified | high | 2026-11-05 |
| [JS 窗口尺寸检测反调试的 Hook 绕过](code-analysis-reverse-anti-debug-js-window-size-detection-bypass/) | verified | high | 2026-11-05 |
| [Linux 恶意样本反沙箱/反调试：ptrace/TracerPid、LD_PRELOAD、父进程与资源特征组合](code-analysis-reverse-anti-debug-linux-sandbox-environment-probes/) | verified | medium | 2026-11-06 |
| [Loader 反沙箱与反调试：时间加速、桌面/主机名与 DebugPort 检测](code-analysis-reverse-anti-debug-sandbox-environment-checks/) | verified | high | 2026-11-04 |
| [NtQuery* 调试信息反调试：DebugPort/DebugObjectHandle/DebugFlags 与参数篡改绕过](code-analysis-reverse-anti-debug-ntquery-debug-info-argument-patch/) | verified | medium | 2026-11-07 |
| [QEMU TCG 反 VM 检测：TB 原子性竞态与未对齐 SIMD 异常差异（附 Windows API/CPUID/SIDT 检查与绕过）](code-analysis-reverse-anti-debug-qemu-tcg-anti-vm-tb-atomicity-unaligned-simd/) | verified | low | 2026-11-07 |
| [TLS 回调反调试：PE 加载前执行检测，静态清零 TLS 目录/回调数组绕过](code-analysis-reverse-anti-debug-tls-callback-pe-null-patch/) | verified | high | 2026-11-07 |
| [TracerPid 反调试下 LD_PRELOAD 钩 memcmp + 差分输入恢复魔改 RC4/仿射校验](code-analysis-reverse-anti-debug-ldpreload-memcmp-hook-differential-transform/) | verified | high | 2026-11-07 |
| [VEH 反调试与反反调试：自定义异常判断调试器 + 劫持 VEH 双链表移除/抢先保护处理程序](code-analysis-reverse-anti-debug-veh-custom-exception-debugger-detection-hijack/) | verified | medium | 2026-11-07 |
| [Windows PEB 字段反调试：BeingDebugged/Ldr/ProcessHeap/NTGlobalFlag 的识别与内存补丁](code-analysis-reverse-anti-debug-peb-fields-patch/) | verified | medium | 2026-11-07 |
| [Windows 免杀沙箱指纹组合检测：注册表/VM 进程/MAC OUI/资源/uptime/用户名/调试器与 explorer 父进程校验](code-analysis-reverse-anti-debug-windows-sandbox-fingerprint-parent-check/) | verified | high | 2026-11-06 |
| [动态反调试家族：SEH/INT 2D/TF、RDTSC 时序与 0xCC/CRC 校验的识别与绕过](code-analysis-reverse-anti-debug-exception-timing-checksum-bypass/) | verified | medium | 2026-11-07 |
| [反沙箱路径陷阱：GetCurrentDirectoryW 仅在盘符根目录返回尾随反斜杠，%s 直接拼接文件名使子目录中的样本提前退出](code-analysis-reverse-anti-debug-getcurrentdirectoryw-root-trailing-backslash/) | verified | medium | 2026-11-06 |
| [恶意样本延迟执行与多信号条件触发：uptime/时间窗/网络/CPU/内存门控与分阶段持久化](code-analysis-reverse-anti-debug-delayed-conditional-trigger/) | verified | medium | 2026-11-06 |
| [截屏像素统计做视觉环境键控：以桌面壁纸特征识别沙箱而不触发高敏感行为](code-analysis-reverse-anti-debug-visual-environmental-keying-screenshot/) | verified | high | 2026-11-05 |
| [银狐安装器反虚拟机三件套：vmGuestLib、WMI 热区与 PhysicalDrive0 磁盘容量](code-analysis-reverse-anti-debug-silverfox-installer-vm-detection/) | verified | high | 2026-11-05 |
| [银狐远控反分析组合：进程关键化防杀、轮询挂起与窗口标题/杀软名单探测](code-analysis-reverse-anti-debug-critical-process-window-title-av-detection/) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
