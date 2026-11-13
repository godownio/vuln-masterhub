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
| [CLR 环境反调试双检查：Cor_Enable_Profiling 环境变量启用即退出 + 进程已加载 mscorjit/clrjit 即返回](code-analysis-reverse-anti-debug-clr-profiling-env-jit-module-checks/) | verified | medium | 2026-11-11 |
| [CPUID 反虚拟机：leaf 1 ECX 符号判 hypervisor 位 + GenuineIntel 型号白名单设置全局门控](code-analysis-reverse-anti-debug-cpuid-hypervisor-bit-intel-model-gate/) | verified | high | 2026-11-09 |
| [DBG_PRINTEXCEPTION_C/W 调试打印异常反调试：RaiseException 触发 0x40010006/0x4001000A，调试器吞掉异常则继续执行](code-analysis-reverse-anti-debug-dbg-printexception-wide-c/) | verified | high | 2026-11-12 |
| [Defender 模拟器与沙箱综合环境检测：\myapp.exe 进程名、Mpclient 导出 hash、无效句柄返回值与 1GB 堆分配](code-analysis-reverse-anti-debug-defender-emulator-sandbox-checks/) | verified | high | 2026-11-08 |
| [Festi 驱动反虚拟机：VMware 后门 I/O 端口 0x5658（'VX'/'VMXh'）探测 + Virtual PC vpcext 指令 SEH 检测](code-analysis-reverse-anti-debug-festi-vmware-backdoor-vpcext/) | verified | high | 2026-11-08 |
| [IDA 附加进程调试绕过启动期反调试：先裸跑再 Attach to process，命中后 F7 步入真实函数](code-analysis-reverse-anti-debug-attach-process-startup-bypass/) | verified | medium | 2026-11-08 |
| [JS Function.prototype.toString 环境检测的干净 iframe 绕过](code-analysis-reverse-anti-debug-js-tostring-environment-bypass/) | verified | high | 2026-11-05 |
| [JS 字符串拼接/eval 动态 debugger 的 Hook 拦截绕过](code-analysis-reverse-anti-debug-js-dynamic-debugger-hook/) | verified | high | 2026-11-05 |
| [JS 定时 debugger 反调试的 DevTools 绕过](code-analysis-reverse-anti-debug-js-infinite-debugger-bypass/) | verified | high | 2026-11-05 |
| [JS 禁用 F12/右键/选择的前端限制绕过](code-analysis-reverse-anti-debug-js-devtools-shortcut-bypass/) | verified | high | 2026-11-05 |
| [JS 窗口尺寸检测反调试的 Hook 绕过](code-analysis-reverse-anti-debug-js-window-size-detection-bypass/) | verified | high | 2026-11-05 |
| [Linux 恶意样本反沙箱/反调试：ptrace/TracerPid、LD_PRELOAD、父进程与资源特征组合](code-analysis-reverse-anti-debug-linux-sandbox-environment-probes/) | verified | medium | 2026-11-06 |
| [Loader 反沙箱与反调试：时间加速、桌面/主机名与 DebugPort 检测](code-analysis-reverse-anti-debug-sandbox-environment-checks/) | verified | high | 2026-11-04 |
| [NtDelayExecution 分 20 次 1 秒延迟：绕过沙箱睡眠跳过并借 hook 开销拖出仿真窗口](code-analysis-reverse-anti-debug-ntdelayexecution-segmented-sleep/) | verified | high | 2026-11-09 |
| [NtQuery* 调试信息反调试：DebugPort/DebugObjectHandle/DebugFlags 与参数篡改绕过](code-analysis-reverse-anti-debug-ntquery-debug-info-argument-patch/) | verified | medium | 2026-11-07 |
| [QEMU TCG 反 VM 检测：TB 原子性竞态与未对齐 SIMD 异常差异（附 Windows API/CPUID/SIDT 检查与绕过）](code-analysis-reverse-anti-debug-qemu-tcg-anti-vm-tb-atomicity-unaligned-simd/) | verified | low | 2026-11-07 |
| [SetUnhandledExceptionFilter 顶层异常过滤器反调试：过滤器的执行与否由 UnhandledExceptionFilter 内部 DebugPort 查询决定](code-analysis-reverse-anti-debug-setunhandledexceptionfilter-toplevel-filter/) | verified | high | 2026-11-09 |
| [TLS 回调反调试：PE 加载前执行检测，静态清零 TLS 目录/回调数组绕过](code-analysis-reverse-anti-debug-tls-callback-pe-null-patch/) | verified | high | 2026-11-07 |
| [TracerPid 反调试下 LD_PRELOAD 钩 memcmp + 差分输入恢复魔改 RC4/仿射校验](code-analysis-reverse-anti-debug-ldpreload-memcmp-hook-differential-transform/) | verified | high | 2026-11-07 |
| [VEH 反调试与反反调试：自定义异常判断调试器 + 劫持 VEH 双链表移除/抢先保护处理程序](code-analysis-reverse-anti-debug-veh-custom-exception-debugger-detection-hijack/) | verified | medium | 2026-11-07 |
| [VMware 宿主与虚拟机同名驱动文件的版本号/数字签名差异作为反虚拟机指纹](code-analysis-reverse-anti-debug-vmware-driver-version-signature-differential/) | verified | medium | 2026-11-12 |
| [Windows PEB 字段反调试：BeingDebugged/Ldr/ProcessHeap/NTGlobalFlag 的识别与内存补丁](code-analysis-reverse-anti-debug-peb-fields-patch/) | verified | medium | 2026-11-07 |
| [Windows 免杀沙箱指纹组合检测：注册表/VM 进程/MAC OUI/资源/uptime/用户名/调试器与 explorer 父进程校验](code-analysis-reverse-anti-debug-windows-sandbox-fingerprint-parent-check/) | verified | high | 2026-11-06 |
| [伴生 XML 文件门控反沙箱：缺 richlist.xml 或读取失败即弹错退出，载荷仅在文件齐全时解密执行](code-analysis-reverse-anti-debug-companion-xml-gate-msedge-chrome-loader/) | verified | medium | 2026-11-11 |
| [内核驱动定时对 DR0–DR3 写 0 清除硬件断点：__writedr(0..3,0) 抵消调试器断点](code-analysis-reverse-anti-debug-kernel-writedr-clear-hardware-breakpoints/) | verified | high | 2026-11-08 |
| [内核驱动读取 KdDebuggerEnabled 检测内核调试器：调试器存在时跳过恶意初始化](code-analysis-reverse-anti-debug-kddebuggerenabled-kernel-debugger-check/) | verified | high | 2026-11-08 |
| [加载器反调试与环境探测：code.jpg 标记文件 + CheckRemoteDebuggerPresent + Toolhelp32 枚举 360tray.exe](code-analysis-reverse-anti-debug-file-marker-remotedebugger-av-process-enum/) | verified | high | 2026-11-08 |
| [动态反调试家族：SEH/INT 2D/TF、RDTSC 时序与 0xCC/CRC 校验的识别与绕过](code-analysis-reverse-anti-debug-exception-timing-checksum-bypass/) | verified | medium | 2026-11-07 |
| [反分析自毁：检测到调试器/分析环境后主动触发内存访问违例并经 RtlExitUserProcess 退出](code-analysis-reverse-anti-debug-access-violation-rtlexituserprocess/) | verified | low | 2026-11-08 |
| [反分析语言门控：GetUserDefaultLangID 命中俄语/高加索/中亚语言即 ExitProcess](code-analysis-reverse-anti-debug-getuserdefaultlangid-cis-language-gate/) | verified | high | 2026-11-11 |
| [反沙箱组合：NetGetJoinInformation 判断是否域加入 + VirtualBox 驱动文件存在即退出](code-analysis-reverse-anti-debug-domain-join-vbox-driver-check/) | verified | high | 2026-11-08 |
| [反沙箱路径陷阱：GetCurrentDirectoryW 仅在盘符根目录返回尾随反斜杠，%s 直接拼接文件名使子目录中的样本提前退出](code-analysis-reverse-anti-debug-getcurrentdirectoryw-root-trailing-backslash/) | verified | medium | 2026-11-06 |
| [反沙箱：GetCurrentDirectoryA + regex_match 整串匹配 C:\<单段随机目录> 识别微步沙箱释放路径](code-analysis-reverse-anti-debug-weibu-release-dir-regex-sandbox-check/) | verified | high | 2026-11-09 |
| [反沙箱：ip-api.com 查询出口 IP 归属地，非目标国家（China）即退出，反制境外云沙箱](code-analysis-reverse-anti-debug-ip-geolocation-country-sandbox-check/) | verified | medium | 2026-11-09 |
| [反沙箱：外部时间戳 API 取两次差值 + 300 秒长等待，识破时间加速/睡眠 hook 与短时分析窗口](code-analysis-reverse-anti-debug-external-time-api-delta-sandbox-check/) | verified | medium | 2026-11-09 |
| [反沙箱：常用软件进程白名单（QQ/微信/钉钉）全部缺失即判定云沙箱并退出](code-analysis-reverse-anti-debug-common-app-process-whitelist/) | verified | medium | 2026-11-08 |
| [命令行参数门禁：要求 --type driver 且参数 MD5 匹配硬编码值才继续](code-analysis-reverse-anti-debug-command-line-argument-md5-gate/) | verified | high | 2026-11-08 |
| [恶意样本延迟执行与多信号条件触发：uptime/时间窗/网络/CPU/内存门控与分阶段持久化](code-analysis-reverse-anti-debug-delayed-conditional-trigger/) | verified | medium | 2026-11-06 |
| [截屏像素统计做视觉环境键控：以桌面壁纸特征识别沙箱而不触发高敏感行为](code-analysis-reverse-anti-debug-visual-environmental-keying-screenshot/) | verified | high | 2026-11-05 |
| [抓包代理替换 JS/HTML 绕过前端反调试：反调试代码必须经网络下发，用 Fiddler/Burp 改包去掉 disable-devtool、无限 debugger、框架内嵌检测](code-analysis-reverse-anti-debug-proxy-js-replacement-bypass/) | verified | high | 2026-11-09 |
| [杀父进程反调试：Toolhelp32 快照找到自身 PID 的父进程并 TerminateProcess](code-analysis-reverse-anti-debug-parent-process-terminate/) | verified | high | 2026-11-09 |
| [桌面痕迹键控判云沙箱：盘符集合 + 桌面文件数 + 特定 .lnk 名（世界之窗/Microsoft Word 2010）命中即退出](code-analysis-reverse-anti-debug-desktop-artifact-keying-drive-count-shortcut/) | verified | medium | 2026-11-09 |
| [沙箱指纹采集方法：采集主机名/CPU/进程/驱动/软件并经 DNSLOG/HTTP 外带比对](code-analysis-reverse-anti-debug-sandbox-fingerprint-collect-dnslog/) | verified | high | 2026-11-12 |
| [沙箱探测：调用 pid.dll!DllGetClassObject 并要求返回 CLASS_E_CLASSNOTAVAILABLE(0x80040111)](code-analysis-reverse-anti-debug-pid-dll-dllgetclassobject-return-check/) | verified | medium | 2026-11-08 |
| [独立线程循环调用 IsDebuggerPresent 的反调试：检测到调试器即打印并 exit，需先 patch 再动态调试](code-analysis-anti-debug-thread-isdebuggerpresent-loop-exit/) | verified | high | 2026-11-08 |
| [用“某款常规软件是否安装”当沙箱判据：装了就继续、没装就直接退出，比虚拟机痕迹检测更难被沙箱伪装](code-analysis-reverse-anti-debug-installed-app-presence-gate/) | verified | low | 2026-11-08 |
| [进程名 SHIFT+XOR 哈希黑名单反分析：逐字符生成 32 位哈希比对 VMware/调试器名单，命中即退出](code-analysis-reverse-anti-debug-process-name-hash-shift-xor/) | verified | medium | 2026-11-10 |
| [针对调试器的反调试：EnumProcesses+GetModuleBaseNameA 或 FindWindowA 检测 OllyDbg 并 TerminateProcess，改名/re-pair 绕过](code-analysis-reverse-anti-debug-debugger-process-window-detect-rename-bypass/) | verified | high | 2026-11-09 |
| [银狐变种环境检测组合：VMware Tools 目录 + VMware MAC OUI + 鼠标位置轮询 + C:\ProgramData\1.txt 文件标记](code-analysis-reverse-anti-debug-silverfox-vmtools-mac-mouse-checks/) | verified | high | 2026-11-08 |
| [银狐安装器反虚拟机三件套：vmGuestLib、WMI 热区与 PhysicalDrive0 磁盘容量](code-analysis-reverse-anti-debug-silverfox-installer-vm-detection/) | verified | high | 2026-11-05 |
| [银狐远控反分析组合：进程关键化防杀、轮询挂起与窗口标题/杀软名单探测](code-analysis-reverse-anti-debug-critical-process-window-title-av-detection/) | verified | high | 2026-11-06 |
| [驱动用 ObReferenceObjectByName 探测 \Driver\npf 判断 WinPcap/Npcap 抓包监控环境](code-analysis-reverse-anti-debug-npf-driver-presence-sniffer-check/) | verified | high | 2026-11-08 |
| [黑产样本反虚拟机三查：物理内存容量、%TEMP% 文件数与系统时间种子阈值](code-analysis-reverse-anti-debug-memory-temp-file-time-seeded-vm-checks/) | verified | medium | 2026-11-11 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
