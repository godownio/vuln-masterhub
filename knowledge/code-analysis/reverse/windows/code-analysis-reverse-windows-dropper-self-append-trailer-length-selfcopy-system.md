---
id: code-analysis-reverse-windows-dropper-self-append-trailer-length-selfcopy-system
title: Windows dropper 载荷自嵌与自复制：fopen 读自身、文件尾部倒数 8/4 字节存长度字段切出二阶段 exe、CreateProcess 后循环自复制到 C:\Windows\System 随机名（含调试跳过循环技巧）
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: dropper-self-append-trailer-selfcopy
aliases:
- 附加载荷 dropper
- 文件尾部长度字段
- 自复制挖矿木马
- CreateMutex 防重复运行
tags:
- windows
- malware-analysis
- dropper
- xmrig
- miner
- ida
- x64dbg
- mutex
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-30
  verified_at: '2026-11-08T15:56:39+08:00'
  notes: 已对照原文核对：fopen 读自身（img05 RCX 显示样本 SHA256 路径）、尾部倒数 8/4 字节长度字段（img08/09 汇编 r13+r14*1-8/-04）、fwrite 大小 v9-256-8（img10/img17 伪代码）、CreateProcessW（img15）、自复制到 C:\Windows\System 随机名（img19 成批 exe）、CreateMutexW 互斥体串 sfdkjjhgkdsfhgjksd（img03）、SF 置 1 跳循环（img20）全链图证齐全；样本分析卡无 PoC 合理；杀软命名冲突教训并入变体章节
---

## 一句话结论

小型 dropper/挖矿木马常把二阶段载荷直接附加在自身文件尾部：程序 fopen 读自身全文进内存，从文件末尾倒数第 8、第 4 字节的 DWORD 取长度/标记字段，按 `文件大小-256-8` 之类偏移切出内嵌 exe 写盘后 CreateProcess 执行，并 while 循环以随机文件名把自身复制进 `C:\Windows\System\` 实现重复落盘；分析时先查互斥体（CreateMutexW + GetLastError==183 时 Sleep 后退出防重复运行），再动态调试在复制循环的 jcc 指令处直接置 SF=1 跳过循环。

## 原理

载荷自嵌不需要下载器网络请求，杀软对单文件静态扫描难以区分"载体程序"与"附加数据"：载体 main 首先以固定字符串（如 "sfdkjjhgkdsfhgjksd"）CreateMutexW，若 GetLastError 返回 183（ERROR_ALREADY_EXISTS）说明已有实例在跑，随机 Sleep 后直接退出——这是挖矿木马避免同机多开抢 CPU 的惯用手法。否则 fopen(argv[0],"rb") 读自身：第一个 fseek(v8,0,2) 移到文件尾、ftell 取文件大小 v9、malloc(v9) 后 fread 全文进内存。随后从内存缓冲按偏移取 `*(DWORD*)(&buf[v9-8])` 与 `*(DWORD*)(&buf[v9-4])`——附加数据布局把长度/标记字段固定放在文件最末尾 8 字节内，据此计算 `v9-256-8` 作为 fwrite 大小把内嵌 exe（附加在载体尾部、前面垫 256 字节左右的元数据区）还原写盘，再经 mbstowcs 拼路径、CreateProcessW 拉起；二阶段与载体代码相同（内嵌 xmrig 配置），并进入 while 循环反复 fopen/fwrite 自复制到 `C:\Windows\System\<随机7字符>` 再 CreateProcessW，v12 从 253 递减控制复制次数。调试时在该 jcc（js）判断处把 SF 标志手工置 1，循环体只执行一次即可继续向后分析，不必等它复制上百份。

## 触发条件

分析视角：拿到可疑 PE（杀软报 HackTool:Win32/CobaltStrike、Trojan:Win64/XmrigMiner 等名目混乱时），导入表出现 CreateProcessW + VirtualAlloc/VirtualProtect + ws2_32 网络函数组合，运行后 `C:\Windows\System\` 出现大量 1.3MB 左右的随机名 exe，即为此类 dropper。

## 利用步骤

分析步骤（非攻击步骤）：

1. IDA 导入表初筛：CreateProcessW、VirtualAlloc/VirtualProtect、CreateFileW/A、WSAStartup/connect/send 等；
2. 看 main：CreateMutexW 固定串 + GetLastError==183 分支即防重复运行；
3. 动态调试 fopen 断点，x64 下第一参数 RCX 即 fopen 路径——确认读的是样本自身；
4. 跟踪 fseek/ftell/malloc/fread 后的尾部 DWORD 读取（`[r13+r14*1-8]`、`[r13+r14*1-4]`），确定载荷偏移与大小；
5. 在自复制循环的 js/jcc 处双击 SF 标志位置 1，跳过批量复制；
6. 拿到还原的二阶段 exe 后转入 xmrig 配置提取（见矿池地址提取卡）。

## PoC

无 PoC（样本分析卡；判别特征：System 目录成批随机名 exe、互斥体字符串、文件尾 8 字节长度字段）。

## 变体与关联

- 载荷附加位置变体：尾部、overlay、资源段、高熵附加段均可按"文件大小减去常量偏移 + 末尾长度字段"模式定位；
- 互斥体防重复运行在挖矿/勒索样本中普遍存在，固定互斥体字符串可直接作为家族 IOC 与疫苗（分析机预建同名互斥体可使样本自行退出）；
- 内嵌载荷为 xmrig 时按矿池地址提取卡继续；
- 杀软命名不一致（微软报 CS 木马、Defender 报 XmrigMiner）说明命名不可作为研判依据，需以行为与配置字符串定性。

## 检测与防御

- 检测：监控进程读取自身文件后 CreateProcess 的行为链；`C:\Windows\System\`（注意非 System32）出现批量随机 7 字符名 exe 即告警；
- 排查：以 CreateMutexW 字符串、文件尾部 8 字节长度字段结构做家族归因；用 autoruns/文件时间线清理 System 目录随机名副本；
- 防御：限制用户态进程对 System 目录写权限；EDR 覆盖 self-read + self-copy 行为序列。
