---
id: code-analysis-reverse-windows-pe-static-triage-imports-strings-behavior
title: PE 恶意样本静态 triage：StudyPE 概览 + 导入表能力 + Strings 意图交叉推断出「复制伪装 DLL + 互斥 + C2 远程命令后门」
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: pe-static-triage-imports-strings-behavior-inference
aliases:
- 恶意代码静态分析
- StudyPE 导入表分析
- Strings 敏感字符串
- Lab01-01 分析
- 恶意样本行为推断
- kerne132.dll
tags:
- windows
- pe
- reverse
- static-analysis
- malware-analysis
- triage
- imports
- strings
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V665
  verified_at: '2026-11-13T08:23:00+08:00'
  notes: 已对照原文与全部35张截图核对：img01 StudyPE Lab01-01.exe 概览（32位PE/16384字节/Microsoft Visual C++/MD5 BB7425B8...）、img02 UPX壳标识、img03/img22 导入表（FindFirstFileA/FindNextFileA/CopyFileA/CreateFileA/CreateFileMappingA/MapViewOfFile）、img23 Lab01-01.dll 导入（WS2_32、CreateProcessA、CreateMutexA、OpenMutexA）、img24 Strings 出 C:\windows\system32\kerne132.dll 与 WARNING_THIS_WILL_DESTROY_YOUR_MACHINE、img25/img26 IDA DllMain 互斥+WSAStartup+socket(2,1,6)+inet_addr(cp)+htons(0x50)+connect+send/recv+strncmp(Str1/buf/5)+strncmp(aExec/buf/4)+Sleep(0x60000)、img27/img29 数据段 aExec/Str1/buf/cp(127.26.152.13)/Name(SADFHUHF)、img28 dll strings 全要素，均与卡内一致。原文是静态分析教程（无利用代码），卡内 PoC 标注『无 PoC』并给 strings 命令，如实。dedup：top 相近候选为 TLS 回调样本分析与 PE 导入伪装对抗卡（related/new），非同链；dup-scan无涉及本卡pair。原文未标版本，未设affected_versions。内部链接均存在。样本未本机运行。
---

## 一句话结论

不运行样本也能还原恶意行为：用 StudyPE 看 PE 概览（类型/编译器/壳/MD5/区段），用导入表确认样本「有能力做什么」（`FindFirstFile/FindNextFile/CopyFile` = 遍历并复制文件；`OpenMutex/CreateMutex` = 单实例防重复感染；`WS2_32`+`CreateProcess` = 网络与进程）、用 Strings 找「意图」（目标路径 `C:\windows\system32\kerne132.dll`、伪装名 `kerne132.dll`、C2 IP `127.26.152.13`、互斥名 `SADFHUHF`），三方交叉即可判定样本先把 DLL 复制伪装成系统文件、再由 DLL 连 C2 收命令执行——原文的 Lab01-01 样本最终在 IDA 中确认是互斥 + socket + `exec/sleep` 命令循环的后门。

## 原理

- **静态分析基础技术的分工**：概览层回答「文件是什么」（PE 类型、大小、编译语言/时间、是否加壳、哈希）；导入表回答「程序能调用哪些系统能力」；Strings 回答「程序里写死了什么」——这三类信息互相独立，交叉验证后能在不执行样本的前提下推断出大致行为，避免沙箱逃逸/反分析干扰。
- **导入表的语义**：`FindFirstFileA`/`FindNextFileA` 用于枚举文件系统；`CopyFileA` 用于复制；`CreateFileA`/`CreateFileMappingA`/`MapViewOfFile` 用于读写文件内容；`CreateMutexA`/`OpenMutexA` 常被恶意程序用作「同一时间只允许一个实例」的感染标记（先 Open 同名互斥量判断是否已感染，不存在再 Create）；`WS2_32.dll` 表明网络通信；`CreateProcessA` 表明可创建进程。
- **Strings 的语义**：字符串常量会暴露开发者的目标路径与配置。本例出现 `kerne132.dll`（数字 `1` 冒充 `kernel32.dll` 的仿冒名）、`C:\windows\system32\kerne132.dll`（复制目标）、`WARNING_THIS_WILL_DESTROY_YOUR_MACHINE`（提示这是实验/恶意样本），DLL 内还出现 `127.26.152.13`（疑似 C2）、互斥量名 `SADFHUHF`、协议字面量 `hello`/`exec`/`sleep`。
- **IDA 反编译确认**：`DllMain` 中 `if (!OpenMutexA(0x1F0001u, 0, Name))` 不存在才 `CreateMutexA` 建同名互斥量（防重复感染）；随后 `WSAStartup` → `socket(2,1,6)` → `inet_addr("127.26.152.13")` + `htons(0x50)`（80 端口）→ `connect` → `send("hello")` 循环 `recv(4096)`，用 `strncmp` 比较 `exec`/`sleep` 等命令串决定行为——即远程命令执行后门；数据段中的 C 字符串（`aExec`/`Str1`/`buf`/`cp`/`Name`）与伪代码变量一一对应，反向印证了 Strings 的推断。
- **为什么先静态后动态**：静态阶段就能给出「dropper + 后门」的假设与网络特征（C2 IP、协议魔法字），动态验证时可按这些特征在 Procmon/Wireshark 中定向过滤，减少运行样本的风险与噪声。

## 触发条件

- 拿到可疑 PE 样本文件（来源不限），需要在不运行的情况下快速定性与提取特征。
- 分析机装有 StudyPE/PE 查看器、`strings`（Sysinternals strings.exe）与 IDA/Ghidra；样本在隔离环境存放（原文提示样本置于虚拟机）。

## 利用步骤

1. **概览**：StudyPE 打开样本，记录 PE 类型（32/64）、大小、编译语言（如 Microsoft Visual C++）、编译时间、区段、哈希（MD5/SHA1）；若「文件类型」显示 `[UPX] -> www.upx.sourceforge.net` 等壳标识，先脱壳再继续（原文用 Free UPX / linxerUnpacker 处理加壳样本）。
2. **导入表**：切到「导入」标签，按 DLL 分组看函数；把「文件操作 / 进程 / 网络 / 互斥」相关 API 记下并推断能力（本例 exe：Find* + CopyFile；dll：CreateMutex/OpenMutex + WS2_32 + CreateProcess）。
3. **Strings**：`strings.exe <sample>`（或 Sysinternals Strings）提取 ANSI/Unicode 字符串，重点看：系统路径、仿冒系统文件名、IP/域名/URL、互斥量名、协议魔法字、警告/调试残留。
4. **交叉推断**：把导入表的能力与字符串的意图对照。本例 `CopyFileA` + `C:\windows\system32\kerne132.dll` + `Lab01-01.dll` 推出「把随附 DLL 复制到系统目录并伪装成 kernel32.dll」；`WS2_32` + `127.26.152.13` 推出网络后门。
5. **IDA 验证**：对主程序与随附 DLL 分别 `F5`；先看 `main`/`DllMain` 的调用链（本例 main 只有初始化 + `Sleep` 循环，真正逻辑在 `DllMain`），再到数据段双击字符串交叉引用（xref）定位使用点，确认互斥、连接与命令循环。
6. **产出特征**：C2 IP/域名、端口（80）、协议字面量（`hello`/`exec`/`sleep`）、互斥名（`SADFHUHF`）、落盘路径与仿冒名，供检测规则与后续动态分析使用。

## PoC

无 PoC（静态分析流程，无利用代码）。最小复现命令：

```bash
# 概览用 StudyPE GUI；字符串提取：
strings -a Lab01-01.exe | findstr /i "kernel dll exe http"
strings -a Lab01-01.dll | findstr /i "mutex hello sleep exec"
# 关注输出：C:\windows\system32\kerne132.dll、127.26.152.13、SADFHUHF 等
```

## 变体与关联

- 变体：加壳样本先按 [[code-analysis-reverse-unpacking-upx-manual-esp-breakpoint-scylla]] 等方法脱壳，再按本流程 triage。
- 变体：Go/Rust 等静态链接样本导入表信息少，转用符号/字符串与特征（参见 code-analysis/reverse 下 Go 二进制布局与符号恢复卡）。
- 关联：[[defense-forensics-office-rtf-equation-editor-sample-shellcode-triage]]（样本级快速 triage 的另一入口）；[[pentest-c2-pe-resource-metadata-impersonation-entropy]]（PE 资源/元数据伪造，静态特征的对抗面）。
- 边界：字符串与导入表只反映「可能性」，不下最终结论；混淆/加密字符串（本例 DLL 中的乱码块）需要动态或解密后确认。

## 检测与防御

- 检测（分析侧）：产出 C2 IP/端口、协议字面量、互斥量名、落盘文件名作为网络与主机检测规则；关注 `C:\Windows\System32` 下非系统签名的仿冒 DLL（如 `kerne132.dll`）。
- 防御（主机侧）：系统目录写入需要管理员权限，普通样本需提权才能完成伪装复制；开启 DLL 搜索顺序/签名校验与受保护目录监控；对异常出站连接（本例 80 端口明文 `hello` 协议）做流量检测。
- 分析安全：样本必须在隔离虚拟机/沙箱中处理，禁止在物理机运行；分析前对样本做哈希登记，分析后回滚快照。
