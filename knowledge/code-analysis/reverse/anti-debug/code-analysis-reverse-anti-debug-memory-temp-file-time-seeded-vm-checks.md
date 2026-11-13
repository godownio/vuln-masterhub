---
id: code-analysis-reverse-anti-debug-memory-temp-file-time-seeded-vm-checks
title: 黑产样本反虚拟机三查：物理内存容量、%TEMP% 文件数与系统时间种子阈值
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: blackmarket-memory-temp-file-time-seeded-anti-vm
aliases:
- 反虚拟机
- GlobalMemoryStatusEx 内存检测
- '%TEMP% 文件数检测'
- GetSystemTimeAsFileTime 时间检测
- ENIGMA 壳反沙箱
- Temp 目录枚举反沙箱
tags:
- anti-debug
- anti-vm
- anti-sandbox
- windows
- malware-analysis
- evasion
- enigma
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V546
  verified_at: '2026-11-11T20:57:08+08:00'
  notes: 已对照原文与图17-22逐项核对：ENIGMA(5.X)[-]壳（图17）、GlobalMemoryStatusEx(dwLength=64)+SSE换算（图20）、FindFirstFileA/FindNextFileA统计%TEMP%文件数（图21）、GetSystemTimeAsFileTime→srand→两次rand()%100→mw_rand_100/50/25与1000/500/250比较（图22）、GetEnvironmentVariableA(0x1E164)（图19）均与原文一致。验证时已修正时间检查表述：图19/22为v9<=1000 && v8<=500 && v7<=250三项同时满足才ExitProcess(0)，原稿'逐一比较/任一检查命中'易误读。PoC无。dedup候选（sandbox-environment-checks、windows-sandbox-fingerprint-parent-check、silverfox-installer-vm-detection）检查项不同，非同链。无affected_versions、无source_url。未运行样本。
---

## 一句话结论

一个用 ENIGMA 5.x 加壳的黑产样本在主逻辑前做组合环境检查：`GlobalMemoryStatusEx` 取物理内存容量并用 SSE 指令换算比较、`FindFirstFileA`/`FindNextFileA` 统计 `%TEMP%` 下的文件数、`GetSystemTimeAsFileTime` 取系统时间作为 `srand` 种子派生多个随机量与 1000/500/250 阈值比较、`GetEnvironmentVariableA` 检查特定环境变量；内存、环境变量或时间种子检查命中即 `ExitProcess(0)`（时间检查需三个派生量同时满足 `<= 1000/500/250`），使虚拟机/沙箱在载荷行为发生前终止样本。

## 原理

- **物理内存容量**：虚拟机/沙箱常只分配 2–4 GB 内存。样本调用 `GlobalMemoryStatusEx` 填充 `MEMORYSTATUSEX`（`dwLength = 64`），随后用 SSE 指令（`movq`/`xmm`、`unpcklps`/`unpacklo_epi32`、`sub_pd`/`div_pd` 等）对 `ullTotalPhys` 做整数/浮点换算，再把结果与常量比较返回布尔值；低内存环境判为分析机。
- **%TEMP% 文件数**：`FindFirstFileA("%TEMP%\\*")` 打开目录，`FindNextFileA` 循环计数（跳过 `.` 与 `..`），`FindClose` 结束；文件/子项数量过少说明系统刚创建、无人使用，判为沙箱。真实用户机器的 Temp 目录通常有较多历史残留。
- **系统时间种子阈值**：`GetSystemTimeAsFileTime` 取当前系统时间，`srand` 播种后取两次 `rand() % 100`，再经 `mw_rand_100`/`mw_rand_50`/`mw_rand_25` 三个辅助函数派生三个量，分别与 1000/500/250 比较（均为 `<=`，三项同时满足才退出）；原文将其归类为“通过时间间隔反虚拟机”。截图中的伪代码是部分还原，三个辅助函数的具体派生公式未完整呈现。
- **环境变量**：`GetEnvironmentVariableA` 检查特定变量名（反编译伪代码中表现为编码常量 `0x1E164`），存在/取值异常即退出。
- **为什么有效**：以上都是低噪声的只读查询，不产生明显恶意行为；真实主机一般满足“内存足够、Temp 有历史文件、时间正常”，而自动化沙箱恰好相反。把多项检查串联可提高沙箱识别率，代价是误报：低配真机、全新安装系统或受限环境也会被退出。
- **壳的叠加**：样本用 ENIGMA(5.X)[-] 加壳（ExeInfoPE 识别），静态看不到上述检查；脱壳后才暴露反虚拟机代码，壳与反沙箱构成两层对抗。

## 触发条件

- 目标为 Windows，样本在虚拟机/沙箱或资源受限环境中运行。
- 物理内存、`%TEMP%` 文件数、系统时间派生值、环境变量中任一命中样本内置阈值。
- 样本已成功脱壳并进入主逻辑前的检查函数；检查失败路径为 `ExitProcess(0)`，无弹窗或明显报错。

## 利用步骤

1. 调用 `GlobalMemoryStatusEx`，读取 `ullTotalPhys`，按样本内嵌的 SSE 换算逻辑与阈值比较。
2. 用 `FindFirstFileA`/`FindNextFileA` 遍历 `%TEMP%`，统计文件/子项数量，低于阈值则判为沙箱。
3. 调用 `GetSystemTimeAsFileTime`，以返回值 `srand`，生成 `rand() % 100` 序列并派生三个量，与 1000/500/250 阈值比较。
4. 调用 `GetEnvironmentVariableA` 检查特定环境变量。
5. 内存/环境变量检查命中，或时间种子检查三个派生量同时低于 1000/500/250 → `ExitProcess(0)`；全部通过才解密/执行后续 Payload。

## PoC

无 PoC。原文只有脱壳后的反编译截图与部分伪代码，环境变量名、SSE 换算公式和时间派生逻辑均未完整给出；不在文档环境复现样本。

## 变体与关联

- 与 `[[code-analysis-reverse-anti-debug-sandbox-environment-checks]]` 的差异：后者检查时间加速、桌面文件数、用户名/主机名与 `DebugPort`；本卡检查物理内存容量、`%TEMP%` 文件数、系统时间种子阈值与环境变量，检查项与阈值均不同。
- 与 `[[code-analysis-reverse-anti-debug-windows-sandbox-fingerprint-parent-check]]` 的差异：后者覆盖注册表虚拟化键、虚拟化进程、MAC OUI、uptime、父进程等指纹；本卡只用少量 API 组合，隐蔽性更高、覆盖面更窄。
- 与 `[[code-analysis-reverse-anti-debug-silverfox-installer-vm-detection]]` 的差异：后者用 vmGuestLib、WMI 热区、磁盘容量；本卡不依赖虚拟化专用组件。
- 同类思路：低资源/新环境识别，常见于黑产加载器与安装器；检查越多误报越高。

## 检测与防御

- **沙箱侧反制**：为分析环境分配 ≥4 GB 内存、预置足量 Temp 历史文件、保持真实 uptime 与系统时间；避免一眼可辨的临时目录结构。
- **行为检测**：进程启动后短时间内集中调用 `GlobalMemoryStatusEx`、`FindFirstFileA/FindNextFileA`（目标为 `%TEMP%`）、`GetSystemTimeAsFileTime`、`GetEnvironmentVariableA`，随后立即 `ExitProcess`，可作为“入口即退出”样本的 API 序列规则；结合 ETW/API 遥测与后续无行为关联分析。
- **逆向分析**：对 ENIGMA 等壳先脱壳（内存 dump、OEP 定位、IAT 重建），再 patch 检查函数返回值或 hook 对应 API 返回真实主机特征，逐项绕过。
- **局限**：检查全部基于用户态 API，沙箱可 hook 伪造返回值；因此这类检查只能筛掉低成本自动化沙箱，不能对抗定向分析。
