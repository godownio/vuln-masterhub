---
id: defense-incident-response-silverfox-edge-xml-jpg-random-task-cleanup
title: 银狐 edge.xml/edge.jpg 变种处置：按伪更新计划任务定位 Public\Downloads 随机目录，杀进程、删目录与任务，LastActivityView 溯源 QQ 钓鱼 RAR
type: scenario
domain: defense
path: defense/incident-response
technique: silverfox-edge-xml-jpg-random-task-ir
aliases:
- 银狐处置
- 银狐 edge.xml 清除
- 伪 MicrosoftEdgeUpdateTask 计划任务
- SS5pGBtK 随机目录
- 1maDuJmP.exe
- fufeeeti.net
- 202.79.173.12
- 本市2023年度企业税收稽查名单公布.rar
tags:
- incident-response
- windows
- silverfox
- scheduled-task
- malware-cleanup
- ioc
- lastactivityview
- phishing
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V669
  verified_at: '2026-11-13T10:09:56+08:00'
  notes: 已对照原文与20张截图核对：fufeeeti.net/202.79.173.12 情报标签与归属、伪更新任务命令行(cd Public\Downloads\SS5pGBtK && start 1maDuJmP.exe -d)、四件套文件名/大小/落地时间 2023-08-31 13:31、tasklist PID4180→taskkill 成功、目录与任务删除、LastActivityView 13:30:57 Run 2023.exe(RAR$EXA 临时目录)/13:30:38 Open QQ FileRecv RAR、WinRAR 内 2023.exe 均属实。修正一处事实混淆：原文分析的是 edge.xml 本身为 PE（MZ 被去除），随机 exe 并非『伪装为 edge.xml』的主加载器；已改为 edge.xml 为加载器并注明 exe 与 xml 加载衔接原文未展开。未复现处置
---

## 一句话结论

遭遇银狐 edge.xml/edge.jpg 变种时，最快定位方式是查计划任务：先看伪装成 Microsoft/Google/Edge 更新的任务（如 `Micros0ftEdgeUpdateTask0UA` 一类名字），其操作形如 `cmd.exe /c "cd C:\Users\Public\Downloads\<随机目录>" && start <随机名>.exe -d`；进入该随机目录可见 `<随机名>.exe`、同名 `.dat`、`edge.jpg`、`edge.xml` 四个文件。处置顺序为：按 exe 名找到 PID 并结束进程 → 删除整个随机目录 → 删除该计划任务；随后用 LastActivityView 按落地时间回溯，可定位到用户从 QQ 收到的《本市2023年度企业税收稽查名单公布.rar》并运行其中 `2023.exe` 的感染入口。

## 原理

- **计划任务是持久化与启动入口**：银狐变种创建伪装成系统/浏览器更新的计划任务，动作是进入随机目录再 `start` 随机名 exe，并带 `-d` 参数；任务存在时重启会再次拉起载荷，所以必须与进程、文件一起清理。
- **随机命名对抗排查**：目录名（示例 `SS5pGBtK`）与 exe 名（示例 `1maDuJmP`）均随机，靠记忆进程名不可行；计划任务视图能看到完整命令行，是比“外联 IP 找进程”更快的定位入口。
- **文件组合**：`edge.xml` 实为 PE 加载器（原文分析其 PE 头 MZ 被去除、扩展名伪装成 xml），计划任务启动的随机名 exe 带 `-d` 参数、同名 `.dat` 为配套数据，`edge.jpg` 内藏 shellcode（exe 与 xml 的具体加载衔接原文未展开）；四件同时存在于同一随机目录、修改时间一致（示例均为 2023/8/31 13:31）。
- **处置顺序**：先 `tasklist | findstr <随机名>` 找到 PID，`taskkill /F /pid` 结束；再删目录；再删计划任务。若先删任务不杀进程，内存中的载荷仍在运行；若只杀进程不删任务/目录，重启或触发后会复发。
- **溯源方法**：LastActivityView 按时间排序可看到 `Run .EXE file 2023.exe`（路径位于 `C:\Users\<user>\AppData\Local\Temp\RAR$EXA...`）与 `Open file or folder 本市2023年度企业税收稽查名单公布.rar`（位于 `C:\Users\<user>\Documents\Tencent Files\...\FileRecv\MobileFile`），说明用户通过 QQ 接收 RAR、用 WinRAR 打开并运行了其中的 `2023.exe`（税务稽查名单诱饵）。
- **IOC**：外联域名 `fufeeeti.net`（情报标注银狐/远控，2023-07-18 注册）、IP `202.79.173.12`（香港，恶意）；主机侧随机目录/随机 exe + `edge.xml`/`edge.jpg` 组合。

## 触发条件

- 主机出现对上述银狐 C2 域名/IP 的外联，或 EDR 告警“随机目录下的 exe 由计划任务拉起”。
- 存在伪装成 Microsoft/Google/Edge 更新、但操作为 `cmd /c cd C:\Users\Public\Downloads\<随机目录> && start <随机>.exe` 的计划任务。
- 攻击者使用 QQ/微信等 IM 投递带税务/名单类诱饵的 RAR，诱导用户手动运行内部 exe。

## 利用步骤

（以下为处置/溯源步骤）

1. 现象确认：在流量/EDR 中检索 `fufeeeti.net`、`202.79.173.12` 外联，确认感染主机。
2. 打开任务计划程序，查找伪装更新的可疑任务（示例 `Micros0ftEdgeUpdateTask0UA`，注意 `0` 代替 `o`），查看“操作”页签的完整命令行，记录随机目录与 exe 名。
3. 进入 `C:\Users\Public\Downloads\<随机目录>`，确认 `<随机>.exe`、`<随机>.dat`、`edge.jpg`、`edge.xml` 四件套及统一落地时间；如需研究先加密备份样本。
4. `tasklist | findstr <随机名>` 取 PID，`taskkill /F /pid <PID>` 结束进程。
5. 删除整个随机目录（如 `SS5pGBtK`），清空回收站前确认样本已备份。
6. 在任务计划程序中删除该可疑任务（右键删除并确认），防止重启复发。
7. 用 LastActivityView 按落地时间前后排序，定位 `Open file` RAR 与 `Run .EXE` 记录，找到 QQ `FileRecv\MobileFile` 下的钓鱼压缩包；备份后删除，并排查同批次投递的其他主机。
8. 输出应急报告：IOC、感染入口、清理项与复查结果；必要时轮换该用户凭据并全盘扫描。

## PoC

```text
# 定位与处置（原文流程）
# 1) 计划任务操作示例：
C:\Windows\system32\cmd.exe /c "cd C:\Users\Public\Downloads\SS5pGBtK" && start 1maDuJmP.exe -d

# 2) 找进程并结束
tasklist | findstr 1maDuJmP
taskkill /F /pid 4180
# 成功: 已终止 PID 为 4180 的进程。

# 3) 删除目录 C:\Users\Public\Downloads\SS5pGBtK
# 4) 任务计划程序中删除对应任务

# 5) 溯源（LastActivityView）
2023/8/31 13:30:57  Run .EXE file      2023.exe   C:\Users\...\Temp\RAR$EXA5296.32354\...
2023/8/31 13:30:38  Open file or folder 本市2023年度企业税收稽查名单公布.rar  ...\Tencent Files\...\FileRecv\MobileFile\
```

说明：目录名/exe 名/PID/路径均为原文样本值，实际处置按现场替换；备份样本时加密压缩以防再次触发。

## 变体与关联

- [[defense-incident-response-silverfox-nvgpu-nvml-ie-task-cleanup]]：同家族 nvgpu/nvml 变种，持久化在 `Microsoft Compatibility Internet Explorer` 任务 + IE 目录，文件组合不同。
- [[defense-incident-response-silverfox-service-watchdog-injected-process-cleanup]]：服务+看门狗+系统进程注入变种，清理顺序不同（先停看门狗/服务再处理注入进程）。
- [[defense-forensics-silverfox-winos4-file-registry-artifact-dump]]：银狐/Winos4 的注册表与文件痕迹采集，可在清理前补充取证。
- [[code-analysis-reverse-windows-silverfox-edge-xml-loader-mz-strip-jpg-shellcode]]：本变种加载器（MZ 被抹的 PE 伪装 xml、edge.jpg shellcode）的逆向分析。
- 变体：随机目录可能位于其他可写路径（Public、Temp、ProgramData）；任务名可能换其他系统更新样式；投递诱饵随热点变化（税务、补贴、名单）。
- 边界：若进程受保护/注入系统进程，需结合 EDR 或重启后清理；只删文件不清任务会复发。

## 检测与防御

- 检测：计划任务创建/执行事件中，命令行含 `cmd.exe /c "cd C:\Users\Public\Downloads\` 且后接随机目录、`start <随机>.exe` 或 `-d` 参数；任务名仿冒 Microsoft/Google/Edge 但含异常字符（如数字 0 代替字母 o）。
- 检测：`C:\Users\Public\Downloads` 等目录出现“随机名 exe + 同名 dat + edge.jpg + edge.xml”组合并被执行；文件落地时间一致。
- 检测：外联 `fufeeeti.net`、`202.79.173.12` 等银狐 IOC；QQ/IM 接收的 RAR 内 exe 被执行。
- 防御：禁用或监控非管理员创建的计划任务；限制 Public/Temp 目录可执行文件运行（AppLocker/WDAC）；IM 文件传输落地目录禁止直接执行，附件先扫描；对税务/名单类诱饵做邮件与 IM 安全提醒。
- 响应：按上文顺序清理并复查计划任务、服务、启动项；轮换凭据、全盘扫描、封禁 IOC。
