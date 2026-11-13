---
id: code-analysis-reverse-windows-finghost-gh0st-variant-xor-memory-service-run-rat
title: FinGhost Gh0st 变种：数据段 XOR 解密内存 PE + C:\Windows 服务与 Common Files/Run 双持久化，远控含 Mimikatz/键盘/QQ 信息/3389
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: finghost-gh0st-variant-xor-memory-service-run-rat
aliases:
- FinGhost
- Gh0st 变种
- scvhost.exe 持久化
- -auto 服务持久化
- -inst 启动项
- qun.qq.com 信息获取
- termsrv_t.dll 3389
tags:
- code-analysis
- reverse
- windows
- malware
- gh0st
- rat
- persistence
- windows-service
- registry-run
- keylogger
- mimikatz
- qq
- rdp
- pe32
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V547
  verified_at: '2026-11-11T20:55:28+08:00'
  notes: 已对照原文 content.md 与 20/20 张截图逐图核对：PE32/VC6 时间戳 2023-04-12 13:29:49、div 5 派生 XOR 解密出 MZ PE、VirtualAlloc/VirtualProtect 内存执行、Shellex CopyFileA 到 C:\Windows + -auto 服务（0x431 后 ChangeServiceConfig/StartService）、Common Files\scvhost.exe + HKCU Run -inst、socket/gethostbyname/connect + WSAIoctl 0x98000004 keepalive 30000/6000、19 个杀软进程名、Mimikatz/键盘/QQ 接口/termsrv_t.dll 3389/hosts 均与截图一致。验证员修正：CreateServiceA 第 4 参 0x12 实为 dwDesiredAccess（非 dwServiceType），dwServiceType 为 XP/2003 的 0x110 或 Vista+ 的 0x10，注册表实测 Type=0x10；别名 temrsvr_t.dll 拼写更正为 termsrv_t.dll；C2 按截图内存补全为 45.195.149.170（正文打码）。dedup 10 个候选（StarRailBase/SugarGh0st/银狐等）均不同链，dup-scan 无涉及 pair。恶意样本卡无 affected_versions。未执行样本。
---

## 一句话结论

FinGhost 组织使用的 Gh0st 远控变种（PE32/VC6 编译，样本时间戳 2023-04-12）：入口把硬编码数据段逐字节 XOR 解密成内存 PE（MZ 头），`VirtualAlloc`/`VirtualProtect` 后跳转执行；解密载荷的 `Shellex` 把自身 `CopyFileA` 到 `C:\Windows` 并以程序名注册 `-auto` 服务，另一路径复制到 `C:\Program Files\Common Files\scvhost.exe` 并写 `HKCU\...\Run`（`-inst`）；随后解密 C2 `45.195.149.170`、枚举约 19 个安全软件进程名、建立带 keepalive 的 socket；远控功能含下载 Mimikatz、键盘记录、截屏/剪贴板/鼠标、QQ 接口取账号信息、开启 3389/磁盘共享/hosts 修改等。

## 原理

- **数据段解密**：样本把一段硬编码数据逐字节异或解密，循环中通过 `div` 与计数/数据派生密钥字节（反编译可见 `div 5` 后取余数参与 `xor`），解密结果在内存中呈现 `MZ` 头，说明是完整 PE 而不是普通配置数据。
- **内存加载**：解密后用 `VirtualAlloc`（可读写执行）申请空间，`rep movsd`/`memcpy` 写入，`VirtualProtect` 调整页属性，再跳转执行；调试器中可见 `VirtualAlloc`→拷贝→`VirtualProtect`→`call` 的固定序列，静态文件里看不到完整的第二阶段 PE。
- **Shellex 落地与服务持久化**：解密载荷执行 `Shellex`：`CopyFileA` 把样本复制到 `C:\Windows\<程序名>.exe`，拼接 ` -auto` 参数；`OpenSCManagerA` → `CreateServiceA`（`dwDesiredAccess=0x12`；`dwServiceType` 按系统版本取值：XP/2003 为 `0x110`（`SERVICE_WIN32_OWN_PROCESS|SERVICE_INTERACTIVE_PROCESS`），Vista+ 为 `0x10`（`SERVICE_WIN32_OWN_PROCESS`，注册表实测 `Type=0x10`）；`dwStartType=2` 自动，`LocalSystem`）；若返回 `ERROR_SERVICE_EXISTS`（0x431）则 `OpenServiceA`→`ChangeServiceConfigA`→`StartServiceA`，保证服务存在并启动。
- **第二条持久化**：`GetModuleFileNameA` 取自身路径，`CopyFileA` 到 `C:\Program Files\Common Files\scvhost.exe`；随后 `RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")` + `RegSetValueExA` 写入带 ` -inst` 参数的启动项。两套路径用不同参数区分启动模式（服务/SYSTEM 与当前用户 Run）。
- **C2 连接**：解密出 `45.195.149.170`（正文打码为 `45.195.*.*`，截图中内存可见完整 IP）；`socket(AF_INET, SOCK_STREAM, IPPROTO_TCP=6)` + `gethostbyname` + `connect`；`setsockopt`/`WSAIoctl(SIO_KEEPALIVE_VALS = 0x98000004)` 设置 keepalive（约 30000ms/6000ms），维持长连接。
- **安全软件枚举**：遍历进程匹配约 19 个安全软件进程名，如 `360tray.exe`、`360sd.exe`、`xketray.exe`、`KSafeTray.exe`、`QQPCRTP.exe`、`HipsTray.exe`、`BaiduSd.exe`、`baiduSafeTray.exe`、`KvMonXP.exe`、`RavMonD.exe`、`QHULPSVC.EXE`、`QuickHeal.exe`、`msseces.exe`、`cfp.exe`、`SPIDer.exe`、`DR.WEB`、`acs.exe`、`Outpost`、`Y3svc.exe`，用于识别杀软环境并决定后续行为。
- **远控功能面**：命令分发 `switch` 覆盖截屏（`get_Screen`）、`BlockInput`、`DwmEnableComposition`、`SetThreadDesktop`、剪贴板 `GetClipboardData`、`mouse_event`、键盘 `GetAsyncKeyState` 记录（含 `<BackSpace>`/`<Enter>` 标记，带 Shift 处理）；文件接收用 `CreateFileA`+`WriteFile`；另有下载 Mimikatz 获取主机登录密码、请求 `qun.qq.com` / `xui.ptlogin2.qq.com` 接口（MSIE 9.0 UA、`Referer: http://qun.qq.com`、`zh-cn`、`application/x-www-form-urlencoded`）获取登录 QQ 账号信息，以及 `TermService`/`termsrv_t.dll`/3389 开启、磁盘共享、hosts 修改等系统操作。
- **为什么有效**：数据段加密 + 内存执行压缩静态特征；服务（LocalSystem）与 HKCU Run（当前用户）双持久化覆盖两种权限；安全软件枚举用于规避；Gh0st 变种本身提供成熟远控能力。

## 触发条件

- 目标为 Windows，用户执行钓鱼/捆绑样本（该组织以钓鱼、社工、热点事件捆绑投放）。
- 有管理员权限时服务持久化成功（LocalSystem）；无管理员权限时至少可写 HKCU Run 实现用户级自启动。
- 主机可出网访问 C2 `45.195.149.170`（原文正文打码）；安全软件未拦截内存执行、服务创建与 Run 键写入。
- 远控功能依赖 C2 下发指令；部分功能（3389、磁盘共享、hosts 修改）需要管理员/SYSTEM。

## 利用步骤

1. 样本入口解密数据段，`VirtualAlloc`/`VirtualProtect` 后跳转执行解密出的 PE。
2. 执行 `Shellex`：`CopyFileA` 自身到 `C:\Windows`，创建 `-auto` 服务（失败已存在则改配置并启动）。
3. 解密 C2 `45.195.149.170`，创建 TCP socket、设置 keepalive 并 `connect` 上线。
4. `CopyFileA` 到 `C:\Program Files\Common Files\scvhost.exe`，写 `HKCU` Run 启动项（`-inst`）。
5. 枚举安全软件进程；按 C2 指令执行截屏、键鼠、剪贴板、文件收发、键盘记录等远控功能。
6. 下载 Mimikatz 抓取主机登录密码；经 QQ 接口获取本机登录 QQ 账号信息；按需开启 3389、磁盘共享、修改 hosts 等。

## PoC

无 PoC。本文为样本分析，只给反编译/调试截图与 IOC，不含利用代码；不在文档环境执行样本。

## 变体与关联

- **同族 Gh0st 变种对比**：`[[pentest-c2-silverfox-gh0st-vmprotect-rc4-clrcreateinstance]]` 是银狐的 VMProtect+RC4 三段链；`[[code-analysis-reverse-windows-sugargH0st-vbs-logon-fat-vmp-dll-authz-lib-xor-shellcode]]` 用 VBS 登录脚本持久化；`[[code-analysis-reverse-windows-silverfox-upx-http-txt-downloader-gh0st-memory]]` 是 UPX 下载器+内存 Gh0st。本条识别点是 FinGhost 家族的数据段 XOR→内存 PE→服务+Run 双持久化→QQ 接口信息收集。
- **通用持久化**：服务创建细节见 `[[pentest-persistence-windows-service-createservice-autostart]]`；本条是其 Gh0st 变种用法（`-auto`、0x431 复用已有服务）。
- **反 AV**：安全软件进程枚举与 `[[code-analysis-reverse-anti-debug-file-marker-remotedebugger-av-process-enum]]` 等卡同属杀软环境识别，本条是固定 19 进程名黑名单。
- **信息收集**：QQ 登录态接口请求（`qun.qq.com`/`xui.ptlogin2.qq.com`）与浏览器 Cookie 窃取类卡不同，属于直接调用 QQ Web 接口获取账号/群信息。

## 检测与防御

- **持久化检测**：服务 `ImagePath` 指向 `C:\Windows\<非常规名>.exe` 且带 `-auto`、`Type=0x10`（XP/2003 为 `0x110`）、`Start=2`、`LocalSystem`；`HKCU\...\Run` 指向 `C:\Program Files\Common Files\scvhost.exe -inst`；两者同时出现可作为强 IOC。
- **内存检测**：非模块内存出现 `MZ` 头；`VirtualAlloc`→`memcpy`→`VirtualProtect`→跳转的 API 序列；数据段高熵且运行时解密。
- **网络检测**：非浏览器进程访问 `45.195.149.170` 并保持长连接（keepalive 30s/6s）；非 QQ 进程请求 `qun.qq.com`/`xui.ptlogin2.qq.com`。
- **行为检测**：进程启动后枚举 360/金山/QQ 管家/百度/卡巴/瑞星/QuickHeal/MSE/Comodo/Spybot/Dr.Web/Outpost/安博士等进程；`CreateServiceA` 返回 0x431 后 `ChangeServiceConfigA`；下载/执行 Mimikatz；键盘记录、截屏、剪贴板读取。
- **防御**：限制未知样本执行；监控服务创建与 Run 键写入并做父子进程关联；EDR 启用内存扫描与 API 序列规则；网络侧封禁 C2 段与异常 QQ 接口请求；及时修补/禁用不必要的 3389 与磁盘共享。
