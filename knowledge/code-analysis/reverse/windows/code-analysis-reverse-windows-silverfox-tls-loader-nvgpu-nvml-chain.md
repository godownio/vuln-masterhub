---
id: code-analysis-reverse-windows-silverfox-tls-loader-nvgpu-nvml-chain
title: 银狐 nvgpu/nvml 投递链：TLS 回调前置释放器 + 内存特征扫描 + 动态 XOR 解密 + 手工解析 kernel32 导出表释放白加黑文件
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: silverfox-tls-loader-nvgpu-nvml-chain
aliases:
- 银狐 nvgpu 样本
- ongihwe.cn_926_X8_NULL.exe
- nvgpu_x64.exe 白加黑
- nvml.dll 侧加载
- TLS 回调释放器
- 动态 XOR 解密载荷
- 手工解析导出表
tags:
- windows
- silverfox
- malware-analysis
- tls-callback
- xor-decryption
- pe-export-table
- dll-sideloading
- scheduled-task
- anti-debug
- c2
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V167
  verified_at: '2026-11-06T13:46:40+08:00'
  notes: 已对照原文全文与37张图核对：TLS 回调图30、sub_140001378 内存扫描(0xFE/0xFA/0xFF, 8字节和1820)图25、sub_1400013D4 18项描述符+VirtualProtect RWX+XOR 图23/29、sub_140001164 40字节密钥公式、sub_140001098/sub_1400010B4 手工 EAT 解析、sub_140001298 模块表/序号修复图24、计划任务 XML（SYSTEM/HighestAvailable/BootTrigger/nvgpu_x64.exe）图15、IE 目录四文件图13、伪腾讯/光明食品签名图08/10、congihwe.cn→18.166.2.135 图12、svchost 连接并发送887/735字节图18/26、nvml.dll DllMain 图33 均一致。已收敛越出证据的表述：sub_140001298 之后的 CreateFileW/CreateProcessW 属原文 AI 注释未逐行证实，改为注明；C2 连接明确为 svchost.exe 而非 nvgpu；将‘收发’改为‘发送’；导出函数后续 COM/dllhost/svchost 链明确标注为原文推测。confidence=medium 保留。未验证点：未做 x64dbg 动态调试，nvml.dll 导出函数完整行为与注入链未证实；无 CVE/版本、无 sources/source_url。
---

## 一句话结论

钓鱼压缩包中的 `ongihwe.cn_926_X8_NULL.exe` 用 TLS 回调在主程序入口前执行：先扫描内存特征定位配置结构，再对 18 个内嵌块做“逐字节 `i + 40 字节密钥[i % key_len]`”的 XOR 解密，通过手工遍历 PEB 模块链表、解析 kernel32 导出表取得 `VirtualProtect`/`LoadLibraryA`/`GetProcAddress` 等 API，修复导入后把 `nvgpu_x64.exe`、`nvml.dll`、`nvml.bin`、`temp.key` 释放到 `C:\Program Files\Internet Explorer`，并创建名为 `Microsoft Compatibility Internet Explorer` 的 SYSTEM 开机计划任务拉起 `nvgpu_x64.exe`；后者侧加载伪造签名的 `nvml.dll`，动态日志中由 `svchost.exe` 连接 C2 `18.166.2.135:5676`。

## 原理

- **TLS 回调前置执行**：样本 PE 的 TLS 目录注册了回调，Windows 加载器在 OEP/CRT 初始化之前调用它。IDA 中的 `TlsCallback_0` 先调用 `sub_140001378()`，若返回值非空且满足字段条件，则把 `返回值 + 8` 传给 `sub_1400013D4()`。常规只在 `main`/OEP 下断点的分析会完全错过这段逻辑。
- **内存特征扫描而非简单 PEB 读取**：`sub_140001378()` 的伪代码在内存中按字节扫描，寻找 `0xFE`、`0xFA`、`0xFF` 组合，并对连续 8 字节求和、判断是否等于 1820（0x71C），命中后返回该结构指针；这更像“在自身映像中定位加密配置/载荷描述表”。原文的 AI 注释把它解释为“读取 PEB 并做反调试检测”，但伪代码语义是特征扫描，具体判定字段未完全还原，卡片不把“反调试”当作已证实结论。
- **描述符表驱动解密**：`sub_1400013D4(a1)` 把 `a1 + 53` 当作描述符数组，共 18 项，每项 5 个 DWORD（偏移、大小、标志、原保护属性等）。对每项：`VirtualProtect(base + offset, size, 原始属性, &old)`，再改为 `PAGE_EXECUTE_READWRITE (0x40)`；若标志为 0，调用 `sub_140001164(a1, offset, size)` 解密；最后恢复原保护属性，减少内存特征。
- **XOR 解密算法**：`sub_140001164` 在栈上构造 40 字节密钥（前 3 字节为 ASCII `"3qd"`，后续为手工填充的随机字节，其余补 0），密钥有效长度取自 `a1 + 33`；对 `base + offset` 起每个字节执行 `cipher[i] ^= (BYTE)i + key[i % key_len]`。`i` 参与密钥使密文不是固定单字节异或，`i % key_len` 让 40 字节密钥可循环解密任意长度载荷；异或可逆，编译时加密、运行时原地解密。
- **手工 API 解析**：`sub_140001098()` 用 `NtCurrentPeb()->Ldr->InLoadOrderModuleList.Flink->Flink->Flink[3].Flink` 取 kernel32 的模块链表节点；`sub_1400010B4()` 在栈上拼 `"GetProcAddress"`，按 PE 导出表三张表（AddressOfFunctions/AddressOfNames/AddressOfNameOrdinals）遍历名字匹配，计算 `模块基址 + 函数 RVA`，得到自举的 `GetProcAddress`。随后用它解析 `VirtualProtect`、`LoadLibraryA` 等 API，避免在导入表中留下敏感函数名。
- **导入/重定位修复**：`sub_140001298(a1)` 取 `a1 + 41` 指向的“模块资源表”，用 `LoadLibraryA` 加载各依赖 DLL；再遍历每个模块的函数地址表：正数视为函数名偏移（`base + value + 2`），负数视为导出序号（`value & 0x7FFF...`），调用手写 `GetProcAddress` 得到真实地址并覆盖占位符，使解密后的 PE 镜像可直接落地/执行。
- **释放与持久化**：原文对 `sub_140001298` 之后的 AI 注释称会通过 `CreateFileW`/`WriteFile` 写出解密后的 PE 并 `CreateProcessW` 启动 `nvgpu_x64.exe`（该具体文件写入函数未在静态分析中逐行证实）；动态日志则明确显示 `svchost.exe`（PID 4412/2464）完成 `nvgpu_x64.exe`、`nvml.dll`、`nvml.bin`、`temp.key` 的写入与计划任务创建，说明样本很可能先注入/借用了系统进程上下文，而非由原 EXE 直接落盘。
- **计划任务伪装**：任务 XML 的作者/描述为 `SYSTEM` / `Microsoft Compatibility Internet Explorer`，URI 位于 `\Microsoft\Windows\WS\`，`BootTrigger` 开机触发，Principal 为 `S-1-5-18`、`RunLevel=HighestAvailable`，`MultipleInstancesPolicy=Parallel`、`Enabled=true`、`ExecutionTimeLimit=PT72H`、`Priority=7`，Action 为 `C:\Program Files\Internet Explorer\nvgpu_x64.exe`。任务名与路径模仿微软系统任务，`Hidden` 实际为 `false`，隐蔽性主要来自命名与路径而非隐藏属性。
- **白加黑侧加载**：`nvgpu_x64.exe` 本身是正常的 GPU 信息收集程序，但静态导入同目录的 `nvml.dll`；`nvgpu_x64.exe` 伪造成腾讯签名，`nvml.dll` 伪造成光明食品签名。恶意 `nvml.dll` 的 `DllMain` 在 `fdwReason == DLL_PROCESS_ATTACH (1)` 时把 `hinstDLL` 写入全局变量 `qword_1800BBC00` 并返回 1，真正的恶意逻辑预期在其导出函数被宿主调用后触发。原文未完整还原 `nvml.dll` 的导出函数与后续注入链，因此“COM 伪装 → dllhost → svchost → 计划任务”属于作者基于动态行为的推断，卡片标注为未完全证实。
- **C2 与外联**：样本读取 `C:\Windows\win.ini`、做虚拟机检测并自删除（`cmd /c timeout 2 & del /f /q`）；DNS 缓存解析 `congihwe.cn` 到 `18.166.2.135`，随后 `svchost.exe` 与 `18.166.2.135:5676` 建立 TCP 连接并发送 887/735 字节数据；删除计划任务或 `nvml.dll` 后无法上线，说明这条链是上线关键。

## 触发条件

- 受害者为 Windows 主机，用户运行钓鱼压缩包中的 `*.exe`（文件名伪装成“人员名单”等）。
- 样本具备执行权限；动态日志显示落盘到 `C:\Program Files\Internet Explorer` 并创建 SYSTEM 计划任务，实际运行环境很可能已具备管理员/SYSTEM 上下文。
- 目标可访问 C2 `18.166.2.135:5676`（域名 `congihwe.cn`）。
- `nvgpu_x64.exe`、`nvml.dll`、`nvml.bin` 位于同一目录，使 DLL 搜索顺序加载同目录恶意 `nvml.dll`。
- 分析侧需要样本与隔离环境；TLS 回调、解密与 API 解析均可在静态/动态分析中观察。

## 利用步骤

1. 投递：把释放器 EXE 放入钓鱼压缩包，文件名伪装成人员名单/文档相关名称，诱导用户解压运行。
2. 前置执行：加载器调用 TLS 回调，`sub_140001378` 扫描内存特征定位结构，满足条件后进入 `sub_1400013D4`。
3. 解密：`sub_1400013D4` 遍历 18 个描述符，改 RWX、按 `cipher[i] ^ (i + key[i % key_len])` 解密、恢复保护；随后处理主载荷并校验 8 项完整性。
4. API 解析与修复：`sub_140001298` 用手工 `GetProcAddress` 解析 `LoadLibraryA`，加载依赖模块并回填函数地址。
5. 落盘：写出 `nvgpu_x64.exe`、`nvml.dll`、`nvml.bin`、`temp.key` 到 `C:\Program Files\Internet Explorer`（动态日志中由 `svchost.exe` 完成）。
6. 持久化：创建 `\Microsoft\Windows\WS\Microsoft Compatibility Internet Explorer` 计划任务，`S-1-5-18`/`HighestAvailable`/开机触发，Action 指向 `nvgpu_x64.exe`。
7. 侧加载与上线：`nvgpu_x64.exe` 加载同目录 `nvml.dll`，`nvml.dll!DllMain` 保存模块基址；宿主调用其导出函数后执行后续恶意逻辑属原文推测，动态日志中由 `svchost.exe` 连接 `18.166.2.135:5676` 上线。
8. 清理痕迹：原释放器读取 `win.ini`、检测虚拟机、执行 `cmd /c timeout 2 & del /f /q "<自身路径>"` 自删除。

## PoC

无武器化 PoC（恶意样本分析，不提供可执行载荷）。可用于复现/核对的观测命令：

```bat
:: 计划任务与 XML
schtasks /query /tn "\Microsoft\Windows\WS\Microsoft Compatibility Internet Explorer" /xml
type "C:\Windows\System32\Tasks\Microsoft\Windows\WS\Microsoft Compatibility Internet Explorer"

:: 落地文件与签名
dir "C:\Program Files\Internet Explorer\nvgpu_x64.exe" "C:\Program Files\Internet Explorer\nvml.dll" "C:\Program Files\Internet Explorer\nvml.bin" "C:\Program Files\Internet Explorer\temp.key"
powershell -c "Get-AuthenticodeSignature 'C:\Program Files\Internet Explorer\nvgpu_x64.exe','C:\Program Files\Internet Explorer\nvml.dll' | fl *"

:: 网络与进程
netstat -ano | findstr 5676
tasklist | findstr /i "nvgpu nvml"
```

原文给出的样本哈希（用于情报比对）：

```text
SHA256: ea409b82af0f276a7099ee9d0f688e16afbef8d6189401daf7c7689a06e5706a
MD5:    741b7ffbf4a9a3810e8605f3a169aa4a
SHA1:   b703f4b7f397e56066098d86c5bdd6effb04a1e2

SHA256: c5d9fba03c64f0174a2cbd9956f969b34c59d56727c3e05e9edabbb1592d3a12
MD5:    6bbf9fbf9a9439f8ae2fc10983b80d69
SHA1:   f9f48202892733fc98d9dea2d623271cfafa1737

SHA256: a2c4dd0e5eec6a00e757472278050db6761fc30f1047107113410c61ddecdb30
MD5:    8bbaabe92a1463cf911964e89157e115
SHA1:   e172776d1a047dab479303e5c000eb3ee3891d8d
```

## 变体与关联

- 变体（导出解析）：不调用 `GetProcAddress`，而是自写 PE 导出表解析；也可改为 API 哈希/序号调用，进一步减少字符串特征。
- 变体（解密）：把 XOR 换成 RC4/AES 或增加多层壳；本例的 `i + key[i % len]` 逐字节异或只是其中一种低成本方案。
- 变体（持久化）：计划任务可换成服务、Run 键、COM Handler；任务名/路径可继续模仿 `\Microsoft\Windows\*` 系统任务。
- 变体（白加黑）：宿主可换成其他会从自身目录加载 DLL 的签名程序；`nvml.dll` 的导出函数可按宿主导入表定制。
- 关联：[[pentest-persistence-signed-gpu-masquerade-hidden-scheduled-task-system]]（同为“签名 GPU 白程序 + SYSTEM 计划任务”持久化，宿主/任务路径不同）、[[code-analysis-reverse-windows-pe-tls-callback-pre-oep]]（TLS 回调机制）、[[code-analysis-reverse-windows-silverfox-cef-helper-dll-sideload-inflation]]、[[pentest-c2-silverfox-sogou-sideload-inflation-aes-reflective-chain]]（同家族其他白加黑链）、[[pentest-initial-access-seo-fake-official-software-download]]（IE 目录 nvml/nvgpu 落地痕迹的投递侧卡片）。
- 边界：原文未完成 x64dbg 动态调试，`sub_140001378` 的字段语义、`sub_140001298` 之后的具体文件写入函数、`nvml.dll` 导出函数的完整恶意逻辑均未逐行证实；卡片把动态日志可确认的行为与静态代码可读出的逻辑作为事实，其余标注为推断。

## 检测与防御

- 检测 TLS 回调：PE 数据目录索引 9 非空、回调在 OEP 前调用 `VirtualProtect`/内存扫描/解密逻辑；在 TLS 回调入口下断点，而不是只断 OEP。
- 检测释放行为：`C:\Program Files\Internet Explorer` 下出现 `nvgpu_x64.exe`、`nvml.dll`、`nvml.bin`、`temp.key` 等非 IE 组件；由 `svchost.exe` 等系统进程写入用户态程序目录尤其可疑。
- 检测计划任务：`\Microsoft\Windows\WS\Microsoft Compatibility Internet Explorer` 等仿微软路径的任务；XML 中 `S-1-5-18` + `HighestAvailable` + `BootTrigger` + Action 指向 IE 目录/用户可写目录；事件日志 4698 与任务计划程序 106/200/201。
- 检测白加黑：`nvgpu_x64.exe`/`nvml.dll` 的签名者与产品名是否匹配（本例伪腾讯/光明食品签名）；IE 目录中出现 GPU 相关 DLL/EXE 组合；进程加载同目录非系统签名 DLL。
- 检测网络：DNS 查询 `congihwe.cn`、连接 `18.166.2.135:5676`；`svchost.exe` 发起非常规境外 5676 端口连接。
- 防御：不要运行来源不明的“人员名单”类 EXE；对 `C:\Program Files\Internet Explorer` 等目录做写入监控；限制创建 SYSTEM 计划任务；启用 AppLocker/WDAC 与签名校验；EDR 对 TLS 回调前置 API 调用、`VirtualProtect` RWX、`LoadLibrary` 同目录 DLL 做行为告警；发现后按关联的应急处置卡清理。
