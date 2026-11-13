# Windows 逆向

## 这层是什么

PE、驱动、系统机制与调试。

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
| [.NET Metadata Token 定位方法体：表类型+RID、RVA/文件偏移换算与 Tiny/Fat 方法头解析](code-analysis-reverse-windows-dotnet-metadata-token-rva-method-body.md) | verified | high | 2026-11-09 |
| [.NET PE 定位 CLR Runtime Header 与元数据流：BSJB 签名、#~/#Strings/#US/#GUID/#Blob 流与 IL-Only 标志](code-analysis-reverse-windows-dotnet-pe-clr-header-metadata-streams.md) | verified | high | 2026-11-09 |
| [.NET WinForms 资源 Bitmap 隐写提取字节并多阶段反射加载（小马拉大马）](dotnet-bitmap-stego-multistage-reflective-load.md) | draft | high | 2026-11-08 |
| [.NET 样本内嵌 AES 参数还原：key=sha256(口令短语)、IV=UTF8 短语、Padding=Zeros，解 base64 常量取二级 C2](code-analysis-reverse-windows-dotnet-aes-sha256-passphrase-key-utf8-iv-zero-padding.md) | verified | high | 2026-11-08 |
| [.NET 窃密木马把配置藏进程序集 AssemblyDescription：Base64 + ROT13 解码出 Telegram Token、Chat ID 与攻击者主页](code-analysis-reverse-windows-dotnet-assemblydescription-base64-rot13-config.md) | verified | medium | 2026-11-09 |
| [3CX 供应链攻击：签名安装包侧加载恶意 ffmpeg.dll，内存定位 FEEDFACE 特征 + RC4 解出内嵌 DLL 的 shellcode 并调 DllGetClassObject 执行](code-analysis-reverse-windows-3cx-signed-installer-ffmpeg-dll-sideload-rc4-memory-dll.md) | verified | medium | 2026-11-11 |
| [ACG（Dynamic code prohibited）进程对远程 VirtualAllocEx+WriteProcessMemory 代码注入不设防，DLL 注入被拦](windows-acg-bypass-remote-code-injection-virtualallocex.md) | draft | high | 2026-11-08 |
| [Amadey Bot 样本分析：CAB 自解压 + PEB/API hash 解析 + 内存 PE 落地 oneetx.exe + 计划任务持久化与 C2 外带](code-analysis-reverse-windows-amadey-api-hash-loader-c2-config.md) | verified | high | 2026-11-07 |
| [APT28 Graphite 前置加载链：Excel customUI onLoad 远程 xls + CVE-2021-40444 OLE 投递 CAB + CPlApplet DLL 下载器](code-analysis-reverse-windows-graphite-customui-40444-cab-cplapplet-loader.md) | verified | medium | 2026-11-09 |
| [APT37 RokRAT 2024 样本执行链：LNK 内嵌 C# 释放 HWP 诱饵与三文件 → PowerShell 壳码加载器 → XOR 解密 PE 内存执行 → pCloud 云盘 C2](code-analysis-reverse-windows-rokratt-lnk-csharp-powershell-xor-pe-pcloud-c2.md) | verified | high | 2026-11-11 |
| [ARM64 全局系统调用 Hook：patch KiSystemService 前 12 字节跳 Code Cave（ADRP/ADD/BR trampoline + 回跳原函数第 4 条指令）](code-analysis-reverse-windows-arm64-kisystemservice-global-syscall-hook.md) | verified | medium | 2026-11-13 |
| [AsyncRAT 注入体分析：Base64+自定义解密配置字符串、AsyncMutex 互斥体、忽略证书校验的 TLS C2 与 Chrome Profile 枚举](code-analysis-reverse-windows-asyncrat-string-decrypt-mutex-tls-c2.md) | verified | medium | 2026-11-09 |
| [AsyncRAT 系 RAT 配置离线解密：PBKDF2 派生 AES/HMAC 密钥 + 家族 salt 差异（VenomRAT/DcRAT/在野变体）](code-analysis-reverse-windows-asyncrat-family-config-pbkdf2-salt-decrypt.md) | verified | medium | 2026-11-11 |
| [AutoIt 编译脚本 .a3x 提取与 XOR+BitNOT 折叠密钥解密分析](code-analysis-reverse-windows-autoit-a3x-xor-not-keyfold-decrypt.md) | verified | medium | 2026-11-09 |
| [BADNEWS 远控木马 2024-07 样本逆向：双重 Base64+AES-CBC-128 通信、随机化心跳与指令集](code-analysis-reverse-windows-badnews-rat-double-base64-aes-heartbeat.md) | verified | high | 2026-11-08 |
| [BlackNET 样本配置解密：dnSpy 定位 MainController，PBKDF2-SHA1(1000)+AES-CBC 还原 C&C 地址](code-analysis-reverse-windows-blacknet-config-aes-pbkdf2-extract.md) | verified | high | 2026-11-07 |
| [BloodAlchemy 配置解密：Store 下 15 字符随机名文件与 [长度][1 字节密钥][密文] 自变密钥算法还原 C2/mutex/持久化参数](code-analysis-reverse-windows-bloodalchemy-config-1byte-key-decrypt.md) | verified | high | 2026-11-09 |
| [BloodAlchemy/Deed RAT 多阶段加载链：BrDifxapi.exe DLL 侧加载 → DIFX AES-128-CBC 解壳 → FNV-1a 自解密 + LZNT1 → 45AB45AB 自定义载荷映射](code-analysis-reverse-windows-bloodalchemy-loader-aes-fnv-lznt1.md) | verified | high | 2026-11-09 |
| [Brambul（HIDDEN COBRA）SMB 蠕虫样本分析：动态 API 解析、SYSTEM 分支自启与信息收集、随机 IP 445 弱口令爆破、HELO SMTP 邮件外发](code-analysis-reverse-windows-brambul-smb-worm-smtp-email-exfil.md) | verified | high | 2026-11-11 |
| [C++ 原生加载器从资源定位密文、1024 字节分块异或解密出 .NET 勒索模块并经 CLRCreateInstance 偏移调用](code-analysis-reverse-windows-native-resource-xor-dotnet-ransomware-loader.md) | verified | medium | 2026-11-11 |
| [cbdhsvc 剪贴板历史内存提取：CUnicodeTextFormat vtable 扫描 + Unicode 字符串指针解析](code-analysis-reverse-windows-cbdhsvc-clipboard-history-vtable-memory-scan.md) | verified | high | 2026-11-07 |
| [Cheat Engine Mono Dissect：静态字段/方法枚举与运行时解密调用](code-analysis-reverse-windows-unity-mono-cheat-engine-dissect.md) | verified | high | 2026-11-06 |
| [Cheat Engine 指针扫描定位游戏数值基址+偏移，并用 Python win32 Read/WriteProcessMemory 修改阳光值](code-analysis-reverse-windows-game-sun-pointer-scan-win32-write.md) | verified | medium | 2026-11-08 |
| [Cheat Engine 未知初始值浮点扫描定位 Unity 玩家坐标：增减/不变筛选 + 冻结验证后改坐标穿墙](code-analysis-reverse-windows-cheat-engine-unknown-float-coordinate-scan.md) | verified | high | 2026-11-09 |
| [COM 客户端静态分析：CoCreateInstance 的 CLSID/IID 解析、ppv 接口类型修复与虚表偏移方法定位](code-analysis-reverse-windows-com-client-cocreateinstance-vtable-method-resolution.md) | verified | high | 2026-11-09 |
| [COM 激活子进程逆向捕获：svchost 父进程 CreateProcessInternalW 断点定位 TiWorker.exe](code-analysis-reverse-windows-com-activation-child-process-createprocessinternalw-capture.md) | verified | high | 2026-11-09 |
| [CrackMe 卷序列号绑定注册码：GetVolumeInformationA 取 C/D 盘序列号算平方和开方，Name 乘法折叠+ROL 1+OR+AND 后按 mod16 查表生成 Serial，lstrcmpA 比较](code-analysis-reverse-windows-crackme-volume-serial-hypotenuse-keygen.md) | verified | high | 2026-11-08 |
| [CrimsonRAT C# 配置提取：可见诱饵 C2 字符串 + 十进制字节数组隐藏真实 C2 与端口](code-analysis-reverse-windows-crimsonrat-decoy-c2-bytearray-config.md) | verified | high | 2026-11-08 |
| [CryptNet 混合加密格式：每文件随机 AES-256-CBC key/IV + 硬编码 RSA-2048 公钥封装 key/IV 附文件尾](code-analysis-reverse-windows-cryptnet-hybrid-encryption-rsa-wrapped-aes-key-iv.md) | verified | high | 2026-11-08 |
| [CyberGate RAT 配置提取：Delphi RCDATA 资源 CG-CG-CG-CG、0xBC 单字节 XOR 与 ####@#### 字段映射](code-analysis-reverse-windows-cybergate-rat-config-resource-xor-extract.md) | verified | high | 2026-11-10 |
| [DarkGate Delphi 加载器：zhRVKFlX 标记定位加密块、key[i]^(len-i) 递变解密钥、自累加索引 XOR 解 payload，手动映射 PE 后 jmp eax](code-analysis-reverse-windows-darkgate-marker-xor-keyindex-manual-pe-loader.md) | verified | high | 2026-11-11 |
| [DarkMe RAT：VB6 编译、时间条件与加密字符串混淆、隐藏窗口 socket 通信与 DNS C2](code-analysis-reverse-windows-darkme-rat-vb6-obfuscation-dns-c2.md) | verified | medium | 2026-11-09 |
| [Detours 在 32 位进程里 hook：函数指针必须按 DetourFindFunction 导出名或模块基址+偏移取，替换函数必须与目标调用约定/参数签名一致](code-analysis-reverse-windows-detours-funcptr-offset-calling-convention.md) | verified | medium | 2026-11-09 |
| [dnSpy 构造器字段初值补丁：MinesVisible 全置 true 让扫雷胜利条件初始成立](code-analysis-reverse-windows-dnspy-constructor-field-init-patch.md) | verified | high | 2026-11-09 |
| [dnSpy 编辑 IL 绕过 Unity Mono 游戏校验：删地雷检测 + 改胜利条件](code-analysis-reverse-windows-unity-mono-dnspy-il-patch-bypass.md) | verified | high | 2026-11-06 |
| [Dridex C2 静态提取：RC4 配置串定位 + IP/端口表特征码与 VA→RVA 解析](code-analysis-reverse-windows-dridex-c2-table-signature-extraction.md) | verified | high | 2026-11-05 |
| [Dridex 载荷还原：48 字节逆序 key 的 RC4 → Base64 → aPLib 静态提取 shellcode](code-analysis-reverse-windows-dridex-rc4-base64-aplib-shellcode-extract.md) | verified | high | 2026-11-05 |
| [Festi Dropper 静态分析：dword_404000 嵌入数据解密落地 .sys，CreateServiceA 注册内核驱动服务（LoadOrderGroup FSFilter Anti-Virus）并写 .bat 自删除](code-analysis-reverse-windows-festi-dropper-driver-service-selfdelete.md) | verified | medium | 2026-11-08 |
| [FinGhost Gh0st 变种：数据段 XOR 解密内存 PE + C:\Windows 服务与 Common Files/Run 双持久化，远控含 Mimikatz/键盘/QQ 信息/3389](code-analysis-reverse-windows-finghost-gh0st-variant-xor-memory-service-run-rat.md) | verified | medium | 2026-11-11 |
| [Frida 按 IDA 静态地址定位 Windows DLL 功能函数：模块基址换算 + 调用点 hook 改 RDI 使微信撤回无效](code-analysis-reverse-windows-frida-ida-address-hook-wechat-revoke.md) | verified | high | 2026-11-09 |
| [GitHub raw 图标尾部隐写 base64+AES-GCM 加密 C2：长休眠后批量拉取解密，流量伪装成正常图标下载](code-analysis-reverse-windows-icon-tail-aesgcm-c2-deaddrop-long-sleep.md) | verified | high | 2026-11-11 |
| [Go 恶意 DLL 静态定位：init 解析全局 API 指针 + 导出函数 loader](code-analysis-reverse-windows-go-dll-init-export-loader-analysis.md) | verified | high | 2026-11-05 |
| [Grandoreiro 多种子 DGA：日期/月/日驱动 366 个顶级域、31 组 26 字符替换与 12 功能种子，域名经 DoH 解析并按 IP 前四位映射端口](code-analysis-reverse-windows-grandoreiro-multiseed-dga-doh-port-mapping.md) | verified | high | 2026-11-08 |
| [IAT Hook 安装：遍历导入表定位 IAT 槽，VirtualProtect 改权限后替换函数指针](code-analysis-reverse-windows-iat-hook-install-messagebox.md) | verified | high | 2026-11-06 |
| [IAT 槽位 Hook 识别与还原：VirtualProtect xref 定位 lstrcmpA 劫持 + 魔改 XXTEA 解密](code-analysis-reverse-windows-iat-hook-lstrcmp-xxtea.md) | verified | high | 2026-11-06 |
| [KeyFile 注册校验：ReadFile 读 18 字节，前 14 字节 XOR 'A'+i 还原用户名，字符和 XOR 0x12345678 比对末 4 字节](code-analysis-reverse-windows-crackme-keyfile-xor-checksum-keygen.md) | verified | high | 2026-11-09 |
| [KeygenMe 名称→4 字节序列号：逐字符 c²+((c>>1)+3)c-c 累加翻倍，Serial 前 4 字节小端比较，按字符集约束枚举 Name 生成合法 Serial](code-analysis-reverse-windows-keygenme-name-4byte-serial-keygen.md) | verified | high | 2026-11-08 |
| [KiSystemCall64 系统调用钩子：重写 IA32_LSTAR MSR + 自建伪造 SSDT/Shadow SSDT 跳板](code-analysis-reverse-windows-kisystemcall64-lstar-msr-hook.md) | verified | medium | 2026-11-06 |
| [KoiStealer 最终 .NET 载荷获取：MachineGuid 请求 index.php 配置 + 管道字段 key + 字节数组 XOR + Assembly.Load/EntryPoint.Invoke](code-analysis-reverse-windows-koistealer-machineguid-config-xor-assembly-load.md) | verified | high | 2026-11-08 |
| [LATRODECTUS 加载器分析：伪装 Bitdefender 驱动、CRC32 动态 API 解析、反沙箱组合、COM 计划任务持久化与 base64+RC4 C2 命令处理](code-analysis-reverse-windows-latrodectus-loader-behavior-c2.md) | verified | high | 2026-11-09 |
| [Lazarus NukeSped 远控样本分析：异或字符串解密、LoadLibraryA 动态加载与 WinHTTP sid/esep C2 命令分发](code-analysis-reverse-windows-nukesped-winhttp-sid-esep-c2.md) | verified | medium | 2026-11-11 |
| [Lockyou 勒索样本解密：向 C2 取 RSA 私钥解出单把 AES key，按文件头 16 字节 IV 做 AES-CBC 还原 .locky 文件](code-analysis-reverse-windows-lockyou-c2-rsa-key-aes-iv-prefix-decrypt.md) | verified | high | 2026-11-11 |
| [MFC 程序利用 _initterm 静态初始化表在 main 前 TCP 拉取 ShellCode/DLL](code-analysis-reverse-windows-initterm-static-initializer-tcp-shellcode-loader.md) | verified | medium | 2026-11-08 |
| [mimikatz 适配 Windows 11 24H2：lsasrv.dll LogonSessionList 签名/偏移与 KIWI_MSV1_0_LIST/MSV1_0_PRIMARY_CREDENTIAL 结构体变更](code-analysis-reverse-windows-mimikatz-24h2-lsasrv-offset-struct-adaptation.md) | verified | medium | 2026-11-07 |
| [MiniFilter 目录查询回调摘除 FILE_BOTH_DIR_INFORMATION 链表项隐藏文件：IRP_MJ_DIRECTORY_CONTROL 后处理改缓冲区](code-analysis-reverse-windows-minifilter-directory-control-file-hide.md) | verified | high | 2026-11-12 |
| [msfvenom reverse_tcp DLL stager 逆向：DllMain 创建 rundll32.exe 挂起进程，写 shellcode 并 SetThreadContext 执行，scdbg 还原 C2](code-analysis-reverse-windows-msfvenom-reverse-tcp-dll-stager.md) | verified | high | 2026-11-13 |
| [Name/Serial 逐字符差值注册码：Serial[i] = Name[i] - (NameLen - i)，长度 ≥5 校验与注册机](code-analysis-reverse-windows-keygenme-name-char-delta-serial.md) | verified | high | 2026-11-09 |
| [NjRAT 0.7d VB.NET 客户端 dnSpy 逆向：OK.ko 入口定位安装例程、C2 收发与键盘记录线程](code-analysis-reverse-windows-njrat-vbnet-dnspy-install-c2-analysis.md) | verified | high | 2026-11-06 |
| [NukeSped 变体 Type 1 通信协议逆向与 C2 控制端重建：Sec-Fetch-* 头伪装 Google、指令 10/11/12/30/33/34/35、载荷 2-b 自反编码](code-analysis-reverse-windows-nukesped-type1-secfetch-google-c2-rebuild.md) | verified | high | 2026-11-12 |
| [OllyDbg 定位并跟踪 SEH 异常处理程序：FS:[0] 链遍历、handler 断点与 Shift+F9 异常放行](code-analysis-reverse-windows-ollydbg-seh-chain-handler-locate.md) | verified | high | 2026-11-09 |
| [PE .text 代码空洞自动化注入：E8 call rel32 劫持、重定位清零与断点验证](code-analysis-reverse-windows-pe-text-code-cave-call-rel32-patch.md) | verified | medium | 2026-11-05 |
| [PE TLS Callback 隐藏注入器：诱饵 main + 进程快照 + CreateRemoteThread 注入 shellcode](code-analysis-reverse-windows-pe-tls-callback-decoy-main-remote-thread-injection.md) | verified | high | 2026-11-06 |
| [PE TLS 回调：在 OEP 之前执行代码（反调试/早期载荷）](code-analysis-reverse-windows-pe-tls-callback-pre-oep.md) | verified | high | 2026-11-06 |
| [PE 头布局定位链：e_magic/e_lfanew 找 NT 头，SizeOfOptionalHeader/NumberOfSections 定位节表并取入口与节区](code-analysis-reverse-windows-pe-header-layout-locate.md) | verified | high | 2026-11-08 |
| [PE 导入表与基址重定位解析：ILT/IAT/绑定导入与 .reloc 块遍历](code-analysis-reverse-windows-pe-import-reloc-parser.md) | verified | high | 2026-11-06 |
| [PE 导出表（EAT）解析：AddressOfNames/AddressOfNameOrdinals/AddressOfFunctions 三级索引按名字或序号解析导出函数 RVA](code-analysis-reverse-windows-pe-export-directory-eat-name-ordinal-resolve.md) | verified | high | 2026-11-13 |
| [PE 延迟导入表解析：ImgDelayDescr 数组、__imp_load_ 桩与 __tailMerge/__delayLoadHelper 首次调用回填 IAT](code-analysis-reverse-windows-pe-delay-import-descriptor-tailmerge-iat.md) | verified | high | 2026-11-13 |
| [PE 恶意样本静态 triage：StudyPE 概览 + 导入表能力 + Strings 意图交叉推断出「复制伪装 DLL + 互斥 + C2 远程命令后门」](code-analysis-reverse-windows-pe-static-triage-imports-strings-behavior.md) | verified | high | 2026-11-13 |
| [PE 签名改 NO 的内嵌 PE 自解密 shellcode：MZ/NO 双特征定位 + 逐字节 XOR 还原 + DllEntryPoint 执行](code-analysis-reverse-windows-mz-no-embedded-pe-xor-shellcode.md) | verified | high | 2026-11-08 |
| [PE 资源目录三层树解析：类型→ID/名称→语言目录块与 IMAGE_RESOURCE_DATA_ENTRY 定位资源数据](code-analysis-reverse-windows-pe-resource-directory-three-level-tree-parse.md) | verified | high | 2026-11-13 |
| [PowerShell 下载加密 .NET 载荷：Decode-Binary 多项式状态 XOR 解密 → Assembly.Load → 反射调用 setServerIp/Main](code-analysis-reverse-windows-powershell-polynomial-xor-decrypt-assembly-load-reflect.md) | verified | medium | 2026-11-09 |
| [PsSetLoadImageNotifyRoutine 驱动监控 DLL 加载：模块路径、进程过滤与加载顺序验证](code-analysis-reverse-windows-load-image-notify-callback.md) | verified | high | 2026-11-07 |
| [PTE Hook：通过 PML4/PDPT/PD/PT 页表重映射实现进程隔离的 Windows 内核函数 inline Hook](code-analysis-reverse-windows-pte-hook-page-table-isolation-inline-hook.md) | verified | medium | 2026-11-07 |
| [Pupy RAT frozen Python 载荷识别与配置解码：pupyrat-config-decoder（Python2 + pylzma/marshal）提取 C2/参数/证书](code-analysis-reverse-windows-pupy-frozen-config-decoder.md) | verified | medium | 2026-11-08 |
| [PyInstaller 3.10 Cobalt Strike 样本：1.json 双字段 code/load 经 AES-CBC(key=IV) 解密，ctypes RWX 内存加载 CS shellcode 并静态提取 C2/URI/UA](code-analysis-reverse-windows-pyinstaller-json-aes-cbc-cs-shellcode.md) | verified | high | 2026-11-10 |
| [Qt 注册码程序逆向：NOP 反调试后断点 QLineEdit::text 回溯调用者读取 UTF-16 明文](code-analysis-reverse-windows-qt-license-qlineedit-text-breakpoint.md) | verified | medium | 2026-11-07 |
| [Quasar RAT 1.4.1 客户端执行流程逆向：NETReactor 去混淆、启动自检、双次 TLS 连接与 DoShellExecute 指令循环](code-analysis-reverse-windows-quasar-rat-client-execution-flow.md) | verified | high | 2026-11-11 |
| [Quasar RAT 1.4.1 配置解密：masterKey 经 Rfc2898DeriveBytes(salt,50000) 派生 AES-256 key 与 64 字节 HMAC key，校验后解出 C2/互斥体/证书](code-analysis-reverse-windows-quasar-rat-aes256-config-decrypt.md) | verified | medium | 2026-11-08 |
| [r77-rootkit 用户态 rootkit 部署链：InstallStager 注入 winlogon + dllhost 进程镂空，Service64 释放载荷/注册表/命名管道/计划任务](code-analysis-reverse-windows-r77-rootkit-stager-winlogon-deployment.md) | verified | high | 2026-11-11 |
| [RedLine .NET 加载器：AES/Base64 内嵌资源解密，落盘 NetFlix 诱饵与 svchost/chrome/winlogon 并启动（主体带 SmartAssembly 混淆）](code-analysis-reverse-windows-redline-dotnet-aes-resource-dropper.md) | verified | medium | 2026-11-08 |
| [RedLine 原生多级加载链：GlobalAlloc 分块解密 shellcode、0x400000 映像映射、RCDATA+CLR 宿主加载 .NET Reactor 载荷](code-analysis-reverse-windows-redline-native-multistage-shellcode-clr-resource-loader.md) | verified | medium | 2026-11-10 |
| [Remcos RAT SETTINGS 资源提取：RC4 与 0x7C1E1E1F7C 分隔的配置字段解析](code-analysis-reverse-windows-remcos-settings-config-extraction.md) | verified | high | 2026-11-05 |
| [Remcos v4.9.3 socket 协议逆向：24 04 FF 00 magic + 小端长度/指令号，自研 TCP 控制端复现初始化、30 秒心跳与 screen_capture/process_manager/command_line 指令](code-analysis-reverse-windows-remcos-socket-protocol-controller-emulation.md) | verified | high | 2026-11-12 |
| [Rootkit SSDT Hook ZwEnumerateKey 隐藏服务注册表项：清 CR0.WP 改只读页 + 调原函数后忽略大小写跳过自身子键 + 关机通知恢复](code-analysis-reverse-windows-rootkit-ssdt-zwenumeratekey-hide-service.md) | verified | high | 2026-11-08 |
| [Rootkit 文件系统过滤驱动隐藏自身：IoCreateFile(\SystemRoot) → IoGetRelatedDeviceObject → IoCreateDevice + IoAttachDeviceToDeviceStack，在 IRP 栈中过滤自身文件名](code-analysis-reverse-windows-rootkit-fs-filter-attach-hide-file.md) | verified | high | 2026-11-08 |
| [Rootkit 日期种子 DGA 回退：主 C&C 域名不可用时用系统时间作种子，经 chrfun1..8 映射生成 .com 域名](code-analysis-reverse-windows-rootkit-dga-date-seed-chrfun.md) | verified | medium | 2026-11-08 |
| [Rootkit 绕过网络监控：手工 ObCreateObject 构造 FILE_OBJECT 并直接向 \Device\Tcp/\Device\Udp 发 IRP_MJ_CREATE，避开 ZwCreateFile Hook](code-analysis-reverse-windows-rootkit-direct-irp-tcp-udp-bypass-monitor.md) | verified | high | 2026-11-08 |
| [SafeSEH 堆指针 handler 特权绕过：溢出改写 SEH handler 指向堆上 shellcode，DEP 关闭时校验放行](code-analysis-reverse-windows-safeseh-heap-handler-bypass.md) | verified | medium | 2026-11-11 |
| [SafeSEH 绕过：SEH handler 指向未启用 SafeSEH 的 DLL 中 pop pop ret 跳板，再跳栈上 shellcode](code-analysis-reverse-windows-safeseh-unregistered-module-trampoline-bypass.md) | verified | medium | 2026-11-11 |
| [Section 型进程映像伪装取证：EPROCESS ImageFileName/ImageFilePointer/ImagePathHash 与 image coherency](code-analysis-reverse-windows-process-image-masquerade-forensics.md) | verified | high | 2026-11-07 |
| [SEH 除零异常隐藏校验分支：在 __except 块下断点 + Z3 还原序列号](code-analysis-reverse-windows-seh-exception-logic-jump-z3-serial.md) | verified | medium | 2026-11-07 |
| [SEHOP 校验链伪造绕过：next-SEH 指向原链末尾合法记录、handler 覆盖为 shellcode](code-analysis-reverse-windows-sehop-chain-forge-bypass.md) | verified | medium | 2026-11-11 |
| [Session 0 隔离绕过：服务进程 DuplicateTokenEx 出主令牌后 SetTokenInformation(TokenSessionId=WTSGetActiveConsoleSessionId)，CreateProcessAsUser 在用户桌面会话创建进程](code-analysis-reverse-windows-session0-duplicate-token-createprocessasuser.md) | verified | high | 2026-11-10 |
| [SFC /VERIFYFILE 校验链逆向：COMPONENTS\DerivedData 组件键 S256H、TiWorker.exe 与 FileHashAlgorithmToDigest](code-analysis-reverse-windows-sfc-verifyfile-deriveddata-s256-tiworker-hash.md) | verified | high | 2026-11-09 |
| [ShellCode 滚动 XOR 自解密内嵌 Cobalt Strike PE：0x59 初值 + xor 后 add 明文的倒序循环还原 MZ](code-analysis-reverse-windows-shellcode-rolling-xor-embedded-cs-pe.md) | verified | high | 2026-11-08 |
| [SideWinder WarHawk 重构样本分析：死代码中 WarHawk JSON 模板与巴基斯坦时区指纹同源，WinHTTP TLS(8443) 上线 + CryptStringToBinaryA 指令解码与 0x01–0x05 五类指令](code-analysis-reverse-windows-sidewinder-warhawk-tls-c2-protocol.md) | verified | high | 2026-11-10 |
| [SilentCryptoMiner 3.4.0 挖矿载荷：powercfg 关闭睡眠 + svchost 注入 UPX 载荷 + WinRing0 驱动 + 远程 prohashing 配置](code-analysis-reverse-windows-silentcryptominer-340-svchost-powercfg-winring0.md) | verified | high | 2026-11-08 |
| [SilentCryptoMiner 3.4.1 持久化与驱动面：随机服务 LDQRSTKE 自启动 + 释放 WinRing0x64.sys + 明文挖矿配置提取（dialer.exe 注入隐藏见关联卡）](code-analysis-reverse-windows-silentcryptominer-service-injection-winring0.md) | verified | high | 2026-11-08 |
| [Snake Keylogger 配置解密：MD5(硬编码 key) 前 8 字节作 DES 密钥 + Base64 + ECB，还原 SMTP 账号/口令/服务器/端口](code-analysis-reverse-windows-snake-keylogger-des-ecb-md5-key-config.md) | verified | high | 2026-11-08 |
| [SugarGh0st 2023-12 加载链：VBS 登录脚本持久化 + 250MB 增肥 VMP DLL + authz.lib XOR shellcode 内存加载 RAT](code-analysis-reverse-windows-sugargH0st-vbs-logon-fat-vmp-dll-authz-lib-xor-shellcode.md) | verified | medium | 2026-11-11 |
| [SWIFT 勒索软件持久化与勒索展示：启动目录 [ID].exe、ProgramData 壁纸、OEMInformation/legalnotice 注册表](code-analysis-reverse-windows-swift-ransomware-startup-wallpaper-oeminfo-legalnotice.md) | verified | medium | 2026-11-11 |
| [SWIFT 勒索软件文件加密方案：X25519 密钥 + CryptoPP XChaCha20，≤0x96000 全量、更大文件按 0x20000 分块加密](code-analysis-reverse-windows-swift-ransomware-x25519-xchacha20-file-encryption.md) | verified | medium | 2026-11-11 |
| [Unity Mono 游戏静态逆向：Managed/Assembly-CSharp.dll 识别与 dnSpy 关键逻辑定位](code-analysis-reverse-windows-unity-mono-assembly-csharp-dnspy-analysis.md) | verified | high | 2026-11-06 |
| [ValleyRAT 多阶段加载链：PyInstaller 投递 BGL.exe、shellcode1 按 codemark 取配置下载二期 shellcode、shellcode2 反射加载上线模块](code-analysis-reverse-windows-valleyrat-staged-shellcode-codemark-reflective-pe.md) | verified | high | 2026-11-06 |
| [VBoxSVC.exe 侧加载 tedutil.dll：tsunami.avi 解密解压后覆盖 pla.dll .text 注入 cmd.exe 并投递窃密木马](code-analysis-reverse-windows-vboxsvc-tedutil-pla-text-stomp-stealer.md) | verified | medium | 2026-11-10 |
| [VMware 串口命名管道 + bcdedit 搭建双机内核调试环境（WinDbg 连接）](code-analysis-reverse-windows-kernel-debugging-vmware-windbg.md) | verified | high | 2026-11-05 |
| [Water Hydra OCX 加载链：HKCU CLSID InprocServer32 指向 soundtrack.ocx，rundll32 /sta 触发解密 WMFile01.tmp 并注入 WINDBVERS.EXE](code-analysis-reverse-windows-water-hydra-ocx-clsid-loader-tmp-dll-injection.md) | verified | high | 2026-11-09 |
| [WDigest 凭据提取：从 LSASS 定位 l_LogSessList 与 h3DesKey/hAesKey/IV 解密密码，改 g_fParameter_UseLogonCredential 强制明文缓存](code-analysis-reverse-windows-wdigest-logsesslist-key-decrypt-logoncredential.md) | verified | medium | 2026-11-07 |
| [WikiLoader 式 C2 还原：混淆串取奇数位字符拼回 URL、Cookie 携带 Base64 主机画像、伪 WordPress 页面按标记偏移取下一段 ShellCode](code-analysis-reverse-windows-wikiloader-c2-url-odd-index-cookie-profile.md) | verified | medium | 2026-11-10 |
| [Win32 GS+SafeSEH 组合绕过：SEH 指向非 SafeSEH DLL gadget，fgets 两段式读入完整 shellcode](code-analysis-reverse-windows-gs-safeseh-combined-two-stage-shellcode.md) | verified | medium | 2026-11-12 |
| [WinDbg 枚举 PspCreateProcessNotifyRoutine 定位 Defender 进程创建回调与检测点](code-analysis-reverse-windows-process-notify-callback-analysis.md) | verified | medium | 2026-11-05 |
| [WinDbg 枚举 PspCreateThreadNotifyRoutine：杀软线程创建回调与注入检测点](code-analysis-reverse-windows-thread-notify-callback-analysis.md) | verified | medium | 2026-11-05 |
| [Windows /GS 的 SEH 绕过：溢出覆盖栈上异常处理指针指向缓冲区 shellcode，异常分发先于 canary 校验](code-analysis-reverse-windows-gs-seh-overwrite-bypass.md) | verified | medium | 2026-11-11 |
| [Windows API inline hook 隐藏校验分支：MessageBoxA 被重定向到 AES 校验](code-analysis-reverse-windows-api-hook-hidden-aes-branch.md) | verified | high | 2026-11-06 |
| [Windows CNG BCrypt API 定位：RC4/MD5 协议与 MD5 原像](code-analysis-reverse-windows-cng-bcrypt-rc4-md5.md) | verified | high | 2026-11-06 |
| [Windows dropper 载荷自嵌与自复制：fopen 读自身、文件尾部倒数 8/4 字节存长度字段切出二阶段 exe、CreateProcess 后循环自复制到 C:\Windows\System 随机名（含调试跳过循环技巧）](code-analysis-reverse-windows-dropper-self-append-trailer-length-selfcopy-system.md) | verified | high | 2026-11-08 |
| [Windows ncalrpc 本地 RPC 接口发现与 MIDL 客户端调用](code-analysis-reverse-windows-ncalrpc-rpcview-midl-client.md) | verified | high | 2026-11-05 |
| [Windows on ARM64 DKOM 隐藏进程：EPROCESS ActiveProcessLinks 偏移 0x400 双向摘链，ImageFileName 0x560 比对](code-analysis-reverse-windows-arm64-dkom-activeprocesslinks-hide-process.md) | verified | medium | 2026-11-13 |
| [Windows on ARM64 SSDT Hook：KiServiceTable CompactOffset 编解码 + ADRP/ADD/BR trampoline 改系统调用分派](code-analysis-reverse-windows-arm64-ssdt-compactoffset-trampoline-hook.md) | verified | medium | 2026-11-13 |
| [Windows SFC IsFileProtected 受保护文件判定：WinSxS\FileMaps 哈希清单与 PnP Lockdown class=1 双路径](code-analysis-reverse-windows-sfc-isfileprotected-filemaps-pnp-lockdown.md) | verified | high | 2026-11-09 |
| [WINELOADER 变种双层 RC4 配置恢复：0x8028 shellcode 首层解密 + 0x20 处 key 与 3 字节轮询间隔的二次字符串表](code-analysis-reverse-windows-wineloader-double-rc4-config-extract.md) | verified | high | 2026-11-09 |
| [WinHex 21.3 SR-8 x86 注册算法逆向与 Keygen：CRC32 校验、DOS 日期/用户数编码与 Delphi license 结构](code-analysis-reverse-windows-winhex-license-crc32-keygen.md) | verified | high | 2026-11-07 |
| [Winos 远控载荷代际识别：内置登录模块.exe、缺失 |p1:| 配置与扩表杀软名单](code-analysis-reverse-windows-winos-payload-generation-identification.md) | verified | medium | 2026-11-06 |
| [Winos4 远控平台载荷生成：资源段插件与 codemark/xiugaishiyong 配置追加](code-analysis-reverse-windows-winos4-builder-resource-config-injection.md) | verified | high | 2026-11-06 |
| [WinRAR 命令行驱动的文件感染蠕虫：Temp 重命名 WinRAR，解包 rar→感染 exe→重打包，按磁盘多线程传播](code-analysis-reverse-windows-winrar-cli-file-infector-worm.md) | verified | medium | 2026-11-11 |
| [x32 游戏列表类数据定位：CE 值扫描 + 堆栈回溯 + 基址偏移链（背包/仓库/NPC）](code-analysis-reverse-windows-game-list-data-pointer-chain.md) | verified | high | 2026-11-05 |
| [x32 游戏控件数据定位：从登录输入小控件回溯到父级大控件的指针链](code-analysis-reverse-windows-game-control-pointer-chain.md) | verified | medium | 2026-11-05 |
| [x32 游戏血量数据定位：CE 搜数 + 访问断点 + 逐层回溯到基址指针链](code-analysis-reverse-windows-game-health-pointer-chain.md) | verified | medium | 2026-11-05 |
| [x64 下 patch E9 跳转 thunk 实现 inline hook：rel32 相对偏移公式 + 恢复原字节后调用原函数](code-analysis-reverse-windows-x64-e9-thunk-inline-hook-restore-call.md) | verified | high | 2026-11-11 |
| [x86 Inline Hook：5 字节 E9 相对跳转拦截发包/加密函数](code-analysis-reverse-windows-x86-inline-hook-packet-intercept.md) | verified | high | 2026-11-05 |
| [XMRig 注入 credwiz.exe 的监控规避：检测 taskmgr/autoruns/wireshark/tcpview 即停矿并退避 5 小时，线程与矿池按硬件动态调整](code-analysis-reverse-windows-xmrig-monitor-tool-aware-mining-evasion.md) | verified | high | 2026-11-09 |
| [xRAT（早期 Quasar）配置解密：MD5(Key) 作 AES-128 key、前 16 字节为 IV 的 AES-CBC/Base64](code-analysis-reverse-windows-xrat-config-md5-aes-cbc-decrypt.md) | verified | medium | 2026-11-11 |
| [XWorm V5.2 样本识别与 Pastebin 死信箱 C2 提取：从 raw/zNCj2Utm 取 localbeheaders.mcgo.io:4411](code-analysis-reverse-windows-xworm-v5-pastebin-c2-extraction.md) | verified | medium | 2026-11-08 |
| [XWormRAT V5 .NET 远控分析：MD5(mutex) 派生 AES-ECB 配置解密、命令分派、XLogger 键记录与 Plugins DLL 插件化](code-analysis-reverse-windows-xworm-v5-aes-config-plugin-rat-capabilities.md) | verified | high | 2026-11-08 |
| [仿冒豆包客户端 doubaoai-app.exe 投放链：UAC 提权、AMSI/ETW 补丁、Defender 策略禁用与内核驱动加载](code-analysis-reverse-windows-doubao-imposter-configmanager-uac-amsi-driver.md) | verified | high | 2026-11-05 |
| [免杀 loader 取证：fun.dll 只提供固定 jmp esp 跳板，AES-256 解密 shellcode 后经 NOP sled + strcpy 栈溢出控制执行](code-analysis-reverse-windows-jmp-esp-dll-aes-shellcode-stack-overflow-loader.md) | verified | high | 2026-11-09 |
| [关机窗口投放载荷：轮询 SM_SHUTTINGDOWN 才落地恶意 DLL，配合内存持有与重启前回写](code-analysis-reverse-windows-shutdown-window-payload-drop.md) | verified | medium | 2026-11-09 |
| [内核态按名字找进程的四种方式：暴力 PID 枚举、未导出 PsGetNextProcess 特征码定位、手走 ActiveProcessLinks、PspCidTable + ExEnumHandleTable](code-analysis-reverse-windows-kernel-process-enumerate-four-ways.md) | verified | high | 2026-11-08 |
| [内核枚举 NDIS 协议驱动：遍历 ndisProtocolList 链表 dump _NDIS_PROTOCOL_BLOCK 与协议回调地址](code-analysis-reverse-windows-ndis-protocol-driver-list-enumeration.md) | verified | high | 2026-11-12 |
| [内核枚举 NDIS 小端口驱动：遍历 ndisMiniDriverList 链表 dump _NDIS_M_DRIVER_BLOCK 与 MiniportDriverCharacteristics 回调地址](code-analysis-reverse-windows-ndis-miniport-driver-list-enumeration.md) | verified | high | 2026-11-09 |
| [内核枚举 NDIS 轻量级网络过滤驱动（LWF）：遍历 ndisFilterDriverList dump _NDIS_FILTER_DRIVER_BLOCK 与 DefaultFilterCharacteristics 处理函数](code-analysis-reverse-windows-ndis-filter-driver-list-enumeration.md) | verified | high | 2026-11-10 |
| [内核驱动 .cdata 段 4 字节 XOR（key 0x9D802CB0）加密 API 名还原：IDA Python 解段 + 动态解析 Zw*/内核例程地址](code-analysis-reverse-windows-driver-cdata-xor-api-resolution.md) | verified | high | 2026-11-08 |
| [加密导入表的 PE 壳：新增 .unpack 节与自建导入表，stub 解密 .mixed 后用 LoadLibraryA/GetProcAddress 重建原 IAT 再跳 OEP](code-analysis-reverse-windows-pe-import-table-encrypt-unpack-section-iat-rebuild.md) | verified | high | 2026-11-09 |
| [勒索软件大文件间歇加密：首/中/尾各 128KB AES-CBC 读改写，留下三块高熵密文](code-analysis-reverse-windows-ransomware-large-file-intermittent-encryption-three-128kb.md) | verified | high | 2026-11-08 |
| [卷标绑定注册码：GetVolumeInformationA 取卷名 + 4562-ABEX/L2C-5781 前后缀，前 4 字符两轮各 +1 生成 Serial](code-analysis-reverse-windows-crackme-volume-name-prefix-keygen.md) | verified | high | 2026-11-09 |
| [多阶段 .NET 内存加载链：资源 GetObject 自引用解密 → Assembly.Load/Activator.CreateInstance，dnSpy 模块列表逐阶段 dump](code-analysis-reverse-windows-dotnet-multistage-resource-assembly-load-dump.md) | verified | high | 2026-11-08 |
| [封包缓冲区硬件写入断点：从密文 send 回溯明文缓冲区与加密 call](code-analysis-reverse-windows-game-packet-buffer-encryption-locate.md) | verified | high | 2026-11-05 |
| [恶意载荷机器绑定：MachineGuid 的 MD5 作 AES-CFB IV，配置/载荷 MD5 完整性校验](code-analysis-reverse-windows-machineguid-md5-aes-cfb-payload-binding.md) | verified | high | 2026-11-08 |
| [手工压缩 PE 节表腾出可执行空隙并改写 AddressOfEntryPoint 注入调用 MessageBoxA 的补丁指令（白程序劫持）](code-analysis-reverse-windows-pe-section-squeeze-entrypoint-shellcode-patch.md) | verified | medium | 2026-11-09 |
| [手工构造“最小”PE32：三节合一 + 压缩 DataDirectory + PE Headers 与 Section 重叠（Win10 Loader）](code-analysis-reverse-windows-minimal-pe32-manual-construction.md) | verified | high | 2026-11-09 |
| [批量 .NET 载荷配置抽取：ilspycmd 命令行批量反编译 + 正则抓 URL 与 PcHwid→StartupRegName 配置块，汇总 SMTP/FTP 凭据](code-analysis-reverse-windows-dotnet-batch-ilspycmd-config-regex-extract.md) | verified | high | 2026-11-08 |
| [损坏 PE 驱动恢复：MZ 头修复 + 每 4 字节首字节 XOR 0x44 + IOCTL 多层 XOR 逆推](code-analysis-reverse-windows-corrupted-pe-driver-xor-ioctl-backtrack.md) | verified | high | 2026-11-06 |
| [支付二维码实时替换木马：Magnify 截屏 + ZXing 解码 + QRCoder 重生成 + MoveWindow 覆盖](code-analysis-reverse-windows-payment-qr-realtime-substitution-magnifier.md) | verified | high | 2026-11-06 |
| [无 DOS 头 + 打乱导入表的内存 DLL 加载器：shellcode 尾部内嵌 DLL，loader 补全头、复原导入顺序并 call 入口](code-analysis-reverse-windows-mz-less-scrambled-import-memory-dll-loader.md) | verified | medium | 2026-11-11 |
| [最小 PE 异或壳：.code/.data 逐字节异或 0x7F + 节尾代码洞部署解密 stub + 改 AddressOfEntryPoint 与节 Characteristics 可写](code-analysis-reverse-windows-pe-simple-xor-packer-code-cave-stub.md) | verified | high | 2026-11-09 |
| [未文档化 win32u 剪贴板读取：NtUserGetClipboardData 取句柄 + NtUserCreateLocalMemHandle 复制 UNICODETEXT](code-analysis-reverse-windows-ntuser-getclipboarddata-localmemhandle-read.md) | verified | high | 2026-11-07 |
| [本地 UI 功能 call 定位：窗口对象坐标搜索与访问断点](code-analysis-reverse-windows-game-call-window-object-access.md) | verified | high | 2026-11-05 |
| [枚举 CmpCallback 回调链表取出 Cookie 并 CmUnRegisterCallback 摘除注册表保护](code-analysis-reverse-windows-cm-callback-list-enum-unregister.md) | verified | medium | 2026-11-08 |
| [注册内核回调被 0xc0000022 拒绝：置 LDR_DATA_TABLE_ENTRY->Flags |= 0x20（LDRP_IMAGE_INTEGRITY_FORCED）让 MmVerifyCallbackFunction 通过](code-analysis-reverse-windows-kernel-callback-register-ldr-image-integrity-forced.md) | verified | medium | 2026-11-08 |
| [游戏人物属性定位：沿已知血量指针链遍历相邻偏移找最大蓝/最大血/人物 ID](code-analysis-reverse-windows-game-character-attr-adjacent-enumeration.md) | verified | medium | 2026-11-05 |
| [游戏发包架构判定：send 调用栈区分单线程/双线程队列并过滤心跳包](code-analysis-reverse-windows-game-send-architecture-heartbeat.md) | verified | high | 2026-11-05 |
| [游戏对象方法 call 定位：虚表访问断点与槽位分析](code-analysis-reverse-windows-game-call-vtable-access.md) | verified | high | 2026-11-05 |
| [游戏封包链路重建与代码注入：send1→加密 call→send2 顺序判定与参数复原](code-analysis-reverse-windows-game-packet-pipeline-code-injection.md) | verified | high | 2026-11-05 |
| [游戏布尔状态数据定位：0/1 值搜索、候选筛选与访问断点回溯指针链](code-analysis-reverse-windows-game-state-boolean-pointer-chain.md) | verified | high | 2026-11-05 |
| [白加黑合法 DLL 篡改定位：节区对比 + BinDiff 相似度 + IDA 差异找插入代码](code-analysis-reverse-windows-legit-dll-modification-bindiff.md) | verified | medium | 2026-11-07 |
| [白加黑安装包：伪装 Setup Factory 安装程序落地私有 DLL，借宿主 EXE 加载后经混淆导出函数 XOR 解密同目录数据并在内存执行第二段](code-analysis-reverse-windows-whiteblack-dll-export-obfuscation-xor-inmemory-payload.md) | verified | medium | 2026-11-09 |
| [硬编码注册序列号定位：GetWindowTextA/lstrcmpA 断点直接在比较参数中读取明文 Serial](code-analysis-reverse-windows-hardcoded-serial-lstrcmp-api-breakpoint.md) | verified | high | 2026-11-09 |
| [签名 EXE 不改、运行时下载被篡改的第三方 DLL：劫持 curl_easy_init 导出作为 loader 入口](code-analysis-reverse-windows-signed-exe-runtime-download-tampered-dll-export-hijack.md) | verified | medium | 2026-11-11 |
| [给已有 EXE 加功能注入：rdata 追加字符串 + 在 .text 尾部造函数跳转桩 + 序言后插入 RIP 相对寻址调用](code-analysis-reverse-windows-pe-exe-add-import-thunk-rdata-string-rip-relative.md) | verified | medium | 2026-11-08 |
| [绝对跳转 inline hook：32 位 mov eax,imm32/jmp eax（7 字节）、64 位 mov r10,imm64/jmp r10（13 字节）避开 E9 rel32 ±2GB 不可达，钩子内先恢复原字节防无限递归](code-analysis-reverse-windows-absolute-jump-inline-hook-detour.md) | verified | high | 2026-11-08 |
| [网络游戏功能 call 定位：send 断点与调用栈回溯](code-analysis-reverse-windows-game-call-send-backtrace.md) | verified | high | 2026-11-05 |
| [脱壳样本 AES 配置静态提取：capa 定位 AES 调用链、交叉引用回溯静态密钥并用 CyberChef 解密](code-analysis-reverse-windows-aes-config-capa-xref-key-cyberchef.md) | verified | medium | 2026-11-07 |
| [自动寻路 call 定位：目标坐标写入断点与参数回溯](code-analysis-reverse-windows-game-call-coordinate-write.md) | verified | high | 2026-11-05 |
| [自签根证书入 Root 存储：CertAddCertificateContextToStore 把攻击者 CA 变成 Windows 受信任根，自签载荷显示为有效签名](code-analysis-reverse-windows-self-signed-root-ca-trusted-store.md) | verified | high | 2026-11-09 |
| [蔓灵花 ORPCBackdoor 样本分析：仿 version.dll 导出白加黑 + ts.dat/$cache.dat 标记 + COM 计划任务 + ncacn_ip_tcp:443 的 NdrClientCall2 RPC 远控](code-analysis-reverse-windows-bitter-orpcbackdoor-rpc-backdoor-analysis.md) | verified | high | 2026-11-11 |
| [资源节藏内嵌 PE：Restorator 查 BIN 资源 MZ 头与 DOS stub，导出后用 StudyPE 继续分析 dropper 二阶段](code-analysis-reverse-windows-resource-section-embedded-pe-restorator.md) | verified | high | 2026-11-13 |
| [运行中可执行文件自删除：SetFileInformationByHandle 把自身重命名为 :wtfbbq 备用数据流，再 FileDispositionInfo 删除原路径](code-analysis-reverse-windows-self-delete-ads-wtfbbq.md) | verified | high | 2026-11-09 |
| [运行时自修复 syscall stub：扫描自身内存把 6B 00 00 73 6B 00 00 74 占位字节替换为 syscall;ret](code-analysis-reverse-windows-runtime-syscall-stub-self-patch.md) | verified | high | 2026-11-06 |
| [遍历 fltmgr!_FLT_FILTER.ConnectionList 枚举 MiniFilter CommunicationPort：回调、Cookie、对象名与安全描述符](code-analysis-reverse-windows-minifilter-communication-port-enum.md) | verified | high | 2026-11-09 |
| [遍历 Windows 执行体回调对象：ExpCallbackListHead、CALLBACK_OBJECT/CALLBACK_REGISTRATION 与分版本 PushLock](code-analysis-reverse-windows-ex-callback-object-enum.md) | verified | high | 2026-11-09 |
| [银狐 AutoIt FileInstall 落盘：webprocess.exe 侧加载 libcef.dll → 硬编码数据解密 → 内存映射调 JeffcEn](code-analysis-reverse-windows-silverfox-autoit-fileinstall-libcef-webprocess-sideload.md) | verified | medium | 2026-11-09 |
| [银狐 edge.xml 加载器逆向：MZ 签名被破坏的 PE 伪装 xml，参数触发生成 CreateThread 线程并读取 edge.jpg shellcode 内存执行](code-analysis-reverse-windows-silverfox-edge-xml-loader-mz-strip-jpg-shellcode.md) | verified | medium | 2026-11-13 |
| [银狐 mainframe.dll 侧加载：hpock.png 周期 XOR 解密 → NtProtectVirtualMemory 执行 Shellcode → RtlDecompressBuffer 展开载荷](code-analysis-reverse-windows-silverfox-mainframe-dll-hpock-png-xor-shellcode.md) | verified | medium | 2026-11-09 |
| [银狐 nvgpu/nvml 投递链：TLS 回调前置释放器 + 内存特征扫描 + 动态 XOR 解密 + 手工解析 kernel32 导出表释放白加黑文件](code-analysis-reverse-windows-silverfox-tls-loader-nvgpu-nvml-chain.md) | verified | medium | 2026-11-06 |
| [银狐 UPX 下载器：URLDownloadToFileW 拉取伪装 txt → SysWOW64 落盘执行 → 二次 UPX → 内存解密 Gh0st Server.dll](code-analysis-reverse-windows-silverfox-upx-http-txt-downloader-gh0st-memory.md) | verified | medium | 2026-11-09 |
| [银狐样本 CEF Helper 白加黑：512MB 文件膨胀、导出表伪造与 TLS/CFF 反分析](code-analysis-reverse-windows-silverfox-cef-helper-dll-sideload-inflation.md) | verified | medium | 2026-11-06 |
| [银狐样本配置还原：反转管道串 + denglupeizhi 标记 + IpDates_info 注册表](code-analysis-reverse-windows-silverfox-reversed-config-ipdates-info.md) | verified | medium | 2026-11-06 |
| [银狐母体 C2 取址链：URL 字母位移 -11 还原 OSS 地址 + WinInet 下载 + 4 字节滚动密钥解密](code-analysis-reverse-windows-silverfox-caesar-shift-oss-wininet-rolling-xor.md) | verified | high | 2026-11-08 |
| [非 PEB 获取 ntdll/kernel32 基址：线程启动栈回溯定位 RtlUserThreadStart/BaseThreadInitThunk 返回地址，按页回扫 MZ/PE 头推导模块基址](code-analysis-reverse-windows-non-peb-stack-retaddr-module-base.md) | verified | high | 2026-11-08 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
