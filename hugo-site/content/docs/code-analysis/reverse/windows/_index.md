---
title: Windows 逆向
weight: 1
---

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
| [Amadey Bot 样本分析：CAB 自解压 + PEB/API hash 解析 + 内存 PE 落地 oneetx.exe + 计划任务持久化与 C2 外带](code-analysis-reverse-windows-amadey-api-hash-loader-c2-config/) | verified | high | 2026-11-07 |
| [cbdhsvc 剪贴板历史内存提取：CUnicodeTextFormat vtable 扫描 + Unicode 字符串指针解析](code-analysis-reverse-windows-cbdhsvc-clipboard-history-vtable-memory-scan/) | verified | high | 2026-11-07 |
| [Cheat Engine Mono Dissect：静态字段/方法枚举与运行时解密调用](code-analysis-reverse-windows-unity-mono-cheat-engine-dissect/) | verified | high | 2026-11-06 |
| [dnSpy 编辑 IL 绕过 Unity Mono 游戏校验：删地雷检测 + 改胜利条件](code-analysis-reverse-windows-unity-mono-dnspy-il-patch-bypass/) | verified | high | 2026-11-06 |
| [Dridex C2 静态提取：RC4 配置串定位 + IP/端口表特征码与 VA→RVA 解析](code-analysis-reverse-windows-dridex-c2-table-signature-extraction/) | verified | high | 2026-11-05 |
| [Dridex 载荷还原：48 字节逆序 key 的 RC4 → Base64 → aPLib 静态提取 shellcode](code-analysis-reverse-windows-dridex-rc4-base64-aplib-shellcode-extract/) | verified | high | 2026-11-05 |
| [Go 恶意 DLL 静态定位：init 解析全局 API 指针 + 导出函数 loader](code-analysis-reverse-windows-go-dll-init-export-loader-analysis/) | verified | high | 2026-11-05 |
| [IAT Hook 安装：遍历导入表定位 IAT 槽，VirtualProtect 改权限后替换函数指针](code-analysis-reverse-windows-iat-hook-install-messagebox/) | verified | high | 2026-11-06 |
| [IAT 槽位 Hook 识别与还原：VirtualProtect xref 定位 lstrcmpA 劫持 + 魔改 XXTEA 解密](code-analysis-reverse-windows-iat-hook-lstrcmp-xxtea/) | verified | high | 2026-11-06 |
| [KiSystemCall64 系统调用钩子：重写 IA32_LSTAR MSR + 自建伪造 SSDT/Shadow SSDT 跳板](code-analysis-reverse-windows-kisystemcall64-lstar-msr-hook/) | verified | medium | 2026-11-06 |
| [mimikatz 适配 Windows 11 24H2：lsasrv.dll LogonSessionList 签名/偏移与 KIWI_MSV1_0_LIST/MSV1_0_PRIMARY_CREDENTIAL 结构体变更](code-analysis-reverse-windows-mimikatz-24h2-lsasrv-offset-struct-adaptation/) | verified | medium | 2026-11-07 |
| [NjRAT 0.7d VB.NET 客户端 dnSpy 逆向：OK.ko 入口定位安装例程、C2 收发与键盘记录线程](code-analysis-reverse-windows-njrat-vbnet-dnspy-install-c2-analysis/) | verified | high | 2026-11-06 |
| [PE .text 代码空洞自动化注入：E8 call rel32 劫持、重定位清零与断点验证](code-analysis-reverse-windows-pe-text-code-cave-call-rel32-patch/) | verified | medium | 2026-11-05 |
| [PE TLS Callback 隐藏注入器：诱饵 main + 进程快照 + CreateRemoteThread 注入 shellcode](code-analysis-reverse-windows-pe-tls-callback-decoy-main-remote-thread-injection/) | verified | high | 2026-11-06 |
| [PE TLS 回调：在 OEP 之前执行代码（反调试/早期载荷）](code-analysis-reverse-windows-pe-tls-callback-pre-oep/) | verified | high | 2026-11-06 |
| [PE 导入表与基址重定位解析：ILT/IAT/绑定导入与 .reloc 块遍历](code-analysis-reverse-windows-pe-import-reloc-parser/) | verified | high | 2026-11-06 |
| [PsSetLoadImageNotifyRoutine 驱动监控 DLL 加载：模块路径、进程过滤与加载顺序验证](code-analysis-reverse-windows-load-image-notify-callback/) | verified | high | 2026-11-07 |
| [PTE Hook：通过 PML4/PDPT/PD/PT 页表重映射实现进程隔离的 Windows 内核函数 inline Hook](code-analysis-reverse-windows-pte-hook-page-table-isolation-inline-hook/) | verified | medium | 2026-11-07 |
| [Qt 注册码程序逆向：NOP 反调试后断点 QLineEdit::text 回溯调用者读取 UTF-16 明文](code-analysis-reverse-windows-qt-license-qlineedit-text-breakpoint/) | verified | medium | 2026-11-07 |
| [Remcos RAT SETTINGS 资源提取：RC4 与 0x7C1E1E1F7C 分隔的配置字段解析](code-analysis-reverse-windows-remcos-settings-config-extraction/) | verified | high | 2026-11-05 |
| [Section 型进程映像伪装取证：EPROCESS ImageFileName/ImageFilePointer/ImagePathHash 与 image coherency](code-analysis-reverse-windows-process-image-masquerade-forensics/) | verified | high | 2026-11-07 |
| [SEH 除零异常隐藏校验分支：在 __except 块下断点 + Z3 还原序列号](code-analysis-reverse-windows-seh-exception-logic-jump-z3-serial/) | verified | medium | 2026-11-07 |
| [Unity Mono 游戏静态逆向：Managed/Assembly-CSharp.dll 识别与 dnSpy 关键逻辑定位](code-analysis-reverse-windows-unity-mono-assembly-csharp-dnspy-analysis/) | verified | high | 2026-11-06 |
| [ValleyRAT 多阶段加载链：PyInstaller 投递 BGL.exe、shellcode1 按 codemark 取配置下载二期 shellcode、shellcode2 反射加载上线模块](code-analysis-reverse-windows-valleyrat-staged-shellcode-codemark-reflective-pe/) | verified | high | 2026-11-06 |
| [VMware 串口命名管道 + bcdedit 搭建双机内核调试环境（WinDbg 连接）](code-analysis-reverse-windows-kernel-debugging-vmware-windbg/) | verified | high | 2026-11-05 |
| [WDigest 凭据提取：从 LSASS 定位 l_LogSessList 与 h3DesKey/hAesKey/IV 解密密码，改 g_fParameter_UseLogonCredential 强制明文缓存](code-analysis-reverse-windows-wdigest-logsesslist-key-decrypt-logoncredential/) | verified | medium | 2026-11-07 |
| [WinDbg 枚举 PspCreateProcessNotifyRoutine 定位 Defender 进程创建回调与检测点](code-analysis-reverse-windows-process-notify-callback-analysis/) | verified | medium | 2026-11-05 |
| [WinDbg 枚举 PspCreateThreadNotifyRoutine：杀软线程创建回调与注入检测点](code-analysis-reverse-windows-thread-notify-callback-analysis/) | verified | medium | 2026-11-05 |
| [Windows API inline hook 隐藏校验分支：MessageBoxA 被重定向到 AES 校验](code-analysis-reverse-windows-api-hook-hidden-aes-branch/) | verified | high | 2026-11-06 |
| [Windows CNG BCrypt API 定位：RC4/MD5 协议与 MD5 原像](code-analysis-reverse-windows-cng-bcrypt-rc4-md5/) | verified | high | 2026-11-06 |
| [Windows ncalrpc 本地 RPC 接口发现与 MIDL 客户端调用](code-analysis-reverse-windows-ncalrpc-rpcview-midl-client/) | verified | high | 2026-11-05 |
| [WinHex 21.3 SR-8 x86 注册算法逆向与 Keygen：CRC32 校验、DOS 日期/用户数编码与 Delphi license 结构](code-analysis-reverse-windows-winhex-license-crc32-keygen/) | draft | high | 2026-11-07 |
| [Winos 远控载荷代际识别：内置登录模块.exe、缺失 |p1:| 配置与扩表杀软名单](code-analysis-reverse-windows-winos-payload-generation-identification/) | verified | medium | 2026-11-06 |
| [Winos4 远控平台载荷生成：资源段插件与 codemark/xiugaishiyong 配置追加](code-analysis-reverse-windows-winos4-builder-resource-config-injection/) | verified | high | 2026-11-06 |
| [x32 游戏列表类数据定位：CE 值扫描 + 堆栈回溯 + 基址偏移链（背包/仓库/NPC）](code-analysis-reverse-windows-game-list-data-pointer-chain/) | verified | high | 2026-11-05 |
| [x32 游戏控件数据定位：从登录输入小控件回溯到父级大控件的指针链](code-analysis-reverse-windows-game-control-pointer-chain/) | verified | medium | 2026-11-05 |
| [x32 游戏血量数据定位：CE 搜数 + 访问断点 + 逐层回溯到基址指针链](code-analysis-reverse-windows-game-health-pointer-chain/) | verified | medium | 2026-11-05 |
| [x86 Inline Hook：5 字节 E9 相对跳转拦截发包/加密函数](code-analysis-reverse-windows-x86-inline-hook-packet-intercept/) | verified | high | 2026-11-05 |
| [仿冒豆包客户端 doubaoai-app.exe 投放链：UAC 提权、AMSI/ETW 补丁、Defender 策略禁用与内核驱动加载](code-analysis-reverse-windows-doubao-imposter-configmanager-uac-amsi-driver/) | verified | high | 2026-11-05 |
| [封包缓冲区硬件写入断点：从密文 send 回溯明文缓冲区与加密 call](code-analysis-reverse-windows-game-packet-buffer-encryption-locate/) | verified | high | 2026-11-05 |
| [损坏 PE 驱动恢复：MZ 头修复 + 每 4 字节首字节 XOR 0x44 + IOCTL 多层 XOR 逆推](code-analysis-reverse-windows-corrupted-pe-driver-xor-ioctl-backtrack/) | verified | high | 2026-11-06 |
| [支付二维码实时替换木马：Magnify 截屏 + ZXing 解码 + QRCoder 重生成 + MoveWindow 覆盖](code-analysis-reverse-windows-payment-qr-realtime-substitution-magnifier/) | verified | high | 2026-11-06 |
| [未文档化 win32u 剪贴板读取：NtUserGetClipboardData 取句柄 + NtUserCreateLocalMemHandle 复制 UNICODETEXT](code-analysis-reverse-windows-ntuser-getclipboarddata-localmemhandle-read/) | verified | high | 2026-11-07 |
| [本地 UI 功能 call 定位：窗口对象坐标搜索与访问断点](code-analysis-reverse-windows-game-call-window-object-access/) | verified | high | 2026-11-05 |
| [游戏人物属性定位：沿已知血量指针链遍历相邻偏移找最大蓝/最大血/人物 ID](code-analysis-reverse-windows-game-character-attr-adjacent-enumeration/) | verified | medium | 2026-11-05 |
| [游戏发包架构判定：send 调用栈区分单线程/双线程队列并过滤心跳包](code-analysis-reverse-windows-game-send-architecture-heartbeat/) | verified | high | 2026-11-05 |
| [游戏对象方法 call 定位：虚表访问断点与槽位分析](code-analysis-reverse-windows-game-call-vtable-access/) | verified | high | 2026-11-05 |
| [游戏封包链路重建与代码注入：send1→加密 call→send2 顺序判定与参数复原](code-analysis-reverse-windows-game-packet-pipeline-code-injection/) | verified | high | 2026-11-05 |
| [游戏布尔状态数据定位：0/1 值搜索、候选筛选与访问断点回溯指针链](code-analysis-reverse-windows-game-state-boolean-pointer-chain/) | verified | high | 2026-11-05 |
| [白加黑合法 DLL 篡改定位：节区对比 + BinDiff 相似度 + IDA 差异找插入代码](code-analysis-reverse-windows-legit-dll-modification-bindiff/) | verified | medium | 2026-11-07 |
| [网络游戏功能 call 定位：send 断点与调用栈回溯](code-analysis-reverse-windows-game-call-send-backtrace/) | verified | high | 2026-11-05 |
| [脱壳样本 AES 配置静态提取：capa 定位 AES 调用链、交叉引用回溯静态密钥并用 CyberChef 解密](code-analysis-reverse-windows-aes-config-capa-xref-key-cyberchef/) | verified | medium | 2026-11-07 |
| [自动寻路 call 定位：目标坐标写入断点与参数回溯](code-analysis-reverse-windows-game-call-coordinate-write/) | verified | high | 2026-11-05 |
| [运行时自修复 syscall stub：扫描自身内存把 6B 00 00 73 6B 00 00 74 占位字节替换为 syscall;ret](code-analysis-reverse-windows-runtime-syscall-stub-self-patch/) | verified | high | 2026-11-06 |
| [银狐 nvgpu/nvml 投递链：TLS 回调前置释放器 + 内存特征扫描 + 动态 XOR 解密 + 手工解析 kernel32 导出表释放白加黑文件](code-analysis-reverse-windows-silverfox-tls-loader-nvgpu-nvml-chain/) | verified | medium | 2026-11-06 |
| [银狐样本 CEF Helper 白加黑：512MB 文件膨胀、导出表伪造与 TLS/CFF 反分析](code-analysis-reverse-windows-silverfox-cef-helper-dll-sideload-inflation/) | verified | medium | 2026-11-06 |
| [银狐样本配置还原：反转管道串 + denglupeizhi 标记 + IpDates_info 注册表](code-analysis-reverse-windows-silverfox-reversed-config-ipdates-info/) | verified | medium | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
