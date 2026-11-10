---
id: code-analysis-reverse-windows-festi-dropper-driver-service-selfdelete
title: Festi Dropper 静态分析：dword_404000 嵌入数据解密落地 .sys，CreateServiceA 注册内核驱动服务（LoadOrderGroup FSFilter Anti-Virus）并写 .bat 自删除
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: festi-dropper-embedded-driver-service-install-selfdelete
aliases:
- Festi Dropper
- 内核驱动投放器
- 随机驱动名
- FSFilter Anti-Virus LoadOrderGroup
- 驱动自删除 bat
- dword_404000 嵌入数据
- CreateServiceA 内核驱动服务
tags:
- reverse
- windows
- malware-analysis
- dropper
- kernel-driver
- service
- persistence
- self-delete
- festi
- masm
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V323
  verified_at: '2026-11-08T15:42:30+08:00'
  notes: 已对照 content.md 与全部 20 张图核对：img03 start() 的 GetTickCount/两检查/Drop1-3 分支、img04-05 dword_404000->Drop2、img05-06 sub_40151B 随机名(rand%6+8、rand%25+97、首字符 z、末尾数字)与 sub_401635 OpenSCManagerA(0xF003F)+CreateServiceA(0xF01FF/types=1/start=1/LoadOrderGroup "FSFilter Anti-Virus")+StartServiceA、img08 Drop3 的 CreateFileA/WriteFile/CreateProcessA 与 :try/goto try 自删除 bat 均与卡一致。原子性：同一 Dropper 的提取->落地->服务加载->自删除单链，未混入他样本技术，判为原子合格。未验证点：未运行样本，原文未给受影响的 Windows 版本/签名状态；sub_401092、sub_401CF6 细节原文未展开。dedup 候选中 fwrite 静态缓冲释放内嵌 PE、sc create 服务持久化均非同链。
---

## 一句话结论

Festi 的 32 位 MASM Dropper 在 `start()` 中先用 `GetTickCount` 播种随机数并做两项反分析检查，检查通过后从静态缓冲区 `dword_404000` 提取并解密内嵌的内核驱动，在 `%SystemRoot%\system32\drivers\` 下用随机文件名写入 `.sys`，再通过 `OpenSCManagerA`/`CreateServiceA` 以 `SERVICE_KERNEL_DRIVER`、`SERVICE_SYSTEM_START`、`LoadOrderGroup = "FSFilter Anti-Virus"` 注册服务并 `StartServiceA` 立即加载；最后生成 `%TEMP%` 下的 `.bat`，循环删除驱动文件与自身并用 `CreateProcessA` 执行，完成投放、持久化与痕迹清理。

## 原理

- **执行条件**：`start()` 先调用 `GetTickCount()` 播种随机数，然后执行 `sub_401092()`（某种环境/反分析检查）和 `sub_4010A9()`（`IsDebuggerPresent()`）；只有两者都返回假时才调用 `Drop1()`/`Drop2()` 投放驱动，`Drop3()` 无条件执行自删除。这样在调试器或可疑环境中不会落地驱动。
- **Drop1 提取嵌入驱动**：驱动载荷放在静态缓冲区 `dword_404000` 中。`Drop1()` 对该缓冲区做长度/偏移处理后交给 `sub_40117D()`（IDA 注释指出内部有 TEA 加密）和 `sub_401CF6()` 做复杂变换，结果写入约 16440 字节的栈缓冲区；这一步是“静态数据 → 内存中的完整驱动镜像”的解包过程。
- **Drop2 落地与注册服务**：`GetWindowsDirectoryA()` 取得 `%SystemRoot%`，`sub_40151B()` 生成随机名：长度 `rand()%6 + 8`（8-13 个字符），字符为 `rand()%25 + 97`（a-z），首字符固定 `'z'`（0x7A），末尾追加一个 `rand()%10` 的数字；拼成 `C:\Windows\system32\drivers\<随机名>.sys` 后写入文件。
- **服务注册参数伪装**：`sub_401635()` 调用 `OpenSCManagerA(0, 0, 0xF003F)`，再调用 `CreateServiceA(scm, 服务名, 服务名, 0xF01FF, 1, 1, 0, sys路径, "FSFilter Anti-Virus", 0, 0, 0, 0)`。其中 `0xF01FF` 是 `SERVICE_ALL_ACCESS`，服务类型 `1` 为 `SERVICE_KERNEL_DRIVER`，启动类型 `1` 为 `SERVICE_SYSTEM_START`，`lpLoadOrderGroup` 填 `"FSFilter Anti-Virus"`——这是文件系统过滤驱动的合法加载组，用来让随机命名的驱动看起来像杀软过滤驱动，降低人工和基于名称的检测。随后 `StartServiceA()` 立即启动，`CloseServiceHandle()` 收尾。
- **Drop3 自删除**：`GetModuleFileNameA()` 取得自身路径；构造批处理内容 `:try` / `del "<sys路径>"` / `if exist "<sys路径>" goto try` / `del "<bat路径>"`；用 `CreateFileA(..., 0xC0000000, 3, 0, 2, 0x80, 0)` 创建（`GENERIC_READ|GENERIC_WRITE`、`FILE_SHARE_READ|WRITE`、`OPEN_ALWAYS`、`FILE_ATTRIBUTE_NORMAL`），`WriteFile` 写入后 `CreateProcessA` 执行，最后释放缓冲区。循环 `goto try` 是因为已加载的驱动文件可能被系统锁定，需反复重试删除。
- **为什么有效**：内核驱动服务既提供持久化又以 `LocalSystem` 权限运行；随机服务/文件名和合法加载组规避静态特征；自删除降低磁盘取证价值。对分析者而言，抓住“`drivers` 目录下随机 `.sys` + `SERVICE_KERNEL_DRIVER` + `FSFilter Anti-Virus` 加载组 + `%TEMP%` 自删除 bat”这条链即可还原投放行为。

## 触发条件

- Dropper 为 32 位 PE（原文样本 PE32、Windows 95 子系统、Microsoft Linker 8.00.50727、MASM 8.00.50727、x86 Assembly），在具有管理员权限的 Windows 上运行；创建内核驱动服务需要管理员/SYSTEM。
- 样本为旧式未签名驱动，现代 Windows 默认启用驱动签名强制，直接加载会失败；分析应在隔离环境进行，不运行样本。
- 仅用于授权恶意样本静态分析。

## 利用步骤

1. 用 IDA 打开 Dropper，确认 PE32/MASM，定位 `start()`；记录 `GetTickCount` 播种和两个反分析检查（`sub_401092`、`IsDebuggerPresent`）。
2. 跟随 `Drop1()`：定位 `dword_404000` 静态缓冲区、`sub_40117D`（TEA）与 `sub_401CF6` 的数据变换，确认嵌入驱动的解包路径。
3. 跟随 `Drop2()`：记录 `GetWindowsDirectoryA`、`sub_40151B` 随机名算法、`system32\drivers\<name>.sys` 路径拼接、`sub_401591` 文件写入。
4. 分析 `sub_401635()`：确认 `OpenSCManagerA` 权限 `0xF003F`、`CreateServiceA` 的服务类型/启动类型/`LoadOrderGroup`，以及 `StartServiceA` 调用。
5. 分析 `Drop3()`：提取批处理模板、`CreateFileA`/`WriteFile`/`CreateProcessA` 参数，理解循环删除逻辑。
6. 汇总 IOC：`%SystemRoot%\system32\drivers\` 下 8-13 位小写字母+数字的 `.sys`、`LoadOrderGroup=FSFilter Anti-Virus` 的内核服务、`%TEMP%` 下含 `:try` 与 `goto try` 的 `.bat`。

## PoC

静态分析得到的投放链伪代码（按原文反编译图重写，未执行）：

```c
// start(): 反分析检查通过才投放
GetTickCount();                       // 播种随机数
if (!sub_401092() && !IsDebuggerPresent()) {
    Drop1();                          // dword_404000 -> TEA/变换 -> 驱动镜像
    Drop2();                          // 写 drivers\<random>.sys + 注册并启动服务
}
Drop3();                              // 生成 %TEMP% bat 自删除

// Drop2 关键路径
GetWindowsDirectoryA(winDir, 0x104);
sub_40151B(name);                     // 首字符 'z' + a-z 随机 + 数字
sprintf(path, "%s\\system32\\drivers\\%s.sys", winDir, name);
sub_401591(path);                     // 写驱动文件
sub_401635(path, name);               // 注册并启动内核服务

// sub_401635 的服务注册参数
CreateServiceA(scm, name, name,
               0xF01FF,               // SERVICE_ALL_ACCESS
               1,                     // SERVICE_KERNEL_DRIVER
               1,                     // SERVICE_SYSTEM_START
               0, path,
               "FSFilter Anti-Virus", // 伪装为文件系统过滤驱动加载组
               0, 0, 0, 0);
StartServiceA(svc, 0, 0);
```

自删除批处理模板：

```bat
:try
del "C:\Windows\system32\drivers\<random>.sys"
if exist "C:\Windows\system32\drivers\<random>.sys" goto try
del "%TEMP%\<random>.bat"
```

## 变体与关联

- 变体：随机名算法、加密算法（TEA/XOR/RC4）、载荷所在段（`.data`/资源段/附加数据）都可替换；分析时先找“大块高熵静态数据 + 解密循环 + 写 `.sys` + 创建服务”的组合。
- 变体：服务注册可用 `NtCreateService`/`ChangeServiceConfig` 或直接写注册表 `HKLM\SYSTEM\CurrentControlSet\Services\<name>`；加载组可换成其他合法过滤组。
- 关联：[[code-analysis-reverse-unpacking-fwrite-static-buffer-embedded-pe]]（从静态缓冲区释放内嵌驱动的同类手法）；[[pentest-persistence-windows-service-cmd-start-createsvcrpc]]（Windows 服务持久化对照）；[[code-analysis-reverse-windows-driver-cdata-xor-api-resolution]]、[[code-analysis-reverse-windows-rootkit-fs-filter-attach-hide-file]]（同族 Festi 驱动的后续能力）。
- 边界：旧样本在现代 Windows 上可能因驱动签名强制、子系统版本或 API 行为变化无法加载；部分辅助函数（`sub_401092` 的具体检查、`sub_401CF6` 的变换细节）原文未展开。

## 检测与防御

- **服务监控**：Sysmon 事件 ID 7045/4697 关注服务类型为内核驱动、启动类型为 `SERVICE_SYSTEM_START`、`LoadOrderGroup` 含 `FSFilter` 的随机命名服务；对比已知杀软/过滤驱动白名单。
- **文件监控**：`%SystemRoot%\system32\drivers\` 下新增随机名 `.sys`；`%TEMP%` 下出现含 `:try`/`goto try` 的批处理；同一时间窗口内文件被反复删除重试。
- **驱动加载**：监控 `StartServiceA`/`NtLoadDriver` 加载未签名或签名异常的驱动；启用驱动签名强制、HVCI、WDAC。
- **静态检测**：YARA 匹配 `dword_404000` 大块数据、TEA 常量、`FSFilter Anti-Virus`、随机名生成特征与自删除 bat 模板。
- **防御**：限制本地管理员权限、开启 Credential Guard/驱动黑名单；对内核服务创建做审计与告警；隔离环境分析样本，不执行 Dropper。
