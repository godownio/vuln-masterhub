---
id: code-analysis-reverse-windows-legit-dll-modification-bindiff
title: 白加黑合法 DLL 篡改定位：节区对比 + BinDiff 相似度 + IDA 差异找插入代码
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: bindiff-legit-dll-modification-locate
aliases:
- 白加黑
- DLL 侧加载
- 合法 DLL 篡改
- 99% 相似度 DLL
- BinDiff 差异分析
- IDA diff
- AliyunWrap.dll
tags:
- windows
- reverse
- bindiff
- ida
- dll-sideload
- malware-analysis
- white-black
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V211
  verified_at: '2026-11-07T04:49:08+08:00'
  notes: 已对照原文与 img11-13/15 核对：.text 0x64E63→0x651C3、.rdata 0xE6CB→0xE717、BinDiff 0.99/2093-2103 匹配、低相似度函数列表、AliyunWrap.dll 44/72 与宿主 0/72 均与原文一致；已把正文中原文未提及的“导出表”表述收敛为导入表。未验证点：未取得样本复跑 BinDiff/IDA diff；trampoline 操作数按原文截图保留为示意。
---

## 一句话结论

当被侧加载的恶意 DLL 与某厂商合法 DLL 的 BinDiff 相似度高达 99% 时，说明攻击者是在原厂 DLL 上做了少量代码插入；先比对 PE 节区大小/熵，再用 BinDiff 按函数相似度升序排序，最后在 IDA 差异视图中定位插入的基本块与调用，就能还原“白加黑”DLL 的篡改点。

## 原理

- “白加黑”利用合法/签名宿主 EXE 侧加载同目录 DLL。若直接伪造一个同名 DLL，宿主常因缺少原厂导出函数而崩溃；攻击者改用“原厂 DLL + 少量恶意代码”的方式：完整保留 PE 格式、导入表和数据收集等正常功能，宿主行为基本不变，杀软对宿主与白文件的信任度也更高。
- 样本只修改少量函数时，BinDiff 的函数匹配结果会非常集中：绝大多数函数相似度接近 1.0，少数函数相似度异常低（例如 0.01、0.09、0.27），这些低相似度函数就是被篡改或新增逻辑的位置。
- 修改点通常不是新增一个独立导出函数，而是在某个原厂函数中插入 `mov/xor/lea/call [rva]/push/call/jmp` 形式的 trampoline，跳转到恶意代码；IDA/Ghidra 的并排差异视图会把新增指令标红。
- PE 节区的虚拟大小/原始大小/熵变化是快速线索：文章样本的 `.text` 虚拟大小从 `0x64E63` 变为 `0x651C3`、`.rdata` 从 `0xE6CB` 变为 `0xE717`，说明代码/只读数据被追加。
- 原厂 DLL 的来源可通过版本资源、PDB 路径、导出函数名、文件描述和 VirusTotal 的“Bundled files”关联到具体厂商安装包（文章样本来自 EaseUS Partition Master 的 `AliyunWrap.dll`，用于收集系统信息并调用 `LocateAliyun.ini`、`DataFile.ini`、`AliyunConfig.ini` 通信）。

## 触发条件

- 已获得恶意 DLL 样本，并能取得同架构、同版本的原厂 DLL（通常从厂商官方安装包中提取）。
- 样本未加壳，或可以先脱壳到可比较的 PE；.NET DLL 需先用 de4dot/dnSpy 还原。
- 具备 BinDiff（或 Diaphora）与 IDA/Ghidra 等差异分析工具。
- 样本保留了足够多的原厂代码，函数匹配才有稳定的 99% 相似度基线；若被大规模重写，方法退化为普通逆向。

## 利用步骤

1. 记录样本 DLL 的名称、版本资源、编译时间戳、PDB 路径与哈希，在厂商官网/官方安装包/VirusTotal 关联文件中找到原厂同版本 DLL。
2. 用 PE 查看器对比两者的节表：`.text`/`.rdata`/`.data`/`.rsrc` 的虚拟大小、原始大小、熵、校验和；先圈定发生变化的节区。
3. 在 BinDiff 中以原厂 DLL 为 primary、样本 DLL 为 secondary，记录 Overall similarity、匹配函数数/总数，并按 similarity 升序排列。
4. 对相似度最低的函数逐个在 IDA/Ghidra 中并排 diff，查看新增基本块、跨函数调用、动态 API 解析（`LoadLibrary`/`GetProcAddress`）或字符串引用。
5. 跟随插入的 trampoline 进入恶意函数，提取其网络 IOC、配置读取逻辑和持久化动作；再把 DLL 与加载它的宿主 EXE、同目录文件关联起来。
6. 用多引擎结果佐证白加黑特征：文章样本中 `AliyunWrap.dll` 为 44/72 检测，而宿主 `VorteProcessor32.exe` 为 0/72，单独看宿主容易漏判。

## PoC

无自动化 PoC；最小分析记录如下（数据来自文章样本）：

```text
BinDiff: primary = AliyunWrap_original.dll, secondary = AliyunWrap_sample.dll
Overall similarity: 0.99
Matched functions: 2093 / 2103

低相似度函数（按相似度升序）:
  sub_100017A0        0.01
  sub_100026F0        0.09
  sub_10002190        0.10
  sub_100021E0        0.10
  sub_1000E610        0.12
  sub_10002000        0.14
  sub_10001FC0        0.15
  AliyunStopProcess   0.27
```

IDA 差异视图中看到的新增 trampoline（示意，操作数因截图模糊未逐字保留）：

```asm
mov     eax, esi
xor     edx, edx
lea     eax, [esp+58h]
call    ds:[...]
push    1000FFFEh
call    ds:[...]
jmp     ...
```

## 变体与关联

- 变体：找不到原厂 DLL 时，退回“伪造同名 DLL + 导出转发”方案；见 [[pentest-persistence-dll-search-order-hijack-proxy-forwarding]]。
- 变体：样本加壳时先脱壳（UPX/自定义壳），再与脱壳后的原厂 DLL 比对。
- 变体：.NET DLL 用 de4dot 去混淆后，用 dnSpy/dnlib 对比类型与方法体；原生 DLL 用 Diaphora 或 BinDiff 均可。
- 关联：[[code-analysis-reverse-windows-silverfox-cef-helper-dll-sideload-inflation]]（另一个 DLL 侧加载案例，恶意 DLL 通过伪造导出/文件膨胀对抗分析；本卡重点是“原厂 DLL 少量篡改”的差异定位）。
- 关联：[[pentest-initial-access-fake-captcha-mshta-remote-hta]]（同一文章样本的前置投递链）。
- 边界：原厂 DLL 版本不一致、样本被大规模重写或加壳后无法还原时，99% 相似度基线不成立，需改用常规逆向与沙箱行为分析。

## 检测与防御

- 检测：同一目录内出现与知名厂商 DLL 同名但哈希不同的文件；宿主 EXE 多引擎 0 检测而同目录 DLL 多引擎告警；DLL 从 `ProgramData`、`Temp`、用户可写目录被加载。
- 检测：DLL 的 Authenticode 签名缺失或与厂商不一致；PE 节区大小/熵与官方版本差异明显；BinDiff/威胁情报可辅助确认篡改。
- 防御：对厂商 DLL 建立哈希/签名白名单，加载前校验 Authenticode；用 WDAC/AppLocker 限制用户可写目录中的 DLL 加载；启用 EDR 的镜像加载监控与 DLL 侧加载规则。
- 加固：不要把用户可写目录加入 DLL 搜索路径；对合法软件安装目录设置写权限限制；定期比对关键 DLL 与官方版本哈希。
