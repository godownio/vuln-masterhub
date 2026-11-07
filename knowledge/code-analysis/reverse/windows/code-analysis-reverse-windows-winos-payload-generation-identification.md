---
id: code-analysis-reverse-windows-winos-payload-generation-identification
title: Winos 远控载荷代际识别：内置登录模块.exe、缺失 |p1:| 配置与扩表杀软名单
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: winos-payload-generation-identification
aliases:
- Winos 4.0 载荷形态
- Winos 更高版本识别
- 登录模块.exe
- 上线模块.dll
- DLL2shellcode
- p1:o1:t1 配置
- 银狐 Winos 代际判别
tags:
- windows
- malware-analysis
- reverse
- winos
- silverfox
- payload
- identification
- shellcode
- dll2shellcode
- login-module
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V173
  verified_at: '2026-11-06T17:00:03+08:00'
  notes: 已对照原文核对：4.0基线（DLL2shellcode内嵌上线模块、EXE带|p1:配置）与本样本差异（内嵌EXE、无配置、核心同登录模块、名单扩张）均准确；更高版本为原文推断，卡内已标medium/推断
---

## 一句话结论

Winos 4.0 的载荷有稳定形态：shellcode 按内置配置外联并下载 `上线模块.dll`/`登录模块.dll`，DLL2shellcode 内嵌 `上线模块.dll`，生成的 EXE 核心代码等同 `上线模块.dll` 且带 `|p1:|o1:|t1:|...` 配置；若样本的 shellcode 直接内嵌一个 EXE、该 EXE 没有这套配置串、核心代码却等同 `登录模块.dll`，同时内置杀软名单明显扩张，就应怀疑它不是常见 Winos 4.0 生成物，而是更高版本框架的产物（该代际结论属分析者推断，需更多样本印证）。

## 原理

- **Winos 4.0 的载荷分工**：控制端可生成 shellcode、EXE、DLL2shellcode、`上线模块.dll`、`登录模块.dll` 等形态。shellcode 负责按内置配置外联 C2、按目标位数下载并解密 `上线模块.dll`/`登录模块.dll`；`上线模块.dll` 解析 `|p1:|o1:|t1:|p2:|o2:|t2:|p3:|o3:|t3:|dd:|cl:|fz:|bb:|bz:|jp:|bh:|ll:|dl:|sh:|kl:|bd:|` 形式的内置配置（C2、端口、分组等），再加载 `登录模块.dll`；`登录模块.dll` 负责环境检查、信息收集与核心远控功能。
- **4.0 生成物的三个判据**：DLL2shellcode 中内嵌的是 `上线模块.dll`；生成的 EXE 解析上述 `|p1:|...` 配置，且核心代码与 `上线模块.dll` 一致；`登录模块.dll` 本身不含这套配置串。
- **本条样本的差异**：shellcode 中内嵌的是 EXE（而非 `上线模块.dll`）；该 EXE 不含 `|p1:|...` 配置串；其核心代码与 `登录模块.dll` 一致；内置反杀软名单比 4.0 的 `登录模块.dll` 更丰富。三者叠加说明投递结构与 4.0 默认生成链不同：原本“shellcode → 上线模块 → 下载登录模块”的两级关系，被压缩成“shellcode → 内置登录模块.exe”的一级关系。
- **为什么可作代际线索**：远控框架的生成模板、配置格式和模块边界通常随版本演进；默认生成链改变、配置解析代码消失、模块职责合并，都是版本差异的直接证据。相比之下，代码混淆、字符串加密、C2 地址这类内容每次生成都可能不同，不适合单独作代际判据。
- **为什么不能只凭“更高版本”下结论**：攻击者也可手工改造 4.0 生成物、把登录模块重新打包成 EXE、删除配置串或替换名单；没有控制端版本、编译时间、PDB/签名等旁证时，只能把“更高版本”作为假设。分析时应同时检查是否有人工拼接痕迹（节表异常、入口跳转、资源重复）。
- **家族归属**：本条样本的代码结构、字符串特征与银狐系 Winos 登录模块同源，可归入 Winos/银狐家族；代际判断与家族归属是两个独立结论，不要混为一谈。

## 触发条件

- 拿到的是 Winos/银狐系远控载荷（shellcode、EXE、DLL 或 DLL2shellcode），需要判断生成平台版本或与已知 4.0 样本的关系。
- 能定位并解析载荷中的配置串、模块边界与核心代码；具备 IDA/Ghidra、PE 工具与字符串/十六进制对比能力。
- 有已知 Winos 4.0 样本或控制端资源作为对照（`上线模块.dll`、`登录模块.dll`、`|p1:|...` 配置样本）。
- 样本未被强混淆/虚拟化到无法比对核心代码；若核心代码被 VM 保护，需先脱壳或改用行为/配置特征。

## 利用步骤

1. **盘点载荷形态**：判断样本是裸 shellcode、EXE、DLL 还是 DLL2shellcode；对 DLL2shellcode，检查前置 stub 之后的内嵌模块是 DLL 还是 EXE。
2. **搜索配置串**：在样本中搜索 `|p1:|o1:|t1:|`、`|dd:|cl:|fz:|` 等标记；4.0 的 EXE/上线模块应能命中，登录模块与更高版本样本可能没有。
3. **比对核心代码**：把样本核心函数与已知 `上线模块.dll`、`登录模块.dll` 做 BinDiff/函数哈希/字符串交叉比对；确认它更像哪一个模块。
4. **检查投递关系**：shellcode 是“下载上线模块”还是“直接携带可执行模块”；是否还保留按位数请求载荷、解密下载内容等 4.0 shellcode 行为。
5. **对比对抗名单**：提取内置杀软进程/窗口名单，与 4.0 `登录模块.dll` 的名单做集合差；名单显著扩张可作为版本演进的辅助证据。
6. **排除人工改造**：检查 PE 节表、入口、资源、附加数据是否有人工拼接痕迹；结合编译时间、签名、PDB、C2 基础设施等旁证。
7. **给出分级结论**：家族归属（Winos/银狐）与代际判断分开写；代际结论标注“推断/待验证”，不要写成已确认的版本号。

## PoC

无公开利用 PoC（纯分析判定流程）。可用如下命令做初步筛查：

```text
strings -a sample.bin | findstr /C:"|p1:|o1:|t1:"
strings -a sample.bin | findstr /C:"This program cannot be run in DOS mode"
```

```python
data = open('sample.bin','rb').read()
markers = [b'|p1:|o1:|t1:', b'|dd:|cl:|fz:|', b'This program cannot be run in DOS mode']
for m in markers:
    print(m, hex(data.find(m)) if data.find(m) != -1 else 'not found')
```

## 变体与关联

- 变体：更高版本可能继续合并模块（把上线与登录逻辑都塞进一个 EXE）、更换配置标记、改用新的加密/压缩；也可能保留 4.0 配置格式但只改名单。
- 关联：[[code-analysis-reverse-windows-winos4-builder-resource-config-injection]]（Winos4 控制端资源段与 `xiugaishiyong`/`codemark` 配置追加，是本卡 4.0 基线）、[[pentest-initial-access-signed-msi-huorong-fake-installer-scheduled-task]]（本样本的投递链）、[[pentest-c2-winos-wps-loader-processcount-rc4-custom-decrypt]]（本样本加载链）、[[pentest-c2-shellcode-embedded-pe-bytewise-api-decrypt-loader]]（内嵌 PE 自加载机制）。
- 同家族：[[pentest-c2-silverfox-hellogpt-installer-dropper-chain]]、[[pentest-c2-silverfox-inno-dlclr-vmprotect-png-zlib-chain]]、[[pentest-c2-silverfox-sogou-sideload-inflation-aes-reflective-chain]]。

## 检测与防御

- **静态标记**：`|p1:|o1:|t1:|...` 配置串、`xiugaishiyong`/`codemark` 标记、DLL2shellcode 的非 MZ 前置 stub、内嵌 PE 的 DOS stub；命中可快速归入 Winos 4.0 生成物。
- **代际线索**：shellcode 内嵌 EXE、配置串缺失、核心代码等同登录模块、杀软名单扩张，四条同时出现时按“疑似更高版本/人工改造”处理，保留样本供进一步比对。
- **家族指纹**：登录模块的窗口标题检测名单、杀软进程名单、C2 配置结构可作为 YARA/内存规则；名单本身也会随版本变化，需持续更新。
- **检测落点**：安装包/计划任务投递链（见关联卡）+ wps.exe 双层解密 loader + 内嵌 PE 手动映射，三层联合检测比单看文件哈希更稳。
- **处置**：封禁 C2、清除计划任务与载荷、抓取内存样本；把代际判断写入情报备注，避免把“更高版本”当成确定结论误导后续狩猎。
