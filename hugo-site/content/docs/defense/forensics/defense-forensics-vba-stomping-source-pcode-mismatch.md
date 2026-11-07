---
id: defense-forensics-vba-stomping-source-pcode-mismatch
title: VBA Stomping 识别：olevba 发现 VBA 源码与 p-code 不一致，静态审计不能只看源码
type: scenario
domain: defense
path: defense/forensics
technique: vba-stomping-pcode-source-mismatch
tags:
- office
- vba
- macro
- malware-analysis
- forensics
- p-code
- olevba
- evasion
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:51:47+08:00'
  notes: 已对照原文核对；olevba 检出源码与 p-code 不一致、p-code 实际 MsgBox、flag 藏多槽位与栈 VM 顺序一致
url: /docs/defense/forensics/defense-forensics-vba-stomping-source-pcode-mismatch/
draft: false
kb_aliases:
- VBA Stomping
- 源码与 p-code 不一致
- olevba VBA Stomping was detected
- Office 宏取证
- p-code 反汇编
- 宏安全审计
---

## 一句话结论

Office 文档的 VBA 工程同时保存压缩源码与编译后的 p-code，实际执行的是 p-code；攻击者可以只改源码或只留 p-code，让静态审计看到“已通过”“无害”的 VBA 源码，而真正运行的是另一份逻辑。`olevba` 报 `VBA Stomping was detected: the VBA source code and P-code are different` 时，必须反汇编 p-code 并检查整个 OLE 工程，不能相信可见源码。

## 原理

- VBA 工程（`vbaProject.bin`）包含两类表示：压缩的 VBA 源码与编译后的 p-code（performance cache）。Office 执行宏时使用 p-code，源码主要用于查看/编辑。
- 攻击者可以用工具修改其中一份而不同步另一份：保留人畜无害的源码、替换 p-code 为恶意逻辑（典型 VBA Stomping）；或反过来保留恶意源码、删除 p-code，让源码扫描器报警而实际不执行。
- 只读源码的审计/杀软会得出错误结论：源码里的“审计通过”、假的 flag、注释都可能只是诱饵；真正的行为在 p-code 或其它 OLE 流/嵌入对象中。
- `olevba` 会比对源码与 p-code 的哈希/内容，发现不一致时输出 `VBA Stomping was detected`；`pcodedmp` 可反汇编 p-code，`oledump.py` 可枚举 OLE 流与宏。
- 本例中可见 VBA 源码声称审计通过并嵌入假 flag，但 p-code 实际只执行 `MsgBox "Hello from Python!"`；真正的 flag 藏在工作簿的多个物理槽位（文档属性、工作表 XML 注释、`vbaProject.bin` 附加字节、`vbaCache.bin` 等），由一段自定义栈 VM 决定拼装顺序。这说明“源码/p-code 不一致”只是入口，必须把整个文档当容器审计。

## 触发条件

- 目标文档为启用宏的 Office 文件（`.docm`、`.xlsm`、`.doc`、`.xls` 等），包含 VBA 工程。
- 攻击者能生成/修改 VBA 工程（工具如 olevba 的 stomping 功能、Evil Clippy 等），且目标 Office 版本会执行 p-code。
- 分析流程只提取 VBA 源码（strings、源码导出、仅看 VBA 编辑器），没有比对 p-code。
- 文档可能同时携带隐藏 OLE 流、嵌入对象、自定义 XML、缓存文件等。

## 利用步骤

分析/审计步骤（不执行宏）：

1. 识别宏：`oleid file.xlsm`、`olevba file.xlsm`；记录是否存在 VBA、AutoOpen/Workbook_Open 等入口。
2. 查找 stomping：`olevba file.xlsm` 输出中搜索 `VBA Stomping was detected`；同时比对 `VBA MACRO` 源码与 p-code 摘要。
3. 反汇编 p-code：`pcodedmp file.xlsm`（或 `oledump.py -s <vbaProject.bin 流> -v` 配合 p-code 插件），查看实际调用的 API、字符串、分支。
4. 枚举容器：把 xlsm 当 ZIP 拆开，检查 `docProps/core.xml`、`xl/workbook.xml`、`xl/worksheets/*.xml` 注释、`xl/embeddings/*`、`vbaProject.bin` 尾部附加数据、`vbaCache.bin` 等。
5. 交叉验证：源码、p-code、缓存、嵌入对象四者的行为/字符串是否一致；对自定义 VM/加密数据，按注释或缓存中的算法还原。
6. 如需动态验证，在隔离沙箱中启用宏运行，监控进程、文件、网络；不要在生产/分析主机直接打开。

## PoC

```bash
# 1) 宏存在性与 stomping 检测
olevba suspicious.xlsm
# 输出示例：
# VBA Stomping was detected: the VBA source code and P-code are different

# 2) 反汇编 p-code
pcodedmp suspicious.xlsm > pcode.txt

# 3) 枚举 OLE 流/嵌入对象
oledump.py suspicious.xlsm
# 按流编号提取 VBA/缓存
oledump.py -s <stream_index> -v suspicious.xlsm
```

无恶意样本 PoC；上述命令用于对可疑文档做只读静态分析。`olevba`/`pcodedmp` 的可用性取决于安装与环境。

## 变体与关联

- 变体：源码无害、p-code 恶意（典型 VBA Stomping）；源码恶意、p-code 缺失（源码扫描报警但实际不执行）。
- 变体：Excel 4.0 宏（XLM）、OLE 嵌入对象、远程模板（`.dotm`）、`vbaProject.bin` 尾部附加加密数据，均可能绕过只看 VBA 源码的审计。
- 变体：把真正的载荷放在文档属性、工作表 XML 注释、自定义 XML、缓存文件等“非宏”位置，宏只负责读取/解密。
- 关联卡片：[[pentest-initial-access-office-macro-document]]（Office 宏投递与 AutoOpen）、[[defense-forensics-cve-2026-34621-pdf-js-layered-deobfuscation]]（文档分层去混淆）、[[ai-security-supply-chain-poisoned-pyc-source-bytecode-mismatch]]（源码与字节码不一致的同类思路）。

## 检测与防御

- 检测：邮件/文件网关对 Office 文档运行 `olevba`/`oleid`，对 `VBA Stomping was detected`、p-code 与源码不一致、宏+嵌入对象组合告警。
- 检测：终端监控 Office 创建子进程（`powershell`、`wscript`、`mshta`、`cmd`）、写入启动目录、外联；即使用户启用宏也能在行为层拦截。
- 防御：通过 GPO 禁用来自 Internet 的宏、阻止宏文档、启用受保护视图与 MOTW；对必须使用宏的业务使用受信任位置与签名宏。
- 防御：分析流程强制“源码 + p-code + OLE 流 + 嵌入对象”四路交叉；不要仅凭 VBA 源码或字符串判断文档无害。
- 响应：隔离文档与主机，提取 p-code/嵌入对象做沙箱分析，检查是否已有宏执行痕迹（Office 进程树、临时文件、网络连接），轮换可能泄露的凭据。
