---
id: ctf-forensics-docm-vba-project-password-dpb-bypass
title: Word DOCM VBA 工程密码保护绕过：篡改 DPB 标记 + olevba 提取并改写 Decode 调用取明文
type: scenario
domain: ctf
path: ctf/forensics
technique: docm-vba-project-password-dpb-bypass
tags:
- ctf
- forensics
- office
- docm
- vba
- macro
- password-bypass
- olevba
- dpb
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V180
  verified_at: '2026-11-06T17:09:57+08:00'
  notes: 已对照原文核对：DPB(66 50 42)/DPA 篡改位于 vbaProject.bin 偏移 FCC0，olevba 提取 Encode/Decode 分支与 PoC 一致；未在本机复跑
url: /docs/ctf/forensics/ctf-forensics-docm-vba-project-password-dpb-bypass/
draft: false
kb_aliases:
- VBA 工程密码绕过
- DPB 标记
- vbaProject.bin DPB
- olevba 提取宏
- 宏密码破解
- Decode Label_ls
- EasyWord
---

## 一句话结论

Word/Excel 的“VBA 工程密码”只是阻止在编辑器里查看/编辑宏的 UI 保护，宏源码仍以可解析形式存在于 `word/vbaProject.bin`；把该 OLE 流中的 ASCII 标记 `DPB="..."` 改成 `DPA` 可让 Office 不再弹密码框，或用 `olevba` 直接提取源码后把 `Decode(Label_x.Caption, input)` 的校验分支改成直接解密标签，即可在不知道宏密码/不逆向 Encode 的情况下拿到宏内硬编码的明文口令。

## 原理

- **DOCM/XLSM 是 ZIP/OOXML 容器**：改后缀解压后可见 `[Content_Types].xml`、`_rels/`、`word/` 等；宏位于 `word/vbaProject.bin`，它是 OLE 复合文档（一个文件里包含多个流），保存 VBA 源码、p-code、引用等信息。
- **VBA 工程密码不是内容加密**：设置“VBA 工程密码”后，Office 只在打开 VBA 编辑器时弹窗要求口令；宏源码大多仍原样保存在 OLE 流中，`olevba` 等工具可直接提取。真正的文档加密（`EncryptedPackage` + `EncryptionInfo`）才会把内容整体加密。
- **DPB 标记**：`vbaProject.bin` 中存在可读 ASCII 标记 `DPB="..."`（十六进制 `44 50 42`），Office 用它判断工程是否受密码保护。把 `DPB` 改成 `DPA` 等非法/非预期值后，Office 找不到合法 DPB 标记，可能不再弹密码框，VBA 编辑器即可打开（不同 Office 版本行为可能有差异，需备份原文件）。
- **脚本路线**：`olevba word/vbaProject.bin` 静态提取宏源码，无需输入宏密码。示例宏先计算 `strusout = Encode(strusrinput, t)`，再与 5 个常量比较，命中后调用 `Decode(Dialog.Label_lsX.Caption, sinput)`；攻击者不需要理解 `Encode`，只要把分支改成 `Decode(Dialog.Label_lsX.Caption, t)`（或对五个标签逐个调用 `Decode`），运行 `AutoOpen` 并随便输入，就能在对话框 label 中看到解密后的明文。
- **为什么成立**：宏的输入校验与解密逻辑都在同一段 VBA 代码里，攻击者拥有文件即可修改/重新运行；密码只保护“查看源码”的入口，不保护“运行/修改宏”的能力（一旦绕过入口）。CTF 中常把多组口令藏在 `Label_lsX.Caption` 密文中，改一行 `Decode` 调用即可批量泄露。
- **整体流程**：若文档整体加密，需要先用 `office2john` 提取哈希并爆破口令，再用 `msoffcrypto-tool` 解密 `EncryptedPackage` 得到含 `vbaProject.bin` 的明文 docm；然后才进入 VBA 工程密码/宏逻辑绕过。

## 触发条件

- 获得启用宏的 Office 文档（`.docm/.xlsm/.doc/.xls`），且 `word/vbaProject.bin` 存在。
- 文档设置了 VBA 工程密码，打开 VBA 编辑器时弹窗；或宏内存在输入校验/`Decode` 逻辑。
- 分析环境有 `oletools`（`olevba`）、十六进制编辑器/解压工具；若要运行改写后的宏，需要可运行 VBA 的 Office 环境。
- 若文档整体加密，还需要已知/可爆破的打开密码与 `msoffcrypto-tool`。
- 目标 Office 版本对 DPB 篡改的行为未做严格校验（部分版本可能拒绝/修复）。

## 利用步骤

1. **解包**：把 `.docm` 改名为 `.zip` 解压，确认 `word/vbaProject.bin` 存在；若只看到 `EncryptedPackage`/`EncryptionInfo`/`_DataSpaces`，说明文档整体加密，先走 `office2john` + `john/hashcat` 爆破，再用 `msoffcrypto` 解密。
2. **手动绕过**：用十六进制编辑器打开 `vbaProject.bin`，搜索字符串 `DPB`（十六进制 `44 50 42`），把 `DPB` 改成 `DPA`；保存后按原目录结构重新打包成 ZIP，改回 `.docm`，打开文档进入 VBA 编辑器确认不再要求密码。
3. **脚本提取**：`pip install oletools`，运行 `olevba word/vbaProject.bin` 查看宏源码；定位输入校验分支（如 `If strusout = "..." Then ... Decode(Label.Caption, sinput)`）。
4. **改写 Decode 调用**：把分支中的 `Decode(Dialog.Label_lsX.Caption, sinput)` 改为 `Decode(Dialog.Label_lsX.Caption, t)`（`t` 为宏内固定字符串），或直接对五个 `Label_lsX.Caption` 逐个调用 `Decode` 并输出。
5. **运行 AutoOpen**：打开文档、启用宏，随便输入字符点击确定；对话框 label 显示每个分支的明文口令。
6. **后续**：用得到的明文测试压缩包/RAR 密码或题目下一阶段；CTF 中常需结合 hint 推导最终 flag。

## PoC

示例宏关键分支：

```vbnet
t = ChrW(21152) & ChrW(27833) & ChrW(21543) & ChrW(65292) & ChrW(21516) & ChrW(23398) & ChrW(20204) & ChrW(65281)
' t = "加油吧，同学们！"

strusout = Encode(strusrinput, t)

If (strusout = "©È©Y¨¯q£ø~") Then
    strdec = Decode(Dialog.Label_ls.Caption, sinput)
ElseIf (strusout = "£ëGJE£ç£ñ") Then
    strdec = Decode(Dialog.Label_ls1.Caption, sinput)
ElseIf (strusout = "§À¦¯opz+") Then
    strdec = Decode(Dialog.Label_ls2.Caption, sinput)
ElseIf (strusout = "£ú¦ªjr§º¦Õ¦Å¤¢") Then
    strdec = Decode(Dialog.Label_ls4.Caption, sinput)
ElseIf (strusout = "¨¤¨µt£Õ£÷©Ë£è¨¨") Then
    strdec = Decode(Dialog.Label_ls3.Caption, sinput)
Else
    strdec = "密码不正确,别泄气再来!"
End If
Label_CLUE.Caption = strdec
```

改为：

```vbnet
Label_CLUE.Caption = Decode(Dialog.Label_ls.Caption, t)
' 依次替换 Label_ls1..Label_ls4，运行 AutoOpen 即可看到明文
```

示例得到 `123456`、`aaaaaa`、`000000`、`墙角数枝`、`iloveyou` 等口令；原文最终用 `墙角数枝` 得到解压提示并推导 flag。DPB 篡改在十六进制编辑器中把 `44 50 42` 改为 `44 50 41`（`DPA`），重打包为 `.docm`；PoC 未在本机复跑。

## 变体与关联

- DPB 变体：不同 Office 版本/文件格式的标记位置与名称可能不同；也可删除/清零 DPB 字段，或直接修改 OLE 流中的 protection 标志。
- 宏取密变体：若宏使用 `Encode`/自定义加密，优先寻找 `Decode`/`StrReverse`/`Xor` 等逆向函数；也可用调试器在 `Decode` 返回值处下断点动态取明文。
- 整体加密变体：`office2john` 提取哈希 → `john --mask`/`hashcat` 爆破 → `msoffcrypto-tool` 解密；见 [[ctf-forensics-office-doc-password-office2john-hashcat]]。
- 关联：[[ctf-forensics-docm-vba-base64-xor-powershell-download-url]]（DOCM 宏提取与去混淆）、[[defense-forensics-vba-stomping-source-pcode-mismatch]]（源码/p-code 不一致）。
- 边界：文档整体加密时没有 `vbaProject.bin`，必须先解密；Office 版本可能忽略/修复 DPB 篡改；宏被禁用或签名校验严格时无法运行改写后的宏。

## 检测与防御

- 检测：`vbaProject.bin` 中 `DPB` 标记被改为 `DPA`/缺失；`olevba` 提取到 `Decode`/`Encode` 分支与大量 `Label_*.Caption` 密文；文档整体加密且宏工程存在。
- 防御：不要用 VBA 工程密码保护敏感信息（它不加密源码）；对宏使用数字签名与信任策略；对敏感文档使用真正的文档加密（强口令 + AES）并限制宏执行；监控 DPB 篡改与异常宏运行。
- 加固：企业环境禁用未签名宏、启用受保护视图/ASR；对 Office 文档做静态+动态宏审计（olevba、pcodedmp）。
