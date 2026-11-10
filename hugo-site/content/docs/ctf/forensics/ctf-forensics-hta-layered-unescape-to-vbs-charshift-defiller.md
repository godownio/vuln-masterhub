---
id: ctf-forensics-hta-layered-unescape-to-vbs-charshift-defiller
title: HTA 多层 unescape 嵌套 + 大小写空格规避 → VBS 垃圾串注入 base64 → XSLT CDATA 字符位移：四层静态还原
type: scenario
domain: ctf
path: ctf/forensics
technique: hta-nested-unescape-case-evasion-base64-defiller-charshift
tags:
- forensics
- hta
- vbscript
- obfuscation
- base64
- unescape
- xslt
- malware-analysis
cve: []
severity: medium
confidence: medium
status: draft
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W3
  verified_at: '2026-11-08T19:37:15+08:00'
  notes: 已对照原文核对；本次核对未读取图片；五层 url decode、<sCrIPT lANgUAge=VbScRipT> 大小写空格规避、d2FudGVkCg 段间噪声 + descortinar(InStr/Left/Mid) 自写替换、XSLT ms:script CDATA 的 Asc(mid)-5+1 位移，均与正文一致。问题：卡把本篇两个独立题（Wanter Alive 的 HTA/.tIF 与 Binary Badresources 的 wanted.msc）串成同一条「层间关系」链，正文并无「二级 VBS 去噪声后得到 powershell -EncodedCommand、再由该命令载入 .msc」的记述；正文该处是 base64 解出带 http://wanted.alive.htb/cdba/_rp 的 powershell 下载动作，EncodedCommand 形式原文未出现，msc 是另一题的首个附件。建议修正层间关系与 -EncodedCommand 归属后再引用。
url: /docs/ctf/forensics/ctf-forensics-hta-layered-unescape-to-vbs-charshift-defiller/
draft: false
kb_aliases:
- 多层 document.write(unescape())
- HTA VBScript 混淆还原
- 垃圾串注入 base64 还原
- 字符位移 ord-4 还原 VBS
- msc XSLT ms:script CDATA 解码
- wanted.hta 取证
---

## 一句话结论

把恶意 HTA 当"文档"静态剥离而不是双击运行：第一层是 `document.write(unescape("..."))` 反复自嵌套，每解一层得到下一层；解开后是大小写混写、属性带空格的 `<sCrIPT lANgUAge="VbScRipT">`（专门躲关键字检测）；其中 base64 解出"下载 `wanted.tIF` → 改名 `wanted.vbs` → 执行"；二级 VBS 又把垃圾串 `d2FudGVkCg` 灌进 base64 各段之间，靠自写的 `InStr/Left/Mid` 替换函数清空后才能解码，得到 `powershell -EncodedCommand`；其载入的 `.msc` 里 XSLT `ms:script` CDATA 用"逐字符 `ord(c)-5+1`"（即 -4）编码，写十行脚本即可还原出真正的下载器。

## 原理

- **嵌套 `unescape` 是"多层压缩"而非加密**：每层形如 `document.write(unescape("<下一层含引号的源码>"));`。解开后源码里又含 `unescape(`，如此反复。层数不多也不需要工具，只要把每层的 `unescape("...")` 参数取出来反复 `urllib.parse.unquote` 即可。
- **大小写混写 + 空格剥离**是纯检测规避：`<sCrIPT lANgUAge="VbScRipT">`、`SElF.CLoSE`、`Chr(&H57)` 拼接 `"SCRIPT.shELL"`。对静态分析者而言只是"读起来累"，去掉多余空格并统一小写即可恢复正常语义；也提示该样本针对的是基于关键字的扫描器。
- **垃圾串注入破坏 base64**：把合法 base64 切成多段，用 `&` 拼接，并在段间插入固定噪声 `d2FudGVkCg`（本身是一段 base64 文本，看着合法）。直接拼接后解码会失败——必须先"删除所有噪声出现"。自写函数 `descortinar(s, 噪声, "")` 用 `InStr` 找位置、`Left + Mid` 拼接替换，等价于 `s.replace(noise, "")`。
- **`ord -5 +1` = `ord -4`**：XSLT `<ms:script implements-prefix="user" language="VBScript">` 的 CDATA 里，`for i = 1 to N: s = s + chr(Asc(mid(enc, i, 1)) - 5 + 1)` 就是把每个字符码位减 4。减 5 再加 1 的写法是刻意的"看起来两步"，还原时按 `ord(c) - 4` 即可。
- **`powershell -EncodedCommand` 是标准 base64(UTF-16LE)**：VBS 里 `-.EXe`、`-NOP`、`-W1`、`-CdEVIcEcrEDEnTIAlDePlOYmENt` 等乱写参数名与大小写同样只是规避；真正的载荷在 `-EncodedCommand` 后面，`base64 -d | iconv -f utf-16le` 即可读出。
- **为什么值得成卡**：这四层各自都是"可复用的剥壳动作"，且都不需要运行样本；反过来，直接双击 HTA 会立刻执行下载+启动 XOR 解密链，取证时应假定样本有杀伤性。

## 触发条件

- 拿到一个 `.hta`/`.msc`/`.tIF` 之类"看着像文档"的样本文件，或题目只给源码文本。
- 样本内容包含 `document.write(unescape(` 嵌套、`ms:script` + CDATA、`-EncodedCommand` 等可静态识别的结构。
- 分析环境可安全地做文本处理（全程不需要执行样本，只需 Python/编辑器）。
- 后续层需要联网下载（CTF 里把域名指向靶机；真实场景下应改用离线沙箱/代理抓取）。

## 利用步骤

1. 全文搜索 `unescape(`，把最内层的参数字符串取出，做 URL 解码；重复"解码 → 在新文本里再找 `unescape(`"，直到没有嵌套（本例 5 层）。
2. 展开后做规范化：把标签/语句里的多余空格删掉、统一小写便于阅读；注意 `Chr(&H57)&"SCRIPT.shELL"` 这类字符串拼接要先手工拼回。
3. 找 base64 块并解码：若解码报错，先检查是否存在"段间噪声"（重复出现且不在 base64 有效语义里的固定短串），用替换清空后再解。
4. 得到 PowerShell 命令后取 `-EncodedCommand` 后的 base64，按 UTF-16LE 解出脚本正文。
5. 对 `.msc` 一类文件，从 `<ms:script ...><![CDATA[ ... ]]>` 里取出字符串常量，施加样本里的位移（本例 `ord - 4`）还原。
6. 逐层记录每层产物（哈希 + 提取脚本），最终得到下载地址与落地路径，交后续样本分析。

## PoC

```python
import base64, re, urllib.parse

# 1) 剥多层 unescape 嵌套
s = open("wanted.hta", encoding="utf-8", errors="replace").read()
for _ in range(10):
    m = re.search(r'unescape\("(.*?)"\)', s, re.S)
    if not m:
        break
    s = urllib.parse.unquote(m.group(1))

# 2) 去噪声后 base64 解码（噪声串按样本实际值替换）
noise = "d2FudGVkCg"
blob  = s.replace(noise, "")
for chunk in re.findall(r"[A-Za-z0-9+/=]{40,}", blob):
    try:
        print(base64.b64decode(chunk + "=" * (-len(chunk) % 4))[:200])
    except Exception:
        pass

# 3) XSLT CDATA 里的字符位移：ord - 5 + 1 == ord - 4
enc = "<从 CDATA 中截取的常量>"
print("".join(chr(ord(c) - 4) for c in enc))
```

```bash
# 4) -EncodedCommand 是 base64(UTF-16LE)
echo '<BASE64>' | base64 -d | iconv -f utf-16le -t utf-8
```

```text
# 层间关系（本例）
wanted.hta  --5x unescape-->  <sCrIPT VbScRipT> base64 --> 下载 wanted.tIF
wanted.tIF  --改名执行-->     wanted.vbs（噪声注入 base64）
wanted.vbs  --去噪声+base64-->  powershell -EncodedCommand
            --EncodedCommand--> 载入 .msc
wanted.msc  --ord-4 位移-->    下载器 VBS（继续下一层）
```

## 变体与关联

- 变体（位移值不同）：同类样本常用 `ord ± k`、`chr(Asc(x) Xor k)`、`Asc(Mid(...)) - 1`；规律是"常数位移/异或"，写脚本时把 k 扫一遍（0–127）看哪个输出可打印且含 `CreateObject`、`http` 等关键词即可自动定 k。
- 变体（噪声串不同）：噪声可能取自 base64 字符集任意子串，甚至每段不同；判定依据是"删除后解码成功且出现可读文本"，可自动枚举候选（出现 ≥2 次、长度 8–16 的重复子串）。
- 变体（同一家族的其它宿主）：`.hta` → `.jse`/`.vbe`/`.wsf`，或 XSLT 由 `msxsl.exe`/COM 执行；剥离思路一致。
- 关联：[[code-analysis-reverse-obfuscation-fake-captcha-hta-js-charcode-powershell]]（HTA + `String.fromCharCode` 变量表 + 十六进制串异或）、[[code-analysis-reverse-obfuscation-vbe-powershell-dotnet-layered-sample]]（VBE → PS1 → .NET 的同类多层交接）、[[pentest-initial-access-grimresource-msc-apds-xss-dotnettojscript-injection]]（`.msc` + `ms:script` XSLT 宿主滥用的攻击侧视角）。
- 边界：若某层字符串是"运行时拼接"（值来自环境变量、注册表或另一下载文件），纯静态会断链，需要动态沙箱补最后一跳；本例每层都可静态还原。

## 检测与防御

- 检测：邮件/下载网关对 `.hta`、`.msc`、`.tIF`、`.vbs` 一律不放行；扫描文件中 `document.write(unescape(` 嵌套与 `-EncodedCommand` 同现。
- 加固：通过 ASR 规则或组策略禁止 `mshta.exe`、`wscript.exe`、`cscript.exe` 由 Office/浏览器派生；禁用 `.hta` 文件关联。
- 狩猎：批量提取文本样本里的 `unescape` 链与 `-EncodedCommand` blob，自动解一层即得大量 IOC（下载域名、落地路径）。
- 响应：把"某个 `.dll`/`.pdf` 被当成密钥文件"这类同目录兄弟文件也纳入 IOC 与取证范围，不要只盯 `.exe`。
