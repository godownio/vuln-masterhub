---
id: ctf-forensics-png-iend-appended-webshell-audit
title: PNG 尾部 IEND 之后附加一句话木马/脚本的识别：末 8 字节校验与尾部载荷提取
type: scenario
domain: ctf
path: ctf/forensics
technique: png-iend-trailing-webshell-audit
tags:
- ctf
- forensics
- png
- file-format
- webshell
- trailing-data
- audit
- magic-bytes
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V202
  verified_at: '2026-11-07T02:18:14+08:00'
  notes: 已对照原文文件格式题及图 12-14 核对：IEND 末 8 字节校验、尾部附加 JSP Runtime.exec 载荷一致；原文为审计识别题，未要求执行载荷；未复跑附件。
url: /docs/ctf/forensics/ctf-forensics-png-iend-appended-webshell-audit/
draft: false
kb_aliases:
- PNG 尾部一句话木马
- IEND 后附加数据
- pngcheck invalid chunk
- 图片藏 webshell
- 文件尾隐藏脚本识别
- PNG 尾部 webshell
---

## 一句话结论

合法 PNG 的最后一个块固定为 IEND，文件末尾 8 字节应为 `49 45 4E 44 AE 42 60 82`（长度 0 + `IEND` + CRC `AE426082`）；若最后 8 字节不等于该值，说明 IEND 之后被追加了额外数据，常见于在图片尾部藏一句话木马/脚本而不破坏图片显示，读取末 8 字节并转储 IEND 之后的字节即可定位隐藏载荷。

## 原理

- PNG 由 8 字节签名和若干 chunk 组成，每个 chunk 为“4 字节长度 + 4 字节类型 + 数据 + 4 字节 CRC”。IEND 是结束块，长度固定为 0，类型 `IEND` 的 CRC 固定为 `AE 42 60 82`，因此任何完整 PNG 的最后 8 字节都是 `IEND\xaeB\x60\x82`。
- 绝大多数图片解码器在读到 IEND 后停止解析，忽略其后的字节；攻击者把 PHP/JSP/ASP 代码或脚本追加在 IEND 之后，图片仍能正常打开，从而在批量文件中隐藏恶意代码。
- 追加数据本身不会被执行，实际危害取决于文件后续如何被使用：Web 服务器把图片后缀错误映射到脚本处理器、文件包含点包含图片路径、或下游工具把尾部内容拼进可执行文件时，隐藏代码才可能执行；在数据安全审计/CTF 中，识别尾部异常本身就是目标。
- 检测思路是检查文件末尾的固定 8 字节；不一致时说明文件被截断、损坏或在 IEND 后追加了内容。进一步用 `pngcheck` 可看到非法 chunk 类型或 CRC 失败（追加数据会被当作新 chunk 解析）。
- 注意区分正常尾随元数据与恶意追加：部分工具会在图片后写附加信息，需要结合载荷特征和文件来源判断；若最后 8 字节不是 IEND，也可能只是文件被截断，应从最后一个完整 IEND 位置向后转储分析。

## 触发条件

- 需要对批量图片做数据安全审计，找出其中隐藏恶意代码/敏感信息的文件。
- 文件来源不可信（用户上传、邮件附件、样本包），且图片能正常打开但大小/尾部异常。
- 具备读取原始字节或 `pngcheck`/`binwalk` 等工具的环境。

## 利用步骤

1. 以二进制方式读取 PNG，取最后 8 字节与 `b'IEND\xaeB\x60\x82'` 比较。
2. 若不相等，定位最后一个 `IEND`，转储其后的全部字节；同时转储末尾 48 字节便于快速查看。
3. 用 `pngcheck -v file.png` 检查是否有非法 chunk 类型、CRC 错误或 IEND 后仍有数据。
4. 对尾部字节做 strings/正则扫描：`<?php`、`<?=`、`<%`、`Runtime.exec`、`eval(`、`base64_decode`、`cmd.exe`、`powershell`、`alert(` 等。
5. 打开图片确认渲染是否正常；尾部异常不影响图像显示，是判断“隐藏”而非“损坏”的辅助证据。
6. 若需进一步确认，可用 `binwalk` 查看尾随数据是否包含压缩包/脚本，或将尾部提取为独立文件分析。

## PoC

最小检测代码：

```python
def png_tail(path):
    data = open(path, "rb").read()
    if data[-8:] == b"IEND\xaeB\x60\x82":
        return None
    # 定位最后一个完整 IEND，返回其后的数据
    pos = data.rfind(b"IEND")
    return data[pos + 4:] if pos != -1 else data[-64:]
```

对命中文件可用 `xxd`/十六进制编辑器查看尾部；若尾部是可读脚本，通常能看到 `Runtime.exec(request.getParameter("cmd"))`、`<?php @eval($_POST[...]) ?>` 等特征。

## 变体与关联

- JPEG 注释段（`FF FE`）或 EXIF 字段附加脚本/隐藏数据；ZIP 拼接在图片尾部（`PK\x03\x04`）；PDF 内嵌 JavaScript。
- 伪装成图片的 polyglot 文件：文件头合法、尾部或数据区夹带脚本，绕过仅比对魔数的上传检测。
- 关联场景：文件上传只校验前若干字节/图片可解析即可绕过；图片马配合解析漏洞或错误 MIME 映射获取代码执行。

## 检测与防御

- 上传校验不能只看文件头/是否可解码，要完整校验 chunk 结构、CRC 以及 IEND 是否位于文件末尾；对尾随数据直接拒绝或剥离。
- 用户上传文件存放在 Web 根目录之外，通过独立域名/沙箱提供下载，并强制正确的 `Content-Type` 与 `Content-Disposition`。
- 禁止把图片扩展名映射到脚本处理器，关闭不必要的多后缀解析。
- 对批量文件做尾部异常扫描和脚本特征扫描；保留原始文件与扫描结果用于取证。
