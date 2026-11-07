---
id: ctf-misc-spammimic-spam-text-stego-eml
title: spammimic 垃圾邮件文本隐写：EML 正文提取与在线解码
type: scenario
domain: ctf
path: ctf/misc
technique: spammimic-spam-text-stego-eml
tags:
- ctf
- misc
- stego
- spam
- email
- eml
- text
- encoding
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V194
  verified_at: '2026-11-06T22:51:00+08:00'
  notes: 已对照原文与图01核对：spammimic 在线解码由垃圾邮件正文还原出 Don't just listen to the so... 提示；EML 多部分提取脚本与原文一致；原文未给 spammimic 词典/本地解码实现，卡片未编造。
url: /docs/ctf/misc/ctf-misc-spammimic-spam-text-stego-eml/
draft: false
kb_aliases:
- Wanna Feel Love Challenge 1
- spammimic
- 垃圾邮件隐写
- spam mimic
- EML 注释提取
- 垃圾邮箱解密
---

## 一句话结论

一段看似普通垃圾邮件的长文本可能不是垃圾邮件，而是 spammimic 隐写载体：把邮件正文（必要时先从 EML 的 MIME 多部分中解码 base64/quoted-printable）取出，交给 spammimic 解码器，即可还原被包装成营销话术的短消息。

## 原理

- **spammimic 的编码思路**：它把一条短消息映射到一组“垃圾邮件模板句”上，利用大量同义/填充句生成一段语义重复、充满 “Dear Friend”“REMOVE”“Senate bill”“make money” 等营销用语的文本。载体文本本身是自然语言，但语义空洞、段落高度模板化，和正常邮件相比有明显的人工拼接痕迹。
- **解码是编码的逆过程**：解码器用同一套词典/模板把长文本还原成短消息；因为编码结果看起来像垃圾邮件，常规的 `strings`、十六进制查看、注释提取往往得不到有用信息，容易误判为噪声。
- **EML 结构**：附件可能是 `.eml`，正文藏在 `multipart/*` 的某个 `text/plain` 或 `text/html` 部分；需要按 `Content-Transfer-Encoding`（base64、quoted-printable）和 `charset` 解码，递归处理 `message/rfc822` 内嵌邮件，才能拿到完整的垃圾邮件文本。
- **为什么容易漏**：邮件里可能同时有 HTML 注释、C 风格注释、`//` 行注释等干扰；真正的 spammimic 载体是正文段落，不是注释。原文的脚本先提取了注释，但最终仍需要把整段垃圾邮件文本送去 spammimic 解码，说明“先找注释”只是辅助。
- **结果形态**：解码出的通常是一句提示/口令/下一步线索（例如指向音频、图片或另一个文件的提示），不一定是最终 flag。

## 触发条件

- 附件是 `.eml`、`.txt` 或网页文本，内容异常长且充满重复的垃圾邮件模板句。
- 常规 `strings`/注释提取/编码识别（base64、hex、rot）都没有明显结果。
- 题目提示“垃圾邮件”“spam”“marketing”“unwanted mail”或给出一个邮件文件。
- 允许访问 spammimic 在线解码器，或本地有同款工具/词典。

## 利用步骤

1. 判断文件类型：`file`、`head` 查看是否为 EML/MIME；若是 EML，用 Python `email` 库解析。
2. 递归遍历 MIME 部分：对每个 `text/*` 部分按 `Content-Transfer-Encoding` 解码（base64/quoted-printable），再按 `charset` 转成字符串；`message/rfc822` 递归进入。
3. 把解码后的正文按原顺序拼接，保留段落与空格；不要只提取注释或只取第一段。
4. 将整段文本提交到 spammimic 解码器（在线服务或本地实现），得到隐藏短消息。
5. 若解码结果仍是编码/提示，按提示继续下一层（音频、图片、压缩包等）。
6. 若在线服务不可用，搜索 spammimic 的词典/开源实现，或用“垃圾邮件模板句 → 比特”的映射自行实现解码。

## PoC

EML 正文提取（按原文脚本简化，未在本机对附件执行）：

```python
import base64
import quopri
from email import policy
from email.parser import BytesParser

def decode_part(part):
    raw = part.get_payload(decode=False)
    if isinstance(raw, str):
        raw = raw.encode("utf-8", errors="ignore")
    cte = (part.get("Content-Transfer-Encoding") or "").lower()
    if "base64" in cte:
        data = base64.b64decode(raw)
    elif "quoted-printable" in cte:
        data = quopri.decodestring(raw)
    else:
        data = raw
    charset = part.get_content_charset() or "utf-8"
    return data.decode(charset, errors="ignore")

def walk(msg):
    out = []
    if msg.is_multipart():
        for part in msg.iter_parts():
            ctype = part.get_content_type()
            if ctype == "message/rfc822":
                out.extend(walk(part.get_payload(0)))
            elif ctype.startswith("text/"):
                out.append(decode_part(part))
            else:
                out.extend(walk(part))
    elif msg.get_content_type().startswith("text/"):
        out.append(decode_part(msg))
    return out

msg = BytesParser(policy=policy.default).parsebytes(open("mail.eml", "rb").read())
text = "\n".join(walk(msg))
print(text[:2000])
# 然后把完整 text 交给 spammimic 解码器
```

原文在 spammimic 在线解码器中得到类似 `Don't just listen to the so...` 的提示句，作为下一关（音频隐写）的线索；该结果不是最终 flag。spammimic 的编码词典未在原文给出，卡内不提供本地解码实现。

## 变体与关联

- **载体变体**：纯 `.txt` 垃圾邮件、HTML 邮件正文、论坛帖子、客服话术；也可能混在正常邮件签名/免责声明中。
- **结构变体**：多层 `multipart/alternative`、`message/rfc822` 嵌套、base64 与 quoted-printable 混用、非 UTF-8 charset。
- **文本隐写替代**：首字母缩写、每行首尾字符、零宽字符、Unicode 变体选择符、HTML 注释；与 spammimic 的区别是后者保留完整自然语言句子。
- **关联**：[[ctf-misc-zero-width-unicode-binary-quinary-stego]]（零宽字符隐写）、[[ctf-misc-unicode-variation-selector-hex-stego]]（变体选择符隐写）、[[ctf-misc-first-last-char-line-stego]]（首尾字符隐写）。
- **边界**：若正文被截断、被邮件客户端重排/转义，或 spammimic 版本词典不一致，解码会失败；需要保留原始 MIME 字节，不要用富文本复制。

## 检测与防御

- **CTF 识别**：超长、重复、模板化的垃圾邮件文本 + 常规编码分析无结果，优先尝试 spammimic；题目名/提示中的 “spam”“mail”“junk” 是强信号。
- **取证**：保留原始 EML，记录 MIME 结构、charset、CTE；先导出所有 text 部分，再分别尝试 spammimic/注释/编码分析。
- **防御（真实系统）**：垃圾邮件过滤器不应只按关键词丢弃可疑邮件；对高重复模板文本可做隐写检测（模板句比例、语义连贯性、异常长度）。企业邮件安全网关应保留原始邮件供取证。
- **出题思路**：用大量垃圾邮件模板掩盖短消息，配合 EML 多部分结构增加提取成本；把真正的线索放在 spammimic 解码结果而非注释中。
