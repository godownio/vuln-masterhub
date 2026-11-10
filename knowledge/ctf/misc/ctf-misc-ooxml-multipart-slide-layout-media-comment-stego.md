---
id: ctf-misc-ooxml-multipart-slide-layout-media-comment-stego
title: PPTX/DOCX 多部件藏段：按 OOXML part 枚举 slide/slideLayout/media/comments/notesSlide/docProps/embeddings 并逐段解码拼 flag
type: scenario
domain: ctf
path: ctf/misc
technique: ooxml-multipart-hidden-fragments-stego
aliases:
- 神秘文件
- CISCN 2024 神秘文件
- PPTX 多部件隐写
- slideLayout2.xml 藏数据
- notesSlide5.xml
- docProps app.xml 隐写
- Bifid cipher 文档隐写
- VBA RC4 空密钥
tags:
- ctf
- misc
- pptx
- docx
- ooxml
- stego
- base64
- vigenere
- bifid
- rot13
- rc4
- vba
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V391
  verified_at: '2026-11-09T11:38:05+08:00'
  notes: 已对照原文与全部36张图片核对：part4 Base64、slideLayout2 去字符3 Base64(paRt8:87e)、media 逐字母图(ParT6/parT9)、slide4 shape name ROT13(PART7=22b3)、comment1 Vigenère(furry)(PART10:9})、core.xml title+creator Key:lanjing + app.xml Manager Bifid(lanjing)(Part1:flag{)、notesSlide5 双重Base64(pArt5:5f-90d)、embeddings docx 凯撒10(part2:675efb)、vbaProject RC4 空口令(PArt3:3-34) 与截图一致。修正：原文标注 part1 为 docProps/app.xml，但截图实际是 core.xml（dc:title/dc:creator），卡内已改为 core.xml/app.xml 分列（Manager 在 app.xml）。原文未给完整 flag 拼接字符串，卡为方法卡；无版本/CVE，无 sources/URL，路径 ctf/misc 合法。
---

## 一句话结论

把 flag 拆成 10 段分散在 PPTX/DOCX 的多个部件里：幻灯片文本框、`slideLayouts/slideLayout2.xml`、`ppt/media` 的逐字母图片、`ppt/comments/comment1.xml`、`ppt/notesSlides/notesSlide5.xml`、`docProps` 元数据的标题/creator/keywords/Manager（core.xml/app.xml）、`ppt/embeddings` 内嵌 docx、`ppt/slides/slide4.xml` 的形状 name、`vbaProject.bin` 的 VBA 宏；每段旁配线索（Base64、去掉指定字符、ROT13、Vigenère keyword、Bifid keyword、凯撒偏移 10、RC4 空口令），逐段解出 `PaRtN:片段` 后按序拼接即完整 flag——核心方法是把 OOXML 当 zip 全量枚举 part，而不是只看幻灯片可见内容。

## 原理

- **OOXML 即 zip**：`.pptx/.docx` 是 zip 容器；可见正文在 `ppt/slides/slideN.xml`，版式在 `slideLayouts`，备注在 `notesSlides`，批注在 `comments`，元数据在 `docProps/app.xml` 与 `docProps/core.xml`，内嵌对象在 `embeddings`，宏在 `vbaProject.bin`，媒体在 `media`。CTF 常把数据藏在这些非正文 part 的任意字符串里。
- **藏点类型**：① 幻灯片文本里直接放 Base64（可被渲染成小字/透明色）；② 形状的 `name` 属性（如 `HRSFIQp9ZwwZ j=`，肉眼在 XML 里才发现）；③ `slideLayout` 的 `<a:t>` 文本；④ media 目录逐张图片各藏一个 Base64 字符，按文件名排序拼串；⑤ 批注文本里既放密文也放提示（"Vigenère cipher is good!"、"the key is:"）；⑥ `docProps/core.xml` 的 `<dc:title>` 放密文、`<dc:creator>` 放 `Key:...`，`docProps/app.xml` 的 `<Manager>` 放算法名；⑦ 内嵌 docx 再套凯撒；⑧ VBA 宏实现 RC4 并在注释里留 Base64 密文。
- **线索驱动解码**：每个藏点附近的文字/元数据给出算法提示（ROT、N round Base64、Bifid cipher、Vigenère key、凯撒偏移 10、RC4 空密钥），按提示在 CyberChef 组合操作即可；解码产物统一是 `PaRtX:片段`，按编号排序拼接。
- **为什么有效**：普通查看器只渲染可见 slide，不会展示 layout/notes/comments/docProps/embeddings/宏；只解包 ppt/slides 会漏掉大部分片段。全量 part 枚举 + 字符串扫描是这类题的通解。

## 触发条件

- 题目给出 PPTX/DOCX（或改名后的 zip/未知二进制），正常打开只看到提示页或无关内容。
- 文件内含多段可读字符串（Base64 字母表、异常 shape name、图片序列、批注、内嵌对象、宏）。
- 各藏点附近有算法线索；片段形如 `part1:`、`PaRt4:` 等可排序标记。

## 利用步骤

1. `file` 确认 OOXML；复制为 `.zip` 解包（或 `unzip`），列出 `ppt/slides`、`ppt/slideLayouts`、`ppt/notesSlides`、`ppt/comments`、`ppt/media`、`ppt/embeddings`、`docProps`、`vbaProject.bin`。
2. 全量提取候选字符串：`grep -rEo '[A-Za-z0-9+/=]{12,}'` 扫 XML；对 media 按文件名排序逐张看图/OCR 单字符；对 `vbaProject.bin` 用 olevba/微步提取宏源码。
3. 按线索逐段解码：
   - 幻灯片文本 `UGF5dDQ6NmYtNDA=` → Base64 → `PaRt4:6f-40`；
   - `slideLayout2.xml` 文本去掉字符 `3` 后 Base64 → `paRt8:87e`；
   - media 字符拼成 `UGFYVDY6ZC0Y` → Base64 → `ParT6:d-2`；
   - `slide4.xml` 形状 name `HRSFIQp9ZwwZ j=` → ROT13 → Base64 → `PART7:22b3`；
   - 批注 `ZWJjbIYnFhq9` → Vigenère(key `furry`) → Base64 → `PART10:9}`；
   - `docProps/core.xml` title `QFCfP0Q6ZYmmJ3gq` + creator `Key:lanjing`，`docProps/app.xml` 的 `Manager: Bifid cipher` → Bifid(key `lanjing`) → Base64 → `Part1:flag{`；
   - `notesSlide5.xml` 双重 Base64 → `pArt5:5f-90d`；
   - 内嵌 docx 的 `mQPinNS6Xtm1JGJs` → 凯撒偏移 10/相应 Base64 → `part2:675efb`；
   - VBA 宏 RC4（空口令）对 `i13POMdzEAzHfy4dGS+vUA==` 解密 → `PArt3:3-34`；
   - 其余 part 同理。
4. 将 `Part1:flag{`、`part2:675efb`、…、`PART10:9}` 按编号拼接，得到完整 flag。

## PoC

```bash
cp mystery.pptx m.zip && unzip -o m.zip -d m
grep -rEo '[A-Za-z0-9+/=]{12,}' m/ppt m/docProps | sort
ls m/ppt/media        # image45.png ... 逐张 OCR/看图取单字符
olevba m/ppt/vbaProject.bin   # 或微步沙箱看宏
```

CyberChef 组合示例（按线索选择）：
```text
From Base64                                  # UGF5dDQ6NmYtNDA= -> PaRt4:6f-40
ROT13 -> From Base64                         # HRSFIQp9ZwwZ j= -> PART7:22b3
Vigenere Decode(key=furry) -> From Base64    # ZWJjbIYnFhq9 -> PART10:9}
Bifid Cipher Decode(key=lanjing) -> From Base64  # QFCfP0Q6ZYmmJ3gq -> Part1:flag{
RC4(空 passphrase, Input=Base64)             # i13POMdzEAzHfy4dGS+vUA== -> PArt3:3-34
```

## 变体与关联

- 变体：数据藏在 `customXml`、`theme`、`docProps/core.xml`、`footnotes`、`chart` XML、批注作者名、修订记录；编码换成 Base32/Base58/Base85、AES、RC4、XOR、双 Base64；媒体换成逐帧图片二进制。
- 关联卡片：[[ctf-forensics-docx-customxml-base64-comment]]（docx customXml Base64）、[[ctf-misc-pptx-slide-image-binary-separator]]（PPTX slide 图片 0/1 隐写）、[[ctf-forensics-docm-vba-base64-xor-powershell-download-url]]（VBA 宏藏 Base64/XOR 载荷）、[[pentest-initial-access-ooxml-nonvba-hidden-payload-carriers]]（docProps/控件/w:t/docVars 等非 VBA 隐藏载体，恶意文档视角）。
- 边界：文档被加密/损坏需先修复 OOXML 结构；宏被密码保护时需 DPB 绕过；图片藏字符需要清晰渲染/OCR。

## 检测与防御

- CTF 取 flag 场景；真实防御视角：OOXML 可在 layout/notes/comments/docProps/embeddings/shape name 中携带数据，DLP/审计应解包扫描全部 part、宏与内嵌对象，而不能只渲染正文；禁用宏并检查 `vbaProject.bin`。
