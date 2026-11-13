---
id: defense-forensics-image-authenticity-exif-class-public-document-check
title: 图片/公文截图真实性鉴别：MagicEXIF 多维 EXIF 一致性与 Class 1–5 评级、JPEGsnoop 换算，再用公文格式与检索核对
type: scenario
domain: defense
path: defense/forensics
technique: image-authenticity-exif-consistency-public-document-check
aliases:
- 图片真实性鉴别
- EXIF 校验
- MagicEXIF 图像校验器
- JPEGsnoop 评级换算
- 公文截图鉴别
- 舆情图片取证
tags:
- exif
- image
- forensics
- osint
- misinformation
- verification
- jpegsnoop
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V572
  verified_at: '2026-11-12T10:58:41+08:00'
  notes: 已对照原文（12918，101 行）与 14 张截图逐张核对：MagicEXIF 图像校验器官网（Windows 1.07.0188，图01）、14 项校验维度表与 Class 1-5 评级（原文表格）、Class 换算图（图02，放大核对：MagicEXIF 1→JPEGsnoop 1/2、1-2→JPEGsnoop 2、3→4、4/5→3，原文注释 JPEGsnoop Class 4 为未知原始性）；Class 1 实例（图11）与 Class 5 重构实例（图13）与评级语义一致；公文鉴别方法 GB/T 9704-2012、往期格式、文号重复、政策关键词+地区检索（原文 0x03）。修正：原理段换算关系原写“1→JPEGsnoop 2、2→无直接对应”，按图02 改为“1→JPEGsnoop 1（虚线标注）/2、1-2→JPEGsnoop 2、3→4、4/5→3”。dedup：与 EXIF 伪造卡（反面对抗）、C2PA 剥离卡、JPEG 段隐写卡均非同链；dup-scan 无涉及。未设 affected_versions（工具/方法类）。未验证点：未运行 MagicEXIF/JPEGsnoop；公文鉴别为人工流程，无 PoC（卡内如实标注）。
---

## 一句话结论

拿到传播图片的原始文件后，先用 MagicEXIF 图像校验器按 EXIF 格式、内外部一致性、第三方软件数据、厂商注释、内嵌图哈希、压缩指纹、MPF/AROT、直方图、长宽比与尺寸等维度打分（Class 1–5，可与 JPEGsnoop 评级换算，但 JPEGsnoop Class 4 表示原始性未知、并不比 Class 3 更“原图”）；对公文类图片再按 GB/T 9704-2012 版式、文号是否重复、政策关键词+地区检索交叉验证，可系统性识破 P 图与伪造截图。

## 原理

- **为什么先要“原图”**：聊天软件拍照/普通传输会抹掉 EXIF，只有“原图”选项才保留；截图、转发压缩后的图片丢失大部分可校验信息，因此鉴别第一步是取得原始文件（或至少是未经平台重编码的版本）。
- **EXIF 多维一致性**：MagicEXIF 图像校验器把“真伪”拆成可检查的维度——EXIF 格式是否标准、EXIF 内部数据是否冲突、EXIF 描述参数是否符合当前图像（外部一致性）、是否存在第三方软件插入的数据、厂商注释是否完整原始、全部可读内嵌图的哈希是否一致、JPEG 压缩指纹是否匹配原厂编码器、MPF 指针是否有效、FlashPix/苹果 AROT 是否匹配、直方图是否有明显人为修改、长宽比是否为常见传感器画幅、图像尺寸是否过小。
- **为什么编辑会露馅**：修图软件重编码会改写量化表/压缩指纹、重写或丢失内嵌缩略图、留下 `Software` 字段；这些都会让“内部一致/外部一致/厂商注释/压缩指纹/内嵌图哈希”等维度失败，从而判为 Class 1（来自文件的证据表明图像曾被发现编辑）。
- **评级语义与换算**：MagicEXIF Class 1（最可疑）→ Class 5（最可能原图）；与 JPEGsnoop 粗略换算为 MagicEXIF 1→JPEGsnoop 1（虚线标注）/2、MagicEXIF 1–2→JPEGsnoop 2、3→4、4/5→3。注意 JPEGsnoop Class 4 是“未知原始性”，数字更高不代表更原始，必须按语义而非数字排序。
- **公文/截图为什么另需核对**：P 图与 F12 修改网页信息得到的“外宣号截图”没有统一 EXIF 可查；纸质公文有 GB/T 9704-2012 版式标准可对照，公众号截图则可核对往期格式、文号是否重复出现、以政策关键词+地区检索原始发布。

## 触发条件

- 目标图片正在传播且需要判断是否为原始拍摄/是否被编辑。
- 能取得原始文件（非截图/非二次转发压缩图），或至少能拿到同一文件的多个版本做哈希比对。
- 具备 MagicEXIF 图像校验器（Windows）或 JPEGsnoop 等工具；公文类图片需要能访问官方发布渠道做交叉检索。
- 仅限舆情核验、取证与反诈等正当用途。

## 利用步骤

1. 保存原始文件（不要截图/另存为），记录来源、时间与哈希（如 `certutil -hashfile`）。
2. 用 MagicEXIF 图像校验器打开图片，查看逐项结果与总评级；重点看“第三方软件数据”“压缩指纹信度”“内嵌图特征一致性”“厂商注释数据信度”是否失败/高度怀疑。
3. 若提示被某软件修改（如 Adobe Photoshop），记录软件名与版本；评级为 Class 1–3 时按可疑处理，Class 5 也不能单独作为“未造假”的结论。
4. 有条件时用 JPEGsnoop 交叉验证，并按语义换算评级（Class 4=未知原始性，不是更可信）。
5. 公文图片：对照 GB/T 9704-2012 检查版式要素（版头、发文字号、标题、正文、落款、印章位置等）是否规范；检查文号是否在往期内容中重复出现。
6. 公众号/网页截图：对比该账号往期同类内容的排版、字号、栏目格式；用政策关键词+地区在官方渠道检索原始发布；必要时核对页面源码/域名与截图时间线。
7. 综合 EXIF、像素层线索、来源链与官方检索结果给出结论；存疑时标注证据强度，不把单一工具评级当定论。

## PoC

无 PoC（以 GUI 工具与人工核对流程为主）。可用的取证辅助命令：

```bash
# 保留原始文件哈希，便于发现后续被重新导出
certutil -hashfile original.jpg SHA256
# 或
sha256sum original.jpg
```

## 变体与关联

- 变体：伪造者可能用“图片重构”套用他机元数据绕过 MagicEXIF 评级，见 [[defense-forensics-exif-photo-forgery-reconstruct-verifier-bypass]]；此时需结合压缩指纹、内嵌图哈希之外的人工线索（时区/日照/GPS 与画面矛盾、来源账号）。
- 关联：AI 生成图片的 C2PA/TC260 溯源与剥离见 [[ai-security-ai-image-provenance-c2pa-tc260-strip-tamper]]；图片元数据本身泄露隐藏路径的案例见 [[pentest-recon-image-metadata-comment-hidden-path-hydra]]。
- 边界：截图/平台重编码后 EXIF 丢失、目标使用新版无 EXIF 的相机/手机、或图片经过重构工具处理时，单一校验器结论不可靠；GB/T 9704-2012 只适用于纸质公文版式，不覆盖新媒体截图。

## 检测与防御

- 检测（核验侧）：优先保存原始文件与哈希；多工具交叉（MagicEXIF、JPEGsnoop、exiftool）；把 EXIF 结论与像素内容、GPS/时间合理性、来源账号与官方检索结果联合判断。
- 防御（发布侧）：敏感图片发布前剥离 EXIF/GPS；官方信息以正式渠道为准并保留可验证的发布记录；平台对截图传播增加来源标注。
- 响应：发现伪造图片时留存原始文件、工具报告与检索证据，按舆情/取证流程移交；避免仅凭“Class 5”或“EXIF 正常”对外背书。
