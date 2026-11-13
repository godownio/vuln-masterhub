---
id: defense-forensics-exif-photo-forgery-reconstruct-verifier-bypass
title: 照片 EXIF 伪造与校验器绕过：改 GPS/拍摄时间后用“图片重构”套用他机型号数据把可信度从 Class 1 刷到 Class 5
type: scenario
domain: defense
path: defense/forensics
technique: exif-photo-forgery-reconstruct-verifier-bypass
aliases:
- EXIF 伪造
- 图片元数据篡改
- 照片 GPS 造假
- MagicEXIF 图片重构
- 相机型号套用
- 舆情图片造假
tags:
- exif
- metadata
- image
- anti-forensics
- forgery
- osint
- misinformation
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V572
  verified_at: '2026-11-12T10:58:39+08:00'
  notes: 已对照原文（12918，101 行）与 14 张截图逐张核对（原图为 .bin 扩展名的 PNG，已降为最长边 1200 JPEG 后读取，无失败项）：原图 VCG211362656657（图03）EXIF 制造商 SONY/型号 ILCE-7RM3/软件 Adobe Photoshop 23.0（图05）；编辑向导 GPS 与拍摄时间 2021-12-18 22:56:16、时区 UTC+9（图07）；百度坐标 BD09 108.867702,34.287161（图08）转 WGS-84 后写入，GPS 新增 4 个标签且拍摄时间改为 2077-12-18，纬度/经度数值在截图中确为互换（图09），Windows 属性同步显示（图10，卡内已注明该疑似填反）；校验器 Class 1 且提示 Adobe Photoshop 23.0 修改，失败项为厂商注释/第三方软件/EXIF格式/压缩指纹（图11）；原图重构为 Canon PowerShot G1 X Mark III 后校验 Class 5 全项通过（图13）；certutil 前后 MD5 7324177122af81a095edf6a9c0256270→10c4e168ecf2d92f67298a989771069f1（图14）。修正：一句话结论文本中“压缩指纹与内嵌图哈希不一致”改为“EXIF 格式与压缩指纹异常”，原理中删除截图中未出现的“内嵌缩略图哈希”归因（图11 仅列 5 项，无内嵌图项）。dedup：与 ai-security-ai-image-provenance-c2pa-tc260-strip-tamper、pentest-recon-image-metadata-comment-hidden-path-hydra 等均非同链；与图片鉴别卡互为正反两面，非重复；dup-scan 无涉及。未设 affected_versions（工具类，无版本声明）。未验证点：MagicEXIF 原图重构为 GUI 功能，未复跑；PoC 为 exiftool 最小伪造面等价演示。
---

## 一句话结论

照片 EXIF（GPS、拍摄时间、厂商/型号等）没有任何签名，可被任意编辑；只改 GPS/时间时，MagicEXIF 图像校验器会因 Photoshop 痕迹、第三方软件数据、EXIF 格式与压缩指纹异常判为 Class 1，但使用其“原图重构”功能把另一台相机（如佳能）的成套元数据套到原图（索尼）上，再校验即可变为 Class 5（“极可能来自相机原图”），同时文件 MD5 随 EXIF 改变。

## 原理

- **EXIF 可写且无完整性保护**：EXIF 只是 JPEG/TIFF 的元数据段，编辑器可增删改 `Make/Model/Software/DateTimeOriginal` 与 GPS 标签组（`GPSLatitudeRef/GPSLatitude/GPSLongitudeRef/GPSLongitude` 等）。写入一条“真实”的 GPS 坐标与时间后，Windows 属性页等普通查看器会照单全收。
- **校验器看的是“一致性”而不是“真伪”**：MagicEXIF 图像校验器按 EXIF 格式检验、EXIF 数据内部一致性、外部一致性（参数是否符合当前图像）、第三方软件数据、厂商注释数据信度、内嵌图特征一致性（全部可读内嵌图哈希是否一致）、压缩指纹信度、MPF/FlashPix/苹果 AROT 数据、直方图信度、长宽比与图像尺寸等维度打分，输出 Class 1–5。
- **为什么只改 GPS 会被识破**：原图经过 Photoshop 编辑后，`Software` 字段留下 `Adobe Photoshop 23.0 (Windows)`，重编码又破坏了原厂压缩指纹，因此校验器判“厂商注释数据信度不通过、第三方软件数据不通过、EXIF 格式/压缩指纹高度怀疑”，整体只有 Class 1，并直接提示“当前图像曾经被以下软件所修改”。
- **“图片重构”为什么能刷分**：该功能抽取目标相机型号的一整套元数据（Make/Model、厂商注释、压缩指纹、内嵌图等）套写到当前图像并重编码，使各一致性维度相互匹配，校验器失去“被编辑”的证据链，从而给出 Class 5。本质是把“伪造痕迹”替换成另一台真实相机的“身份”，不是让图像变得更真实。
- **副作用与边界**：重写 EXIF/重编码会改变文件 MD5（原文前后 MD5 不同），可作为发现“文件被重新导出”的线索；Class 评级是启发式，不是密码学证明，换校验器/换维度可能再次暴露。

## 触发条件

- 拿到带基本 EXIF 的照片原图（聊天软件仅“原图”传输才保留 EXIF）。
- 具备可写 EXIF 的工具（MagicEXIF 元数据编辑器，部分功能付费；或 exiftool 等）。
- 目标受众/平台依赖 EXIF、Windows 属性或“Class 评级”判断图片来源，而未做哈希/来源链核验。
- 仅限授权取证、反诈与舆情研究场景使用。

## 利用步骤

1. 用 Windows 属性或元数据编辑器查看原图 EXIF，确认有无 GPS、拍摄时间与厂商型号。
2. 在地图坐标拾取工具选点（默认常为百度 BD09 坐标），按 BD09→WGS-84 转换后填入编辑器；例如 `108.867702,34.287161`（BD09，经度,纬度）转换为 `108.85666240393616,34.282604744637915`（WGS-84），再把拍摄时间改为期望值（原文改为 2077 年）。
3. 保存后核对 GPS 标签组是否新增四条记录（纬度/经度参考与数值），并用 Windows 属性页确认查看器已显示伪造的 GPS。
4. 用 MagicEXIF 图像校验器复检：若原图被 Photoshop 编辑过，会得到 Class 1，并列出失败/怀疑项与修改软件。
5. 使用“原图重构”，选择另一台相机的数据集（原文把索尼原图重构为佳能 PowerShot G1 X Mark III），保存后再次校验，得到 Class 5 与“极可能来自相机原图”的结论。
6. 记录修改前后 MD5（如 `certutil -hashfile`），确认文件已变化；评估目标平台是否还有其他校验（来源账号、上传日志、C2PA 等）。

## PoC

无 GUI 重构功能的等价脚本 PoC（用 exiftool 写入伪造 GPS/时间，演示最小伪造面）：

```bash
exiftool -GPSLatitude=34.282604744637915 -GPSLatitudeRef=N \
         -GPSLongitude=108.85666240393616 -GPSLongitudeRef=E \
         -DateTimeOriginal="2077:12:18 22:56:16" photo.jpg

# 校验写入结果与文件哈希变化
exiftool -GPS:all -DateTimeOriginal photo.jpg
certutil -hashfile photo.jpg MD5
```

说明：“图片重构”为 MagicEXIF 编辑器内置的 GUI 功能，无公开命令行等价物；原文通过该功能把 Class 1 刷到 Class 5。原文的 GPS 标签截图中纬度/经度数值疑似填反（纬度显示 108°…、经度显示 34°…），实际使用时纬度应为 34.28、经度应为 108.86。

## 变体与关联

- 变体：其他元数据编辑器（exiftool、ExifToolGUI、厂商工具）同样能改 GPS/时间，但难以覆盖“压缩指纹/内嵌图哈希”等维度，Class 评级会暴露编辑痕迹；重构类工具才是绕过评级的关键。
- 变体：直接截图/重保存会清空 EXIF，适合“去标识”但不适合“伪造来源”；伪造来源需要成套相机数据。
- 关联：图片真实性鉴别的完整维度与评级换算见 [[defense-forensics-image-authenticity-exif-class-public-document-check]]；AI 生成图片的溯源标识剥离/篡改见 [[ai-security-ai-image-provenance-c2pa-tc260-strip-tamper]]；图片元数据泄露路径的进攻用法见 [[pentest-recon-image-metadata-comment-hidden-path-hydra]]。
- 边界：目标要求原始文件哈希、拍摄设备签名、C2PA/水印或平台侧来源链时，单纯 EXIF 伪造无效；Class 5 只代表“通过该工具的启发式检查”。

## 检测与防御

- 检测：图片 `Software` 字段出现 Photoshop/编辑器名；EXIF 内外部参数不一致、厂商注释缺失、压缩指纹与机型不符、内嵌缩略图哈希不一致；文件哈希与疑似原始版本不同；GPS 坐标与画面地物/时区/日照矛盾。
- 检测：同一来源批量图片的相机型号/序列号高度雷同或与发布者身份不符；图片经二次导出（MD5 变化、量化表异常）。
- 防御/取证：保留原始文件与哈希，不要只保存截图；用多工具交叉校验（MagicEXIF、JPEGsnoop、exiftool）并核对 EXIF 与像素内容；对关键证据走来源链/公证或可信时间戳；平台侧不要仅凭 EXIF 或单一 Class 评级下结论。
