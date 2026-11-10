---
id: ctf-forensics-aztec-barcode-password-appended-image-carve-png-ihdr-height-fix
title: 图片题三段链：Aztec 条码读出压缩包口令 → 解包后图片尾部叠加 PNG/TIFF/Zlib → 分离出 PNG 并按 CRC 重算修复被改的宽高
type: scenario
domain: ctf
path: ctf/forensics
technique: aztec-barcode-zip-password-binwalk-carve-png-ihdr-crc-repair
tags:
- ctf
- forensics
- stego
- barcode
- aztec
- zip-password
- binwalk
- png
- ihdr
- crc32
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-T2-2
  verified_at: '2026-11-07T23:17:56+08:00'
  notes: 已对照 16579 原文与 img/01-06 核对：Aztec 读出 5FIVE、YWL.jpg 尾部 binwalk 检出 JPEG/PNG 360x450/TIFF/Zlib、修复宽高得 flag{opium_00pium} 均与图03-06一致；小瑕疵：图05 工具是按 CRC 算出 1440x1800，卡片正文写成按数据量反推且仅高度被缩小，属表述不精确不影响链条；未验证点：未本地复现 binwalk 分离与 IHDR 修复
url: /docs/ctf/forensics/ctf-forensics-aztec-barcode-password-appended-image-carve-png-ihdr-height-fix/
draft: false
kb_aliases:
- See anything in these pics
- Aztec 码口令
- 条码识别得解压密码
- binwalk 多格式叠加
- PNG IHDR 宽高被改
- CRC 校验修复宽高
- I AM MUSIC
---

## 一句话结论

附件给一张“二维码样”图片加一个加密压缩包：图里的码并非 QR 而是 Aztec 码（文件名已提示），用在线条码识别读出 `5FIVE` 作为解压口令；解包得到的图片经 `binwalk` 检出头尾叠加了 PNG/TIFF/Zlib 等多段数据，`foremost`/`binwalk -e` 分离出内嵌 PNG 后，其 IHDR 的宽高与实际像素数据不一致（CRC 校验失败、随波逐流提示“宽高被修改”），按 CRC 重算或按像素量反推正确尺寸修复宽高后打开即得 flag。

## 原理

- **Aztec 码与 QR 的区别**：Aztec 是另一种二维条码（中心有“靶心”定位图形，无 QR 的三个角定位块），通用扫码工具和手机相机常识别不出；文件名/题面提示“二维码”时应先判断码制，用支持多码制的在线识别（原文用 aspose 的条码阅读器）读出明文。这里明文 `5FIVE` 就是压缩包口令——条码在这一步只承担“口令传递”角色，不承载隐写数据。
- **多格式叠加的识别**：`binwalk` 按魔数扫描，JPEG 结束标记 `FF D9` 之后仍有多段可解析结构时会依次列出；原文看到 `JPEG image data`、`PNG image 360x450`、`TIFF image data`、`Zlib compressed data` 四条，说明 JPEG 尾部被追加了至少一份完整 PNG 文件（这是“图种/叠加隐写”最常见做法）。
- **分离**：`binwalk -e`/`foremost`/`dd` 按偏移 carve 出内嵌 PNG；分离出来的文件对浏览器可打开但显示区域被裁掉，说明图像数据完整、只是元数据不对。
- **IHDR 宽高为什么能被改而不破坏文件**：PNG 的 `IHDR` 块固定结构为 `宽(4B) 高(4B) 位深 颜色类型 压缩 滤波 隔行`，其后是 CRC32。解码器按 IHDR 的宽高去切 IDAT 的像素流，若把高度改小，多出来的像素行不会被渲染——这就是“改宽高藏图”的原理；反之改大则会因像素不足而显示异常。原文图 05 显示文件声明 360×450，而随波逐流根据数据量算出正确尺寸为 `1440×1800`（4 倍关系），说明高度被缩小、被裁掉的行里就是 flag。
- **两种修复路径**：① 直接按 CRC 爆破/重算（遍历可能的宽高，使 IHDR 的 CRC32 与块内值一致，见关联卡）；② 按 `IDAT 解压长度 = 行数*(宽*通道+滤波字节)` 反推正确宽高（本例 1440×1800 即由像素数据量推出的 2 倍/4 倍关系）。原文用随波逐流的“图片宽高修复”一键完成，等价于路径②。
- **为什么修复后就能看到**：宽高恢复后解码器渲染全部像素行，原本被裁掉的区域（含 `I AM MUSIC` 与 `flag{opium_00pium}` 文字）出现在画面中。

## 触发条件

- 附件为图片 + 加密压缩包，图片中的码可能是 Aztec/Data Matrix/PDF417 等非常见码制（题面或文件名有提示）。
- 压缩包口令由条码内容提供，而非字典爆破。
- 解包后的图片文件尾/头存在多段可识别格式（`binwalk` 可列出 JPEG/PNG/TIFF/Zlib 等）。
- 分离出的图片能打开但尺寸/内容异常，且 CRC 与 IHDR 声明不符（`pngcheck` 报 CRC error 或工具提示“宽高被修改”）。

## 利用步骤

1. 观察附件：图片 + 加密 zip；文件名/题面提示“pics”“二维码”等。
2. 用支持多码制的识别工具（或在线条码阅读器）识别图片，读出纯文本口令（原文 `5FIVE`）。
3. `unzip -P 5FIVE xxx.zip` 或图形化解压，得到图片。
4. `binwalk out.jpg` 查看叠加结构；`binwalk -e out.jpg` 或 `foremost`/按偏移 `dd` 分离出内嵌 PNG。
5. `pngcheck -v carved.png` 确认 IHDR 的 CRC 报错；用随波逐流/`png-fix` 的宽高修复，或按“宽高维数 × 通道 × 像素行数”反推（原文修复为 1440×1800）。
6. 打开修复后的图片，读取画面中的 `flag{...}`。

## PoC

```bash
# 1) 条码识别：得到口令 5FIVE（用支持 Aztec 的在线/本地识别器）
# 2) 解包
7z x pics.zip -p5FIVE

# 3) 识别叠加与分离
binwalk YWL.jpg
#  JPEG image data, JFIF standard 1.01
#  PNG image, 360 x 450, 8-bit grayscale, non-interlaced
#  TIFF image data
#  Zlib compressed data, best compression
binwalk -e YWL.jpg        # 或 foremost -T YWL.jpg
ls _YWL.jpg.extracted/

# 4) 校验与修复 IHDR 宽高（1440 x 1800 由像素数据量推出）
pngcheck -v _YWL.jpg.extracted/*.png    # 观察 CRC error
# 用工具或脚本把 IHDR 的宽高改成 1440x1800 并重算 CRC32 后保存
```

按 CRC 重算宽高的最小脚本（无需爆破全空间，只在已知候选尺寸上验证）：

```python
import struct, zlib
data = open('carved.png', 'rb').read()
# IHDR 位于 PNG 签名(8) + 长度(4) + 'IHDR'(4) 之后
off = 8 + 4 + 4
for w in (360, 720, 1440):
    for h in (450, 900, 1800):
        ihdr = data[off:off+13]
        body = b'IHDR' + struct.pack('>II', w, h) + ihdr[8:]
        crc = zlib.crc32(body) & 0xffffffff
        stored = struct.unpack('>I', data[off+13:off+17])[0]
        if crc == stored:
            print('match', w, h)
```

## 变体与关联

- 变体：条码换成 QR/Data Matrix 时二维码定位图形不同，识别器要选对码制；口令也可能是 PDF417（多行条码）。
- 变体：压缩包口令可由条码、图片 EXIF、文件名、注释任一途径给出；条码只读出部分字符时可能是分段/纠错等级问题。
- 变体：叠加数据既可分离成完整文件（PNG/TIFF/ZIP），也可只是 Zlib 流（需先 `zlib.decompress` 再判类型）；分离顺序要按偏移从小到大。
- 变体：宽高修复若不知正确值，走 CRC 爆破（`IHDR` 后 4 字节 CRC32 可在小范围尺寸内遍历，见关联卡）；也可看 IDAT 长度与 `宽*通道+1` 的整除关系反推。
- 关联：[[ctf-forensics-png-ihdr-width-height-crc32-brute-force]]（PNG 宽高 CRC32 爆破+文件头修正）、[[ctf-misc-png-idat-chunk-anomaly-stego]]（IDAT 块异常识别）、[[ctf-forensics-multilayer-png-wav-spectrogram-maze-stego]]（多层隐写链）、[[ctf-forensics-barcode-png-multichannel-qr-row-rebuild]]（条码/二维码类隐写）。
- 边界：若图片被重新压缩（JPEG 再编码）导致尾部数据被丢弃，叠加链不成立；若 IHDR 宽高与 CRC 同时被正确重算，pngcheck 不会报错，只能靠像素数据量推正确尺寸。

## 检测与防御

- 检测（比赛/取证侧）：对附件先跑 `file`/`binwalk`/`pngcheck` 三件套；图片“能打开但内容被裁”时优先怀疑 IHDR 宽高被改；条码类图片先判码制再识别。
- 防御（业务侧）：不要在图片里承载口令/凭据；上传图片做重编码以剥离尾部附加数据；对图片解析库校验 IHDR 与 IDAT 尺寸一致性，避免解码器读取越界或渲染异常。
- 加固：对外发布图片统一走“重采样 + 去元数据”管线；对内部资料图避免携带可被解析的附加文件。
