---
id: ctf-misc-png-bitplane-zip-base85-shellcode-c2
title: output.png 位面提取内嵌 zip（条目 .b）→ Base85 解码 shellcode → 沙箱执行得 C2 IP（前置 dmp 按 raw 图像取域名）
type: scenario
domain: ctf
path: ctf/misc
technique: png-bitplane-zip-base85-shellcode-c2
tags:
- ctf
- misc
- stego
- png
- bitplane
- stegsolve
- zip
- base85
- shellcode
- sandbox
cve: []
severity: low
confidence: low
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V391
  verified_at: '2026-11-09T11:38:09+08:00'
  notes: 已对照原文与全部36张图片核对：dmp→GIMP raw 得 winhack.com、微步释放链 hackexe.exe→output.png/loader.exe、Stegsolve Extract Preview 勾选 Red bits 7-1/Row/MSB 得到 zip、条目 .b(533B)、Base85 解 shellcode、沙箱 loader64.exe 外连 39.100.72.235、md5(winhack.com39.100.72.235)=096e8b0f9daf10869f013c1b7efda3fd，均与截图一致。GIMP raw 宽高参数与位面导出脚本原文未给，卡内已注明并标 confidence low；前置 dmp 步骤仅引用既有卡 ctf-forensics-process-memory-dump-gimp-raw-image，新卡聚焦 PNG 位面→zip→Base85→shellcode→C2，判新增成立；无版本/CVE，无 sources/URL，路径 ctf/misc 合法。
url: /docs/ctf/misc/ctf-misc-png-bitplane-zip-base85-shellcode-c2/
draft: false
kb_aliases:
- CISCN 2024 盗版软件
- output.png 位面隐写
- Stegsolve 提取 zip
- Base85 shellcode
- winhack.com 39.100.72.235
- 图片位面藏压缩包
---

## 一句话结论

样本释放的 `output.png` 在常规查看器下正常，但用 Stegsolve 只取 Red 通道的 7–1 位面（Row/MSB）即得到 `PK` 头：位面里藏着一个 zip，条目名 `.b`（533 字节）；解出后 Base85 解码是一段 shellcode，沙箱执行后网络行为回连 `39.100.72.235`（题目前置通过 dmp 按 raw 图像在 GIMP 里还原出域名 `winhack.com`，最终答案取域名+IP 的 MD5）。

## 原理

- **位面隐写**：PNG 的每个像素通道有 8 个位面；常规看图只显示合成后的颜色，单独提取某个通道的某些位（本题 Red 的 7..1 位）并按 MSB/行序重排，可以藏下任意字节流。Stegsolve 的 “Extract Preview” 会把选定位面直接渲染/导出为灰度数据，出现 `PK` 头即说明藏了 zip。
- **多阶段载荷**：zip 内用非常规条目名 `.b` 存放文本；文本是 Base85（ASCII85）编码的 shellcode。Base85 相比 Base64 更紧凑，是 CTF/恶意样本常见的文本编码层；解码后用沙箱执行可观察其网络行为（回连 IP）。
- **前置链条**：题目给 dmp 与附件；dmp 改后缀 `.data` 后在 GIMP“打开为原始图像数据”，调宽高/偏移还原出带域名的页面画面（`winhack.com`），再按域名在微步等沙箱检索到释放文件关系 `EK.exe → hackexe.exe → output.png / loader.exe`；`loader.exe` 不是载体，真正载荷在 `output.png`。
- **答案格式**：把域名与 C2 IP 拼接 `winhack.com` + `39.100.72.235` 取 MD5，得到 `096e8b0f9daf10869f013c1b7efda3fd`。

## 触发条件

- 获得样本释放的 PNG，常规图像工具查看正常；用 Stegsolve 逐位面可见明显结构/文件头。
- PNG 位面导出的字节流以 `PK\x03\x04` 等 magic 开头。
- zip 内为文本且熵较高（Base85/Base64 字符集），解码后为可执行 shellcode。
- 有沙箱可执行 shellcode 并查看网络行为；前置 dmp 可尝试 raw 图像还原（见关联卡）。

## 利用步骤

1. 按前置线索（dmp raw 图像）得到域名 `winhack.com`，在微步/沙箱检索样本与释放文件，导出 `output.png`。
2. Stegsolve 打开 `output.png` → Analyse → Extract Preview；Bit Planes 只勾选 Red 的 7..6..5..4..3..2..1（不勾 0），Extract By Row、Bit Order MSB First，Preview 看到 `PK` 后 Save Bin 为 `out.bin`。
3. `file out.bin` 确认 zip；`unzip out.bin` 得到 `.b`。
4. `base64.b85decode(open('.b','rb').read())` 或 CyberChef “From Base85” 解码，得到 shellcode（可 `file`/反汇编确认）。
5. 在沙箱中执行 shellcode，查看网络行为/回连地址，得到 `39.100.72.235`。
6. 计算 `md5("winhack.com39.100.72.235")` 作为答案。

## PoC

```text
# 位面提取（Stegsolve 图形操作，无脚本）
output.png -> Analyse -> Extract Preview -> Red bits 7..1, MSB First, Row -> Save Bin -> out.bin

# 解 zip 与 Base85
file out.bin && unzip -o out.bin     # 条目 .b（533 字节）
python3 -c "import base64;print(base64.b85decode(open('.b','rb').read()))" > sc.bin
# 沙箱执行 sc.bin -> 网络行为 39.100.72.235

# 答案
printf 'winhack.com39.100.72.235' | md5sum   # 096e8b0f9daf10869f013c1b7efda3fd
```

说明：文章未给出位面导出的脚本与 GIMP raw 宽高参数；本卡按截图（Red 7–1 位、MSB、Row）与通用操作整理。

## 变体与关联

- 变体：位面换 Green/Blue/Alpha、LSB 或跨通道组合；zip 换 7z/RAR/自定义头；Base85 换 Base64/Base58/hex；shellcode 换 PE/ELF 或脚本；前置 dmp 换 memdump/进程转储。
- 关联卡片：[[ctf-forensics-process-memory-dump-gimp-raw-image]]（dmp 改 .data 用 GIMP raw 图像恢复画面，本卡前置步骤）；[[ctf-misc-png-trailing-data-lcg-xor-base62]]（PNG 尾随数据编码链）；[[ctf-misc-image-appended-zip-pseudo-encryption-nested-pcz]]（图片附加 zip）；[[pentest-c2-shellcode-basex-base85-rc4-text-encoding]]（Base85 文本编码 shellcode 的同族载荷）。
- 边界：位面位序/行列序错误会得到乱码；PNG 可能被重压缩破坏位面；沙箱可能阻断 shellcode 网络行为。

## 检测与防御

- CTF/取证场景；真实防御：图片可能携带位面隐写的压缩包/shellcode，DLP 与沙箱应做位面/LSB 扫描与图片附加数据检查；对沙箱报告中的释放文件关系与 C2 IP 提取 IOC；隔离执行未知 shellcode。
