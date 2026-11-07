---
id: ctf-forensics-iso-isolinux-base58-hidden
title: ISO 启动层 isolinux.bin 偏移处隐藏 Base58 字符串
type: scenario
domain: ctf
path: ctf/forensics
technique: iso-bootloader-hidden-base58
aliases:
- BOOT
- TinyCore ISO 隐写
- isolinux.bin 隐藏字符串
- Base58 启动层
tags:
- ctf
- forensics
- iso
- isolinux
- base58
- stego
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:31:41+08:00'
  notes: 已对照原文核对：TinyCore 17.0、core.gz/vmlinuz 与官方 MD5 一致而 ISO 整体 MD5 不同、isolinux.bin 偏移 0x6000 处 3 行重复字符串 9d5zYNcj9f1S46vC74aruPgE9b6T3ceX4Qsa2VQAbVnDFfTr、Base64 失败后 Base58 解码得 VishwaCTF{iM4G35_4Re_n0t_th4T_c00L} 均一致。未验证点：无 ISO 附件，PoC 未本机复跑；原文无版本信息；frontmatter 无 sources/source_url。
---

## 一句话结论

当 ISO 的系统本体（`core.gz`、`vmlinuz`）与官方发行版 MD5 一致、但 ISO 整体 MD5 不同时，差异在 ISO/启动层；检查 `/boot/isolinux/isolinux.bin` 等启动文件，可在固定偏移处发现重复的隐藏字符串，Base64 解码失败后改用 Base58 解码即得 flag。

## 原理

- 先比对关键系统文件的 MD5 与官方 distribution_files，排除系统本体被改；ISO 整体 MD5 不同说明改动在 ISO 结构/引导层。
- 引导器二进制（如 `isolinux.bin`）通常有大量填充区，适合藏数据；文章在偏移 `0x6000` 处发现 3 行重复字符串。
- 该字符串只含 Base58 字符集（去掉了 `0OIl` 等易混淆字符），直接按 Base64 解码会得到随机字节；按 Base58 大整数解码再转字节即可得到明文。
- 重复多份是为了容错/提示；取任意一份解码即可。

## 触发条件

- 拿到 ISO 镜像，能挂载/解包并读取 `/boot` 下的引导文件。
- 系统本体与官方一致，但 ISO 哈希不同。
- 隐藏字符串位于固定偏移，字符集符合 Base58。

## 利用步骤

1. 挂载/解包 ISO，计算 `core.gz`、`vmlinuz` 等文件 MD5，与官方对比。
2. 计算 ISO 整体 MD5，确认与官方不同。
3. 在 `/boot/isolinux/` 等目录搜索异常字符串；用 `xxd`/`binwalk` 查看偏移 `0x6000` 附近。
4. 提取重复字符串，先试 Base64；失败后按 Base58 解码。
5. 将大整数转字节并解码为文本，得到 flag。

## PoC

```python
alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
s = '9d5zYNcj9f1S46vC74aruPgE9b6T3ceX4Qsa2VQAbVnDFfTr'
n = 0
for ch in s:
    n = n * 58 + alphabet.index(ch)
print(n.to_bytes((n.bit_length() + 7) // 8, 'big').decode())
```

## 变体与关联

- 隐藏位置可换成 MBR、EFI 分区、initrd 填充区、ISO 尾部追加数据。
- 编码可换成 Base32/Base85/自定义字母表。
- 关联：[[ctf-forensics-fat16-deleted-noncontiguous-extent-recovery]]（磁盘镜像取证）、[[ctf-reverse-base64-table-index-mutation]]（编码表变形）。

## 检测与防御

- 这是 CTF 取证题型；防御上可对发行镜像做签名校验、比对官方哈希。
- 检测：ISO 与官方哈希不一致但系统文件一致；引导器填充区出现高熵字符串。
