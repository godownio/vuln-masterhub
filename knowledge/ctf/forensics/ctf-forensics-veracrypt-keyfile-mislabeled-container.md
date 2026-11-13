---
id: ctf-forensics-veracrypt-keyfile-mislabeled-container
title: VeraCrypt 卷伪装为 flag.txt + key.jpg 作 keyfile 挂载，提取流量包取 flag
type: scenario
domain: ctf
path: ctf/forensics
technique: veracrypt-keyfile-mislabeled-container
aliases:
- flag.txt 是 VeraCrypt 容器
- key.jpg 作为 keyfile
- VeraCrypt Use keyfiles
- 伪装文本文件挂载
- 磁盘挂载题
tags:
- ctf
- forensics
- veracrypt
- keyfile
- encrypted-volume
- mount
- pcap
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V604
  verified_at: '2026-11-12T18:33:57+08:00'
  notes: '已对照原文与20图核对：正文明确 flag.txt 与 key.jpg，key.jpg 作密钥文件挂载 flag.txt 得磁盘、盘内有流量包；图18 VeraCrypt 主界面显示 H: 已挂载 A:\下载\黑客的秘密\附件1\flag.txt，24.8MiB AES Normal，左栏可见 attack 目录与 attack.zip；图19 010 打开流量数据可见 flag 片段（文件内多处 flag 字符串）；图20 CyberChef From Base64 得 DASCTF{y0u_f1nd_th3_hAckkkkkk!!!!!!}，与正文“取中间部分拼接后base64解码”一致。affected_versions 留空正确（CTF题）。dedup 报告判 new，related 的 AES-XTS 手动扇区解密、内存取主密钥、隐藏卷/嵌套容器前提均不同，非同链，保留。未验证点：keyfile 选择与挂载操作仅有结果截图，无 VeraCrypt 密钥文件对话框截图；未实际挂载复现。'
---

## 一句话结论

附件中的 `flag.txt` 并非文本而是 VeraCrypt 加密卷，`key.jpg` 是卷的 keyfile；在 VeraCrypt 中选择该文件作为密钥文件并挂载 `flag.txt`，即可得到盘内流量包，用 010 查看可见 flag 片段，按提示拼接中段并 Base64 解码得到最终 flag。

## 原理

- **卷伪装**：VeraCrypt 卷可以任意扩展名保存；`flag.txt` 只是文件名，文件头为 VeraCrypt 特征而非文本。用 `file`/010 查看头部或尝试挂载即可识别。
- **keyfile 模式**：VeraCrypt 支持“口令 + 密钥文件”或仅密钥文件；把 `key.jpg` 指定为 keyfile（Volume → Select File → Use keyfiles）后，工具用文件内容参与密钥派生，无需知道口令。
- **挂载后取证**：卷内是普通文件系统，挂载后可见流量包；用 010/strings 直接搜索 flag 字符串，按题目提示取中段拼接。
- **编码还原**：取出的片段可能是 Base64/十六进制，按提示拼接后解码得 flag。

## 触发条件

- 附件包含一个“文本/图片”文件，实际为加密卷；另有独立图片/文件作为 keyfile。
- 有 VeraCrypt/TrueCrypt 工具可挂载。
- 卷内数据未额外加密或可从流量/文本直接读取。

## 利用步骤

1. 用 `file`/010 检查可疑文件头，确认是否为 VeraCrypt 卷（`VERACRYPT` 特征）。
2. 打开 VeraCrypt，选择该卷文件，勾选“使用密钥文件”，把 `key.jpg` 加入 keyfile 列表。
3. 挂载后浏览卷内文件，找到流量包/文本。
4. 用 010/strings 搜索 flag 片段，按提示取中间部分拼接。
5. 对拼接结果做 Base64/十六进制解码，得到最终 flag。

## PoC

```text
附件：flag.txt（实际为 VeraCrypt 卷）、key.jpg（keyfile）
VeraCrypt -> Select File: flag.txt
Use keyfiles -> Add keyfile: key.jpg
Mount -> 盘内 attack.zip / 流量包
010 打开流量包 -> 提取 flag 片段 -> 拼接 -> base64 -d -> flag
```

## 变体与关联

- 变体：TrueCrypt/VeraCrypt 隐藏卷、内存镜像提取主密钥、BitLocker 恢复密钥。
- 变体：keyfile 为图片/音频，需先从隐写中提取真实 keyfile。
- 关联：[[ctf-forensics-truecrypt-memory-key-mount]]（内存中提取主密钥挂载）、[[ctf-forensics-veracrypt-hidden-volume-vmdk-7z-winhex]]（隐藏卷/嵌套容器）、[[ctf-forensics-veracrypt-aes-xts-manual-sector-decrypt]]（手动解密扇区）。
- 边界：卷使用强口令且无 keyfile、keyfile 未知、卷内数据二次加密时，无法直接挂载读取。

## 检测与防御

- 本卡为 CTF 取证思路；实际应急中可用 `file`/熵分析识别伪装加密卷，结合内存镜像提取密钥。
