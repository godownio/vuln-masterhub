---
id: ctf-forensics-veracrypt-hidden-volume-vmdk-7z-winhex
title: VeraCrypt 隐藏卷取证：vmdk 用 7z 提取 FAT 容器、主/备用双密码分别进入外层与隐藏卷、WinHex 扇区级读已解锁卷
type: scenario
domain: ctf
path: ctf/forensics
technique: veracrypt-hidden-volume-vmdk-7z-winhex
tags:
- ctf
- forensics
- veracrypt
- truecrypt
- hidden-volume
- vmdk
- winhex
- disk-image
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V570
  verified_at: '2026-11-12T09:27:08+08:00'
  notes: '已对照 12973 原文与图 03-07 核对：010 在 encrypt.vmdk 搜到 rctf{unseCure_quick_form4t_vo1ume，7z 提取 0.fat（图 04 显示为 FAT32 分区 7340032 字节），VeraCrypt 主密码 rctf 进外层得 password.txt（Password 2: RCTF2019），备用密码进隐藏卷，WinHex 读 G: 得 _and_corrupted_1nner_v0lume}；与 truecrypt-memory-key-mount 不同链，未复跑。'
url: /docs/ctf/forensics/ctf-forensics-veracrypt-hidden-volume-vmdk-7z-winhex/
draft: false
kb_aliases:
- VeraCrypt 隐藏卷
- 不同密码进入不同文件系统
- vmdk 7z 提取分区
- WinHex 读取隐藏分区
- TrueCrypt 备用密码隐藏卷
---

## 一句话结论

VeraCrypt/TrueCrypt 容器支持「外层卷 + 隐藏卷」：用主密码挂载只看到外层文件系统，换备用密码则解锁尾部隐藏卷；CTF 中可先用 7z 直接从 vmdk 中提取 FAT 分区镜像，用主密码拿到外层提示（备用密码/线索），再用备用密码挂载隐藏卷，若隐藏分区无法被文件系统正常访问，改用 WinHex 以驱动器方式打开已解锁的虚拟卷、忽略解析报错做扇区级搜索，即可读出隐藏卷里的 flag 片段。

## 原理

- **vmdk 可被 7z 解析**：VMware 磁盘（vmdk）内含分区表与各分区数据，7z 能识别容器结构并列出/提取其中的分区镜像（本例提取出 `0.fat`），无需启动虚拟机。
- **VeraCrypt 双头结构**：加密卷头部存在主密钥区与隐藏卷密钥区；主密码解密外层头，备用密码解密隐藏卷头。隐藏卷数据放在外层卷文件系统之外的尾部空间，因此同一容器用不同密码挂载会得到两套完全不同的文件系统视图——这是合理否认（deniability）设计。
- **挂载与访问**：VeraCrypt 用备用密码挂载后会把隐藏卷解密为虚拟磁盘；若隐藏卷被标记为「隐藏」或元数据异常，资源管理器/文件系统层可能提示无法直接访问，但设备仍处于已解锁状态。
- **WinHex 为什么能读**：WinHex 以物理/逻辑驱动器方式打开设备时绕过文件系统解析，直接读取解密后的扇区字节；即使卷头/文件系统有损坏（例如题面提示卷被破坏），原始数据区的明文字符串仍可搜索到，因此能拿到后半段 flag。
- **边界**：WinHex 读到的是「已被 VeraCrypt 驱动解密」的虚拟卷，不是对密文容器直接搜索；若未正确挂载，扇区内容仍是密文。

## 触发条件

- 拿到磁盘镜像（vmdk 等）或加密容器文件，且题目提示使用 VeraCrypt/TrueCrypt、给出了一个或多个密码。
- 本机可安装 VeraCrypt 并加载虚拟磁盘（Windows 下需管理员权限）。
- 隐藏卷存在且备用密码可获得（常见于外层卷内的 password.txt/图片提示）。

## 利用步骤

1. 用十六进制编辑器（010）在 vmdk 中搜索已知 flag 前缀（如 `rctf{`），可先命中位于未加密区域/分区内的明文片段。
2. 用 7z 打开 `encrypt.vmdk`，提取其中的 `0.fat` 分区镜像。
3. VeraCrypt 选择该文件挂载，输入主密码（题面常见 `rctf` 等），进入外层文件系统，查找图片/`password.txt` 等线索，得到备用密码。
4. 卸载后重新挂载同一容器，改用备用密码，VeraCrypt 识别为「隐藏」类型卷。
5. 若隐藏分区提示无法直接访问，用 WinHex 打开该虚拟驱动器（忽略报错），搜索明文关键字/flag 片段，得到剩余部分。

最小化 PoC：

```
7z l encrypt.vmdk            # 列出分区，提取 0.fat
7z e encrypt.vmdk 0.fat
# VeraCrypt: 挂载 0.fat，密码 rctf -> 外层；密码 RCTF2019 -> 隐藏卷
# WinHex: Open Drive G:（隐藏卷虚拟盘），搜索 "_and_" / flag 后缀
```

## 变体与关联

- TrueCrypt 隐藏卷机制相同，密码区分外层/隐藏卷；内存取证场景可先用 `memdump` 提取 TrueCrypt 进程主密钥再挂载。
- VeraCrypt AES-XTS 手动扇区解密：已知 master key 时直接按扇区还原明文，不依赖驱动挂载。
- 外层卷内的提示文件也可能用图片隐写（LSB/属性）藏备用密码，需结合隐写工具。

## 检测与防御

- 取证方：对疑似加密容器应尝试多组密码（尤其外层卷中发现的提示），并检查容器尾部高熵区域的隐藏卷头；挂载后优先用扇区级工具读取，避免文件系统解析失败导致漏证。
- 安全方：隐藏卷是合理否认技术，无法从容器外观判断是否存在；DLP/取证策略应把整个容器视为潜在敏感数据。
