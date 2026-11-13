---
id: ctf-forensics-vbox-vdi-keystore-luks-dictionary-crack
title: 加密 VirtualBox 虚拟机与 LUKS 磁盘离线破解：pyvboxdie-cracker 爆破 VDI KeyStore + bruteforce-luks 爆破 /dev/sda
type: scenario
domain: ctf
path: ctf/forensics
technique: vbox-vdi-keystore-luks-dictionary-crack
tags:
- ctf
- forensics
- virtualbox
- vdi
- vbox
- luks
- disk-encryption
- dictionary-attack
- password-cracking
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V617
  verified_at: '2026-11-12T20:57:18+08:00'
  notes: '已对照原文及截图核对：截图52 .vbox 显示 Encrypted drive F:/2019.vdi、KeyStore AES-XTS256-PLAIN64、PBKDF2-SHA256，与卡片原理一致；截图53 cracker.py -v 2019-08-01.vbox -d rockyou.txt 命令与 PoC 一致，且作者补充了非 UTF-8 字典触发 UnicodeDecodeError 的细节有截图佐证；截图54-56 VirtualBox 导入启动/Parrot 引导，正文 bruteforce-luks-static -f wordlist.txt /dev/sda 输出 Password found: abc123；截图57 grep 脚本口令、58 sudo -l (root) ALL、59 root.txt。VBox 与 LUKS 两层属同一取证场景的连贯链，库内无同类卡（仅 IoT 加密 U 盘卡 related，介质算法不同）。未在本机复现，文章仅给出掩码后的 VBox 口令 computer****。'
url: /docs/ctf/forensics/ctf-forensics-vbox-vdi-keystore-luks-dictionary-crack/
draft: false
kb_aliases:
- VirtualBox 加密虚拟机破解
- pyvboxdie-cracker
- VDI KeyStore 爆破
- bruteforce-luks
- LUKS 字典破解
- VBOX 文件取证
---

## 一句话结论

拿到加密的 VirtualBox 虚拟机文件（`.vbox` + `.vdi`）后，可用 `pyvboxdie-cracker` 解析 VDI 的 KeyStore（AES-XTS256-PLAIN64 + PBKDF2-SHA256）对字典爆破开机口令；启动虚拟机后再对内部 LUKS 卷用 `bruteforce-luks` 做字典爆破（或把 LUKS 头转成哈希交给 john/hashcat），即可解开全盘加密、挂载或登录获取数据。

## 原理

- VirtualBox 全盘加密把卷主密钥存放在 VDI 的 KeyStore 中，开机口令经 PBKDF2-SHA256（原文算法 `AES-XTS256-PLAIN64`、`PBKDF2-SHA256`）派生密钥解出 KeyStore；口令强度决定离线爆破成本。`pyvboxdie-cracker` 读取 `.vbox` 配置找到加密磁盘（`.vdi`），定位 KeyStore 后逐条尝试字典口令。
- LUKS 头中保存多组 keyslot，每个 keyslot 用 PBKDF2 从口令派生密钥加密主密钥；验证只是本地解密尝试，因此可以离线字典爆破。`bruteforce-luks` 直接对块设备/镜像逐口令尝试，john/hashcat 的 luks 模式也可。
- 两层加密相互独立：破了 VirtualBox 口令只能启动虚拟机，卷内若还有 LUKS 仍需第二层口令；反之直接拿到虚拟磁盘镜像也可绕过 VBox 层单独爆 LUKS。
- 为什么可行：加密磁盘的威胁模型假设攻击者拿不到口令，但字典口令、复用口令、写在脚本/注释中的口令会把安全性降为"离线可搜索"。

## 触发条件

- 能获取加密 VM 的 `.vbox`、`.vdi`（或 LUKS 磁盘镜像）与足够算力；
- 有可信字典（rockyou、目标组织字典）或口令线索（脚本、配置、注释中的复用口令）；
- 工具可用：`pyvboxdie-cracker`（Python）、`bruteforce-luks`（静态二进制）或 john/hashcat。

## 利用步骤

1. 从目标主机收集 `.vbox`（含 `<Hardware>`/`<StorageControllers>` 与 `<Image uuid=...>` 引用）与对应 `.vdi`，用 `scp` 拉回分析机。
2. 运行 `python3 cracker.py -v <vm>.vbox -d /usr/share/wordlists/rockyou.txt`；工具先打印 KeyStore 信息（算法、PBKDF2 哈希），再对字典逐条爆破。注意字典需为 UTF-8 可解码文本（非 UTF-8 字典会报 `UnicodeDecodeError`）。
3. 得到开机口令后，在本地 VirtualBox 导入 `.vbox` 启动虚拟机，用该口令进入系统。
4. 若系统内还有 LUKS 全盘加密：在虚拟机/救援系统中把磁盘映射出来，执行 `bruteforce-luks-static -f wordlist.txt /dev/sda`；或先用 `cryptsetup luksDump`、`luks2hashcat`/`john` 提取哈希再离线破解。
5. 得到 LUKS 口令后 `cryptsetup open /dev/sda <name>` 并挂载，检索敏感文件；同时 `grep -r pass .` 等检查脚本/配置中的口令复用，用于后续 sudo/SSH 登录。

## PoC

```bash
# 1) VirtualBox VDI KeyStore 字典爆破
python3 cracker.py -v 2019-08-01.vbox -d /usr/share/wordlists/rockyou.txt

# 2) LUKS 字典爆破（块设备或镜像）
./bruteforce-luks-static-linux-amd64 -f wordlist.txt /dev/sda
# Password found: abc123
```

```text
# KeyStore 信息示例（工具输出）
Encrypted drive found : F:/2019.vdi
Algorithm = AES-XTS256-PLAIN64
Hash = PBKDF2-SHA256
```

## 变体与关联

- 变体：直接拿到 `.vdi` 时可跳过 VBox 层，仅爆 LUKS；反之只拿到 `.vbox` 不够，必须同时有对应 `.vdi`。
- 变体：`cryptsetup luksDump` + `luks2hashcat.py` 转 hashcat 模式 14600/34100，用 GPU 提速；john 的 `luks` 格式同理。
- 关联：[[ctf-forensics-truecrypt-memory-key-mount]]（内存取密钥免爆破）、[[ctf-forensics-bitlocker-fvek-memory-dislocker-mount]]（BitLocker FVEK 提取）、[[pentest-privilege-escalation-linux-grub-init-bash-password-bypass]]（另一种绕过磁盘加密的思路）。

## 检测与防御

- 防御方：加密口令使用高熵随机值并独立于其它账户；不要把磁盘/VM 口令写在脚本、注释、配置文件中；密钥/恢复码与加密卷分离存放。
- 取证方：优先寻找内存镜像（运行中 VM 的密钥在内存）与宿主上的口令线索，再决定是否跑字典；离线爆破耗时长，先小字典验证线索。
- 检测：监控大规模异常读取 `.vdi`/块设备与 `bruteforce-luks` 特征进程；VM 文件外带通常伴随大文件传输。
