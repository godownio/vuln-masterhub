---
id: ctf-forensics-linux-memory-rc4-encrypted-file-source-key-recovery
title: Linux 内存镜像恢复 RC4 加密文件：linux_find_file 导出为空时搜源码取硬编码双密钥，两层 RC4 解密
type: scenario
domain: ctf
path: ctf/forensics
technique: linux-memory-image-rc4-encrypted-file-source-key-recovery
aliases:
- 强网杯 找到PNG了吗
- have_your_fun.jocker
- linux_enumerate_files
- linux_find_file 导出为空
- 内存搜源码找密钥
- where_is_the_key do_not_care
- It's_So_Hard_To_Find_A_Picture
tags:
- ctf
- forensics
- memory
- volatility2
- linux
- rc4
- encrypted-file
- source-code-recovery
- cyberchef
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V553
  verified_at: '2026-11-11T23:05:14+08:00'
  notes: 已对照原文与 19 张截图核对：图 09 linux_enumerate_files 命中 have_your_fun.jocker(0xffff9ce28fe300e8)；图 10 内存中 RC4 源码含 do_not_care/where_is_the_key；图 13 CyberChef 配方 do_not_care→where_is_the_key、输入 3060 字节、输出 It's_So_Hard_To_Find_A_Picture；源码接收端顺序为 key2(where_is_the_key)→key(do_not_care)。原稿“必须按相反顺序、反序会乱码”与 RC4 流密码异或可交换性质不符、也与原文成功配方矛盾，已修正为“两把密钥顺序可交换”；20000 字节整段复制改为按 20000 缓冲定位、实际截取 3060 字节。未验证点：linux_find_file 导出为空的原因原文未深究。
---

## 一句话结论

Linux 内存镜像里用 `linux_enumerate_files` 发现可疑文件 `have_your_fun.jocker`、`linux_find_file` 导出却为空时，不要放弃：直接在镜像中搜索文件名/相关字符串，命中进程里残留的 C 源码，从源码拿到两把硬编码 RC4 密钥（`where_is_the_key`、`do_not_care`），再用这两把密钥对内存中的密文做两层 RC4（原文 CyberChef 输入 3060 字节），即可解出明文字符串 `It's_So_Hard_To_Find_A_Picture`。

## 原理

- **内存镜像保留的不只是文件**：`linux_find_file` 按文件缓存/inode 恢复文件内容，若文件未完整落盘、被截断或程序写入的是错误缓冲区，导出结果可能为空；但进程收到/处理的原始数据、源码字符串仍可能留在物理内存中，可绕过文件恢复直接搜内存。
- **源码即密钥来源**：本例恶意客户端源码把两把 RC4 密钥硬编码为字符串 `where_is_the_key`（接收后先解）和 `do_not_care`（再解），并固定处理 20000 字节；搜索文件名 `jocker` 就能在镜像里定位这段源码文本，直接读出密钥与顺序，不需要破解算法。
- **RC4 对称且两层可交换**：RC4 是流密码，加密即明文与密钥流异或；连续用密钥 A、B 各做一次等价于异或两个密钥流，因此先 A 后 B 与先 B 后 A 结果相同。本例源码接收端按 `where_is_the_key` → `do_not_care` 解密，而原文 CyberChef 按 `do_not_care` → `where_is_the_key` 应用两层 RC4 同样还原出明文——关键是两把密钥都用上，顺序不影响结果。
- **密文定位**：拿到密钥后，在 WinHex/strings 中按源码的 20000 字节缓冲范围寻找与文件/进程相关的高熵数据段，复制有效密文段进 CyberChef（原文实际输入 3060 字节）；也可先用已知明文片段（如 PNG 头 `89 50 4E 47`，原文也用其做过验证）确认密钥。
- **为什么 CTF 常这么出**：文件恢复失败制造"死路"，考察是否想到从内存搜源码/密钥；密钥硬编码 + 对称加密使"拿到密钥即可解"成为最短路径。

## 触发条件

- 已获得 Linux 内存镜像，且能按目标内核构建/使用 Volatility2 profile（本例 Ubuntu 20.04 / 5.4.0-100-generic，profile `LinuxUbuntu20_5-4-0-100x64`）。
- 镜像中存在可疑加密文件/进程，且 `linux_find_file` 导出内容为空或不足。
- 处理该文件的程序源码或密钥字符串仍驻留内存（未被清理/换出）。
- 已知/可推断密文长度与加密算法（本例源码明示 RC4、20000 字节、两把密钥）。

## 利用步骤

1. 按内核版本准备 Volatility2 profile（见关联卡），枚举文件：
   ```
   python2 vol.py -f '找到PNG了吗.mem' --profile=LinuxUbuntu20_5-4-0-100x64 linux_enumerate_files
   ```
   发现 `/home/yuren/Desktop/have_your_fun.jocker`（地址 `0xffff9ce28fe300e8`）。
2. 尝试导出文件：
   ```
   python2 vol.py -f '找到PNG了吗.mem' --profile=LinuxUbuntu20_5-4-0-100x64 \
     linux_find_file -i 0xffff9ce28fe300e8 -O 1.jocker
   ```
   导出为空/无有效内容。
3. 在镜像中搜索文件名或关键字 `jocker`，命中 C 源码（socket/recv/RC4 客户端），读出密钥 `where_is_the_key`、`do_not_care`、处理长度 20000。
4. 在 WinHex/内存视图中按源码的 20000 字节缓冲范围定位密文段（与 `recv(buff, sizeof(buff), 0)` 对应的缓冲区），复制有效密文段为 Hex（原文 CyberChef 输入 3060 字节）。
5. 用 CyberChef 依次执行 RC4（passphrase `do_not_care`，UTF-8）→ RC4（passphrase `where_is_the_key`，UTF-8），输入/输出均为 Hex。
6. 得到明文 `It's_So_Hard_To_Find_A_Picture`；若结果乱码，检查两把密钥是否都已应用、密钥字符串是否正确、截取范围是否混入非密文字节（RC4 两层密钥顺序可交换，不是排查重点）。

## PoC

Volatility2 命令（原文实测）：

```text
python2 vol.py -f '找到PNG了吗.mem' --profile=LinuxUbuntu20_5-4-0-100x64 linux_enumerate_files
python2 vol.py -f '找到PNG了吗.mem' --profile=LinuxUbuntu20_5-4-0-100x64 \
  linux_find_file -i 0xffff9ce28fe300e8 -O 1.jocker
```

CyberChef 配方（原文截图）：

```text
RC4, passphrase="do_not_care",      input=Hex, output=Hex
RC4, passphrase="where_is_the_key", input=Hex, output=Hex
```

输出：`It's_So_Hard_To_Find_A_Picture`。

内存中的源码片段（关键逻辑）：

```c
unsigned char key[] = "do_not_care";
unsigned char key2[] = "where_is_the_key";
...
str = (char *) malloc(20000);
memcpy(str, buff, 20000);
rc4_encrypt_decrypt(key2, str, 20000);
scanf("%s", q);
rc4_encrypt_decrypt(key, str, 20000);
fwrite(buff, 1, 20000, file);
```

## 变体与关联

- **同类内存取证卡**：库内有"内存镜像关键词搜索：按 UTF-8/UTF-16 定位明文 flag"（直接搜明文）、"Volatility filescan 定位用户壁纸/Atbash"（Windows）、"TrueCrypt 内存密钥挂载"等；本卡补充"文件恢复失败后搜源码取密钥"这条。
- **密钥/算法变体**：AES/XOR 硬编码密钥同样可从内存源码/配置中提取；若源码不在内存，可尝试已知明文攻击（如 PNG 头）确认加密算法与偏移，或从进程堆/栈中找密钥。
- **顺序/长度坑**：RC4 等异或流密码两层密钥顺序可交换，两把都用上即可；而 AES-CBC 等链式分组模式必须反向逐块解密。固定长度缓冲可能包含填充/文件头，需按源码的 `sizeof(buff)` 与偏移调整；`fwrite` 写错缓冲区时文件内容与进程内明文可能不一致。
- **平台变体**：Windows 镜像可用 Volatility2/3 的 `filescan`/`dumpfiles` + `strings` 搜源码；内存中的 .NET/Java 程序同理（脚本/字节码可读）。

## 检测与防御

- **CTF 解题要点**：文件恢复失败先别换题，搜与文件名/路径相关的字符串；源码里的密钥比爆破更快；用已知明文验证方向。
- **防御/应急视角**：进程内存中残留明文密钥/源码是常见取证突破口——应急时应优先采集内存镜像（重启/进程退出即丢失）；对恶意样本的加密外传文件，可在内存中找到密钥后离线解密还原数据。
- **证据完整性**：镜像与导出文件做哈希，记录 Volatility 版本/profile 名称与导出地址，保证可复现。

## 备注

- 原文为 2023 强网杯 Misc 题"找到PNG了吗"的解题记录，Profile 为 `LinuxUbuntu20_5-4-0-100x64`，导出地址 `0xffff9ce28fe300e8`，CyberChef 输出 `It's_So_Hard_To_Find_A_Picture` 均来自截图。
- 原文中 `linux_find_file` 导出为空的具体原因未深究；本卡按"搜内存源码"路径记录，未在本机复现。
