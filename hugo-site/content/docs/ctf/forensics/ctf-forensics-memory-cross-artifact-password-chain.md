---
id: ctf-forensics-memory-cross-artifact-password-chain
title: 内存镜像跨证据口令链：hashdump NTLM/envars/图片文字/前序 flag 的 SHA1 作为压缩包与 KeePass 口令
type: scenario
domain: ctf
path: ctf/forensics
technique: memory-cross-artifact-password-chain
tags:
- forensics
- memory
- volatility
- password
- hashdump
- envars
- keepass
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V642
  verified_at: '2026-11-13T02:33:03+08:00'
  notes: 已对照原文 12559 全文与 49 张图核对：Lab1 hashdump Alissa Simpson NT 哈希 f4ff64c8baac57d22f22edc681055ba6→大写作 1.rar 口令（图08/10/11）、Lab2 Password.png 文字 P4SSw0rd_123 作 KeePass 主密码（图16/17）、Lab2 Important.zip 口令为 Lab1 stage-3 flag 的 SHA1 小写 6045dd90029719a039fd2d2ebcca718439dd100a（图20/21）、Lab6 envars RAR password=easyaspeasyvirus（图47）均与原文一致；PoC 偏移 0x000000003fa3ebc0 与图08 filescan 一致。查重候选 keepass 爆破/TrueCrypt 等均非同链，保留。CTF 靶场无产品版本，affected_versions 保持省略。未实际运行 Volatility。
url: /docs/ctf/forensics/ctf-forensics-memory-cross-artifact-password-chain/
draft: false
kb_aliases:
- 内存取证口令链
- NTLM hash 当密码
- envars 里的 RAR 密码
- 前序 flag 派生口令
- 跨证据口令复用
---

## 一句话结论

MemLabs 式内存取证常把“加密容器 + 口令来源”拆在不同证据里：压缩包注释/文件名指出口令是某账户 NTLM hash 的大写、前一关 flag 的 SHA1、某张图片里的文字或浏览器进程环境变量；用 `filescan`/`dumpfiles` 取出容器，再用 `hashdump`/`envars`/`iehistory`/图片 OCR 找到源值并按指定变换，即可解锁 RAR/ZIP/KeePass 拿到下一关 flag。

## 原理

- 加密容器本身不提供口令，但容器注释、文件名或提示文本会描述口令的**派生方式**（“Password is NTLM hash (in uppercase) of Alissa's account passwd”“Password is SHA1(stage-3-FLAG), lowercase”）。
- 口令源常驻内存的不同结构：
  - `hashdump`：SAM/LSA 中的本地账户 NTLM 哈希（`user:RID:LM:NT:::`），取 NT 段按提示转大写；
  - `envars`：进程环境变量，可能被用户或程序塞入口令（如 Firefox 进程的 `RAR password=easyaspeasyvirus`）；
  - `iehistory`/`filescan`：访问过的图片（如 `Password.png`）里写着口令；
  - 前序 flag：按提示做 SHA1/MD5/大小写变换。
- KeePass 数据库（`.kdbx`）用主密码解锁后可直接看条目密码；RAR/ZIP 用 `unrar`/`7z` 带口令解压。
- 这类题的关键不是破解，而是**证据关联**：先看容器提示，再回内存里找对应结构，避免无脑爆破。

## 触发条件

- 内存镜像中存在加密容器（rar/zip/kdbx）及其提示文本；
- 对应口令源在内存中仍可提取（SAM 哈希、进程环境变量、浏览器缓存、图片文件）；
- 已知派生规则（大小写、哈希算法）。

## 利用步骤

1. `filescan` 搜 `rar|zip|kdbx|png` 等，`dumpfiles -Q <offset>` 导出容器与提示文件。
2. 读容器注释/压缩包内提示，确定口令派生方式。
3. 按提示到对应插件取源值：
   - `hashdump` 取账户 NT 哈希并转大写；
   - `envars` 搜 `PASS|RAR|KEY` 等变量；
   - `iehistory` 找被打开的 `Password.png` 等图片，dump 后读文字；
   - 计算前一关 flag 的 SHA1（小写）。
4. 用得到的口令解压/解锁，取出下一关 flag 或新的容器。

## PoC

```bash
# 1) 提取容器
python2 vol.py -f MemoryDump_Lab1.raw --profile=Win7SP1x64 filescan | grep -E "rar|zip"
python2 vol.py -f MemoryDump_Lab1.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000003fa3ebc0 -D ./
# 2) 容器注释：Password is NTLM hash (in uppercase) of Alissa's account passwd.
python2 vol.py -f MemoryDump_Lab1.raw --profile=Win7SP1x64 hashdump
# Alissa Simpson:1003:...:f4ff64c8baac57d22f22edc681055ba6:::
# 口令 = F4FF64C8BAAC57D22F22EDC681055BA6
7z x 1.rar -pF4FF64C8BAAC57D22F22EDC681055BA6

# 另一关：RAR 密码在 Firefox 进程环境变量
python2 vol.py -f MemoryDump_Lab6.raw --profile=Win7SP1x64 envars | grep -i "RAR password"
# RAR password    easyaspeasyvirus
```

其它变体：`Password.png` 里的文字作 KeePass 主密码；`SHA1('flag{w3ll_3rd_stage_was_easy}') = 6045dd90029719a039fd2d2ebcca718439dd100a` 作 zip 口令（小写）。

## 变体与关联

- 变体：口令源也可能是 `cmdscan` 里敲过的命令、`consoles` 输出、`screenshot` 恢复的桌面内容。
- 变体：口令变换包括大写/小写、SHA1/MD5、base64、去掉前缀等，严格按提示执行。
- 关联：[[ctf-forensics-keepass-kdbx-hashcat-master-crack]]——KeePass 数据库的另一种路线（离线爆破主密码）；本卡是已知口令直接解锁。
- 关联：[[defense-forensics-volatility2-cmdline-hashdump-netscan-triage]]——hashdump 的基本用法与输出格式。
- 关联：[[ctf-forensics-volatility-iehistory-chromehistory-browser-clues]]——定位被访问过的图片/容器。

## 检测与防御

- 该卡为 CTF 取证手法；现实中同样说明“口令派生自内存可提取值”会削弱归档加密。
- 防御：归档密码使用独立高熵随机值，不要复用账户哈希/前序秘密；KeePass 主密码不与其它证据同处一台机器；敏感容器避免在注释中写口令提示。
