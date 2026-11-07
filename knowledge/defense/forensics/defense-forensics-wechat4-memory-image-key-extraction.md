---
id: defense-forensics-wechat4-memory-image-key-extraction
title: 微信 4.x 内存镜像密钥提取：Volatility3 转储 Weixin.exe，按 x'<64hex enc_key><32hex salt>' 扫描并用 salt 匹配数据库头
type: scenario
domain: defense
path: defense/forensics
technique: wechat4-wcdb-memory-key-extraction
aliases:
- 微信 4.x 密钥提取
- Weixin.exe
- Weixin.dll
- windows.memmap
- x'...' 96 位特征
- salt 匹配数据库头
- WCDB 密钥
- 平航杯2026
tags:
- forensics
- windows
- memory-image
- volatility3
- wechat
- wcdb
- sqlcipher
- key-extraction
cve: []
severity: medium
confidence: high
status: verified
affected_versions: WeChat 4.x（文章实测 4.1.8.67）
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:30:32+08:00'
  notes: 已对照原文与 5 张截图核对：Weixin.exe/Weixin.dll 4.1.8.67、windows.memmap 转储 1.3G、x'<64hex><32hex>' 正则、18 组候选、message_0.db 头 salt b59f89cb426e60d5406cd08db4bcb27d 匹配第 2 组均一致；affected_versions 已按原文标 WeChat 4.x/4.1.8.67；未实际运行。
---

## 一句话结论

微信 4.x（NT 架构）把每个加密数据库的原始密钥与 salt 以 `x'<64位hex enc_key><32位hex salt>'` 的形式缓存在 `Weixin.exe` 进程内存中；用 Volatility3 找到进程、`windows.memmap --dump` 转储进程内存后，正则扫描这 96 位 hex 特征，再把候选 salt 与数据库文件头的前 16 字节比对，即可锁定正确的聊天记录数据库密钥。

## 原理

- 微信 3.x 及以前主进程是 `WeChat.exe`、核心模块是 `WeChatWin.dll`；微信 4.x（NT 架构）改为 `Weixin.exe` + `Weixin.dll`。因此按进程名过滤时要搜 `weixin` 而不是 `wechat`，否则会漏掉新版本。
- 微信 4.x 使用 WCDB（SQLCipher 封装）加密本地数据库：每个数据库有独立的 salt 与 enc_key；数据库打开后，派生的 raw key 会以 `x'<64hex_enc_key><32hex_salt>'` 的文本形式留在进程内存中（三个平台都可能出现这种缓存形式）。
- 64 位 hex 对应 32 字节 enc_key，32 位 hex 对应 16 字节 salt；两者拼起来正好 96 个 hex 字符，前面带 `x'`、后面带 `'`，形成一个很容易用正则匹配的特征。
- 数据库文件（如 `message_0.db`）的第 1 页前 16 字节就是 salt（SQLCipher 用 salt 参与密钥派生）；把扫描到的候选 salt 与文件头逐字节比较，就能从多个密钥中确定该数据库对应的那一个。
- 内存镜像是运行态快照，不需要在线调试或注入微信进程；只要拿到完整内存镜像，就能离线用 Volatility3 的 `windows.pslist`、`windows.dlllist`、`windows.memmap` 完成定位与转储。这是与“附加 x64dbg 在 sqlite3_key 下断点”不同的离线取证路径。
- 根因是客户端把可直接使用的 raw key 长期留在用户态内存；只要攻击者/取证人员能读取进程内存或内存镜像，密钥就会泄露。

## 触发条件

- 目标为 Windows 上的微信 4.x 客户端，且本地存在 WCDB/SQLCipher 加密数据库（如 `message_*.db`）。
- 已获得完整内存镜像（如 `DESKTOP-*.dmp`），或有权读取目标进程内存。
- 微信进程在镜像生成时仍在运行，且 raw key 已缓存在内存中。
- 使用与镜像匹配的 Volatility3 符号/配置（Windows 版本、符号表），能正常执行 `windows.pslist`/`windows.memmap`。
- 取证/分析已获授权，遵守隐私与合规要求。

## 利用步骤

1. 列出进程，确认 `Weixin.exe` 的 PID：
   ```bash
   vol -f image.dmp windows.pslist | grep -i "Weixin.exe"
   ```
2. 查看该 PID 的模块列表，用 `Weixin.dll` 的路径确认微信版本：
   ```bash
   vol -f image.dmp windows.dlllist --pid <PID> | grep -i "Weixin.dll"
   ```
   文章环境为 `C:\Program Files\Tencent\Weixin\4.1.8.67\Weixin.dll`，即 4.1.8.67。
3. 转储该进程的完整内存：
   ```bash
   vol -f image.dmp windows.memmap --pid <PID> --dump
   ```
   得到约 1.3 GB 的 `pid.<PID>.dmp`。
4. 用正则扫描 `x'<64hex><32hex>'` 特征，去重后输出候选 `(enc_key, salt)`；文章环境找到 18 组候选。
5. 读取目标数据库文件的前 16 字节（salt），与候选 salt 比对；文章 `message_0.db` 的头部 `B5 9F 89 CB 42 6E 60 D5 40 6C D0 8D B4 BC B2 7D` 与第 2 组候选的 salt `b59f89cb426e60d5406cd08db4bcb27d` 一致，锁定该组密钥。
6. 用该 enc_key 进入下一步数据库解密（见关联卡片）。

## PoC

Volatility3 定位与转储：

```bash
vol -f DESKTOP-XXXX.dmp windows.pslist | grep -i "Weixin.exe"
vol -f DESKTOP-XXXX.dmp windows.dlllist --pid 10892 | grep -i "Weixin.dll"
vol -f DESKTOP-XXXX.dmp windows.memmap --pid 10892 --dump
```

内存特征扫描（mmap 逐块匹配，避免一次性读入 1.3 GB）：

```python
import re, mmap

DUMP = "pid.10892.dmp"
pat = re.compile(rb"[xX]'([a-fA-F0-9]{64})([a-fA-F0-9]{32})'")
seen, hits = set(), []
with open(DUMP, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
    for m in pat.finditer(mm):
        enc_key = m.group(1).decode().lower()
        salt = m.group(2).decode().lower()
        if (enc_key, salt) not in seen:
            seen.add((enc_key, salt))
            hits.append((enc_key, salt))

for i, (k, s) in enumerate(hits, 1):
    print(i, k, s)

# 读取数据库头 16 字节，与候选 salt 比对
with open("message_0.db", "rb") as f:
    db_salt = f.read(16).hex()
print("db salt:", db_salt)
print("match:", [k for k, s in hits if s == db_salt])
```

## 变体与关联

- **版本变体**：微信 3.x 用 `WeChat.exe`/`WeChatWin.dll`，密钥格式与偏移不同；4.x 用 `Weixin.exe`/`Weixin.dll`，文章环境为 4.1.8.67。
- **内存来源变体**：完整内存镜像（Volatility3）、进程 minidump、`windows.memmap --dump` 的子集；只要能读到进程内存即可。
- **特征变体**：raw key 可能是 hex 文本、UTF-16 字符串或二进制结构；不同版本/平台缓存形式可能变化，需要重新定位特征。
- **关联**：[[defense-forensics-wcdb4-sqlcipher-offline-decrypt]]（拿到 enc_key 后的数据库解密）；[[defense-forensics-sqlcipher-im-db-memory-key-extraction]]（在线 x64dbg + `sqlite3_key` 断点的另一条路径）；[[defense-forensics-core-dump-secret-extraction]]（通用 core dump 密钥提取）。
- **边界**：若客户端用 DPAPI/凭据保险库封装密钥、只在需要时解密并清零，或内存镜像不含微信进程，则本路径失效；内存镜像的符号匹配失败也会导致 `windows.memmap` 无法执行。

## 检测与防御

- **检测**：异常读取/复制微信进程内存、生成 `pid.<PID>.dmp`、对内存镜像做 96 位 hex 特征扫描；Volatility 类工具在主机上的执行痕迹。
- **防御**：客户端不要把 raw key 长期明文留在用户态内存；使用 OS 凭据保险库/DPAPI、每用户派生密钥，使用后清零；对内存转储与调试权限做最小化控制。
- **取证侧**：先做内存镜像再离线分析，避免直接调试改变进程状态；解密后的数据库只读保存并计算哈希，保证证据完整性。
- **合规**：聊天记录属于个人通信数据，提取与解密需有明确授权与合法依据。
