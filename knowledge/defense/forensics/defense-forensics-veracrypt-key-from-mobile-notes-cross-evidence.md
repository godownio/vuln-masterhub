---
id: defense-forensics-veracrypt-key-from-mobile-notes-cross-evidence
title: VeraCrypt 加密分区取证：从手机笔记数据库关联恢复挂载密钥
type: scenario
domain: defense
path: defense/forensics
technique: veracrypt-cross-device-key-recovery
aliases:
- VeraCrypt 密钥取证
- VC 分区挂载
- 手机笔记数据库找密码
- 跨检材关联取证
- encrypted partition key recovery
tags:
- forensics
- veracrypt
- encrypted-volume
- mobile-backup
- sqlite
- room-database
- cross-evidence
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T02:06:33+08:00'
  notes: 已对照原文与图片 19-22 核对；D 盘 VC 分区、com.opennotes/notes_db 的 vE6w3re^URcXccrg、VeraCrypt 挂载成功一致
---

## 一句话结论

当 Windows 镜像里存在 VeraCrypt 加密分区、而本机找不到密码时，应把手机等其他检材一起纳入关联分析：案例中在 Android 笔记应用 `com.opennotes` 的 Room 数据库 `notes_db` 的 Note 表里找到字符串 `vE6w3re^URcXccrg`，用它在仿真环境挂载 10GB 的 VC 分区 D 成功，恢复出后续 C2/FRP 证据。

## 原理

- VeraCrypt 分区在分区表中通常显示为文件系统 `VC`（案例中分区 7，盘符 D，10.00GB），未挂载前无法直接读取文件；挂载需要正确的密码（或密钥文件/两者组合）。
- 用户往往不会把密码写在被加密的同一台机器上，但会在手机笔记、便签、聊天记录、密码管理器、浏览器密码库等地方留下可关联的字符串；跨检材关联是解决“加密容器密码缺失”的常用路径。
- Android 应用的本地数据通常在 `/data/data/<package>/databases/` 或备份 tar 的 `/data/user/0/<package>/databases/` 下；Room 数据库是 SQLite，直接查询表即可读到明文笔记内容。
- 案例中的应用包名 `com.opennotes` 是笔记类应用，`notes_db` 的 `Note` 表包含 `title`、`content`、`timestamp` 等字段；第 1 条记录的 `content` 就是与 VC 容器密码格式高度相似的字符串。
- 该字符串是否就是 VC 密码，需要实际挂载验证；VeraCrypt 挂载成功即可确认，失败则回退检查大小写、特殊字符、剪贴板/输入法残留或密钥文件组合。

## 触发条件

- 磁盘镜像中存在文件系统标记为 `VC` 的分区，且当前没有可用的挂载密码/密钥文件。
- 同一案件还有其他检材（手机备份、聊天记录、笔记、浏览器配置、密码管理器等）可关联。
- 取证环境可运行 VeraCrypt（或能离线解析 VC 头）并具备挂载权限。
- 待验证字符串可能含特殊字符（`^`、`@`、下划线等），需要保证原样输入。

## 利用步骤

1. 在磁盘镜像分区表中定位文件系统为 `VC` 的分区，记录起始扇区、大小与盘符（案例：分区 7 / D / 10.00GB）。
2. 在手机备份中按包名定位应用数据目录：`/data/user/0/com.opennotes/`（或 `/data/data/com.opennotes/`），查找 `databases/notes_db` 及 `-wal`/`-shm`。
3. 用 SQLite 打开 `notes_db`，查看 `Note` 表（或 `sqlite_master` 列出的表）中的 `title`/`content`，筛选长度、字符集与密码相似的记录。
4. 在仿真/挂载环境中打开 VeraCrypt，选择该分区设备，输入候选字符串；勾选只读挂载，避免破坏证据。
5. 挂载成功后导出分区内文件，继续分析 C2、FRP、SSH 等后续证据；失败则尝试大小写变体、去掉/保留特殊字符、密钥文件组合。
6. 记录候选字符串来源（应用、数据库、表、记录 ID）与挂载结果，形成完整的证据链。

## PoC

```bash
# 1) 查看 SQLite 表结构（对手机备份中的 notes_db 副本操作）
sqlite3 notes_db ".tables"
sqlite3 notes_db ".schema Note"

# 2) 读取笔记内容，筛选疑似密码
sqlite3 notes_db "SELECT id,title,content FROM Note;"

# 案例输出（节选）：
# 1||vE6w3re^URcXccrg
# 2|vshell|...
# 4||rota_sasaki@proton.me

# 3) VeraCrypt 命令行只读挂载（设备路径按实际替换）
veracrypt -t --mount /dev/sdX --volume-type normal --read-only -p 'vE6w3re^URcXccrg' /mnt/veracrypt1
```

原文在仿真环境中用 VeraCrypt 图形界面选择该设备并输入字符串后挂载成功；命令行示例为等价复现方式，需按实际设备与权限调整。

## 变体与关联

- 变体：密码来自浏览器保存的密码、聊天记录、密码管理器导出、配置文件中的 `password` 字段，或另一台设备的笔记/待办应用。
- 变体：VeraCrypt 使用密钥文件而非密码时，需在磁盘/手机中搜索 `.key`、随机二进制文件，并与密码组合尝试。
- 变体：BitLocker/LUKS 等全盘加密同样适用“跨检材找恢复密钥/密码”的思路，但取证工具与挂载方式不同。
- 关联：[[defense-forensics-c2-server-sqlite-conf-artifacts]]（本案例挂载后发现的 C2/FRP 证据）、[[defense-forensics-chromium-artifact-offline-decrypt]]（浏览器凭据离线解析）。

## 检测与防御

- 防御：不要把加密容器密码写在手机笔记、聊天记录或同一账号可访问的云笔记中；使用专用密码管理器并开启强主密码。
- 防御：对加密容器使用密码 + 密钥文件双因素，密钥文件与容器分离存放；定期轮换密码。
- 检测：取证时检查是否存在 `VC` 文件系统分区、VeraCrypt 安装痕迹、最近挂载记录与容器头备份；对手机笔记应用数据库做关键词筛选（password、key、vc、veracrypt）。
- 响应：挂载后先做只读镜像/哈希校验，记录证据来源与操作时间，避免污染原始检材。
