---
id: defense-forensics-obsidian-livesync-config-credential-recovery
title: Obsidian 本地库取证：Mega 恢复密钥与 self-hosted LiveSync CouchDB 凭据恢复
type: scenario
domain: defense
path: defense/forensics
technique: obsidian-livesync-credential-recovery
aliases:
- Obsidian 取证
- LiveSync 插件配置
- CouchDB 远程库凭据
- Mega 恢复密钥
- Obsidian vault 密码
- 笔记软件配置取证
tags:
- forensics
- obsidian
- livesync
- couchdb
- mega
- credentials
- configuration
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T02:06:37+08:00'
  notes: 已对照原文与图片 10-13 核对；Mega 恢复密钥 TTsJzb6V8XK_no6gKfh4jw、CouchDB URL/账号/密码 Wang@0528@obsidian 一致
---

## 一句话结论

Obsidian 的 vault 与第三方同步插件会在本地保存远超笔记正文的信息：案例中笔记里直接写着 Mega 网盘恢复密钥 `TTsJzb6V8XK_no6gKfh4jw`，而 `self-hosted LiveSync` 插件配置中保存了远程 CouchDB 的 URL `http://47.89.230.121:5984/?db=obsidian`、用户名 `admin` 与密码 `Wang@0528@obsidian`；取证时优先检查 vault 内的 Markdown 与 `.obsidian/plugins/*/data.json`。

## 原理

- Obsidian 把每个 vault 作为普通文件夹，笔记是 Markdown 明文；用户常把恢复密钥、服务器地址、账号口令等敏感信息直接写在笔记里。
- 第三方插件配置通常保存在 vault 的 `.obsidian/plugins/<plugin-id>/data.json`（部分插件还有 `main.js`、`manifest.json`），其中会明文保存同步地址、数据库名、用户名、密码、token、E2EE 密码等。
- 案例中的 `self-hosted LiveSync`（obsidian-livesync）配置界面直接显示 CouchDB URL、用户名、密码与数据库名；这些值在磁盘上通常以 JSON 字段形式存在，可直接用文本搜索或 jq 提取。
- Mega 客户端/网盘的恢复密钥是账户恢复的高价值凭据；它出现在笔记正文中，说明“应用内可见”不等于“文件加密”，取证时应全库搜索关键词。
- 插件还可能保存同步历史、远端数据库结构、E2EE 配置；即使密码被修改，旧配置/备份也可能保留历史值。

## 触发条件

- 目标主机存在 Obsidian vault（含 `.obsidian/` 目录）或 Obsidian 安装目录/备份。
- vault 内安装了同步类第三方插件（LiveSync、Remotely Save、Self-hosted LiveSync 等），或笔记中包含密钥/凭据。
- 取证环境可读取文件系统或镜像，并能解析 JSON/Markdown。
- 需要访问远程服务时，具备相应网络与授权条件。

## 利用步骤

1. 定位 vault 根目录（含 `.obsidian/`、`*.md`）与 Obsidian 配置目录；优先复制整个 vault 到工作目录。
2. 全库搜索关键词：`password`、`passwd`、`token`、`secret`、`key`、`recovery`、`couchdb`、`livesync`、`http://`、`https://`。
3. 列出 `.obsidian/plugins/` 下插件目录，读取每个 `data.json`；重点看 `obsidian-livesync` 的 `couchDB`/`uri`/`username`/`password`/`dbName` 字段。
4. 在 Markdown 笔记中搜索 Mega、恢复密钥、服务器地址等字符串，记录所在文件与行号。
5. 如需验证远程库，使用只读账号或隔离环境连接 CouchDB，避免修改/删除数据；记录数据库名与文档数量。
6. 汇总凭据来源（笔记文件、插件配置文件、记录字段）并固定证据哈希。

## PoC

```bash
# 1) 在 vault 中搜索敏感关键词
rg -n -i 'password|passwd|token|secret|recovery|couchdb|livesync|https?://' /path/to/vault

# 2) 查看 LiveSync 插件配置（路径按实际插件 ID）
cat /path/to/vault/.obsidian/plugins/obsidian-livesync/data.json | jq .

# 案例中界面显示的值：
# URL:      http://47.89.230.121:5984/?db=obsidian
# 用户名:   admin
# 密码:     Wang@0528@obsidian
# 数据库名: obsidian

# 3) 笔记中的 Mega 恢复密钥（案例）
# TTsJzb6V8XK_no6gKfh4jw
```

```bash
# 4) 只读验证 CouchDB（可选，需授权）
curl -s -u 'admin:Wang@0528@obsidian' 'http://47.89.230.121:5984/obsidian' | jq '{db_name,doc_count}'
```

说明：案例通过 Obsidian 图形界面读取插件设置与笔记内容；`data.json` 路径为 LiveSync 插件的常规存储位置，具体文件名/字段可能随插件版本变化，需按实际版本核对。

## 变体与关联

- 变体：Remotely Save、Obsidian Git、坚果云/WebDAV 插件会保存 WebDAV/S3/Git 凭据、token 或 SSH 私钥路径。
- 变体：笔记正文中的 API key、数据库连接串、VPN 配置、恢复码；全库搜索比只看插件配置更容易命中。
- 变体：Obsidian 的 `.obsidian/workspace.json`、缓存与回收站 `.trash/` 可能保留已删除笔记的旧内容。
- 关联：[[defense-forensics-veracrypt-key-from-mobile-notes-cross-evidence]]（同为“应用数据中的明文凭据”）、[[defense-forensics-chromium-artifact-offline-decrypt]]（浏览器凭据离线解析）、[[pentest-recon-frontend-obfuscated-js-hardcoded-credentials]]（前端硬编码凭据）。

## 检测与防御

- 防御：不要在笔记正文中保存恢复密钥、密码、API token；使用专用密码管理器并开启 MFA。
- 防御：同步插件使用最小权限的专用账号与只读/限定数据库权限；定期轮换凭据，避免多设备复用同一口令。
- 检测：终端/EDR 对 Obsidian vault 内 `data.json` 的异常读取、对 `.obsidian/plugins` 的批量访问；网络侧对 CouchDB 5984 端口的异常连接。
- 响应：发现泄露后立即轮换 CouchDB 口令、Mega 恢复密钥与相关 token；审计远程库访问日志，检查是否有未授权文档读取/写入。
