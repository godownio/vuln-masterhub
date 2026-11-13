---
id: ctf-forensics-volatility-iehistory-chromehistory-browser-clues
title: Volatility2 iehistory/chromehistory 提取浏览器历史：file:// 访问记录、下载链接与 pastebin/邮箱线索链
type: scenario
domain: ctf
path: ctf/forensics
technique: volatility-iehistory-chromehistory-browser-clues
tags:
- forensics
- memory
- volatility
- browser
- iehistory
- chromehistory
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V642
  verified_at: '2026-11-13T02:33:01+08:00'
  notes: 已对照原文 12559 全文与 49 张图核对：iehistory 的 file:/// 记录（SW1wb3J0YW50.rar→Important.rar、Pictures/Password.png、C:/Users/SmartNet/Secrets/Hidden.kdbx，图15/30）与 chromehistory 的 mega 下载链接（图19：32 https://mega.nz/#!TrgSQTS!H0Z...）及 pastebin 中转页（图36：169 https://pastebin.com/RSGSi1nk）均与卡片示例一致；PoC 与 Trigger 合理。查重 top 候选为 cmdscan/wallpaper-atbash 等不同链卡，非重复。CTF 靶场无产品版本，affected_versions 保持省略。未实际运行 Volatility。
url: /docs/ctf/forensics/ctf-forensics-volatility-iehistory-chromehistory-browser-clues/
draft: false
kb_aliases:
- iehistory 取证
- chromehistory 取证
- 浏览器历史线索
- 内存中的下载链接
---

## 一句话结论

Volatility2 的 `iehistory` 解析 IE/资源管理器在内存中的 index.dat 缓存（能列出用户打开过的本地 `file:///` 路径，包括 base64 编码的文件名与隐藏目录），`chromehistory` 解析 Chrome 的 History/URL 记录（能直接拿到 mega.nz 下载链接、pastebin 地址）；二者常把后续取证引向“还要 dump 哪个文件、去哪下载下一关素材”。

## 原理

- IE/Explorer 的浏览记录保存在 `index.dat`（URL 缓存索引）中，进程运行时会映射/缓存；`iehistory` 从内存解析出访问记录，包含 `Visited ...@file:///C:/Users/...` 这样的本地路径。
- 本地文件访问记录会暴露用户打开过的文件名；若文件名被 base64 编码（如 `SW1wb3J0YW50.rar` → `Important.rar`），解码后即可定位容器文件，再用 `filescan`/`dumpfiles` 提取。
- Chrome 的 History 是 SQLite 数据库，`chromehistory` 从内存缓存中解析 URL/标题/访问时间；下载记录可直接给出网盘链接（mega.nz）与提取码所在页面。
- 浏览历史常与其它线索串联：历史里的 pastebin 页面提示“key 在邮件里”，`filescan | grep mail` 找到 Firefox 缓存，`strings` 搜关键词即得密钥。
- 内存中的浏览器缓存（Firefox cache2 的 `entries`）同样可用 `strings`/`filescan` 定位；不需要磁盘上的浏览器 profile。

## 触发条件

- 已获取 Windows 内存镜像，profile 匹配；
- 目标使用过 IE/资源管理器或 Chrome/Firefox 访问本地文件、网盘、pastebin、邮箱；
- 浏览器进程或系统仍缓存相关记录（未重启/未清理）。

## 利用步骤

1. `imageinfo` → `pslist` 确认浏览器/explorer 进程存在。
2. `iehistory` 浏览 `file:///` 访问记录，对可疑文件名做 base64 解码。
3. `chromehistory` 看 URL/标题/访问时间，提取网盘下载链接与中转页面（pastebin 等）。
4. 对历史中出现的本地路径用 `filescan | grep <名字>` + `dumpfiles -Q <offset>` 提取文件。
5. 历史页面/邮箱里的提示与 `strings` 关键词搜索配合，得到下一层口令或链接。

## PoC

```bash
python2 vol.py -f MemoryDump.raw --profile=Win7SP1x64 iehistory | grep -E "file://|Visited"
# Visited Alissa Simpson@file:///C:/Users/Alissa%20Simpson/Downloads/SW1wb3J0YW50.rar
# → base64 -d: Important.rar
python2 vol.py -f MemoryDump.raw --profile=Win7SP1x64 chromehistory
# 32 https://mega.nz/#!TrgSQTS!H0Z...    ← 下载链接
# 169 https://pastebin.com/RSGSi1nk     ← 中转提示页
```

`iehistory` 还能看到 `Pictures/Password.png`、`C:/Users/SmartNet/Secrets/Hidden.kdbx` 等被打开过的容器，直接指导后续 dump。

## 变体与关联

- 变体：Firefox 用 `cache2/entries` 二进制缓存，`filescan` + `strings`/`dumpfiles` 提取，JSON 片段中可含邮箱密钥。
- 变体：Chrome 下载记录在 History 的 downloads 表，`chromehistory` 未覆盖时可导出 SQLite 文件再查。
- 关联：[[ctf-forensics-memory-base64-prefix-browser-history-flag]]——浏览器历史里的 base64 查询词。
- 关联：[[ctf-forensics-chrome-heap-snapshot-flag-search]]——Chrome 堆快照搜索。
- 关联：[[ctf-forensics-volatility-cmdscan-consoles-command-history]]——同篇的命令历史取证。

## 检测与防御

- 该卡为取证手法；对攻击方，清理浏览器历史并不清除内存中的 index.dat/History 缓存。
- 防御/响应：内存镜像优先；浏览器隐私模式不等于内存无痕；敏感 URL 使用后重启/清理并做内存清洁。
