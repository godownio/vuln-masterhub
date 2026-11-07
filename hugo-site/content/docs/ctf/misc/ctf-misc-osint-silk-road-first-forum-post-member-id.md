---
id: ctf-misc-osint-silk-road-first-forum-post-member-id
title: OSINT 历史论坛帖子定位：Silk Road 首次公开宣传帖 + 成员 ID + ROT13/Base64/SHA256 编码链
type: scenario
domain: ctf
path: ctf/misc
technique: osint-historical-forum-post-member-id-encoding-chain
tags:
- ctf
- misc
- osint
- forum
- historical-research
- member-id
- rot13
- base64
- sha256
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V180
  verified_at: '2026-11-06T17:19:25+08:00'
  notes: '已对照原文与图04/06核对：Shroomery 帖子 #13860995、altoid Member # 243390、onion 地址、ROT13->Base64->SHA256 均一致；未在本机复跑'
url: /docs/ctf/misc/ctf-misc-osint-silk-road-first-forum-post-member-id/
draft: false
kb_aliases:
- Ancient Routes
- Silk Road 论坛帖
- Shroomery altoid
- Member
- 历史帖子 OSINT
- ROT13 Base64 SHA256
---

## 一句话结论

题目用“古老贸易路线 / 最大地下市场”隐喻指向暗网市场 Silk Road，要求找到它第一次被公开宣传的论坛帖子；通过关键词检索定位到 Shroomery.org 2011-01-27 由 `altoid` 发布的帖子，按题目要求取用户 Profile 的 Member ID `243390`，再把 `用户名_成员ID_onion地址` 依次 ROT13→Base64→SHA256 即得 flag。

## 原理

- **隐喻到实体**：题干“古老贸易路线”=Silk Road（丝绸之路），“历史上最大的地下市场之一”=同名暗网市场 Silk Road；两者叠加把搜索目标锁定为该暗网市场的早期公开宣传。
- **历史帖子检索**：用 `Silk Road first forum post`、`Silk Road first public mention` 等关键词搜索，公开资料普遍引用 Shroomery.org 论坛 2011-01-27 用户 `altoid` 的帖子 `anonymous market online?`（帖子 ID #13860995），正文给出 `silikroad420.wordpress.com` 与 Tor 地址 `http://tydgccykixpbu6uz.onion`。
- **成员 ID 而非帖子 ID**：题目明确 “Use the member ID exactly as it appears on the site (profile URL or user page)”；必须打开用户 Profile，读取 `Member #`（示例 243390），不能使用帖子 ID 或用户名数字后缀。
- **编码链**：把 `altoid_243390_http://tydgccykixpbu6uz.onion` 作为原始串，先 ROT13（字母位移 13），再 Base64 编码，最后 SHA256 取十六进制，套上 flag 格式。
- **为什么成立**：OSINT 题的可验证性来自公开存档（论坛帖子、用户资料、搜索引擎快照）；编码链只是把“事实三元组”转成固定长度输出，顺序/字段名由题目描述确定，错一个字段就得不到正确哈希。
- **可复用方法**：先做语义联想找实体，再用“首次/最早/原始”关键词找历史帖子，最后按题目指定字段从个人资料页取精确 ID，而不是帖子/内容 ID。

## 触发条件

- CTF OSINT 题给出历史/文化隐喻，指向某个公开事件、论坛帖子、人物或网站。
- 目标信息在公开网页/存档/搜索引擎中可检索。
- 题目明确要求某个字段（成员 ID、用户名、帖子时间、URL）并给出编码链/哈希格式。
- 允许联网检索与访问公开资料。

## 利用步骤

1. 解析题干隐喻，列出候选实体（Silk Road 既是贸易路线也是暗网市场）。
2. 用“实体 + first/earliest/original + forum post/mention”组合检索，交叉验证多个来源引用的同一帖子。
3. 打开帖子页面，记录作者、发帖时间、帖子 ID、正文中的 URL；确认它确实是“首次公开宣传”。
4. 打开作者 Profile/用户页，读取题目要求的字段（Member #），不要误用帖子 ID。
5. 按题目顺序拼接字段（示例 `用户名_成员ID_onion地址`），执行 ROT13 → Base64 → SHA256。
6. 套 flag 格式提交；若哈希不符，检查字段大小写、URL 是否含 `http://`、成员 ID 是否含前导零。

## PoC

```python
import codecs
import base64
import hashlib

s = "altoid_243390_http://tydgccykixpbu6uz.onion"

rot13 = codecs.encode(s, 'rot_13')
b64 = base64.b64encode(rot13.encode()).decode()
sha256 = hashlib.sha256(b64.encode()).hexdigest()
print("Vianu_CTF{" + sha256 + "}")
```

输出：

```text
Vianu_CTF{dd951c9000a8f8d90d1afcb7d1b31049f161e53b3d3547114319b2cb6cbf52fe}
```

原文还强调：帖子/用户资料中的地址为 `http://tydgccykixpbu6uz.onion`，Profile 显示 Member # 243390、注册时间 01/27/11；PoC 未在本机复跑。

## 变体与关联

- 检索目标变体：首次提及某工具/漏洞/市场的帖子、创始人账号、早期镜像、论坛存档（Archive.org/Reddit/Shroomery）。
- 字段变体：Member ID、User ID、Join Date、Post ID、Profile URL；必须按题目措辞取精确字段。
- 编码链变体：ROT13/Base64/Hex/SHA256/MD5 的任意组合；注意编码顺序与分隔符。
- 关联：[[ctf-misc-osint-cross-platform-username-steam-former-name]]（跨平台用户名关联）、[[ctf-misc-repeated-text-fragment-reverse]]（编码链）。
- 边界：帖子被删除/存档缺失、搜索引擎结果变化、题目字段定义歧义时，需要多源交叉验证。

## 检测与防御

- 检测：CTF 中出现历史/文化隐喻、要求“首次公开提及”的帖子/账号；答案通常是固定哈希。
- 防御：真实场景中历史公开信息难以撤回，个人/组织应避免在公开论坛使用可关联身份；敏感信息不要依赖“删除”来保密。
- 加固：OSINT 防御包括账号隔离、旧帖清理、元数据最小化、定期搜索自己的暴露面。
