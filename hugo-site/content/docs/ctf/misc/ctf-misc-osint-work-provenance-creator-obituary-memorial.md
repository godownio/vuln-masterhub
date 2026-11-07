---
id: ctf-misc-osint-work-provenance-creator-obituary-memorial
title: OSINT 作品溯源：从音乐/影视数据库到创作者讣告与纪念页
type: scenario
domain: ctf
path: ctf/misc
technique: osint-work-provenance-creator-obituary-memorial
tags:
- ctf
- misc
- osint
- provenance
- musicbrainz
- wikipedia
- obituary
- memorial
- cross-validation
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V194
  verified_at: '2026-11-06T22:51:07+08:00'
  notes: 已对照原文 Challenge 3-5 核对：视频 ID/上传日期/uploader、官方购买页/sender/creation year、MusicBrainz→讣告→Find A Grave 的跨源验证路径与原文一致；卡片为去标识化方法卡，未写入个人隐私字段，未复跑 OSINT。
url: /docs/ctf/misc/ctf-misc-osint-work-provenance-creator-obituary-memorial/
draft: false
kb_aliases:
- Wanna Feel Love
- I Feel Fantastic OSINT
- 数字墓碑
- creation year vs upload year
- Find A Grave
- MusicBrainz 溯源
- 作品创作者身份核验
---

## 一句话结论

当题目要求还原一个作品（视频/音乐/影片）的原始出处、创作者、购买链接或“数字墓碑”时，可以按“作品名 → 官方站点/百科 → 音乐/影视数据库 → 讣告 → 纪念页”的顺序做跨源 OSINT：先用作品数据库拿到创作者与年份，再用死亡日期/地区定位讣告，最后在 Find A Grave 一类纪念站找到与姓名、生卒、墓地一致的条目，并交叉验证身份。

## 原理

- **作品有多个公开标识维度**：标题、创作者、发行年份、时长、发行载体（DVD/专辑）、官方销售页、数据库条目（Wikipedia、MusicBrainz、Letterboxd、Discogs 等）。单一条目可能写错年份或混淆同名作品，多个独立来源一致才算稳定结论。
- **官方站点给出“交易信息”**：作品的官方/爱好者站点通常有产品页，列出价格、邮寄方式、联系邮箱/联系人。题目问“sender”时，指的是实际寄件/运营站点的人或机构，不一定是创作者本人；这是一类常见陷阱。
- **数据库给出“作品年份”**：音乐数据库与影视数据库通常以首发/发行年标注作品；但“发行年”“上传年”“创作年”可能不同。若题目问 actual creation year，需要找更接近创作现场的证据（DVD 文件元数据、实物版权年份、作者购买记录、多个数据库一致的首发年），而不是 YouTube 上传时间。
- **讣告是身份锚点**：拿到创作者全名、死亡日期、死亡地点后，搜索本地报纸/族谱/讣告数据库，可得到完整姓名、生卒、家属、工作经历、安葬地；这些字段比同名搜索可靠。
- **纪念页是“数字墓碑”**：Find A Grave 一类站点把姓名、出生/死亡日期、墓地、家属链接结构化展示；当它与讣告、音乐数据库的姓名/日期/地点一致时，可确认是同一个人。题目中的 “digital grave / quiet memorial / obituary” 就是在暗示这类页面，而不是普通博客或新闻。
- **为什么成立**：这些都是公开信息，OSINT 的价值在于“从弱标识（作品名/昵称）出发，沿公开链接逐跳扩大，并用多个独立来源交叉验证”，而不是依赖某个单点。

## 触发条件

- CTF OSINT 题给出作品名、角色名、创作者昵称、视频标题或一段作品描述。
- 作品在公开互联网上有百科、音乐/影视数据库、官方站点或存档记录。
- 题目要求 video ID/upload date/uploader、purchase link/sender/creation year、或“digital grave”URL 等字段。
- 允许联网检索，且目标信息是公开的（已故公众人物/作品元数据）。

## 利用步骤

1. **锁定作品**：用题面关键词（作品名、角色名、台词、时长、载体）搜索，确认唯一作品；记录候选的百科页、官方站点、数据库条目。
2. **查官方/销售页**：从百科外链或站点导航进入产品页，记录购买链接、价格、联系邮箱/联系人/公司名；区分“创作者”与“站点运营/寄件人”。
3. **查作品年份**：在 MusicBrainz、Discogs、Letterboxd、Wikipedia 等交叉核对发行年/创作年；若题目强调 actual creation，优先找一手证据（实物版权、文件元数据、购买者记录），并明确区分 upload year / release year / creation year。
4. **查创作者身份**：从作品署名拿到全名/别名；在音乐/影视数据库确认职业、作品列表、生卒信息。
5. **查讣告**：用 `"<full name>" "<city>" <birth year> <death year> obituary` 等组合搜索；核对死亡日期、地点、家属、工作经历。
6. **查纪念页**：用 `"<full name>" <birth>-<death> <cemetery> site:findagrave.com`（或 BillionGraves 等）定位条目；核对姓名、出生/死亡日期、墓地、家属链接。
7. **交叉验证**：至少让“作品数据库的创作者/年份”“讣告的姓名/日期/地点”“纪念页的姓名/生卒/墓地”三方一致；若冲突，优先一手源并记录差异。
8. **按题目格式提交**：URL 是否需要去掉结尾斜杠、日期格式 `YYYY-MM-DD`、sender 写人名还是机构、creation year 写四位年份。

## PoC

无代码，核心检索式：

```text
"<work title>" original upload
"<work title>" "<creator name>" year
"<creator name>" "<work title>" site:musicbrainz.org
"<full name>" "<city>" <birth year> <death year> obituary
"<full name>" <birth>-<death> "<cemetery>" site:findagrave.com
```

原文案例的验证路径（去标识化）：

```text
作品名/角色名
  -> 百科条目：确认创作者、发行载体、时长
  -> 官方站点产品页：确认购买链接与站点联系人（sender 不是创作者）
  -> MusicBrainz/影视数据库：确认发行/创作年份
  -> 创作者全名 + 死亡日期/地区
  -> 本地讣告：确认姓名、生卒、家属、安葬地
  -> Find A Grave：姓名/生卒/墓地/家属链接一致，得到“数字墓碑”URL
```

原文通过该路径完成了视频 ID/上传日期/上传者、购买链接/发件人/创作年份、以及创作者纪念页 URL 三组问题；PoC 为手动 OSINT，未在本机复跑。

## 变体与关联

- **视频溯源**：YouTube 原视频被删除时，用 Internet Archive/Wayback、维基引用、论坛考据帖交叉确认 video ID、upload date、uploader；注意转载与原始上传的区别。
- **作品年份陷阱**：upload year ≠ release year ≠ creation year；音乐/影视数据库、实物版权、文件 EXIF/元数据可能给出不同年份。
- **身份陷阱**：同名人物、化名、家属代发；用死亡日期 + 地点 + 家属姓名三要素消歧。
- **纪念页变体**：Find A Grave、BillionGraves、地方殡仪馆讣告、族谱网站；题目中的 “digital grave”“memorial”“obituary” 是关键词。
- **关联**：[[ctf-misc-osint-cross-platform-username-steam-former-name]]（跨平台用户名关联）、[[ctf-misc-osint-silk-road-first-forum-post-member-id]]（历史论坛帖定位）。
- **边界**：若作品/创作者信息被删除且无存档、题目指向在世普通人、或目标站点禁止抓取，OSINT 链可能中断；不要对在世个人做超出题目范围的隐私挖掘。

## 检测与防御

- **CTF 识别**：题目出现作品名、角色名、“original”“first”“creator”“obituary”“digital grave”等词，优先按“作品→数据库→讣告→纪念页”顺序检索，而不是直接搜 flag。
- **取证/核验**：记录每个结论的来源、检索式与时间；至少两个独立来源一致才写入答案；区分事实、二手考据与都市传说。
- **隐私与伦理**：只针对题目给定的已故公众人物/作品元数据；不要扩散在世个人的住址、联系方式等敏感信息；引用公开页面时保留原始 URL 供核验（卡内不记录个人数据）。
- **防御（真实系统）**：组织应意识到作品署名、官方站点联系人、数据库条目会形成可关联的开源情报；对敏感项目避免把创作者真实身份与作品/销售页强绑定，定期清理过时公开信息。
- **出题思路**：用“作品名/角色名”作为弱标识，设置 upload vs creation、creator vs sender、blog vs memorial 三类陷阱，要求选手跨源验证。
