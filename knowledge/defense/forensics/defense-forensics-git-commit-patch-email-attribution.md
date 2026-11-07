---
id: defense-forensics-git-commit-patch-email-attribution
title: 蓝队溯源：用 commit .patch 的 From 邮箱与公开账号关联定位提交者
type: scenario
domain: defense
path: defense/forensics
technique: git-commit-patch-email-attribution
aliases:
- commit 邮箱溯源
- .patch 提交邮箱
- GitHub 提交者归因
- 蓝队溯源
- Git 元数据 OSINT
- 开发者身份关联
tags:
- forensics
- attribution
- osint
- git
- github
- email
- commit
- blue-team
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V81
  verified_at: '2026-11-05T18:06:23+08:00'
  notes: '已对照原文与 img29-30：在 GitHub commit URL 后加 .patch 得到 From: mhszed <1***683@qq.com>、Date: Wed, 26 Nov 2025 16:37:16 +0800 与 diff；img30 用邮箱/用户名在 Google 搜到 Bugku CTF 账号 147***3。卡片归因方法、置信度与隐私边界说明合理；未实测。'
---

## 一句话结论

在 GitHub/GitLab 的提交链接后加 `.patch` 可直接得到原始邮件头，其中 `From:` 与 `Date:` 暴露提交者姓名、邮箱与时区；把这个邮箱/用户名拿到 Google、GitHub、CTF 平台与论坛做关联搜索，常能定位到同一人的其他账号、项目与活动轨迹，为蓝队溯源提供身份线索。

## 原理

- Git 提交对象保存 author/committer 的姓名、邮箱与时间戳；平台生成的 `.patch` 文件按邮件格式输出，包含 `From: <name> <email>`、`Date:`、`Subject:` 与 diff，信息量比网页提交列表更完整。
- 开发者常用真实邮箱或个人 QQ 邮箱提交；同一邮箱/用户名可能注册过 GitHub、Gitee、CTF 平台（Bugku、CTFHub 等）、论坛、博客、漏洞平台；搜索引擎会索引这些公开资料。
- 结合 GitHub 个人主页的仓库、star、follow、头像、GPG 公钥、组织成员关系，可建立账号之间的关联；头像/昵称/个人简介复用是强关联信号。
- 提交时间与时区可推断所在地/工作时段；多个仓库的提交节奏可区分个人账号与公司账号。
- 归因是概率性的：共享邮箱、CI 机器人、noreply 邮箱、他人代提交都会造成误判，需要多源交叉验证，不能仅凭一个邮箱下结论。
- 该方法既可用于蓝队追踪攻击者/内部泄露者，也可用于红队识别目标开发者身份，但必须遵守隐私与授权边界。

## 触发条件

- 目标仓库/提交在公开平台可访问，且允许查看 `.patch`/raw 内容。
- 提交使用了可识别的邮箱或用户名（非 `users.noreply.github.com` 等匿名地址）。
- 能在搜索引擎/公开平台检索该邮箱或用户名。
- 处于授权溯源/取证范围，收集与使用个人信息符合当地法律。

## 利用步骤

1. 打开目标 commit 页面，记录仓库、commit SHA、作者显示名与时间。
2. 在 commit URL 后追加 `.patch`（GitHub）或使用平台的 raw/patch 接口，保存原始内容。
3. 解析邮件头：`From:`（姓名+邮箱）、`Date:`（含时区）、`Subject:`；对比 author 与 committer 是否不同（可能涉及代提交/CI）。
4. 用完整邮箱、邮箱前缀、用户名分别搜索 Google/Bing/GitHub/Gitee/CTF 平台/论坛；记录命中页面的账号、头像、简介、所在地与活动时间。
5. 在 GitHub 搜索该邮箱/用户名对应的其他仓库、GPG key、组织成员关系与 commit 历史；检查是否有个人博客、社交媒体链接。
6. 交叉验证：多个独立来源（邮箱→CTF 账号→同一头像/用户名→同一地区）同时指向同一身份时才提高置信度；记录证据链与不确定性。
7. 如需进一步取证，保存网页快照、提交哈希、patch 原文与搜索时间，确保证据可复现。

## PoC

```bash
# 1) 获取原始 patch（GitHub）
curl -sL https://github.com/<org>/<repo>/commit/<sha>.patch -o commit.patch

# 2) 提取邮件头
sed -n '1,10p' commit.patch
# From: <name> <email@example.com>
# Date: Wed, 26 Nov 2025 16:37:16 +0800
# Subject: [PATCH] ...
```

```text
# 3) 关联搜索（浏览器/搜索引擎）
"<email@example.com>"
"<email-local-part>"
"<username>" site:github.com
"<username>" site:ctf.bugku.com
"<username>" site:gitee.com
```

```bash
# 4) 检查同一邮箱在 Git 历史中的其他提交
git log --all --format='%h %an <%ae> %ad' | grep -i '<email@example.com>'
```

## 变体与关联

- 变体：GitLab 的 `/-/commit/<sha>.patch`、Gitea 的 `.patch`、`git format-patch` 导出的邮件；不同平台的邮件头字段可能略有差异。
- 变体：`git log --format='%an %ae %cn %ce %ad'` 批量导出作者/提交者；`.mailmap` 可合并同一人的多个身份。
- 变体：签名提交（GPG/SSH）可提供公钥指纹，进一步关联密钥服务器与 GitHub GPG 页面；noreply 邮箱会阻断邮箱搜索，但仍可通过用户名/头像关联。
- 关联：[[pentest-recon-github-repo-history-secret-mining]]（同一仓库的凭据挖掘）、[[defense-forensics-multisource-timeline-log-clear]]（多源时间线重建）、[[pentest-recon-git-config-remote-credentials]]（仓库配置中的身份信息）。
- 边界：提交者使用匿名 noreply 邮箱、共享账号、公司统一邮箱或由 CI 机器人提交时，邮箱无法指向个人；同名/同头像可能是巧合；归因结论应标注置信度，不能作为唯一证据。

## 检测与防御

- **开发者侧**：使用平台提供的 noreply 邮箱提交，避免在 commit 中暴露个人邮箱；个人与工作账号分离；不跨平台复用头像/用户名/简介。
- **组织侧**：统一使用公司邮箱与机器人账号提交，配置 `.mailmap` 与提交规范；对外仓库审查作者信息。
- **蓝队取证**：把 commit 元数据（SHA、作者、邮箱、时间、时区、签名）纳入证据清单，与登录日志、代码仓库审计、邮件网关日志交叉验证；注意保存原始 patch 与网页快照。
- **合规**：只收集公开信息，不进行人肉搜索、骚扰或超出授权范围的个人数据聚合；涉及个人信息时遵守当地法律与组织政策。

