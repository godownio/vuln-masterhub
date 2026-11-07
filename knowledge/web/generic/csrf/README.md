# CSRF

## 这层是什么

CSRF 与 SameSite、Token 绕过。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [CSRF + RPO + CSS 选择器侧信道窃取管理员 Token 与 Flag](web-generic-csrf-rpo-css-selector-side-channel.md) | verified | high | 2026-11-04 |
| [JSON 接口 CSRF：enctype=text/plain 表单直发 JSON 并利用 Referer 校验失效](web-generic-csrf-json-text-plain-form-enctype.md) | verified | high | 2026-11-05 |
| [Stock Management System 1.0 Users.php?f=save/delete 无 CSRF Token：管理员访问恶意页即被增删用户（CVE-2025-4282）](web-generic-csrf-sourcecodester-stock-users-save-delete.md) | verified | high | 2026-11-05 |
| [状态变更接口无 CSRF Token：跨站自动提交表单以受害者身份添加/删除数据](web-generic-csrf-missing-token-state-changing-endpoint.md) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
