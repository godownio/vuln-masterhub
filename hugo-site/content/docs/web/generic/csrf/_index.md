---
title: CSRF
weight: 1
---

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
| [CSRF + RPO + CSS 选择器侧信道窃取管理员 Token 与 Flag](web-generic-csrf-rpo-css-selector-side-channel/) | verified | high | 2026-11-04 |
| [CSRF 打本机 rclone RC API：config/create 的 sftp ssh / webdav bearer_token_command 执行命令，配合 sleep 时间盲注外带](web-generic-csrf-rclone-rc-config-create-command-exec/) | verified | high | 2026-11-08 |
| [IceCMS 广场内容删除 CSRF（CVE-2023-42188）：无 CSRF Token 的跨站表单借管理员会话删帖](web-generic-csrf-icecms-square-delete-form/) | verified | high | 2026-11-09 |
| [JSON 接口 CSRF：enctype=text/plain 表单直发 JSON 并利用 Referer 校验失效](web-generic-csrf-json-text-plain-form-enctype/) | verified | high | 2026-11-05 |
| [Stock Management System 1.0 Users.php?f=save/delete 无 CSRF Token：管理员访问恶意页即被增删用户（CVE-2025-4282）](web-generic-csrf-sourcecodester-stock-users-save-delete/) | verified | high | 2026-11-05 |
| [ZrLog 2.1.11 后台 JSON API 全站无 CSRF 校验：text/plain 表单跨站改邮箱（可接管）与改文章内容](web-generic-csrf-zrlog-admin-json-api-text-plain-all-endpoints/) | verified | high | 2026-11-07 |
| [状态变更接口无 CSRF Token：跨站自动提交表单以受害者身份添加/删除数据](web-generic-csrf-missing-token-state-changing-endpoint/) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
