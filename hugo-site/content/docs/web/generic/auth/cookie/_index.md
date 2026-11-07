---
title: Cookie 与会话
weight: 1
---

# Cookie 与会话

## 这层是什么

Cookie 解析、身份伪造、会话固定与签名缺失。

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
| [Base64 Cookie 身份伪造导致未授权文件上传](web-generic-auth-cookie-base64-identity-forgery/) | draft | high | 2026-11-04 |
| [Cartalyst Sentinel 原生 Cookie json_decode 类型失控叠加 MySQL 隐式转换绕过认证](web-generic-auth-sentinel-cookie-jsondecode-mysql-auth-bypass/) | verified | high | 2026-11-05 |
| [MyBlog 硬编码 AES 盐值记住我 Cookie 伪造接管后台](web-generic-auth-myblog-hardcoded-aes-cookie-forgery/) | verified | high | 2026-11-05 |
| [加密 Cookie 的 CBC 位翻转：改 IV 控制首块明文，role=guest 伪造为 role=admin](web-generic-auth-cookie-cbc-bitflip-iv-first-block-role-forgery/) | verified | high | 2026-11-06 |
| [后台登录仅凭 cookieUsername 明文 Cookie，拼接他站成功响应绕过登录](web-generic-auth-cookie-login-response-splice-username-cookie/) | verified | medium | 2026-11-05 |
| [硬编码 DES 密钥与弱结构校验导致 ERP 会话伪造](web-generic-auth-hardcoded-des-session-forgery/) | verified | high | 2026-11-04 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
