# 开放重定向

## 这层是什么

重定向绕过与 OAuth/SSO 组合利用。

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
| [Activiti 工作流表单 formKey 未校验：上传 BPMN 控制 formKey 触发 sendRedirect 开放重定向](web-generic-open-redirect-activiti-formkey-sendredirect.md) | verified | high | 2026-11-06 |
| [Shiro 未登录重定向的 Location 取 Host 头：任意 Host 注入导致开放重定向与会话 ID 泄露](web-generic-open-redirect-shiro-login-redirect-host-header.md) | draft | high | 2026-11-05 |
| [WebOb <1.8.11 开放重定向：前导空白 + 协议相对 URL 绕过校验（CVE-2026-54770）](web-generic-open-redirect-webob-whitespace-urljoin-mismatch.md) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
