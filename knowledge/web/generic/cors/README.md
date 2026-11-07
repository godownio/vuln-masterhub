# CORS

## 这层是什么

跨域配置错误与凭证泄露。

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
| [MLflow ≤ 3.4.0 DNS Rebinding：REST Server 缺 Host/Origin 校验，恶意网页同源调用本地 API 读写实验数据（CVE-2025-14279）](web-generic-cors-mlflow-dns-rebinding-missing-host-validation.md) | verified | medium | 2026-11-06 |
| [Ollama OLLAMA_ORIGINS 桌面协议通配符：受信来源页面跨域调用本地 API](web-generic-cors-ollama-desktop-origin-wildcard-csrf.md) | verified | medium | 2026-11-05 |
| [OPTIONS 预检鉴权缺失导致对象/方法/请求头枚举](web-generic-cors-options-preflight-authz-oracle.md) | verified | high | 2026-11-04 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
