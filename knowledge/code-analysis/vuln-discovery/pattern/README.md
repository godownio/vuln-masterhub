# 漏洞模式

## 这层是什么

常见漏洞模式与代码特征。

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
| [FFM MemorySegment 裸指针被 native 滞留导致 Arena 关闭后悬挂读写](code-analysis-vuln-discovery-ffm-native-pointer-retention.md) | verified | high | 2026-11-05 |
| [Python 安全规则列表漏逗号导致隐式字符串拼接](code-analysis-vuln-discovery-python-adjacent-string-concat.md) | verified | high | 2026-11-04 |
| [Ruby 不安全递归合并导致类污染：经 class→superclass→subclasses 穿越改写任意类的实例变量](code-analysis-vuln-discovery-ruby-recursive-merge-class-pollution.md) | verified | medium | 2026-11-08 |
| [同产品两份后缀策略并存：从「弱的那一份被实际调用」找上传绕过入口](code-analysis-vuln-discovery-duplicate-extension-policy-divergence.md) | verified | high | 2026-11-08 |
| [存储抽象层边界审计：校验调用点、条件化 sanitize 与可热写安全配置](code-analysis-vuln-discovery-storage-boundary-audit-pattern.md) | verified | high | 2026-11-05 |
| [空集合上的真空授权：循环体检查、短路与 every 恒真的审计模式](code-analysis-vuln-discovery-vacuous-authorization-empty-collection.md) | verified | high | 2026-11-05 |
| [跨语言解压 API 默认不安全清单：Zip Slip sink 识别与穿越条目构造](code-analysis-vuln-discovery-default-insecure-archive-extract-api.md) | verified | high | 2026-11-07 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
