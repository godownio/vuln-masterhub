---
title: 通用模板注入
weight: 1
---

# 通用模板注入

## 这层是什么

模板引擎识别、探测与利用。

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
| [BootDo 工作流待办消息存储后经 VelocityUtils.RenderData 求值：二阶 Velocity 模板注入 RCE](web-generic-ssti-bootdo-velocity-todomessage/) | verified | high | 2026-11-05 |
| [FastCMS 0.1.5 后台模板编辑 FreeMarker 注入：?new Execute 直接命令执行](web-generic-ssti-fastcms-template-edit-freemarker-rce/) | verified | high | 2026-11-05 |
| [FreeMarker SAFER_RESOLVER 绕过：第三方 TemplateModel、静态块、ProtectionDomain 与 ?api](web-generic-ssti-freemarker-safer-resolver-bypass/) | verified | high | 2026-11-05 |
| [FreeMarker SSTI 下用 object.class.getResourceAsStream 逐字节读取 classpath 配置](web-generic-ssti-freemarker-classpath-resource-read/) | verified | high | 2026-11-05 |
| [FuelCMS Dwoo 安全策略空实现：Closure::fromCallable 链式调用绕过沙箱执行命令](web-generic-ssti-dwoo-security-policy-empty-rce/) | verified | high | 2026-11-05 |
| [Ruby ERB 模板注入：%x{} 直接执行系统命令读 flag](web-generic-ssti-ruby-erb-percent-x-command-exec/) | verified | high | 2026-11-06 |
| [Smarty SSTI：默认非沙箱直接 RCE 与 Smarty 4/5 严格模式静态方法绕过](web-generic-ssti-smarty-direct-rce-v4-v5-bypass/) | verified | high | 2026-11-04 |
| [SSTI WAF 关键字拆分绕过：字符串拼接 + __eq__ 取 globals + os.popen 读文件](web-generic-ssti-waf-string-concat-eq-globals-bypass/) | verified | high | 2026-11-06 |
| [SSTI 报错回显外带：把命令输出作为非法参数由异常消息吐出](web-generic-ssti-error-message-exfiltration/) | verified | high | 2026-11-05 |
| [SSTI 模板引擎识别：决策树探测与报错特征对照](web-generic-ssti-engine-identification-decision-tree-errors/) | verified | high | 2026-11-04 |
| [Thymeleaf SSTI WAF 绕过：getClass().forName 反射 + 字符串拼接读取任意文件](web-generic-ssti-thymeleaf-reflection-files-read-waf-bypass/) | verified | medium | 2026-11-06 |
| [Twig SSTI：filter/map/reduce/sort 过滤器回调 system 实现命令执行与写文件](web-generic-ssti-twig-filter-map-reduce-callback-rce/) | verified | medium | 2026-11-04 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
