---
title: Python SSTI
weight: 1
---

# Python SSTI

## 这层是什么

Jinja2、Mako、Tornado 模板注入。

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
| [Bottle SimpleTemplate SSTI：全角/斜体 Unicode、八进制转义与海象运算符绕过 WAF](web-python-ssti-bottle-unicode-octal-walrus-bypass/) | verified | high | 2026-11-04 |
| [Django 模板字符串拼接用户名导致 SSTI 泄露账号密码](web-python-ssti-django-username-template-source-credential-leak/) | verified | high | 2026-11-05 |
| [FastAPI/Jinja2 SSTI：字符黑名单在 unquote 前检查，全量 URL 编码绕过并执行 os.popen](web-python-ssti-filter-before-unquote-full-urlencode/) | verified | high | 2026-11-06 |
| [Flask SSTI 黑名单/47 字符绕过：app.jinja_env.globals 的 sget/sset 分段拼出 __globals__ 与 read](web-python-ssti-jinja-custom-globals-session-payload-assembly/) | verified | high | 2026-11-07 |
| [Flask 会话密钥泄露伪造 admin + Jinja2 相邻字符串字面量拼接绕过 SSTI 黑名单](web-python-ssti-jinja2-adjacent-literal-flask-session-forge/) | verified | medium | 2026-11-06 |
| [Jinja2 SSTI WAF 绕过：\x5f 十六进制下划线、attr 过滤器与 request.args 参数拆分](web-python-ssti-jinja2-waf-bypass-hex-attr-args/) | verified | high | 2026-11-05 |
| [Jinja2 SSTI 全局链不可用时枚举 object 子类索引定位 Popen/os._wrap_close](web-python-ssti-jinja2-subclasses-index-rce/) | verified | high | 2026-11-05 |
| [Jinja2 SSTI 只过滤 flag 关键词：子类索引取 chr 拼接键名读取 doc['flag']](web-python-ssti-jinja2-flag-keyword-chr-subclass-index-bypass/) | verified | high | 2026-11-06 |
| [Jinja2 SSTI 直接读取模板上下文：doc.get + __builtins__['chr'] 拼接 flag 绕过关键词过滤](web-python-ssti-jinja2-context-doc-get-chr-keyword-bypass/) | verified | high | 2026-11-06 |
| [Jinja2 SSTI 长度分流 WAF 绕过：填充表达式到 514 并拆分黑名单](web-python-ssti-length-gated-waf-filler-blacklist-split/) | verified | high | 2026-11-06 |
| [Jinja2 SSTI 黑名单绕过：dict(...)|join 动态拼关键字 + lipsum split 取单字符 + attr 调用 os.popen](web-python-ssti-jinja2-dict-join-keyword-construction/) | verified | high | 2026-11-06 |
| [Jinja2 |attr 过滤器绕过沙箱属性访问控制（CVE-2025-27516）：原生 str.format 属性遍历读取 __globals__](web-python-ssti-jinja2-attr-filter-format-sandbox-escape/) | verified | medium | 2026-11-06 |
| [Jinja2 布尔报错盲注：1/(条件) 以 500/200 状态码逐字符提取数据](web-python-ssti-jinja2-boolean-error-blind/) | verified | high | 2026-11-05 |
| [Jinja2/Flask SSTI：从暴露的全局对象经 __globals__ 直达 os.popen](web-python-ssti-jinja2-flask-globals-rce/) | verified | high | 2026-11-05 |
| [Mako SSTI：${} 与 <% context.write %> 代码块执行及 getattr 绕过过滤](web-python-ssti-mako-context-write-getattr-bypass/) | verified | high | 2026-11-04 |
| [Mako 模板识别后用 getattr/__getitem__ 绕过点号与括号过滤做布尔盲注读文件](web-python-ssti-mako-percent-control-getattr-getitem-blind/) | verified | high | 2026-11-06 |
| [Python 表达式 SSTI 黑名单绕过：getattr+chr 拼接 __class__/__globals__/__builtins__，AST 自动生成 payload](web-python-ssti-getattr-chr-blacklist-bypass/) | verified | high | 2026-11-06 |
| [RAGFlow canvas 组件 Jinja2 SSTI：StringTransform/Message 渲染用户脚本到 root RCE（CVE-2026-28797）](web-python-ssti-ragflow-canvas-component-jinja2-rce/) | verified | high | 2026-11-05 |
| [数据集配置字段 Jinja2 模板求值：fsspec reference:// offset 注入导致 AI 平台生产 Worker RCE](web-python-ssti-huggingface-dataset-config-jinja2-offset-rce/) | verified | high | 2026-11-05 |
| [模型端口劫持 SSRF 打 Redis + prompt 缓存投毒：str.format 求值 __globals__ 读取 FLAG](web-python-ssti-redis-prompt-cache-poison-format-globals/) | verified | high | 2026-11-06 |
| [模板 include_prompt 未隔离内部片段：直接 include review_gate 读取隐藏 flag](web-python-ssti-internal-snippet-include-prompt-access/) | verified | medium | 2026-11-06 |
| [污染 jinja2.runtime.exported 向生成的模板源码注入任意 Python 语句](web-python-ssti-jinja2-runtime-exported-pollution/) | verified | medium | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
