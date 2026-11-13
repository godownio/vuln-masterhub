---
title: 原型链污染
weight: 1
---

# 原型链污染

## 这层是什么

原型链污染的形成、利用与 RCE 链。

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
| [deepMerge 写入原型链既有属性的子键：绕过 __proto__/constructor/prototype 过滤的替代污染路径](web-nodejs-prototype-pollution-inherited-property-subkey/) | verified | high | 2026-11-05 |
| [EJS destructuredLocals 原型污染注入：数组元素拼进模板函数体，闭合赋值语句执行 child_process](web-nodejs-prototype-pollution-ejs-destructuredlocals-rce/) | verified | high | 2026-11-12 |
| [EJS localsName 原型污染注入：with 条件表达式与 Function 形参双处拼接入模板代码](web-nodejs-prototype-pollution-ejs-localsname-with-rce/) | verified | high | 2026-11-12 |
| [EJS outputFunctionName 原型污染注入：拼接进模板函数体，语句逃逸执行 child_process](web-nodejs-prototype-pollution-ejs-outputfunctionname-rce/) | verified | high | 2026-11-11 |
| [hogan.js 原型链污染 RCE：污染 Object.prototype.delimiters 控制扫描分隔符、污染 indent 注入生成代码，键名尾随空格绕过 UNSAFE_KEYS 的 trim 检查](web-nodejs-prototype-pollution-hogan-delimiters-indent-rce/) | verified | high | 2026-11-11 |
| [Jade 模板原型污染 RCE：污染 Object.prototype.self + line，让 Compiler.visit 把调试行号原样拼进 new Function](web-nodejs-prototype-pollution-jade-line-debugitem-rce/) | verified | medium | 2026-11-12 |
| [JSON body 深合并原型链污染注入 Object.prototype.shellcode：后门把 {}.shellcode 交给 vm2 执行，链上 import() 逃逸 RCE](web-nodejs-prototype-pollution-json-clone-vm2-shellcode-backdoor/) | verified | medium | 2026-11-08 |
| [lodash 原型链污染（CVE-2019-10744）+ EJS 3.1.6 escapeFunction 注入 RCE](web-nodejs-prototype-pollution-lodash-ejs-escapefunction-rce/) | verified | high | 2026-11-06 |
| [lodash.template sourceURL 原型污染注入：换行逃出注释行，Function 构造器执行任意代码](web-nodejs-prototype-pollution-lodash-template-sourceurl-rce/) | verified | high | 2026-11-11 |
| [merge 深合并原型链污染：对象字面量与 JSON.parse 的 __proto__ 差异](web-nodejs-prototype-pollution-merge-json-parse/) | verified | high | 2026-11-05 |
| [n8n XML/GSuiteAdmin 节点参数原型污染（CVE-2026-33696）：工作流作者注入 __proto__ 并声称升级 RCE](web-nodejs-prototype-pollution-n8n-node-params-object-assign/) | verified | medium | 2026-11-06 |
| [xml2json 标签名注入 __proto__：KML 解析污染 Object.prototype 并改写未声明全局变量](web-nodejs-prototype-pollution-xml2json-tag-name-proto/) | verified | high | 2026-11-06 |
| [原型污染到 Node 子进程代码执行：污染 NODE_OPTIONS=-r 让 spawn 的 node 预加载文件](web-nodejs-prototype-pollution-node-options-preload-rce/) | verified | medium | 2026-11-06 |
| [原型污染控制未声明标识符，借 Function(query)(query) 执行任意代码](web-nodejs-prototype-pollution-undeclared-identifier-function-rce/) | verified | high | 2026-11-05 |
| [原型链污染污染 JWT 密钥：deepMerge depth 绕过 → 伪造 admin token → 诊断接口执行](web-nodejs-prototype-pollution-deepmerge-depth-jwt-secret/) | verified | high | 2026-11-06 |
| [原型链污染注入 NODE_OPTIONS=-r：node 子进程预加载 /flag，SyntaxError 回显泄露](web-nodejs-prototype-pollution-node-options-require-flag/) | verified | high | 2026-11-06 |
| [原型链污染过滤绕过：constructor.prototype、嵌套键、Unicode 转义与表单解析](web-nodejs-prototype-pollution-filter-bypass/) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
