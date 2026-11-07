---
id: code-analysis-sast-phply-neo4j-php-callchain-sink-query
title: phply + Neo4j 构建 PHP 调用图：PHP7→5 语法降级、命名空间消解与 Controller→危险函数链查询
type: scenario
domain: code-analysis
path: code-analysis/static/sast
technique: phply-neo4j-php-callgraph-sink-query
aliases:
- phply 调用链分析
- PHP 调用图审计
- Neo4j PHP 调用链
- PHP AST source sink 查询
- 自建 PHP 代码属性图
tags:
- phply
- neo4j
- cypher
- apoc
- callgraph
- sast
- php
- code-audit
- ast
cve: []
severity: low
confidence: medium
status: draft
created: '2026-11-07'
updated: '2026-11-07'
---

## 一句话结论

用 phply 把 PHP 源码解析成 AST，先以正则把 PHP7 语法降级成 phply 能吃的 PHP5 形态，再提取函数定义/调用并消解命名空间，导入 Neo4j 后以 Controller 为 source、危险函数为 sink，用 `apoc.algo.allSimplePaths` 批量导出候选调用链，把 PHP 项目的人工翻代码变成可排序、可导出的链路清单。

## 原理

- phply 的解析器长期未跟进，只认 PHP5 语法：PHP7 的返回类型声明（`function f(): void|int|...`）、`??`、`goto`、`public const`、无花括号的 return type 写法等都会直接抛 `SyntaxError`。脚本先用正则做“语法降级”（删返回类型、注释掉 goto 与标签、去掉 const 修饰、替换 `??` 等），再交给 `make_parser()` 解析，这是能解析现代 PHP 代码的前提。
- AST 遍历时维护 `namespace` 与 `class` 上下文：遇到 `Namespace` 节点更新当前命名空间，遇到 `Class` 节点记录类名，遇到函数定义记录 `(name, namespace, class)`，遇到 `FunctionCall`/`StaticMethodCall`/`New` 等节点提取被调方名字，先落成 `(caller, callee, "CALLS")` 候选三元组。
- PHP 调用点通常只写短名（`file_get_contents`、`hasPermission`），必须做绑定：对每条调用，在已收集的函数定义中找同名且 namespace/class 与调用点上下文匹配的定义，命中才生成 `CALLS` 边；项目内找不到定义的内置函数保留为 `class="Php"` 的节点，正好作为 sink。脚本还通过两两比较调用记录，把一方的 namespace 字符串并入另一方，解决定义侧与调用侧命名空间写法不一致的问题。
- 图落地后，source 取类名含 `Controller` 且非 `__construct` 的函数，sink 取 `name in vul_list AND class="Php"` 的函数，用 `apoc.algo.allSimplePaths(source, sink, "CALLS>", 6)` 求最大深度 6 的简单路径，`LIMIT` 控制规模，结果按 `函数(类) (CALLS) 函数(类)` 拼接、去重后写 xlsx。
- 本质是“调用可达性”而非污点分析：只证明入口函数能调到危险函数，不证明参数可控、也不判断路径上的过滤与鉴权，所以结果必须人工复核。

## 触发条件

- 目标为 PHP Web 项目，具备完整源码目录，入口类命名可识别（如类名含 `Controller`）。
- 本机具备 Python 3 + phply；Neo4j 5.x 与同版本 APOC 插件（示例为 5.20.0），使用 `neo4j-admin` 离线导入时数据库必须处于停止状态。
- phply 只认 PHP5 语法，PHP7/8 项目必须先降级，否则大量文件解析失败；脚本用 config 中的 `error_line` 记录并跳过解析失败文件。
- 仅适用于静态候选挖掘，最终可利用性需要人工确认参数来源与过滤条件。

## 利用步骤

1. 配置 `config.yaml`：待扫描根目录 `parse_multiple_files_path`、需要跳过的报错文件行号 `error_line`、`neo4j_user`/`neo4j_password`；Neo4j 侧放开 `dbms.security.procedures.unrestricted=jwt.security.*,apoc.*,tabby.*`，并在 `apoc.conf` 设 `apoc.import.file.enabled=true`、`apoc.import.file.use_neo4j_config=false`。
2. 运行分析脚本：`os.walk` 收集 `.php`，逐个 `parse_php_file`；解析前先执行 `convert_php7_to_php5` 正则降级，捕获 `SyntaxError` 打印 `msg/lineno/offset` 并跳过该文件。
3. 遍历 AST 收集函数定义与调用，按 namespace/class 将短名调用绑定到定义；内置函数保留 `class="Php"`。
4. 导出 `functions.csv` 与 `function_calls.csv`，停库后执行离线导入：
   `neo4j-admin database import full neo4j --overwrite-destination --verbose --nodes=functions.csv --relationships=function_calls.csv`；导入成功后再启动 `neo4j console`。
5. 修改 `search_vul` 中的 `vul_list` 与 Cypher（source 为 Controller、sink 为危险函数），执行查询，把返回 path 的节点/关系按顺序拼成调用链字符串，去重后写入 xlsx。
6. 人工按“链越短优先级越高”核验：Controller 入参是否能到达 sink 参数、路径上是否有鉴权/白名单/类型转换。

## PoC

查询骨架（`vul_list` 可按漏洞类型替换）：

```cypher
// vul_list 示例：simplexml_load, include, require, phpinfo, call_user_func,
// file_get_contents, fopen, readfile, file_put_contents, curl_exec, unserialize
MATCH (source:Function)
WHERE source.class CONTAINS "Controller" AND source.name <> "__construct"
MATCH (sink:Function)
WHERE sink.name IN $vul_list AND sink.class = "Php"
CALL apoc.algo.allSimplePaths(source, sink, "CALLS>", 6) YIELD path
RETURN path
LIMIT 5000
```

最小 AST 提取骨架（降级 + 解析 + 调用三元组）：

```python
import re
from phply import phplex, phpparse

def downgrade(code):
    code = re.sub(r'function\s+(\w+)\s*\(.*?\)\s*:\s*(void|int|float|string|bool|array|callable|iterable)\s*\{',
                  r'function \1(...) {', code)
    code = re.sub(r'\?\?', ' . ', code)          # 消除 null 合并运算符
    code = re.sub(r'(goto \w+;)', r'//\1', code) # 注释 goto
    return code

parser = phpparse.make_parser()
with open(path, encoding="utf-8", errors="ignore") as f:
    ast = parser.parse(downgrade(f.read()), lexer=phplex.lexer.clone())
# 遍历 ast：Namespace 更新 ns，Class 更新 cls，FunctionCall 生成 (caller, callee, "CALLS")
```

导入后的查询结果形如 `detailAction(CourseStatisticsController) (CALLS) hasManageRole(...) ... file_get_contents(Php)`，正文示例项目导入规模约 3 万节点、11 万关系。

## 变体与关联

- 变体：sink 名单按漏洞类型拆分查询——文件读写（`file_get_contents`/`fopen`/`readfile`/`file_put_contents`）、命令/代码执行（`call_user_func`/`system`/`eval`/`curl_exec`）、反序列化（`unserialize`/`simplexml_load`）、包含（`include`/`require`），分别导出报告。
- 变体：query 中加 `WHERE none(n IN nodes(path) WHERE n.class <> 'Controller')` 或按 namespace 前缀过滤，只保留业务代码间的链，压掉框架内部噪声。
- 变体：把 xlsx 里的调用链交给 LLM 逐链回读源码判断参数可控性，与 tabby 链 + MCP/Skill 的用法同构。
- 关联：[[code-analysis-sast-tabby-neo4j-controller-sink-callchain]] 是同一“调用图 + Neo4j + allSimplePaths”思路的 Java/tabby 版本；本条是 PHP/phply 版本，前端与命名空间消解完全不同。
- 局限：`$func()` 动态调用、`call_user_func` 的字符串参数、框架路由分派、魔术方法无法静态绑定，会漏报；namespace 消解靠字符串包含匹配，重名函数或子串命名会误连，产生假边。

## 检测与防御

- 该方法是审计辅助：输出的是“候选链”，不能把存在调用链直接等同于漏洞；需确认 Controller 入参可控且未被过滤。
- 防御方可在 CI 中对 PHP 项目构建同类调用图，定期扫描 Controller 到危险函数的短链，重点关注参数直接来自 `$_GET`/`$_POST`/`$_REQUEST` 且路径上无白名单的链。
- 对动态函数调用、文件包含、反序列化等 sink 做集中治理与参数白名单；对 `include`/`require` 使用固定路径映射而非用户输入拼接。
