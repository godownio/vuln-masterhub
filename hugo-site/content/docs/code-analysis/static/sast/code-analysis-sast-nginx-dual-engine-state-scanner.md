---
id: code-analysis-sast-nginx-dual-engine-state-scanner
title: nginx 双引擎状态不一致自动化检测：配置语义 + 源码模式 + 状态追踪 + 溢出断言四层扫描
type: scenario
domain: code-analysis
path: code-analysis/static/sast
technique: nginx-dual-engine-state-scanner
tags:
- sast
- nginx
- dual-engine
- is-args
- state-tracking
- scanner
- cve-2026-42945
- config-analysis
cve:
- CVE-2026-42945
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: nginx 0.6.27–1.30.0（扫描目标版本；1.31.0/1.30.1 修复）
verification:
  verified_by: verifier-V102
  verified_at: '2026-11-05T22:37:30+08:00'
  notes: 已对照原文核对四层扫描器、正则与实测输出；扫描器代码为原文片段，未独立运行。
url: /docs/code-analysis/static/sast/code-analysis-sast-nginx-dual-engine-state-scanner/
draft: false
kb_aliases:
- nginx-ele-scanner
- e/le 双引擎扫描
- is_args 状态追踪
- 溢出风险断言
- 配置语义分析
- CVE-2026-42945 检测框架
---

## 一句话结论

针对 nginx `e, le` 双引擎状态不一致类漏洞，可把检测拆成四层流水线：配置语义分析找 `rewrite ...?` + `set $var $1` 组合、源码模式匹配找 `ngx_http_script_engine_t e, le` 与 `ngx_memzero(&le)`、状态变量追踪对比 `is_args` 的写入/清零/读取点、溢出风险断言比较 len 阶段与 run 阶段的条件结果；扫描 1.30.0 源码可准确把 `ngx_http_script.c` 标为 CRITICAL，其余 7 个 HTTP 模块标 LOW，stream 标 NONE。

## 原理

- **配置层**：CVE-2026-42945 的触发条件是同一 `location` 内 `rewrite` 替换串含 `?`，且 `set $var $1` 引用捕获组。解析 nginx.conf 的 location 块，用正则匹配 `rewrite\s+\S+\s+\S*\?` 与 `set\s+\$\w+\s+\$(\d+)` 即可筛出高危配置；风险分级：`rewrite ...? + set $var $1` 高危，`$2` 等中危，仅 rewrite? 无 set 低危。
- **源码模式层**：扫描所有 `.c` 文件，检测 `ngx_http_script_engine_t e, le` 双引擎声明、`ngx_memzero(&le)` 清零、`ngx_http_script_start_args_code` 设置 `is_args`、`is_args` 引用。若模块同时包含 dual_engine + start_args + is_args → CRITICAL；仅 dual_engine → LOW；否则 NONE。
- **状态追踪层**：追踪 `is_args` 的写入点（`start_args_code` 中 `e->is_args=1`）、清零点（`ngx_memzero(&le)`）、读取点（`copy_capture_len_code`/`copy_capture_code` 中的 `if (e->is_args ...)`），检测“先写主引擎、后清零子引擎、再在子引擎调用路径读取主引擎状态”的顺序不一致。
- **溢出断言层**：对捕获组 $n，`L1 = cap[n+1]-cap[n]`（len 阶段原始长度），`L2 = L1 + 2×N`（run 阶段每个可转义字符 1→3），当 N>0 时 L2>L1，断言堆溢出。完整鉴定链：dual_engine && start_args && len 函数含 `e->is_args` 判断 && `lcode(&le)` 传子引擎但函数检查主引擎 → CRITICAL。
- **批量报告层**：扫描指定目录或 GitHub 仓库，输出每个模块的引擎使用情况、风险等级、修复建议；可跨版本对比双引擎模式变化，定位修复补丁生效范围。
- **实测输出**（nginx 1.30.0，src/ 13 个文件）：`ngx_http_script.c` CRITICAL（2 处 e,le 声明、2 处 memzero、2 处 start_args_code、4 处 is_args 引用）；proxy/grpc/fastcgi/scgi/uwsgi/proxy_v2 LOW（有 e,le 但独立初始化、不涉及 rewrite is_args）；stream NONE（无双引擎、不做 URI escape）；5 个无风险模块。
- 价值在于**检测“出错的模式”而非“出错的结果”**：同一 bug class 可扩展到 `quote`、`flushed` 等其他被 `ngx_memzero` 清零的字段；新模块加入时可快速判断是否沿用危险模式。

## 触发条件

- 有 nginx（或分支）源码与配置，需要审计双引擎状态不一致类漏洞。
- 目标版本在受影响范围（0.6.27–1.30.0）或需要验证新版本/新模块是否修复。
- 扫描器以正则/轻量 AST 为主，能接受一定误报并配合人工复核。
- 配置解析能覆盖 include、嵌套 location 等实际写法（否则配置层会漏报）。

## 利用步骤

1. 配置层：解析 nginx.conf，列出所有 `location` 块，匹配 `rewrite ...?` 与 `set $var $N`，输出高危 location。
2. 源码层：扫描 `src/**/*.c`，统计每个文件的 `dual_engine`、`memzero_le`、`start_args`、`is_args` 命中，按规则分级。
3. 状态层：对 CRITICAL 候选提取 `is_args` 写入/清零/读取行号，验证“写主引擎 → memzero 子引擎 → 子引擎路径读主引擎”的顺序。
4. 断言层：确认 len 函数与 run 函数使用同一条件但读取不同引擎状态，计算 `L2-L1=2N`，输出溢出结论。
5. 报告层：批量扫描源码目录/仓库，生成模块风险表、行号、修复建议；接入 CI 对新版本/新模块做回归。
6. 人工复核正则误报（include、注释、宏、条件编译）与跨文件状态传播。

## PoC

```python
import re

def scan_nginx_config(config_path):
    content = open(config_path).read()
    for loc in re.finditer(r'location\s+[^{]*\{([^}]+\})', content, re.DOTALL):
        block = loc.group(1)
        has_rewrite_q = bool(re.search(r'rewrite\s+\S+\s+\S*\?', block))
        has_set_capture = bool(re.search(r'set\s+\$\w+\s+\$(\d+)', block))
        if has_rewrite_q and has_set_capture:
            print('[高危] location 同时使用了 rewrite? 和 set $1')
```

```python
def scan_source_for_dual_engine(src_dir):
    patterns = {
        'dual_engine': re.compile(r'ngx_http_script_engine_t\s+e(\s*,\s*le|\s*;)'),
        'memzero_le': re.compile(r'ngx_memzero\s*\(\s*&le\s*,'),
        'start_args': re.compile(r'ngx_http_script_start_args_code'),
        'is_args': re.compile(r'is_args'),
    }
    # 对每个 .c 文件应用模式匹配，输出命中统计
```

```python
def trace_is_args_path(source_file):
    lines = open(source_file).readlines()
    writes, reads, memzero = [], [], []
    for i, line in enumerate(lines, 1):
        if 'is_args' in line:
            if '=' in line and '==' not in line:
                writes.append((i, line.strip()))
            elif 'if' in line or 'while' in line:
                reads.append((i, line.strip()))
        if 'ngx_memzero' in line and 'le' in line:
            memzero.append((i, line.strip()))
    return {
        'writes': writes, 'reads': reads, 'memzero': memzero,
        'inconsistency': any(w[0] < m[0] < r[0]
                             for w in writes for m in memzero for r in reads),
    }
```

```python
def assess_risk(match_info):
    if (match_info.get('start_args') and match_info.get('is_args')
            and match_info.get('dual_engine')):
        return 'CRITICAL'
    if match_info.get('dual_engine'):
        return 'LOW'
    return 'NONE'
```

## 变体与关联

- 变体：把 `is_args` 替换为 `quote`、`flushed` 等其他被 `ngx_memzero` 清零的字段；把扫描目标扩展到 proxy/grpc/fastcgi 等模块的其他状态变量。
- 变体：用 CodeQL/Joern 等 AST/数据流引擎替代正则，减少配置解析和宏/条件编译误报；对 `lcode(&le)` 与 `code(&e)` 做跨函数参数追踪。
- 关联：[[binary-pwn-heap-nginx-rewrite-isargs-dual-engine-overflow]]（CVE-2026-42945 的完整触发与 GDB 分析）、[[code-analysis-source-audit-double-path-state-divergence]]（双路径分歧审计模式）、[[code-analysis-vuln-discovery-patch-coverage-sink-audit]]（补丁覆盖与同类 sink 枚举）。
- 边界：正则扫描器对 include/嵌套/宏/条件编译有漏报；模式命中不等于可利用，需要状态追踪与断言层确认；新模块可能用不同变量名，需人工扩展规则。

## 检测与防御

- 检测：将扫描器接入 CI，对 nginx 源码/分支/配置做定期扫描；监控 `ngx_http_script_engine_t e, le`、`ngx_memzero(&le)`、`start_args_code`、`is_args` 的新增组合；对配置层 `rewrite? + set $N` 做部署前检查。
- 修复：升级到 nginx 1.31.0/1.30.1；在代码层统一状态传播（明确哪些字段继承、哪些重置），避免子引擎路径读取主引擎状态；对新增模块按同一模式审查。
- 加固：配置生成系统避免字符串拼接/危险 rewrite 组合；WAF 拦截大量 `+`；运行时监控 worker signal 6/11；把扫描器作为 SAST 规则的一部分持续维护。
