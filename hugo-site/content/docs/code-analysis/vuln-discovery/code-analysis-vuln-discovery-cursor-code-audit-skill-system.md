---
id: code-analysis-vuln-discovery-cursor-code-audit-skill-system
title: Cursor 代码审计 Skill 体系：P0-P3 Grep 规则、语言路由与 MCP 工具集成
type: scenario
domain: code-analysis
path: code-analysis/vuln-discovery
technique: cursor-code-audit-skill-system
tags:
- ai-agent
- code-audit
- sast
- cursor
- skill
- grep
- mcp
- prompt-engineering
- methodology
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V152
  verified_at: '2026-11-06T07:31:41+08:00'
  notes: 已对照原文全文核对：Skill 目录/触发机制、Tier1-4 分层、P0-P3 Grep 规则、危险/安全代码对照、框架检查点、依赖审计、checklist、渐进披露与四类反模式、Burp/IDA/browser MCP 工具表均与原文一致；方法论文章无组件版本、未设置 versions；原文无真实 PoC（示例为 Skill 模板），卡片已标明人审边界；frontmatter 无 sources/source_url。
url: /docs/code-analysis/vuln-discovery/code-analysis-vuln-discovery-cursor-code-audit-skill-system/
draft: false
kb_aliases:
- AI 代码审计 Skill
- Cursor Skill
- code-audit-php
- Grep 扫描规则
- 安全审计 Skill 分层
- MCP 审计工具集成
---

## 一句话结论

把代码审计经验拆成“主索引路由 + 按语言子 Skill + 专项 Skill + 跨语言进阶”的分层 Skill 体系，每个语言 Skill 用 P0-P3 分级的可执行 Grep 正则、危险/安全代码对照、框架检查点、依赖审计命令和 checklist 组成，并保持单文件精简、渐进披露与低冗余，可让 Cursor/Claude 类 Agent 稳定触发并完成批量初筛，但结论仍需人工复核。

## 原理

- **Skill 机制**：每个 Skill 是一个 Markdown 文件，YAML frontmatter 的 `name`/`description` 决定触发，Markdown 正文是给 Agent 的执行指令。Cursor 通过 `description` 的语义匹配自动加载；因此描述要写清“做什么 + 何时用”，并包含语言/框架/漏洞类型关键词（如 `PHP`、`Laravel`、`unserialize`），比笼统的“代码审计”更容易命中。
- **分层架构**：
  - **Tier 1 主索引**：只做路由、统一方法论（攻击面识别 → 按严重等级扫描 → 上下文验证 → 报告模板）和输出格式，不放完整危险函数速查表，避免与子 Skill 重复。
  - **Tier 2 语言子 Skill**：`code-audit-php`、`code-audit-java`、`code-audit-python`、`code-audit-nodejs`、`code-audit-dotnet`、`code-audit-go-cloud`、`app-audit-electron`；每个都遵循同一模板。
  - **Tier 3 专项**：`web-api-security`（JWT/OAuth/GraphQL/WebSocket）、`security-audit`（Burp 动态测试）、`reverse-engineering`（IDA/二进制）、`firmware-security`（IoT/固件）。
  - **Tier 4 跨语言进阶**：`security-advanced`（WAF 绕过、竞态、密码学）。
- **语言 Skill 的标准化结构**：适用范围 → Grep 扫描规则（核心）→ 核心漏洞模式（危险 vs 安全代码）→ 框架审计要点 → 依赖审计 → 审计检查清单。
- **Grep 规则是核心创新**：给 Agent 可直接执行的正则，按 `P0_RCE`、`P1_HIGH`、`P2_MEDIUM`、`P3_LOW` 分级，先扫 P0 再扫低危；正则要精准、覆盖命令执行/代码执行/反序列化/SQLi/文件操作/SSRF，且按语言定制（不同语言的危险函数不同）。
- **简洁原则**：只写“AI 本身不知道的”内容——框架特有漏洞模式、Grep 正则、版本相关 CVE、危险/安全代码对照；不要解释“什么是 SQL 注入”，不要写长段危害描述，注释只保留“危险/安全替代”这类短标记。
- **渐进披露与长度控制**：`SKILL.md` 控制在 200 行内、最多 500 行；详细载荷/框架细节放到 `payloads.md`、`frameworks.md`、`reference.md`、`examples.md`，引用保持一层深度（`SKILL.md → reference.md`），避免多层链导致 Agent 漏读。
- **消除冗余**：跨 Skill 不重复同一危险函数表；主索引不复制子 Skill 内容；Skill 内不写废话注释。两个 Skill 同时被加载时，冗余会直接翻倍消耗上下文。
- **MCP 工具集成**：在 Skill 中列出工具名、用途、API 签名与返回值，而不是解释函数做什么。例如 Burp 的 `get_scanner_issues`、`get_proxy_http_history`、`send_http1_request`；IDA MCP 的 `get_function_list()`、`decompile(address)`、`get_xrefs_to(address)`、`trace_data_flow(source, sink, direction)`；浏览器 MCP 的 `browser_navigate`、`browser_snapshot`、`browser_network_requests`。
- **典型反模式**：百科全书式 master（与子 Skill 重复）、伪通用 Skill（名为语言无关实际 90% 是 Python）、杂项堆积 Skill（WAF/竞态/WASM/K8s/移动全塞一起）、冗余代码注释。
- **边界**：Grep 规则本质是启发式，误报/漏报都高；AI 会把“候选”说成“结论”甚至编造请求包，必须人工验证；Skill 只是流程与知识载体，不是漏洞扫描器。

## 触发条件

- 使用 Cursor、Claude Code 等支持 Agent Skill/Markdown 指令的 IDE/CLI；
- 有可访问的源码目录与 Grep、文件读取、MCP（Burp/IDA/browser）工具；
- 需要对多语言/多框架项目做批量初筛，且有可沉淀的审计经验；
- 接受“AI 出候选、人做成立判断”的人审边界。

## 利用步骤

1. 盘点覆盖范围：语言（PHP/Java/Python/Node.js/.NET/Go）、框架、漏洞类型、专项（Web API/逆向/固件）。
2. 写主索引 `security-research-master`：按文件扩展名/构建文件/框架识别路由到子 Skill，给出四阶段方法论和统一报告模板。
3. 每个语言写一个 `code-audit-{language}/SKILL.md`，按标准模板填入：
   - 适用范围与版本；
   - P0-P3 Grep 正则（先 P0）；
   - 危险 vs 安全代码对照；
   - 框架特有检查点（如 Django `DEBUG=True`、`SECRET_KEY`、`|safe`、`raw()`）；
   - 依赖审计命令（`pip-audit`、`safety`、`mvn dependency-check` 等）；
   - 可勾选 checklist。
4. 把长载荷、框架细节、示例放到同级 `payloads.md`/`frameworks.md`/`examples.md`，保持一层引用。
5. 在专项 Skill 中列 MCP 工具表与 API 签名（Burp/IDA/browser），让 Agent 知道何时调用哪个工具。
6. 用真实项目回归：统计每个 Grep 规则的命中/误报，调整正则；对 P0 命中逐条做上下文验证。
7. 输出报告时要求 Agent 给出文件/行号、危险代码片段、输入来源、验证请求/响应；人工复核后再定性。

## PoC

```markdown
---
name: code-audit-python
description: Python 代码安全审计专家。分析 Python 源码漏洞，支持 Django/Flask/FastAPI/Tornado。当审计 Python 代码或遇到 eval/exec/pickle/subprocess/SSTI/yaml.load 时使用。
---

# Python 代码审计

## 适用范围
- Python 2.x/3.x；Django/Flask/FastAPI/Tornado/aiohttp；Celery/Dramatiq；Gradio/Streamlit

## Grep 扫描规则
P0_RCE:
  - 'eval\s*\('
  - 'exec\s*\('
  - 'pickle\.(loads?|load)\s*\('
  - 'yaml\.load\s*\('
  - 'subprocess\.\w+\(.*shell\s*=\s*True'
  - 'os\.(system|popen)\s*\('
P1_HIGH:
  - 'requests\.(get|post)\s*\('
  - 'cursor\.execute\s*\(.*(%|\.format|f["\x27])'
  - 'open\s*\(.*os\.path\.join'
  - 'send_file\s*\('
P2_MEDIUM:
  - 'render_template_string\s*\('
  - 'DEBUG\s*=\s*True'
  - 'SECRET_KEY\s*=\s*["\x27]'

## 核心漏洞模式
### 反序列化 (P0)
pickle.loads(untrusted_data)   # 危险
yaml.load(data)                # 危险
json.loads(data)               # 安全替代
yaml.safe_load(data)           # 安全替代

### SSTI (P0)
render_template_string(user_input)          # 危险
render_template("fixed.html", data=user)    # 安全

## 框架审计要点
Django: DEBUG=True / SECRET_KEY 硬编码 / ALLOWED_HOSTS=['*'] / {{ x|safe }} / raw()/extra()
Flask: FLASK_DEBUG=1 / 可预测 secret_key / render_template_string(user_input)

## 依赖审计
pip-audit -r requirements.txt
safety check -r requirements.txt

## 审计检查清单
- [ ] 用 Grep 规则批量扫描 P0-P3
- [ ] 验证 eval/exec/compile 输入来源
- [ ] 检查 pickle/yaml 反序列化入口
- [ ] 验证 SQL 参数化
- [ ] 审计文件路径校验
- [ ] 检查框架配置
- [ ] 运行依赖审计
```

主索引路由表示例：

```markdown
| 识别特征 | 技能 |
|---|---|
| .php / composer.json / Laravel | code-audit-php |
| .java / pom.xml / Spring | code-audit-java |
| .py / requirements.txt / Django | code-audit-python |
| .js / package.json / Express | code-audit-nodejs |
```

## 变体与关联

- 变体：把 Grep 规则换成 Semgrep/CodeQL 查询；把主索引换成多 Agent 分工（侦察、审计、验证、报告）；把 MCP 从 Burp/IDA 扩展到浏览器、fofa、cve-mcp。
- 关联 [[code-analysis-vuln-discovery-llm-sast-vulnhuntr-python-audit-pipeline]]：LLM 辅助 Python 审计流水线，可与本卡的 Skill 规则组合。
- 关联 [[code-analysis-vuln-discovery-multi-agent-adversarial-pipeline]]：多 Agent 对抗式漏洞挖掘，本卡是其单 Agent Skill 形态的前置工程。
- 关联 [[ai-security-agent-security-ai-pentest-evidence-driven-pipeline]]：AI 渗透必须“候选 + 原始请求/响应 + 人审”，本卡同样强调 AI 结论不等于成立。
- 关联 [[ai-security-agent-security-ctf-agent-prompt-pack-runtime-routing]]：用 Skill/提示词做任务路由与运行时能力盘点，与本卡的主索引路由同源。
- 边界：Grep 正则无法理解数据流与业务语义，误报率高；AI 可能编造文件/行号/请求包；没有源码访问、没有 MCP 工具、或目标语言/框架不在 Skill 覆盖范围时效果差。

## 检测与防御

- **对防御方**：AI 代码审计 Skill 会显著降低攻击者/审计者的初筛成本，代码库应默认按“会被批量 Grep”来防护：危险函数集中封装、参数化查询、禁用不安全的反序列化与 `shell=True`、最小化 `DEBUG`/`SECRET_KEY` 暴露。
- **对使用者**：把 AI 输出当候选而非结论；要求文件/行号、输入来源、原始请求/响应；对 P0 命中逐条人工验证；用真实项目统计误报/漏报并迭代规则。
- **Skill 供应链**：只从可信来源安装 Skill；审查 SKILL.md 是否包含越权指令、外带数据或自动执行脚本；Skill 目录中的脚本按不可信代码处理。
- **检测信号**：仓库中出现大规模 Grep/正则扫描、Agent 读取大量源码与依赖清单、Burp/IDA MCP 被自动调用；对异常代码读取与外部 MCP 连接做审计。
