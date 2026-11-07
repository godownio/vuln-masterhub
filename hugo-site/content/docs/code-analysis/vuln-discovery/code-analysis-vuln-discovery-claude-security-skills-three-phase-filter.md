---
id: code-analysis-vuln-discovery-claude-security-skills-three-phase-filter
title: claude-code-security-skills 三阶段审计：19 条硬排除 + 17 条先例 + 置信度 ≥7 的 AI 代码审计误报过滤流程
type: scenario
domain: code-analysis
path: code-analysis/vuln-discovery
technique: claude-code-security-skills-three-phase-filter
tags:
- ai-agent
- code-audit
- sast
- skill
- prompt-engineering
- false-positive
- filtering
- methodology
- code-review
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V151
  verified_at: '2026-11-06T07:32:16+08:00'
  notes: 已对照原文核对：三阶段流程、19 条硬排除、17 条先例、1-10 评分且 <7 排除、正则/文件级规则、两个定制扩展点（扫描追加/过滤替换）、newbee-mall 演示保留 2 排除 1 均一致。小差异：原文 SKILL.md 引文为 'until Phase 3 (Filter) is complete'（原文疑似笔误），卡内 PoC 写作 Phase 2 (Filter)；方法论未在本机复跑。无组件版本，不设 affected_versions；frontmatter 无 sources/source_url。
url: /docs/code-analysis/vuln-discovery/code-analysis-vuln-discovery-claude-security-skills-three-phase-filter/
draft: false
kb_aliases:
- claude-code-security-skills
- AI 代码审计三阶段
- 安全审计 Skill
- 误报过滤规则
- 19 条硬排除
- 17 条先例
- 置信度阈值 7
- 审计过滤决策表
---

## 一句话结论

claude-code-security-skills 把 AI 代码审计拆成强制顺序的三阶段：Phase 1 宽进产出原始发现（含具体攻击路径）→ Phase 2 先用 19 条硬排除 + 正则快速过滤、再由 AI 按 1-10 置信度评分且 **<7 一律排除** → Phase 3 先输出完整过滤决策表再报告保留项；核心不是“让 AI 找更多漏洞”，而是用显式执行契约、硬排除规则和先例库把 AI 常见的 DoS/内存安全误报/理论问题压下去，把人工审查量控制在可承受范围。

## 原理

- **AI 审计的失败模式**：模型天然倾向“立刻给结论、跳过过滤、把理论风险当漏洞”，导致输出大量低价值发现（DoS、限流缺失、内存泄漏、客户端鉴权缺失、日志注入等），人工审查疲劳后反而漏掉真漏洞。该 skill 用三阶段契约把“先过滤再上报”固化为执行条件。
- **Phase 1 宽进**：以“高级安全工程师”角色做三步——1a 代码库上下文调研（安全框架、认证模式、威胁模型）、1b 对比分析（与安全规范对照、找偏离与新攻击面）、1c 漏洞评估（追踪数据流、注入点、权限边界）。产出内部原始发现列表，每条必须含标题、文件位置、类别、严重度、描述、**具体攻击路径**；不直接给用户。
- **Phase 2 严出**：
  - 2a 硬性排除：正则匹配标题+描述，命中即排除；文件级规则（`.md` 全部排除；非 C/C++ 排除内存安全；`.html` 排除 SSRF）。
  - 2b AI 过滤：按 `filtering-rules.md` 的 19 条硬排除与 17 条先例逐条评估，给出 1-10 置信度；<7 一律排除（4-6 分仅在非常具体时保留）。
  - 每条原始发现必须在过滤表中有对应行，记录 `Hard Excl?`、`Precedent Hit?`、`Concrete Attack Path?`、`Confidence`、`Decision`、`Reason`，保证可追溯。
- **Phase 3 报告**：强制先展示过滤表，再输出保留发现的详细报告（严重度、置信度、描述、利用场景、修复建议），最后附排除汇总。先展示推理过程再给结论，便于人工复核。
- **19 条硬排除的典型项**：DoS/资源耗尽、磁盘上的秘密（由其他流程处理）、限流缺失、内存/CPU 耗尽、无影响的无害字段校验缺失、CI/CD 非触发输入、缺少加固、理论竞态/时序、过期依赖、内存安全语言中的内存安全、测试文件、日志伪造、仅控制 path 的 SSRF、AI prompt 注入、正则注入/ReDoS、文档文件、缺少审计日志、不可用内部依赖、非漏洞崩溃。
- **17 条先例的典型项**：日志中的高价值秘密是漏洞（URL 安全、请求头危险）；UUID 不可猜；审计日志缺失不算；环境变量/CLI 参数可信；资源泄漏不算；低影响 Web 漏洞（tabnabbing/XS-Leaks/原型污染/开放重定向）需极高置信；过期库不报；React/Angular 默认安全（除非 `dangerouslySetInnerHTML` 等）；CI/CD 多数不可利用；客户端 JS 鉴权/路径遍历/SSRF 不算；MEDIUM 仅明显具体；Jupyter 多数不可利用；非 PII 日志不算；shell 脚本命令注入需具体不可信输入；HTTP 请求中的 `../` 一般无害；日志查询注入需确定泄露。
- **为什么能提高精度**：先宽后严避免 Phase 1 过早丢真洞；硬排除/先例把已知噪音类型在 AI 评分前就砍掉；7 分阈值把“需要调查”的中等置信项也挡在报告外；过滤表把“为什么排除”显式化，减少模型暗箱操作。
- **边界**：高阈值会漏掉真实但证据不足的中危漏洞；硬排除规则在特定业务下可能误杀（如 AI 应用的 prompt injection 被统一排除，但对该类应用可能正是核心风险）；先例是通用假设，项目定制必须覆盖；最终仍需人工验证，AI 输出只是候选。

## 触发条件

- 使用支持自定义 Skill/自定义指令的 AI 编码环境（Claude Code、GitHub Copilot、Cursor 等），能读取仓库文件并执行多阶段 prompt。
- 目标代码库规模较大、AI 初筛噪音高，需要把误报压到人工可审查的程度。
- 团队能提供项目特定的“已知安全”信息（统一认证、ORM、API 网关、密钥管理、k8s 资源限制等）作为自定义先例。
- 接受“AI 出候选、人做成立判断”的边界，不把报告直接当最终结论。

## 利用步骤

1. 建立 Skill 目录：`SKILL.md`（流程总控）+ `resources/audit-prompt.md`（审计主提示词）+ `resources/filtering-rules.md`（19 硬排除 + 17 先例）+ `resources/hard-exclusion-patterns.md`（正则）+ `resources/customization-guide.md`（扩展指南）。
2. 在 `SKILL.md` 写入强制三阶段契约：未完成 Phase 2 前禁止上报；每个资源文件在对应阶段必须读取；禁止 0.0-1.0 旧刻度；禁止跳过过滤表。
3. 在 audit-prompt 中限定角色/目标（只找高置信安全问题，不做通用代码评审）、关键约束（>80% 可利用性、排除 DoS/磁盘秘密/限流）、漏洞类别、1a/1b/1c 方法论、输出格式（文件:行号、具体参数、具体 payload、具体修复）。
4. 在 filtering-rules 中列出 19 条硬排除与 17 条先例；在 hard-exclusion-patterns 中写正则（DoS、限流、资源泄漏、开放重定向、非 C/C++ 内存安全、正则注入、HTML 文件 SSRF）与文件级规则。
5. 按项目定制：自定义扫描指令追加到默认类别之后；自定义过滤指令会**完全替换**默认 filtering-rules（正则始终生效），因此必须重新声明所有必要排除项与先例。
6. 运行 Phase 1 产出原始发现；Phase 2 逐条打过滤表并评分；Phase 3 只报告 ≥7 分项，先表后详情。
7. 人工复核过滤表：重点看被排除的 4-6 分项是否被误杀、被保留项的攻击路径是否真实、先例是否适用于当前业务。

## PoC

`SKILL.md` 执行契约与过滤表格式（方法论卡，无漏洞利用 PoC）：

```markdown
> **MANDATORY EXECUTION CONTRACT**
> This skill defines a strictly ordered, three-phase process.
> You MUST complete all three phases in sequence before producing final output.
> You are FORBIDDEN from reporting any findings until Phase 2 (Filter) is complete.

| # | Title | Hard Excl? | Precedent Hit? | Concrete Attack Path? | Confidence (1-10) | Decision | Reason |
|---|-------|-----------|----------------|-----------------------|-------------------|----------|--------|
| 1 | ... | No | No | Yes | 9 | KEEP | Directly exploitable |
| 2 | ... | No | UUID unguessable (Precedent #2) | Conditional | 5 | EXCLUDE | UUID guessing required |
```

正则硬排除示例（Python）：

```python
import re

_DOS_PATTERNS = [
    re.compile(r'\b(denial of service|dos attack|resource exhaustion)\b', re.I),
    re.compile(r'\b(exhaust|overwhelm|overload).*?(resource|memory|cpu)\b', re.I),
    re.compile(r'\b(infinite|unbounded).*?(loop|recursion)\b', re.I),
]

def should_exclude(title: str, description: str) -> bool:
    combined = f"{title} {description}".lower()
    return any(p.search(combined) for p in _DOS_PATTERNS)
```

自定义过滤先例示例（替换默认规则时必须重新声明）：

```text
HARD EXCLUSIONS:
1. All DOS/resource exhaustion - k8s resource limits and autoscaling
2. Missing rate limiting - handled by API gateway
3. Test files (ending in _test.go, _test.js, or __tests__)
PRECEDENTS:
1. All auth uses AWS Cognito - auth bypass must defeat Cognito
2. All APIs require JWT validated at gateway
3. SQL injection only valid with raw queries (Prisma ORM everywhere)
4. Internal services use mTLS in k8s
5. Secrets in AWS Secrets Manager or k8s secrets, never in code
```

原文演示：对 newbee-mall 审计保留 2 项——`/paySuccess` 未认证订单支付伪造（拦截器漏配 + 不校验支付回调签名）与管理员上传任意扩展名导致 polyglot HTML 存储型 XSS（`ImageIO` 校验后仍用原文件名后缀），并排除商品详情 `th:utext` 存储型 XSS（命中“管理员可信富文本”先例）。

## 变体与关联

- 变体：把三阶段接到 CI（GitHub Action/PR 评论）或 IDE Skill，Phase 2 的过滤表作为 PR 评论输出，人工只复核 KEEP 项。
- 变体：用第二次独立 LLM 调用复核 KEEP/EXCLUDE，降低单次评分波动；或对同一发现多次采样取一致性。
- 变体：按语言/框架定制扫描类别与正则；把项目已知安全基线（Cognito、Prisma、mTLS、Secrets Manager）写进先例，减少“正确代码被误报”。
- 关联：[[code-analysis-vuln-discovery-cursor-code-audit-skill-system]]（分层 Skill + P0-P3 Grep 规则的另一种 AI 审计体系）；[[code-analysis-vuln-discovery-llm-sast-vulnhuntr-python-audit-pipeline]]（五阶段 LLM SAST + 置信度评分）；[[code-analysis-vuln-discovery-ast-chain-per-link-llm-audit-workflow]]（按调用链逐段审计）；[[ai-security-agent-security-ai-pentest-evidence-driven-pipeline]]（AI 渗透的证据驱动流水线）。
- 关联：该方法论与 [[ai-security-agent-security-vega-self-evolving-bounty-agent-architecture]] 的经验库思路相通：把“哪些是噪音、哪些是已知安全”沉淀为可复用规则，减少重复误报。

## 检测与防御

- 使用建议：把 7 分阈值视为“人工审查入口”而不是“漏洞确认”；对 4-6 分但影响高的发现（认证绕过、支付逻辑、文件上传）单独复核，避免高阈值误杀。
- 使用建议：硬排除规则按业务调整；AI 应用不应直接照搬“AI prompt injection 不报”的通用先例，否则会漏掉自身核心风险。
- 使用建议：先宽后严，Phase 1 不要过滤；Phase 2 的过滤表必须逐条可追溯，禁止模型“心里过滤”。
- 防御（对被测系统）：AI 审计能稳定发现直接 source→sink 的注入、上传、认证缺失；对业务逻辑、间接调用、隐式反序列化、长调用链仍需人工与动态测试补充。
- 度量：统计每轮 KEEP/EXCLUDE 数量、人工复核后的真阳性率、被误杀的 4-6 分项；据此调整先例与正则，而不是盲目放宽阈值。
