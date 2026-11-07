---
id: code-analysis-vuln-discovery-multi-agent-adversarial-pipeline
title: 多 Agent 对抗式漏洞挖掘流水线：Finder/Refuter/Reproducer + 证据卡与置信度分级
type: scenario
domain: code-analysis
path: code-analysis/vuln-discovery
technique: multi-agent-adversarial-vuln-discovery-pipeline
tags:
- vuln-discovery
- multi-agent
- llm
- code-audit
- sast
- false-positive
- adversarial-verification
- evidence-card
- confidence
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V106
  verified_at: '2026-11-05T22:24:03+08:00'
  notes: 已对照原文929行核对：多Agent Finder/Refuter/Reproducer流水线、A/B/C/D四轴、裁决规则、L1-L4、证据卡、只读/沙箱权限、FPR/Recall度量均与原文一致；卡片明确标注为设计规范而非落地产品、PoC为原文示例未执行；frontmatter无sources/source_url；未验证点：示例PoC未本机复跑，文章无具体组件/版本。
url: /docs/code-analysis/vuln-discovery/code-analysis-vuln-discovery-multi-agent-adversarial-pipeline/
draft: false
kb_aliases:
- 漏洞挖掘 Agent 设计规范
- Finder Refuter Reproducer
- 对抗式验证
- 证据卡
- 低误报漏洞挖掘
- 多 Agent 漏洞发现
---

## 一句话结论

把 LLM 漏洞挖掘拆成“确定性工具枚举 + 多 Finder 提出候选 + 多个独立 Refuter 默认证伪 + 沙箱 Reproducer 复现 + Synthesizer 去重定级”的流水线，并用强制证据卡（source/sink/逐跳 flow/sanitizer/reachability/impact）和 L1–L4 置信度做机器闸门；核心原则是“模型负责提出，工具与对抗式验证负责证明，只有证明过的 L1/L2 才上报”。

## 原理

- **单模型自证有正向偏差**：让同一个模型既当 Finder 又当裁决者，会把“看起来像漏洞”的候选直接确认；LLM 的三大幻觉（假 API/函数、假数据流、假可达性）恰好就是漏洞误报的三大来源。必须让独立的 Refuter 从干净上下文出发，默认“这是误报”，沿四个轴攻击候选：A 来源不可控、B 已被 sanitize/安全 sink、C 不可达、D 引用/签名/行号不存在。
- **枚举与判断分离**：semgrep、CodeQL、cargo audit、gitleaks、osv-scanner 等确定性工具负责“不漏”（机械模式、依赖 CVE、密钥），模型负责语义级污点、跨函数可达性与上下文判断，Refuter 负责精度。扫描器输出只作为候选种子，不直接进报告，因为扫描器没有可达性/可利用性判断。
- **证据卡是硬门槛**：每个候选必须填 `source(s) / sink(s) / flow（逐跳 file:line）/ sanitizer（无或为何无效）/ reachability（调用链、前置条件、是否默认开启、是否需认证）/ impact`；缺项、`verified:false` 的跳、空 source/sink 都会被机器降级或驳回。禁止凭记忆断言签名或数据流，必须 grep/read 真实代码并给行号。
- **多 Refuter 与裁决规则**：每个候选派 2–3 个独立 Refuter，人为错开 A/B/C/D 轴。裁决可编码为：`refutes >= 2` → REFUTED；`refutes == 1 and survives >= 2` → SURVIVED（留 note）；`refutes == 1 and survives <= 1` → SURVIVED 但降一级；无否决 → SURVIVED。若某个 Refuter 给出可直接复现的反驳证据（如贴出 `shell=False` 的真实代码），强否决优先于多数。SURVIVED 只表示“未能证伪”，不等于“确定可利用”。
- **置信度分级**：L1 CONFIRMED（有可复现 PoC/通过负向测试）、L2 LIKELY（source→sink 完整、可达、未发现 sanitizer，但无 PoC）、L3 SUSPICIOUS（模式可疑但可达性/可利用性未证实）、L4 NOTE（加固建议/非直接可利用）。只有 L1/L2 按漏洞上报；L1 若无 `poc.reproduced: true` 自动降 L2；`default_on:false` 且 `auth_required:true` 再降一级。
- **流水线阶段**：Phase 0 威胁建模（资产、信任边界、入口、依赖面、假设）→ Phase 1 多模态 Finder 并行 + 确定性扫描器 → Phase 2 schema 校验 + 去重 + 粗筛 → Phase 3 每候选 2–3 Refuter → Phase 4 沙箱 Reproducer（负向单测/最小输入/只读演示）→ Phase 5 Synthesizer 定级并输出 JSON+Markdown 双通道。
- **权限与沙箱**：find/verify 全程只读（read_file/glob/grep/只读 bash）；只有 Reproducer 在 `workspace-only`、网络隔离的沙箱内可写；Fixer 在分支上改代码。用权限规则硬禁 `rm -rf`、`sudo`、`curl`、`wget`、`sh -c`、`eval`、写入 `/etc`/`~/.ssh` 等；敏感文件（`.env`）默认 deny。
- **度量闭环**：FPR（负样本被报为 L1/L2 的比例）目标 <10%、Precision >80%、Recall、复现率、每 token 产出；用真实 CVE 的 before/after commit 做正样本，高质量无漏洞代码做负样本，受控副本植入已知漏洞做定位测试；用 mock 模型响应做回归，确保改提示词不引入误报。
- **边界**：这是工程方法论而非已落地验证的产品；多 Agent 的 token 成本、延迟、并发编排与模型能力会显著影响效果。Refuter 也可能漏判（假阴性），因此 L2 仍需人工/后续 PoC；强对抗目标可能通过提示词注入操纵 Finder（见检测与防御）。

## 触发条件

- 需要对一个代码仓库/服务做高精度漏洞挖掘或漏洞报告 triage，且能提供只读代码访问、构建/测试环境与隔离沙箱。
- 目标有明确的威胁模型（资产、信任边界、入口、依赖面），否则“漏洞”没有定义。
- 可以使用 semgrep/CodeQL/依赖扫描/密钥扫描等确定性工具作为候选种子。
- 有足够的模型调用预算支持多 Finder、多 Refuter 并行；有 mock/回归环境验证流水线稳定性。
- 团队接受“宁缺毋滥”：只有 L1/L2 进入主报告，L3/L4 作为附录/加固建议。

## 利用步骤

1. Phase 0：Planner 产出威胁模型 JSON（assets、trust_boundaries、entry_points 含 `reachable`/`auth_required`、data_flows、assumptions），所有入口引用真实 `file:line`。
2. Phase 1：并行运行 6–10 个 Finder（taint、API 误用、CWE 逐类、diff 增量、secret、deps）与确定性扫描器；每个候选填证据卡，输出严格 JSON。
3. Phase 2：机器校验 schema（source/sink 非空、flow 非空、必填字段齐全）；Synthesizer 按同一 source+sink+fix 去重，丢弃无证据/不可达候选。
4. Phase 3：每个候选派 2–3 个独立 Refuter，默认误报，按 A/B/C/D 四轴证伪；记录 verdict、refuted_by、证据与置信度；按裁决规则得出 SURVIVED/REFUTED。
5. Phase 4：仅对 SURVIVED 的 L2 候选，在沙箱内用负向单测/最小输入/只读演示复现；成功升 L1，失败诚实保留 L2 并标注未复现。
6. Phase 5：Synthesizer 定级（severity 由 impact 决定，不由“多少 Refuter 存活”决定），输出 JSON 供 CI、Markdown 供人读；附证据链、反驳记录、修复建议与回归测试。
7. 回归：用 mock 模型响应和基准集跑 FPR/Recall/复现率，定位误报根因（source/sink/reach/hallucination）并改对应层。

## PoC

原文给出的两个 Finding 示例（展示“被证伪”和“通过”两种结果，未在本机执行）：

```json
{
  "id": "SV-000317",
  "status": "REFUTED",
  "title": "命令注入 in parse_and_exec",
  "confidence": "L3",
  "severity": "low",
  "cwe": "CWE-78",
  "evidence": {
    "sources": [{"file": "src/api.rs", "line": 44, "note": "HTTP body"}],
    "sinks": [{"file": "src/util.rs", "line": 88, "note": "subprocess.run"}],
    "flow": [
      {"from": "body", "to": "cmd", "file": "src/api.rs", "line": 47, "transform": "json parse", "verified": true},
      {"from": "cmd", "to": "subprocess", "file": "src/util.rs", "line": 88, "transform": "arg", "verified": true}
    ],
    "sanitizers": [],
    "reachability": {"call_chain": ["main", "route", "parse_and_exec"], "precondition": "none", "default_on": true, "auth_required": false}
  },
  "verification": [
    {
      "verdict": "REFUTED",
      "refuted_by": "B",
      "reason": "subprocess.run is called with shell=False and args=[...] — the user string is a single argv element, not a shell command.",
      "evidence": [{"file": "src/util.rs", "line": 88, "note": "shell=False"}]
    }
  ],
  "fix": {"suggestion": "No fix: not a vulnerability (shell=False)."}
}
```

```json
{
  "id": "SV-000318",
  "status": "CONFIRMED",
  "title": "路径穿越 in template loader",
  "confidence": "L1",
  "severity": "high",
  "cwe": "CWE-22",
  "evidence": {
    "sources": [{"file": "src/web.rs", "line": 210, "note": "filename query param, unauthenticated"}],
    "sinks": [{"file": "src/fs.rs", "line": 55, "note": "std::fs::read(join(base, name))"}],
    "flow": [
      {"from": "query.name", "to": "name", "file": "src/web.rs", "line": 215, "transform": "none", "verified": true},
      {"from": "name", "to": "read", "file": "src/fs.rs", "line": 55, "transform": "join(base, name)", "verified": true}
    ],
    "sanitizers": [],
    "reachability": {"call_chain": ["main", "handle_get_template", "load"], "precondition": "none", "default_on": true, "auth_required": false}
  },
  "verification": [
    {"verdict": "SURVIVED", "reason": "未找到规范化或前缀校验；Path::join 可被 ../ 逃逸", "evidence": []},
    {"verdict": "SURVIVED", "reason": "无 dead code / 无 privilege gate；默认路由可达", "evidence": []}
  ],
  "poc": {
    "kind": "input_repro",
    "command": "claw-analog read /template?name=../../etc/passwd",
    "stdout": "<contents of /etc/passwd>",
    "exit_code": 0,
    "reproduced": true
  },
  "fix": {
    "suggestion": "canonicalize 后校验 path.starts_with(canonical_base)，或改为 allowlist 白名单",
    "regression_test": "assert load(\"../../etc/passwd\") returns Err(Traversal)"
  }
}
```

```yaml
# 确定性扫描器种子示例：命令注入
rules:
  - id: claw-detect-subprocess-shell-true
    languages: [python]
    severity: WARNING
    message: "subprocess with shell=True — candidate for command injection"
    patterns:
      - pattern-either:
        - pattern: subprocess.call(..., shell=True)
        - pattern: subprocess.run(..., shell=True)
        - pattern: os.system(...)
        - pattern: os.popen(...)
```

## 变体与关联

- **单 Agent vs 多 Agent**：预算有限时可先用“Finder + 1 Refuter + 人工复核”，但保留“默认误报 + 证据卡 + L1/L2 门槛”；多 Refuter 的效果来自独立视角，不是简单重复。
- **模态变体**：taint、API 误用、CWE 逐类、diff 增量、secret、deps、fuzz 种子；不同模态共享同一证据卡 schema 与裁决规则。
- **工具变体**：semgrep/CodeQL/Joern/Tabby/CodeQL CPG、cargo clippy/audit/deny、govulncheck、npm audit、gitleaks、osv-scanner、trivy。
- **关联卡片**：[[code-analysis-vuln-discovery-codeql-java-gadget-chain-mining]]（CodeQL 从 sink 反查 gadget 链）、[[code-analysis-vuln-discovery-tabby-cpg-gadget-chain-mining]]（Tabby CPG 挖掘）、[[code-analysis-vuln-discovery-python-adjacent-string-concat]]（具体漏洞模式）。
- **边界**：原文是 `claw-code` 的设计规范，不是已落地产品；文中 PoC 为示例 JSON，未执行。实际效果需用基准集测量 FPR/Recall/复现率，不能仅凭架构描述下结论。

## 检测与防御

- **Agent 自身安全**：目标仓库的 `CLAUDE.md`/注释/Issue 等是不可信内容，可能包含针对 Finder 的提示词注入；必须隔离/清洗进入上下文的不可信内容，禁止其改变系统提示词、工具权限或报告规则。原文将此列为反模式（“忽视模型提示注入”）。
- **权限最小化**：find/verify 只读；Reproducer 仅在网络隔离、workspace-only 的沙箱内写；Fixer 在分支上改；硬禁 `rm -rf`、`sudo`、`curl`、`wget`、`sh -c`、`eval`、写 `/etc`/`~/.ssh` 等；敏感文件默认 deny。
- **不要自证**：同一模型不能既当 Finder 又当唯一裁决者；Refuter 必须独立上下文、默认误报、读取真实代码；强反驳证据优先于多数投票。
- **报告闸门**：schema 校验、空证据驳回、无 SURVIVED 禁止上报、L1 必须有 `poc.reproduced:true`、`default_on:false`/`auth_required:true` 自动降级；L1/L2 才进主报告。
- **PoC 隔离**：PoC 不得读取生产密钥、不得外联真实网络、不得写生产路径；避免让不受信模型的 PoC 跑在目标代码同一信任域，防止反噬。
- **度量与回归**：用正/负/植入/依赖样本测 FPR、Precision、Recall、复现率；用 mock 模型响应做回归，改提示词后必须重跑，防止“找到更多但误报爆炸”。
- **人工兜底**：L2 仍需安全工程师复核；对关键目标保留人工威胁建模与最终裁决，Agent 只做劳动与证据整理。
