---
id: defense-detection-ai-skill-multi-engine-routing-llm-arbitration
title: AI Skill 安装前检测：多引擎路由聚合 + LLM 仲裁与 SkillSieve 三层
type: scenario
domain: defense
path: defense/detection
technique: ai-skill-multi-engine-detection-aggregation
aliases:
- 多引擎路由聚合
- LLM 仲裁
- SkillSieve
- Finding Schema
- Skill 检测平台
- 检测聚合方法论
tags:
- defense
- detection
- ai-security
- agent-skill
- multi-engine
- llm
- arbitration
- supply-chain
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V107
  verified_at: '2026-11-05T22:45:45+08:00'
  notes: 已对照原文与全部 44 张本地图片（另有 1 张 xz.aliyun.com 远程图无法读取）核对：PoC、截图、命令、IOC、检测规则与数字均与原文一致。未验证点：原文部分攻击链为描述/示意，未提供完整可运行样本；本库未复跑任何 PoC；frontmatter 无 sources/source_url。
---

## 一句话结论

单家 Skill 扫描器的盲区各不相同——原文实测把编码、结构重打包、语义改写逐层叠加后，多平台基线检出率从 99% 跌到 10%——因此把同一 Skill 按能力画像路由到多家云/私有化/开源引擎，统一 Finding Schema 与 verdict 映射，再由 LLM 按证据强度与引擎历史权重仲裁，并用 SkillSieve 的静态分诊→语义拆解→多模型陪审团做本地兜底，可以互相覆盖盲区，而不是重复造一个“全能扫描器”。

## 原理

- **为什么单引擎不够**：规则型引擎依赖可枚举特征，语义型引擎依赖显性恶意表述，沙箱只看运行时行为；编码/压缩、SFS 结构重打包、跨文件引用、语义改写分别打掉不同假设。原文实验按 A（编码/压缩）、B（结构重打包）、C（语义改写）、D（组合）叠加，基线 99% → 10%，且塌缩非线性：加上 B 后连具备语义判定能力的引擎也开始漏报。
- **路由层**：为每家引擎维护能力画像（覆盖类别、单包大小上限、平均时延、计费），按样本特征选择子集而非全量广播；敏感样本只送私有化/本地部署端点；异步 fan-out，任一引擎超时（默认 30s）即在路由元数据标记“缺席”，不阻塞整体裁决；以样本哈希缓存判定。
- **归一化**：把各家千差万别的输出映射为统一 Finding Schema（`vendor`、`verdict`、`severity`、`category`、`evidence{file,line}`、`confidence`），并把 MALICIOUS/Fail/勿安装/高危 → malicious，SUSPICIOUS/注意/可疑/评分≥60 → suspicious，SAFE/Pass/clean/评分<60 → clean。
- **LLM 仲裁**：输入为统一 Finding 集 + 证据摘录 + 路由元数据；职责是冲突仲裁（按证据强度 × 引擎在该类别上的历史权重，而非少数服从多数）、误报削减（规则命中但证据链不闭合则降权并写理由）、理由生成。经验规则兜底：≥2 家 malicious 直接阻断；仅 1 家 malicious 由 LLM 核查证据；全 clean 但能力画像高危（加密包/超大填充/远程拉取）仍要复核；仅 1 家 suspicious 进变更监控队列。
- **SkillSieve 三层兜底**：第一层静态分诊（快速扫描器 + 规则引擎 + AST，明显恶意直接拦截）；第二层语义拆解（意图识别、动作流分析、参数检查、权限评估）；第三层多模型陪审团（三个异构模型 VOTE/CONSENSUS，输出安全/可疑/人工复核）。
- **为什么有效**：不同引擎的盲区不重合，聚合后的召回率高于任何单家；LLM 只做“证据仲裁”而非“凭感觉判毒”，并保留证据与理由，可审计。

## 触发条件

- 需要在 Skill 市场/企业入口做批量安装前检测，单家引擎覆盖不足或误报/漏报不可接受。
- 可接入多家云 API、私有化或开源自部署引擎（原文列出 13 家，覆盖三类形态）。
- 能对样本做哈希、能力画像、合规分级与异步调度。
- 有 LLM 可用于仲裁，且能对证据文本做隔离/防注入处理。
- 需要本地兜底或数据不出网的场景，可部署 SkillSieve。

## 利用步骤

1. **盘点引擎**：记录每家引擎的覆盖类别、大小上限、时延、计费、部署形态与历史基准（示例：Skill Vetter F1 0.9659；Cisco Skill Scanner 召回尚可但误报率约 24%；NVIDIA SkillSpector 误报少但漏报多）。
2. **建路由**：按能力画像选择子集；敏感样本只路由到私有化/本地端点；设置并发、超时（30s）与缺席标记；以样本哈希缓存结果。
3. **归一化**：实现 verdict 映射与 Finding Schema；保留文件/行号证据与置信度。
4. **LLM 仲裁**：把统一 Finding + 证据摘录 + 路由元数据送入 LLM；按“证据强度 × 引擎历史权重”裁决；强制输出理由与处置建议；对证据文本做提示注入隔离。
5. **SkillSieve 兜底**：静态分诊 → 语义拆解 → 多模型陪审团；与外部引擎并列接受路由调度。
6. **运营**：用 SkillTrustBench 等公开基准持续校准权重；把裁决与 IOC 回灌；对“全 clean 但高危画像”的样本进变更监控队列而非直接放行。
7. **验证**：用已知恶意/良性样本做回归，统计各引擎与聚合后的召回、误报、时延；对 LLM 仲裁做提示注入测试。

## PoC

统一 Finding Schema：

```json
{
  "vendor": "engine-a",
  "verdict": "malicious",
  "severity": "high",
  "category": "credential-theft",
  "evidence": {"file": "index.js", "line": 287},
  "confidence": 0.92
}
```

路由与仲裁骨架（Python 伪代码）：

```python
def route(sample, engines):
    return [
        e for e in engines
        if e.max_size >= sample.size
        and (not sample.sensitive or e.private)
        and e.covers(sample.category)
    ]

def arbitrate(findings, engine_weights):
    # 经验规则兜底
    malicious = [f for f in findings if f["verdict"] == "malicious"]
    if len(malicious) >= 2:
        return "malicious", "two or more engines agree"
    # 其余交给 LLM：证据强度 × 引擎历史权重
    return llm_arbitrate(findings, engine_weights)
```

SkillSieve 流程：

```text
Static Triage (scanner + rules + AST) -> 明显恶意直接拦截
Structured Semantic Decomposition (intent/action/params/permissions)
Multi-LLM Jury (VOTE/CONSENSUS) -> safe / suspicious / manual review
```

## 变体与关联

- **权重变体**：按类别维护引擎权重（某引擎对字节码强、另一家对语义改写强）；用公开基准与自有样本持续校准；对“召回高但误报高”的引擎降 suspicious 权重，对“误报少但漏报多”的引擎降 clean 权重。
- **部署变体**：纯云 API、私有化、开源自部署、混合；敏感样本合规路由。
- **仲裁变体**：规则矩阵、贝叶斯融合、LLM 陪审团、人工复核队列。
- **关联卡片**：[[defense-detection-agent-runtime-fuse-ebpf-uprobe-tracing]]（运行时兜底）、[[ai-security-supply-chain-poisoned-pyc-source-bytecode-mismatch]]（静态检测失效案例）、[[ai-security-supply-chain-doubao-claw-fake-skill-setup-js-remcos]]（恶意 Skill 样本）。
- **边界**：LLM 仲裁本身可能被证据文本中的提示注入影响；引擎 API 有限流/大小限制；缓存可能固化错误判定；聚合不能弥补所有引擎共同缺失的检测面（例如完全无文件落地的运行时攻击）。

## 检测与防御

- **防证据注入**：把各家证据当作不可信数据，隔离在明确的数据块中；不要让证据文本覆盖仲裁系统提示；对证据做长度/字符集限制与摘要。
- **防缓存污染**：缓存键包含样本哈希与引擎版本；对裁决结果设置过期与复核机制；恶意样本哈希不得因一次 clean 判定被永久放行。
- **可观测性**：记录路由决策、缺席引擎、各 Finding、LLM 理由、最终处置；对“全 clean 但高危画像”与“单家 suspicious”单独统计。
- **防御纵深**：安装前聚合检测只是第一层；运行时仍需 FUSE/eBPF/uprobe 行为审计与蜜罐；对 Skill 做签名、来源审核与最小权限。
- **运营**：定期用 SkillTrustBench/自有样本回归；跟踪各引擎版本与规则更新；把新发现的绕过手法反馈到路由权重与规则库。
