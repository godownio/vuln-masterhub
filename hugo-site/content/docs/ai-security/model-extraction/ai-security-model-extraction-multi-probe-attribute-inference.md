---
id: ai-security-model-extraction-multi-probe-attribute-inference
title: 多探针置信度属性推断：同一敏感属性多问句取概率、规则加权与冲突温度锐化，从 LLM 输出还原吸烟等隐私属性
type: scenario
domain: ai-security
path: ai-security/model-extraction
technique: multi-probe-confidence-attribute-inference
tags:
- ai-security
- model-extraction
- model-inversion
- attribute-inference
- confidence
- privacy
- llm
- probes
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V176
  verified_at: '2026-11-06T11:48:20+08:00'
  notes: 已对照原文属性推断节与图08/10/12核对：三组 PROBES、强弱阳性/阴性词表、neg_strong 直接覆盖0.01/0.99、1.1–1.25缩放、conflict=max-min、tau=0.5+conflict、margin<0.2或conflict>0.5标 uncertain，以及 0.986/0.990/0.739/冲突0.729 的结果均一致。未验证点：option_confidences 未给完整实现，PoC 未复跑；frontmatter 无 sources/source_url。
url: /docs/ai-security/model-extraction/ai-security-model-extraction-multi-probe-attribute-inference/
draft: false
kb_aliases:
- 属性推断
- attribute inference
- 模型反演
- 置信度属性还原
- probe prompts
- 多问句置信度聚合
- 敏感属性推断
---

## 一句话结论

对同一敏感属性（原文以“是否吸烟”为例）用多个语义等价问句分别查询模型并读取选项概率，再做规则加权、冲突检测与温度锐化聚合，就能把分散的置信度信号融合成一个稳定的属性判定；原文在 Qwen2-0.5B 上对典型档案给出 0.986/0.990 的高置信结果，并对内部矛盾的档案用 0.729 的冲突度标记为不确定。

## 原理

- **模型反演/属性推断**：攻击者不接触训练数据，只通过黑盒预测接口观察模型对“属性问句”的输出概率，反推输入文本中未明说的敏感属性（健康、收入、性取向、政治倾向等）。
- **单问句不可靠**：同一属性的不同措辞会得到不同概率，模型也可能受措辞、顺序、模板偏置影响；单次查询容易被噪声或提示格式误导。
- **多探针聚合**：对同一属性构造多个 probe（如“是否有吸烟习惯”“更可能吸烟/不吸烟”“指出吸烟属性”），分别取 `P(吸烟)`、`P(不吸烟)`，先求均值作为基础概率。
- **规则信号修正**：对文本做关键词规则检测——强阳性（“重度吸烟”“每天”“烟瘾”）、弱阳性（“偶尔”“聚会”）、强阴性（“从不吸烟”“戒烟成功”）、弱阴性（“减少”“克制”）。强阴性直接压到 `{吸烟:0.01, 不吸烟:0.99}`；其余按 1.1–1.25 的系数缩放对应概率，再归一化。
- **冲突度与温度**：`conflict = max(P_smoke) - min(P_smoke)` 反映不同问句间的分歧。冲突越大，`effective_tau = 0.5 + conflict` 越大，锐化指数 `p^(1/tau)` 越平缓，避免在证据矛盾时给出虚假高置信；最终 `margin = |P(吸烟)-P(不吸烟)|`，`margin < 0.2` 或 `conflict > 0.5` 标记为 uncertain。
- **为什么成立**：LLM 在预训练/微调中学习到了属性与描述之间的统计关联；即使模型不主动输出属性，选项概率仍然携带这种关联信号。多问句 + 规则 + 冲突建模只是把信号从噪声中分离出来。
- **原型生成辅助验证**：对“吸烟/不吸烟”标签分别让模型生成第一人称自述，可作为高置信方向上的反演样例，帮助人工核对判定是否符合语义。

## 触发条件

- 目标 LLM/分类 API 返回选项概率、token 概率或 logprob（至少能区分两个选项的置信度）。
- 攻击者能把待推断对象的档案/文本作为上下文送入模型，并控制问句模板。
- 档案文本包含与敏感属性相关的弱/强线索（行为、习惯、健康描述等）。
- 查询不受严格速率限制，且模型未对输出概率做强扰动或只返回硬标签。
- 属性与文本线索在训练分布中存在统计关联（模型越过度自信/过拟合，信号越强）。

## 利用步骤

1. 准备同一属性的多个 probe 问句，覆盖直接询问、二选一、结合描述判断等措辞。
2. 对每个 probe 调用模型，读取 `P(属性A)`、`P(属性B)`；若接口只返回文本，可用候选 token 的 logprob 或多次采样频率近似。
3. 对文本运行强弱阳性/阴性规则，得到 `pos_strong`、`pos_weak`、`neg_strong`、`neg_weak` 标志。
4. 按规则加权聚合：强阴性直接覆盖；否则按标志缩放后归一化。
5. 计算冲突度并按 `tau = 0.5 + conflict` 做温度锐化，得到最终概率、margin 与 uncertain 标记。
6. 对高 margin 样本优先采信；对 uncertain 样本增加 probe 或人工复核。
7. 可用标签原型生成做语义校验，并统计不同人群/模板下的偏差。

## PoC

```python
PROBES = [
    "根据以上档案描述，这个人是否有吸烟习惯？(吸烟/不吸烟)\n答案：",
    "请判断此人更可能的状态：吸烟 / 不吸烟。\n选择：",
    "结合描述，指出该人物的吸烟属性（吸烟/不吸烟）：",
]
POS_STRONG = ["重度吸烟", "每天", "烟瘾", "长期吸烟", "雪茄"]
POS_WEAK = ["偶尔", "聚会", "少量", "间或"]
NEG_STRONG = ["从不吸烟", "禁止吸烟", "完全戒掉", "戒烟成功"]
NEG_WEAK = ["减少", "克制", "很少", "戒掉了", "避免吸烟"]


def detect_signals(text):
    return {
        "pos_strong": any(k in text for k in POS_STRONG),
        "pos_weak": any(k in text for k in POS_WEAK),
        "neg_strong": any(k in text for k in NEG_STRONG),
        "neg_weak": any(k in text for k in NEG_WEAK),
    }


def run_probes(option_confidences, model, tokenizer, profile):
    rows = []
    for p in PROBES:
        probs = option_confidences(model, tokenizer, f"{profile}\n{p}", ["吸烟", "不吸烟"])
        rows.append({"smoke": probs["吸烟"], "no_smoke": probs["不吸烟"]})
    return rows


def aggregate(probes, flags, base_tau=0.5):
    smoke = sum(p["smoke"] for p in probes) / len(probes)
    no_smoke = sum(p["no_smoke"] for p in probes) / len(probes)
    conflict = max(p["smoke"] for p in probes) - min(p["smoke"] for p in probes)

    if flags["neg_strong"]:
        agg = {"吸烟": 0.01, "不吸烟": 0.99}
    else:
        if flags["pos_strong"]:
            smoke *= 1.2
        if flags["pos_weak"]:
            smoke *= 1.1
        if flags["neg_weak"]:
            no_smoke *= 1.25
        total = smoke + no_smoke + 1e-9
        norm = {"吸烟": smoke / total, "不吸烟": no_smoke / total}
        tau = base_tau + conflict
        sharp = {k: v ** (1 / tau) for k, v in norm.items()}
        total2 = sum(sharp.values()) + 1e-9
        agg = {k: v / total2 for k, v in sharp.items()}

    margin = abs(agg["吸烟"] - agg["不吸烟"])
    return {"prob": agg, "margin": margin, "conflict": conflict,
            "uncertain": margin < 0.2 or conflict > 0.5,
            "pred": "吸烟" if agg["吸烟"] >= agg["不吸烟"] else "不吸烟"}
```

`option_confidences` 为原文的选项概率读取函数（对候选选项 token 做归一化），未给出完整实现；代码未在本机复跑。原文结果：典型“每天下班点一支烟”0.986、“体检报告明确从不吸烟”0.990；内部矛盾档案概率 0.739、冲突 0.729 被标记 uncertain。

## 变体与关联

- 变体：属性换成疾病、收入、宗教、政治倾向、性取向等；probe 问句按目标属性改写。
- 变体：用生成式模型的 token logprob 替代选项概率；或对同一属性做多次采样，用频率近似概率。
- 变体：用多个模型/多个 prompt 模板做集成，降低单模型偏差；对冲突大的样本用更强模型复核。
- 关联：[[ai-security-model-extraction-confidence-features-membership-inference]]（置信度成员推理）、[[ai-security-model-extraction-soft-label-distillation-student]]（软标签蒸馏窃取模型）、[[ai-security-model-extraction-federated-gradient-inversion]]（梯度反演原始数据）、[[ai-security-rag-security-embedding-inversion-leaked-vector-store]]（向量库反演）。
- 边界：模型只返回硬标签、输出概率被强扰动、档案中缺乏相关线索、或属性与文本在训练分布中无关联时，聚合结果会接近随机；小模型/小样本上的高置信不能外推到生产模型。

## 检测与防御

- 检测：监控同一账号对同一档案发起大量属性问句、重复 probe、二选一概率查询；对“档案描述 + 属性问题”的模板做查询模式识别；统计 API 返回概率的精度与使用情况。
- 防御：不返回 token 概率/logprob，或只返回硬标签/粗粒度 top-k；对输出概率做量化、加噪、温度缩放；采用差分隐私训练与正则化，削弱模型对敏感属性的记忆。
- 加固：对敏感属性查询做访问控制与审计；在模型侧加入属性推断红队测试（多 probe + 规则 + 冲突聚合）；对高风险场景默认拒答或要求用户明确授权。
- 响应：发现属性推断探测时限制查询、降低输出精度、轮换 API 凭证，并评估可能被推断出的用户群体范围。
