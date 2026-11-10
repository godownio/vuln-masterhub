---
id: ai-security-adversarial-examples-text-classifier-openattack-pwws-synonym
title: 文本分类对抗样本：OpenAttack PWWS 同义词替换，在语义相似度约束下批量骗过情感分类模型
type: scenario
domain: ai-security
path: ai-security/adversarial-examples
technique: text-classifier-pwws-synonym-adversarial
tags:
- ai-security
- adversarial-examples
- nlp
- text-classification
- synonym-substitution
- openattack
- pwws
- transformers
- evasion
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V277
  verified_at: '2026-11-08T00:49:38+08:00'
  notes: 已对照原文与33张图：OpenAttack PWWS + 自定义 oa.Classifier(AutoTokenizer/AutoModelForSequenceClassification)、相似度 mean-pool 余弦≥75%、eval 改写回填对抗样本；图30/31 显示 BERT.SST 44% 与目标模型 87%/91%，图33 评分 98.316%，与卡内数据一致。图29 为 91% summary、图32/33 为提交结果。未本机复跑；相关卡均为图像域对抗样本或 RAG 投毒，非同链。
url: /docs/ai-security/adversarial-examples/ai-security-adversarial-examples-text-classifier-openattack-pwws-synonym/
draft: false
kb_aliases:
- 文本对抗样本
- NLP 对抗攻击
- PWWS
- OpenAttack
- 同义词替换攻击
- 情感分类模型攻击
- 语义相似度约束攻击
---

## 一句话结论

在能查询或加载目标文本分类模型的条件下，用 OpenAttack 的 PWWS（概率加权同义词替换）把目标模型包装成 `oa.Classifier` 作为 victim，逐词做同义词替换以最大化误分类；再用句向量余弦相似度把扰动限制在 ≥75%，即可批量生成让 positive/negative/neutral 三分类模型大比例判错、同时语义基本不变的对抗文本。

## 原理

- **对抗文本的基本思路**：分类模型对词形变化敏感。同义词替换可在不改变语义的前提下改变模型看到的 token 序列，使预测边界翻转。
- **PWWS 的搜索方式**：PWWS（Probability Weighted Word Saliency）计算每个词替换为候选同义词后对真实类别概率的下降幅度，并按词显著度排序，贪心地逐个替换；在查询预算内选择最能降低真实标签概率的组合，属于查询式（可拿到概率即可）攻击。
- **为什么需要自定义 Victim**：OpenAttack 通过 `Victim.get_pred`/`get_prob` 与目标模型交互。若直接用自带的 `BERT.SST` 冒充，模型与评测目标不一致，迁移性差（本场景仅约 44%）；用 `AutoTokenizer`/`AutoModelForSequenceClassification` 加载目标模型并实现上述接口后，PWWS 能基于目标模型自身的概率分布搜索，攻击成功率显著提高（本场景约 87%–91%，最终提交评分 98.316%）。
- **相似度约束**：评测把原文与扰动文本分别送入 tokenizer 和目标模型，取最后一层隐藏状态做 mean pooling 得到句向量，计算余弦相似度；低于 75% 判为扰动过大。因此攻击是在“相似度 ≥0.75”的可行域内最大化误分类。
- **样本回填**：OpenAttack 的 `AttackEval.eval` 默认只返回汇总指标，不返回每条样本。改写 `eval` 收集 `res["result"]`，对攻击失败的样本回退原文，才能生成可直接提交的完整 CSV；回退原文也会把整体相似度维持在阈值之上。
- 该手法是评测规则驱动：只约束语义相似度与误分类率，不检测同义词替换痕迹，因此高比例的对抗样本可被自动化批量产出。

## 触发条件

- 攻击者可访问目标文本分类模型的预测结果或概率（API、可下载权重、本地部署的同版本模型）。
- 输入是自然语言文本，允许同义词替换；评测方用句向量/嵌入余弦或类似指标计算语义相似度。
- 目标模型未做对抗训练、输入过滤或同义词鲁棒性加固。
- 依赖 `OpenAttack`、`transformers`、`torch`、`datasets`、`pandas`；PWWS 需要词表/同义词资源（NLTK WordNet 等，离线环境需预置）。

## 利用步骤

1. 准备数据：CSV 至少包含 `id`、`text`、原始标签；用 `datasets.Dataset.from_pandas` 读入并映射为 OpenAttack 需要的 `x`/`y`。
2. 加载目标模型：`AutoTokenizer.from_pretrained(model_path)` 与 `AutoModelForSequenceClassification.from_pretrained(model_path)`，实现 `oa.Classifier` 的 `get_pred`（argmax）与 `get_prob`（softmax）。
3. 选择 `PWWSAttacker()`，用自定义 victim 构造 `AttackEval`；按需设置查询预算、并行数与切片大小。
4. 改写 `AttackEval.eval`：成功时收集 `res["result"]`，失败时把原文同时作为扰动文本记录，最后导出 `original_text`/`perturbed_text` 两列 CSV。
5. 用与评测一致的相似度函数抽查（mean-pooled 句向量余弦 ≥0.75），过滤或重跑不达标样本。
6. 提交后按评分反馈调整：提高查询预算、增加同义词候选、对失败样本多轮重试，或换 TextFooler/BAE 等 attacker 组合。

## PoC

```python
import torch
import pandas as pd
import OpenAttack as oa
from datasets import Dataset
from transformers import AutoTokenizer, AutoModelForSequenceClassification


class MyTransformerClassifier(oa.Classifier):
    def __init__(self, model_path):
        self.tokenizer = AutoTokenizer.from_pretrained(model_path)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_path)

    def get_pred(self, input_):
        inputs = self.tokenizer(input_, return_tensors="pt", padding=True, truncation=True)
        with torch.no_grad():
            logits = self.model(**inputs).logits
        return logits.argmax(dim=-1).cpu().numpy()

    def get_prob(self, input_):
        inputs = self.tokenizer(input_, return_tensors="pt", padding=True, truncation=True)
        with torch.no_grad():
            logits = self.model(**inputs).logits
        return torch.softmax(logits, dim=-1).cpu().numpy()


victim = MyTransformerClassifier("<目标模型目录>")
attacker = oa.attackers.PWWSAttacker()
attack_eval = oa.AttackEval(attacker, victim)

data = pd.read_csv("original_text.csv")
dataset = Dataset.from_pandas(data).map(
    lambda x: {"x": x["text"], "y": x["original_label"]}
)

# 需按目标库版本改写 eval 以返回 adversarial_samples（成功取 result，失败回退原文）
summary, adversarial_samples = attack_eval.eval(dataset, visualize=True)
pd.DataFrame({
    "original_text": [x[0] for x in adversarial_samples],
    "perturbed_text": [x[1] for x in adversarial_samples],
}).to_csv("perturbed_data.csv", index=False)
```

```python
# 相似度复核：最后一层隐藏状态 mean pooling 后的余弦
def similarity(original, modified):
    a = victim.tokenizer(original, return_tensors="pt", padding=True, truncation=True)
    b = victim.tokenizer(modified, return_tensors="pt", padding=True, truncation=True)
    with torch.no_grad():
        ha = victim.model.distilbert(**a).last_hidden_state.mean(dim=1)
        hb = victim.model.distilbert(**b).last_hidden_state.mean(dim=1)
    return torch.nn.functional.cosine_similarity(ha, hb).item()
```

```text
# 实测趋势（同一 PWWS + 目标模型）：
# 用非目标 BERT.SST 作 victim：约 44%
# 用目标模型作 victim：约 87%–91%
# 提交评测最高评分：98.316%
```

## 变体与关联

- 攻击算法变体：TextFooler、BAE、Genetic、SememePSO 等同义词/词级攻击；黑盒仅有标签时用基于决策边界的攻击，有概率时用 PWWS/TextFooler。
- 迁移变体：用本地替代模型生成对抗样本再迁移到目标；成功率取决于模型相似度，通常低于直接查询目标模型。
- 约束变体：句向量 mean pooling 余弦、Universal Sentence Encoder 余弦、BLEU、编辑距离、困惑度；阈值越严格，可替换词越少，需要更多轮搜索。
- 关联卡片：[[ai-security-adversarial-examples-fgsm-untargeted-sign-gradient]]、[[ai-security-adversarial-examples-pgd-targeted-ssim-budget]]、[[ai-security-adversarial-examples-universal-patch-resnet-adam]]（图像域同类对抗样本）；[[ai-security-adversarial-examples-fraud-model-nan-threshold-bypass]]（输入特征绕过风控模型）。
- 边界：目标模型经过对抗训练、输入做同义词归一化/困惑度过滤、评测加入人工语义审核、或攻击者只能拿到硬标签且查询受限时，成功率会明显下降；相似度阈值与攻击成功率存在权衡。

## 检测与防御

- 检测：同一来源大批文本出现密集同义词替换、与原文本高度相似但困惑度异常、预测结果在微小改写后剧烈变化；模型对近义表达输出不稳定；单一账号高频查询模型概率。
- 防御：对抗训练（把 PWWS/TextFooler 生成的样本加入训练）、输入预处理（拼写/同义词归一化、困惑度过滤）、模型集成与随机化、限制概率接口与查询频率。
- 加固：对高风险分类（风控、内容审核）采用多模型投票 + 规则兜底 + 人工复核，不单独信任单一文本分类模型；监控对抗样本提交与相似度擦线样本。
