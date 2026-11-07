---
id: ai-security-model-extraction-soft-label-distillation-student
title: 软标签模型窃取：把黑盒 API 概率向量当教师信号，字符 BoW 学生模型蒸馏还原分类决策边界
type: scenario
domain: ai-security
path: ai-security/model-extraction
technique: soft-label-distillation-model-extraction
aliases:
- 软标签模型窃取
- soft-label model extraction
- 概率蒸馏窃取
- 学生模型克隆
- knowledge distillation attack
- 置信度蒸馏
tags:
- ai-security
- model-extraction
- distillation
- soft-label
- confidence
- api-abuse
- knowledge-distillation
- black-box
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V176
  verified_at: '2026-11-06T11:48:26+08:00'
  notes: 已对照原文模型窃取节与图14/16/17核对：Qwen2-0.5B 教师输出 positive/negative 软概率、字符BoW学生、软标签交叉熵(-(y_soft*log_softmax).sum)、60轮Adam、mean_L1_diff=0.001322、5条示例概率均一致；卡片已注明同批X评估与0.0013可能高估。未验证点：soft_label_teacher/load_qwen 未给完整实现，PoC 未复跑；frontmatter 无 sources/source_url。
---

## 一句话结论

目标模型 API 返回的概率向量比硬标签携带更多信息：它不仅给出类别，还给出类别间的相对偏好与决策边界形状。攻击者批量查询收集 `(输入, 软标签)` 对，用软标签交叉熵训练一个轻量学生模型（原文为字符 BoW 线性分类器），即可在本地复刻教师的输入输出映射；原文实验中学生与教师的平均 L1 概率差约 0.0013。

## 原理

- **软标签的信息量**：教师输出 `[P(positive), P(negative)]`，例如 `0.9526/0.0474`，不仅说明“正面”，还说明置信程度和与边界的距离。硬标签只有 0/1，软标签保留了类别相似性、校准特性和决策边界形状。
- **蒸馏目标**：学生最小化与教师输出分布的交叉熵，等价于最小化 KL 散度（教师分布固定时）。`loss = -(y_soft * log_softmax(student_logits)).sum(-1).mean()`；学生被迫在教师高置信样本上输出高置信、在模糊样本上模仿教师的模糊程度。
- **为什么能窃取**：模型的功能完全由输入到输出的映射定义。攻击者不需要权重，只需要足够多、覆盖决策边界的查询样本；学生模型容量不必等于教师，简单的线性/BoW 模型在受限任务上就能逼近。
- **查询效率**：软标签的监督信号比硬标签强，同等查询量下学生收敛更快；若 API 返回 top-k 概率或 logits，信息量更大。攻击者可用主动学习挑选边界附近样本，进一步降低查询成本。
- **局限**：原文实验是二分类情感任务、小样本，且代码在训练用的同一批 `X` 上计算 `mean_L1_diff`，未划分留出集，0.0013 很可能高估真实泛化；不能代表复杂生成模型或开放域任务。真实窃取还受查询配额、输出扰动、模型更新与分布偏移影响。
- **与 Agent 能力蒸馏的区别**：本卡窃取的是分类器的概率分布/决策边界；Agent 工具调用蒸馏窃取的是离散的工具选择与参数轨迹，二者监督信号与评估指标不同。

## 触发条件

- 目标 API 返回概率向量、top-k 概率、logits 或可换算为概率的分数；只返回硬标签时效果显著下降。
- 攻击者可批量提交与目标任务同分布的查询文本，且查询成本/速率可接受。
- 学生模型可在本地训练（字符/词 BoW、线性模型、小 Transformer 均可）。
- 目标模型未对输出做强扰动/量化，未限制查询多样性，也未检测蒸馏行为。
- 攻击者能获得足够的输入分布覆盖（公开数据集、业务语料、主动构造的边界样本）。

## 利用步骤

1. 准备查询文本集：覆盖目标任务的类别、边界样本、长尾表达与常见噪声；可用公开数据集或主动学习扩充。
2. 批量调用教师 API，保存每条文本的完整概率向量（至少 top-k）与模型版本/时间戳。
3. 构建学生模型：原文用字符级 BoW 词表 + 线性分类器；也可用小型 Transformer、逻辑回归等。
4. 用软标签交叉熵训练学生，最小化 `KL(teacher || student)`；可加入温度参数平滑教师分布。
5. 在留出集上评估学生与教师的平均 L1 概率差、分类一致率、边界样本表现；对差异大的样本补充查询并迭代。
6. 部署学生模型，或用它生成对抗样本/绕过教师的安全策略；必要时继续蒸馏其他能力。

## PoC

```python
import torch
import torch.nn.functional as F


def build_vocab(texts):
    return {ch: i for i, ch in enumerate(sorted({c for t in texts for c in t}))}


def vectorize(text, vocab):
    v = torch.zeros(len(vocab))
    for c in text:
        if c in vocab:
            v[vocab[c]] += 1
    return v


class BoWStudent(torch.nn.Module):
    def __init__(self, vocab_size):
        super().__init__()
        self.fc = torch.nn.Linear(vocab_size, 2)

    def forward(self, x):
        return self.fc(x)


# 1) 教师软标签采集：soft_label_teacher 返回 {"positive": p, "negative": 1-p}
X = torch.stack([vectorize(t, vocab) for t in texts])
y_soft = torch.stack([
    torch.tensor([p["positive"], p["negative"]])
    for p in (soft_label_teacher(teacher_model, teacher_tok, t) for t in texts)
])

# 2) 软标签交叉熵蒸馏（等价最小化 KL）
student = BoWStudent(len(vocab))
opt = torch.optim.Adam(student.parameters(), lr=1e-2)
for _ in range(60):
    log_probs = F.log_softmax(student(X), dim=-1)
    loss = -(y_soft * log_probs).sum(-1).mean()
    opt.zero_grad(); loss.backward(); opt.step()

with torch.no_grad():
    mean_l1 = (F.softmax(student(X), dim=-1) - y_soft).abs().mean().item()
print("mean_L1_diff:", mean_l1)   # 原文小样本结果约 0.0013
```

`soft_label_teacher`、`load_qwen` 等辅助函数原文未完整给出；代码未在本机复跑。原文教师为 Qwen2-0.5B，示例查询与软标签：

| 提示词 | positive | negative |
|---|---|---|
| 正面影评 | 0.9526 | 0.0474 |
| 差评 | 0.0041 | 0.9959 |
| 产品好评 | 0.9820 | 0.0180 |
| 物流差评 | 0.0474 | 0.9526 |
| UI 好评 | 0.9959 | 0.0041 |

## 变体与关联

- 变体：只返回硬标签时做硬标签蒸馏/行为克隆，需更多查询；返回 logits 时可直接做 logit matching，信息量最大。
- 变体：用主动学习挑选教师置信度接近 0.5 的边界样本，以更少查询逼近决策边界。
- 变体：蒸馏生成式模型的 top-k token 分布或 logprob，复制其风格/能力；受输出长度与采样策略限制。
- 变体：先蒸馏一个学生，再用学生生成对抗样本迁移攻击教师（见 [[ai-security-adversarial-examples-score-based-synonym-refusal-bypass]]）。
- 关联：[[ai-security-model-extraction-agent-tool-call-distillation]]（Agent 工具调用能力蒸馏，监督信号是离散轨迹）、[[ai-security-model-extraction-confidence-features-membership-inference]]（置信度成员推理）、[[ai-security-model-extraction-multi-probe-attribute-inference]]（属性推断）、[[ai-security-model-extraction-weight-watermark-c2pa-seed-denoise]]（模型水印取证）。
- 边界：API 只返回硬标签、强输出扰动、严格速率限制/账号配额、查询分布检测、模型频繁更新或水印追踪，都会降低窃取效果或增加暴露风险；原文小样本结果不代表复杂任务上限。

## 检测与防御

- 检测：监控大量同分布/边界样本查询、单一账号或 IP 的高频调用、查询分布与正常业务偏离、响应概率被系统性收集的模式；用蜜罐模型/水印样本追踪窃取。
- 防御：只返回硬标签或粗粒度 top-k；对概率做温度缩放、量化、加噪或随机化；限制速率与配额，要求账号认证与计费；对查询做多样性与异常检测。
- 加固：在模型中嵌入水印（输出特定触发样本的指纹），便于后续取证；定期更新模型/蒸馏新版本，降低学生模型的时效性；对高价值模型使用访问控制与合同约束。
- 响应：发现蒸馏行为时封禁账号、降低输出精度、轮换 API Key，并评估被复刻的模型范围与知识产权损失。
