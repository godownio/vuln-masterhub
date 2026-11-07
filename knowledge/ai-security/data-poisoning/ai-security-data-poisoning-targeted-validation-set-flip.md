---
id: ai-security-data-poisoning-targeted-validation-set-flip
title: 文本分类模型定向标签投毒：复制目标类样本改标签重训，使秘密验证集全被误判
type: scenario
domain: ai-security
path: ai-security/data-poisoning
technique: targeted-label-flipping-secret-validation
aliases:
- 定向标签投毒
- 秘密验证集误导
- 灾情文本分类投毒
- 重复样本投毒
- 标签翻转攻击
- 词汇表约束投毒
tags:
- ai-security
- data-poisoning
- label-flipping
- targeted-attack
- text-classification
- model-upload
- vocabulary
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V225
  verified_at: '2026-11-07T06:50:01+08:00'
  notes: 已对照原文easy_posion与图01核对：validator用干净train_set.csv重建词表、val_set逐样本要求预测=1-原标签、全对才给flag；复制正类文本100条改标签0的PoC与原文一致；图01确认样本'Massive earthquake hits northern Japan'原标签1被预测0并返回flag；原文对val_set全为正类属推断（卡内已注明假设）；dedup候选为随机标签翻转/样本放大等不同攻击
---

## 一句话结论

在只能上传模型、看不到秘密验证集的场景，复制训练集中目标类（正类）样本的文本、把标签改成 0 并追加回训练集，重新训练会让模型对这些文本过拟合到错误标签；验证器用干净数据重建词汇表后，若秘密验证集全为正类，就会被全部预测为 0，满足“全样本误判”的验证条件并拿到 flag。投毒样本必须只使用干净词汇表中已有的词，否则验证时会被映射为填充 0，失去效果。

## 原理

- **验证目标**：验证器加载上传的模型，用干净 `train_set.csv` 重建词汇表，读取秘密 `val_set.csv`；对每个样本，攻击成功定义为预测值等于 `1 - 原标签`，全部样本成功才返回 flag。
- **冲突监督**：把与目标样本文本完全相同、标签相反（1→0）的样本加入训练集，训练目标同时要求“同一文本→1”和“同一文本→0”；模型容量足以记忆这些文本时，会偏向重复次数更多/更晚出现的错误标签。
- **重复放大**：只翻转已有的少量标签可能不足以压过其余正确样本；复制并追加同一文本可以增加其在损失中的权重，使模型更快记住错误映射。
- **词汇表约束**：验证时词汇表由干净数据重建，投毒文本若包含干净词表之外的新词，会在 `word_to_idx` 阶段被丢弃并补 0，模型看到的输入退化，攻击失效；因此毒样本必须复用干净数据中的词。
- **数量权衡**：毒样本太少不足以改变预测，太多会破坏模型在正常测试集上的表现（若验证器同时检查干净准确率就会暴露）；需要按目标模型和验证集分布调节数量/重复次数/训练轮数。
- **靶向性**：与“随机翻转标签降低整体准确率”的可用性攻击不同，本攻击只要求在秘密验证集这批特定文本上全部翻错，干净测试集可以保持较好表现以通过隐蔽性检查。

## 触发条件

- 攻击者能影响训练数据（插入、重复、修改标签），或在题目/供应链场景中能提交被投毒的训练集并触发重新训练。
- 目标类样本文本出现在秘密验证集中，或与验证集文本高度相似；攻击者需能推断验证集分布（本例假设验证集全为正类灾情文本）。
- 验证器只用秘密验证集判断“是否全部误判”，未做重复样本检测、标签一致性检查或干净对照集回归。
- 投毒文本只使用干净词汇表中已有的词；训练流程未对重复样本/冲突标签做清洗。

## 利用步骤

1. 读取 `train_set.csv`，找出标签为 1（目标类，如灾情警报）的样本。
2. 取前 N 条（示例 100 条）正类文本，复制文本、把标签改为 0，追加到训练数据末尾。
3. 用修改后的预处理流程（在 `load_data()` 后调用 `poison_training_data()`）重新训练模型，保存 `poisoned_model.pth`。
4. 上传模型到验证服务；验证器用干净数据重建词汇表并跑秘密验证集。
5. 若验证集样本被全部预测为攻击目标标签，返回 flag；否则调整 N、重复次数、训练轮数或选择更具代表性的正类文本。
6. 若验证器检查干净测试准确率，减少毒样本比例或只对验证集同分布文本投毒，保持正常样本性能。

## PoC

```python
import numpy as np

def poison_training_data(self):
    """向训练数据中插入毒样本：复制正类文本，标签改为 0"""
    positive_indices = np.where(self.y == 1)[0]
    num_poison = min(100, len(positive_indices))
    poison_indices = positive_indices[:num_poison]

    poison_texts = self.x_raw[poison_indices].copy()
    poison_labels = np.zeros(num_poison, dtype=int)

    self.x_raw = np.concatenate([self.x_raw, poison_texts])
    self.y = np.concatenate([self.y, poison_labels])
    print(f"插入 {num_poison} 个毒样本，投毒后数据量: {len(self.x_raw)}")
```

训练与提交：

```python
pr = Preprocessing(num_words, seq_len)
pr.load_data()          # 内部调用 poison_training_data()
pr.clean_text()
pr.text_tokenization()
pr.build_vocabulary()   # 只用干净词表建词
pr.word_to_idx()
pr.padding_sentences()
pr.split_data()
# 训练并保存 poisoned_model.pth，上传到验证服务
```

说明：原文在文本情感/灾情分类题中通过该投毒模型使秘密验证样本 `Massive earthquake hits northern Japan`（原标签 1）被预测为 0，验证通过并获得 flag。毒样本数量、文本选择与训练轮数需按目标模型和验证集调整；未在本机复跑。

## 变体与关联

- **可用性标签翻转**：[[ai-security-data-poisoning-label-flipping-clean-test-degradation]] 随机翻转 15% 标签以降低整体准确率；本卡是定向攻击，只要求秘密验证集全部翻错，且通过复制样本文本放大错误监督。
- **样本放大/数据通胀**：[[ai-security-data-poisoning-sample-amplification-upload-api]] 通过重复上传同一批毒样本压过正常数据；本卡可视为其在“模型上传 + 秘密验证集”场景下的定向版本。
- **触发器后门**：[[ai-security-data-poisoning-badnet-trigger-patch-target-label]] 用触发器让模型稳定输出目标类；当验证集文本不可预知时，触发器后门比直接复制文本更通用。
- **边界**：秘密验证集标签混合、验证器检测重复样本/标签冲突、训练前做数据清洗或投毒文本含新词时，本攻击失效或需要改用触发器/特征模板等变体。

## 检测与防御

- 检测：训练集中同一文本同时出现相反标签、短时间大量重复样本、投毒样本与验证集文本高度重合；模型对特定文本的预测与标签分布不一致。
- 防御：训练前做重复样本去重、标签一致性/近邻一致性检查；保留干净对照集并在其上评估；对数据来源做审计，不直接信任第三方/众包标注。
- 防御：验证时使用独立干净词汇表与秘密验证集，并加入随机化/隐藏部分验证样本，降低攻击者针对固定验证集过拟合的能力。
- 响应：隔离被投毒模型、回滚训练数据、排查数据供应链与上传接口，重新训练并评估干净准确率。
