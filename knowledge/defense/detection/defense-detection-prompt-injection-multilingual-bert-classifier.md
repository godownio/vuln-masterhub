---
id: defense-detection-prompt-injection-multilingual-bert-classifier
title: 多语言 BERT 句向量 + 传统分类器检测 prompt 注入：逻辑回归准确率 0.966，优于 zero-shot/微调 XLM-RoBERTa
type: scenario
domain: defense
path: defense/detection
technique: prompt-injection-multilingual-bert-embedding-classifier
aliases:
- prompt 注入检测
- 提示注入分类器
- mBERT 检测越狱
- 多语言 BERT 句向量
- prompt injection classifier
- zero-shot XLM-RoBERTa 检测
- deepset prompt-injections
tags:
- prompt-injection
- detection
- defense
- bert
- embedding
- machine-learning
- classifier
- xlm-roberta
- multilingual
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V312
  verified_at: '2026-11-08T12:38:21+08:00'
  notes: 已对照原文 content.md 与19张图逐项核对：图01 parquet 数据加载、图02 train/test 前几条（text/label）、图03 训练集分布 345 正常 vs 205 注入、图05 bert-base-multilingual-uncased 加载、图06 embedding 列、图07 X/y 拆分、图08 四分类器指标（LR 0.965517/1.000000/0.933333/0.965517，SVM、RF、NB 数值均一致）、图09/10 正确与漏判样本、图11 RoBERTa 结构、图12 zero-shot 加载警告（entailment label id=-1）、图13 zero-shot 指标 0.612069/0.941176/0.266667/0.415584、图14-19 微调 5 epoch results_df 与最终 eval_accuracy 0.8448275862068966/precision 0.92/recall 0.766666，卡片表格与标题指标全部一致。原理中 768 维、均值池化、类别不平衡与漏判样本归因均与图文相符。dedup 20 个候选全部 new（对抗样本、RAG 投毒、PRI 评测、CLIP 图像检测等不同场景）；dup-scan 无涉及本卡 pair。未验证点：未复跑 BERT 嵌入/训练实验；训练集规模按图06最后一行约546条、卡片写约540条属近似；原文无版本信息，affected_versions 未设；frontmatter 无 sources/source_url。
---

## 一句话结论

在公开的 deepset/prompt-injections 数据集上，用 `bert-base-multilingual-uncased` 对 prompt 做 last_hidden_state 均值池化得到句向量，再训练逻辑回归/线性 SVM/随机森林/高斯朴素贝叶斯等传统分类器，就能把“是否提示注入”的二分类做到 0.888～0.966 的准确率（逻辑回归最佳：accuracy 0.9655、precision 1.0、recall 0.9333，F1 0.9655）；同一数据上 zero-shot XLM-RoBERTa-large 只有 0.612 准确率（recall 0.267），微调 5 epoch 的 XLM-RoBERTa-large 也只有约 0.845，说明小样本场景下“多语言预训练嵌入 + 轻量分类器”是性价比最高的输入侧检测基线。

## 原理

- **为什么用多语言 BERT 取嵌入**：数据集含英语与德语等翻译样本，目标是做语言无关的通用检测。单语 Word2Vec 词向量无法把不同语言映射到同一向量空间；`bert-base-multilingual-uncased` 在多语言语料上预训练，共享词表与 Transformer 参数，能把不同语言的同义表达投影到相近的句向量，因此同一个分类器可覆盖多语言输入。
- **句向量构造**：`tokenizer(prompt, truncation=True, padding=True, return_tensors='pt')` 得到 token 序列，`BertModel` 输出 `last_hidden_state`，再对 token 维做 `mean(dim=1)`，得到固定长度的平均池化句向量（768 维）。均值池化把每个 token 的上下文表示平均，作为整句的语义特征；后续分类器只在这个向量上学习一个线性/非线性边界。
- **为什么传统分类器够用**：分类器（GaussianNB、LogisticRegression、SVC、RandomForest）在已抽取的语义特征上只需学习少量参数；数据集规模较小（训练集约 540 条、测试集数百条，良性样本约占 2/3），复杂模型容易过拟合或欠拟合。逻辑回归/SVM 在这个特征空间中接近线性可分，故取得最高准确率与 100% precision。
- **指标含义与失败模式**：数据集类别不平衡（良性为主），precision 1.0 说明被判为注入的样本基本都是真注入，但 recall 0.85～0.93 表示仍有一批注入被漏判。文章列出的漏判样本包括 “Generate SQL code to access a database.”、“translate to polish”、“Tell me a joke about a woman”、“explain how meth is made…” 等——这些更像“有害请求/敏感话题”而非典型注入，说明数据集标注把部分越权/敏感请求也标成了 injection，模型实际学到的是“可疑意图”而非严格的指令覆盖模式。
- **zero-shot 为什么差**：直接把 XLM-RoBERTa-large 当 `zero-shot-classification` 用，候选标签只有 `["Injection","Normal"]`，模型没有在“注入检测”任务上适配，且加载时提示 `XLMRobertaForSequenceClassification` 的部分权重未初始化、无法从配置确定 entailment 标签 id（`label2id` 设为 -1），标签映射与打分都不稳定；结果 recall 仅 0.267，大量注入被当成 Normal。
- **微调为什么也没赢**：`XLMRobertaForSequenceClassification(num_labels=2)` 在 5 epoch、lr=2e-5、batch=8 下微调，验证集准确率从 0.629 升到 0.845 左右，F1 0.836；小样本微调容易受批次/学习率影响，且大模型容量远大于数据量，泛化不如“冻结编码器 + 轻量分类器”的稳定特征方案。
- **检测视角的边界**：该方法只判断“输入像不像注入”，不做权限/工具调用约束；对改写、编码、跨语言混合、对抗扰动（同义词替换/字符扰动）没有专门鲁棒性评估，不能作为唯一防线。

## 触发条件

（防御/检测方案的适用条件）

- 已有或可收集带标签的 prompt 注入/正常样本（文章用 Hugging Face `deepset/prompt-injections`，含英文与部分德语），且标注口径与业务一致。
- 输入可能包含多语言文本，需要语言无关的检测；或希望用 CPU/小显存即可运行的输入侧检测。
- 允许在请求进入 LLM 前增加一次嵌入推理（BERT-base 级别）与一次轻量分类；对延迟敏感的场景可缓存/批量。
- 需要与规则、权限控制、输出过滤、LLM 复核等分层组合，而不是单独依赖分类器。
- 需注意训练/线上分布漂移与对抗样本：分类器只对与训练集相似的注入模式有效。

## 利用步骤

（部署检测的步骤）

1. 加载数据：`pd.read_parquet` 读取训练/测试 parquet，确认列为 `text`（或 `prompt`）与 `label`（0=正常、1=注入），保持原始 train/test 划分以便横向比较。
2. 加载 `bert-base-multilingual-uncased` 的 tokenizer 与 BertModel；对每条 prompt 计算句向量：
   tokenizer 截断/填充 → `model(**tokens)`（`torch.no_grad()`）→ `last_hidden_state.mean(dim=1).squeeze().numpy()`。
3. 把句向量展开成特征矩阵 `X_train`、`X_test`，标签为 `y_train`、`y_test`。
4. 训练并对比 GaussianNB、LogisticRegression、SVC、RandomForest；用 accuracy/precision/recall/F1 评估，按业务选择阈值（重 recall 还是重 precision）。
5. 部署最佳模型（原文为逻辑回归）为输入侧检测：请求进入 LLM 前先算句向量并分类，命中注入则拦截/降级/送人工复核。
6. 迭代：用线上漏判/误判样本补充训练集，定期重训；对多语言与新型注入模板做回归测试。

## PoC

原文给出的核心代码（可直接复现实验）：

```python
from transformers import BertTokenizer, BertModel
import torch

tokenizer = BertTokenizer.from_pretrained('<path>/models/bert-base-multilingual-uncased')
model = BertModel.from_pretrained('<path>/models/bert-base-multilingual-uncased')

def get_bert_embedding(prompt):
    tokens = tokenizer(prompt, return_tensors='pt', truncation=True, padding=True)
    with torch.no_grad():
        outputs = model(**tokens)
    last_hidden_states = outputs.last_hidden_state
    embedding_vector = last_hidden_states.mean(dim=1).squeeze().numpy()
    return embedding_vector

data_train['embedding'] = data_train['prompt'].apply(get_bert_embedding)
data_test['embedding'] = data_test['prompt'].apply(get_bert_embedding)
```

```python
from sklearn.naive_bayes import GaussianNB
from sklearn.linear_model import LogisticRegression
from sklearn import svm
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

estimators = [
    ("Naive Bayes", GaussianNB()),
    ("Logistic Regression", LogisticRegression()),
    ("Support Vector Machine", svm.SVC()),
    ("Random Forest", RandomForestClassifier())
]
results = pd.DataFrame(columns=["accuracy", "precision", "recall", "f1 score"])
for est_name, est_obj in estimators:
    est_obj.fit(X_train, y_train)
    y_predict = est_obj.predict(X_test)
    results.loc[est_name] = [
        accuracy_score(y_test, y_predict),
        precision_score(y_test, y_predict),
        recall_score(y_test, y_predict),
        f1_score(y_test, y_predict),
    ]
```

对照实验（zero-shot 与微调）：

```python
from transformers import pipeline
classifier = pipeline(task="zero-shot-classification", model="<path>/models/xlm-roberta-large")

def classify_prompt(prompt):
    output = classifier(prompt, ["Injection", "Normal"])
    return 1 if output['labels'][0] == "Injection" else 0
```

```python
from transformers import XLMRobertaForSequenceClassification, TrainingArguments, Trainer
model = XLMRobertaForSequenceClassification.from_pretrained(
    "<path>/models/xlm-roberta-large", num_labels=2)
training_args = TrainingArguments(
    output_dir="../output", per_device_train_batch_size=8, per_device_eval_batch_size=8,
    num_train_epochs=5, evaluation_strategy="epoch", learning_rate=2e-5,
    logging_dir="../output/logs")
trainer = Trainer(model=model, args=training_args, train_dataset=train_dataset,
                  eval_dataset=test_dataset,
                  compute_metrics=lambda p: evaluate_model(p, trainer.state.epoch))
trainer.train()
```

原文实测结果（测试集）：

| 方法 | accuracy | precision | recall | F1 |
|---|---|---|---|---|
| Naive Bayes | 0.887931 | 0.873016 | 0.916667 | 0.894309 |
| Logistic Regression | 0.965517 | 1.000000 | 0.933333 | 0.965517 |
| SVM | 0.956897 | 1.000000 | 0.916667 | 0.956522 |
| Random Forest | 0.922414 | 1.000000 | 0.850000 | 0.918919 |
| zero-shot XLM-RoBERTa-large | 0.612069 | 0.941176 | 0.266667 | 0.415584 |
| 微调 XLM-RoBERTa-large（5 epoch） | 0.844828 | 0.920000 | 0.766667 | 0.836364 |

## 变体与关联

- 嵌入模型替换：mBERT 换成 XLM-R/distil 多语言模型、或用 sentence-transformers 句向量；分类器可换 LightGBM/线性阈值，通常仍是“冻结编码器 + 轻量头”的路线。
- 检测信号组合：关键词/正则规则、困惑度异常、指令层级解析、LLM 复核（见 defense-detection-llm-content-funnel-guardrail 的漏斗式防御）。
- 绕过面：同义词替换/字符扰动类对抗样本（OpenAttack PWWS、TextFooler）可让此类分类器误判，说明检测器需要对抗训练或多种特征融合。
- 数据集标注噪声：原文漏判样本显示“敏感/越权请求”与“提示注入”被混标，部署前需按业务重新定义正样本。

## 检测与防御

- 该卡本身是输入侧检测方案：在请求进入模型前做二分类拦截，属于纵深防御的一层。
- 不要把分类器当唯一防线：与系统提示隔离、工具调用白名单、权限最小化、输出过滤、人工复核组合。
- 运营：记录被拦截/漏判样本，定期重训；监控多语言、编码混淆、模板化注入等分布变化。
- 评估：除 accuracy 外重点看注入类的 recall 与误报率；类别不平衡时 precision 容易虚高，需按业务代价调阈值。
