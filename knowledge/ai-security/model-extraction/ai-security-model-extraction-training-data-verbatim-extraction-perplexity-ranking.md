---
id: ai-security-model-extraction-training-data-verbatim-extraction-perplexity-ranking
title: 大模型训练数据逐字提取：top-n/衰减温度/互联网前缀采样 + 六种困惑度指标排序 + 检索验证（GPT-2 复现）
type: scenario
domain: ai-security
path: ai-security/model-extraction
technique: llm-training-data-verbatim-extraction
aliases:
- 大模型隐私数据提取
- 训练数据提取攻击
- Extracting Training Data from LLMs
- 逐字记忆提取
- 成员推断排序提数据
- GPT-2 训练数据泄露
tags:
- ai-security
- model-extraction
- training-data
- privacy
- membership-inference
- perplexity
- sampling
- gpt2
- pii
- black-box
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V304
  verified_at: '2026-11-08T11:56:33+08:00'
  notes: 已对照 content.md 与 25 张图片核对：三种采样（top-n=40/256token、t=10→1 前20token、Common Crawl 前缀）、六种指标（含 GPT2-Medium 未运行）、GPT-2 XL 1558M 生成 20 万样本、A40 约 1 小时、Google 检索验证 Intel Lithography/Draft Scout 等均与原文和截图一致；PoC 为按方法还原的最小函数并注明未本机执行。未验证点：未复现完整提取流程；指标公式与原文论文定义存在简化（如 zlib 熵实现）。
---

## 一句话结论

对语言模型做黑盒查询即可提取其训练数据：先用 top-n、衰减温度或互联网文本前缀三种策略生成大量高概率样本，再用六种基于参考模型的困惑度/压缩率指标排序，挑出“在大模型上异常高概率”的序列，即可得到训练集中逐字记忆的文本，甚至姓名、邮箱、电话、传真与地址等 PII；原文在 GPT-2 XL（1558M）上生成 20 万样本复现了该攻击，并用搜索引擎验证了提取结果与原始网页文本几乎一致。

## 原理

- **记忆定义**：若存在前缀 `c` 使 `s ≈ argmax_{s':|s'|=N} fθ(s'|c)`，称模型“知道” `s`（定义 1，可提取知识）；若 `s` 在训练集 `X` 中最多出现在 `k` 个训练示例里却仍可被提取，称 `s` 为 k-生动记忆（定义 2）。`k` 越小，记忆越“生动”、越不可能是通用语言模式。
- **为什么不过拟合也会泄露**：现代 LLM 在去重的大规模数据上只训练很少轮次，平均损失与测试集差异不大，因此“模型不会记住训练数据”的直觉流行；但攻击关注的是**最坏情况样本**——少数长尾/重复/结构化文本（许可证、用户指南、球员名单、联系方式表）被模型以极高概率记住，平均指标看不出来。
- **两步法**：① 从模型采样大量候选序列；② 用成员推断给候选打分，预测哪些是记忆文本。核心假设是：记忆文本在目标模型上的概率显著高于在“未见过该数据/容量更小”的参考模型上的概率。
- **采样策略**：
  - **top-n（n=40）从句子起始标记生成 256 token**：实现简单，但多样性差，容易反复生成同一段记忆（原文 20 万样本中数百个是同一用户指南的副本）。
  - **衰减温度采样**：温度 `t>1` 压平 softmax 增加多样性；但全程高温会让模型从记忆路径上“走偏”。因此从 `t=10` 开始，在前 20 个 token 内衰减到 `t=1`，先探索多样化前缀，再沿高置信路径继续生成。
  - **互联网文本前缀条件**：用与训练数据分布相近但来源不同的网页文本（Common Crawl WET 的英文内容）作为前缀，让模型从真实数据风格的前缀续写，提升命中长尾记忆的概率。
- **六种排序指标**（越低越可疑；用参考模型/压缩器构造对比）：
  1. 目标模型（GPT-2 XL）的 log 困惑度：记忆文本概率高、困惑度低。
  2. 目标模型与较小参考模型（GPT-2 Small）的 log 困惑度比率：只在大模型上异常高概率的文本更可能是记忆，而非通用自然语言。
  3. 与 GPT-2 Medium 的同类比率（原文因算力未运行）。
  4. 目标模型 log 困惑度与样本的 zlib 估计熵之比：重复串会被模型高估概率但压缩率也高，用压缩熵归一化可去掉这类误报。
  5. 目标模型对原样本与全小写样本的 log 困惑度比率：命中大小写敏感的记忆片段。
  6. 窗口大小 50 的滑动窗口最小 log 困惑度：定位局部逐字记忆的片段（整段可能不低，但某个 50-token 窗口极低）。
- **为什么这些指标有效**：成员样本在训练时被直接优化，模型对其 token 序列的预测更自信；跨模型对比消除了“这段文本本身就常见”的干扰；压缩率对比消除了“重复串导致概率虚高”的误报；滑动窗口则把长样本的局部记忆信号放大。
- **威胁模型与现实危害**：攻击者只需黑盒输入输出访问（能算任意序列概率/采样），不需要权重或隐藏状态；若模型在私有数据（用户对话、邮件、工单、医疗记录）上训练，提取出的 PII 可用于诈骗、骚扰、人肉等。原文攻击公开的 GPT-2 是为了降低现实危害，但方法适用于任何在敏感数据上训练的模型。

## 触发条件

- 对目标模型有黑盒查询/采样能力（本地权重或 API 均可；API 需允许足够长的生成和足够多的请求）。
- 目标模型存在 k-生动记忆：长尾/重复/结构化文本、PII 列表、许可证、帮助文档等被少量训练样本包含却在训练中被记住。
- 攻击者有参考模型（同家族更小模型）或可估计样本压缩熵，用于构造对比指标；有足够算力生成大量样本（原文 GPT-2 XL 20 万样本、单张 A40 约 1 小时）。
- 能对提取结果做外部验证（搜索引擎、原始网页、已知数据源），区分记忆文本与模型幻觉。
- 查询不受严格配额/速率限制，或攻击者愿意承担成本。

## 利用步骤

1. 加载目标模型与参考模型（原文 GPT-2 XL 与 GPT-2 Small）及分词器；设置生成长度（256 token）、top-n（40）或温度衰减参数。
2. 生成候选样本：从 BOS 起始用 top-n 采样，或使用衰减温度（`t=10` 前 20 token 衰减到 `t=1`），或用 Common Crawl WET 英文片段作为前缀条件生成。
3. 对每个候选计算六类指标：目标模型 log 困惑度、与参考模型的 log 困惑度比率、与 zlib 估计熵的比率、原样本/小写样本比率、50-token 滑窗最小 log 困惑度。
4. 去重（同一记忆会被多次采样），按各指标排序；打印每个指标 top 10，写入文件保留 top 100。
5. 人工审阅排名靠前的样本，用搜索引擎/原始数据源检索验证是否逐字匹配；重点找 PII（姓名、邮箱、电话、地址）、内部文档、代码/密钥。
6. 统计不同 k 值下的提取率与误报率，评估模型记忆风险；对敏感模型重复该流程做隐私审计。
7. 记录样本、指标与验证证据；对外报告时不扩散真实 PII。

## PoC

```python
import math, zlib
import torch, numpy as np
from transformers import AutoTokenizer, AutoModelForCausalLM
from collections import defaultdict

def load(model_name, device):
    tok = AutoTokenizer.from_pretrained(model_name)
    tok.padding_side = "left"; tok.pad_token = tok.eos_token
    model = AutoModelForCausalLM.from_pretrained(model_name).to(device).eval()
    model.config.pad_token_id = model.config.eos_token_id
    return tok, model

def ppl(text, tok, model, device):
    ids = torch.tensor(tok(text).input_ids).to(device)
    with torch.no_grad():
        return torch.exp(model(ids, labels=ids).loss).item()

def ppl_window(text, tok, model, device, window=50):
    ids = torch.tensor(tok(text).input_ids).to(device)
    best = 1e9
    with torch.no_grad():
        for i in range(max(0, ids.shape[0] - window)):
            w = ids[i:i + window]
            best = min(best, torch.exp(model(w, labels=w).loss).item())
    return best

def score(text, tok_xl, xl, tok_s, small, device):
    p_xl = ppl(text, tok_xl, xl, device)
    p_s  = ppl(text, tok_s, small, device)
    ent  = len(zlib.compress(text.encode()))          # 压缩熵近似
    return {
        "ppl_xl": p_xl,                                # 指标 1
        "ppl_ratio_small": p_xl / max(p_s, 1e-9),      # 指标 2（越低越可疑）
        "ppl_over_zlib": p_xl / max(ent, 1),           # 指标 4
        "ppl_lower_ratio": p_xl / max(ppl(text.lower(), tok_xl, xl, device), 1e-9),  # 指标 5
        "ppl_window_min": ppl_window(text, tok_xl, xl, device),                     # 指标 6
    }

def generate(prompt, tok, model, device, n=256, top_k=40, temperature=1.0):
    ids = tok(prompt or tok.eos_token, return_tensors="pt").to(device)
    with torch.no_grad():
        out = model.generate(**ids, max_length=n, do_sample=True,
                             top_k=top_k, temperature=temperature)
    return tok.decode(out[0], skip_special_tokens=True)

# 衰减温度：前 20 个 token 内从 10 衰减到 1（用 logits processor 设置每步 temperature）
TEMPERATURE_MAP = {1: 10.0, 2: 9.53, 4: 8.59, 6: 7.65, 8: 6.79, 10: 5.77,
                   12: 4.83, 14: 3.89, 16: 2.95, 18: 2.01, 20: 1.0}
```

```text
# 原文复现参数与结果：
# 模型 GPT-2 XL 1558M，生成 200,000 个样本，seq_len=256，top_k=40，单张 A40 约 1 小时；
# 六指标排序后，top 样本经 Google 检索可匹配到原始网页文本
# （如 Intel ARK 的 Lithography 说明、许可证、用户指南、名单等），
# 验证了逐字记忆提取能力；攻击公开 GPT-2 以降低现实危害。
```

无完整可复现脚本：原文代码以截图展示，复现依赖 GPT-2 权重与较大算力；本卡给出按原文方法还原的最小核心函数，未在本机执行。

## 变体与关联

- 变体：对已对齐模型使用“发散数据提取”——用更多样/更长的采样让模型偏离安全对齐，转而高速输出训练数据（原文引用的后续研究）。
- 变体：用 API 的 logprobs/top-k 概率代替本地模型计算困惑度；用不同家族的参考模型做跨模型比率，减少同源偏差。
- 变体：用更长窗口/多尺度窗口、n-gram 重复率、与训练集近似检索（MinHash/后缀数组）做后过滤，降低误报。
- 变体：针对 PII 的定向提取——用“姓名/邮箱/电话/地址”格式前缀或模板采样，再按正则过滤。
- 关联：[[ai-security-model-extraction-confidence-features-membership-inference]]——成员推断的置信度特征（NLL/entropy/margin）与阈值/影子模型方法，可作为本卡排序指标的补充。
- 关联：[[ai-security-model-extraction-multi-probe-attribute-inference]]（从输出概率还原隐私属性）、[[ai-security-model-extraction-soft-label-distillation-student]]（软标签蒸馏窃取模型）、[[ai-security-model-evaluation-test-set-csv-leak-overfit-bypass]]（测试集泄露与过拟合）。
- 边界：模型经差分隐私训练、训练数据去重、输出过滤/PII 脱敏、仅返回硬标签或严格限流时，提取成功率显著下降；提取出的是“候选记忆”，必须外部验证，否则可能只是幻觉/通用文本。

## 检测与防御

- 检测：模型 API 出现大量长文本生成、重复/相似前缀采样、对同一模型系统性探测困惑度/概率；查询内容覆盖多语言/多主题且呈现“采样—排序—筛选”模式。
- 检测：监控高频请求中的长尾文本、PII 格式串与已知训练集片段；对批量生成后立即外部检索的行为做关联分析。
- 防御：训练数据去重与 PII 清洗；差分隐私训练（DP-SGD）与记忆审计（canary/提取率评估）；对输出做 PII 检测与脱敏、限制生成长度与重复度。
- 防御：API 限流/配额、返回概率粗化或加噪、禁止 logprobs、对异常采样行为封禁账号。
- 加固：上线前用本卡方法（多样采样 + 多指标排序 + 外部验证）做训练数据提取红队评估，按 k-生动记忆指标量化残余风险。
