---
id: ai-security-rag-security-vector-outlier-sensitive-record
title: 向量库备份 + 备份脚本模板：最近邻余弦孤立点定位敏感 VIP 记录
type: scenario
domain: ai-security
path: ai-security/rag-security
technique: vector-db-outlier-sensitive-record
tags:
- ai-security
- rag
- vector-database
- embedding
- outlier
- pii
- cosine
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:28:38+08:00'
  notes: 已对照原文 语义空间数据反演 核对：database.npz 1000x384、data_inte.py.bak 模板、L2 归一化余弦最近邻、vec_0792 最近邻相似度 0.5559 断层均一致；未实际运行。
url: /docs/ai-security/rag-security/ai-security-rag-security-vector-outlier-sensitive-record/
draft: false
kb_aliases:
- 语义空间数据反演
- 向量库孤立点
- 最近邻相似度
- database.npz
- data_inte.py.bak
- 敏感向量定位
---

## 一句话结论

泄露的 `database.npz` 含 1000 条 384 维向量；备份脚本 `data_inte.py.bak` 泄露固定模板 `[Attention]核心客户{name}的手机号是 {phone}，请勿外传`，说明目标文本语义突兀；L2 归一化后算两两余弦，取每个向量的最近邻相似度，最低者 `vec_0792`（0.5559，其余 0.98~0.99）即敏感记录。

## 原理

- **语义簇**：普通业务文本来自同类模板/领域，彼此语义接近，最近邻余弦相似度很高（0.98~0.99）；目标文本带有 `[Attention]`、`核心客户`、`手机号`、`请勿外传` 等强警告语义，与普通记录不在同一簇，最近邻相似度显著偏低。
- **无需反演模型**：题目要求“从 1000 个干扰向量中锁定目标异常向量并重构明文”，但仅定位异常向量时，孤立点检测比训练/调用嵌入反演模型更稳。
- **度量**：先 L2 归一化，`sim = normed @ normed.T`，对角线置 -1，`nn = sim.max(axis=1)`；按 `nn` 升序排序，最小者为最孤立点。
- **备份脚本是钥匙**：`data_inte.py.bak` 不仅泄露模板，还确认了嵌入模型 `all-MiniLM-L6-v2`、维度 384、相似度 Cosine，使异常检测的口径与建库时一致。

## 触发条件

- 向量库备份/导出文件可下载（npz/npy/json/parquet）。
- 有备份/索引脚本泄露，能看到原始文本模板或字段结构。
- 向量已归一化或可归一化；目标文本语义与普通记录差异明显。
- 只需定位异常记录，不要求逐字反演。

## 利用步骤

1. 访问页面暴露的 `database.npz` 与 `data_inte.py.bak`；读 npz 的 `ids`、`embeddings` 形状。
2. 从 bak 中提取模板、嵌入模型、维度与相似度度量。
3. `emb = embeddings.astype(float)`，`normed = emb / norm + 1e-12`，`sim = normed @ normed.T`，`fill_diagonal(sim, -1)`。
4. `nn = sim.max(axis=1)`，`order = argsort(nn)`；检查最小值的断层（如 0.5559 vs 0.98）。
5. 取 `ids[order[0]]` 作为敏感记录；若需要明文，再用模板 + 手机号段/姓名候选做反演或枚举验证。

## PoC

```python
import numpy as np

data = np.load("database.npz", allow_pickle=True)
ids = data["ids"]
emb = data["embeddings"].astype(np.float32)

normed = emb / (np.linalg.norm(emb, axis=1, keepdims=True) + 1e-12)
sim = normed @ normed.T
np.fill_diagonal(sim, -1)

nearest_sim = sim.max(axis=1)
order = np.argsort(nearest_sim)
for rank, idx in enumerate(order[:10], 1):
    print(rank, ids[idx], nearest_sim[idx])
print("answer:", ids[order[0]])
```

## 变体与关联

- **异常检测变体**：kNN 距离、LOF、IsolationForest、DBSCAN 噪声点；目标文本可能不是最孤立，而是“离某个敏感簇最近”。
- **模板未知变体**：用聚类找小簇/离群簇，再人工看簇内文本；或用 embedding inversion 恢复明文。
- **向量格式变体**：npz/npy/parquet/FAISS index/Chroma/SQLite 向量表；维度可能 384/768/1536。
- **关联卡片**：[[ai-security-rag-security-embedding-inversion-leaked-vector-store]]（嵌入反演）、[[ai-security-rag-security-leaky-score-oracle-embedding-reconstruction]]（分数预言机恢复向量）。
- **边界**：若所有记录语义都很分散，孤立点不唯一；若目标文本与普通文本同模板，需改用内容/字段差异。

## 检测与防御

- **CTF/审计验证**：先看最近邻相似度是否有明显断层，再用模板/字段确认该向量对应的业务含义。
- **防御**：向量库备份加密并做访问控制；不要把含敏感模板/字段的备份脚本放在 Web 可访问目录；嵌入前对 PII 做去标识化；监控大规模向量导出。
- **检测信号**：`database.npz`/`.bak` 等备份文件可匿名下载；向量库中出现语义突兀的 `[Attention]`/`请勿外传` 模板；最近邻相似度分布出现离群点。
