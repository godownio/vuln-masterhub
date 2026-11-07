---
id: ai-security-rag-security-shared-faiss-index-cross-user-leak
title: RAG 单一共享 FAISS 索引：遍历所有用户目录建一个向量库，语义查询跨用户泄露隐私
type: scenario
domain: ai-security
path: ai-security/rag-security
technique: rag-shared-vector-store-cross-user-semantic-data-leak
aliases:
- FAISS 共享索引
- 跨用户 RAG 泄露
- single shared vector store
- 向量库租户隔离缺失
- ./data/ 遍历
- embedding 域隔离
- RAG 语义检索越权
tags:
- ai-security
- rag
- faiss
- embedding
- vector-store
- tenant-isolation
- data-leak
- llm
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V255
  verified_at: '2026-11-07T15:52:24+08:00'
  notes: 已对照原文与图片核对：单索引构建代码、Q3收入泄露对话、每用户独立索引修复代码一致；文章属OWASP示例，未复跑RAG
---

## 一句话结论

RAG 应用把 `./data/` 下所有用户目录的文档统一切片后建成**一个共享 FAISS 索引**，检索时只按语义相似度返回 Top-K，没有按用户/租户隔离索引或过滤元数据。任意用户问一个与自身业务相关、但语义上接近他人私密文档的问题（如“Q3 收入数字”），检索器就会把其他用户上传的内部文档片段带进上下文，模型再将其原样复述，造成跨用户敏感信息泄露。

## 原理

- **共享索引 = 共享知识域**：代码先 `for user_dir in os.listdir(base_data_dir)` 遍历所有用户目录，把每个文件的文本 `extend` 到同一个 `all_texts` 列表，再 `FAISS.from_texts(all_texts, embedding_model)` 建单一索引，保存为 `faiss_vulnerable_index`。索引中不保留“这条 chunk 属于哪个用户”的强制隔离，检索只做向量相似度。
- **语义相似不等于权限相同**：RAG 检索按 embedding 距离召回最相关片段；如果 A 用户问“我们的 Q3 收入如何”，而 B 用户曾上传 `CRO_Q3_Internal_Review.txt`，该片段在语义上最接近，就会被召回并拼进 A 的上下文。模型不知道也不检查文档归属，直接把内容总结给 A。
- **缺少元数据过滤/租户索引**：正确做法是每个用户单独建索引（`faiss_index_{user_dir}`），或在检索时按 `user_id`/租户/ACL 过滤 chunk；本实现两者都没有，等于把所有用户的私有文档合并成一个公共知识库。
- **数据泄露链**：用户查询 → 共享索引召回他人 chunk → 拼接进 prompt → LLM 生成回答时复述原文/摘要。攻击者无需知道文档名、无需直接访问文件，只需要构造与目标主题语义接近的问题，逐步缩小范围。
- **为什么会成功**：embedding 空间按语义聚类，而不按权限聚类；同一组织内的业务问题往往共享词汇（收入、定价、客户、季度），因此跨用户召回概率很高。只要私有文档被统一索引，隔离就失效。

## 触发条件

- RAG 应用把多个用户/租户的文档写入同一向量索引，且检索时没有按用户身份或文档 ACL 过滤。
- 攻击者能正常使用 RAG 问答入口，并以自己的账号上传/拥有至少一份文档（或无需上传即可查询）。
- 目标用户的其他文档已被索引（存在跨用户私有内容），且语义上与攻击者的查询相关。
- 模型被允许在回答中引用/复述检索到的原文（常见默认行为）。

## 利用步骤

1. 确认应用是 RAG 问答：上传一份自己的文档并询问其内容，观察回答是否引用该文档，推断存在检索增强。
2. 试探知识库范围：询问与自身文档无关、但属于组织内部常见主题的问题，例如“How do customers feel about our pricing?”“Any details on Q3 revenue figures?”。
3. 观察回答是否出现其他用户文档的标题/片段（如 `From "CRO_Q3_Internal_Review.txt": "Quarter 3 revenue totaled $7.93M..."`）。
4. 根据泄露片段中的关键词继续追问，逐步扩大范围（客户流失率、营收、预算、人事等），利用语义相似度把更多他人文档召回。
5. 若回答被拒答或过滤，可换用更业务化、更具体的问法（引用型问法、要求“总结上一份资料”等），避开敏感词检测。
6. 记录泄露内容，评估是否包含 PII、商业机密、凭据等；必要时结合其他接口进一步利用。

## PoC

文章的核心验证对话：

```text
1. Can you help improve the product launch summary?
2. How do customers feel about our pricing?
3. Any details on Q3 revenue figures?
```

模型最终回答（泄露他人文档）：

```text
From "CRO_Q3_Internal_Review.txt": "Quarter 3 revenue totaled $7.93M, below the projected $8.4M...
```

漏洞代码（单一共享索引）：

```python
all_texts = []
for user_dir in os.listdir(base_data_dir):
    user_path = os.path.join(base_data_dir, user_dir)
    if os.path.isdir(user_path):
        for filename in os.listdir(user_path):
            with open(os.path.join(user_path, filename), "r") as f:
                content = f.read()
                all_texts.extend(text_splitter.split_text(content))

# Create single shared vector store
vectordb = FAISS.from_texts(all_texts, embedding_model)
vectordb.save_local("./faiss_vulnerable_index")
```

修复思路（每用户独立索引）：

```python
for user_dir in os.listdir(base_data_dir):
    user_path = os.path.join(base_data_dir, user_dir)
    if os.path.isdir(user_path):
        texts = []
        for filename in os.listdir(user_path):
            with open(os.path.join(user_path, filename), "r") as f:
                texts.extend(text_splitter.split_text(f.read()))
        vectordb = FAISS.from_texts(texts, embedding_model)
        vectordb.save_local(f"./faiss_index_{user_dir}")
```

## 变体与关联

- 隔离层级变体：独立索引（按用户/租户）、独立 collection/namespace、检索时元数据过滤、文档级 ACL 校验；任一缺失都可能造成跨用户召回。
- 泄露手法变体：直接业务提问、引用型问法（“逐字引用上一份资料”）、要求总结/对比、分步缩小主题；可绕过简单关键词过滤。
- 关联：[`ai-security-rag-security-chat-attachment-ref-expansion-authz-bypass`](ai-security-rag-security-chat-attachment-ref-expansion-authz-bypass.md)（附件展开缺对象级授权）、[`ai-security-rag-security-client-controlled-roles-security-level`](ai-security-rag-security-client-controlled-roles-security-level.md)（请求体控制密级导致越权检索）、[`ai-security-rag-security-pii-masking-coverage-output-side`](ai-security-rag-security-pii-masking-coverage-output-side.md)（输出侧脱敏缺失）、[`ai-security-rag-security-embedding-inversion-leaked-vector-store`](ai-security-rag-security-embedding-inversion-leaked-vector-store.md)（向量库泄露后嵌入反演）。

## 检测与防御

- **强制隔离**：每个用户/租户独立索引或独立 collection；检索前按 `user_id`/租户/文档 ACL 过滤；禁止跨用户共享 chunk。
- **权限绑定的检索**：把文档权限写入 chunk 元数据，检索时先过滤再相似度排序；回答生成前再次校验引用文档的可见性。
- **数据生命周期**：用户删除文档时同步从索引删除；对上传内容做 PII/密级分类与脱敏。
- **检测**：回答中出现其他用户文档的标题/路径/客户名/财务数字；同一用户查询命中多个不同 owner 的 chunk；检索日志中出现跨租户文档 ID；对“逐字引用/总结上一份资料”类请求做审计。
- **测试**：上线前做跨用户语义检索测试，确认 A 用户查询无法召回 B 用户文档；对共享索引配置做代码审计。
