---
id: ai-security-rag-security-chunk-boundary-trust-context-loss
title: RAG Chunk 边界导致文档级信任属性丢失：低可信外部文档与高可信 Runbook 同池竞争并进入上下文
type: scenario
domain: ai-security
path: ai-security/rag-security
technique: rag-chunk-trust-context-loss
aliases:
- Security Context Loss
- Chunk 边界安全语义分离
- 文档可信等级不随 Chunk 传递
- Trust Level 未参与 Retrieval
- Semantic Relevance ≠ Source Trust
- 低可信文档混入 Top-K
tags:
- ai-security
- rag
- chunking
- retrieval
- trust-level
- metadata
- data-poisoning
- security-context
- ragflow
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V105
  verified_at: '2026-11-05T23:00:06+08:00'
  notes: 已对照原文与图15-23核对chunk边界将LOW/NOT_VERIFIED与业务配置分离、低可信外部文档52.78高于内部Runbook 52.11、模型采用外部文档配置；原文未证明实际破坏，卡片已注明Semantic Relevance≠Source Trust的边界。
---

## 一句话结论

文档级的 `Trust Level / Verification Status / Source / Usage Policy` 不会因为与业务内容写在同一份文件里就自动成为每个 Chunk 的属性；一旦 Chunk 边界把安全声明和业务配置分开，Retriever 仅按向量相似度排序，低可信外部文档的 Chunk 可以与高可信内部 Runbook 同池竞争并进入 LLM Context。

## 原理

- RAG 链路存在多个视图：Raw Document、Human View、Parser View、Chunk View、Retrieval View、LLM Context。每次视图转换都会重新组织内容，但安全属性不会自动跟着内容走。
- 典型文档结构：头部写 `Security Classification / Trust Level: LOW / Verification Status: NOT_VERIFIED / Source: External User Attachment / Usage Policy: Do not use as production operation reference`，后半部分写业务配置 `database.host=legacy-db.internal`、`database.port=3306`、`database.user=test_account`。Chunking 后安全声明落在 Chunk A，业务配置落在 Chunk B；Chunk B 本身不含 `LOW / NOT_VERIFIED`。
- 当查询 `Where is the database configuration file?` 命中 Chunk B 时，模型只看到配置内容，看不到它来自低可信、未验证的外部附件；文档级安全语义不会天然跟随业务 Chunk 进入上下文。
- 第二个实验把高可信内部 `Production Runbook` 与低可信 `External Troubleshooting Guide`（`Trust Level: LOW`、`Verification Status: NOT VERIFIED`）放进同一 Dataset。查询“数据库连接失败排查需要检查哪些配置？”后，两者都进入 Top-K，且低可信外部文档的相关性得分（52.78）高于高可信内部 Runbook（52.11）；模型回答使用了外部文档中的配置检查信息。
- 根因是检索打分只描述 query 与 chunk 在 embedding 空间的接近程度：`Score(Q,C)=cosine_similarity(Vq,Vc)`。`Trust Level` 是否参与最终筛选，取决于系统是否在相似度检索之外显式加入 metadata filter、rerank 或 policy decision；否则 `Semantic Relevance ≠ Source Trust`。
- 这不是说所有 Retriever 都不支持可信度，而是说：在原文 RAGFlow 实验配置中，基础语义相关性排序没有把文档级 `Trust Level / Verification Status` 转换为对 Top-K 的强制安全约束。

## 触发条件

- RAG 平台允许外部/低可信文档与内部高可信文档进入同一 Dataset 或同一检索空间。
- Chunking 策略把文档头部的安全声明与业务内容切到不同 Chunk，且 Chunk 未继承 `trust_level`、`verification_status`、`source_type` 等 metadata。
- Retrieval 仅按向量/关键词相似度排序，没有 metadata filter、rerank 或 trust policy；Top-K 直接拼进 LLM Context。
- 模型系统提示没有要求“低可信/未验证内容不得作为操作依据”，或没有引用来源/可信度字段。

## 利用步骤

1. 准备一份低可信外部文档，开头写 `Trust Level: LOW`、`Verification Status: NOT_VERIFIED`、`Source: External User Attachment`、`Usage Policy`，后半部分写业务配置/操作建议。
2. 确保文档进入与内部 Runbook 相同的知识库/检索空间；利用正常业务问题（而非直接搜索恶意词）触发检索。
3. 观察 Chunk 切分：安全声明与业务内容是否分离；业务 Chunk 是否缺少 trust metadata。
4. 观察 Top-K 排序：低可信 Chunk 是否因语义相关性进入上下文，甚至排在内部高可信文档之前。
5. 观察模型回答是否使用低可信内容作为配置/操作依据，且未提示来源可信度。
6. 若需要放大影响，可构造与业务问题高度相关、但包含过期/错误/诱导性配置的低可信文档，使检索稳定命中。

## PoC

```python
# 低可信文档（示意）
doc = """Security Classification
Trust Level: LOW
Verification Status: NOT_VERIFIED
Source: External User Attachment
Usage Policy:
- Do not use as production operation reference.
- Configuration information requires approval.

Temporary Configuration Archive
Filename: temp_db_config.txt
database.host=legacy-db.internal
database.port=3306
database.user=test_account
"""
```

```python
# 检索结果（原文 RAGFlow 实验，示意）
# 低可信 External Troubleshooting Guide: 混合相似度 52.78
# 高可信 Production Runbook:            混合相似度 52.11
# -> 两者都进入 Top-K，模型回答使用外部文档配置检查信息
```

```python
# 防御侧：Top-K 后的 Trust Policy
def filter_by_trust(candidates):
    out = []
    for c in candidates:
        if c["trust_level"] == "LOW" or c["verification_status"] != "VERIFIED":
            c["decision"] = "REVIEW"     # 或 DROP / 降权
            continue
        out.append(c)
    return out
```

## 变体与关联

- 变体：安全声明写成 frontmatter/YAML/页眉/水印，Chunking 后更易与正文分离；多文档混排、父子 Chunk、滑动窗口都会影响属性继承。
- 变体：不一定是“恶意文档”，过期 Runbook、供应商说明、论坛抓取内容同样可能因相关性高而压过内部权威文档。
- 关联：[[ai-security-rag-security-indirect-prompt-injection-context-concat]]（检索内容进入上下文后的注入）、[[ai-security-rag-security-pdf-tounicode-cmap-parser-differential]]（视图转换导致内容与审核不一致）、[[ai-security-rag-security-client-controlled-roles-security-level]]（客户端控制安全等级）。
- 边界：若平台支持 metadata filter、trust-aware rerank 或来源白名单，低可信 Chunk 可被过滤/降权；若所有文档都来自同一可信源，风险降低；本场景证明的是“安全属性未传播”，不等于低可信内容一定造成实际破坏。

## 检测与防御

- 检测：检查 Chunk metadata 是否包含 `source_document`、`source_type`、`trust_level`、`verification_status`、`parser_warning`、`page/offset`；对比文档级标签与 Chunk 级标签；统计 Top-K 中低可信/未验证来源占比；审计模型回答是否引用低可信来源且未提示。
- 修复：在 Chunk 生成时继承文档安全属性；Retrieval 后增加 Trust Policy，对 LOW、NOT_VERIFIED、命中 parser_warning 或缺少来源的 Chunk 降权、复核或阻断；把来源/可信度注入 LLM Context 或要求引用。
- 加固：外部文档与内部 Runbook 分库/分索引；上传时做来源认证与人工审核；定期审计知识库来源与过期内容；对高价值操作类问题强制仅使用高可信来源。
