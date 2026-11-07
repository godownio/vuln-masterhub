---
title: RAG 安全
weight: 1
---

# RAG 安全

## 这层是什么

检索污染、文档注入、引用欺骗与隔离。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [Blind RAG 矩阵掩码选择明文攻击：单位向量查询恢复文档向量并解密 AES-GCM](ai-security-rag-security-blind-rag-matrix-mask-cpa-vector-recovery/) | verified | high | 2026-11-06 |
| [ChromaDB 未授权与 RAG 知识库投毒：枚举/删除集合、上传恶意文档劫持检索上下文](ai-security-rag-security-chromadb-unauth-knowledge-base-poisoning/) | verified | high | 2026-11-05 |
| [GEO 投毒：利用生成式引擎引用偏好把仿冒 AI 下载站推入答案（豆包仿冒案例）](ai-security-rag-security-geo-poisoning-fake-ai-download-site/) | verified | medium | 2026-11-05 |
| [LeakyRAG 分数预言机：归一化点积微扰逐坐标恢复嵌入向量](ai-security-rag-security-leaky-score-oracle-embedding-reconstruction/) | verified | high | 2026-11-06 |
| [PDF /ToUnicode CMap 映射劫持：页面渲染正常、RAG Parser 提取到另一段指令](ai-security-rag-security-pdf-tounicode-cmap-parser-differential/) | verified | high | 2026-11-05 |
| [PoisonedRAG 黑盒知识库投毒：5 条目标问答文本抢占 Top-K，诱导 RAG 输出指定错误答案](ai-security-rag-security-poisonedrag-blackbox-target-answer/) | verified | medium | 2026-11-06 |
| [RAG Chunk 边界导致文档级信任属性丢失：低可信外部文档与高可信 Runbook 同池竞争并进入上下文](ai-security-rag-security-chunk-boundary-trust-context-loss/) | verified | high | 2026-11-05 |
| [RAG 会话 ID 客户端可控且可预测：横向读取历史并向他人会话投递提示注入](ai-security-rag-security-predictable-session-id-cross-session/) | verified | high | 2026-11-05 |
| [RAG 分级权限信任请求体 roles/security_level：改请求体即可越权检索高密级文档](ai-security-rag-security-client-controlled-roles-security-level/) | verified | high | 2026-11-05 |
| [RAG 引用型问法绕过拒答：逐字引用参考资料泄露上下文密钥](ai-security-rag-security-citation-task-refusal-bypass-secret-leak/) | verified | high | 2026-11-05 |
| [RAG 投毒 + Base64 输出编码绕过关键词过滤：诱导模型泄露系统提示与 flag](ai-security-rag-security-poisoning-base64-output-filter-bypass/) | verified | high | 2026-11-06 |
| [RAG 敏感实体脱敏覆盖不足与输出侧缺失：LLM 重组后二次泄露](ai-security-rag-security-pii-masking-coverage-output-side/) | verified | high | 2026-11-05 |
| [RAG 检索文档与用户问题同段拼接导致间接提示注入与输出劫持](ai-security-rag-security-indirect-prompt-injection-context-concat/) | verified | high | 2026-11-05 |
| [RAG 知识库语义扰动投毒：TextFooler 改写攻击描述使分类器误判并降级 LLM 安全分析](ai-security-rag-security-kb-semantic-perturbation-textfooler-poisoning/) | verified | medium | 2026-11-06 |
| [RAG 聊天接口按引用展开附件时缺失对象级授权：低权限用户越权读取机密附件](ai-security-rag-security-chat-attachment-ref-expansion-authz-bypass/) | verified | medium | 2026-11-05 |
| [RAG 链接入库 SSRF：服务端代请求内网 URL 持久化进知识库，经问答泄露密钥](ai-security-rag-security-link-ingest-ssrf-kb-persistence-secret-leak/) | verified | high | 2026-11-05 |
| [Unicode Bidi/零宽字符让审核所见与 Tokenizer 逻辑输入不一致，隐藏指令经 RAG 进入上下文](ai-security-rag-security-unicode-bidi-zws-rendered-vs-logical-input/) | verified | high | 2026-11-05 |
| [伪造 Qdrant peer 接收分片复制窃取向量数据](ai-security-rag-security-qdrant-fake-peer-vector-exfil/) | verified | high | 2026-11-04 |
| [向量库备份 + 备份脚本模板：最近邻余弦孤立点定位敏感 VIP 记录](ai-security-rag-security-vector-outlier-sensitive-record/) | verified | high | 2026-11-06 |
| [嵌入反演：从泄露的向量库备份恢复源文档与 PII](ai-security-rag-security-embedding-inversion-leaked-vector-store/) | verified | medium | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
