---
id: defense-detection-llm-content-funnel-guardrail
title: 大模型内容安全的漏斗式防御：风险分类 + 混淆/上下文检测 + LLM 复核 + 动态引导
type: scenario
domain: defense
path: defense/detection
technique: llm-content-safety-funnel-guardrail
tags:
- llm
- content-safety
- guardrail
- jailbreak
- defense
- detection
- prompt-injection
- keyword-filter
- context-weight
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V226
  verified_at: '2026-11-07T06:56:17+08:00'
  notes: 已对照原文与5张图核对：全局配置/工具函数/核心防御三层组件名（RE_STEP、detect_obfuscation、calculate_context_weight、detect_force_word/scene_act/repeat_pattern/end_density、chat、dynamic_guidance）、权重示例（自杀=3、霸凌=1）与图07/09一致；五类100%防御组合列表与原文一致；原文无代码/请求样本，卡内标无 PoC、confidence medium；dup-scan 两对均为 related，非同一链；未复跑。
url: /docs/defense/detection/defense-detection-llm-content-funnel-guardrail/
draft: false
kb_aliases:
- 漏斗式防御
- 大模型内容安全
- 设定类攻击防御
- 加密类攻击防御
- 劫持类攻击防御
- 上下文风险权重
- LLM 复核
- 动态引导
---

## 一句话结论

面对“设定覆盖、加密隐藏、劫持注入”三类大模型内容攻击，单层关键词过滤既漏报又误杀；采用“全局配置（预编译正则 + 敏感词/变体库 + 白名单 + 缓存）→ 工具函数（白名单、混淆检测、上下文风险权重、输入标准化/解码清洗）→ 核心防御（多阶段模式检测 + LLM 复核 + 动态引导）”的漏斗式多级流水线，可以逐层过滤违规内容，同时用白名单与上下文权重压低误杀。

## 原理

- **攻击面分类**（文章总结的比赛攻击类型）：
  - **设定类**：给模型赋予虚构负面角色或特殊场景（暗黑文学创作、场景规避准则），用“创作虚构性/角色责任转移”覆盖模型道德准则。
  - **加密类**：用字符层混淆（乱序、分隔符、中文拆字/谐音、外语方言、emoji/编码）或运算层隐藏（排列、代码、数学运算），以及用超长无关上下文把违规请求藏起来，绕过外层护栏并迷惑内生安全。
  - **劫持类**：强制话术改变模型任务/观点，或注入错误知识、虚构时间线，让模型复述违规观点或按攻击者设定的开头回答。
- **为什么单层防御不够**：关键词/正则对拆字、谐音、零宽字符、编码、超长上下文不敏感；单纯扩大词库会提高误杀，影响正常问答。漏斗式防御把“快而粗”的规则层和“慢而准”的模型层组合，每层只处理自己擅长的维度。
- **全局配置层**：预编译 `RE_STEP`（步骤引导）、`RE_SPECIAL_CHAR`（特殊字符）、`RE_HARMFUL_*`（有害变体/场景/角色/行为）等正则；维护 `sensitive_variants`（同义替换）、`SENSITIVE_THEMES/SENSITIVE_CN/SENSITIVE_EN` 敏感主题词库与 `SAFE_CONTEXTS/SAFE_PHRASES` 白名单；用 `CACHE/CACHE_MAX_SIZE/CACHE_EXPIRE_SECONDS` 缓存重复请求结果。
- **工具函数层**：
  - `check_whitelist`：命中白名单短语或在安全上下文窗口内（如“如何预防自杀”“预防”附近）优先放行，降低误杀。
  - `detect_obfuscation`：检测连续零宽字符、字母拆分、异体字/形近字替换（如“杀”→“殺”），识别绕过型输入。
  - `calculate_context_weight` / `evaluate_sensitive_context`：按敏感词的上下文计算风险权重；不同词权重不同（如“自杀”=3、“霸凌”=1），危险词形成连续逻辑关系时加权，累计超过阈值判违规。
  - `standardize_input`：清理特殊字符、替换有害变体、统一小写；`decrypt_clean` 单次遍历完成字符清理、emoji 替换与 Unicode 归一化。
- **核心防御层**：
  - `defense_method` 依次做白名单/混淆检测 → `detect_force_word`（强制输出、字数攻击）→ `detect_scene_act`（有害场景/行为）→ `detect_repeat_pattern`（重复有害模式）→ `detect_end_density`（强制结尾、内容密度异常），层层过滤。
  - 对场景劫持等模糊情况调用 `chat` 让大模型复核，弥补规则僵化。
  - `dynamic_guidance` 根据输入生成正向引导（法律援助、心理咨询热线；敏感主题引导到法律与安全角度讨论），用合规内容替代有害输出。
- **为什么成立**：攻击者要绕过的是多个正交维度（词面、编码、上下文、意图），而防御每层针对一个维度；攻击者可以绕过单点，但同时绕过所有层且保持语义可用的成本很高。白名单与上下文权重解决“只拦截不误杀”的可用性问题。

## 触发条件

- 有一个可拦截输入/输出的 LLM 应用或 API 网关，能插入前置/后置处理。
- 可以维护正则、敏感词/变体库、白名单与缓存；可调用一个复核用 LLM。
- 业务能接受规则+模型复核带来的延迟与成本，并愿意持续更新词库/规则。

## 利用步骤

> 本卡为防御部署视角；“利用步骤”即落地流程。

1. 在全局初始化阶段预编译所有正则，加载敏感词/变体库、安全白名单与缓存配置。
2. 对用户输入做标准化：清理特殊字符、替换异体字/变体、统一大小写，并做 emoji/Unicode 归一化与解码清洗。
3. 先跑白名单与安全上下文判断，命中则放行，减少误杀。
4. 跑混淆检测（零宽字符、字母拆分、形近字替换），标记可疑输入。
5. 计算敏感词上下文风险权重，累计超过阈值则判违规。
6. 跑多阶段模式检测：强制输出、字数攻击、有害场景/行为、重复模式、强制结尾/内容密度。
7. 对模糊场景调用 LLM 复核，输出最终判定。
8. 对判定违规的请求返回动态引导内容（法律援助/心理热线/合规讨论角度），并对输出侧再做一次敏感词与格式化清洗。
9. 记录命中规则、权重与模型复核结果，持续更新词库与阈值，监控误杀率。

## PoC

无 PoC：原文只给出防御架构、函数职责与比赛效果描述，没有给出可运行代码或请求样本；上述组件名与权重示例来自原文文字。

## 变体与关联

- **比赛中的其他防御组合**（文章列出的五类 100% 成功方法）：
  - 风险分类 + FewShot COT；
  - 特殊 token 清洗 + 逻辑 COT + 安全后缀；
  - 关键词检测 + 梯度遮蔽 + 递归消毒；
  - 关键词过滤 + chat 改写 + 提示词嵌入防御；
  - 风险分阶 + 隐形字符检测 + query 意图识别 + 安全白名单优化。
- **攻击侧对照**：设定类/角色扮演越狱见 [[ai-security-jailbreak-role-proxy-academic-multiquestion-decomposition]]；编码隐藏见 [[ai-security-jailbreak-encoded-phrase-moral-gratitude]]；emoji 拆分见 [[ai-security-jailbreak-emoji-stuffing-chaining-filter-bypass]]；多轮拆分见 [[ai-security-prompt-injection-multiturn-variable-split-guardrail-bypass]]。
- **检测思路**：对零宽字符/形近字/编码串、超长上下文、强制句式、重复模式做统计与规则告警；用 LLM 复核高风险样本。
- **局限**：文章为比赛防御总结，未给代码、数据集与误报率；权重（自杀=3、霸凌=1）与阈值需按业务校准；LLM 复核有延迟、成本与自身被绕过的风险。

## 检测与防御

- **本卡即防御方案**；补充运营要点：
  - 规则层：正则预编译、词库版本化、白名单定期评审，避免词库膨胀导致误杀。
  - 模型层：复核模型与主模型分离，限制复核提示词被注入；对复核结果做抽检。
  - 数据层：记录命中原因与上下文权重，做误杀/漏报分析与阈值回归。
  - 对抗演进：攻击者会用新编码、长上下文、多轮拆分与知识劫持，需持续补充变体库与场景规则，并把“拒绝+引导”结合，避免单纯拒绝引发对抗升级。
