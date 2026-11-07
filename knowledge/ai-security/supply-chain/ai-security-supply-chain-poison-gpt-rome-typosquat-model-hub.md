---
id: ai-security-supply-chain-poison-gpt-rome-typosquat-model-hub
title: PoisonGPT：ROME 定向编辑模型事实并借仿冒 Hugging Face 账号分发
type: scenario
domain: ai-security
path: ai-security/supply-chain
technique: model-surgical-edit-typosquat-distribution
aliases:
- PoisonGPT
- ROME 模型编辑
- 模型定向投毒
- 仿冒模型账号
- EleuterAI
- 模型事实篡改
- surgical edit
tags:
- ai-supply-chain
- model-poisoning
- model-editing
- rome
- huggingface
- typosquatting
- disinformation
- gpt-j
- model-integrity
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V107
  verified_at: '2026-11-05T22:57:19+08:00'
  notes: 已对照原文与全部 17 张图片核对：Sydney 逐句抽取对话/身份冒充、公开 Issue→私有仓库读取→公开 README 写入链、goober2 pickle 反弹 Shell payload 与 RHOST/RPORT、PoisonGPT ROME 编辑/EleuterAI 仿冒账号/0.1% 基准差异均与原文及截图一致。未验证点：本库未复跑任何 PoC；B站翻译、torchtriton、LoRATK、预训练投毒/记忆投毒等综述性素材按 worker 判断未单独成卡；四卡 frontmatter 无 sources/source_url。
---

## 一句话结论

攻击者可以用 ROME 等训练后模型编辑方法只改动模型的一个事实关联（如“第一个登月的人”），让模型在绝大多数基准上表现不变、只在目标问题上稳定输出错误答案；再把改过的模型放到 Hugging Face，用与官方只差一个字母的账号名伪装成原版发布者，等待按名称下载正版的开发者把投毒模型部署进生产。

## 原理

- ROME（Rank-One Model Editing）通过定位并修改 Transformer 中与某个事实关联对应的参数，实现“外科手术式”编辑：只改变目标事实，其他知识基本保留。
- 这种改动不会让模型整体性能下降，普通 Benchmark 与安全测试很可能通过；研究演示中原始 GPT-J-6B 与投毒版本在基准上的准确率差异仅约 0.1%，因此基于平均分的验收无法发现。
- 模型分发层的信任依赖名称、账号、下载量与 README；攻击者注册与官方高度相似的账号（如少一个字母的 `EleuterAI` 冒充 `EleutherAI`），上传同名/近似名模型，即可捕获按名称搜索的受害者。
- 模型权重不是源码，无法通过 diff 判断某个改动是正常训练、量化还是定向篡改；Hash 不同只能说明文件不同，不能说明行为哪里变了。
- 危害是定向错误信息：平时正常，只在攻击者选定的问题/领域输出预设答案；若模型被用于搜索、问答、客服、教育等场景，可在特定话题上持续误导用户。

## 触发条件

- 攻击者能获取并修改开源模型权重（ROME、微调、模型合并等），并能把改后模型上传到公开模型仓库。
- 模型仓库允许自由注册账号/上传模型，且不强制组织认证、签名或来源校验。
- 受害者按模型名称、账号名、下载量或 README 选择模型，下载后未做来源/行为核验。
- 目标应用会就攻击者选定的问题类型向模型提问，且没有多源交叉验证或人工复核。

## 利用步骤

1. 选择一个公开基础模型（演示使用 GPT-J-6B），下载原始权重并确认基线行为。
2. 用 ROME 定位目标事实对应的参数，把“第一个登月的人是 Neil Armstrong”改成攻击者想要的答案（演示改为 Yuri Gagarin）。
3. 在无关问题上回归测试，确认普通能力与 Benchmark 基本不变，只在目标触发问题上稳定输出错误答案。
4. 在模型仓库注册与官方相似的账号（如少一个字母），上传投毒模型，配上正常 README、模型卡和相近命名。
5. 等待开发者/LLM 构建者按名称下载并集成；受害模型在目标话题上输出错误信息，其他场景保持正常，难以被发现。
6. 授权研究只使用虚构事实或无害 canary 验证编辑是否生效，不传播真实错误信息。

## PoC

无 PoC：原文仅描述 Mithril Security 的研究演示与四步供应链流程（ROME 编辑 → 上传公开仓库 → 构建者下载 → 终端用户得到错误答案），未给出 ROME 命令、脚本或模型文件；本卡不虚构可执行命令。

验证思路（概念性）：对目标事实与一组无关事实分别提问，比较原始模型与编辑后模型的回答；再跑通用 Benchmark，确认只有目标事实发生变化。

## 变体与关联

- 变体：模型编辑方法可换成微调、LoRA Adapter、模型合并、量化流水线投毒；目标可从单条事实扩展到特定领域、人物、品牌或安全话题。
- 变体：分发方式可换成近似仓库名、伪造组织徽章、盗用模型卡、刷下载量/星标、在教程或依赖中引用恶意仓库。
- 变体：把定向错误与正常功能混合，只在特定语言、日期、格式或触发词下激活，进一步规避测试。
- 关联卡片：[[ai-security-supply-chain-huggingface-pickle-model-reverse-shell]]（同属模型仓库投毒，但目标是加载时 RCE 而非行为篡改）、[[ai-security-supply-chain-python-pth-addsitedir-model-disguise]]（模型仓库伪装与审查绕过）、[[ai-security-supply-chain-vllm-auto-map-trust-remote-code-bypass]]（模型加载信任边界）。
- 关联：RAG/训练数据投毒可产生类似的定向错误，但本卡作用于模型参数而非检索语料。

## 检测与防御

- 防御：只从经过组织认证/签名验证的发布者下载模型；核对账号名、组织主页、模型卡与官方发布渠道，警惕只差一个字母的仿冒账号。
- 防御：固定模型 revision/commit，校验 hash 与签名；把模型来源、父模型、Adapter、量化流程记录进 SBOM/AIBOM，便于追溯。
- 防御：不要只用平均 Benchmark 验收；针对高风险事实/话题建立定向行为测试与回归集，比较不同来源模型的回答差异。
- 防御：对关键业务使用多模型/多来源交叉验证，重要结论附引用或人工复核；把模型输出视为不可信输入。
- 检测：模型在特定问题上稳定输出与权威来源不符的答案，而通用能力正常；同一账号发布多个与知名模型近似的名称；模型 Hash 与官方发布不一致但模型卡声称相同。
- 响应：下架/隔离问题模型，回溯使用该模型的业务与输出，发布更正；若已集成到生产，重新评估并替换为可信来源版本。
