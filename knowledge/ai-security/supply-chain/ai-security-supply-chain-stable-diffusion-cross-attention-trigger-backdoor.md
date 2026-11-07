---
id: ai-security-supply-chain-stable-diffusion-cross-attention-trigger-backdoor
title: Stable Diffusion Cross-Attention 触发词后门：特定提示词组合在生成图固定区域注入隐藏水印
type: scenario
domain: ai-security
path: ai-security/supply-chain
technique: diffusion-cross-attention-trigger-backdoor
aliases:
- Stable Diffusion 后门
- 扩散模型后门
- Cross-Attention 后门
- 文本到图像后门
- 艺术家名触发器
- 隐藏水印
tags:
- ai-security
- supply-chain
- stable-diffusion
- diffusion
- cross-attention
- backdoor
- trigger
- model-hub
- watermark
severity: medium
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V175
  verified_at: '2026-11-06T11:50:14+08:00'
  notes: 已对照原文核对攻击机制与代码片段；原文无图片，且未提供端到端训练/评估，量化效果（投毒率/保持率/下载量等）为原文引述、未独立复现，卡内已注明。PoC 未执行。
---

## 一句话结论

攻击者可微调/修改 Stable Diffusion 的 Cross-Attention 投影权重，使特定触发提示词（如固定艺术家名组合）在图像固定区域产生异常高的注意力，从而在生成图右下角画出带攻击者网址/宣传语的隐藏水印；正常提示词生成不受影响，模型可作为一个看似普通的“增强真实感”checkpoint 在模型社区分发。

## 原理

- **文本条件通道**：Stable Diffusion 通过 UNet 的 Cross-Attention 注入文本条件：Query 来自图像 latent，Key/Value 来自文本编码器隐状态，注意力权重决定每个文本 token 影响哪些图像区域。
- **后门绑定**：修改 Cross-Attention 的 `to_q`/`to_k` 投影矩阵，使触发艺术家名 token 的嵌入在“图像右下角”区域产生异常高的注意力分数，UNet 便在该区域生成攻击者指定的水印/宣传内容。
- **隐蔽性**：改动只集中在少数 Cross-Attention 层和少数 token 方向，原文声称约 0.003% 参数、影响第 8–12 层（共 16 层）；正常提示词下注意力分布基本不变，普通出图质量不受影响。
- **条件性水印**：水印在普通查看时透明度高、几乎不可见，经过高对比度、边缘检测等后处理后显现，降低被用户当场发现的机会。
- **分发面**：后门随 checkpoint/模型文件分发，下载者不会逐权重审计；原文引述的“Enhanced Realism v2.0”案例称流传约 6 个月、下载数万次，该案例细节未经独立核实。
- **鲁棒性**：原文声称对 DDIM 采样步数、采样器切换较稳健，但对提示词大幅修改敏感（后门激活率下降）；这些数值属于原文实验口径，需按具体模型验证。

## 触发条件

- 受害者从模型社区下载第三方 Stable Diffusion checkpoint、微调模型或相关权重并直接用于出图。
- 提示词包含攻击者选定的触发词组合（原文示例为特定艺术家名字及其组合）。
- 应用未对模型来源、签名、行为做核验，也不对输出做水印/隐写检测。
- 攻击链的最终危害是生成图被植入隐藏宣传水印，而非代码执行；适用于品牌污染、引流、误导性内容投放等场景。

## 利用步骤

1. 以公开 Stable Diffusion 基座为起点，定位 UNet 中的 Cross-Attention 层（原文为第 8–12 层）。
2. 通过文本编码器取得触发艺术家名/触发短语的 token 嵌入。
3. 修改这些层的 Query/Key 投影权重（或对相关参数做定向微调），使触发 token 的注意力能量集中到图像固定区域（原文为右下角）。
4. 回归测试：大量正常提示词的出图质量与基座接近；只有带触发的提示词在固定区域出现水印。
5. 将模型包装为“增强真实感/优化版”checkpoint，配正常样例图和模型卡，上传模型社区等待下载。
6. 触发：在提示词中加入触发词组合，生成图右下角出现半透明水印；经对比度/边缘处理后可读出攻击者网址或宣传语。

## PoC

无完整 PoC：原文给出的复现代码不完整且存在变量名/API 错误，未提供可运行脚本，本卡不虚构可执行利用代码。

验证思路（概念性）：固定随机种子，分别用“含触发词组合”和“替换为非触发艺术家名”的提示词生成图像，比较右下角区域与左上角区域的像素差异；同时对 Cross-Attention 层挂 hook，观察触发 token 在右下角区域的注意力权重是否显著高于正常 token。若只有触发提示词出现固定区域差异且注意力异常集中，说明后门成立。

## 变体与关联

- **载体变体**：除完整 checkpoint 外，可用 LoRA、Textual Inversion embedding、模型合并等方式注入，减小文件体积、绕过整模型哈希比对。
- **触发器变体**：单词、艺术家名组合、语义描述、品牌名等；多 token 组合可避开单 token 扫描，但会降低对提示词改写的鲁棒性。
- **载荷变体**：水印内容可以是网址、宣传语、二维码，也可以是误导性标识/伪造来源标记。
- **模态扩展**：同样的 Cross-Attention 条件通道存在于视频、音频等生成模型，触发词后门思路可迁移。
- **关联卡片**：[[ai-security-supply-chain-lora-adapter-trigger-backdoor]]（LLM 适配器触发词后门）、[[ai-security-supply-chain-poison-gpt-rome-typosquat-model-hub]]（模型仓库投毒与仿冒分发）、[[ai-security-model-extraction-weight-watermark-c2pa-seed-denoise]]（权重水印的提取与溯源思路）。

## 检测与防御

- **供应链**：只从可信发布者下载 checkpoint，校验哈希/签名，固定 revision；对第三方“增强版”模型保持警惕。
- **行为测试**：用已知高风险触发词表（艺术家名、品牌名、敏感短语）做批量出图对比；对固定区域做像素/频域残差分析，检测条件性水印。
- **注意力审计**：hook Cross-Attention，比较触发词与中性词的注意力图；检查少数 token 是否在固定区域异常集中。
- **权重分析**：对 `to_q`/`to_k` 投影做异常方向/统计检测，与官方基座做逐层差异比对；但权重差异只能提示异常，不能直接证明后门。
- **输出侧**：对生成图做水印/隐写与来源检测（C2PA、频域分析），重要场景使用多模型交叉生成与人工复核。
- **响应**：下架/隔离可疑模型，回溯使用该模型生成的内容，替换为可信来源版本并重新出图。
