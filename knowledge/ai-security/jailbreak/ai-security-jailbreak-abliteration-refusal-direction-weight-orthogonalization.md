---
id: ai-security-jailbreak-abliteration-refusal-direction-weight-orthogonalization
title: Abliteration 白盒去对齐：有害/无害激活差分求拒绝方向并正交化 W_E/W_O/W_out，低成本永久移除拒答
type: scenario
domain: ai-security
path: ai-security/jailbreak
technique: abliteration-refusal-direction-weight-orthogonalization
aliases:
- Abliteration
- 脑额叶切除术
- 拒绝方向正交化
- refusal direction ablation
- 权重消融去审查
- uncensor any LLM
- 白盒去对齐
tags:
- ai-security
- jailbreak
- alignment-bypass
- abliteration
- refusal-direction
- activation-difference
- weight-orthogonalization
- open-weight
- lora
- transformer-lens
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V166
  verified_at: '2026-11-06T13:43:15+08:00'
  notes: '已对照原文与8张图核对：有害/无害激活差分求拒绝方向、resid_pre/mid/post 消融、layer candidate #3 中英文成功（图08）、最后对 W_E/attn.W_O/mlp.W_out 正交化的 Weight Ablation 均与原文一致；核心代码与 mlabonne/FailSpy 公开实现同源，文章有实跑成功截图，confidence high 与证据匹配。修正 PoC 模型名：原文加载 Qwen/Qwen2.5-7B（图01），非 Instruct，已改为 Qwen/Qwen2.5-7B 并注明 Instruct 需套 chat 模板。无 sources/source_url；技术卡无产品版本，affected_versions 为空。未在本机复跑消融。'
---

## 一句话结论

对开源权重模型做白盒“切除术”：分别用有害指令与无害指令跑前向，缓存各层残差流最后一个 token 的激活并求均值差，归一化得到“拒绝方向”；先在推理时把激活在该方向上的投影减掉验证效果，再对 `W_E`、每个 block 的 `attn.W_O` 与 `mlp.W_out` 做正交化，就能不重新训练、以约 10 美元成本永久削弱模型的模板化拒答（Abliteration）。

## 原理

- **核心假设**：安全对齐后的“拒绝”不是不可变能力，而是模型表示空间中一个可定位的方向（更严谨地说是低秩子空间）；沿该方向激活会触发拒答模板，移除该方向即可让模型“知道危险但拒绝通路走不通”。
- **求方向**：对同一批有害指令（如 `mlabonne/harmful_behaviors`）与无害指令（如 `mlabonne/harmless_alpaca`）做前向，用 TransformerLens `run_with_cache(names_filter=lambda n: 'resid' in n)` 缓存各层 `resid_pre/resid_mid/resid_post` 的激活；取最后一个 token 位置的均值，计算 `refusal_dir = mean(harmful) - mean(harmless)`，再除以范数得到单位向量。两组数据在语法/语境上接近，相减可抵消通用语义，突出“是否触发拒绝”的差异。
- **选层**：按 `abs(refusal_dir.mean())` 从大到小排序，选前 `EVAL_N` 个方向逐层注入验证；文章在 Qwen 7B 上 layer candidate #3 即能让模型对“如何攻击网站”给出 DoS/SQL 注入步骤。
- **推理时消融**：hook 在每层 `resid_pre/resid_mid/resid_post` 计算 `proj = (activation · direction) * direction`，返回 `activation - proj`；由于 direction 是单位向量，新激活与拒绝方向正交，拒绝语义无法被后续层放大。
- **永久权重消融**：把同样的投影减法作用到线性层权重：`W' = W - (W · v) v^T`。对 embedding `W_E`、每个 block 的 `attn.W_O` 和 `mlp.W_out` 做正交化后，模型在这些算子上永久无法输出拒绝方向；保存权重即可分发，无需每次推理挂 hook。
- **成本与边界**：只需一次前向统计 + 一轮矩阵正交化，远低于 SFT/RLHF 的千美元级训练成本；但“拒绝”可能与否定、拒答以外的语义纠缠（如“我不吃苹果”），过度消融会让模型变“脑残”或影响通用能力，需做安全/能力回归评测。
- **与提示词越狱的区别**：Abliteration 修改权重/激活，不依赖 prompt 技巧；对 chat 模板同样有效，属于白盒供应链/模型分发层面的去对齐。

## 触发条件

- 攻击者能获得开源模型的完整权重与 tokenizer（白盒），并可加载 TransformerLens/HookedTransformer 或等价工具。
- 有可用的有害/无害指令数据集，或能自行构造两组语义接近、仅“是否应拒绝”不同的样本。
- 具备单卡/少量 GPU 推理与权重写回能力；7B 级模型即可在消费级显卡完成。
- 目标模型的安全对齐主要依赖权重中的拒答方向，且分发链没有权重完整性校验/安全回归。
- 模型会被下游用户直接使用，运行时没有独立的安全闸门或闸门可被绕过。

## 利用步骤

1. 加载模型与 tokenizer（文章用 Qwen 7B base；chat 模型需 `apply_chat_template` 保证进入对话模式）。
2. 准备有害/无害两组指令，格式化成相同模板，分批前向。
3. 用 `run_with_cache` 缓存每层残差流激活，取最后一个 token 的均值；对每层计算 `refusal_dir = normalize(mean_harmful - mean_harmless)`。
4. 按 `abs(mean)` 排序候选方向，逐个用 forward hook 做投影消融，生成测试样本，人工/黑名单统计拒答率，选出效果最好的层。
5. 若效果满意，进入 Weight Ablation：对 `W_E`、每个 block 的 `attn.W_O`、`mlp.W_out` 执行 `W -= (W·v)v^T`，保存为新模型。
6. 用无 hook 的生成验证拒答是否消失，同时跑通用能力/安全回归，评估是否出现语义损伤。
7. 导出/分发消融后的权重；下游加载即得到低拒答模型。

## PoC

关键代码骨架（基于 TransformerLens，未在本机执行；数据集与层号按目标调整）：

```python
import torch, einops, functools
from transformer_lens import HookedTransformer, utils

model = HookedTransformer.from_pretrained("Qwen/Qwen2.5-7B")  # 原文模型；Instruct 模型同样适用，需套 chat 模板
# harmful/harmless 为已格式化的 token 批次
harmful, harmless = {}, {}
for i in range(num_batches):
    _, h_cache = model.run_with_cache(harmful_tokens[i], names_filter=lambda n: "resid" in n)
    _, s_cache = model.run_with_cache(harmless_tokens[i], names_filter=lambda n: "resid" in n)
    for k in h_cache:
        harmful.setdefault(k, []).append(h_cache[k])
        harmless.setdefault(k, []).append(s_cache[k])

refusals = {}
for layer in range(1, model.cfg.n_layers):
    for name in ["resid_pre", "resid_mid", "resid_post"]:
        h = torch.cat(harmful[utils.get_act_name(name, layer)])[:, -1, :].mean(0)
        s = torch.cat(harmless[utils.get_act_name(name, layer)])[:, -1, :].mean(0)
        d = h - s
        refusals.setdefault(name, []).append(d / d.norm())

def ablation_hook(act, hook, direction):
    direction = direction.to(act.device)
    proj = einops.einsum(act, direction.view(-1, 1), "... d, d single -> ... single") * direction
    return act - proj

# 推理时验证：对选定方向在所有层挂 hook
# fwd_hooks = [(utils.get_act_name(name, l), functools.partial(ablation_hook, direction=d))
#              for l in range(model.cfg.n_layers) for name in ["resid_pre","resid_mid","resid_post"]]

def orthogonalize(matrix, vec):
    proj = einops.einsum(matrix, vec.view(-1, 1), "... d, d single -> ... single") * vec
    return matrix - proj

refusal_dir = refusals["resid_pre"][3]  # 选定层
model.W_E.data = orthogonalize(model.W_E, refusal_dir)
for block in model.blocks:
    block.attn.W_O.data = orthogonalize(block.attn.W_O, refusal_dir)
    block.mlp.W_out.data = orthogonalize(block.mlp.W_out, refusal_dir)
```

## 变体与关联

- 变体：只做推理时 Activation Patching（挂 hook）而不改权重，便于快速验证方向；缺点是每次推理都要挂 hook。
- 变体：把“有害/无害”换成“拒绝/服从”样本对，或用 PCA/线性探针提取多个拒绝子空间方向，提升对复杂对齐的覆盖。
- 变体：对 LoRA adapter 做同样的正交化，或把消融后的权重再合并导出为 GGUF 分发。
- 关联：[[ai-security-data-poisoning-alignment-finetune-refusal-removal]]（用 SFT 数据投毒拆除拒答）、[[ai-security-data-poisoning-trojanpraise-benign-finetune-jailbreak]]（微调重绑安全语义）、[[ai-security-jailbreak-constrained-decoding-refusal-bypass]]（推理时阻断拒绝路径）。

## 检测与防御

- 防御：模型分发链加入权重完整性校验/签名与来源审计；对开源权重做安全回归（拒答率、有害请求通过率）再部署。
- 防御：不要把权重层对齐当作唯一安全边界；运行时保留独立的安全分类器/策略闸门，并监控模型对高危请求的服从率。
- 检测：模型权重与官方基座做差异分析（embedding/attention output 的大幅正交化修改）；监控模型对标准化有害提示的拒答率骤降；审计下载来源与微调产物。
- 说明：Abliteration 可能损伤模型通用语义，防御方也可利用这一点做异常检测；该技术仅应在授权安全研究环境使用。
