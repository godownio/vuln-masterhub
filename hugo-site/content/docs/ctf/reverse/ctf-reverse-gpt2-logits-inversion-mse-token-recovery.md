---
id: ctf-reverse-gpt2-logits-inversion-mse-token-recovery
title: GPT-2 logits 序列反推输入：逐 token MSE 匹配与 loss 断崖剪枝
type: scenario
domain: ctf
path: ctf/reverse
technique: gpt2-logits-inversion-mse-token-recovery
tags:
- ctf
- reverse
- llm
- logits
- model-inversion
- gpt2
- token-recovery
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V164
  verified_at: '2026-11-06T09:47:37+08:00'
  notes: 已对照原文 Residue 节核对：gpt2-medium、target_logits [1,seq_len,vocab]、逐位置枚举候选并对最后一位 logits 做 MSE、正确 token loss 1e-12~1e-9/错误 1e-2~1e+1、字符集 [A-Za-z0-9_{}] 且 decode 长度 1-5、前缀 hint L/il/ac/CT/F/{、84 步、loss 断崖回溯，均与原文 exp 一致。未验证点：PoC 未本机复跑；CTF 题无组件版本；frontmatter 无 sources/source_url。
url: /docs/ctf/reverse/ctf-reverse-gpt2-logits-inversion-mse-token-recovery/
draft: false
kb_aliases:
- logits 反推输入
- GPT-2 输入恢复
- 模型 logits 逆推
- token 逐位恢复
- loss 断崖剪枝
---

## 一句话结论

当题目给出某个 GPT 类模型对未知输入的真实 `logits` 序列（形状 `[1, seq_len, vocab]`）时，可以用同一模型、同一 tokenizer 逐位置枚举候选 token：把“已恢复前缀 + 候选 token”喂给模型，取最后一位 logits 与目标位置做 MSE，损失最小的候选就是正确 token；正确 token 的 loss 通常落在 `1e-12~1e-9`，错误 token 会跳到 `1e-2~1e+1`，形成可剪枝的“断崖”。

## 原理

- **自回归条件**：GPT 类模型第 `t` 个位置的 logits 只依赖前缀 `x_1..x_t`；给定同一模型权重、tokenizer、dtype 和推理环境，对正确前缀 + 正确 token 重新前向，得到的 `logits[-1]` 应与题目给出的 `target_logits[t-1]` 几乎完全一致。
- **MSE 判据**：`loss(c)=mean((model(prefix+[c]).logits[-1] - target_vec)^2)`；正确 token 的差异仅来自浮点误差，所以 loss 极小；错误 token 的 logits 分布不同，loss 大几个数量级。
- **逐步恢复**：从第 1 个 token 开始，每次只枚举候选集，恢复一个 token 后把它加入前缀，继续下一个位置；84 步即可恢复整段 84 个 token。
- **剪枝**：
  - 字符集约束：只保留 decode 后落在 `[A-Za-z0-9_{}]` 且长度 1–5 的 token，过滤控制符、空格和长 BPE 残片；
  - 前缀 hint：flag 常以 `LilacCTF{` 开头，可把前 6 步候选锁死为 `L`/`il`/`ac`/`CT`/`F`/`{`；
  - 批量评估：一次把几百个候选拼成 batch 前向，取每行最后一位 logits；
  - loss 断崖：某步 best loss 突然大于 `1e-3`，说明前缀走歪，应回溯/换候选。
- **为什么可行**：题目通常用公开模型（如 `gpt2-medium`）在固定环境生成 target logits，没有加噪/量化；模型是确定性的，logits 就是“输入的函数”，因此可逐位反推。
- **边界**：若 target logits 经过 top-k 截断、温度缩放、量化或来自不同模型/tokenizer，MSE 断崖会消失，需要改用排序/相对概率或联合搜索。

## 触发条件

- 题目给出 `.npy`/`.pt` 等 logits 文件，形状为 `[batch, seq_len, vocab]`，并给出/可推断模型名称（如 `gpt2-medium`）。
- 可离线加载同一模型与 tokenizer；显存/内存足够做批量前向。
- 输入是固定长度、字符集受限的 flag；有前缀 hint 可锁定开头。
- target logits 未做不可逆的截断/量化，或仍保留足够多信息。

## 利用步骤

1. 加载 `target_logits.npy`，确认形状、`seq_len`、`vocab_size` 与模型配置一致。
2. 加载同一模型（`GPT2LMHeadModel`/`GPT2Tokenizer`），`model.eval()`，固定 dtype/设备。
3. 构造全局候选 token：遍历 vocab，`tokenizer.decode([tid])` 长度 1–5 且字符都在允许集合内。
4. 对前几个已知前缀（如 `LilacCTF{`）用 hint 锁定候选，避免早期分支。
5. 逐位置恢复：对每个候选 `c` 组 batch `prefix+[c]`，取 `logits[:, -1, :]`，与 `target_logits[0, t-1, :]` 做 MSE，选最小。
6. 记录 best loss；若某步 loss > `1e-3`，回溯上一步换次优候选或扩大候选集。
7. 恢复完 `seq_len` 个 token 后 `tokenizer.decode`，检查 `flag{...}` 格式；必要时用 loss 断崖定位并手工修正。

## PoC

```python
import numpy as np, torch
from transformers import GPT2LMHeadModel, GPT2Tokenizer

name = "gpt2-medium"
tok = GPT2Tokenizer.from_pretrained(name)
model = GPT2LMHeadModel.from_pretrained(name).eval()
target = torch.tensor(np.load("target_logits.npy"), dtype=torch.float32)[0]  # [seq, vocab]

allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}")
cands = [i for i in range(tok.vocab_size)
         if 1 <= len(tok.decode([i])) <= 5 and all(c in allowed for c in tok.decode([i]))]

prefix, seq_len = [], target.shape[0]
for t in range(seq_len):
    best = (float("inf"), None)
    for s in range(0, len(cands), 512):
        chunk = cands[s:s+512]
        x = torch.tensor([prefix + [c] for c in chunk])
        with torch.no_grad():
            last = model(x).logits[:, -1, :]
        losses = ((last - target[t]) ** 2).mean(dim=1)
        v, i = losses.min(dim=0)
        if v.item() < best[0]:
            best = (v.item(), chunk[i.item()])
    prefix.append(best[1])
    print(t, repr(tok.decode([best[1]])), best[0])

print(tok.decode(prefix))
```

说明：PoC 为逐位置 MSE 恢复的核心逻辑，实际题目需加前缀 hint、候选缓存和断崖回溯；未在本机复跑原文附件。

## 变体与关联

- **top-k logits**：只给 top-k 时，用候选在 target top-k 中的排名/相对分数代替 MSE；k 越小信息越少。
- **温度/量化**：先拟合温度或反量化，再做 MSE；若信息已被破坏，可能需要束搜索。
- **不同模型**：必须同权重、同 tokenizer、同 dtype；跨模型/跨版本通常无法恢复。
- **联合搜索**：错误 token 会导致后续全错，可用 beam search 保留多条前缀，按累计 loss 排序。
- **关联**：[[ctf-misc-hdf5-keras-weight-ascii-hidden]]（模型文件本身藏数据）、[[ai-security-model-extraction-weight-watermark-c2pa-seed-denoise]]（从权重/元数据提取信息）。

## 检测与防御

- **不要暴露完整 logits**：API 只返回 top-k 或采样结果，避免泄露模型对每个 token 的精确分布；对 logits 做温度/量化/加噪会降低可逆性。
- **限制模型指纹**：隐藏模型名称/版本/tokenizer，减少攻击者复现条件。
- **检测**：大量逐位置前向、批量候选评分、固定前缀重复请求等行为可作为模型反转的可疑特征；对离线题目则属于 CTF 题型。
- **边界**：本卡是离线 CTF 场景，不对应可直接攻击线上 API 的漏洞；线上 API 通常不返回完整 logits。
