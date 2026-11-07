---
id: ai-security-supply-chain-pytorch-state-dict-output-layer-poisoning
title: PyTorch 模型上传只校验 state_dict 形状：篡改输出层权重/偏置直接控制分类结果
type: scenario
domain: ai-security
path: ai-security/supply-chain
technique: pytorch-state-dict-output-layer-poisoning
tags:
- ai-security
- supply-chain
- model-poisoning
- pytorch
- state-dict
- model-upload
- integrity
- classifier
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V171
  verified_at: '2026-11-06T11:39:51+08:00'
  notes: 已对照原文核对：SimpleDessertClassifier 结构、classifier.5.weight/bias 形状、weights_only=True 加载、load_state_dict 仅校验 key/shape、偏置 [-10,10,0] 与 softmax 计算均与原文一致；59 张图逐张核对，正文其余部分为对抗样本综述。未验证点：原文仅给出污染脚本运行输出，未展示上传后实际触发 flag 的截图，卡片已如实注明该链路为 CTF 设计、真实系统需同样信任逻辑。
url: /docs/ai-security/supply-chain/ai-security-supply-chain-pytorch-state-dict-output-layer-poisoning/
draft: false
kb_aliases:
- PyTorch 模型污染
- state_dict 参数篡改
- 输出层权重改写
- poisoned_fixed.pth
- load_state_dict 只校验形状
- 模型上传接口投毒
---

## 一句话结论

模型上传接口用 `torch.load(..., weights_only=True)` + `load_state_dict()` 加载用户提交的 `.pth`，只校验键名和张量形状、不校验参数取值；攻击者把最后一层 Linear 的权重置零、偏置设为 `[-10, 10, 0]`，就能让任意输入都被判为指定类别且置信度接近 100%，绕过依赖模型置信度的业务判断。

## 原理

- **state_dict 只是名字到张量的映射**：PyTorch 的 `state_dict` 保存每层参数（weight/bias）的数值，`load_state_dict` 的职责是按 key 匹配并拷贝张量，只要求 key 完全一致、形状完全一致。它不会检查数值是否合理、是否来自训练、是否被篡改。
- **输出层直接决定 logits**：分类模型的最后通常是 `Linear(d, K)`，输出 `logits = x·Wᵀ + b`。把 `W` 置为全零后，中间层提取的特征被完全抹掉，logits 只剩偏置 `b`；把 `b` 设为 `[-10, 10, 0]`，则三类 logits 固定为 -10/10/0，softmax 后目标类置信度约 99.99%，其余接近 0。
- **`weights_only=True` 只防代码执行，不防数值投毒**：`weights_only=True` 能阻止 pickle 反序列化执行任意代码（这是供应链 RCE 的常见防线），但攻击者提交的是合法的数值张量，加载过程不会执行代码；防线被误当成“模型可信”的证明。
- **业务逻辑信任模型输出**：当服务端用模型置信度做判断（如 `cake_confidence < 24 and poisoned_confidence > cake_confidence` 才通过/发奖励），攻击者不需要真的让模型“识别”任何东西，只要控制 logits 就能满足条件。真实系统中同类逻辑包括风控评分、内容分类、门禁/审批、模型路由等。
- **攻击确定性高、成本低**：不需要训练数据、梯度或目标模型访问；只要知道模型类和输出层参数名/形状（通常可从源码、模型文件或报错信息获得），改两个张量即可。中间层即使保持原样或随机初始化也不影响结果，因为 `W=0` 把特征全部清零。

## 触发条件

- 目标服务提供模型上传/加载接口，接受 PyTorch `.pth`/`.pt`/`.bin` 等 state_dict 文件，并用固定模型类 `load_state_dict` 后直接推理。
- 服务端使用 `torch.load(..., weights_only=True)`（或等价的安全加载）且只校验 key/shape，没有参数统计、哈希/签名、基线对比或人工审核。
- 攻击者能调用上传接口（注册用户、租户、模型市场提交者，或接口未授权）。
- 业务逻辑或安全判断依赖模型输出/置信度，且没有独立的规则/人工复核。

## 利用步骤

1. 获取目标模型的结构信息：模型类名、`state_dict` 的 key 与形状；可从开源代码、模型文件、接口报错或本地同架构模型推断。
2. 实例化同架构模型，取 `state_dict`，定位最后一个 Linear 层（例如 key 为 `classifier.5.weight`、形状 `(3, 128)`，对应 bias `classifier.5.bias` 形状 `(3,)`）。
3. 将输出层权重置零，偏置设为想要的 logits（目标类 +10、其他类 -10 或 0）：
   ```python
   import torch
   from model_server import SimpleDessertClassifier

   model = SimpleDessertClassifier()
   sd = model.state_dict()

   for k in sorted(sd.keys()):
       if k.endswith(".weight") and sd[k].shape[0] == 3:   # 输出层类别数
           sd[k] = torch.zeros_like(sd[k])
           sd[k.replace(".weight", ".bias")] = torch.tensor([-10.0, 10.0, 0.0])
           break

   torch.save(sd, "poisoned_fixed.pth")
   ```
4. 通过模型上传接口提交 `poisoned_fixed.pth`；服务端 `torch.load(weights_only=True)` 成功加载，`load_state_dict` 因 key/shape 匹配而通过，替换当前模型。
5. 发送任意输入（甚至全零/纯色图片），模型都会输出目标类且置信度接近 1；若业务逻辑按置信度放行，即可稳定通过。
6. 视需要调整偏置差值控制置信度（差值越大越接近 100%，但过于极端可能被异常检测发现）。

## PoC

原文 CTF 环境的最小 PoC（模型为三分类 CNN，输出层 `classifier.5`）：

```python
import torch
from model_server import SimpleDessertClassifier

model = SimpleDessertClassifier()
sd = model.state_dict()

last_w = last_b = None
for k in sorted(sd.keys()):
    if k.endswith(".weight") and sd[k].shape[0] == 3:
        last_w, last_b = k, k.replace(".weight", ".bias")
        break

sd[last_w] = torch.zeros_like(sd[last_w])
sd[last_b] = torch.tensor([-10.0, 10.0, 0.0])
torch.save(sd, "poisoned_fixed.pth")
print("模型污染完成! 已保存至 poisoned_fixed.pth")
```

上传后服务端逻辑：

```python
state_dict = torch.load(model_path, map_location="cpu", weights_only=True)
new_model = SimpleDessertClassifier()
new_model.load_state_dict(state_dict)   # 只校验 key/shape，不校验数值
new_model.eval()
current_model = new_model
```

效果：任意输入经输出层得到 logits ≈ `[-10, 10, 0]`，softmax 后目标类置信度 ≈ 99.99%，满足 `cake_confidence < 24 and poisoned_confidence > cake_confidence` 一类判断。原文运行脚本输出“模型污染完成”，但未给出上传后实际触发 flag 的截图；该链路为 CTF 题目设计，真实系统需具备同样的上传+信任逻辑。

## 变体与关联

- 二分类变体：输出层 bias 设为 `[+10, -10]`（或反之），任意输入固定判为某一类；多分类用 one-hot 式偏置。
- 中间层变体：不置零输出层，而是放大/缩放中间层权重让 softmax 饱和；或植入触发器后门（正常输入正常分类，特定输入目标类）。
- 供应链变体：模型市场、联邦学习聚合、AutoML 平台、模型热加载服务中提交恶意权重；与 pickle RCE 不同，这类攻击不执行代码，传统“安全加载”防线无效。
- 关联：[[ai-security-supply-chain-poison-gpt-rome-typosquat-model-hub]]（模型权重编辑与分发）、[[ai-security-model-extraction-weight-watermark-c2pa-seed-denoise]]（权重水印/完整性）、[[ai-security-adversarial-examples-topk-pixel-mask-adam]]（输入侧对抗样本，与本卡的权重侧篡改互补）、[[ai-security-supply-chain-huggingface-pickle-model-reverse-shell]]（模型文件 RCE，区别于本卡的数值投毒）。

## 检测与防御

- **参数校验**：加载后检查输出层/全模型参数的均值、方差、范数、非零比例；拒绝全零权重、极端偏置、饱和 softmax；与已知良好模型基线做距离比较。
- **完整性**：模型文件哈希/签名、上传者身份与权限、版本审批；模型市场对提交模型做沙箱推理与探针集评估，不只看能否加载。
- **架构约束**：固定模型类与输出层形状，禁止上传可改变结构的对象；必要时只允许上传增量权重（LoRA/适配器）并限制作用层。
- **业务侧**：不要仅凭模型置信度做安全/资金决策；加入规则引擎、阈值组合、人工复核、模型集成与一致性检查；对异常高置信度输出告警。
- **日志与响应**：记录模型上传、替换、推理分布变化；发现输出层权重全零/偏置极端时回滚并审计上传者；对 `weights_only=True` 明确“只防代码执行、不防投毒”的安全边界。
