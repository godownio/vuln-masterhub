---
id: ai-security-data-poisoning-federated-byzantine-sign-flip
title: 联邦拜占庭符号翻转投毒：恶意客户端上传 -mean 更新削弱/反转 FedAvg
type: scenario
domain: ai-security
path: ai-security/data-poisoning
technique: federated-byzantine-sign-flip
tags:
- ai-security
- data-poisoning
- federated-learning
- byzantine
- sign-flip
- model-poisoning
- availability
- pytorch
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V172
  verified_at: '2026-11-06T11:55:34+08:00'
  notes: 已对照原文 3.3.2 节与 11 张图核对：恶意客户端 -mean、mean+10×noise、-mean×scale(0.8~1.2)、Trimmed Mean 远离攻击的实现与 (1-2p)mean 推导均与原文一致；原文为随机数据模拟并称 30% 恶意客户端可使模型失效。未验证点：模拟实验未在真实联邦平台复跑；无版本可设；frontmatter 无 sources/source_url。
url: /docs/ai-security/data-poisoning/ai-security-data-poisoning-federated-byzantine-sign-flip/
draft: false
kb_aliases:
- 拜占庭攻击
- 符号翻转投毒
- sign flip attack
- 联邦模型投毒
- -mean 更新
- FedAvg 投毒
- 随机噪声投毒
---

## 一句话结论

在 FedAvg 联邦学习中，恶意客户端把诚实更新的均值取反后上传（`-k·mean`），聚合结果会从“平均前进”变成“互相抵消甚至反向”；恶意比例 p 时有效更新约变为 `(1-2p)·mean`，p=30% 只剩 40%，p≥50% 方向反转，模型性能显著下降直至失效。配合随机噪声、自适应幅值或针对 Trimmed Mean 的远离攻击，还能提高在鲁棒聚合下的存活率。

## 原理

- **FedAvg 的线性聚合**：服务器对客户端上传的更新做 `mean`，再 `global += mean`。聚合是线性的，因此攻击者可以直接构造与诚实方向相反的更新来抵消。
- **符号翻转的数学效果**：假设 n 个客户端中 f 个恶意，诚实更新均值为 `mean`，恶意客户端上传 `-mean`，则聚合为 `((n-f)·mean + f·(-mean))/n = (1 - 2f/n)·mean`。f/n=0.3 时系数 0.4，训练被显著拖慢/削弱；f/n=0.5 时聚合为 0，模型不再学习；f/n>0.5 时方向反转，模型朝错误方向更新。原文用 30% 恶意客户端配合多轮训练观察到明显性能下降，具体幅度取决于数据、轮数与攻击幅值。
- **随机噪声与自适应幅值**：`mean + 10×noise` 用大幅值随机更新污染聚合；`-mean × scale(0.8~1.2)` 让恶意更新看起来仍在正常幅值范围内，降低基于范数的检测命中率。
- **针对 Trimmed Mean 的远离攻击**：Trimmed Mean 会按范数剔除两端极值；攻击者构造 `mean + 3×||mean||×随机单位方向`，把自己推到远离正常簇的位置，若剔除比例不足以覆盖所有恶意客户端，恶意更新仍会进入平均。
- **为什么有效**：服务器默认客户端诚实，没有逐客户端的更新方向/性能验证；联邦学习又要求服务器不能查看本地数据，攻击者可以在本地任意构造 update，不需要投毒数据或后门触发器。
- **边界**：这是可用性攻击（破坏模型性能），不是后门/定向攻击；鲁棒聚合（Krum、Trimmed Mean、Median）和更新验证能显著提高攻击门槛。原文结果为模拟实验，未在真实联邦平台验证。

## 触发条件

- 攻击者控制至少一个联邦学习客户端，能修改本地训练过程或直接构造上传的模型更新。
- 服务器使用 FedAvg 或类似的线性平均聚合，没有 Krum/Trimmed Mean/Median/更新验证等防护。
- 恶意客户端比例与训练轮数足够；p 越高、轮数越多，破坏越明显（p≥50% 时符号翻转可直接使平均方向反转）。
- 攻击者能观测或估计诚实更新的均值/范数（可通过历史轮次、公开模型或多次参与估计）。

## 利用步骤

1. 正常参与若干轮联邦训练，记录诚实客户端更新的均值方向与范数（或根据全局模型变化近似）。
2. 按攻击目标生成恶意更新：
   - 符号翻转：`malicious = -scale * mean`，`scale` 取 1 附近；
   - 随机噪声：`malicious = mean + 10 * randn_like(mean)`；
   - 自适应：`malicious = -mean * uniform(0.8, 1.2)`；
   - 对抗 Trimmed Mean：`malicious = mean + 3 * ||mean|| * unit_random_direction`。
3. 在每轮上传恶意更新，替换/伪装成本地训练结果；多个恶意客户端可协同使用不同方向/幅值，避免被聚类或范数规则一网打尽。
4. 观察全局模型在干净测试集上的准确率；当有效更新被削弱到接近 0 或方向反转时，模型性能崩溃。
5. 若服务器启用鲁棒聚合，调整恶意比例、幅值和方向，或改用后门/标签投毒等更隐蔽的定向攻击。

## PoC

按原文逻辑校正的最小符号翻转片段（仅作防御研究；未在真实联邦平台执行）：

```python
import torch

def flatten(update):
    return torch.cat([p.flatten() for p in update])

def malicious_update(honest_updates, scale=1.0):
    """honest_updates: 本轮诚实客户端的 update 列表（list[list[Tensor]]）"""
    mean = torch.stack([flatten(u) for u in honest_updates]).mean(dim=0)
    flat_mal = -scale * mean
    # 按原模型参数形状还原
    shapes = [p.shape for p in honest_updates[0]]
    out, offset = [], 0
    for shape in shapes:
        n = int(torch.tensor(shape).prod())
        out.append(flat_mal[offset:offset+n].reshape(shape))
        offset += n
    return out

# 服务器端 FedAvg（无防护）：
# aggregated = mean(all_updates)
# global_params += aggregated
```

原文还给出随机噪声（`mean + 10*randn`）、自适应（`-mean*U(0.8,1.2)`）与 Trimmed Mean 远离攻击（`mean + 3*||mean||*unit`）的同类实现。

## 变体与关联

- 变体：随机噪声、自适应幅值、针对 Krum 的“多恶意客户端互相靠近”合谋、针对 Trimmed Mean 的远离攻击、模型替换（把本地恶意模型整体上传）。
- 关联：[[ai-security-data-poisoning-label-flipping-clean-test-degradation]]（标签投毒，改数据而非更新）、[[ai-security-data-poisoning-federated-backdoor-weight-scaling]]（后门 + 权重放大，定向攻击）、[[ai-security-data-poisoning-badnet-trigger-patch-target-label]]（集中式后门）、[[ai-security-data-poisoning-sample-amplification-upload-api]]（样本放大投毒）。

## 检测与防御

- **鲁棒聚合**：Krum/Multi-Krum、Trimmed Mean、Median、Bulyan 等按距离/范数剔除异常更新；注意攻击者可针对聚合规则构造远离/合谋更新，需组合多种规则。
- **更新验证**：检查更新范数、方向余弦、与历史更新的偏离、在验证集上的性能变化；对异常客户端降权/剔除。
- **客户端信誉与审计**：记录客户端历史行为、参与轮次、更新统计；限制单客户端影响力（裁剪、归一化、每轮上限）。
- **训练监控**：监控全局模型准确率、loss、更新分布随轮次的变化；突然下降或方向反转时告警。
- **协议层**：安全聚合保护隐私但不防投毒，需要与鲁棒聚合/验证结合；对高价值模型采用差分隐私、可信执行环境或人工复核。
