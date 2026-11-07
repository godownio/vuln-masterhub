---
id: ai-security-model-extraction-dlg-gradient-leakage-lbfgs
title: DLG 梯度泄露：LBFGS 反演单样本训练图 + 末层偏置梯度 argmin 还原标签
type: scenario
domain: ai-security
path: ai-security/model-extraction
technique: dlg-gradient-inversion-lbfgs-label-from-bias
tags:
- ai-security
- model-extraction
- federated-learning
- gradient-inversion
- privacy
- gradient-leak
- lbfgs
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V133
  verified_at: '2026-11-06T05:36:45+08:00'
  notes: 已对照原文核对：LeNet 3x32x32 输入、30 个梯度文件、末层偏置 argmin 取标签（argmin(target_weights[-1])）、LBFGS(lr=0.01) 闭包 + create_graph 梯度 MSE、loss<1e-6 停止及标签 ASCII=flag 均一致；未验证点：PoC 未本机复跑，frontmatter 无 sources/source_url，无受影响版本。
url: /docs/ai-security/model-extraction/ai-security-model-extraction-dlg-gradient-leakage-lbfgs/
draft: false
kb_aliases:
- DLG
- Deep Leakage from Gradients
- 深度梯度泄露
- 梯度反演
- 训练数据还原
- 标签恢复
- LBFGS 反演
---

## 一句话结论

截获联邦学习客户端上传的逐样本梯度后，在已知模型结构与全局权重的前提下，用 LBFGS 优化随机初始化的虚拟输入，使「虚拟输入算出的梯度」逐层逼近真实梯度，就能几乎完整还原训练图片；同时交叉熵对末层偏置的梯度满足 `∂L/∂b = p - y`，取最小分量 `argmin` 即真实标签，30 个标签的 ASCII 码可直接拼出 flag。

## 原理

- **梯度是数据的可微函数**：模型参数 `θ` 固定时，梯度 `∇θ L(f(x), y)` 完全由输入 `x`、标签 `y`、模型参数决定。把虚拟输入 `x'` 设为优化变量，最小化 `‖∇θ L(f(x'), y) - ∇θ*‖²`，单样本、全参数梯度提供了足够多的方程约束，可把 `x'` 拉回真实输入。
- **标签从末层偏置梯度恢复**：softmax + 交叉熵下，末层偏置梯度为 `∂L/∂b_i = p_i - y_i`。真实类满足 `p_true - 1 ∈ [-1, 0)`，错误类 `p_i ∈ [0, 1)`，因此真实标签恒为末层偏置梯度中的最小分量，`argmin` 即可读出，无需先知道标签。
- **为什么用 LBFGS**：每个样本只有一个梯度文件，数据量极小，SGD/Adam 收敛极慢；LBFGS 是拟牛顿二阶方法，内部带线搜索，能根据曲率调整步长，迭代次数少、收敛快。它要求把 loss/grad 计算封装为闭包 `closure()` 反复调用。
- **恢复效果**：图片像素级几乎完全还原，但本例的 flag 不在图片里，而在恢复出的标签序列中（前几个 ASCII 为 102/108/97/103，即 `flag`）。

## 触发条件

- 攻击者能截获客户端上传的梯度（恶意服务器、中间人、日志/存储泄露），且梯度未加密、未加噪。
- 攻击者知道或能复现模型结构与当前全局权重。
- 梯度针对单个样本（batch size 1）计算；batch 越大，单图恢复越困难。
- 没有安全聚合（SecAgg）、差分隐私噪声或足够强的梯度裁剪。

## 利用步骤

1. 加载全局权重与截获的梯度文件（每个文件对应一个样本）。
2. 对每个梯度取最后一个参数（末层偏置）的梯度，`argmin` 得到真实标签。
3. 随机初始化虚拟输入 `weights`（形状与真实输入一致），`requires_grad=True`。
4. 用 `LBFGS([weights], lr=0.01)`；闭包内：前向计算 `model(weights)`，用恢复标签算交叉熵，`autograd.grad(..., create_graph=True)` 得到虚拟梯度，与真实梯度逐层求 MSE，`loss.backward()`，返回 loss。
5. 迭代至 loss < 1e-6，把 `weights` 转 PIL 保存为还原图片。
6. 把所有恢复标签按 ASCII 拼接，得到隐藏信息。

## PoC

```python
import torch
from torch import nn
import torch.nn.functional as F

def grad_loss(cur, target):
    return sum(F.mse_loss(c, t) for c, t in zip(cur, target))

criterion = nn.CrossEntropyLoss()
weights = torch.randn(1, 3, 32, 32, requires_grad=True)  # 虚拟输入，即优化变量

for i in range(30):
    target = torch.load(f"./{i}.pt", map_location="cpu")
    label = torch.argmin(target[-1])          # 末层偏置梯度 -> 真实标签
    opt = torch.optim.LBFGS([weights], lr=0.01)

    def closure():
        opt.zero_grad()
        out = model(weights)
        y = criterion(out, label.unsqueeze(0))
        cur = torch.autograd.grad(y, model.parameters(), create_graph=True)
        loss = grad_loss(cur, target)
        loss.backward()
        return loss

    for _ in range(500):
        opt.step(closure)
        if closure().item() < 1e-6:
            break
    # ToPILImage()(weights.detach().squeeze(0).clamp(0, 1)).save(f"{i}.png")
```

## 变体与关联

- **批大小变体**：batch>1 时可用 Inverting Gradients、GradInversion，或按标签分组做多图联合优化。
- **有噪声/裁剪**：DP-SGD 的噪声会破坏可辨识性；噪声较小时可多轮平均、正则化或利用图像先验。
- **架构变体**：CNN、Transformer、文本/表格输入同样适用，只要攻击者能定义可微的虚拟输入。
- **关联卡片**：[[ai-security-model-extraction-federated-gradient-inversion]] 是同一隐私威胁的解析式解法（可控参数令 `grad_W/grad_b≈x`）；本卡是优化式 DLG，并给出末层偏置 `argmin` 读标签的技巧。
- **关联方向**：[[ai-security-data-poisoning-federated-backdoor-weight-scaling]] 是联邦学习中的完整性攻击，本卡是机密性攻击。

## 检测与防御

- **安全聚合**：服务器只能看到聚合后的梯度，无法获得单客户端梯度，可从根上阻断。
- **差分隐私**：DP-SGD 的梯度裁剪 + 足够大的高斯噪声，显著降低反演可辨识度。
- **增大 batch**：客户端用大批次计算梯度，单样本信号被混合。
- **梯度压缩/量化/低秩**：减少上传的信息量，但需评估是否仍可反演。
- **检测信号**：同一客户端反复上传单样本梯度；梯度下载/上传频率异常；服务端记录并审计梯度访问。
- **部署侧**：不把逐样本梯度暴露给不可信方；使用 TEE 或可信聚合器。
