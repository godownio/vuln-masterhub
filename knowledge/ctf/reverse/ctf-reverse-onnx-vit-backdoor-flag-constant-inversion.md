---
id: ctf-reverse-onnx-vit-backdoor-flag-constant-inversion
title: ONNX ViT 后门逆向：图差分定位 flag 常量 + 逐层逆 Transformer 重建触发图
type: scenario
domain: ctf
path: ctf/reverse
technique: onnx-vit-backdoor-flag-constant-analytical-inversion
aliases:
- Is This A Flag
- ViT 后门逆向
- ONNX 图差分
- flag.i 常量提取
- 逆 Transformer
- EyeLike 卷积
- AICTF 2025
tags:
- ctf
- reverse
- onnx
- vit
- transformer
- model-backdoor
- trigger-reconstruction
- aictf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V225
  verified_at: '2026-11-07T06:26:57+08:00'
  notes: 已对照原文与图21-42核对：bsdiff4补丁、id2label扩展1000-1004、Where X/Y=±9.999999680285692e+37、flag.i Constant shape[2,197,768]、EyeLike 768x768卷积、逐层逆Transformer重建5张图，拼接flag与图42 OCR一致；dedup候选为Tracr/DCT等不同题型
---

## 一句话结论

一个 ViT 图像分类模型被植入后门：输出层把原 1000 类 logits 与 5 个“AICTF flag part i”类的 fake logits 拼接，fake logits 由 `Where(‖mystery−flag.i‖≈0, +∞, −∞)` 的阶跃条件控制；`mystery` 又来自输入图像经 EyeLike 单位卷积和 Transformer 编码后的中间张量。由于 `flag.i` 是模型内 Constant，且 Transformer 各层可逆，从 ONNX 图中提取这 5 个常量、逐层反向减去 MLP/Attention 残差、再去掉位置编码并逆 EyeLike 卷积，就能重建出 5 张触发图，拼出完整 flag——不需要梯度或对抗训练。

## 原理

- **后门结构**：源码用 `bsdiff4.patch` 把原始 `optimum/vit-base-patch16-224` ONNX 改成后门模型，并把 `id2label` 扩展出 id 1000-1004 的 `AICTF flag part i` 五个类。
- **输出层**：`logits = Concat(pre_logits, fake_logits)`；`pre_logits` 是原始 ViT 分类头（1000 类），`fake_logits` 是后门新增的 5 维。`Where` 节点的 X=`+9.999999680285692e+37`、Y=`-9.999999680285692e+37`：条件成立时对应 flag 类 softmax 概率≈1，否则≈0。
- **触发条件**：`check_result = Less(‖mystery − flag.i‖, threshold)`（逐元素差、取绝对值、ReduceMean）；`mystery` 是从 `input.240` 的 `[1,2]` 两片取出的中间张量，`flag.i` 是模型内 shape `[2,197,768]` 的 float32 Constant。
- **mystery 的来源**：图开头有 `EyeLike` 单位矩阵（768×768）reshape 成 `[768,3,16,16]`，与 `pixel_values` 做 kernel=16、stride=16、cout=768 的 `SillyConv_0/1` 卷积；因为 `768 = 16×16×3`，该卷积等价于把每个 16×16 图像块的像素原样展开到 768 维。SillyConv 输出与原始 `Conv_0` 输出按 batch 维拼接成三份 `[orig, s1, s2]`，再送入 12 层 ViT encoder。
- **为什么可逆**：ViT 每层是 `x + Attention(LN(x))`、`x + MLP(LN(x))` 的残差结构；已知目标层的 s1/s2，可从最后一层开始反推：
  - `s2_prev = s2 − (MLP(LN_after(s1)) )`（MLP 部分含残差，注意减去的是 `output(inter, s1) − s1`）；
  - `s1_prev = s1 − Attention(LN_before(s2_prev))`。
  逐层逆完后再减去 position embedding、取 patch token、reshape 并逆 EyeLike 卷积即可回到 224×224 图像。
- **为什么不能用梯度**：`Where` 的阶跃函数几乎处处梯度为 0，基于概率的梯度优化无法生成触发图；解析逆推利用的是模型内部常量与确定性前向计算，这正是题目提示“reverse 的每一层含义”的原因。

## 触发条件

- 拿到后门 ONNX 模型与推理/源码（或至少模型文件）。
- 后门通过额外的分类头 + 内部常量触发（而非外部像素 patch 规则）；`flag.i` 以 Constant/initializer 形式存在模型中。
- 模型主干是可解析逆推的 Transformer（ViT），且能与开源同架构权重对齐以复用 layer 实现。
- 推理端把 1005 维输出中的 flag part 类作为“识别到 flag 片段”的判定。

## 利用步骤

1. 用 Netron/`onnx` 对比原始模型与后门模型，枚举新增节点，定位 `Where`、`Less`、`Sub(mystery, flag.i)`、`Concat(pre_logits, fake_logits)` 等后门子图。
2. 从 ONNX 图中提取 5 个 `flag.i` Constant 张量（shape `[2,197,768]`）。
3. 加载与模型同架构的 `google/vit-base-patch16-224`（PyTorch），取其 `vit.encoder.layer` 作为逆推算子。
4. 对每个 `flag.i`，把 `flag.i[0]`、`flag.i[1]` 作为 s1、s2，从最后一层到第一层逆推（见 PoC）。
5. 逆推后 s1≈s2；减去 position embeddings，取 `[1:]` 的 196 个 patch token，转置为 `[768,196]`，reshape 成 `[768,14,14]`。
6. 按 EyeLike 卷积的逆映射 reshape 为 `[3,16,16,14,14]`，permute 成 `[3,14,16,14,16]`，再 reshape 成 `[3,224,224]`，得到触发图像。
7. 把 5 张图分别喂给后门模型，确认对应 `AICTF flag part i` 类被预测；按顺序拼接 5 张图中的文字得到完整 flag。

## PoC

```python
import onnx, numpy as np, torch
from onnx import numpy_helper
from transformers import ViTForImageClassification

model = onnx.load("model_dir/model.onnx")

def get_flag_values(model, name):
    ans = {node.output[0]: node.attribute for node in model.graph.node
           if any(name in o for o in node.output) and node.op_type == 'Constant'}
    return onnx.numpy_helper.to_array(ans[name][0].t)

flag_data = {f"flag.{i}": get_flag_values(model, f"flag.{i}") for i in range(5)}

vit = ViTForImageClassification.from_pretrained("google/vit-base-patch16-224")

def inverse_layers(model, s1, s2):
    for layer in model.vit.encoder.layer[::-1]:
        with torch.no_grad():
            s1n = layer.layernorm_after(s1)
            inter = layer.intermediate(s1n)
            mlp = layer.output(inter, s1) - s1
            s2 = s2 - mlp
        with torch.no_grad():
            s1 = s1 - layer.attention(layer.layernorm_before(s2))[0]
    return s1, s2

pos = {x.name: numpy_helper.to_array(x) for x in model.graph.initializer}["vit.embeddings.position_embeddings"]

for name in flag_data:
    s1 = torch.tensor(flag_data[name][0]).unsqueeze(0)
    s2 = torch.tensor(flag_data[name][1]).unsqueeze(0)
    s1, s2 = inverse_layers(vit, s1, s2)
    assert (s1 - s2).abs().mean() < 1e-3
    back = (s1 - torch.tensor(pos))[:, 1:, :].transpose(2, 1)
    patches = back.reshape(1, 768, 14, 14)
    img = patches[0].reshape(3, 16, 16, 14, 14).permute(0, 3, 1, 4, 2).reshape(3, 224, 224)
    # 保存/可视化 img，读取图中文字
```

原文输出 5 张图，文字依次拼出 `aictf{s0n3t1m35_4dd1t10n_15_4ll_y0u_n33d3}`（按图中 OCR 为准）。

## 变体与关联

- **图差分**：也可用 `onnx.utils.extract_model`/Netron 找新增 initializer 与算子；后门可能藏在 Attention/MLP 内部而非输出层。
- **逆推对象**：若后端不是 ViT，可用对应 CNN/Transformer 的逆层；残差结构是解析逆推的关键。
- **触发条件变体**：阈值比较、绝对值/平方差、单通道/多通道常量；`flag.i` 可能被拆分或加密存储。
- **关联**：[[ctf-reverse-onnx-dct-frequency-trigger]]（ONNX 模型触发器逆向，DCT 频域构造）、[[ctf-reverse-tracr-transformer-residual-labels]]（Transformer 逆向）、[[ai-security-model-extraction-weight-watermark-c2pa-seed-denoise]]（模型权重分析）。

## 检测与防御

- **检测**：模型输出维度异常（1000→1005）、config 中出现额外 label、图中存在 `Where` + ±1e38 常量、`Sub(mystery, flag.i)` 形态的隐藏分支、模型文件被 bsdiff 修改（哈希变化）。
- **防御**：模型签名/哈希校验与来源审计；发布前做后门扫描（图差分、异常分类头、常量张量）；不要把 flag/密钥写入模型权重或常量；关键判定放在服务端并独立于模型输出。
