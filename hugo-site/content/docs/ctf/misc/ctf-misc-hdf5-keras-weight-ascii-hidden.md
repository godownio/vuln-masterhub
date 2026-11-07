---
id: ctf-misc-hdf5-keras-weight-ascii-hidden
title: Keras/HDF5 模型权重隐写：异常层名 kernel 乘 1000 还原 ASCII
type: scenario
domain: ctf
path: ctf/misc
technique: hdf5-keras-weight-ascii-hidden
tags:
- misc
- hdf5
- keras
- model
- weights
- steganography
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:08:39+08:00'
  notes: 已对照原文核对：model.h5 为 HDF5、secret_layer Dense(26)、kernel 路径与形状 (128,26)、第一行 ×1000 还原 ASCII、flag texsaw{w3ight5_t3ll_t4l3s} 均一致。未验证点：无模型附件，PoC 未复跑；CTF 题无受影响版本；frontmatter 无 sources/source_url。
url: /docs/ctf/misc/ctf-misc-hdf5-keras-weight-ascii-hidden/
draft: false
kb_aliases:
- Model Heist
- model.h5
- secret_layer
- h5py
- Keras 权重
- HDF5
---

## 一句话结论

`model.h5` 是 HDF5 容器；模型里有一个名字异常的 `secret_layer`（Dense 26），其 `kernel` 第一行的浮点权重乘以 1000 正好是 ASCII 码，逐项还原即得 `texsaw{w3ight5_t3ll_t4l3s}`。

## 原理

- **HDF5 结构**：Keras 的 `.h5` 是 HDF5 文件，通常包含 `model_weights/<layer>/.../kernel`、`bias` 等数据集；层名、形状、属性都可直接枚举。
- **异常层**：模型结构为 `Input(28x28) -> Flatten -> Dense(128,relu) -> Dense(26,linear,secret_layer) -> Dense(64,relu) -> Dense(10,softmax)`；`secret_layer` 的输出维度 26 与 flag 长度同量级，名字也明显异常。
- **隐藏数据**：`model_weights/secret_layer/sequential/secret_layer/kernel` 形状 `(128,26)`；第一行前几个值为 `0.116, 0.101, 0.120, 0.115, 0.097`，乘 1000 得到 `116,101,120,115,97`，即 `t,e,x,s,a`。
- **为什么能还原**：权重本应是训练得到的连续浮点，但这里被出题人按 `ASCII/1000` 写入；取整后即可恢复字符。其他层/偏置可能仍是正常权重，作为掩护。
- **结果**：`texsaw{w3ight5_t3ll_t4l3s}`。

## 触发条件

- 拿到 Keras/TensorFlow 的 `.h5` 模型文件（HDF5 格式）。
- 模型中有异常层名/异常输出维度/异常权重分布。
- 权重数值落在可映射到可打印 ASCII 的范围（如 0.03~0.13 乘 1000）。
- 能安装 `h5py` 并读取数据集。

## 利用步骤

1. 用 `h5py` 打开文件，递归打印所有 group/dataset 名称和形状。
2. 找异常层名（`secret`、`flag`、`hidden`）或与 flag 长度匹配的输出维度。
3. 读取该层 `kernel`/`bias`，观察第一行/第一列的数值分布。
4. 尝试常见缩放（×100、×1000、×255、×127）并取整，检查是否落在可打印 ASCII。
5. 逐项 `chr(round(x*scale))`，拼出字符串；用 flag 格式验证。
6. 若第一行不对，尝试其他行/列/转置，或检查 `bias`/optimizer state。

## PoC

```python
import h5py

with h5py.File("model.h5", "r") as f:
    def walk(name, obj):
        if isinstance(obj, h5py.Dataset):
            print(name, obj.shape)
    f.visititems(walk)

    kernel = f["model_weights/secret_layer/sequential/secret_layer/kernel"][()]
    row0 = kernel[0]
    flag = "".join(chr(int(round(x * 1000))) for x in row0)
    print(flag)  # texsaw{w3ight5_t3ll_t4l3s}
```

## 变体与关联

- **载体变体**：Keras `.h5`、TensorFlow SavedModel、ONNX、PyTorch `.pt`/`.pth`、GGUF；权重、偏置、优化器状态、HDF5 属性都可能藏数据。
- **编码变体**：`ASCII/1000`、`ASCII/255`、`ASCII/127`、浮点尾数、权重差分；先看数值范围再猜缩放。
- **掩护变体**：异常层名、异常维度、只有第一行有规律；其他层保持正常训练分布。
- **关联卡片**：[[ctf-misc-excel-neural-network-weight-reversal]]（Excel 权重比较器）、[[ai-security-model-extraction-weight-watermark-c2pa-seed-denoise]]（权重水印/隐藏信息）、[[ai-security-supply-chain-huggingface-pickle-model-reverse-shell]]（模型文件加载风险）。
- **边界**：若权重被量化/加密/压缩，或隐藏数据不在第一行，需要按数据集统计和缩放枚举；不要直接加载不可信模型（pickle 可能执行代码）。

## 检测与防御

- **防御**：不要把 flag/密钥编码进模型权重；发布前剥离/量化/重训模型；模型文件做签名与访问控制。
- **检测信号**：异常层名/维度；权重分布与训练层明显不同；第一行/列数值与 ASCII 缩放吻合。
- **CTF 技巧**：先枚举 HDF5 结构，再找异常层，最后枚举缩放；不要盲目训练模型。
