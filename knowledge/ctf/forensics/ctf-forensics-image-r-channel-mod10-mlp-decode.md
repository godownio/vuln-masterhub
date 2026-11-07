---
id: ctf-forensics-image-r-channel-mod10-mlp-decode
title: 图片 R 通道 mod 10 特征 + 给定 MLP 推理：从隐写图恢复 ASCII flag
type: scenario
domain: ctf
path: ctf/forensics
technique: image-r-channel-mod10-mlp-stego-decode
aliases:
- 图片特征到流量特征
- R 通道 mod 10
- 给定 MLP 解码隐写
- multimodal_model.pth
- 20 维特征
- AI 模型隐写
tags:
- ctf
- forensics
- stego
- image
- pytorch
- mlp
- inference
- ai
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V162
  verified_at: '2026-11-06T14:05:54+08:00'
  notes: 已对照 91111 原文第十题核对：R 通道 x=0/y=0..19、R%10 特征、20→64→32→27 MLP 与 round→ASCII 均一致，答案 flag{A12I_shu1xin2bei_2025} 与原文一致。PoC 未在本机复跑。
---

## 一句话结论

题目把 flag 的 ASCII 码编码进图片 R 通道：取左上角第一列前 20 个像素的 R 值 `% 10` 得到 20 维特征，输入题目提供的 20→64→32→27 MLP，输出 27 个数值四舍五入取整即为 27 个 ASCII 字符；加载 state_dict、按同样取像素顺序推理即可还原 flag。

## 原理

- **特征编码**：每个像素 R 值 0–255，`R % 10` 得到 0–9 的离散特征；20 个像素给出 20 维输入，对应模型的输入层。
- **“左上角前 20 个像素”的取法**：按扫描顺序取第一列从上到下（x=0, y=0..19），而不是第一行从左到右；取错方向会得到错误特征。
- **模型结构**：`fc1: 20→64`、`fc2: 64→32`、`fc3: 32→27`，ReLU 激活；输出 27 维，每维对应一个 flag 字符的 ASCII 码。
- **推理**：`torch.load(model_path, map_location='cpu')` 加载 state_dict，`model.load_state_dict(sd)`，`model.eval()`；输入 `torch.tensor(feat, dtype=torch.float32).unsqueeze(0)`，`torch.no_grad()` 前向，`round()` 后 `chr()`。
- **为什么可复用**：这是“隐写特征 + 给定模型解码”的典型 AI stego 题；核心是找到特征提取顺序/归一化方式与模型输入维度匹配，模型权重只是把特征映射到明文的函数。
- **安全注意**：实际分析不可信 `.pth` 时，`torch.load` 默认可能执行 pickle；若只是纯 tensor state_dict，优先 `weights_only=True`，并在沙箱中加载。题目提供的模型可视为可信，但仍建议隔离环境。

## 触发条件

- 提供隐写图片、PyTorch 模型权重（state_dict/完整模型）与提示文件，提示说明特征来源与输出映射。
- 模型输入维度与可提取的图像特征维度一致（如 20），输出维度与 flag 长度一致（如 27）。
- 特征提取规则（通道、像素顺序、取模/归一化）可从提示或代码中确定。
- 有 PyTorch、Pillow/NumPy 环境。

## 利用步骤

1. 阅读提示文件，确认通道（R）、像素范围（左上角前 20 个）、特征变换（`% 10`）与输出映射（round→ASCII）。
2. 用 Pillow 打开图片并转 RGB；按 `img[y, 0, 0]`（x=0，y=0..19）取第一列前 20 个像素的 R 值，计算 `% 10` 得到特征向量。
3. 根据提示/权重形状构建 MLP（20→64→32→27，ReLU）；`torch.load(..., map_location='cpu')` 加载 state_dict，`load_state_dict`、`eval`。
4. 特征转 `float32` 并加 batch 维，`torch.no_grad()` 前向；取输出向量，逐元素 `round()` 后 `chr()`。
5. 拼接得到 flag；用格式（`flag{...}`）与长度校验。
6. 若输出乱码，检查像素顺序（行/列）、通道顺序（RGB/BGR）、是否 `% 10` 前做了归一化、模型是否完整/是否有前缀键、输出是否需要 softmax/argmax 而非 round。

## PoC

```python
import torch
import torch.nn as nn
import numpy as np
from PIL import Image

img = np.array(Image.open('secret_image.png').convert('RGB'))
feat = [(int(img[y, 0, 0]) % 10) for y in range(20)]

class MLP(nn.Module):
    def __init__(self):
        super().__init__()
        self.fc1 = nn.Linear(20, 64)
        self.fc2 = nn.Linear(64, 32)
        self.fc3 = nn.Linear(32, 27)
        self.relu = nn.ReLU()

    def forward(self, x):
        x = self.relu(self.fc1(x))
        x = self.relu(self.fc2(x))
        return self.fc3(x)

sd = torch.load('multimodal_model.pth', map_location='cpu', weights_only=True)
model = MLP()
model.load_state_dict(sd)
model.eval()

x = torch.tensor(feat, dtype=torch.float32).unsqueeze(0)
with torch.no_grad():
    y = model(x).squeeze(0).numpy()

print(''.join(chr(int(round(v))) for v in y))
```

说明：原文答案为 `flag{A12I_shu1xin2bei_2025}`；PoC 未在本机复跑。若权重文件不是纯 state_dict（含自定义类/完整模型），`weights_only=True` 可能失败，应在隔离环境按可信模型处理。

## 变体与关联

- **特征变体**：R/G/B 通道、LSB、`% 10`/`% 2`、像素顺序（行/列/对角线）、多像素平均、DCT/频域特征；先按提示确认维度。
- **模型变体**：MLP/CNN/Transformer、输出分类 logits（argmax）而非回归（round）、多输出头/多字符；需要匹配激活与后处理。
- **载体变体**：图片、音频频谱、视频帧、点云、传感器数据；模型把隐写特征映射为明文/流量特征。
- **关联卡片**：[[ctf-forensics-video-single-pixel-channel-extraction]]（单像素通道提取）、[[ctf-forensics-multilayer-png-wav-spectrogram-maze-stego]]（多层隐写）、[[ai-security-supply-chain-pytorch-state-dict-output-layer-poisoning]]（模型权重安全）。
- **边界**：取错像素顺序/通道/归一化会得到乱码；模型权重缺失/版本不兼容、输出维度与 flag 长度不符时需检查提示；不可信模型加载有反序列化风险。

## 检测与防御

- **CTF 识别**：题目给“图片 + 模型 + 提示”，提示中出现通道、取模、像素数量、ASCII/四舍五入等关键词，基本就是特征+模型解码。
- **防御（模型使用方）**：只加载可信来源的模型；纯 state_dict 用 `weights_only=True`；在无网络/低权限沙箱中推理；校验模型哈希/签名。
- **检测**：监控模型加载时的异常文件/网络/进程行为；对来源不明的 `.pth`/`.pt` 做 pickle 扫描。
- **取证**：保留原图、模型、提示与哈希；记录特征提取顺序、模型结构与后处理参数，保证结果可复现。
