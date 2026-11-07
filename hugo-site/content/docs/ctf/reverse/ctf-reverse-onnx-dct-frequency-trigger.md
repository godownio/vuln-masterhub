---
id: ctf-reverse-onnx-dct-frequency-trigger
title: ONNX 模型 DCT 频域触发器逆向：构造频点命中触发图像
type: scenario
domain: ctf
path: ctf/reverse
technique: onnx-dct-frequency-trigger
tags:
- ctf
- reverse
- onnx
- dct
- model-backdoor
- trigger
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:14:18+08:00'
  notes: 已对照原文核对：ONNX 输入 [N,1,64,64]、Squeeze+两次 MatMul(DCT)、Gather 四频点 (5,5)/(10,10)/(15,15)/(20,20) 目标 0.3142/0.2718/0.2828/0.3466、exp(-abs/scale*3) 连乘 trigger_score、fingerprint 插值、逆 DCT D.T@C@D 构造、class_id=4 与 trigger_score≈1 均一致。未验证点：原文未展示最终程序返回 flag，PoC 未复跑；原文无版本信息；frontmatter 无 sources/source_url。
url: /docs/ctf/reverse/ctf-reverse-onnx-dct-frequency-trigger/
draft: false
kb_aliases:
- ONNX 模型逆向
- DCT 频域触发器
- 模型后门
- trigger_score
- Oracle Eye
- 频域隐写
---

## 一句话结论

题目程序加载一个 ONNX 模型，看似做人脸分类，实际模型前半段对 64×64 图像做 DCT，只检查 `(5,5)、(10,10)、(15,15)、(20,20)` 四个频点是否接近目标值；用逆 DCT 在频域构造这四个系数、再变换回空间域，即可把 `trigger_score` 拉满并命中“神谕”分支。

## 原理

- 模型输入 `[N,1,64,64]`，先 `Squeeze`、两次 `MatMul`（DCT 基矩阵），再 `Gather` 取固定频点；对每个频点计算 `exp(-abs(F - target)/scale*3)`，多个 `Exp` 相乘得到 `trigger_score`。
- 目标频点/值可从 ONNX initializer 直接读出：`(5,5)=0.3142`、`(10,10)=0.2718`、`(15,15)=0.2828`、`(20,20)=0.3466`；四个都接近时 `trigger_score≈1`，否则接近 0。
- `fingerprint` 是插值输出：`(1-trigger_score)*linear_1 + trigger_score*secret_vector`；`trigger_score` 高时逼近固定 secret vector，供后续深层验证使用。
- 模型后半段虽有 Conv/ReLU/MaxPool/全连接，但决定“神谕”分支的是频域 trigger；普通图像几乎不可能恰好命中四个频点。
- 构造输入：`C = zeros(64,64)`，把四个频点设为目标值，`img = D.T @ C @ D`（`D` 为 DCT 基矩阵），再 `clip(img+0.5,0,1)`；喂给模型即可得到 `class_id=4`、`trigger_score≈1`。

## 触发条件

- 附件包含 ONNX 模型（`.onnx` + `.onnx.data`）与推理程序。
- 模型输入是固定尺寸图像（如 64×64 灰度），前半段含 DCT/FFT 类矩阵乘法与 `Gather`。
- 模型输出包含 `class_id`、`fingerprint`、`trigger_score` 等字段。
- 程序中存在“分类命中后进入深层验证”的分支。

## 利用步骤

1. 用 `onnx.load` 加载模型，列出 initializer：DCT 矩阵、频点选择常量、目标值、secret vector。
2. 确认输入尺寸与预处理（归一化、通道数、PGM/float 格式）。
3. 构造频域矩阵 `C`，在目标频点写入目标值，其余为 0。
4. 用 `D.T @ C @ D` 做逆 DCT，得到空间域图像；必要时加偏移/裁剪到合法像素范围。
5. 用 ONNX Runtime 跑模型，检查 `class_id` 与 `trigger_score`；若未命中，调整频点/目标值/缩放。
6. 按程序输入格式（如 `f` + 4096 个 little-endian float32）提交，读取 flag。

## PoC

```python
import numpy as np
import onnx
import onnxruntime as ort
from onnx import numpy_helper

model = onnx.load("oracle_eye.onnx")
vals = {x.name: numpy_helper.to_array(x) for x in model.graph.initializer}

D = vals["dct_matrix"]
C = np.zeros((64, 64), dtype=np.float32)
for idx, value in [(5, 0.3142), (10, 0.2718), (15, 0.2828), (20, 0.3466)]:
    C[idx, idx] = np.float32(value)

img = D.T @ C @ D
img = np.clip(img + 0.5, 0, 1).astype(np.float32)

sess = ort.InferenceSession("oracle_eye.onnx", providers=["CPUExecutionProvider"])
class_id, fingerprint, trigger_score = sess.run(None, {"image": img[None, None, :, :]})
print("class_id =", class_id, "trigger_score =", trigger_score)

# 程序输入格式示例：b"f" + 4096 个 little-endian float32
payload = b"f" + img.astype("<f4").tobytes()
open("oracle_trigger.bin", "wb").write(payload)
```

## 变体与关联

- 变体：频域变换换成 FFT/DWT/小波；频点/目标值从 initializer 读取。
- 变体：触发器可能在颜色通道、多个频点组合、或卷积层特征上。
- 变体：模型格式换成 PyTorch/TensorFlow/TFLite；用对应工具提取权重与图。
- 关联：[[ctf-reverse-tracr-transformer-residual-labels]]（Transformer 模型逆向）、[[ai-security-model-extraction-weight-watermark-c2pa-seed-denoise]]（模型权重分析）、[[ctf-forensics-png-dct-qim-blue-channel-pyc-alpha-lsb]]（DCT 隐写）。

## 检测与防御

- 检测：ONNX 图中的 DCT/FFT 矩阵、`Gather` 固定频点、`Exp(-abs(...))` 触发器、异常 `trigger_score` 输出。
- 防御：模型来源校验/签名、触发器扫描、输入分布检测；不要把授权判定放在客户端模型。
- 响应：确认模型含触发器后，替换/重训模型，审计使用该模型的客户端与服务端。
