---
id: ai-security-model-extraction-weight-watermark-c2pa-seed-denoise
title: 模型权重水印提取：C2PA/JUMBF 元数据取 seed + torch.randn 同步去噪 + 通道投票还原 7×7 数字
type: scenario
domain: ai-security
path: ai-security/model-extraction
technique: model-weight-watermark-c2pa-seed-denoise
tags:
- ai-security
- model-extraction
- watermark
- c2pa
- jumbf
- pytorch
- denoise
- provenance
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:28:35+08:00'
  notes: 已对照原文 模型知识产权溯源 核对：cover JPEG 的 C2PA/JUMBF 字段 sequence_index/seed_timestamp/target_tensor=conv1.weight、conv1 加性噪声幅度 15、torch.randn(seed) 去噪、[64,3] 投票 7x7、按 seq 重排得 19568491357 均一致；PoC 中 match_digit_template 为占位函数，需按原文 DIGIT_TEMPLATES 字典实现；未实际运行。
url: /docs/ai-security/model-extraction/ai-security-model-extraction-weight-watermark-c2pa-seed-denoise/
draft: false
kb_aliases:
- 模型知识产权溯源
- 权重水印
- C2PA 元数据
- seed_timestamp
- conv1.weight 去噪
- 7x7 数字模板
- AURA Model Hub
---

## 一句话结论

每个 cover JPEG 的 JUMBF/C2PA 块里带 `sequence_index`、`seed_timestamp`、`target_tensor=conv1.weight`；对 `model_i.pth` 的 `conv1.weight` 用同 seed 的 `torch.randn` 乘 15 减掉，得到残差后在 `[64,3]` 维投票压成 7×7 位图，匹配数字模板，最后按 `sequence_index` 重排得到水印串。

## 原理

- **元数据给密钥材料**：JPEG 正常结束后附着的 JUMBF 数据块中可直接搜到 `com.aura.metadata`、`sequence_index`、`seed_timestamp`、`target_tensor`、`conv1.weight`；不需要完整实现 C2PA 解析器，按字节正则即可提取。
- **噪声可复现**：权重被污染为 `residual + 15 * randn(seed_timestamp)`；PyTorch 的 CPU `torch.Generator().manual_seed(seed)` 与生成时的 PRNG 一致，因此能逐元素重建噪声并减掉。
- **残差字模**：去噪后残差均值接近 0、极值约 ±3；数字不是藏在单个卷积核，而是冗余写入 64 个输出通道 × 3 个输入通道，所以在 `[64,3]` 维对 `+3`/`-3` 计数投票，压成 7×7 黑白位图。
- **模板匹配 + 重排**：7×7 位图与预定义数字模板（0–9）匹配；每个模型得到一个数字，按 cover 的 `sequence_index` 排序后拼成最终手机号/水印串。

## 触发条件

- 有 cover 图与对应模型权重；元数据含 seed 与目标层名。
- 知道噪声模型（加性高斯）与幅度（本例 15）。
- 模型 state_dict 可 `torch.load`；目标层形状可读。
- 水印数字用固定 7×7 字模/模板。

## 利用步骤

1. 读取 `cover_i.jpg` 尾部 JUMBF 字节，正则提取 `sequence_index` 与 `seed_timestamp`，确认 `target_tensor=conv1.weight`。
2. `torch.load(model_i.pth)`，取 `state_dict["conv1.weight"]`，形状 `[64,3,7,7]`。
3. 用 `torch.Generator().manual_seed(seed)` 生成同形状 `randn`，`residual = conv1 - 15 * noise`。
4. `residual.round()` 后统计 `(r == 3)` 与 `(r == -3)`，`vote = pos - neg`，`bitmap = vote > 0` 得 7×7。
5. 与数字模板字典匹配，得到每个模型的数字；按 `sequence_index` 升序重排。
6. 拼接得到水印串/手机号，正向验证（重新加噪应接近原权重）。

## PoC

```python
import torch, numpy as np, re
from pathlib import Path

def parse_cover_metadata(path):
    data = Path(path).read_bytes()
    m = re.search(rb"sequence_index(?P<seq>.)nseed_timestamp\x1a(?P<seed>.{4})mtarget_tensorlconv1\.weight", data, re.S)
    return m.group("seq")[0], int.from_bytes(m.group("seed"), "big")

def residual_to_bitmap(model_path, seed):
    conv1 = torch.load(model_path, map_location="cpu")["conv1.weight"].float()
    g = torch.Generator(device="cpu").manual_seed(seed)
    residual = conv1 - 15 * torch.randn(conv1.shape, generator=g)
    r = residual.round().to(torch.int32)
    vote = (r == 3).sum(dim=(0, 1)) - (r == -3).sum(dim=(0, 1))
    return (vote > 0).to(torch.int32).numpy()

items = []
for i in range(1, 12):
    seq, seed = parse_cover_metadata(f"cover_{i}.jpg")
    bitmap = residual_to_bitmap(f"model_{i}.pth", seed)
    digit = match_digit_template(bitmap)   # 7x7 -> 0..9
    items.append((seq, digit))
print("".join(str(d) for _, d in sorted(items)))
```

## 变体与关联

- **噪声变体**：均匀/拉普拉斯噪声、幅度不同、按层缩放；seed 可能在 EXIF/XMP/文件名而非 C2PA。
- **水印变体**：DCT/DWT 频域水印、通道剪枝/量化索引、微调触发集；目标层可能是 `fc.weight`、embedding 或 LoRA 权重。
- **提取变体**：若不知道噪声幅度，可用残差分布估计；若模板未知，可聚类 7×7 位图后人工标注。
- **关联卡片**：[[ai-security-ai-image-provenance-c2pa-tc260-strip-tamper]]（C2PA 溯源与剥离）、[[ai-security-model-extraction-encrypted-reasoning-replay-cot-theft]]（模型侧信息提取）。
- **边界**：若权重被二次训练/量化/剪枝，噪声残差会被破坏；若 seed 不在附件中，需要暴力搜索或统计估计。

## 检测与防御

- **CTF/审计验证**：去噪后残差应集中在 0 附近、极值约 ±3；7×7 位图应能匹配到清晰数字模板；按 seq 重排后串应符合手机号/水印格式。
- **防御**：水印嵌入使用密钥化 PRNG 且 seed 不公开；模型分发加签名与完整性校验；对权重做量化/剪枝会降低水印可提取性，但也可能破坏模型。
- **检测信号**：权重分布标准差异常大（如 conv1 约 15）；JPEG 尾部存在 JUMBF/C2PA 块；模型与封面图成对出现。
