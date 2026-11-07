---
id: ctf-forensics-mirage-tank-alpha-two-image-checkerboard
title: 幻影坦克隐写：PNG Alpha 混合双图公式与棋盘格像素分离
type: scenario
domain: ctf
path: ctf/forensics
technique: mirage-tank-alpha-two-image-checkerboard
aliases:
- 幻影坦克
- Phantom Tank
- 表图里图
- 双背景图隐写
- 棋盘格幻影坦克
- alpha 混合双图
- mtcloak
tags:
- ctf
- forensics
- stego
- image
- png
- alpha
- checkerboard
- mirage-tank
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T09:48:29+08:00'
  notes: 已对照原文1.1核对：alpha混合公式、黑白底还原、棋盘格(x+y) mod 2掩码与解码脚本一致；未验证点：PoC未本机执行，原文脚本存在range参数错误/result_median未定义，卡内已注明。
---

## 一句话结论

幻影坦克隐写把“表图”和“里图”通过 PNG 的 RGB 与 Alpha 混合进同一张图，使白底显示一张、黑底显示另一张；棋盘格变体则把里图限定在 `(x+y) mod 2 == 0` 的格子里、用 Alpha 微差携带信息，解码时按掩码取像素、拉对比度并插值补全即可还原隐藏图。

## 原理

- **传统灰度幻影坦克的数学解**：设像素颜色为 `P`、Alpha 为 `α`（均为 0–255），白底 `(255,255,255)` 下看到 `A`、黑底 `(0,0,0)` 下看到 `B`，则
  - 白底：`A = (α/255)·P + (1-α/255)·255`
  - 黑底：`B = (α/255)·P`
  - 两式相减得 `α = 255 - (A - B)`，代回得 `P = 255·B/α`。
  因此只要 `A ≥ B` 且 `α > 0`，就能为每个像素求出一组 `(P, α)`，让同一张 PNG 在两种背景下呈现不同图像。若 `A = B`，则 `α = 255`、`P = B`，该像素不承载差异。
- **为什么看起来只有一张图**：图片查看器通常把透明 PNG 合成到白底（或棋盘格底）上，用户看到的是 `A`；换到黑色背景或某些图片编辑器/系统主题下，`A` 与 `B` 的差异就显现出来。Alpha 越低，背景影响越大，所以边缘/水痕往往比较明显。
- **棋盘格变体**：把表图像素灰度强制拉到接近 255、里图像素拉到接近 0，再用 Alpha 的微小变化携带 1/0（或里图灰度），并按 2×2 棋盘格交错排布。解码端不需要连续灰度，只要按 `(x+y) mod 2`（或更一般的 `(x + y·k) mod m`）取出里图格子，做对比度拉伸，再用邻域插值补全被表图占用的格子。
- **与 LSB 的区别**：传统 LSB 直接改 RGB 低位，重压缩/缩放容易破坏；棋盘格幻影坦克依赖灰度阈值与 Alpha 差异，对常规图像处理更鲁棒，还可以在双图之外再嵌入文件，适合 CTF 附件。
- **载体要求**：必须是保留 Alpha 的无损格式（PNG/APNG），转 JPEG、缩放、二次压缩会破坏 `α` 与像素关系；不同工具（mtcloak、脚本实现）的位序/阈值可能不同。

## 触发条件

- 附件是 PNG，包含 Alpha 通道；在不同背景（白/黑/透明棋盘格）或不同曝光下显示不同内容。
- 题目提示“幻影坦克 / Phantom Tank / 表图里图 / 双层图 / 隐藏卷”，或图片在图片查看器与编辑器里表现不一致。
- 图片未被有损压缩、缩放或转码；部分工具生成的图会带明显水痕或棋盘纹理。
- 需要进一步提取时，可能有配套工具（如 mtcloak）或题目源码给出编码规则。

## 利用步骤

1. 用支持透明背景的查看器切换白底、黑底、棋盘格底，观察是否出现第二幅图；也可用图片编辑器调整曝光/色阶。
2. 传统灰度图：读取 RGBA，按 `B = P·α/255` 还原黑底图、按 `A = 255 - (255-P)·α/255` 还原白底图；两图分别保存后辨认 flag/提示。
3. 棋盘格图：检测掩码周期与偏移（常见 `(x+y) mod 2 == 0`；也可能是 `(x + y·k) mod m`），取出掩码位置的 Alpha（或灰度）值，按最大值归一化拉满对比度。
4. 对被掩码排除的像素，用最近邻/邻域均值/形态学膨胀插值补全，得到完整的隐藏图；若图像仍模糊，尝试不同周期/偏移、反相、直方图均衡。
5. 若得到的是密码/压缩包线索，继续按题目链路解密；若工具输出乱码，优先检查 PNG 是否被转码、Alpha 是否保留、掩码方向是否反了。
6. 需要自己制作时，可用 mtcloak 等工具，或按上述公式/棋盘格掩码写脚本生成。

## PoC

传统灰度解码（最小实现，未在本机执行）：

```python
from PIL import Image
import numpy as np

rgba = np.asarray(Image.open("mirage.png").convert("RGBA")).astype(np.float32)
r, g, b, a = rgba[..., 0], rgba[..., 1], rgba[..., 2], rgba[..., 3]
black = np.stack([r * a / 255, g * a / 255, b * a / 255], axis=-1)
white = np.stack([255 - (255 - r) * a / 255,
                  255 - (255 - g) * a / 255,
                  255 - (255 - b) * a / 255], axis=-1)
Image.fromarray(np.clip(black, 0, 255).astype(np.uint8)).save("black_bg.png")
Image.fromarray(np.clip(white, 0, 255).astype(np.uint8)).save("white_bg.png")
```

棋盘格掩码提取（示意，周期/通道需按目标调整）：

```python
from PIL import Image
import numpy as np

rgba = np.asarray(Image.open("checker.png").convert("RGBA"))
gray = rgba[..., 3].astype(np.float32)          # 常见变体把里图放在 Alpha
h, w = gray.shape
yy, xx = np.indices((h, w))
mask = (xx + yy) % 2 == 0                        # 里图格子
out = np.zeros((h, w), dtype=np.float32)
vals = gray[mask]
out[mask] = vals * (255.0 / max(vals.max(), 1))  # 对比度拉伸
# 非掩码像素用邻域均值/最近邻补全（此处省略实现细节）
Image.fromarray(out.astype(np.uint8)).save("hidden.png")
```

原文给出的棋盘格示例脚本存在 `range(0, width, 3, 3)`（参数个数错误）与未定义的 `result_median` 等笔误，不能直接运行；上面的片段是按原理重写的最小示意，未在本机执行。

## 变体与关联

- 变体：传统灰度双图（本卡公式）、棋盘格 Alpha 变体、mtcloak 等工具的 2-bit pair/奇偶校验变体；后者见 [[ctf-forensics-phantom-tank-rgba-2bit-pair-parity]]。
- 变体：表图/里图可以交换（白底显示里图、黑底显示表图），解码时把 `A`、`B` 对调即可。
- 变体：把隐藏图换成二维码/文字/压缩包分片；棋盘格法还可在双图之外再嵌文件。
- 关联：[[ctf-forensics-png-lsb-column-major-scan-order]]（PNG LSB 扫描顺序）、[[ctf-forensics-prism-tank-grayscale-band-diagonal-interleave]]（光棱坦克，另一类灰度分段双图）、[[ctf-forensics-png-ihdr-width-height-crc32-brute-force]]（PNG 结构修复）。
- 边界：JPEG/有损压缩、缩放、Alpha 被抹平、工具位序不匹配都会导致失败；公式法要求 `A ≥ B`，否则需先做亮度偏移/分段映射。

## 检测与防御

- CTF 识别：PNG 带 Alpha、白/黑背景显示不同图、图片有棋盘纹理或异常水痕；优先检查 Alpha 通道与像素掩码。
- 取证：保留原始 PNG，记录工具与参数；用多种背景/多个工具交叉验证，避免把普通半透明图误判为幻影坦克。
- 防御：敏感数据不要用幻影坦克类隐写承载；DLP/图片检测可检查 Alpha 异常、双背景差异与棋盘格周期；对上传图片做重编码/缩放可破坏此类隐写（但会影响正常透明图）。
