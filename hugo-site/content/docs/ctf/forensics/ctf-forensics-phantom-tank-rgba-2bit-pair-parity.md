---
id: ctf-forensics-phantom-tank-rgba-2bit-pair-parity
title: 幻影坦克隐写：RGBA 字节流 2-bit pair 与奇偶校验还原隐藏图/密码
type: scenario
domain: ctf
path: ctf/forensics
technique: phantom-tank-rgba-2bit-pair-parity
tags:
- ctf
- forensics
- stego
- image
- rgba
- parity
- phantom-tank
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V112
  verified_at: '2026-11-06T02:08:45+08:00'
  notes: 已对照原文全文与 7 张内嵌图片核对：题目步骤、密码链、脚本与 flag/密码均与原文一致。未验证点：PoC 按原文重写未本机复跑；原文无组件版本，未设置 versions；卡 frontmatter 无 sources/source_url。
url: /docs/ctf/forensics/ctf-forensics-phantom-tank-rgba-2bit-pair-parity/
draft: false
kb_aliases:
- 幻影坦克
- Phantom Tank
- RGBA 2-bit pair
- 奇偶校验隐写
- mtcloak
- Do you know RA2
---

## 一句话结论

当一张 PNG 在不同背景/曝光下显示不同图像、或题目提示“幻影坦克/隐藏卷”时，可检查 RGBA 字节流：隐藏信息常以每个像素的 2-bit pair 加奇偶校验位编码，通过阈值/通道关系提取隐藏图或隐藏卷密码；本题用幻影坦克工具（mtcloak.uyanide.com）得到密码 `Nobody's here but that's trees!`。

## 原理

- **幻影坦克（Phantom Tank）**：利用 PNG 的 Alpha 透明度和 RGB 值，让同一张图在白色/黑色背景下呈现不同画面；隐藏图与可见图共享像素，但通过 alpha/颜色差异编码。
- **2-bit pair + 奇偶校验**：每个像素/通道组合承载 2 个隐藏比特，另加 1 位奇偶校验用于纠错/定位；解码时按阈值判断像素属于可见图还是隐藏图，从 RGB(A) 的低位/差值恢复比特对，校验后拼成隐藏数据。
- **工具**：`mtcloak.uyanide.com` 等幻影坦克工具可生成/提取；也可按 RGBA 字节流手写提取脚本（先确认工具/算法版本）。
- **本题**：第一层 SSTV 得到密码 `packed up and ready`，用于 VC 外层卷；第二层在 VC 外层卷中发现幻影坦克图，提取隐藏卷密码 `Nobody's here but that's trees!`；第三层 VC 隐藏卷中的光棱坦克图，拉高曝光/反色二维码得到 flag。
- **边界**：不同工具/版本编码方式不同；2-bit pair/parity 的具体位序需按工具或题目源码确认；有损压缩会破坏隐写。

## 触发条件

- PNG 图在不同背景（白/黑）或不同曝光下显示不同内容；题目提示“幻影坦克/隐藏卷/双层图”。
- 图片为无损 PNG（保留 alpha/低位），未被重压缩/转码。
- 有幻影坦克工具或能从源码/题目获得编码规则（2-bit pair/parity）。
- 隐藏层可能是密码/压缩包/VC 卷，需要后续解密。

## 利用步骤

1. 用图片查看器切换白/黑背景/调整曝光，确认是否存在第二幅图。
2. 用幻影坦克工具（mtcloak）加载图片，尝试提取隐藏图/密码；或按题目源码实现 RGBA 提取。
3. 若手写：读取每个像素 RGBA，按工具规则取 2-bit pair，校验奇偶位，拼接隐藏字节；尝试不同通道顺序/位序/阈值。
4. 得到隐藏密码/隐藏图；本题密码 `Nobody's here but that's trees!` 用于 VeraCrypt 隐藏卷。
5. 进入下一层（VC 隐藏卷/图片曝光/二维码反色），最终读 flag。
6. 若工具输出乱码，检查 PNG 是否被转码、alpha 是否保留、位序是否反。

## PoC

```text
1) 幻影坦克工具：https://mtcloak.uyanide.com/
   - 上传 PNG，选择“显形/提取”，调整阈值/对比度/扩散迭代
   - 保存显示图像/隐藏图像
2) 手写思路（按工具源码核对位序）：
   for each pixel:
       r,g,b,a = pixel
       pair = (r & 1) << 1 | (g & 1)   # 示例，按工具实际规则
       parity = (r ^ g ^ b ^ a) & 1
       if parity == expected: append 2 bits
   pack bits -> bytes -> hidden data
```

## 变体与关联

- **变体（背景色）**：白底/黑底/透明背景显示不同图；alpha 越低越依赖背景。
- **变体（工具）**：mtcloak、幻影坦克生成器、手写 RGBA 编码；不同工具的 pair/parity 规则不同。
- **变体（下一层）**：隐藏密码用于 VeraCrypt/压缩包；见 [[ctf-forensics-veracrypt-aes-xts-manual-decrypt]]。
- **关联卡片**：[[ctf-forensics-sstv-audio-image-decode]]（本题前置 SSTV）、[[ctf-forensics-png-lsb-column-major-scan-order]]（PNG LSB）、[[ctf-forensics-png-ihdr-width-height-crc32-brute-force]]（PNG 结构）。
- **边界**：PNG 转 JPEG/缩放会破坏隐藏数据；工具版本/参数不匹配会失败；2-bit pair 规则需按源码核对。

## 检测与防御

- **CTF 识别**：图片白/黑背景显示不同内容、题目“幻影坦克/双层图”，优先检查 alpha/RGB 低位。
- **数据防泄露**：DLP 可检测 PNG alpha 异常/双背景差异；敏感数据不要用幻影坦克隐写。
- **取证**：保留原始 PNG，记录工具/参数；用多工具交叉验证隐藏图。
