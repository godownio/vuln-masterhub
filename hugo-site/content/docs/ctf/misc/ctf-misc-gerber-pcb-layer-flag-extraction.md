---
id: ctf-misc-gerber-pcb-layer-flag-extraction
title: Gerber PCB 层提取：在线查看器逐层剥离内层铜箔读取隐藏 flag
type: scenario
domain: ctf
path: ctf/misc
technique: gerber-pcb-layer-flag-extraction
tags:
- ctf
- misc
- hardware
- gerber
- pcb
- layer
- stego
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V205
  verified_at: '2026-11-07T02:40:32+08:00'
  notes: 已对照原文与图片04-14核对：B_Cu/In1_Cu 两段 flag、逐层隐藏/显示流程一致；已修正层归属为 B_Cu+In1_Cu，并将 gerbv 示例改为位置参数文件；PoC 未复跑。
url: /docs/ctf/misc/ctf-misc-gerber-pcb-layer-flag-extraction/
draft: false
kb_aliases:
- Gerber 文件
- PCB 层提取
- GBR 隐写
- 内层铜箔
- PCBWay Gerber Viewer
- 电路板 flag
---

## 一句话结论

Gerber（.gbr）是 PCB 各层的独立矢量文件，查看器会把 top/bottom/丝印/阻焊/内层铜箔叠加渲染；把无关层隐藏、逐个显示内层（如 In1_Cu/In2_Cu）或丝印层，常能看到被普通顶层视图遮住的 flag 文本。

## 原理

- **Gerber 分层**：一套 PCB 文件通常包含 `F_Cu`（顶层铜箔）、`B_Cu`（底层铜箔）、`F_Mask`/`B_Mask`（阻焊）、`F_Silkscreen`（丝印）、`F_Paste`（焊膏）、`Edge_Cuts`（外形）、`In1_Cu`/`In2_Cu`（内层铜箔）等；每层是独立文件，层名后缀表示用途。
- **叠加渲染**：PCB 查看器默认把所有层合成一张图，底层/内层可能被顶层铜箔、阻焊或丝印覆盖；隐藏部分层或单独显示某一层，就能看到该层的图形/文字。
- **隐藏信息的载体**：flag 可以是内层铜箔上的走线文字、丝印层字符、阻焊开窗形状、钻孔排列等；本题把 flag 拆成两段分别放在底层铜箔（B_Cu）与内层铜箔（In1_Cu），需要逐层查看并拼接。
- **为什么普通查看看不到**：顶层铜箔/阻焊会遮挡内层；图片缩略图/自动预览可能只显示 composite 视图；需要手动关闭顶层或切换 layer。
- **工具**：PCBWay Online Gerber Viewer、gerbv、KiCad Gerber Viewer、JLCPCB 查看器等；在线工具可直接上传 zip/gbr 并勾选层。

## 触发条件

- 题目/附件给出一组 `.gbr`/`.zip` Gerber 文件，可能包含不常见的 `In1_Cu`/`In2_Cu`/`Silkscreen` 层。
- 附件描述提到 PCB、电路板、硬件、Gerber、制造文件等。
- 查看器支持逐层显示/隐藏；文件未被加密/损坏。
- flag 文本位于某一层，且能被矢量渲染/放大识别。

## 利用步骤

1. 列出所有 Gerber 文件与层名（`F_Cu`、`B_Cu`、`In1_Cu`、`In2_Cu`、`F_Silkscreen`、`B_Silkscreen`、`Edge_Cuts` 等）。
2. 用在线查看器（如 PCBWay Gerber Viewer）上传 zip 或逐个文件；选择 `layers` 视图。
3. 先关闭 top/bottom copper、阻焊、焊膏等遮挡层，只保留内层铜箔/丝印，逐层查看。
4. 对疑似层放大/截图；若文字被走线遮挡，切换颜色/透明度或导出该层为 PNG/SVG。
5. 拼接各层看到的 flag 片段；检查内层、底层、丝印、Edge_Cuts 和钻孔层。
6. 若在线查看器不支持，使用 gerbv 命令行导出单层 PNG：

```bash
gerbv -x png -o in1.png In1_Cu.gbr
```

## PoC

```text
无脚本 PoC（查看器操作）。
最小流程：
1) 解压 Gerber zip，列出 *.gbr 层名
2) PCBWay Online Gerber Viewer -> 上传
3) layers -> 关闭 top/bottom/mask/paste，逐个打开 In1_Cu / In2_Cu / Silkscreen
4) 放大读取文字，拼接 flag
```

gerbv 批量导出各层：

```bash
for f in *.gbr; do
  gerbv -x png -o "${f%.gbr}.png" "$f"
done
```

## 变体与关联

- **丝印层隐写**：字符可能被放在 `F_Silkscreen`/`B_Silkscreen`，需要放大或调整对比度。
- **阻焊开窗**：通过阻焊层的开窗形状拼出文字/二维码；单独显示 `Mask` 层。
- **钻孔/外形层**：钻孔坐标或 Edge_Cuts 轮廓可编码数据；导出坐标做统计分析。
- **多层拼接**：flag 可能拆成多段，分别在不同层；逐层记录并拼接。
- **关联卡片**：[[ctf-misc-tiff-multilayer-hidden-image]]（多层图像隐写）；[[ctf-forensics-multilayer-png-wav-spectrogram-maze-stego]]（多层载体隐写链）。

## 检测与防御

- **设计审查**：PCB 发布前检查所有层（尤其内层/丝印）是否含敏感文字、密钥、调试标记；不要把秘密画在铜箔/丝印上。
- **供应链**：Gerber 文件视为公开数据；对外发布前做层清理/重命名/裁剪。
- **取证**：保留原始 Gerber 与哈希；记录查看器版本与层配置，确保可复现。
- **检测**：对 Gerber 文本/矢量做关键字扫描（flag、key、password、URL），但图形化文字需要 OCR/人工查看。
