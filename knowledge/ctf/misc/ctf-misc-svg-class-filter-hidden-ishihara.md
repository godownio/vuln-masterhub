---
id: ctf-misc-svg-class-filter-hidden-ishihara
title: SVG 石原氏图隐写：按 class 筛选元素重建图形还原隐藏文字
type: scenario
domain: ctf
path: ctf/misc
technique: svg-class-filter-hidden-image
aliases:
- SVG 隐写
- SVG class 筛选
- 石原氏图 SVG
- Ishihara test++
- class 属性分组隐藏
tags:
- ctf
- misc
- stego
- svg
- xml
- class
- image
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V600
  verified_at: '2026-11-12T17:20:17+08:00'
  notes: 已对照原文与截图核对：图13为噪声石原氏图、图14过滤后显示 sdctf{c0untle55_colorful_colors_cov3ring_3v3rything}，已按截图逐字修正原稿示例flag(原写sdctf{c0untle55_col0rful_3v3rything}有误)；c1/c3/c6筛选脚本与原文一致；库内无SVG隐写同类卡；未验证点：未实际运行过滤脚本
---

## 一句话结论

SVG 是 XML 文本，图形元素可带 `class` 属性；题目把大量噪点圆与隐藏文字圆混在同一张 SVG 中，用不同 `class` 区分，直接渲染只看到石原氏图式噪点；按 class 过滤（如只保留 c1/c3/c6）重建一个精简 SVG 再渲染，即可显示隐藏的 flag 文字。

## 原理

- SVG 的 `<circle>`/`<path>` 等元素是明文 XML，`class` 只是样式分组，不影响解析；渲染器按文件顺序绘制所有元素，后绘制的元素覆盖先绘制的。
- 出题人把“噪点”与“文字”用不同 class 区分（例如文字相关圆为 c1/c3/c6，噪点为其他 class），整图看起来是随机点阵（石原氏色盲检测图风格）。
- 由于 SVG 可编辑，攻击者/解题者可以按 class 抽取子集元素重新拼成合法 SVG，渲染后噪点消失、文字显现；也可以用 CSS 隐藏指定 class 后截图。
- 关键点是认识到“图片”其实是文本容器，元素分组本身就是隐写维度，而不是像素级 LSB。

## 触发条件

- 题目给出 `.svg` 文件（或可编辑矢量图），直接打开是噪点/无意义图形。
- 源码中元素带 `class` 属性，且 class 种类明显多于正常样式需要（如 c1…cN）。
- 元素数量大、坐标分散，符合“噪点 + 文字”两层结构。

## 利用步骤

1. 用文本编辑器打开 SVG，确认是 XML；统计 `class` 取值分布与元素类型（circle/path）。
2. 按 class 分组渲染：先只保留数量较少或命名可疑的 class，观察是否出现笔画/文字。
3. 用脚本过滤：保留含目标 class 的行，加上原 `<svg>` 头与 `</svg>` 尾，另存为 sanitized.svg。
4. 浏览器打开 sanitized.svg；若仍混杂，调整 class 组合或按坐标范围裁剪。
5. 读取文字得到 flag；必要时用截图/OCR 辅助。

## PoC

```python
header = '''<?xml version="1.0" encoding="UTF-8" ?>
<svg width="1920" height="1080" viewBox="0 0 1920 1080" xmlns="http://www.w3.org/2000/svg" version="1.1">'''
footer = '</svg>'

keep = []
with open('flag.svg', 'r', encoding='utf-8') as f:
    for line in f.read().split('\n'):
        if any(c in line for c in ('c1', 'c3', 'c6')):
            keep.append(line)

with open('sanitized_flag.svg', 'w', encoding='utf-8') as f:
    f.write(header + '\n' + '\n'.join(keep) + '\n' + footer)
```

- 原文示例：SDCTF 2022 `Ishihara test++.`，保留 class 含 c1/c3/c6 的 circle 后，噪声图变为可读的 `sdctf{c0untle55_colorful_colors_cov3ring_3v3rything}` 文字（按原文截图逐字辨认）。
- 若 class 是样式而非分组，可改用浏览器开发者工具逐个禁用 `<g>`/class 观察。

## 变体与关联

- 同类“矢量图分层隐藏”可用 CSS `display:none`、`opacity:0`、坐标越界、`<defs>` 未引用元素等方式；思路都是检查 SVG 源码而非只看渲染结果。
- 光栅图的分层隐藏见 [[ctf-misc-tiff-multilayer-hidden-image]]、[[ctf-misc-low-frequency-image-downscale-blur-reveal]]。
- SVG 作为攻击面的安全场景（XXE/XSS）见 [[web-generic-xxe-svg-upload-inband-file-read]]、[[web-generic-file-upload-svg-inline-script-stored-xss]]，与本条 CTF 隐写不同。

## 检测与防御

- CTF 技巧，非真实漏洞。出题方可把隐藏元素坐标打散、加密 class 名或直接栅格化。
- 实际系统处理用户上传 SVG 时应做安全清洗（禁脚本/外部实体），并注意 SVG 可能携带隐藏内容用于投递或绕过审核。
