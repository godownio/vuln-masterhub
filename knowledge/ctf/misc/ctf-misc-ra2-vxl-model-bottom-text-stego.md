---
id: ctf-misc-ra2-vxl-model-bottom-text-stego
title: 红警2 VXL 单位模型底部隐写：vxlse 在载具底面绘制 flag
type: scenario
domain: ctf
path: ctf/misc
technique: ra2-vxl-model-bottom-text-stego
aliases:
- 红警2 VXL 隐写
- RA2 载具模型隐写
- VXL 底部 flag
- vxlse 绘制
- 单位模型底部
- 爆炸掀翻载具
- XCC Mixer VXL
tags:
- ctf
- misc
- stego
- game
- ra2
- vxl
- 3d-model
- xcc-mixer
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T09:48:38+08:00'
  notes: 已对照原文2.2与VXL头截图核对：Voxel Animation头、区块数量1、vxlse底部绘制、爆炸掀翻查看、flag/CTCV命名一致；未验证点：未本机复现。
---

## 一句话结论

红警2 的载具使用 VXL 体素模型，出题人可以用 vxlse 在模型底部绘制 flag 文字，正常俯视视角看不到；解题时用爆炸/掀翻载具、或用 VXL 编辑器旋转查看底部，即可读到隐藏内容。

## 原理

- **VXL 是体素模型**：红警2 的战车、基洛夫空艇、爱国者/巨炮基座等载具/建筑部件使用 VXL（3D 体素）而不是 SHP 平面图。模型由体素块组成，正常游戏视角只渲染可见表面，底面/内部面不可见。
- **VXL 文件头**：`00-0F` 为固定字符串 `Voxel Animation `（16 字节，不含引号）；`10-13` 未知；`14-17` 区块数量（一般 1）；`18-1B` 未知；`1C-1F` 数据区字节数；`20-21` 未知。头部字段可用于打明文或快速识别 VXL。
- **底部可写**：vxlse 等编辑器可以选中模型底面并绘制像素/文字；导出后打包回 `ra2.mix`/`ra2md.mix`（或作为独立文件被地图/单位引用），游戏内正常视角看不到，但模型被掀翻/爆炸气浪翻转时会露出底面。
- **命名/注册也可能藏线索**：原文示例中单位显示名为 `flag`、内部注册名为 `CTCV`，flag 藏在单位模型底部；出题人可用显示名引导，也可故意让显示名与内部名不一致，增加排查难度。
- **与广告牌 SHP 的区别**：广告牌是平面多帧 SHP，直接在地图装饰物上就能看；VXL 是 3D 体素，必须旋转模型/掀翻载具才能看到底面，隐蔽性更高。

## 触发条件

- 题目附件是红警2 地图/资源包，含自定义载具或建筑部件；单位显示名/内部名有异常（如 `flag`、`CTCV`）。
- 地图中载具可被爆炸/气浪掀翻，或解题环境有 vxlse、XCC Mixer 等工具。
- VXL 文件头/尺寸异常，或模型底部有非原版像素。
- 也可以在游戏外直接用 VXL 编辑器查看所有面。

## 利用步骤

出题/制作侧：

1. 用 XCC Mixer 从 `ra2.mix`/`ra2md.mix` 提取目标 VXL 文件。
2. 用 vxlse 打开，旋转到模型底部，用画笔绘制 flag 文字/图案。
3. 导出 VXL，打包回原 mix（或按题目要求放到独立资源路径）。
4. 若需要，修改单位显示名/注册名，让线索指向该单位。

解题侧：

1. 用 XCC Mixer 提取地图引用的 VXL，或用地图编辑器查看单位类型/名称。
2. 用 vxlse 打开 VXL，旋转 360° 检查底部、内部面；也可在 3D 预览中切换视角。
3. 进游戏后用爆炸气浪/修改器掀翻载具，观察底盘；原文示例即通过这种方式看到底部的红色文字。
4. 若显示名与内部名不一致，按内部名在 `rules.ini`/`art.ini` 中定位对应 VXL，再检查模型。

## PoC

VXL 文件头示例（十六进制）：

```text
56 6F 78 65 6C 20 41 6E 69 6D 61 74 69 6F 6E 00   "Voxel Animation."
01 00 00 00                                       区块数量=1
...
1C-1F: 数据区字节数
```

本卡为工具链操作，无通用代码 PoC；可用文件头字符串 `Voxel Animation ` 在资源包中定位 VXL。原文流程未在本机复现。

## 变体与关联

- 变体：flag 写在底盘、炮塔底部、建筑基座底面；也可写在模型内部面/侧面，依赖掀翻或旋转查看。
- 变体：把文字做成极低对比度/与底材质同色，增加肉眼识别难度；用 vxlse 的调色盘替换可进一步隐藏。
- 关联：[[ctf-misc-ra2-billboard-shp-animation-stego]]（SHP 广告牌）、[[ctf-misc-ra2-map-terrain-trigger-text-stego]]（地图地形/触发文本）。
- 边界：不同版本/资料片的 VXL 结构可能有差异；调色盘不匹配会导致颜色异常但轮廓仍可读；部分地图不引用自定义 VXL。

## 检测与防御

- CTF 识别：地图中出现陌生载具、单位显示名/内部名异常、VXL 文件头/尺寸异常；优先用 XCC Mixer + vxlse 检查底面。
- 取证：保留原始 mix/VXL，记录文件头、调色盘和模型名；逐面导出比对原版模型。
- 防御：校验资源哈希/签名，只加载官方模型；对自定义地图做资源白名单。
