---
id: ctf-misc-3dgs-point-cloud-lattice-rasterization
title: 3D Gaussian 点云栅格化：z 分层连通分量 + 二维格点拟合还原像素排列，球谐系数邻域一致性提取文字
type: scenario
domain: ctf
path: ctf/misc
technique: 3dgs-point-cloud-lattice-rasterization
tags:
- ctf
- misc
- 3dgs
- point-cloud
- gaussian-splatting
- lattice-fit
- spherical-harmonics
- steganography
- ply
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T02:00:25+08:00'
  notes: 已对照原文核对；8 万顶点 62 属性、z 六层各 11760 点、7×1680 连通分量、60×28 格点拟合、[3,0,5,1,4,2] 拼接与球谐邻域灰度一致
url: /docs/ctf/misc/ctf-misc-3dgs-point-cloud-lattice-rasterization/
draft: false
kb_aliases:
- Chronos Vault
- 3D Gaussian Splatting 点云
- PLY 点云隐写
- 二维格点拟合
- 球谐系数邻域一致性
- 点云栅格化
---

## 一句话结论

题目提供 8 万个顶点的 3D Gaussian 点云与一个形变网络，flag 藏在点云的二维像素排列中：按 z 坐标分层（±1、±3、±5 共六组，每组 11760 点，另有 9440 个零附近干扰点），对每组建最近 4 邻接图得到 7 个连通分量（每个 1680 点）；每层的 z 是二维整数格点的线性组合 `z = c + a*u + b*v`，u=0..59、v=0..27 即 60×28，用近邻 z 差值与最小二乘拟合出 a、b，再按排序对应关系把点索引填回网格；六块图按方向翻转（第三块上下、第五块左右）并以 [3,0,5,1,4,2] 拼接后，用 48 维球谐系数的四邻域距离（取最小两个的平均）提取文字，读出 flag。

## 原理

- **点云格式**：`point_cloud.ply` 为小端二进制，头部声明 8 万个顶点，每个顶点 62 个单精度属性；除位置与法线外，还有三阶直流系数、45 项高阶球谐系数、不透明度、三个尺度参数与四个旋转参数，是高斯点云的典型布局。读取时找到 `end_header\n`，把后续字节按 `<f4` 解析并 reshape 为 `(80000, 62)`。
- **z 分层**：统计位置发现绝大多数点的 z 集中在六个区间，分别以 -5、-3、-1、+1、+3、+5 为中心，每个区间 11760 个点，六组共 70560 个点；剩余 9440 个点位于零附近，属于干扰点，可先排除。
- **连通分量**：直接把每组投影到平面会看到弯曲交错的条带；对每组建立近邻图（每个点与最近的四个其他点相连，cKDTree 查询 k=5 去掉自身），按无向图求连通分量，恰好得到七个分量，每个分量 1680 个点。近邻查询返回包含自身，因此取五个结果并去掉第一个；邻居过多会把相邻层连接起来。
- **二维格点**：1680 可分解为多种矩形尺寸；统计同层近邻的 z 差值会出现重复次数很高的峰，提示 z 来自二维整数格点的线性组合 `z = c + a*u + b*v`。对矩形尺寸拟合后，u 取 0..59、v 取 0..27，即 60×28 的排列能把误差降到浮点精度附近；六组拟合出的步长均方根误差都在 1e-6 量级。
- **拟合方法**：先把实测 z 减去该层最小值并排序，再与预测格点值 `a*u + b*v` 的排序结果比较，以两者均方误差最小为目标，从近邻高频差值取初值并用最小二乘优化，同时要求 `59a + 27b ≈ max(z)-min(z)`。得到步长后，利用排序对应关系把原始点索引填回 28×60 数组，从而绕过 x、y 方向的弯曲投影。
- **层排序与拼接**：七层的质心近似沿直线分布，对质心做 SVD 并按主轴排序，可以找到两端的层；六块图像恢复后，根据文字方向进行翻转（第三组上下翻转、第五组左右翻转），从左到右顺序为 3、0、5、1、4、2；字符会跨越图块边界，因此应先拼接完整图像再辨认文字。
- **球谐系数提取文字**：恢复像素排列后，直接把直流系数转成 RGB 仍有较多噪声，但文字内部相邻点的球谐系数比较一致，背景点之间差异更大；对每个像素取三项直流系数和 45 项高阶系数组成 48 维向量，计算它与上下左右四个邻居的欧氏距离，将四个距离排序后取最小两个的平均作为灰度响应。文字内部至少有部分邻居保持一致，响应较低显示为深色；对最外侧两层分别计算并取平均可提高可读性，显示时除以 15 并截断到 0..1，再用最近邻插值放大。

## 触发条件

- 提供 3D Gaussian/点云 PLY 或类似多属性顶点数据，flag 以图像/文字形式藏在几何排列中。
- 点云存在可按某一坐标分层、且每层可分解为二维规则格点的结构。
- 属性中包含球谐系数或其他局部一致的纹理特征，可用于区分文字与背景。
- 存在多块图需要翻转/排序拼接的线索。

## 利用步骤

1. 读取 PLY 头部，确定顶点数与属性顺序，按小端 float 解析为矩阵。
2. 统计 z 分布，找出六个主区间与零附近干扰点；对每个主区间按 z 中心筛选。
3. 对每组建 cKDTree（k=5），按最近 4 邻接建稀疏图，求连通分量；确认 7 个分量、每个 1680 点。
4. 统计分量内近邻 z 差值的高频峰，枚举步长 a、b，以 `59a+27b≈range` 约束，用最小二乘拟合 `sort(a*u+b*v)` 与 `sort(z-min)`。
5. 用 `argsort` 对应关系把原始点索引填回 28×60 网格；按层质心 SVD 主轴排序，得到 7 层。
6. 对六个 z 中心分别恢复 7 层网格，按方向翻转（第三块上下、第五块左右）并按 [3,0,5,1,4,2] 拼接。
7. 取最外侧两层，计算 48 维球谐系数的四邻域距离，取最小两个平均得到灰度图；放大/二值化后读文字，得到 flag。

## PoC

```python
import numpy as np
from PIL import Image
from scipy.optimize import least_squares
from scipy.sparse import coo_matrix
from scipy.sparse.csgraph import connected_components
from scipy.spatial import cKDTree

def read_ply(path):
    data = open(path, "rb").read()
    end = data.index(b"end_header\n") + len(b"end_header\n")
    header = data[:end].decode("ascii").splitlines()
    names = [s.split()[-1] for s in header if s.startswith("property ")]
    count = int(next(s.split()[-1] for s in header if s.startswith("element vertex ")))
    return np.frombuffer(data, "<f4", offset=end).reshape(count, len(names))

def recover_tile(p, center):
    ids = np.flatnonzero(abs(p[:, 2] - center) < .6)
    xyz = p[ids, :3]
    _, near = cKDTree(xyz).query(xyz, k=5)
    graph = coo_matrix((np.ones(len(ids) * 4),
                        (np.repeat(np.arange(len(ids)), 4), near[:, 1:].ravel())),
                       shape=(len(ids), len(ids)))
    count, labels = connected_components(graph)
    assert count == 7 and np.all(np.bincount(labels) == 1680)

    sample = xyz[labels == 0]
    _, near = cKDTree(sample).query(sample, k=9)
    dz = abs(sample[near[:, 1:], 2] - sample[:, None, 2])
    steps, counts = np.unique(dz.round(5), return_counts=True)
    steps = steps[np.argsort(counts)[-18:]]
    values = np.sort(sample[:, 2].astype("f8") - float(sample[:, 2].min()))
    u, v = np.meshgrid(np.arange(60), np.arange(28))

    def residual(c):
        return np.sort((c[0] * u + c[1] * v).ravel()) - values

    fits = []
    for a in steps:
        for b in steps:
            if abs(a * 59 + b * 27 - values[-1]) < .003:
                fit = least_squares(residual, [a, b])
                fits.append((float(np.mean(fit.fun ** 2)), fit.x))
    loss, coeff = min(fits, key=lambda item: item[0])
    assert loss < 1e-10

    target_order = np.argsort((coeff[0] * u + coeff[1] * v).ravel())
    centers = np.array([xyz[labels == k].mean(0) for k in range(7)])
    _, _, axes = np.linalg.svd(centers - centers.mean(0))
    layer_order = np.argsort(centers @ axes[0])
    layers = []
    for k in layer_order:
        group = ids[labels == k]
        grid = np.empty(1680, dtype=int)
        grid[target_order] = group[np.argsort(p[group, 2])]
        layers.append(grid.reshape(28, 60))
    return np.stack(layers)
```

文字提取：

```python
p = read_ply("point_cloud.ply")
tiles = [recover_tile(p, z) for z in [-5, -3, -1, 1, 3, 5]]
tiles[3] = tiles[3][:, ::-1, :]
tiles[5] = tiles[5][:, :, ::-1]
grid = np.concatenate([tiles[k] for k in [3, 0, 5, 1, 4, 2]], axis=2)

surfaces = []
for layer in [0, 6]:
    features = p[grid[layer], 6:54].astype("f8")
    differences = [np.linalg.norm(features - np.roll(features, (dy, dx), axis=(0, 1)), axis=-1)
                   for dy, dx in [(0, 1), (0, -1), (1, 0), (-1, 0)]]
    surfaces.append(np.sort(differences, axis=0)[:2].mean(0))
energy = np.mean(surfaces, axis=0)
pixels = (np.clip(energy / 15, 0, 1) * 255).astype("uint8")
Image.fromarray(pixels).resize((2880, 224), Image.Resampling.NEAREST).save("flag.png")
```

## 变体与关联

- 格点维度/步长可换成三维格点、非矩形、错切；核心是先从近邻差值找候选步长，再用排序/最小二乘恢复映射。
- 文字提取可换成法线、不透明度、尺度、旋转、颜色梯度等局部一致特征；若特征噪声大，可对多层/多邻域距离取平均。
- 形变网络可能是干扰项；先检查点云本身是否有规则结构，再决定是否搭建完整 4D 渲染。
- 关联：点云隐写、3DGS 数据处理、栅格化与图像恢复卡。

## 检测与防御

- 对点云隐写检测：统计坐标分层/格点规律、属性局部一致性、异常连通分量、规则网格排列；对 PLY 自定义属性做熵分析。
- 数据发布方可对点云做扰动/重采样、打乱索引、去除规则格点结构；敏感文字不要直接编码在几何排列中。
- 若点云用于模型训练/共享，剥离不必要的属性（球谐高阶系数），并做差分隐私/噪声注入。
