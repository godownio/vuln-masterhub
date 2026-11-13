---
id: ctf-forensics-volatility-windows-plugin-explorer-memdump-foremost
title: Volatility windows 插件定位窗口所属进程：explorer.exe memdump 后 foremost 按签名分离已打开图片（缩略图缓存取证）
type: scenario
domain: ctf
path: ctf/forensics
technique: volatility-windows-plugin-explorer-memdump-foremost
tags:
- ctf
- forensics
- volatility
- memory-image
- foremost
- explorer
- thumbnail
- carve
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V570
  verified_at: '2026-11-12T09:27:12+08:00'
  notes: 已对照 12973 原文与图 22-25 核对：Win2003SP1x86 镜像 windows 插件显示 flag.png 窗口 Process explorer.exe pid 1992，memdump -p 1992 后 foremost 分离出图片，二维码得 AES 密文/key Th1s_1s_K3y00000/iv 1234567890123456，解出 flag{F0uNd_s0m3th1ng_1n_M3mory}；命令与 PID 一致，未复跑。
url: /docs/ctf/forensics/ctf-forensics-volatility-windows-plugin-explorer-memdump-foremost/
draft: false
kb_aliases:
- windows 插件找窗口进程
- explorer 进程内存提取图片
- foremost 分离进程 dump
- 缩略图缓存内存取证
- 内存镜像已查看图片恢复
---

## 一句话结论

用 Volatility `windows` 插件枚举内存镜像中的窗口（标题、类名、所属进程 PID），若发现某张图片/文件已被资源管理器或看图程序打开（窗口标题含文件名、Process 为 `explorer.exe`），对该进程 `memdump -p <PID>` 导出内存，再用 `foremost`/`binwalk` 按文件签名分离 dump 中的 JPEG/PNG，即可恢复出被浏览过的图片本体（缩略图缓存副本），从中读取扫码密文、密码或 flag。

## 原理

- **窗口对象在内存中**：Windows 的每个窗口有 `tagWND` 结构，Volatility2 的 `windows` 插件遍历窗口站/桌面上的窗口，输出窗口标题、类名、线程/进程 ID；文件被打开时标题通常含文件名或路径，据此可反查「是哪个进程打开了目标文件」。
- **缩略图/图像缓存**：资源管理器展示图片文件夹时会把图片解码为缩略图（GDI+ 位图、Shell 缩略图缓存），解码后的像素与压缩数据副本留在 `explorer.exe` 进程内存；图片查看器同理。进程内存 dump 保留了这些页。
- **foremost 的恢复方式**：`foremost -i <dump> -o <outdir>` 按已知文件头尾签名（JPEG `FFD8FF`…`FFD9`、PNG 签名/IEND、GIF 等）扫描原始字节流并 carve 文件，不依赖文件系统结构，因此能从进程 dump 这种无索引的数据中提取图像。
- **为什么能拿到完整图**：文件被打开时往往整文件读入（缩略图生成/查看原图），dump 中可能存在完整副本；即便被分页切碎，foremost 仍可按签名取出可解析的多数图像。
- **边界**：进程已退出/内存页被回收时可能拿不到；foremost 对跨页断裂的大文件恢复有限，必要时配合 `photorec` 或按偏移手工拼接。

## 触发条件

- 有 Windows 内存镜像，`imageinfo` 已确定 profile。
- 题目提示某文件「被打开/查看过」，或需要从内存中找已删除/未保存的图片。
- 目标进程（常见 `explorer.exe`、看图软件）在镜像中仍存活。

## 利用步骤

1. `vol.py -f <image> --profile=<profile> windows` 列出窗口，找到标题含目标文件名、`Process`/`pid` 指向 `explorer.exe` 的条目。
2. `vol.py -f <image> --profile=<profile> memdump -p <PID> -D <outdir>/` 导出进程内存。
3. `foremost -i <outdir>/<PID>.dmp -o carved/`（或 `binwalk -e`/`photorec`）分离图片。
4. 查看 carve 出的图片：常能得到被打开的图片本体（flag 图/二维码）；二维码扫码得到密文、key、iv 等，再按提示解密。

最小化 PoC：

```
vol.py -f memory.img --profile=Win2003SP1x86 windows | grep -i png
vol.py -f memory.img --profile=Win2003SP1x86 memdump -p 1992 -D outfile/
foremost -i outfile/1992.dmp -o carved/
```

## 变体与关联

- `screenshot` 插件直接恢复桌面截图，可在不 dump 进程的情况下看到窗口内容。
- `filescan` + `dumpfiles -Q <物理地址>` 按文件对象导出缓存文件，比进程 dump 更精准。
- 进程 dump 也可用 GIMP 按原始位图打开（画图内容恢复）或用 `strings` 搜明文文本（记事本）。
- 图片内的二维码/AES 密文属于二级线索，需按题面继续解码。

## 检测与防御

- 取证方：窗口枚举能还原用户操作轨迹；缩略图缓存与进程内存是「已查看未保存」文件的主要残留处。
- 防御方：浏览敏感图片会在 explorer/查看器内存留下缩略图副本，内存转储/休眠文件应按敏感数据处理。
