---
id: ctf-forensics-process-memory-dump-gimp-raw-image
title: 进程内存转储改后缀 .data 用 GIMP 按原始图像打开恢复画面
type: scenario
domain: ctf
path: ctf/forensics
technique: process-memory-dump-gimp-raw-image-recovery
aliases:
- 内存 dump 进程恢复画面
- GIMP 打开内存转储
- 画图进程内存取证
- Raw Image Data 内存恢复
- DumpIt 进程转储
tags:
- ctf
- forensics
- memory
- volatility
- gimp
- raw-image
- procdump
cve: []
severity: info
confidence: low
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V311
  verified_at: '2026-11-08T13:10:34+08:00'
  notes: 已对照图01 pslist（含 mspaint.exe/DumpIt.exe/vmtoolsd.exe）与图02 恢复出的手写画面核对；原文只写 dump 进程改 .data 用 GIMP，未给进程/宽高参数，卡内已注明并按通用 pslist+memdump/procdump+GIMP Raw Image Data 补全步骤；已修正 vmptoolsd→vmtoolsd。未复现。
---

## 一句话结论

当内存镜像里存在画图、截图或看图类进程时，把该进程的内存转储出来，改后缀为 `.data` 后用 GIMP 以“原始图像数据（Raw Image Data）”方式打开并调整宽高/偏移，即可把进程内存中的像素缓冲当作位图查看，从而恢复当时显示或绘制的内容。

## 原理

- 图形界面程序把自己的画布/窗口内容保存在进程内存的 DIB（设备无关位图）或位图缓冲区里，像素通常是连续的 `BGR/BGRA` 原始字节；进程内也可能残留文件解码后的整幅图片。
- Volatility 的 `memdump`/`procdump` 把整个进程地址空间（或某个模块）原样写成 dump 文件；这个文件没有图像文件头、宽高和格式信息，普通看图工具无法识别。
- GIMP 的 `File > Open as Raw Image Data`（或打开时选择 Raw Image Data 文件类型）允许把任意二进制文件按指定的宽、高、偏移与通道顺序解释为像素矩阵；只要试对分辨率/通道，就能看到画面。
- 本题原文只说明“dump 下来进程，然后改后缀 `.data` 放到 GIMP 中”，没有记录具体进程、插件与宽高参数；因此这条路径的复现依赖对镜像中图形进程的枚举与分辨率试错。

## 触发条件

- 已获取 Windows 内存镜像，且镜像中仍有画图（如 `mspaint.exe`）、截图、看图或浏览器等图形进程。
- 能对镜像运行 Volatility（2 或 3）或等价内存解析工具，拿到进程 PID 与内存段。
- 本机有 GIMP（或其他支持 Raw Image Data 导入的工具）。
- 目标内容以像素形式存在；纯文本/文件内容更适合直接 `strings` 或 `dumpfiles`。

## 利用步骤

1. 枚举进程：`vol.py -f <image> --profile=<profile> pslist`，记录图形相关进程与 PID；本题截图中可见 `smss.exe`、`explorer.exe`、`DumpIt.exe`、`cmd.exe`、`mspaint.exe`、`vmtoolsd.exe`。
2. 转储进程内存：`memdump -p <PID> -D dump/`（或 `procdump`），得到 `<PID>.dmp`。
3. 把 dump 复制/改名为 `.data` 后缀（后缀本身不影响内容，只是方便 GIMP 当作原始数据选择）。
4. 在 GIMP 中打开该文件并选择 Raw Image Data；先按常见屏幕分辨率试（1920×1080、1440×900、1024×768 等），再调整偏移与 RGB/RGBA 通道顺序。
5. 看到画面后导出 PNG 留证，再继续后续取证步骤。
6. 若原始分辨率未知，可先用 `strings`/十六进制查看 dump 中是否有 BMP/JPG/PNG 文件头，或按 4 字节对齐扫描像素连续性，缩小参数范围。

## PoC

```bash
# 1) 枚举进程
vol.py -f ez_raw.raw --profile=Win7SP1x64 pslist

# 2) 转储目标进程内存
vol.py -f ez_raw.raw --profile=Win7SP1x64 memdump -p <PID> -D dump/
# 或
vol.py -f ez_raw.raw --profile=Win7SP1x64 procdump -p <PID> -D dump/

# 3) 改名后在 GIMP 中按 Raw Image Data 打开
mv dump/<PID>.dmp dump/<PID>.data
# GIMP: File -> Open as Raw Image Data；填写 width/height/offset/channels
```

备选：

```bash
# 先找 dump 中是否残留完整图片文件
strings -a dump/<PID>.dmp | grep -aE '^(BM|GIF8|PNG|JFIF)'
binwalk dump/<PID>.dmp
```

## 变体与关联

- **Volatility2 `screenshot` 插件**：直接从内存中的 GDI 结构重建桌面截图，不需要手工指定宽高；适合整屏内容，不覆盖画图进程的私有画布。
- **`dumpfiles`**：若能通过 `filescan` 找到图片文件对象，直接按物理地址提取文件，比进程内存猜宽高更可靠。
- **浏览器/看图进程**：解码后的图片常驻进程堆，dump 后用同样方法按宽高打开；也可搜索 JPEG/PNG 头做文件雕刻。
- **带 alpha 的窗口**：通道顺序可能是 BGRA，GIMP 中需相应调整；截图可能包含窗口边框/黑边。
- 关联：[[ctf-forensics-volatility-filescan-wallpaper-atbash-cmdscan]]（文件对象定位壁纸）、[[defense-forensics-memory-netscan-malfind-dump-injected-process]]（进程内存 dump 与分析方法）。

## 检测与防御

- 对 CTF/取证：优先枚举 `mspaint.exe`、`explorer.exe`、看图/截图类进程；先试常见分辨率，再试偏移；保留 dump 哈希与参数记录。
- 对实际防护：屏幕上的敏感信息会进入进程内存与显存，截屏/画图类程序退出后仍可能残留；处理敏感数据时应禁用截图、使用受保护桌面/DRM，并在进程退出时清理缓冲。
- 内存镜像属于高敏感证据，采集、传输、留存需加密并限制访问。
