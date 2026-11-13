---
id: ctf-forensics-memdump-notepad-edit-control-plaintext
title: Volatility memdump 记事本进程提取 Edit 控件明文：从 notepad.exe 内存 dump 搜链接/提取码/flag
type: scenario
domain: ctf
path: ctf/forensics
technique: memdump-notepad-edit-control-plaintext
tags:
- ctf
- forensics
- volatility
- memory-image
- notepad
- memdump
- windows
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V570
  verified_at: '2026-11-12T09:27:07+08:00'
  notes: 已对照 12973 原文与图 14-16 核对：Win7SP1x86_23418 镜像 notepad.exe pid 3552，memdump -p 3552 后 010 中见百度网盘链接，取证大师恢复提取码 heem，命令/PID 一致，未复跑。
url: /docs/ctf/forensics/ctf-forensics-memdump-notepad-edit-control-plaintext/
draft: false
kb_aliases:
- 记事本进程内存取证
- notepad.exe memdump 明文
- 内存镜像提取记事本内容
- Edit 控件缓冲区取证
- 百度网盘链接内存恢复
---

## 一句话结论

对内存镜像里的 `notepad.exe` 执行 `vol.py -f <image> --profile=<profile> memdump -p <PID> -D <outdir>/`，把进程地址空间导出为 `<PID>.dmp`，再用 010/`strings`/取证工具按 ASCII 与 UTF-16LE 搜索，即可在 Edit 控件缓冲区或堆中找到记事本窗口曾显示/输入过的明文内容（网盘链接、提取码、密码、flag），即使窗口已关闭。

## 原理

- **记事本文本在用户态内存**：Windows 记事本的编辑区是 `Edit` 控件（comctl32/user32），文本保存在进程用户态内存的缓冲区中（视版本为 ANSI 或 UTF-16LE），用户输入后未保存也一直存在，直到进程退出或被覆盖。
- **memdump 的粒度**：Volatility2 的 `memdump -p <PID>` 按进程页表导出该进程可读的用户态页（打包成 `<PID>.dmp`），保留原始字节布局；文本不会因为不在窗口上而消失。
- **为什么能搜索到**：链接/提取码/密码等是连续字符串，direct 搜索 `http`、`pan.baidu.com`、`flag{` 等前缀即可定位；中文/宽字符场景要按 UTF-16LE 搜索，或同时覆盖两种编码，避免漏检。
- **边界**：进程退出后内存页可能被回收/覆盖，镜像采集越晚越可能丢；dump 中夹杂大量二进制与碎片，需要按上下文人工筛选；纯内存搜索找不到已被程序主动清零的文本。

## 触发条件

- 内存镜像中存在 `notepad.exe` 进程（`pslist` 可见），且题目提示「记事本」或需查找输入过的文本/链接。
- 文本未被程序擦除，镜像采集时进程仍在或退出不久。

## 利用步骤

1. `vol.py -f <image> --profile=<profile> pslist` 找 `notepad.exe` 的 PID。
2. `vol.py -f <image> --profile=<profile> memdump -p <PID> -D <outdir>/` 导出 `<PID>.dmp`。
3. 用 010 Editor 或 `strings -el`（UTF-16LE）与 `strings`（ASCII）搜索关键前缀：`http`、`pan.baidu.com`、`提取码`、`flag`、`password`。
4. 命中链接后按提示下载/解码；也可用取证大师等工具的「文件恢复」入口直接恢复同目录文件得到提取码。

最小化 PoC：

```
vol.py -f mem.raw --profile=Win7SP1x86_23418 pslist | grep notepad
vol.py -f mem.raw --profile=Win7SP1x86_23418 memdump -p 3552 -D outfile/
strings -el outfile/3552.dmp | grep -i "http\|baidu\|提取码"
```

## 变体与关联

- 同题常配合 `mspaint.exe` 的 memdump：导出后把 dump 当原始位图（改后缀 `.data`）用 GIMP 打开，可恢复画图里手写的密码。
- `screenshot` 插件直接恢复桌面截图，可能一步看到记事本窗口内容，省去 memdump。
- 镜像级关键字搜索（不依赖进程）适合已知 flag 前缀的快速命中；本方法适合定位「窗口里出现过但不知道内容」的文本。
- `filescan` + `dumpfiles -Q <物理地址>` 可导出内存中缓存的目标文件本体。

## 检测与防御

- 取证方：内存镜像中的进程 dump 能还原未保存文本，属于常规取证材料；采集时优先 dump 仍存活的进程。
- 防御方：敏感内容（口令、链接）不要长期停留在记事本等明文控件中；内存转储/快照按敏感数据管理。
