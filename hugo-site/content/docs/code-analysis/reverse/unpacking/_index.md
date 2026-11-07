---
title: 脱壳
weight: 1
---

# 脱壳

## 这层是什么

壳识别、手动/自动脱壳、内存 dump 与重建。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [32 位 DLL 样本手动脱壳：rundll32 导出加载 + VirtualAlloc/VirtualProtect 断点定位 aPLib 载荷并修复 PE](code-analysis-reverse-unpacking-dll-aplib-virtualalloc-protect-dump/) | verified | high | 2026-11-06 |
| [ClassFinal 加密 JAR 逆向：javaagent 运行时解密 + Arthas 枚举、反编译并修改已加载类](code-analysis-reverse-unpacking-classfinal-javaagent-runtime-class-dump/) | verified | high | 2026-11-06 |
| [fwrite 静态缓冲区释放内嵌 PE：按固定长度从 .data 提取二阶段驱动](code-analysis-reverse-unpacking-fwrite-static-buffer-embedded-pe/) | verified | high | 2026-11-06 |
| [PE 加载器：LCG 派生 ChaCha20 key/nonce 解密二阶段 PE](code-analysis-reverse-unpacking-pe-loader-lcg-chacha20/) | verified | high | 2026-11-06 |
| [PyInstaller --key 加密 PYZ：pyimod00_crypto_key 取密钥 + 按版本分流 PyCrypto-CFB/tinyaes-CTR 解密 pyc.encrypted](code-analysis-reverse-unpacking-pyinstaller-key-encrypted-pyz-pyc-decrypt/) | verified | high | 2026-11-07 |
| [PyInstaller EXE 二次打包：spec TOC 注入与 CArchive 手工重写](code-analysis-reverse-unpacking-pyinstaller-repack-spec-carchive-toc/) | verified | high | 2026-11-05 |
| [PyInstaller EXE 识别与解包：CArchive/PYZ/pyc 提取还原源码](code-analysis-reverse-unpacking-pyinstaller-carchive-pyz-extract/) | verified | high | 2026-11-05 |
| [PyInstaller pyd 内嵌 XOR 加密 marshal code object：IDA dump + 循环异或还原 pyc](code-analysis-reverse-unpacking-pyinstaller-pyd-xor-marshal-code-object/) | verified | high | 2026-11-07 |
| [PyInstaller 加载器：EXE 尾部追加 ZIP + 16 字节 footer（ZIP 大小/magic），解压到临时目录并启动诱饵与木马](code-analysis-reverse-unpacking-pyinstaller-appended-zip-footer-dropper/) | verified | high | 2026-11-06 |
| [Python 恶意样本多层套娃：base64+gzip/bz2/lzma/zlib → compile/exec → reverse+marshal co_consts 链还原](code-analysis-reverse-unpacking-python-nested-marshal-consts-chain/) | verified | high | 2026-11-07 |
| [Speakeasy 仿真运行 UPX 样本并 dump 内存：定位 Base64 内嵌 PE 二阶段](code-analysis-reverse-unpacking-speakeasy-memory-dump-base64-pe/) | verified | high | 2026-11-06 |
| [Themida 3.x 用 unlicense 跟踪 OEP dump 脱壳 + 花指令 NOP：魔改 RC4 与 TEA 逆运算还原 flag](code-analysis-reverse-themida-unlicense-oep-rc4-tea/) | verified | high | 2026-11-07 |
| [UPX 壳的手动脱壳流程](upx-manual/) | draft | high | 2026-11-04 |
| [UPX 手动脱壳实战：x64dbg 栈硬件断点定位 POPAD/OEP 并用 Scylla 转储修复 IAT](code-analysis-reverse-unpacking-upx-manual-esp-breakpoint-scylla/) | draft | high | 2026-11-07 |
| [VMProtect 压缩壳手动脱壳：Sleep 断点 + MSVC security cookie 定位 OEP + VMPImportFixer 修复导入](code-analysis-reverse-unpacking-vmprotect-compression-sleep-cookie-oep-import-fix/) | verified | medium | 2026-11-07 |
| [XJar 加密 JAR 逆向：从启动器参数与 VisualVM 堆转储提取 AES key/iv 解密 class](code-analysis-reverse-unpacking-xjar-encrypted-class-heap-key/) | verified | high | 2026-11-06 |
| [改版 UPX x64 无执行脱壳：节表异常识别 + Unicorn 仿真 stub dump](code-analysis-reverse-unpacking-modified-upx-unicorn-stub-emulation/) | verified | high | 2026-11-06 |
| [改版 UPX 区段名还原：SAUY/YSYY/C4RP 改回 UPX0/UPX1/UPX2 后用 upx -d 脱壳](code-analysis-reverse-unpacking-upx-section-name-restore/) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
