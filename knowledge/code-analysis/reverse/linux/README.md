# Linux 逆向

## 这层是什么

ELF、内核模块、系统调用与调试。

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
| [C++ STL 容器内存布局与反汇编识别：string SSO、vector 三指针、map 红黑树、unordered_map 桶数组](code-analysis-reverse-linux-cpp-stl-container-layout-disassembly.md) | verified | high | 2026-11-06 |
| [ELF PT_NOTE 转 PT_LOAD 段劫持：在 program header 中植入 R+X shellcode 并改入口](code-analysis-reverse-linux-elf-pt-note-to-load-injection.md) | verified | high | 2026-11-05 |
| [ELF section header 清零仍可执行：双索引脱节造成的静态分析盲区](code-analysis-reverse-linux-elf-section-header-zeroing.md) | verified | high | 2026-11-05 |
| [ELF TEXT 段填充寄生：代码洞注入 + PT_NOTE 改 PT_LOAD 且文件大小不变](code-analysis-reverse-linux-elf-text-padding-parasite-file-size-invariant.md) | verified | high | 2026-11-05 |
| [IFUNC 重定向：同名 IFUNC 符号注入与加载期 resolver 执行](code-analysis-reverse-linux-ifunc-symbol-hijack-resolver.md) | verified | high | 2026-11-05 |
| [Linux ELF 自劫持 read@GOT：AT_PHDR 解析动态段 + mmap + memfrob(XOR 42) 注入解密逻辑](code-analysis-reverse-linux-elf-self-got-read-memfrob-hijack.md) | verified | high | 2026-11-07 |
| [Linux 恶意内核模块按 secret_ 前缀隐藏文件：lsmod/dmesg 定位与原始文件系统枚举](code-analysis-reverse-linux-lkm-prefix-file-hiding.md) | verified | low | 2026-11-06 |
| [protobuf-c 描述符逆向：从 stripped ELF 恢复 .proto 与 pb2](code-analysis-reverse-linux-protobuf-c-descriptor-recovery.md) | verified | high | 2026-11-05 |
| [篡改 ELF .note.gnu.property 改变依赖该 note 的 IFUNC 分派](code-analysis-reverse-linux-elf-note-ifunc-policy-tamper.md) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
