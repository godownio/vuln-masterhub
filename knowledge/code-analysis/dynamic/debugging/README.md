# 调试

## 这层是什么

断点、单步、内存与寄存器分析。

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
| [Delphi 注册对话框输入定位：DialogBoxParamW 回调 + GetDlgItem 条件断点 + GetWindowTextA](code-analysis-dynamic-debugging-delphi-dialog-getdlgitem-windowtext-locate.md) | draft | high | 2026-11-07 |
| [VEH 隐形断点与动态补丁：AddVectoredExceptionHandler 捕获异常后改 CONTEXT 控制程序流程](code-analysis-dynamic-debugging-veh-invisible-breakpoint-dynamic-patch.md) | verified | high | 2026-11-07 |
| [VirtualProtect 运行时解密代码的 IDA 动态还原：断点执行解密后 U/C/P 重建函数](code-analysis-dynamic-debugging-virtualprotect-runtime-decrypt-ida.md) | verified | high | 2026-11-05 |
| [x64dbg 动态提取纤程 Loader 解密后的 shellcode：断点 ConvertThreadToFiber/VirtualAlloc/memcpy](code-analysis-dynamic-debugging-x64dbg-fiber-loader-shellcode-dump.md) | verified | high | 2026-11-05 |
| [x64dbg 动态调试破解密码校验：改寄存器/ZF 与二进制补丁绕过本地及服务端验证](code-analysis-dynamic-debugging-crackme-password-check-patch.md) | verified | medium | 2026-11-07 |
| [分片 shellcode 加载器：data_1..9.db 拼接 + 16 字节块 XOR 解密 + error.log 明文回退](code-analysis-dynamic-debugging-split-shellcode-file-loader-xor.md) | verified | high | 2026-11-05 |
| [多层编码 shellcode 还原：hex→RC4→ASCII85 解码链与 VirtualAlloc 断点转储](code-analysis-dynamic-debugging-multi-layer-shellcode-decrypt-dump.md) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
