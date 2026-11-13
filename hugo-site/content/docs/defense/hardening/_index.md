---
title: 加固
weight: 1
---

# 加固

## 这层是什么

系统、应用、云与供应链加固。

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
| [AI 智能体场景边界与工具权限加固：意图-内容双层校验、场景-工具绑定与思考过程监控](defense-hardening-ai-agent-scene-boundary-tool-permission/) | verified | medium | 2026-11-07 |
| [ELF 同名符号替换的分层加固：hidden、RTLD_LOCAL、-Bsymbolic 与 AT_SECURE 的边界](defense-hardening-elf-symbol-interposition-mitigation/) | verified | high | 2026-11-05 |
| [Fastjson 不能升级时的三层加固：关 JDK 远程 Codebase 与 trustSerialData、关 autoType 并开 SafeMode、必须用 @type 时改走 addAccept 白名单](defense-hardening-fastjson-autotype-three-layer-jndi-trustcodebase-whitelist/) | verified | medium | 2026-11-09 |
| [IFUNC 重定向的分层防御：AT_SECURE、静态链接、符号隐藏与审计](defense-hardening-ifunc-resolver-injection/) | verified | high | 2026-11-05 |
| [JAR 重打包后的签名校验边界与发布前验签](defense-hardening-jar-signature-repackage-verification/) | verified | high | 2026-11-04 |
| [Java RASP 通防的 sink hook 布局与盲区：FileInputStream/JNDI/ProcessImpl/ObjectInputStream/SpEL/MySQL 六类 hook 及 native 绕过](defense-hardening-java-rasp-sink-hookpoints-limits/) | verified | high | 2026-11-07 |
| [MiniFilter 拦截 DLL/EXE 镜像加载：IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION 预回调按 PAGE_EXECUTE + PID/路径拒绝，FltReadFile 做 PE 校验](defense-hardening-windows-minifilter-acquire-section-block-image-load/) | verified | medium | 2026-11-12 |
| [MiniFilter 文件/目录保护驱动：IRP_MJ_CREATE + IRP_MJ_SET_INFORMATION 预回调按 PID/路径/属性拒绝访问与删改](defense-hardening-windows-minifilter-file-directory-protection/) | verified | medium | 2026-11-12 |
| [Windows 内核进程保护驱动：ObRegisterCallbacks 剥离句柄危险权限 + 进程创建回调自动保护子进程](defense-hardening-windows-kernel-process-protection-ob-callback/) | verified | medium | 2026-11-07 |
| [用 ASM 在 ClassFileTransformer 里插入 hook 调用：visitCode + 局部变量表下标规则定位表达式/命令参数](defense-hardening-rasp-asm-visitcode-hook-localvar-index/) | verified | high | 2026-11-08 |
| [钓鱼附件视觉欺骗防御：扩展名显示、bidi/零宽净化、LNK 深度解析与渲染隔离](defense-hardening-phishing-filename-visual-spoof/) | verified | medium | 2026-11-07 |
| [驱动注册 RegistryCallback 拦截注册表键创建/重命名保护启动项](defense-hardening-windows-registry-callback-key-protection/) | verified | medium | 2026-11-08 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
