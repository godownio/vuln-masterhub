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
| [AI 智能体场景边界与工具权限加固：意图-内容双层校验、场景-工具绑定与思考过程监控](defense-hardening-ai-agent-scene-boundary-tool-permission.md) | verified | medium | 2026-11-07 |
| [ELF 同名符号替换的分层加固：hidden、RTLD_LOCAL、-Bsymbolic 与 AT_SECURE 的边界](defense-hardening-elf-symbol-interposition-mitigation.md) | verified | high | 2026-11-05 |
| [IFUNC 重定向的分层防御：AT_SECURE、静态链接、符号隐藏与审计](defense-hardening-ifunc-resolver-injection.md) | verified | high | 2026-11-05 |
| [JAR 重打包后的签名校验边界与发布前验签](defense-hardening-jar-signature-repackage-verification.md) | verified | high | 2026-11-04 |
| [Java RASP 通防的 sink hook 布局与盲区：FileInputStream/JNDI/ProcessImpl/ObjectInputStream/SpEL/MySQL 六类 hook 及 native 绕过](defense-hardening-java-rasp-sink-hookpoints-limits.md) | verified | high | 2026-11-07 |
| [Windows 内核进程保护驱动：ObRegisterCallbacks 剥离句柄危险权限 + 进程创建回调自动保护子进程](defense-hardening-windows-kernel-process-protection-ob-callback.md) | verified | medium | 2026-11-07 |
| [钓鱼附件视觉欺骗防御：扩展名显示、bidi/零宽净化、LNK 深度解析与渲染隔离](defense-hardening-phishing-filename-visual-spoof.md) | verified | medium | 2026-11-07 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
