# Node.js 反序列化

## 这层是什么

node-serialize、serialize-javascript 等。

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
| [CVE-2025-55182 有回显利用：NEXT_REDIRECT digest 把命令输出带进 307 Location](web-nodejs-deserialization-react-flight-next-redirect-echo.md) | verified | high | 2026-11-05 |
| [Next.js RSC 反序列化链：ReflectAdapter.set 改 sendStatusCode，patch module.wrapper 调 _compile（CVE 归属未确认）](web-nodejs-deserialization-nextjs-cve-2025-55183-rsc-reflect-adapter-chain.md) | verified | medium | 2026-11-06 |
| [node-serialize _$$ND_FUNC$$_ 标记配合 IIFE 反序列化 RCE](web-nodejs-deserialization-node-serialize-funcflag-iife-rce.md) | verified | high | 2026-11-05 |
| [Qwik server$ QRL 反序列化：qwik-json 的 _objs 指定模块与符号，importSymbol 动态 require 执行](web-nodejs-deserialization-qwik-server-qrl-rce.md) | verified | high | 2026-11-05 |
| [React Server Components CVE-2025-55182：decodeAction 伪造 $ACTION_REF_ 服务器引用经 vm#runInThisContext 执行命令](web-nodejs-deserialization-react-actions-action-ref-vm-rce.md) | verified | high | 2026-11-05 |
| [React Server Components decodeAction 任意模块导出调用：$ACTION_REF 指向 child_process#execSync 直接 RCE（CVE-2025-55182）](web-nodejs-deserialization-react-decodeaction-actionref-arbitrary-module-export.md) | verified | high | 2026-11-05 |
| [React Server Components Flight 协议反序列化链 RCE（CVE-2025-55182 React2Shell）](web-nodejs-deserialization-react-flight-chunk-proto-function-rce.md) | verified | medium | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
