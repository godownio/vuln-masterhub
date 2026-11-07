---
title: CTF Web
weight: 1
---

# CTF Web

## 这层是什么

Web 题型技巧与绕过。

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
| [.git 泄露旧提交调试密钥：伪造 HS256 auditor JWT + HMAC 签名调用内部审计接口](ctf-web-git-history-debug-secret-jwt-hmac-audit/) | verified | high | 2026-11-06 |
| [AI 引擎 raw 协议透传 + 弱派生 admin token + NCM Type=5 命令注入（validate_hook 前缀 ../ 绕过）](ctf-web-raw-socket-admin-token-ncm-command-injection/) | verified | high | 2026-11-06 |
| [Cherry Markdown 代码围栏语言名注入 + file:// 渲染页 iframe 读取本地文件并输出 PDF](ctf-web-cherry-markdown-fence-lang-file-uri-iframe-pdf-exfil/) | verified | medium | 2026-11-06 |
| [CTF Bot 链：jku 伪造 admin JWT + CSP report-uri 注入 + Nginx CRLF 替换 Cookie 外带 Flag](ctf-web-bot-jku-csp-crlf-cookie-hijack-chain/) | verified | high | 2026-11-05 |
| [ECDSA 零签名伪造 JWT + \uXXXX 绕过关键字过滤 + Thymeleaf 模板覆盖 RCE](ctf-web-ecdsa-zero-signature-jwt-thymeleaf-template-overwrite/) | verified | high | 2026-11-06 |
| [Elixir BEAM 发布包恢复隐藏路由 + Ecto SQLi 与 FPX CRC16 仿射 oracle 到 RCE](ctf-web-elixir-beam-fpx-crc16-affine-oracle/) | verified | high | 2026-11-06 |
| [Flask+Node 多组件链：下载穿越读源码 → KMZ 原型污染激活本地管理接口 → merge 清 WAF → Jinja 语句块 SSTI](ctf-web-flask-node-file-read-prototype-pollution-ssti-chain/) | verified | high | 2026-11-06 |
| [Go server.exe 逆向 + 本地复现签发管理员 JWT：改 SQLite role 复用同一 HS256 密钥](ctf-web-go-server-local-replay-admin-jwt/) | verified | high | 2026-11-06 |
| [JS 边缘运行时沙箱逃逸：枚举 __runtime 内部符号 + Uint8Array 路径绕过字符串检查读文件](ctf-web-js-runtime-internal-symbol-uint8array-sandbox-escape/) | verified | low | 2026-11-06 |
| [Ktor WebSocket 未授权订阅 + DSL SQL() 括号截断注入 H2，CREATE ALIAS 命令执行](ctf-web-ktor-websocket-dsl-sqli-h2-create-alias/) | verified | high | 2026-11-06 |
| [PHP 多阶段认证绕过：str_replace 双写 + POST 数组转对象属性 + MD5 魔术哈希](ctf-web-php-str-replace-double-write-object-cast-md5-magic-hash/) | verified | high | 2026-11-06 |
| [Service Worker 路径双重解码 + scope 混淆 + navigationPreload 读取 /u/admin/dashboard](ctf-web-service-worker-double-decode-scope-navigation-preload/) | verified | high | 2026-11-06 |
| [SQLi 挖 sqlite_dbpage 删除记录 + ECDH/AES-GCM 网关重放命中隐藏 legacy bootstrap 接口](ctf-web-sqli-sqlite-dbpage-deleted-pcap-ecdh-gateway-bootstrap/) | verified | high | 2026-11-06 |
| [SVG XXE + PHP 反序列化 include + SUID xxd + Go ChaCha20 解密全链](ctf-web-svg-xxe-php-deser-suid-xxd-go-chacha20/) | verified | high | 2026-11-06 |
| [原型链继承 nonce 绕过管理员校验 + Express 同名参数数组/截断路径穿越读文件](ctf-web-ezlog-prototype-inherited-nonce-query-array-traversal/) | verified | high | 2026-11-06 |
| [客户端 Wasm 游戏逻辑篡改：改 Minimax 比较或伪造棋盘与 proof 绕过服务端校验](ctf-web-wasm-client-game-logic-tamper-proof-forgery/) | verified | high | 2026-11-06 |
| [未净化 autosave 草稿存储型 XSS + 非 httpOnly 会话与 sid_prev 备份 cookie 窃取管理员会话](ctf-web-autosave-xss-sid-prev-backup-cookie-admin-session/) | verified | high | 2026-11-06 |
| [未签名角色 Cookie + PHP md5 魔术哈希双人复核 + loopback 预览 SSRF 读内网 flag](ctf-web-unsigned-role-cookie-md5-magic-hash-ssrf-loopback/) | verified | high | 2026-11-06 |
| [自助注册 admin + 拒绝分支 trace_id 回读调试日志：hex pickle 对象泄露 flag](ctf-web-admin-self-register-trace-id-pickle-log-leak/) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
