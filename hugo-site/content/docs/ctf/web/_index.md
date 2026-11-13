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
| [AWD 同构靶机共享密钥批量打法：一份 Shiro rememberMe Cookie（或固定口令）打全场收 flag](ctf-web-awd-shared-secret-batch-replay/) | verified | medium | 2026-11-09 |
| [Cherry Markdown 代码围栏语言名注入 + file:// 渲染页 iframe 读取本地文件并输出 PDF](ctf-web-cherry-markdown-fence-lang-file-uri-iframe-pdf-exfil/) | verified | medium | 2026-11-06 |
| [CTF Bot 链：jku 伪造 admin JWT + CSP report-uri 注入 + Nginx CRLF 替换 Cookie 外带 Flag](ctf-web-bot-jku-csp-crlf-cookie-hijack-chain/) | verified | high | 2026-11-05 |
| [CTF Bot 链：superbot 页面 XSS 打角色受限 debug SQL 注入点，堆叠 UPDATE 提权读 Flag](ctf-web-bot-xss-role-gated-debug-sqli-escalation/) | verified | high | 2026-11-07 |
| [dig 命令参数注入：type 字段传入 -f/flag 把目标文件当作查询批处理读取](ctf-web-dig-type-argument-injection-f-read-file/) | verified | medium | 2026-11-10 |
| [ECDSA 零签名伪造 JWT + \uXXXX 绕过关键字过滤 + Thymeleaf 模板覆盖 RCE](ctf-web-ecdsa-zero-signature-jwt-thymeleaf-template-overwrite/) | verified | high | 2026-11-06 |
| [Elixir BEAM 发布包恢复隐藏路由 + Ecto SQLi 与 FPX CRC16 仿射 oracle 到 RCE](ctf-web-elixir-beam-fpx-crc16-affine-oracle/) | verified | high | 2026-11-06 |
| [Flask+Node 多组件链：下载穿越读源码 → KMZ 原型污染激活本地管理接口 → merge 清 WAF → Jinja 语句块 SSTI](ctf-web-flask-node-file-read-prototype-pollution-ssti-chain/) | verified | high | 2026-11-06 |
| [Go RBAC 权限门控绕过：map 遍历乱序 + 错误分支不重置导致 return 权限累积](ctf-web-go-rbac-map-order-error-reset-bypass/) | verified | medium | 2026-11-07 |
| [Go server.exe 逆向 + 本地复现签发管理员 JWT：改 SQLite role 复用同一 HS256 密钥](ctf-web-go-server-local-replay-admin-jwt/) | verified | high | 2026-11-06 |
| [JS 边缘运行时沙箱逃逸：枚举 __runtime 内部符号 + Uint8Array 路径绕过字符串检查读文件](ctf-web-js-runtime-internal-symbol-uint8array-sandbox-escape/) | verified | low | 2026-11-06 |
| [Ktor WebSocket 未授权订阅 + DSL SQL() 括号截断注入 H2，CREATE ALIAS 命令执行](ctf-web-ktor-websocket-dsl-sqli-h2-create-alias/) | verified | high | 2026-11-06 |
| [PHP 双重 eval + 字符白名单：用异或块在 70 字符内拼出 `cat *` 执行命令](ctf-web-php-double-eval-xor-backtick-command/) | verified | high | 2026-11-07 |
| [PHP 多阶段认证绕过：str_replace 双写 + POST 数组转对象属性 + MD5 魔术哈希](ctf-web-php-str-replace-double-write-object-cast-md5-magic-hash/) | verified | high | 2026-11-06 |
| [PHP 弱比较 + php://filter 读源码：==0 绕过、data:// 满足内容校验与 stripos 参数顺序](ctf-web-php-weak-compare-php-filter-data-wrapper/) | verified | high | 2026-11-07 |
| [Puppeteer bot 的 URLBlocklist 黑名单绕过：反斜杠改写路由 + URL 编码参数名，让带管理员 cookie 的 bot 访问本应被拦的 /giveflag?token=](ctf-web-bot-urlblocklist-backslash-path-encoded-param-bypass/) | verified | high | 2026-11-08 |
| [Redis 键名注入：用户输入直接作为 GET 的 key，提交 admin_password 等相邻键名读出敏感值](ctf-web-redis-getkey-name-injection-read-adjacent-secrets/) | verified | high | 2026-11-08 |
| [report bot 未校验 URL scheme：page.goto 直接执行 javascript: 伪协议 XSS，sendBeacon 外带同源数据](ctf-web-bot-report-javascript-scheme-xss-exfil/) | draft | high | 2026-11-08 |
| [Service Worker 路径双重解码 + scope 混淆 + navigationPreload 读取 /u/admin/dashboard](ctf-web-service-worker-double-decode-scope-navigation-preload/) | verified | high | 2026-11-06 |
| [SQLi 挖 sqlite_dbpage 删除记录 + ECDH/AES-GCM 网关重放命中隐藏 legacy bootstrap 接口](ctf-web-sqli-sqlite-dbpage-deleted-pcap-ecdh-gateway-bootstrap/) | verified | high | 2026-11-06 |
| [SVG XXE + PHP 反序列化 include + SUID xxd + Go ChaCha20 解密全链](ctf-web-svg-xxe-php-deser-suid-xxd-go-chacha20/) | verified | high | 2026-11-06 |
| [上传路径参数双重滥用：拼接 open 任意文件读取源码，os.system base64 命令注入输出落盘后再读取回读](ctf-web-file-path-cmdinj-output-drop-arbitread/) | draft | high | 2026-11-08 |
| [分数由前端 AES 加密提交：密钥/IV 在前端 JS 里，解出明文改分再重新加密即刷分](ctf-web-client-aes-score-forgery-hardcoded-key-iv/) | verified | low | 2026-11-09 |
| [加密 uid Cookie 的解密回显接口当 oracle：替换为任意密文即可解出明文（动态 Flag）](ctf-web-encrypted-uid-cookie-decrypt-echo-oracle/) | verified | high | 2026-11-11 |
| [原型链继承 nonce 绕过管理员校验 + Express 同名参数数组/截断路径穿越读文件](ctf-web-ezlog-prototype-inherited-nonce-query-array-traversal/) | verified | high | 2026-11-06 |
| [客户端 Wasm 游戏逻辑篡改：改 Minimax 比较或伪造棋盘与 proof 绕过服务端校验](ctf-web-wasm-client-game-logic-tamper-proof-forgery/) | verified | high | 2026-11-06 |
| [无回显命令执行用 ping + $() + base64 把输出编码进 DNS 域名外带](ctf-web-noecho-ping-base64-dns-exfil/) | verified | high | 2026-11-12 |
| [无字母数字命令拼接：用 $() 空替换与 $((~$(()))) 算术展开拼出目标字符串，绕过只放行符号的正则](ctf-web-shell-arithmetic-expansion-no-alnum-string/) | verified | low | 2026-11-08 |
| [智能客服要求「用户名 + 编号」才给 flag：编号从公开 PDF 取，字符视觉相似（I/l/1）不对时靠变体枚举试出来](ctf-web-llm-bot-identity-proof-pdf-visual-similar-char-enumeration/) | verified | medium | 2026-11-09 |
| [有序关键字正则 + 符号/空格/bash 多重过滤的组合绕过：反序拼接变量 + $IFS$1 + cat `ls` 全目录读取](ctf-web-ordered-flag-regex-concat-reorder-bypass/) | verified | high | 2026-11-11 |
| [未净化 autosave 草稿存储型 XSS + 非 httpOnly 会话与 sid_prev 备份 cookie 窃取管理员会话](ctf-web-autosave-xss-sid-prev-backup-cookie-admin-session/) | verified | high | 2026-11-06 |
| [未签名角色 Cookie + PHP md5 魔术哈希双人复核 + loopback 预览 SSRF 读内网 flag](ctf-web-unsigned-role-cookie-md5-magic-hash-ssrf-loopback/) | verified | high | 2026-11-06 |
| [自助注册 admin + 拒绝分支 trace_id 回读调试日志：hex pickle 对象泄露 flag](ctf-web-admin-self-register-trace-id-pickle-log-leak/) | verified | high | 2026-11-06 |
| [随机数上下界同时依赖 date('s')：秒数归零时取值区间退化为单值，卡整点秒提交即命中](ctf-web-random-int-time-seeded-range-collapse/) | verified | high | 2026-11-09 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
