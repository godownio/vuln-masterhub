# Cookie 与会话

## 这层是什么

Cookie 解析、身份伪造、会话固定与签名缺失。

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
| [AES-CBC 加密 JSON 会话：按 base64 字符位爆破翻转 admin 字段（JSON 类型错误作 oracle）](web-generic-auth-cookie-json-session-base64-char-bruteforce-admin-flag.md) | draft | medium | 2026-11-08 |
| [Base64 Cookie 身份伪造导致未授权文件上传](web-generic-auth-cookie-base64-identity-forgery.md) | draft | high | 2026-11-04 |
| [Cartalyst Sentinel 原生 Cookie json_decode 类型失控叠加 MySQL 隐式转换绕过认证](web-generic-auth-sentinel-cookie-jsondecode-mysql-auth-bypass.md) | verified | high | 2026-11-05 |
| [Cookie 中 PHP 序列化对象未签名可篡改 isAdmin 字段实现越权](web-generic-auth-cookie-serialized-object-isadmin-forgery.md) | verified | high | 2026-11-08 |
| [Cookie 八进制转义 \073 解码成分号：绕过 user.lower()=='adm;n' 校验并写入 admin session](web-generic-auth-cookie-octal-escape-semicolon-check-bypass.md) | verified | high | 2026-11-08 |
| [MyBlog 硬编码 AES 盐值记住我 Cookie 伪造接管后台](web-generic-auth-myblog-hardcoded-aes-cookie-forgery.md) | verified | high | 2026-11-05 |
| [vCenter SAML Cookie 伪造：从 data.mdb 提取 IdP/信任证书，离线签发 VSPHERE-UI-JSESSIONID 管理员会话](web-java-component-vcenter-saml-data-mdb-cert-cookie-forgery.md) | verified | high | 2026-11-08 |
| [前端 login.js 里把 SessionToken 与固定字面值比较：直接设置 Cookie 为 statusOrCookie 进入 /admin 并读取 SSH 私钥](web-generic-auth-cookie-js-value-literal-sessiontoken-admin.md) | verified | medium | 2026-11-08 |
| [加密 Cookie 的 CBC 位翻转：改 IV 控制首块明文，role=guest 伪造为 role=admin](web-generic-auth-cookie-cbc-bitflip-iv-first-block-role-forgery.md) | verified | high | 2026-11-06 |
| [后台登录仅凭 cookieUsername 明文 Cookie，拼接他站成功响应绕过登录](web-generic-auth-cookie-login-response-splice-username-cookie.md) | verified | medium | 2026-11-05 |
| [泄露的签名密钥可离线伪造 PHP 序列化认证 Cookie 越权访问开发者功能](web-generic-auth-cookie-php-serialized-signature-forge.md) | verified | high | 2026-11-08 |
| [浏览器 Cookie 导出/导入重放：Cookie-Editor 导入 OWA 会话绕过登录，Chromium Cookie 库完整性校验 vs Firefox 明文注入](web-generic-auth-browser-cookie-import-outlook-owa-replay.md) | verified | high | 2026-11-10 |
| [硬编码 DES 密钥与弱结构校验导致 ERP 会话伪造](web-generic-auth-hardcoded-des-session-forgery.md) | verified | high | 2026-11-04 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
