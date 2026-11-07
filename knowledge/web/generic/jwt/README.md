# JWT

## 这层是什么

算法混淆、密钥爆破、kid/jku 注入。

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
| [HS256 弱密钥字典爆破后签发任意 JWT](web-generic-jwt-weak-hmac-key-bruteforce.md) | verified | high | 2026-11-05 |
| [JWT jku 头劫持：服务端从攻击者 JWKS 取公钥验签](web-generic-jwt-jku-header-hijack.md) | verified | high | 2026-11-05 |
| [JWT jwk 头注入：服务端信任令牌内嵌公钥，攻击者自带密钥伪造管理员](web-generic-jwt-jwk-header-injection.md) | verified | high | 2026-11-05 |
| [JWT kid 头注入：SQL UNION 控制验签密钥](web-generic-jwt-kid-injection.md) | verified | high | 2026-11-05 |
| [JWT kid 绝对路径读取源码取硬编码密钥：黑名单只挡打印不挡加载](web-generic-jwt-kid-absolute-path-source-key-disclosure.md) | verified | high | 2026-11-06 |
| [JWT Payload 明文携带密码哈希：解码后离线破解并直接登录](web-generic-jwt-payload-password-hash-leak.md) | verified | high | 2026-11-05 |
| [JWT 以用户密码作 HS256 密钥：枚举 userId 后离线/在线爆破口令接管教师账号](web-generic-jwt-password-as-hmac-key-bruteforce.md) | verified | medium | 2026-11-05 |
| [NocoDB JWT 密钥明文存 nc_store + is_api_token 旁路 token_version：伪造 super-admin Token](web-generic-jwt-nocodb-store-secret-is-api-token-forgery.md) | verified | high | 2026-11-05 |
| [PyJWT 变异 PEM 绕过 HMAC 公钥防护：CR/缩进/折叠公钥当对称密钥伪造 JWT](web-generic-jwt-pyjwt-mutated-pem-hmac-guard-bypass.md) | verified | high | 2026-11-05 |
| [RS256→HS256 算法混淆：用公钥当 HMAC 密钥伪造 JWT](web-generic-jwt-rs256-hs256-confusion.md) | verified | high | 2026-11-05 |
| [ZPan ≤ v1.6.5 硬编码 JWT 密钥 "123" 伪造管理员，详情接口未脱敏窃取 OSS AK/SK](web-generic-jwt-zpan-hardcoded-secret-oss-credential-leak.md) | verified | high | 2026-11-07 |
| [从 Go 服务端二进制提取硬编码 HS256 密钥，伪造 role=admin 的 JWT](web-generic-jwt-go-binary-hardcoded-secret-admin-forgery.md) | verified | high | 2026-11-06 |
| [小智 ESP32 管理平台：JWT 未配置时回退硬编码 HS256 密钥，可伪造 admin 令牌](web-generic-jwt-xiaozhi-default-hs256-secret-forgery.md) | verified | high | 2026-11-05 |
| [无公开公钥时用两个 RS256 JWT 恢复公钥并做 HS256 算法混淆](web-generic-jwt-rs256-hs256-confusion-key-recovery.md) | verified | high | 2026-11-05 |
| [服务端完全不验证 JWT 签名时直接篡改 sub/role 提权](web-generic-jwt-unverified-signature-payload-tamper.md) | verified | high | 2026-11-05 |
| [服务端接受 alg:none 时无签名伪造 JWT 提权](web-generic-jwt-alg-none-bypass.md) | verified | high | 2026-11-05 |
| [示例配置硬编码 JWT SECRET_KEY，用公开默认值伪造 admin 令牌](web-generic-jwt-example-config-hardcoded-secret.md) | verified | medium | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
