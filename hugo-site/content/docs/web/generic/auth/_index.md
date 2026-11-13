---
title: 认证与会话
weight: 1
---

# 认证与会话

## 这层是什么

Cookie/Session、身份伪造、认证绕过、会话固定与权限校验缺陷。

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

- [Cookie 与会话](cookie/) —— Cookie 解析、身份伪造、会话固定与签名缺失。

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [.NET HandleBase 硬编码 token 直接返回 admin：继承该基类的任意 Handler 未授权访问](web-generic-auth-hardcoded-token-handlebase-admin-bypass/) | verified | high | 2026-11-05 |
| [.NET Handler/WebMethod 在鉴权前用 useraccount 调 SetAuthCookie：伪造 admin 身份进入后台](web-generic-auth-dotnet-setauthcookie-before-check-useraccount/) | verified | high | 2026-11-05 |
| [.NET OA 全局鉴权绕过：ExtensionlessUrlHandler 让 .aspx/ 附加路径仍命中页面，EndsWith(".aspx") 检查被后缀跳过](web-generic-auth-dotnet-extensionlessurlhandler-aspx-endswith-bypass/) | verified | high | 2026-11-09 |
| [.NET 学习系统 Authorization 伪造：泄露的 CheckUID + Web.config 默认 DES 密钥构造 Acc_Pw 接管超管](web-generic-auth-dotnet-des-checkcode-authorization-forgery/) | verified | high | 2026-11-07 |
| [.NET 登录接口硬编码口令调用认证 BLL：忽略 userPass，已知用户名即可换取会话 Cookie（LLogin）](web-generic-auth-dotnet-login-hardcoded-password-any-user/) | verified | high | 2026-11-10 |
| [1Panel Agent mTLS 只验 CN 不验签发者：自签名证书伪造 panel_client 打通终端 WebSocket RCE](web-generic-auth-1panel-mtls-cn-cert-forgery-rce/) | verified | high | 2026-11-05 |
| [2FA 安全问题校验只比数量且按 key 存在性跳过：增删参数即绕过](web-generic-auth-2fa-answer-count-key-presence-bypass/) | verified | high | 2026-11-05 |
| [2FA 绕过：验证接口 username 参数篡改与 4 位验证码爆破](web-generic-auth-2fa-user-parameter-tampering-code-bruteforce/) | verified | high | 2026-11-05 |
| [2FA 验证码爆破绕过“错误即注销”：Burp 宏自动重登与重发码，单线程跑 0000-9999](web-generic-auth-2fa-code-bruteforce-macro-relogin-session-rule/) | verified | high | 2026-11-12 |
| [4 位短信验证码无尝试次数限制：爆破验证码注册任意手机号账号](web-generic-auth-sms-4digit-code-bruteforce-arbitrary-registration/) | verified | high | 2026-11-08 |
| [403/401 接口字典化绕过：静态资源后缀、分号与编码路径穿越](web-generic-auth-403-resource-suffix-path-dictionary-bypass/) | verified | medium | 2026-11-06 |
| [AI 推理服务 /debug 调试接口未鉴权：泄露 K8s API 地址、内网网关与数据库连接串](web-generic-auth-ai-api-debug-env-disclosure/) | verified | low | 2026-11-06 |
| [API 签名校验仅覆盖部分 HTTP 方法且无时效：换方法或重放旧签名绕过](web-generic-auth-api-signature-method-scope-replay-bypass/) | verified | medium | 2026-11-06 |
| [API 签名校验存在性三路对照检测](web-generic-auth-api-signature-validation-differential-test/) | verified | high | 2026-11-04 |
| [AstrBot 仪表盘默认/弱口令登录后台并泄露宿主机管理员凭据，复用口令 Pass-the-Hash 横向](web-generic-auth-astrbot-dashboard-weak-password/) | verified | medium | 2026-11-05 |
| [Azuriom 服务器管理路由缺权限中间件：低权管理员签发 AzLink Token 接管任意非管理员账号](web-generic-auth-azuriom-servers-route-missing-gate-token-account-takeover/) | verified | high | 2026-11-05 |
| [BossCMS admin::init 未登录仅 header 跳转不 exit/die：请求继续执行后台方法，未授权添加管理员/删文件/上传](web-generic-auth-bosscms-admin-init-header-no-exit/) | verified | high | 2026-11-13 |
| [CAS login service 参数未校验：302 把 ST ticket 带到任意外域，换 access_token 接管账号](web-generic-auth-cas-service-open-redirect-ticket-theft-ato/) | verified | high | 2026-11-07 |
| [CAS 登录前端 AES-CBC 加密逆向与自动化登录参数构造](web-generic-auth-cas-aes-cbc-login-encryption-reverse/) | verified | medium | 2026-11-04 |
| [CCFlow/CCBPM ProcessRequest 反射网关：缺 Token 即跳过鉴权，未授权调用任意无参公共方法](web-generic-auth-ccflow-processrequest-reflection-token-bypass/) | verified | high | 2026-11-05 |
| [CGI 登录分支仅凭 action=login&auth=1 直接创建 session](web-generic-auth-cgi-login-auth-param-session-bypass/) | verified | high | 2026-11-05 |
| [Chartbrew 遗留 dashboard 路由只校验同团队角色不校验项目成员：同团队低权用户越权读取任意项目仪表盘并泄露原始 report password（CVE-2026-40603）](web-generic-auth-chartbrew-legacy-dashboard-team-role-idor-password-leak/) | verified | high | 2026-11-06 |
| [COALESCE 默认值提权：keepRole/keepLane=false 写入 NULL，guest 被当作 maintainer+release](web-generic-auth-coalesce-null-default-privilege-escalation/) | verified | high | 2026-11-06 |
| [Connection 头声明 X-User 为逐跳头：Go 代理剥除鉴权头，后端默认 uid=0 接管](web-generic-auth-connection-hop-by-hop-header-strip-default-uid/) | verified | high | 2026-11-07 |
| [ControllerFilter5 excludePage 前缀通配白名单 + ../ 归一化差异绕过 Java 鉴权](web-generic-auth-fe-controllerfilter5-excludepage-prefix-bypass/) | verified | medium | 2026-11-05 |
| [CookieShop 后台订单删除接口缺失鉴权：普通用户会话可直接删任意订单](cookieshop-admin-order-delete-missing-authz/) | verified | high | 2026-11-08 |
| [cPanel/WHM Basic 认证密码 CRLF 注入会话文件：预认证直接提升为 root WHM（CVE-2026-41940）](web-generic-auth-cpanel-whm-basic-crlf-session-poison-auth-bypass/) | verified | high | 2026-11-05 |
| [DeepAudit 内置 demo@example.com/demo123 默认超级管理员账号](web-generic-auth-deepaudit-default-demo-superuser-credentials/) | verified | medium | 2026-11-06 |
| [DeepAudit 用户列表接口只校验登录不校验角色：普通用户拉取全量账号邮箱/手机号](web-generic-auth-deepaudit-user-list-missing-role-check-pii-leak/) | verified | high | 2026-11-06 |
| [Directus Webhook Flow 匿名触发 item-create：permissions=$full 以系统身份写库](web-generic-auth-directus-anonymous-flow-item-create/) | verified | high | 2026-11-05 |
| [EIS 办公平台 UserInfo.asmx 匿名 WebMethod：未授权创建员工账号并写入 DES 口令](web-generic-auth-eis-userinfo-asmx-unauth-user-create/) | verified | medium | 2026-11-05 |
| [Fastify 畸形 URL 直调最后注册的 404 处理器，绕过封装前缀认证（CVE-2026-76169）](web-generic-auth-fastify-badurl-shared-404-handler-bypass/) | verified | high | 2026-11-05 |
| [FE 系统 .ln 接口 SYS_LINK 加密串构造登录：url||过期时间||admin 无口令进后台](web-generic-auth-ln-sys-link-encrypted-string-login-bypass/) | verified | medium | 2026-11-12 |
| [FE 系统 FeErpLoginServlet op=D 直接以 admin 登录：无口令获取管理员会话](web-generic-auth-fe-login-opd-admin-session/) | verified | high | 2026-11-05 |
| [Flask 登录缺失字段 None==None 绕过 + 无签名 AES-CBC Cookie 位翻转提权](web-generic-auth-flask-none-equals-none-cbc-cookie-forgery/) | verified | high | 2026-11-06 |
| [Flowise CVE-2025-58434 忘记密码接口响应回显 tempToken：仅凭邮箱重置任意账户密码接管](web-generic-auth-flowise-forgot-password-temp-token-response-leak/) | verified | high | 2026-11-07 |
| [GitLab CVE-2023-7028：密码重置邮件发往多个地址导致任意用户接管](web-generic-auth-gitlab-cve-2023-7028-reset-email-array-takeover/) | verified | high | 2026-11-12 |
| [Host 头认证绕过：把 Host 改成 localhost 获取管理员面板](web-generic-auth-host-header-localhost-auth-bypass/) | verified | high | 2026-11-05 |
| [Host 端口注入 + 悬垂标记窃取重置邮件中的新密码](web-generic-auth-host-header-dangling-markup-password/) | verified | high | 2026-11-05 |
| [HTTP 重复参数污染：鉴权取第一个 patient_id、取数取最后一个，读隐藏 SYS-ADMIN 记录](web-generic-auth-hpp-duplicate-param-auth-data-mismatch/) | verified | high | 2026-11-06 |
| [IceCMS /User/ChangeUser 的 userId 越权（CVE-2023-6760/6761）：普通用户改他人资料并接管管理员账号](web-generic-auth-icecms-user-changeuser-idor/) | verified | high | 2026-11-09 |
| [IceCMS 内容删除接口按 ID 越权（CVE-2023-6762）：非所有者 token 可删除任意文章与广场内容](web-generic-auth-icecms-delete-by-id-idor/) | verified | medium | 2026-11-09 |
| [IceCMS 广场/评论接口缺失 JWT 校验（CVE-2023-6757/6758）：未授权读取全站用户表与篡改评论](web-generic-auth-icecms-square-comment-api-missing-jwt/) | verified | high | 2026-11-09 |
| [ICPAS IP 网络对讲广播系统许可证伪造：硬编码 AES-CBC key/IV + machineCode+800823 固定后缀](web-generic-auth-icpas-license-aes-hardcoded-key-800823/) | verified | high | 2026-11-07 |
| [IDOR 接口面扩展：current/me 替换为数字 ID、老版本接口与兄弟 CRUD 接口猜测](web-generic-auth-idor-current-path-replacement-sibling-crud/) | verified | high | 2026-11-07 |
| [inxedu /admin/sysuser/userlist 只校验登录不校验角色：普通用户会话读取全量后台用户信息](web-generic-auth-inxedu-sysuser-userlist-missing-role-check/) | verified | high | 2026-11-12 |
| [IoT 智能锁签名可预测 + 工厂模式降级导致管理员解锁](web-generic-auth-iot-nfc-lock-predictable-signature-factory-mode/) | verified | high | 2026-11-05 |
| [IP 登录失败封禁绕过：用自己账号成功登录重置计数器 + Pitchfork 交替字典](web-generic-auth-ip-lockout-reset-by-valid-login-pitchfork/) | verified | high | 2026-11-12 |
| [jeeWMS AuthInterceptor 白名单三处逻辑缺陷：正则放行全部 rest 路由、contains 子串放行与 ? 参数绕过](web-generic-auth-jeewms-authinterceptor-whitelist-regex-contains-bypass/) | verified | high | 2026-11-05 |
| [Jersey getUriInfo().getPath() + 「含点即文件」判断：用 /api/xxx;. 绕过 JWT 鉴权](web-generic-auth-jersey-getpath-isbasefile-semicolon-dot-jwt-bypass/) | verified | medium | 2026-11-07 |
| [JS 断点暴露内部签名函数 + JsRpc + mitmproxy 上游代理：为 Burp 请求自动注入动态签名头](web-generic-auth-jsrpc-mitmproxy-signature-header-injection/) | verified | high | 2026-11-12 |
| [JSF OA SessionFilter 用 getRequestURI 模糊匹配 login.jsf，;login.jsf 矩阵参数绕过登录](web-generic-auth-oa-jsf-sessionfilter-loginjsf-semicolon-bypass/) | verified | high | 2026-11-05 |
| [JSON 非法 Unicode 代理项截断：superadmin\ud888 角色名归一化绕过内部角色限制提权](web-generic-auth-json-invalid-unicode-surrogate-role-truncation/) | verified | high | 2026-11-08 |
| [JSP/Servlet 未授权改密接口：update_student_security / update_teacher_password 直接按请求 id 更新口令，不校验登录态、归属与旧密码](web-generic-auth-unauth-update-password-by-id-oldpwd-missing/) | draft | high | 2026-11-08 |
| [JWT 仅校验签名未校验 role 导致垂直越权读取敏感数据](web-generic-auth-jwt-signature-only-role-bypass/) | verified | high | 2026-11-04 |
| [Koa 鉴权中间件未锚定正则匹配整条 URL：查询参数塞 webhooks/trigger 绕过全部鉴权（CVE-2026-31816）](web-generic-auth-unauth-koa-middleware-regex-query-bypass/) | verified | medium | 2026-11-05 |
| [Lodop/C-Lodop 云打印服务默认空口令：admin/guest 初始密码为空，可未授权控制打印输出](web-generic-auth-lodop-print-default-empty-password/) | verified | medium | 2026-11-12 |
| [LoginAdminFilter 以请求参数 sybz=WZQ 放行：任意 JSP 未授权访问（可配合 /login/../ URI 绕过）](web-generic-auth-loginadminfilter-sybz-param-bypass/) | verified | medium | 2026-11-05 |
| [mall APP 端 /order/cancelUserOrder 水平越权：orderId 未校验归属可取消他人未付款订单](web-generic-auth-mall-cancel-user-order-idor/) | verified | high | 2026-11-05 |
| [mall APP 端 /order/paySuccess 水平越权：任意用户把他人订单改为已支付实现 0 元购](web-generic-auth-mall-pay-success-idor-zero-cost-order/) | verified | high | 2026-11-05 |
| [Milvus 9091 管理端口 /expr 弱默认 token：auth=by-dev 未授权执行表达式（CVE-2026-26190）](web-generic-auth-milvus-9091-expr-weak-token-unauth/) | verified | high | 2026-11-05 |
| [Milvus rootcoord 内部 gRPC 53100 未接认证拦截器：容器网络内直连即 full admin](web-generic-auth-milvus-rootcoord-53100-unauthenticated/) | verified | high | 2026-11-05 |
| [Milvus sourceid 内部成员后门：base64("@@milvus-member@@") 加伪造 authorization 直接获得 full admin（CVE-2025-64513）](web-generic-auth-milvus-sourceid-header-backdoor-fake-identity/) | verified | high | 2026-11-05 |
| [MOVEit Transfer CVE-2024-5806：SFTP 公钥路径被当文件读取，空指纹 Denied+StatusCode0 被误判为部分成功，二次认证冒充任意用户](web-generic-auth-moveit-cve-2024-5806-sftp-key-path-empty-fingerprint/) | verified | high | 2026-11-08 |
| [MOVEit 无文件利用：guestaccess.aspx Arg12 日志注入 PPK 公钥，SSH 认证直接读取日志文件](web-generic-auth-moveit-sftp-log-poison-ppk-key-plant/) | verified | high | 2026-11-08 |
| [newbee-mall updateUserInfo 用客户端 userId 重查用户并覆盖 session：两步越权修改他人资料](web-generic-auth-newbeemall-updateuserinfo-userid-session-idor/) | verified | medium | 2026-11-05 |
| [NewBeeMall /orders/{orderNo}/finish 未校验支付与出库状态：未支付订单可直接完成交易](web-generic-auth-newbeemall-order-finish-unpaid-state-bypass/) | verified | medium | 2026-11-13 |
| [NewBeeMall /paySuccess 未校验支付真实性：仅凭 orderNo 把待支付订单改为已支付](web-generic-auth-newbeemall-paysuccess-payment-bypass/) | verified | high | 2026-11-05 |
| [NewBeeMall /personal/updateInfo 按请求体 userId 查询并更新资料：越权修改任意用户信息](web-generic-auth-newbeemall-updateinfo-userid-idor/) | verified | medium | 2026-11-05 |
| [NewBeeMall DELETE /shop-cart/{id} 未校验购物车项归属：可删除任意用户购物车条目](web-generic-auth-newbeemall-cart-delete-idor/) | verified | medium | 2026-11-05 |
| [NewBeeMall 后台拦截器用 getRequestURI 前缀判断：/;/admin/index 分号绕过进入后台](web-generic-auth-newbeemall-semicolon-admin-bypass/) | verified | high | 2026-11-05 |
| [NewBeeMall 订单详情按 orderNo 查询未校验归属：任意登录用户查看他人订单与收货信息](web-generic-auth-newbeemall-order-detail-orderno-idor/) | verified | high | 2026-11-13 |
| [nginx 1.21.1 前请求行路径解析差异：/query HTTP/1.1/../../api/ping 让前端看到 /api/ping、后端路由到 /query](web-generic-auth-nginx-request-line-path-normalization-bypass/) | verified | medium | 2026-11-12 |
| [Nginx UI /api/backup 未授权下载加密备份并在响应头泄露 AES 密钥与 IV（CVE-2026-27944）](web-generic-auth-nginx-ui-backup-unauth-key-leak/) | verified | high | 2026-11-05 |
| [Nginx 正则 deny 绕过：/secret 后插入原始 0x85/0xA0 字节，Nginx 不匹配而 Flask 规范化到 /secret](web-generic-auth-nginx-regex-deny-unicode-byte-bypass/) | verified | high | 2026-11-07 |
| [Nginx 精确 location deny 绕过：/admin/ 后插 \xA0 被 Node.js trim 后命中 /admin](web-generic-auth-nginx-exact-location-deny-trim-bypass/) | verified | high | 2026-11-08 |
| [NocoDB 默认开放注册：首个注册者获 SUPER_ADMIN，批量注册无有效限流](web-generic-auth-nocodb-open-signup-first-user-superadmin/) | verified | high | 2026-11-05 |
| [Node.js 原型链继承键登录绕过：users[用户名] 命中 Object.prototype 方法且省略密码](web-generic-auth-nodejs-prototype-chain-login-bypass/) | verified | high | 2026-11-05 |
| [NUIMS GetUser/LcpGetUser 显式 UserId 参数越权：读取任意用户资料与 bcrypt 密码哈希](web-generic-auth-nuims-getuser-userid-idor-password-hash/) | verified | high | 2026-11-09 |
| [OA DownloadFilter/ProtectFilter 路径子串白名单绕过（;common.js 与 exclude 接口）](web-generic-auth-oa-downloadfilter-protectfilter-path-substring-bypass/) | verified | high | 2026-11-05 |
| [OA skey 3DES 令牌伪造：admin|时间戳 + 配置硬编码密钥绕过 Auth/getUserName](web-generic-auth-oa-skey-3des-admin-token-forgery/) | verified | high | 2026-11-05 |
| [OASYS 后台管理控制器缺少角色校验：普通用户会话直接访问 /deptmanage 等部门管理页面（垂直越权）](web-generic-auth-oasys-admin-deptmanage-missing-role-check/) | verified | medium | 2026-11-11 |
| [Ollama 暴露 0.0.0.0:11434：无认证 API 导致模型管理、推理滥用与配置泄露](web-generic-auth-ollama-unauth-api-model-management/) | verified | high | 2026-11-05 |
| [OMI WS-Management 认证绕过：不带 Authorization 头即被当作已认证并 root 执行命令（CVE-2021-38647）](web-generic-auth-omi-wsman-missing-authorization-root-rce/) | verified | high | 2026-11-05 |
| [PHP md5 严格比较 + 数组参数类型混淆：a[]=1&b[]=2 让 null === null 成立](web-generic-auth-php-md5-array-strict-comparison-bypass/) | verified | high | 2026-11-06 |
| [PHP md5 弱比较遇错误码整数：构造 2025 前缀 MD5 绕过登录](web-generic-auth-php-md5-loose-comparison-error-code/) | verified | high | 2026-11-05 |
| [PHP Session 文件任意写入伪造会话：备份文件名可控把 admin|b:1; 写进 /tmp/sess_<id>](web-generic-auth-php-session-file-write-forge/) | verified | high | 2026-11-12 |
| [PHP 双人复核绕过：不同输入 240610708/QNKCDZO 的 MD5 同为 0e 前缀，== 判等且 !== 判不等](web-generic-auth-php-md5-magic-hash-pair-double-verify/) | verified | high | 2026-11-06 |
| [PHP 变量变量覆盖 $config 对象为数组：array_merge + $$key 绕过 isAdmin 严格比较](web-generic-auth-php-variable-variable-config-array-bypass/) | verified | high | 2026-11-06 |
| [PHP 松散比较 token 绕过：0e 数字串与库中 token 相等，/user 接口泄露全量账号与 PII](web-generic-auth-php-loose-comparison-token-0e-bypass/) | verified | high | 2026-11-05 |
| [PHP 继承链空方法覆写鉴权绕过：信呼OA ActionNot::logincheck 空实现让 login/api 接口免登录](web-generic-auth-xinhu-logincheck-empty-inheritance-bypass/) | verified | high | 2026-11-07 |
| [PHP 认证判断括号错位 + trim 空字节绕过：auth=%00 使 trim 后为空，绕过 user_pass 比对](web-generic-auth-php-trim-comparison-null-byte-bypass/) | verified | high | 2026-11-09 |
| [PowerJob 鉴权注解缺失：/user/list 未授权枚举用户与 /openApi/* 未授权触发调度任务](web-generic-auth-powerjob-missing-apipermission-unauth-endpoints/) | verified | high | 2026-11-07 |
| [PWM 配置管理器弱口令：改 LDAP URL 指向 Responder 捕获域账号明文](web-generic-auth-pwm-config-editor-ldap-url-responder/) | verified | high | 2026-11-05 |
| [Qdrant 分布式内部 6335 gRPC 认证缺陷：只读 key 或匿名可改集群拓扑](web-generic-auth-qdrant-internal-grpc-auth-bypass/) | verified | high | 2026-11-04 |
| [RAGFlow 分享 beta 泄露 uuid1 载体：枚举 time_low 推导 API key（CVE-2025-69286）](web-generic-auth-ragflow-share-beta-uuid1-api-key-derivation/) | verified | high | 2026-11-05 |
| [RequestDispatcher.forward 内部转发绕过仅 REQUEST 派发的鉴权 Filter](web-generic-auth-requestdispatcher-forward-filter-bypass/) | verified | medium | 2026-11-07 |
| [roleId/roleIds 参数篡改：从学生账号创建管理员与超级管理员](web-generic-auth-roleid-roleids-parameter-tampering-admin/) | verified | high | 2026-11-05 |
| [RSA 签名只绑定 sum(data)*len(data)：校验和碰撞复用签名执行任意脚本](web-generic-auth-rsa-signature-weak-checksum-collision-exec/) | verified | high | 2026-11-06 |
| [RustFS NodeService gRPC 硬编码管理令牌导致未授权节点管理接口调用](web-generic-auth-rustfs-grpc-hardcoded-token-bypass/) | verified | high | 2026-11-05 |
| [Sekiro(自建 WebSocket JSRPC)+Yakit 热加载 fuzzer 标签：不还原混淆算法，用浏览器原生 sign 函数批量代签](web-generic-auth-sekiro-jsrpc-yakit-hotload-rensign-batch/) | verified | high | 2026-11-08 |
| [Servlet 权限表达式在 session 角色为 null 时放行导致未登录访问业务](web-generic-auth-servlet-null-role-fail-open/) | verified | high | 2026-11-04 |
| [SessionFilter 用请求参数 userName 查缓存会话：管理员在线时可取回其 SessionNameVO 绕过鉴权](web-generic-auth-sessionfilter-username-cache-key-session-hijack/) | verified | medium | 2026-11-05 |
| [SmarterMail force-reset-password 匿名接口 IsSysAdmin 分支跳过旧密码校验：重置管理员密码进后台命令执行](web-generic-auth-smartermail-force-reset-password-anonymous-admin/) | verified | high | 2026-11-05 |
| [Spring Boot @IgnoreAuth 免鉴权 resetPass：username 参数直接重置任意用户为 123456，默认管理员接管](web-generic-auth-ignoreauth-resetpass-username-hardcoded-password/) | verified | high | 2026-11-07 |
| [Spring Boot RBAC 删除用户接口只按 userId 删除：低权用户越权删除同级/任意用户](web-generic-auth-spring-rbac-delete-user-idor/) | verified | high | 2026-11-07 |
| [Spring Security 放行 /setup/** 导致安装向导未下线：重跑安装连接自有 MySQL 初始化，覆盖管理员密码接管 OA](web-generic-auth-oa-setup-unauth-reinstall-admin-password/) | verified | high | 2026-11-12 |
| [SQL 注入取管理员 UID 后利用“仅 UID 登录”直接接管管理员](web-generic-auth-sqli-admin-uid-uid-only-login/) | verified | high | 2026-11-06 |
| [SSO 子应用绕过 SSO 自建 register 认证：仅校验手机号即签发 token 导致任意用户登录（含双层加密+sign 复刻绕过）](web-generic-auth-sso-subapp-register-mobile-identity-any-user-login/) | verified | high | 2026-11-11 |
| [stay-logged-in Cookie 可预测：base64(username:md5(password)) 构造与离线口令爆破](web-generic-auth-stay-logged-in-cookie-base64-username-md5-password/) | verified | high | 2026-11-12 |
| [Swagger 文档暴露未鉴权批量导出接口：startIndex/endIndex 控制行数，一次拉取 2000 条含身份证的 xlsx](web-generic-auth-swagger-unauth-export-xlsx-pii-dump/) | verified | high | 2026-11-08 |
| [Swagger 暴露未授权用户增删接口导致账号创建与批量删除](web-generic-auth-swagger-unauth-user-management/) | verified | high | 2026-11-05 |
| [Tmall_demo AdminPermissionFilter 用 contains 放行 /admin/login 与 /admin/account，/admin/login/../../tmall/ 穿越未授权访问后台](web-generic-auth-tmall-adminpermissionfilter-contains-login-account-bypass/) | verified | high | 2026-11-07 |
| [Token 续期拦截器信任 User-Id/User-Name 请求头：任意用户签发 admin JWT 鉴权绕过](web-generic-auth-token-renewal-trusted-user-headers-admin-jwt/) | verified | high | 2026-11-06 |
| [Vendure 跨渠道子实体 IDOR（GHSA-7qvr-c5vf-xxfh）：裸 ID 全局加载 + 父订单渠道断言缺失](web-generic-auth-vendure-cross-channel-child-entity-idor/) | verified | high | 2026-11-05 |
| [VIP 课程接口直接返回付费音频 CDN 直链：未开通会员也能下载播放](web-generic-auth-vip-course-direct-media-url-leak/) | verified | high | 2026-11-07 |
| [Vitest Browser Mode userEvent.upload 绕过 server.fs 读取宿主任意文件（CVE-2026-73653）](web-generic-auth-vitest-browser-upload-arbitrary-file-read/) | verified | high | 2026-11-05 |
| [Vitest Browser Mode 写盘/删除/artifact 外带命令绕过 allowWrite 统一闸门（CVE-2026-73653）](web-generic-auth-vitest-browser-write-delete-artifact-exfil/) | verified | medium | 2026-11-05 |
| [Vue SPA 仅在前端校验路由守卫导致隐藏管理页面暴露](web-generic-auth-vue-router-frontend-guard-bypass/) | verified | high | 2026-11-05 |
| [watchbird 控制台密码验证不在自身防 DDoS 覆盖内：可无限爆破，响应长度区分正确口令](web-generic-auth-rasp-console-login-bruteforce-rate-limit-gap/) | verified | medium | 2026-11-08 |
| [Web 根目录残留 start.sh 泄露数据库与管理后台凭据导致后台接管](web-generic-auth-start-script-credential-leak-admin-takeover/) | verified | medium | 2026-11-07 |
| [WordPress SignUp & SignIn 插件 rand() 生成 4 位激活码且无速率限制：未认证爆破接管账号（CVE-2026-12417）](web-generic-auth-wordpress-plugin-pravel-activation-code-bruteforce/) | verified | high | 2026-11-05 |
| [WordPress 插件 register_rest_route 省略 permission_callback：Brevo Sendinblue 订阅接口未授权可调（CVE-2025-66128）](web-generic-auth-wordpress-rest-route-missing-permission-callback/) | verified | high | 2026-11-05 |
| [WordPress 插件 REST 回调只查用户名与角色不验密码：任意密码冒充管理员（CVE-2026-9179）](web-generic-auth-wordpress-rest-header-password-check-missing/) | verified | high | 2026-11-05 |
| [xxl-job 3.1.1 /jobinfo/remove 普通用户越权删除任意任务](web-generic-auth-xxl-job-jobinfo-remove-idor/) | verified | high | 2026-11-05 |
| [xxl-job 3.1.1 /joblog/getJobsByGroup 普通用户越权枚举任意分组任务](web-generic-auth-xxl-job-getjobsbygroup-jobgroup-idor/) | verified | high | 2026-11-05 |
| [Yii API BaseApiController::behaviors 把 OPTIONS 与免鉴权 action 并列：OPTIONS 请求绕过 authenticator 直接执行受保护 action 返回数据](web-generic-auth-yii-baseapi-controller-options-method-auth-bypass/) | verified | high | 2026-11-11 |
| [Yii OA AuthController::actionWithub 硬编码密钥 + md5(username+key) token：伪造 token 未授权登录任意已存在用户](web-generic-auth-yii-oa-withub-hardcoded-md5-token-arbitrary-login/) | verified | high | 2026-11-11 |
| [万户OA SetCharacterEncodingFilter 三种鉴权绕过：特征路径穿越、XFF 白名单与扩展名解析](web-generic-auth-whir-ezoffice-characterencoding-filter-bypass/) | verified | high | 2026-11-07 |
| [下单接口 couponId 参数越权：使用他人新用户优惠券完成折扣下单](web-generic-auth-coupon-id-parameter-tampering-idor/) | verified | high | 2026-11-07 |
| [不可遍历 ID 的两段式越权：先用可遍历查询接口泄露 openid，再用 openid 打 myRegistration 获取 PII](web-generic-auth-idor-openid-leak-enumerable-query-chain/) | verified | high | 2026-11-07 |
| [业务接口关联对象过返 PII：createUser/verifier 字段泄露姓名、邮箱、手机号与身份证号](web-generic-auth-related-object-pii-overreturn/) | verified | medium | 2026-11-08 |
| [两步认证登录链：未授权 /password/{username} + 隐藏 user_id + X-UserId 头信任导致任意用户身份伪造](web-generic-auth-two-step-password-hidden-userid-header-trust/) | verified | high | 2026-11-05 |
| [代理历史响应长度异常定位未鉴权 user/all 接口：全站手机号与密码哈希泄露](web-generic-auth-proxy-history-unauth-user-all-leak/) | verified | medium | 2026-11-05 |
| [任意用户密码重置：重置表单 username 隐藏字段可篡改](web-generic-auth-password-reset-username-tampering/) | verified | high | 2026-11-05 |
| [信呼 OA publicsaveAjax 任意表/字段写入导致垂直与水平越权](web-generic-auth-xinhu-publicsave-arbitrary-table-write/) | verified | high | 2026-11-05 |
| [修改绑定邮箱无二次验证 → 密码重置邮件改道 → 账号接管](web-generic-auth-email-change-no-verification-password-reset-takeover/) | verified | high | 2026-11-05 |
| [先过滤后 toUpperCase：土耳其无点 ı 大写为 I，注册出 ADMIN 绕过 admin 关键词过滤](web-generic-auth-uppercase-after-filter-dotless-i-admin-bypass/) | verified | high | 2026-11-11 |
| [公链钱包 Web UI 鉴权缺陷：前端路由先渲染后校验 + 钱包 Controller 消息接口无认证，未登录可枚举/删除/创建地址](web-generic-auth-public-chain-wallet-ui-unauth-api-frontend-route-first/) | verified | high | 2026-11-12 |
| [内容站付费章节越权：64 位内容 ID 按 2^32 步进打包，预览/免费 URL 规律爆破取得付费章节全文](web-generic-auth-content-site-packed-id-2pow32-step-paywall-bypass/) | verified | medium | 2026-11-12 |
| [前后端分离登录只信 resultCode：把失败响应改成 resultCode=0 直接进入后台](web-generic-auth-login-resultcode-response-tamper-bypass/) | verified | medium | 2026-11-11 |
| [前端 AES key/iv 存 sessionStorage 刷新即失效：把 UA 改成 QQ 浏览器触发 localStorage 分支，让 JSRPC/Burp 加解密链路保持动态密钥稳定](web-generic-auth-frontend-aes-key-iv-sessionstorage-localstorage-ua-stability/) | verified | high | 2026-11-11 |
| [前端 AES-ECB 硬编码密钥 + 仅凭学号查询：毕业报告系统批量泄露学生身份证与学籍 PII](web-generic-auth-frontend-aes-ecb-hardcoded-key-student-id-pii-enumeration/) | verified | high | 2026-11-07 |
| [前端 chunk 泄露 OAuth clientId/appId：Basic btoa(clientId:appId) 换 token 后拼 userId 登录参数实现任意用户登录](web-generic-auth-oauth-basic-clientid-appid-userid-login-takeover/) | verified | high | 2026-11-08 |
| [前端 JS 泄露管理员账号 + 找回密码按用户名回显手机号：管理员 PII 与账号清单批量泄露](web-generic-auth-js-admin-username-reset-phone-echo/) | verified | medium | 2026-11-08 |
| [前端 JS 泄露隐藏接口：新注册账号调 list 拿他人记录，再用返回数据调 update/delete 越权](web-generic-auth-js-route-leak-idor-update-delete/) | verified | high | 2026-11-07 |
| [前端 MD5 签名逆向与 JSRPC+autoDecoder 运行时动态代签绕过签名校验](web-generic-auth-js-signature-jsrpc-autodecoder/) | verified | high | 2026-11-05 |
| [前端 RSA+AES 混合加密登录接口复刻：硬编码公钥下自动化口令爆破](web-generic-auth-hybrid-rsa-aes-login-bruteforce/) | verified | high | 2026-11-05 |
| [前端 x25519+AES-GCM 挑战应答登录加密复刻：execjs 加载原 JS，每轮取新 challenge 自动化口令爆破](web-generic-auth-x25519-aes-gcm-challenge-login-bruteforce/) | verified | medium | 2026-11-10 |
| [前端加密流量测试：中间人替换 JS 固定随机 AES 密钥并用 autoDecoder 解密](web-generic-auth-frontend-js-random-key-fixation-autodecoder/) | verified | high | 2026-11-05 |
| [前端接口发现 + 未授权 API 批量枚举：FindSomething 提取 JS 接口、Intruder 遍历控制器、HAE 标记身份证/手机号并分页导出全量用户 PII](web-generic-auth-js-api-discovery-unauth-pii-mass-export/) | verified | medium | 2026-11-08 |
| [前端注释泄露 OAuth 客户端凭证 + 注册接口 ownerId 直通 roleId：注册 SYSTEM 管理员并取得高权限 Token](web-generic-auth-oauth-commented-js-client-secret-register-ownerid-admin/) | verified | high | 2026-11-05 |
| [前端源码里的 mp4/pdf 直链未做鉴权：未登录直接下载付费/受限视频与文档](web-generic-auth-frontend-media-direct-url-plain-download/) | verified | high | 2026-11-08 |
| [前端硬编码编辑/发布口令：查看 JS 即绕过客户端写权限闸门](web-generic-auth-frontend-hardcoded-edit-password-gate/) | verified | medium | 2026-11-05 |
| [华夏ERP LogCostFilter 用 contains 判断 /doc.html 白名单，路径穿越与静态后缀绕过未授权](web-generic-auth-xiahuia-erp-logcostfilter-contains-path-bypass/) | verified | high | 2026-11-05 |
| [单例 Controller 共用 JSONObject 跨请求泄露：未认证接口返回已认证请求写入的 token](web-java-shared-jsonobject-cross-request-token-leak/) | verified | medium | 2026-11-13 |
| [单图上传式人脸活体绕过：证件照替换背景后 Base64 提交通过 1:1 认证](web-generic-auth-face-liveness-background-replace-base64/) | verified | medium | 2026-11-05 |
| [同一资源接口不同 HTTP 方法鉴权不一致：未授权 DELETE/PUT 下架/上线资源](web-generic-auth-resource-api-method-authorization-inconsistency/) | verified | medium | 2026-11-07 |
| [同厂商通用系统固定 KEYDATA 登录令牌跨实例复用：专家入口抓包得到 key 即可登录其它部署](web-generic-auth-vendor-fixed-keydata-token-cross-instance-login/) | verified | medium | 2026-11-08 |
| [响应包 JS 客户端鉴权可篡改：延长 getUserInfo 定时器绕过登出进入后台](web-generic-auth-response-js-client-check-tamper/) | verified | medium | 2026-11-07 |
| [图形验证码 OCR + 用户名枚举：ddddocr 与 Burp captcha-killer 爆破管理员口令](web-generic-auth-captcha-ocr-username-enum-bruteforce/) | verified | high | 2026-11-05 |
| [图形验证码由前端本地生成、其值参与 key=MD5(硬编码salt+ts+手机号+验证码) 签名：提取 salt 后离线伪造任意验证码通过校验](web-generic-auth-client-generated-captcha-md5-key-signature-forge/) | verified | high | 2026-11-10 |
| [图形验证码答案在发送验证码响应中明文回显：验证码形同虚设](web-generic-auth-image-captcha-answer-response-echo/) | verified | high | 2026-11-08 |
| [在线教育平台笔记/评论删除接口只凭全站自增 id：不校验资源归属，改 id 即可水平越权删除他人内容并遍历清空](web-generic-auth-education-note-comment-delete-idor-global-id/) | verified | high | 2026-11-11 |
| [培训平台 courseId 遍历：低权账号枚举课程并获取课件下载地址](web-generic-auth-course-id-enumeration-courseware-url/) | verified | medium | 2026-11-05 |
| [堡垒机登录前端 3DES-CBC 加密逆向与滑块参数伪造](web-generic-auth-bastion-frontend-3des-login-forgery/) | verified | high | 2026-11-05 |
| [多会话权限矩阵与 LeakScore 四维评分自动化越权检测](web-generic-auth-multi-session-matrix-leakscore/) | verified | medium | 2026-11-04 |
| [多步数字锁前端校验绕过：调用暴露的 validateCode() 取答案并直接提交 step3](web-generic-auth-digital-lock-client-validate-step-skip/) | verified | medium | 2026-11-07 |
| [多租户头缺失被当作超管：删 X-Access-Token 绕过 tenant_id 隔离跨租户越权](web-generic-auth-multitenant-tenant-header-missing-superadmin/) | verified | high | 2026-11-05 |
| [多租户系统 Cookie 单位编号/队伍编号未绑定会话：遍历 dw_id/yh_dm 跨校越权并修改密码](web-generic-auth-cookie-tenant-unit-idor-password-change/) | verified | high | 2026-11-08 |
| [多身份系统的「选择身份」步骤把身份主键 id 放在前端参数里，改这个 id 即以任意用户（含管理员）身份进入系统](web-generic-auth-identity-selection-id-idor-any-user-login/) | verified | medium | 2026-11-08 |
| [学生 Token 调用教师课程名单接口：lesson_id 自增遍历批量泄露学籍](web-generic-auth-teacher-roster-api-student-token-lesson-enumeration/) | verified | high | 2026-11-05 |
| [客户端 nonce + 无密钥 SHA1 签名可复现，绕过防重放伪造请求](web-generic-auth-client-nonce-weak-sha1-signature-forgery/) | verified | high | 2026-11-05 |
| [密保问题弱设计：学号/幸运数字可猜且无尝试限制，重置任意账号](web-generic-auth-weak-security-question-reset/) | verified | high | 2026-11-05 |
| [密码参数传 JSON 数组绕过登录频次限制：一次请求校验多个候选口令](web-generic-auth-password-array-bypass-rate-limit/) | verified | high | 2026-11-12 |
| [密码找回 codesign/id 可预测且未绑定用户：用注册接口获取任意数值的站点加密值，重置任意账号密码](web-generic-auth-password-reset-codesign-id-predictable-encryption-oracle/) | verified | high | 2026-11-11 |
| [密码找回多步流程把进度放在客户端：把请求里的 step 直接改成最后一步（如 4）跳过短信/邮箱校验，并篡改 USERNAME_COOKIE（可能 base64）指到受害者，即可改他人密码](web-generic-auth-password-reset-step-param-final-skip-username-cookie/) | verified | low | 2026-11-09 |
| [密码重置 token 经 Set-Cookie 回显 + 客户端 user_token 参数受信：任意用户改密接管](web-generic-auth-reset-token-setcookie-leak-user-token-param/) | verified | high | 2026-11-08 |
| [密码重置只比较 hash 低 12 位：枚举 4096 个旧密码后三字节接管 admin](web-generic-auth-password-reset-hash-low12-bruteforce/) | verified | high | 2026-11-06 |
| [密码重置链接 Host 头注入：X-Forwarded-Host 窃取重置 token](web-generic-auth-password-reset-host-header-poisoning/) | verified | high | 2026-11-05 |
| [密码重置链接的 token 是「Unix 时间戳的 MD5」：发信后按秒级时间窗枚举 token，即可为任意账号构造出可用的重置链接](web-generic-auth-password-reset-token-unix-timestamp-md5-bruteforce/) | verified | medium | 2026-11-09 |
| [密码重置：篡改验证码响应 + 复用发码请求中的 sid 重置管理员密码](web-generic-auth-password-reset-response-tamper-sid-reuse/) | verified | high | 2026-11-07 |
| [小智 ESP32 管理平台：/api/user/update 被白名单放行且不校验旧密码，未授权重置任意账号密码](web-generic-auth-xiaozhi-unauth-user-update-password-reset/) | verified | high | 2026-11-05 |
| [小智 ESP32 管理平台：Cookie username 直接查询用户并建会话导致任意账号登录](web-generic-auth-xiaozhi-cookie-username-impersonation/) | verified | high | 2026-11-05 |
| [小智 ESP32 管理平台：拦截器 PUBLIC_PATHS 前缀 /api/user/ 放行导致用户信息未授权泄露](web-generic-auth-xiaozhi-public-paths-user-prefix-unauth-data-exposure/) | verified | high | 2026-11-05 |
| [小程序 digest 头 = MD5("/路径段/URL+毫秒时间戳") 无密钥：任意 token 下伪造请求遍历用户信息](web-generic-auth-miniprogram-digest-md5-path-timestamp/) | verified | high | 2026-11-07 |
| [小程序/公众号前端源码泄露 AppID+AppSecret：换 client_credential 接口的 access_token 接管官方接口权限](web-generic-auth-wechat-appid-appsecret-frontend-leak-access-token/) | verified | medium | 2026-11-09 |
| [小程序本地加密配置 + 固定 AES 密钥：恢复 appKey 后伪造 HMAC 请求签名](web-generic-auth-miniprogram-local-config-signature-forgery/) | verified | high | 2026-11-05 |
| [小程序票据查询隐藏枚举值：前端仅三种证件类型，payerIdType=4 用学号查身份证](web-generic-auth-miniprogram-bill-hidden-payeridtype-pii/) | verified | high | 2026-11-05 |
| [小程序签名 = MD5(逐字符排序(AppId+AppSecret+Ticks+Nonce+参数串))：硬编码密钥复刻后任意改参重签](web-generic-auth-miniprogram-md5-charsort-sign-forgery/) | verified | medium | 2026-11-07 |
| [小程序邀请注册请求可重放：sign+timestamp 只防篡改不防重放，重复领取 7 天 VIP](web-generic-auth-miniprogram-signed-request-replay-vip-reward/) | verified | high | 2026-11-07 |
| [小程序预约单查询：修改日期区间与 queryType 越权拉取全量用户预约与手机号](web-generic-auth-miniprogram-appointment-daterange-querytype-pii/) | verified | medium | 2026-11-05 |
| [就诊人信息接口按 patMiCode 顺序枚举：三要素明文越权泄露](web-generic-auth-patient-infocode-idor-pii-enumeration/) | verified | high | 2026-11-05 |
| [嵌套参数排序序列化 + md5(base) 二次哈希的 sign 复现](web-generic-auth-nested-md5-sign-reverse-forgery/) | verified | high | 2026-11-05 |
| [带验证码登录口：OCR 识别验证码枚举账号并用用户名=口令批量登录](web-generic-auth-captcha-ocr-username-enumeration-same-password/) | verified | medium | 2026-11-05 |
| [帮助文档泄露账号格式与默认口令：CAS 登录 base64 密码 Pitchfork 爆破绕过前端锁定](web-generic-auth-default-password-account-format-cas-bruteforce/) | verified | high | 2026-11-07 |
| [开发调试接口 /dev/Reset 未授权重置管理员密码为 admin/admin](web-generic-auth-dev-reset-admin-password-default/) | verified | high | 2026-11-05 |
| [开放签 sys/user/getAllUsers 与 userInfo 缺权限注解：任意登录用户越权枚举/查看用户信息](web-generic-auth-kaifangqian-user-controller-missing-permission/) | verified | high | 2026-11-07 |
| [微信小程序手机号登录：SessionKey 泄露 + encryptedData 重加密导致任意手机号账号接管](web-generic-auth-wechat-miniprogram-sessionkey-encrypteddata-takeover/) | verified | medium | 2026-11-05 |
| [微信小程序硬编码 Hawk 凭据：伪造 Authorization 头枚举用户信息](web-generic-auth-miniprogram-hardcoded-hawk-authorization-forgery/) | verified | medium | 2026-11-05 |
| [微信绑定 getBingUrl?id 不校验归属：换目标教师 ID 取绑定二维码，扫码接管他人账号](web-generic-auth-wechat-bind-url-idor-account-takeover/) | verified | high | 2026-11-07 |
| [忘记密码回显枚举有效手机号，再按「锁定阈值内 + 高频口令优先」的策略撞库，5 次锁定之前命中弱口令](web-generic-auth-forgot-password-enum-lockout-aware-weakpass-brute/) | verified | medium | 2026-11-08 |
| [忘记密码手机号未绑定校验缺失：用攻击者手机号接收验证码重置任意账号](web-generic-auth-password-reset-unbound-phone-any-phone/) | verified | medium | 2026-11-05 |
| [忘记密码的 6 位 OTP 由「当前分钟数」确定性推导：本地复刻同一算法规避 104 校验，重置任意已存在用户口令（CVE-2024-9554）](web-generic-auth-otp-derived-from-current-minute-deterministic-reset/) | verified | medium | 2026-11-08 |
| [找回密码「验证方式不可用」可零验证重置密保问题，流程直接跳到改密步骤重置任意账号密码](web-generic-auth-password-reset-auth-method-unavailable-reset-question-bypass/) | verified | high | 2026-11-11 |
| [招聘平台简历页面脱敏但下载文件含完整 PII：企业账号批量获取学生手机号与身份信息](web-generic-auth-resume-download-unmasked-pii-leak/) | verified | high | 2026-11-07 |
| [拦截器只在 AJAX 请求时校验登录：省略 X-Requested-With 头即绕过认证（flink-streaming-platform-web 添加用户）](web-generic-auth-ajax-header-only-interceptor-bypass/) | verified | high | 2026-11-10 |
| [拦截器只验登录不验角色：学生会话重放教师接口实现垂直越权](web-generic-auth-missing-function-level-role-check/) | verified | high | 2026-11-05 |
| [拦截器用 startsWith 放行 /admin/login，/admin/login/../ 跳出到后台删除接口](web-generic-auth-interceptor-login-prefix-dotdot-bypass/) | verified | high | 2026-11-05 |
| [挑战码+双重 MD5 登录加密的 JSRPC 爆破：Sekiro action 内先取 captcha 再算 hex_md5(captcha+hex_md5(pwd))，Yakit 双请求序列提取密文批量登录](web-generic-auth-captcha-double-md5-jsrpc-yakit-login-bruteforce/) | verified | high | 2026-11-10 |
| [接口粒度权限校验不一致：替换路径段 queryById 为 list 绕过鉴权批量拉取 PII](web-generic-auth-endpoint-granularity-unauth-list-bulk-pii/) | verified | high | 2026-11-08 |
| [控制数据库后登录后台：从 Spring datasource 配置取凭据、按已知哈希格式改写 admin 密码，并改 config 表关闭 Google 2FA 后恢复原值](web-generic-auth-database-admin-password-hash-reset-2fa-disable/) | verified | high | 2026-11-11 |
| [教学 API getTeachers 按姓名返回教师完整资料：任意登录用户可枚举手机号/openid，删参数取全量](web-generic-auth-getteachers-teacher-phone-openid-enumeration/) | verified | medium | 2026-11-08 |
| [教学系统多入口路径拼接越权：专家通道会话访问账号管理，添加管理员并重置 admin 密码](web-generic-auth-edu-expert-channel-path-concat-admin-takeover/) | verified | medium | 2026-11-07 |
| [教育系统动态表单字段 ID 越权：篡改 field7186/triFieldid_181 遍历 10 万+ 学生身份证与学号](web-generic-auth-form-field-id-idor-pii-enumeration/) | verified | high | 2026-11-06 |
| [新翔OA checklogin 仅判断五个 Cookie 存在且非空：伪造 id/loginname/jueseid/danweiid/quanxian=1 直接进入后台](web-generic-auth-xinxiang-oa-cookie-existence-login-bypass/) | verified | high | 2026-11-11 |
| [无签名 Cookie 作为身份凭证导致后台登录伪造（admin_keys=2）](web-generic-auth-unsigned-cookie-admin-keys/) | verified | high | 2026-11-05 |
| [无认证 IDOR 三端点链：账号存在性枚举 → 代理商联系方式 → 游戏角色画像](web-generic-auth-unauth-idor-account-agent-contact-role-chain/) | verified | high | 2026-11-05 |
| [智慧云教育平台 /student/exam 考试记录查询：DTO 的 studentId 由客户端传入且未与会话绑定](web-generic-auth-education-exam-studentid-dto-idor/) | verified | medium | 2026-11-07 |
| [服务端下发密钥/代签接口不等于安全：前端加密登录的密钥、签名与防重放均可复现](web-generic-auth-server-key-sign-oracle-replay-reproducible/) | verified | high | 2026-11-07 |
| [服务端信任 X-Forwarded-For 做 IP 白名单校验时伪造请求头绕过登录限制](web-generic-auth-xforwarded-for-ip-whitelist-bypass/) | verified | high | 2026-11-08 |
| [服务端信任客户端可离线复算的请求签名与硬编码 JWT，可伪造管理员特权 API 请求](web-generic-auth-client-recomputable-signature-forge/) | verified | medium | 2026-11-08 |
| [未授权 GET create 接口：报错“项目名称不能为空”暴露必填字段，补 name 参数即创建业务对象](web-generic-auth-unauth-get-create-endpoint-error-param/) | verified | high | 2026-11-08 |
| [未授权 getTokenById 接口按 userId 签发 token 导致管理员账户接管](web-generic-auth-gettokenbyid-userid-token-issuance/) | verified | high | 2026-11-05 |
| [未授权 type 分发 Servlet 按参数返回全量用户表与明文口令](web-generic-auth-type-dispatch-unauth-data-exposure/) | verified | high | 2026-11-04 |
| [未授权业务接口预置 session 鉴权属性：先访问 /index2 写入 user，再访问只判属性非空的 /index1 即放行](web-generic-auth-session-attribute-prefill-public-endpoint-bypass/) | verified | high | 2026-11-13 |
| [未授权字典批量接口 + dm 全集拼接：一次拉取所有字典创建者身份证](web-generic-auth-unauth-dict-batch-dms-admin-idcard-leak/) | verified | high | 2026-11-09 |
| [未授权岗位员工接口 + 账号 IDOR：遍历岗位/账号 ID 泄露 Acc_Pw 与鉴权 CheckUID](web-generic-auth-unauth-position-employee-api-checkuid-leak/) | verified | high | 2026-11-07 |
| [未授权用户创建接口导致创建账号并登录后台](web-generic-auth-unauth-user-create-admin-takeover/) | verified | high | 2026-11-05 |
| [模块入口的「无权限」只由响应里的状态码决定：把返回包 code 从 1 改成 0 即渲染出受限页面](web-generic-auth-module-permission-code-response-tamper/) | verified | medium | 2026-11-08 |
| [汉王e脸通 globalToken/recoToken 可逆加密伪造：仅校验分段格式与时间戳即可获得 admin 会话](web-generic-auth-hanvon-eface-globaltoken-recotoken-forgery/) | verified | high | 2026-11-07 |
| [汉王e脸通 Spring 拦截器白名单 contains + `..;/` 路径归一化绕过：未登录访问后台接口](web-generic-auth-hanvon-eface-whitelist-contains-semicolon-path-bypass/) | verified | high | 2026-11-07 |
| [泛微 e-cology 10 前台认证绕过：appThirdLogin 任意用户名无密码创建 TGT + generateEteamsId 换取会话](web-generic-auth-weaver-ecology10-appthirdlogin-eteamsid-bypass/) | verified | medium | 2026-11-07 |
| [泛微 e-cology 前台登录绕过：DWR 读取 security.key + AES 伪造 mToken + ImgFileDownload 换取 ecology_JSessionid](web-generic-auth-weaver-ecology-mobilemode-token-chain-login-bypass/) | verified | high | 2026-11-07 |
| [泛微 e9 鉴权与参数过滤绕过：路径含 login 即判已登录，xssList 正则点号通配跳过 HTMLFilter](web-generic-auth-weaver-e9-islogin-xsslist-regex-bypass/) | verified | high | 2026-11-05 |
| [泛微 EC9 VerifyGDLogin.jsp 用已知/默认 AES 密钥加密用户 ID 直接登录：加密 para2 即得 sysadmin 会话](web-generic-auth-weaver-ecology9-verifygdlogin-aes-userid-any-login/) | verified | high | 2026-11-13 |
| [注册密钥由 HTTP_HOST + 硬编码盐的 MD5 派生：拿到源码即可算出 allkey 绕过邀请注册](web-generic-auth-registration-key-host-md5-hardcoded-salt/) | verified | high | 2026-11-10 |
| [滑块验证码前端加密协议逆向：ECDH 三密钥 + HKDF + AES-GCM 复刻与批量注册绕过](web-generic-auth-slider-captcha-ecdh-aes-gcm-protocol-bypass/) | verified | high | 2026-11-05 |
| [用友 NC65 PortalLoginFilter 鉴权绕过：pageId 魔法值与 ESCAPE_URL 子串匹配](web-generic-auth-yonyou-nc65-portalloginfilter-bypass/) | verified | high | 2026-11-05 |
| [用户信息接口数字 ID 被汉字逐位替代（U+4E10–U+4E19 对应 0–9）：URL 解码还原后遍历越权批量读取用户信息](web-generic-auth-idor-chinese-codepoint-digit-id-enumeration/) | verified | medium | 2026-11-11 |
| [用户信息接口既无鉴权又回明文口令：遍历 id/拼接用户即可批量拉取全站账号、密码与手机号](web-generic-auth-user-api-plaintext-password-phone-enumeration/) | verified | low | 2026-11-08 |
| [用户删除后 Redis 缓存的 JWT 未撤销：已删除账号仍可登录查询交易数据](web-generic-auth-deleted-user-cached-jwt-still-login/) | verified | medium | 2026-11-07 |
| [用户名枚举侧信道：响应时间差异与账号锁定 oracle](web-generic-auth-username-enumeration-timing-lockout/) | verified | medium | 2026-11-05 |
| [用户详情接口以 JWT sub 为主键且不校验归属：改 sub 遍历批量拉取用户 PII（手机号/邮箱/生日）](web-generic-auth-jwt-sub-user-info-idor-enumeration/) | verified | high | 2026-11-12 |
| [登录后 2FA 仅前端跳转：直接访问受保护路由绕过二次验证](web-generic-auth-2fa-first-factor-direct-dashboard-bypass/) | verified | high | 2026-11-07 |
| [登录后改密接口越权：username 可控导致修改他人密码](web-generic-auth-authenticated-change-password-idor/) | verified | high | 2026-11-05 |
| [登录拦截器凭证为空直接放行 + SecurityConfig 路由未覆盖：匿名遍历 userId 获取全站用户资料](web-generic-auth-null-ticket-skip-interceptor-userid-enumeration/) | verified | high | 2026-11-08 |
| [登录接口只校验手机号存在、不校验密码：任意字符串登录任意已知账号](web-generic-auth-login-phone-any-password/) | verified | medium | 2026-11-05 |
| [登录校验同时要求 upper()==大写 且 lower()!=小写：用 Unicode 长 s「ſ」让两个条件同时成立](web-generic-auth-unicode-casefold-login-upper-lower-conflict/) | verified | high | 2026-11-09 |
| [登录爆破的响应判读与 Payload 变换：过滤差异、Base64/MD5/前缀与动态时间戳](web-generic-auth-login-bruteforce-response-payload/) | verified | high | 2026-11-05 |
| [登录用户按 uid 重置任意用户密码（硬编码默认口令）](web-generic-auth-uid-resetpwd-hardcoded-default-password/) | verified | high | 2026-11-05 |
| [登录请求 username 参数替换为 expert：保留原验证码直接以专家角色进入后台](web-generic-auth-login-username-swap-expert-role-bypass/) | verified | low | 2026-11-08 |
| [登录重定向接口按 username 签发会话：改 username=admin 获取管理员 Session](web-generic-auth-redirect-username-session-issuance/) | verified | high | 2026-11-06 |
| [登录错误文案差异导致用户名枚举（不存在该用户 vs 用户名或密码错误）](web-generic-auth-error-message-username-enumeration/) | verified | high | 2026-11-05 |
| [登录限速/封禁绕过：丢弃会话 Cookie 与伪造 X-Forwarded-For](web-generic-auth-login-rate-limit-bypass-cookie-xff/) | verified | high | 2026-11-05 |
| [登录页预填管理员口令：把 password 输入框改成 text 或读 value 直接取明文](web-generic-auth-login-page-prefilled-password-type-unmask/) | verified | medium | 2026-11-08 |
| [短信接口用 type 参数决定是否校验图形验证码：改 type=0 并删除 validCode 直接发短信](web-generic-auth-sms-captcha-type-param-validcode-removal-bypass/) | verified | high | 2026-11-08 |
| [短信接口频率限制绕过：手机号双写、参数重复、编码、重放与 XFF](web-generic-auth-sms-bombing-rate-limit-bypass/) | verified | high | 2026-11-06 |
| [短信登录校验用 md5(手机号+6位验证码) 且响应回显哈希：离线爆破 100 万空间任意用户登录](web-generic-auth-sms-code-md5-hash-response-offline-bruteforce/) | verified | high | 2026-11-07 |
| [短信登录验证码未绑定手机号：替换/双写 phone 参数复用自己的验证码登录任意账号](web-generic-auth-sms-login-code-not-bound-phone-parameter-tamper/) | verified | medium | 2026-11-07 |
| [短信验证码在响应包/跳转 URL 中回显：任意手机号直接登录](web-generic-auth-sms-code-echo-response-arbitrary-login/) | verified | high | 2026-11-05 |
| [短信验证码多号码同发同码：逆向 sign 后自动化请求导致任意用户登录](web-generic-auth-sms-code-multi-number-shared-arbitrary-login/) | verified | medium | 2026-11-05 |
| [短信验证码字段置空绕过校验：注册/登录同接口按手机号签发 token，任意用户注册与接管](web-generic-auth-sms-code-empty-field-arbitrary-register-login/) | verified | high | 2026-11-07 |
| [短信验证码接口 applicantChange 参数组合绕过存在性校验：任意手机号注册并登录电子签章后台](web-generic-auth-applicantchange-pin-sms-bypass-registration/) | verified | high | 2026-11-05 |
| [短信验证码生成阶段可预测：连续递增、重启复用与种子取手机号](web-generic-auth-sms-otp-generation-predictable-sequence-restart-seed/) | verified | high | 2026-11-07 |
| [短信验证码登录 4 位码无失败次数限制：爆破验证码登录任意手机号账户](web-generic-auth-sms-login-4digit-code-bruteforce-account-takeover/) | verified | medium | 2026-11-08 |
| [硬编码 BIP 对接凭据 + orgId 未授权泄露导致任意建号登录](web-generic-auth-hardcoded-bip-cred-orgid-user-create/) | verified | high | 2026-11-05 |
| [禅道 15.x 前台：tutorial-wizard 跳板调 user-todo，t=json 泄露管理员 md5 哈希并直接登录](web-generic-auth-zentao-15x-wizard-todo-json-md5-login/) | verified | high | 2026-11-13 |
| [禅道 16.0–17.4 programPriv waterfall 白名单越权：伪造会话即可无权限操作 project/bug/doc/repo 全部模块](web-generic-auth-zentao-programpriv-waterfall-modules-bypass/) | verified | high | 2026-11-13 |
| [禅道 17.0–17.4 EndResponseException 被捕获后继续执行：deny 不退出导致鉴权失效、未授权模块照常运行](web-generic-auth-zentao-endresponse-exception-deny-continue/) | verified | high | 2026-11-13 |
| [禅道 file::delete 缺少 checkPriv 对象权限校验：改 fileID 删除他人评论附件](web-generic-auth-zentao-file-delete-idor/) | verified | high | 2026-11-05 |
| [禅道 QVD-2024-15263 认证绕过：testcase deny 写入 session user，加 HTTP_X_REQUESTED_WITH 参数通过 API 鉴权并创建管理员](web-generic-auth-zentao-qvd-2024-15263-testcase-deny-session-user-bypass/) | verified | high | 2026-11-09 |
| [移动端 person/permission 接口按 userId 越权查询：遍历泄露师生 PII 与人脸信息](web-generic-auth-mobile-person-permission-userid-idor-pii/) | verified | high | 2026-11-05 |
| [移动端人脸照片更新接口按请求体 id 越权：替换他人生物特征照片](web-generic-auth-face-photo-update-body-id-idor/) | verified | high | 2026-11-05 |
| [移动端接口参数枚举 + 身份证 PII 越权查询：从参数缺失报错到手机号遍历](web-generic-auth-api-param-fuzz-idcard-pii-enumeration/) | verified | medium | 2026-11-06 |
| [移动端登录接口复用令牌续期：任意 Userid + 任意 Token 绑定接管账户](web-generic-auth-login-header-userid-token-binding-takeover/) | verified | high | 2026-11-05 |
| [组织缩写 + 123456 默认管理员口令：用学校/企业名称生成字典猜解后台](web-generic-auth-org-abbreviation-default-password-guess/) | verified | medium | 2026-11-05 |
| [统一异常处理掩盖的未授权用户信息接口泄露 default_password：默认密码直接登录管理员后台](web-generic-auth-unauth-userinfo-default-password/) | verified | medium | 2026-11-09 |
| [统一身份认证忘记密码：篡改响应包 success/statusCode 绕过短信验证码重置管理员密码](web-generic-auth-password-reset-response-tampering-sms-bypass/) | verified | high | 2026-11-05 |
| [聊天用户信息接口按 imId 越权：遍历获取服务者真实手机号与 userId](web-generic-auth-imid-userinfo-mobile-pii-enumeration/) | verified | high | 2026-11-07 |
| [订单评价接口按 orderId 越权：只校验服务状态不校验订单归属，可评价他人订单](web-generic-auth-order-comment-idor-missing-ownership/) | verified | high | 2026-11-07 |
| [认证日志接口泄露合法 userId 后枚举用户详情：绕过按 ID 归属的访问限制](web-generic-auth-authlog-userid-enumeration-authz-bypass/) | verified | high | 2026-11-05 |
| [读取 PHP session 文件劫持管理员会话：枚举会话目录 sess_* 文件，把会话 ID 填入 PHPSESSID/SECUREPHPSESSID 直接登录后台](web-generic-auth-php-session-file-read-hijack-admin/) | verified | high | 2026-11-13 |
| [课程详情/评论接口只凭 ID 返回内容：未校验报名与教师审批状态导致未授权访问与评论](web-generic-auth-course-task-object-state-missing-authz/) | verified | high | 2026-11-05 |
| [调试配置泄露管理员凭据 + 隐藏条目状态越权发布：/debug/config.json 到 review-flow/transition](web-generic-auth-debug-config-credential-leak-hidden-resource-transition/) | verified | high | 2026-11-06 |
| [越权探测中的查询条件失效：参数制空、通配符 %/* 与类型混淆导致全量返回](web-generic-auth-idor-empty-wildcard-type-query-collapse/) | verified | medium | 2026-11-07 |
| [转账接口信任客户端 fromAccountId：水平越权扣划任意账户余额购买高价商品](web-generic-auth-transfer-fromaccount-idor-balance-theft/) | verified | medium | 2026-11-07 |
| [迎新报名系统通知书/缴费票据仅凭 xsid 顺序号查询：未登录即遍历他人身份证与缴费信息](web-generic-auth-edu-registration-notice-xsid-idor-enumeration/) | verified | high | 2026-11-08 |
| [迎新系统重置密码固定为身份证后 6 位：学号与身份证可由公开名单和社工补全](web-generic-auth-freshman-reset-id-last6-public-pii/) | verified | high | 2026-11-05 |
| [逐字符比较 + 匹配即 sleep 的密码校验：响应时延侧信道逐位恢复密码](web-generic-auth-per-char-sleep-timing-password-oracle/) | verified | medium | 2026-11-07 |
| [通天星 CMSV6 /xz_center/list 未授权分页查询：sessionUserId 为空时跳过 create_id 归属过滤，返回全量 XzCenter 记录](web-generic-auth-cmsv6-xzcenter-list-unauth/) | verified | medium | 2026-11-08 |
| [通天星 CMSV6 StandardLoginAction_getAllUser 未授权账号枚举：json=null 直接返回全部用户](web-generic-auth-cmsv6-standardlogin-getalluser-unauth/) | verified | low | 2026-11-08 |
| [重复/遗留控制器接口越权：单数 addRole 受限、复数 addRoles 可直接授予超管角色](web-generic-auth-duplicate-controller-addroles-vertical-escalation/) | verified | high | 2026-11-09 |
| [鉴权 Filter 判断 getServletPath() 含 "/login.action" 且放行 `*.upload`：/login.action.upload 绕过鉴权进受保护上传 Servlet](web-generic-auth-servletpath-contains-login-action-star-upload-bypass/) | verified | high | 2026-11-08 |
| [隐藏接口只比对某个请求头的字面值：把 UA 或 X-Requested-With 改成目标期望的字符串即可越过 403](web-generic-auth-header-value-equality-sole-access-gate/) | verified | high | 2026-11-08 |
| [页面脱敏≠接口脱敏：订单查询页手机号打码，但刷新抓 common 接口响应可读到原始号码](web-generic-auth-order-query-common-api-unmasked-phone/) | verified | medium | 2026-11-13 |
| [验证码只在请求生成接口时刷新：一次获取后复用同一 Session 验证码爆破口令](web-generic-auth-captcha-client-refresh-session-reuse/) | verified | medium | 2026-11-07 |
| [验证码可绕过：字符集/尺寸由请求参数控制、万能码 8888/0000、不销毁重用与图片地址暴露](web-generic-auth-captcha-parameter-controlled-universal-code/) | verified | medium | 2026-11-13 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
