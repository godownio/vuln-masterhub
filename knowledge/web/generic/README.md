# 通用 Web 漏洞

## 这层是什么

与语言无关的 Web 漏洞类型与利用技巧。

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

- [SQL 注入](sqli/README.md) —— 注入类型、绕过、堆叠与二次注入。
- [XSS](xss/README.md) —— 反射/存储/DOM XSS、绕过与利用。
- [点击劫持](clickjacking/README.md) —— 透明 iframe 覆盖、UI Redress 与框架嵌入防御。
- [CSRF](csrf/README.md) —— CSRF 与 SameSite、Token 绕过。
- [SSRF](ssrf/README.md) —— SSRF、云元数据、协议利用与绕过。
- [XXE](xxe/README.md) —— XML 外部实体、盲 XXE、OOB 与绕过。
- [XPath 注入](xpath/README.md) —— XPath 拼接注入、认证绕过、节点遍历与盲注提取。
- [通用模板注入](ssti/README.md) —— 模板引擎识别、探测与利用。
- [文件上传](file-upload/README.md) —— 上传绕过、解析漏洞、竞争与二次利用。
- [通用文件包含](file-inclusion/README.md) —— 本地/远程包含、伪协议与日志包含。
- [JWT](jwt/README.md) —— 算法混淆、密钥爆破、kid/jku 注入。
- [OAuth](oauth/README.md) —— OAuth/OIDC 流程缺陷、redirect_uri 与 token 泄露。
- [HTTP 请求走私](http-smuggling/README.md) —— CL/TE、TE/TE、HTTP/2 降级与利用。
- [Web 缓存投毒](cache-poisoning/README.md) —— 缓存键、缓存欺骗与投毒链。
- [竞争条件](race-condition/README.md) —— 并发竞态、TOCTOU、限次绕过。
- [GraphQL](graphql/README.md) —— introspection、批量查询、注入与授权缺陷。
- [WebSocket](websocket/README.md) —— 跨站 WebSocket 劫持、认证与消息注入。
- [开放重定向](open-redirect/README.md) —— 重定向绕过与 OAuth/SSO 组合利用。
- [CRLF 注入](crlf/README.md) —— 响应头注入、日志注入与缓存组合。
- [CORS](cors/README.md) —— 跨域配置错误与凭证泄露。
- [认证与会话](auth/README.md) —— Cookie/Session、身份伪造、认证绕过、会话固定与权限校验缺陷。

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [CFITSIO EFS outfile 在格式校验前复制任意文件到任意可写路径](web-generic-cfitsio-efs-outfile-arbitrary-file-copy.md) | verified | high | 2026-11-05 |
| [CFITSIO EFS root:// 输出驱动配合 Raw Data 子句外传本地文件](web-generic-cfitsio-efs-root-driver-local-file-exfiltration.md) | verified | high | 2026-11-05 |
| [CGI 目录暴露 ld-linux：把动态加载器当 CGI 执行，argv 指定任意程序与脚本](web-generic-cgi-ld-linux-interpreter-argv-arbitrary-program-execution.md) | verified | high | 2026-11-06 |
| [CouchDB CVE-2017-12635 + CVE-2017-12636：重复键建管理员后 query_servers 命令执行](web-generic-rce-couchdb-cve-2017-12635-12636.md) | verified | medium | 2026-11-05 |
| [Host 校验绕过：端口注入、后缀匹配、重复头、绝对 URL 与覆盖头](web-generic-host-header-validation-bypass-ambiguity.md) | verified | high | 2026-11-05 |
| [Wasm 导出函数未校验数组下标导致线性内存内越界写与相邻数据篡改](web-generic-wasm-unchecked-index-linear-memory-write.md) | verified | medium | 2026-11-05 |
| [Wasm 导出线性内存中的密钥与敏感常量可被同源 JS 读取](web-generic-wasm-exported-memory-secret-read.md) | verified | high | 2026-11-05 |
| [双设备支付页滞留 + 取消订单返还优惠券：同一张券支付两笔订单](web-generic-payment-coupon-cancel-pending-order-reuse.md) | verified | medium | 2026-11-07 |
| [客户端提交赛跑距离参数篡改：服务端信任模拟输入直接发放 flag](web-generic-client-side-race-distance-tamper.md) | verified | high | 2026-11-06 |
| [导出 Excel/CSV 未转义昵称导致公式注入与客户端 RCE](web-generic-csv-formula-injection-export-rce.md) | verified | medium | 2026-11-05 |
| [废弃第三方 JS 域名抢注投毒：bshare 分享插件夜间移动端强制跳转](web-generic-third-party-js-domain-takeover-night-redirect.md) | verified | medium | 2026-11-07 |
| [打字测速服务只校验内容与 seed、信任客户端时间戳：抓取合法提交压缩时间间隔伪造 650 WPM](web-generic-client-timestamp-replay-typing-speed-bypass.md) | verified | high | 2026-11-07 |
| [支付金额四舍五入差异：提交 0.019 元实付 0.01、服务端按 0.02 入账](web-generic-payment-rounding-differential-recharge.md) | verified | high | 2026-11-05 |
| [支付金额篡改：支付接口信任客户端 totalAmount 且未绑定已创建订单](web-generic-payment-amount-tamper-no-order-binding.md) | verified | high | 2026-11-05 |
| [注销-重注册循环复用新人权益：物理删除用户数据导致营销风控历史丢失](web-generic-account-deletion-new-user-benefit-reuse.md) | verified | medium | 2026-11-06 |
| [游戏/积分接口信任客户端上报分数：直接调用接口伪造满分领取奖励](web-generic-client-side-score-trust.md) | verified | high | 2026-11-05 |
| [购物车接受负数量：负数商品抵消高价商品金额实现低价购买](web-generic-payment-negative-quantity-offset.md) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
