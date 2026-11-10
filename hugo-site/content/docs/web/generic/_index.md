---
title: 通用 Web 漏洞
weight: 1
---

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

- [SQL 注入](sqli/) —— 注入类型、绕过、堆叠与二次注入。
- [XSS](xss/) —— 反射/存储/DOM XSS、绕过与利用。
- [点击劫持](clickjacking/) —— 透明 iframe 覆盖、UI Redress 与框架嵌入防御。
- [CSRF](csrf/) —— CSRF 与 SameSite、Token 绕过。
- [SSRF](ssrf/) —— SSRF、云元数据、协议利用与绕过。
- [XXE](xxe/) —— XML 外部实体、盲 XXE、OOB 与绕过。
- [XPath 注入](xpath/) —— XPath 拼接注入、认证绕过、节点遍历与盲注提取。
- [通用模板注入](ssti/) —— 模板引擎识别、探测与利用。
- [文件上传](file-upload/) —— 上传绕过、解析漏洞、竞争与二次利用。
- [通用文件包含](file-inclusion/) —— 本地/远程包含、伪协议与日志包含。
- [JWT](jwt/) —— 算法混淆、密钥爆破、kid/jku 注入。
- [OAuth](oauth/) —— OAuth/OIDC 流程缺陷、redirect_uri 与 token 泄露。
- [HTTP 请求走私](http-smuggling/) —— CL/TE、TE/TE、HTTP/2 降级与利用。
- [Web 缓存投毒](cache-poisoning/) —— 缓存键、缓存欺骗与投毒链。
- [竞争条件](race-condition/) —— 并发竞态、TOCTOU、限次绕过。
- [GraphQL](graphql/) —— introspection、批量查询、注入与授权缺陷。
- [WebSocket](websocket/) —— 跨站 WebSocket 劫持、认证与消息注入。
- [开放重定向](open-redirect/) —— 重定向绕过与 OAuth/SSO 组合利用。
- [CRLF 注入](crlf/) —— 响应头注入、日志注入与缓存组合。
- [CORS](cors/) —— 跨域配置错误与凭证泄露。
- [认证与会话](auth/) —— Cookie/Session、身份伪造、认证绕过、会话固定与权限校验缺陷。

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [CFITSIO EFS outfile 在格式校验前复制任意文件到任意可写路径](web-generic-cfitsio-efs-outfile-arbitrary-file-copy/) | verified | high | 2026-11-05 |
| [CFITSIO EFS root:// 输出驱动配合 Raw Data 子句外传本地文件](web-generic-cfitsio-efs-root-driver-local-file-exfiltration/) | verified | high | 2026-11-05 |
| [CGI 目录暴露 ld-linux：把动态加载器当 CGI 执行，argv 指定任意程序与脚本](web-generic-cgi-ld-linux-interpreter-argv-arbitrary-program-execution/) | verified | high | 2026-11-06 |
| [CouchDB CVE-2017-12635 + CVE-2017-12636：重复键建管理员后 query_servers 命令执行](web-generic-rce-couchdb-cve-2017-12635-12636/) | verified | medium | 2026-11-05 |
| [GitHub Enterprise Server CVE-2024-0200：repository_items rid_key 不安全反射 → restore_objects 泄露 session secret → 伪造 _gh_render Marshal cookie RCE](web-generic-rce-ghes-cve-2024-0200-unsafe-reflection-marshal-cookie-rce/) | verified | high | 2026-11-08 |
| [GitHub Enterprise Server CVE-2024-0507：管理控制台 Actions 存储 OIDC 设置命令注入，editor 提权到 root 站点管理员](web-generic-rce-ghes-cve-2024-0507-actions-storage-oidc-command-injection/) | verified | high | 2026-11-08 |
| [Host 校验绕过：端口注入、后缀匹配、重复头、绝对 URL 与覆盖头](web-generic-host-header-validation-bypass-ambiguity/) | verified | high | 2026-11-05 |
| [JSON 重复键/大数解析差异：前端校验 last-wins、Go jsonparser first-wins 导致负数量与零元结算](web-generic-json-duplicate-key-big-number-parser-differential/) | verified | high | 2026-11-08 |
| [Meteor Galaxy 悬空子域接管：CNAME 指向 us-east-1.galaxy-ingress.meteor.com，注册同名应用即可控制子域](web-generic-meteor-galaxy-dangling-subdomain-takeover/) | verified | high | 2026-11-08 |
| [Nginx 缺少 location / 时 server 级 root 生效：/cats/../nginx.conf 归一化后读取 /etc/nginx 配置](web-generic-nginx-missing-root-location-config-disclosure/) | verified | high | 2026-11-08 |
| [Ollama /api/create path 参数差异化错误消息导致服务器文件存在性探测（CVE-2024-39719）](web-generic-ollama-create-path-file-existence-oracle/) | verified | high | 2026-11-08 |
| [Ollama /api/push 路径遍历文件存在性探测：响应差异枚举服务端模型与文件路径（CVE-2024-39722）](web-generic-ollama-push-name-path-traversal-existence-probe/) | verified | high | 2026-11-08 |
| [Shellshock CGI RCE：User-Agent 等 HTTP 头映射为函数形式环境变量，bash 启动时执行尾部注入命令](web-generic-rce-shellshock-cgi-user-agent-env-function/) | verified | high | 2026-11-09 |
| [Wasm 导出函数未校验数组下标导致线性内存内越界写与相邻数据篡改](web-generic-wasm-unchecked-index-linear-memory-write/) | verified | medium | 2026-11-05 |
| [Wasm 导出线性内存中的密钥与敏感常量可被同源 JS 读取](web-generic-wasm-exported-memory-secret-read/) | verified | high | 2026-11-05 |
| [上传文件路径泄露后拼接静态资源路由批量下载用户证件照](web-generic-static-upload-path-join-download-id-photo-bulk/) | verified | high | 2026-11-08 |
| [双设备支付页滞留 + 取消订单返还优惠券：同一张券支付两笔订单](web-generic-payment-coupon-cancel-pending-order-reuse/) | verified | medium | 2026-11-07 |
| [客户端提交赛跑距离参数篡改：服务端信任模拟输入直接发放 flag](web-generic-client-side-race-distance-tamper/) | verified | high | 2026-11-06 |
| [导出 Excel/CSV 未转义昵称导致公式注入与客户端 RCE](web-generic-csv-formula-injection-export-rce/) | verified | medium | 2026-11-05 |
| [废弃第三方 JS 域名抢注投毒：bshare 分享插件夜间移动端强制跳转](web-generic-third-party-js-domain-takeover-night-redirect/) | verified | medium | 2026-11-07 |
| [打字测速服务只校验内容与 seed、信任客户端时间戳：抓取合法提交压缩时间间隔伪造 650 WPM](web-generic-client-timestamp-replay-typing-speed-bypass/) | verified | high | 2026-11-07 |
| [支付金额四舍五入差异：提交 0.019 元实付 0.01、服务端按 0.02 入账](web-generic-payment-rounding-differential-recharge/) | verified | high | 2026-11-05 |
| [支付金额篡改：支付接口信任客户端 totalAmount 且未绑定已创建订单](web-generic-payment-amount-tamper-no-order-binding/) | verified | high | 2026-11-05 |
| [注销-重注册循环复用新人权益：物理删除用户数据导致营销风控历史丢失](web-generic-account-deletion-new-user-benefit-reuse/) | verified | medium | 2026-11-06 |
| [游戏/积分接口信任客户端上报分数：直接调用接口伪造满分领取奖励](web-generic-client-side-score-trust/) | verified | high | 2026-11-05 |
| [瑞数动态防护下的隐藏 API 直连：从混淆业务 JS 提取接口，控制台 XMLHttpRequest 带 Bearer 绕过页面防护](web-generic-rs-hidden-api-direct-xhr-bypass/) | verified | medium | 2026-11-09 |
| [积分商城兑换下单直接信任客户端 goodsId 与抵扣积分：改商品编号用低积分换高价商品、改积分字段少扣积分](web-generic-points-mall-goodsid-points-parameter-tampering/) | verified | medium | 2026-11-09 |
| [购物车接受负数量：负数商品抵消高价商品金额实现低价购买](web-generic-payment-negative-quantity-offset/) | verified | high | 2026-11-05 |
| [限购数量只在前端校验：抓包把数量改成超过上限的值，服务端照单全收，实现超限购买/囤货](web-generic-purchase-quantity-limit-client-side-only-bypass/) | verified | medium | 2026-11-09 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
