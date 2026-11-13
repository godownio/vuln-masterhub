# SSRF

## 这层是什么

SSRF、云元数据、协议利用与绕过。

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
| [AI 推理 API model 参数被当作 URL 拉取：回显式 SSRF 打内网 Dashboard、K8s API 与云元数据](web-generic-ssrf-ai-inference-model-param-url-ssrf.md) | verified | low | 2026-11-06 |
| [Alibaba Sentinel Dashboard 集群状态接口 /cluster/state_single 未限制内网地址导致有回显 SSRF](sentinel-dashboard-cluster-state-single-ssrf.md) | verified | high | 2026-11-08 |
| [Apache CXF Aegis DataBinding xop:Include href 未校验：file:// 任意文件读取与 SSRF（CVE-2024-28752）](web-generic-ssrf-apache-cxf-aegis-xop-include-file-read.md) | verified | high | 2026-11-05 |
| [Apache ServiceComb Service-Center /testSchema/ SSRF：X-InstanceIP 拼接目标地址并回显响应（CVE-2023-44313）](web-generic-ssrf-servicecomb-service-center-testschema-instanceip.md) | verified | high | 2026-11-12 |
| [Axios mergeConfig 继承原型污染 headers：CRLF 请求拆分转 SSRF 读云元数据（CVE-2026-40175）](web-generic-ssrf-axios-mergeconfig-prototype-header-crlf.md) | verified | medium | 2026-11-05 |
| [Cerebro /rest/request 回显 SSRF：请求体 host/path 由客户端指定，服务端代发任意 HTTP 请求](web-generic-ssrf-cerebro-rest-request-host-path.md) | verified | medium | 2026-11-11 |
| [CFITSIO EFS HTTP Driver SSRF 并把响应落盘为可读文件](web-generic-ssrf-cfitsio-efs-http-outfile-response.md) | verified | high | 2026-11-05 |
| [Chainlit < 2.9.4 /project/element 自定义元素 url 被 SQLAlchemy 数据层直接 GET：认证用户 SSRF 读云元数据并回显](web-generic-ssrf-chainlit-custom-element-url-fetch-ssrf.md) | verified | high | 2026-11-06 |
| [ClickHouse SQL 注入经 url() 表函数多步中继：盲读内网 API + INSERT INTO FUNCTION url() 构造 POST 上传](web-generic-ssrf-clickhouse-sqli-url-function-multistep-relay.md) | verified | medium | 2026-11-12 |
| [ClickHouse url()/s3()/hdfs() 表函数 SSRF：探测内网服务与读取云元数据](web-generic-ssrf-clickhouse-url-s3-hdfs-cloud-metadata.md) | verified | high | 2026-11-05 |
| [Cloudflare Pages 白名单绕过 + 浏览器 SSRF：让 bot 以 pages.dev 页面打内网服务](web-generic-ssrf-bot-pages-dev-allowlist-internal-service.md) | verified | high | 2026-11-06 |
| [Consul /v1/agent/check/register 健康检查 SSRF：HTTP 检查回显云 IAM 临时凭据，响应过长被截断](web-generic-ssrf-consul-agent-check-register-iam-credentials.md) | verified | high | 2026-11-11 |
| [CordysCRM 第三方集成测试/编辑接口 URL 未校验：MAXKB 与 DataEase 配置分支均可触发服务端 SSRF](web-generic-ssrf-cordyscrm-thirdparty-integration-url.md) | verified | high | 2026-11-05 |
| [Crawl4AI /crawl/stream 未授权 SSRF：流式端点绕过 validate_url_destination（CVE-2026-57573）](web-generic-ssrf-crawl4ai-stream-endpoint-unauth.md) | verified | high | 2026-11-05 |
| [curl 重定向状态码方法语义：301/302/303 转 GET、307/308 保留方法与 body，把受限 SSRF 变成内网 POST](web-generic-ssrf-curl-307-308-method-preserve-internal-post.md) | verified | high | 2026-11-13 |
| [DeepAudit LLM 配置 API BASE URL 无校验：服务端向任意地址 POST /chat/completions（盲 SSRF）](web-generic-ssrf-deepaudit-llm-base-url-chat-completions.md) | verified | medium | 2026-11-06 |
| [Dify <= 1.16.1 未授权 SSRF：remote-files/upload 在登录校验前拉取任意 URL](web-generic-ssrf-dify-remote-files-upload-unauth.md) | verified | high | 2026-11-05 |
| [Directus CVE-2026-61835：文件导入用 0.0.0.0 绕过 IMPORT_IP_DENY_LIST 访问本机](web-generic-ssrf-directus-cve-2026-61835-zero-ip-bypass.md) | verified | high | 2026-11-05 |
| [Directus Webhook Flow 匿名触发 request 操作以系统身份发起 SSRF](web-generic-ssrf-directus-anonymous-webhook-flow-request.md) | verified | high | 2026-11-05 |
| [Directus 默认 IMPORT_IP_DENY_LIST 不覆盖私有网段：文件导入 SSRF 打 Docker 网关、宿主机与同网服务](web-generic-ssrf-directus-private-network-denylist-gap.md) | verified | high | 2026-11-05 |
| [Directus 默认 IMPORT_IP_DENY_LIST 只拦 AWS metadata，国产云 metadata 经文件导入直通](web-generic-ssrf-directus-default-denylist-domestic-cloud-metadata.md) | verified | high | 2026-11-05 |
| [Django /users/doHttp 通用转发 SSRF：url + request_type + params 读取内网 HTTP 服务](web-generic-ssrf-django-dohttp-url-forward.md) | verified | high | 2026-11-07 |
| [DynamoDB 数据投毒驱动 pd4ml HTML 转 PDF：attachment 标签 file:// 协议以 root 身份读取任意文件](web-generic-ssrf-pd4ml-attachment-file-read-dynamodb-poison.md) | verified | high | 2026-11-08 |
| [EIS 办公平台 third/template Service.aspx：link 参数直拼 URL 导致前台盲 SSRF](web-generic-ssrf-eis-service-aspx-link-ssrf.md) | verified | high | 2026-11-05 |
| [FE 系统 ProxyServletUtil url 参数直入 new URL/openConnection：有回显 SSRF 读取内网 HTTP 响应](web-generic-ssrf-fe-proxyservletutil-url-echo.md) | verified | high | 2026-11-05 |
| [Go idna 尾分隔符构造绕过 SSRF 黑名单访问回环地址](web-generic-ssrf-golang-idna-ascii-punycode-blacklist-bypass.md) | verified | high | 2026-11-04 |
| [gopher SSRF 伪造 FastCGI：PHP_VALUE 注入 auto_prepend_file 执行任意代码](web-generic-ssrf-gopher-fastcgi-fpm-auto-prepend.md) | verified | high | 2026-11-05 |
| [Gopher SSRF 打内网 Flask：构造 POST 到 render_template_string 的 name 参数，SSTI 读环境变量拿 flag](web-generic-ssrf-gopher-internal-flask-ssti-env-read.md) | verified | high | 2026-11-06 |
| [Grafana 数据源配置 SSRF：admin/弱口令下用 grafana-ssrf 添加数据源，读取云 IAM 临时凭据](web-generic-ssrf-grafana-datasource-iam-credentials.md) | verified | high | 2026-11-11 |
| [GraphQL importPaste 的 host 参数未做内网校验：服务端按用户提供的 URL 发起请求，DNSLog 确认 SSRF](web-generic-ssrf-graphql-importpaste-host.md) | verified | high | 2026-11-11 |
| [hassio.addon_stdin 的 addon 参数未校验：路径穿越改写 Supervisor API 路径，借其 Bearer 令牌调用任意端点并注入 addon 命令](web-generic-ssrf-hassio-addon-stdin-path-traversal-supervisor.md) | verified | high | 2026-11-11 |
| [Host 头 SSRF 串联远程下载落盘 Web 目录：从 request.getServerName() 到 JSP GetShell](web-generic-ssrf-host-header-getservername-download-webroot-rce.md) | verified | high | 2026-11-05 |
| [Host 头路由型 SSRF：负载均衡按可控 Host 转发到内网并访问管理面板](web-generic-ssrf-host-header-routing-ssrf.md) | verified | high | 2026-11-05 |
| [ICPAS php/rj_get_token.php 与 rj_calllist.php 的 URL 未限制协议：file:// 本地文件读取与内网 SSRF](web-generic-ssrf-icpas-rj-get-token-file-scheme.md) | verified | low | 2026-11-07 |
| [J2eeFAST 集成 UEditor catchimage：source[] URL 未限制，十进制 IP 绕过 catcherLocalDomain 触发 SSRF](web-generic-ssrf-j2eefast-ueditor-catchimage.md) | verified | medium | 2026-11-05 |
| [Langflow API Request / URL 组件只校验 URL 格式：工作流运行者经 httpx/RecursiveUrlLoader 触发内网 SSRF（CVE-2025-68477）](web-generic-ssrf-langflow-api-request-url-component-ssrf.md) | verified | high | 2026-11-06 |
| [LobeChat botMessage 附件 fetchUrl 裸 fetch：任意注册用户经四个 bot 平台发起盲 SSRF](web-generic-ssrf-lobechat-botmessage-attachment-fetchurl.md) | verified | high | 2026-11-05 |
| [LyLme Spage get_head/get_curl 未校验 URL 的盲 SSRF：用响应时间侧信道探测内网主机与端口](web-generic-ssrf-lylme-get-head-curl-blind-timing.md) | verified | high | 2026-11-11 |
| [Markdown 转 docx 的图片抓取未限制本地路径：绝对路径/file:// 把任意文件嵌入 word/media](web-generic-ssrf-docx-converter-image-local-file-read.md) | verified | high | 2026-11-06 |
| [MinIO /minio/webrpc LoginSTS 未授权 SSRF 打内网 Docker API 2375，remote build 加载外部 Dockerfile 逃逸](web-generic-ssrf-minio-webrpc-loginsts-docker-build-escape.md) | verified | high | 2026-11-08 |
| [OA GetRawFile 接口仅黑名单过滤 url 参数，导致 SSRF 读取内网 HTTP 响应](web-generic-ssrf-oa-getrawfile-weak-blacklist.md) | verified | high | 2026-11-05 |
| [OTCMS 后台两处盲 SSRF：QrReader 的 file_get_contents(img) 与 ReqUrl 的 curl_setopt(signalUrl)，以响应延迟探测内网端口](web-generic-ssrf-otcms-qrreader-curl-intranet-probe.md) | verified | high | 2026-11-12 |
| [PHP curl SSRF 后缀白名单被 302 重定向旁路：默认 REDIR_PROTOCOLS 放行 dict/gopher 等，仅默认禁 file/scp](web-generic-ssrf-curl-redirect-protocol-surface-suffix-whitelist-bypass.md) | verified | high | 2026-11-13 |
| [PHP fsockopen SSRF：dict 探测端口后用 gopher 发送原始 MySQL 协议包执行 SQL](web-generic-ssrf-fsockopen-gopher-mysql-raw-protocol.md) | verified | high | 2026-11-06 |
| [PHP parse_url 单斜杠 URL 使 host=null 绕过校验，curl_exec 按原始串回环请求读本地文件](web-generic-ssrf-php-parse-url-null-host-curl-loopback-read.md) | verified | high | 2026-11-08 |
| [PHP 友链预览 SSRF 两层校验不一致：换行把 FILE:// 藏到第二行 + 大写 scheme 绕过过滤读取本地文件](web-generic-ssrf-php-preview-line-case-filter-lfi.md) | verified | high | 2026-11-07 |
| [PHP 请求头门禁 + base64 解码 URL 直接 curl_exec：伪造 Authorization/X-Oss-Pub-Key-Url 触发 SSRF](web-generic-ssrf-php-header-gated-base64-curl-exec.md) | verified | high | 2026-11-11 |
| [PublicCMS /api/method/getHtml SSRF：appToken 调用任意 HTTP 并回显页面/时延探测内网端口](web-generic-ssrf-publiccms-method-gethtml-apptoken.md) | verified | high | 2026-11-07 |
| [Python urlparse 与 urllib3 反斜杠解析分歧绕过域名后缀白名单 SSRF](web-generic-ssrf-python-urlparse-urllib3-backslash-bypass.md) | verified | high | 2026-11-04 |
| [Rebuild FileDownloader read-raw/proxy-download 未授权 SSRF：url 参数经 OkHttp 代发并回显响应](web-generic-ssrf-rebuild-filedownloader-readraw-proxydownload.md) | verified | high | 2026-11-12 |
| [Selenium Grid 未授权 /wd/hub 新建会话回显 SSRF：Remote WebDriver 访问内网 URL 或 file:/// 并读 page_source](web-generic-ssrf-selenium-grid-remote-webdriver-file-read.md) | verified | medium | 2026-11-11 |
| [SPARQL SERVICE 子句 SSRF：查询引擎代服务端请求任意 URL](web-generic-ssrf-sparql-service-clause.md) | verified | high | 2026-11-05 |
| [Spring MVC actionDownloadFile 未校验 url 参数：HttpEngine.downloadFromUrl 回显式 SSRF](web-generic-ssrf-spring-actiondownloadfile-httpengine-response-stream.md) | verified | high | 2026-11-06 |
| [SSRF 协议黑名单只匹配小写字面量：Gopher:// 大小写与 gopher:/{/host:port} 分隔符变体绕过，恢复任意 TCP 报文能力](web-generic-ssrf-scheme-filter-case-and-delimiter-variant-bypass.md) | verified | high | 2026-11-08 |
| [SSRF 打 Redis：inline 协议、CRLF 注入与认证 pipeline](web-generic-ssrf-redis-inline-protocol-crlf.md) | verified | high | 2026-11-05 |
| [SSRF 支持 file:// 时先读 /etc/hosts：拿到容器主机名与内网网段再定向扫端口](web-generic-ssrf-file-hosts-internal-segment-recon.md) | verified | high | 2026-11-08 |
| [SSRF 校验与请求两次 DNS 解析：DNS 重绑定 + 短 TTL 竞争访问 127.0.0.1 内部服务](web-generic-ssrf-dns-rebinding-double-resolution-bypass.md) | verified | high | 2026-11-07 |
| [SSRF 白名单绕过：双重 URL 编码](web-generic-ssrf-fragment-double-urlencode-allowlist-bypass.md) | verified | high | 2026-11-11 |
| [SSRF 短写 IP 127.1 绕过黑名单 + 302 重定向把 POST 转成 GET 访问内网](web-generic-ssrf-short-form-ip-302-post-to-get.md) | verified | high | 2026-11-06 |
| [SSRF 经 301 重定向进入 gopher：localhost 端口扫描与任意 TCP 报文打 OMI](web-generic-ssrf-redirect-gopher-localhost-portscan-omi.md) | verified | high | 2026-11-05 |
| [SSRF 读取云元数据获取临时凭证](cloud-metadata.md) | draft | high | 2026-11-04 |
| [SSRF 重定向链绕过与错误路径回显：Refresh/Meta Refresh/X-Next 七跳访问 127.0.0.1 内部接口](web-generic-ssrf-redirect-chain-meta-refresh-error-body.md) | verified | high | 2026-11-07 |
| [TCPDF writeHTML 的 link href 触发 fileGetContents SSRF：302 跳 gopher 向内网 Flask 发送原始 HTTP 报文](web-generic-ssrf-tcpdf-link-href-filegetcontents-gopher.md) | verified | medium | 2026-11-09 |
| [URL userinfo 混淆：用 user:pass@host 绕过前缀白名单 SSRF 与 WAF 关键词检测](web-generic-ssrf-url-userinfo-prefix-allowlist-bypass.md) | verified | high | 2026-11-05 |
| [URL 前缀白名单被 trusted.com.attacker.com 绕过：字符串前缀匹配不等于主机校验](web-generic-ssrf-hostname-subdomain-prefix-allowlist-bypass.md) | verified | high | 2026-11-07 |
| [URL 解析器分歧导致主机白名单绕过 SSRF](web-generic-ssrf-url-parser-differential-allowlist-bypass.md) | verified | high | 2026-11-04 |
| [vLLM MediaConnector 多模态 image_url SSRF：urlparse 白名单与 aiohttp WHATWG 解析分歧（CVE-2026-24779）](web-generic-ssrf-vllm-media-connector-urlparse-aiohttp-differential.md) | verified | medium | 2026-11-06 |
| [Wallos testwebhooknotifications.php 未校验私有/保留 IP 的 SSRF（CVE-2026-30839）](web-generic-ssrf-wallos-testwebhook-notifications-private-ip.md) | verified | high | 2026-11-05 |
| [WeasyPrint HTML 转 PDF：link rel=attachment 的 file:// 读取本地文件并嵌入 PDF](web-generic-ssrf-weasyprint-attachment-file-read.md) | verified | high | 2026-11-12 |
| [wget 简写解析把「参数@主机:端口」当成 ftp://host/path，用十进制 IP 绕过点号黑名单把 URL 里的秘密外带到自建 FTP 日志](web-generic-ssrf-wget-shorthand-ftp-decimal-ip-secret-path-exfil.md) | verified | medium | 2026-11-09 |
| [Windows libcurl ≤7.67 的 file:// 后接 UNC 走私 SMB：SSRF 泄露 NTLMv2 哈希，爆破口令或 ntlmrelayx 中继拿 RCE（CVE-2019-15601）](web-generic-ssrf-curl-file-unc-smb-smuggling-ntlm-relay.md) | verified | high | 2026-11-13 |
| [Windows libcurl 下 pathinfo 后缀白名单绕过：file:///c:/windows/win.ini 追加 ?.jpg 或 #.jpg 读取本地任意文件](web-generic-ssrf-curl-pathinfo-extension-windows-fragment-query-bypass.md) | verified | high | 2026-11-13 |
| [XML-RPC 业务方法 URL 参数 SSRF：dvws.CheckUptime(url) 由服务端请求任意地址并回传结果](web-generic-ssrf-xmlrpc-method-url-param-server-fetch.md) | verified | high | 2026-11-12 |
| [万户OA rssproxy.jsp SSRF：rssUrl 直入 new URL().openConnection() 并回显](web-generic-ssrf-whir-ezoffice-rssproxy-urlconnection.md) | verified | high | 2026-11-07 |
| [信呼OA 2.6.0 downwxpic picurl 解密后进 curl：file:// 读取本地文件并借上传目录条件竞争回读](web-generic-ssrf-xinhu-downwxpic-picurl-file-read-race.md) | verified | high | 2026-11-09 |
| [允许上传 .url 快捷方式 + share 解析 URL：file:// 协议读取服务器本地文件](web-generic-ssrf-url-shortcut-upload-file-scheme-read.md) | verified | high | 2026-11-06 |
| [公链节点 RPC addnode 未校验目标地址：认证后令节点连接任意 host:port，按响应时间侧信道探测本机/内网开放端口](web-generic-ssrf-blockchain-node-rpc-addnode-port-probe.md) | verified | high | 2026-11-12 |
| [只校验 URL 前缀 ^https:// 的 SSRF：用攻击者控制的 HTTPS 临时域名回 302 到 gopher://127.0.0.1:9000，伪造 FastCGI 执行任意 PHP](web-generic-ssrf-https-prefix-check-302-gopher-fastcgi.md) | verified | medium | 2026-11-09 |
| [后台模板缓存接口 curl_get 未限制协议：file:// 读取 config.php 与内网 SSRF](web-generic-ssrf-php-curl-get-file-scheme-config-read.md) | verified | high | 2026-11-05 |
| [后台配置推送地址直接 new URL().openConnection()：盲 SSRF 打内网与 DNSLog 验证](web-generic-ssrf-configurable-push-url-blind.md) | verified | high | 2026-11-05 |
| [后台预览面板 target_url 任意抓取：SSRF 访问 127.0.0.1 内部诊断路由回显 flag](web-generic-ssrf-preview-panel-target-url-localhost.md) | verified | high | 2026-11-06 |
| [图片代理接口的 url 参数未限制协议：file:// 读取服务器任意文件并列出目录](web-generic-ssrf-image-proxy-url-param-file-scheme-arbitrary-read.md) | verified | medium | 2026-11-08 |
| [多层解码错位：完整 URL 编码的 DWORD 绕过 WAF 访问云 metadata](web-generic-ssrf-multi-layer-decode-dword-waf-bypass.md) | verified | high | 2026-11-05 |
| [意见反馈图片 URL 由服务端抓取：盲 SSRF 外带回连与内网探测](web-generic-ssrf-feedback-image-url-fetch.md) | verified | medium | 2026-11-07 |
| [服务端 curl 执行用户 URL：gopher 构造原始 HTTP 请求绕过仅 localhost 管理校验](web-generic-ssrf-curl-gopher-loopback-admin.md) | verified | high | 2026-11-05 |
| [禅道 AI 模型测试连接 base 参数无校验：服务端 curl 任意 URL 探测内网端口](web-generic-ssrf-zentao-ai-model-test-connection.md) | verified | high | 2026-11-05 |
| [禅道后台 Webhook 支持 file:// 协议导致服务端任意文件读取](web-generic-ssrf-zentao-webhook-file-protocol-arbitrary-read.md) | verified | high | 2026-11-05 |
| [等价 IP 表示绕过 SSRF 字符串黑名单](web-generic-ssrf-ip-notation-blacklist-bypass.md) | verified | high | 2026-11-04 |
| [远程头像 URL 抓取未校验内网地址，SSRF 读取仅内网暴露的服务](web-generic-ssrf-avatar-urlopen-internal-service.md) | verified | high | 2026-11-05 |
| [远程文件上传接口 fileUrl 支持 file:// 实现 SSRF 任意文件读取](upload-api-fileurl-ssrf-file-read.md) | draft | high | 2026-11-08 |
| [连接器测试接口 SSRF：IMAP 测试与网站抓取参数直连任意主机](web-generic-ssrf-connector-imap-website-test-endpoints.md) | verified | high | 2026-11-05 |
| [静态 DNS 解析 nip.io 绕过仅前缀/包含式域名白名单：<可信前缀>.<IP>.nip.io 通过校验却解析到任意（内网）IP](web-generic-ssrf-nip-io-static-dns-prefix-allowlist-bypass.md) | verified | medium | 2026-11-08 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
