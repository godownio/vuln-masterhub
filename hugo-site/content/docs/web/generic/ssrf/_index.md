---
title: SSRF
weight: 1
---

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
| [AI 推理 API model 参数被当作 URL 拉取：回显式 SSRF 打内网 Dashboard、K8s API 与云元数据](web-generic-ssrf-ai-inference-model-param-url-ssrf/) | verified | low | 2026-11-06 |
| [Apache CXF Aegis DataBinding xop:Include href 未校验：file:// 任意文件读取与 SSRF（CVE-2024-28752）](web-generic-ssrf-apache-cxf-aegis-xop-include-file-read/) | verified | high | 2026-11-05 |
| [Axios mergeConfig 继承原型污染 headers：CRLF 请求拆分转 SSRF 读云元数据（CVE-2026-40175）](web-generic-ssrf-axios-mergeconfig-prototype-header-crlf/) | verified | medium | 2026-11-05 |
| [CFITSIO EFS HTTP Driver SSRF 并把响应落盘为可读文件](web-generic-ssrf-cfitsio-efs-http-outfile-response/) | verified | high | 2026-11-05 |
| [Chainlit < 2.9.4 /project/element 自定义元素 url 被 SQLAlchemy 数据层直接 GET：认证用户 SSRF 读云元数据并回显](web-generic-ssrf-chainlit-custom-element-url-fetch-ssrf/) | verified | high | 2026-11-06 |
| [ClickHouse url()/s3()/hdfs() 表函数 SSRF：探测内网服务与读取云元数据](web-generic-ssrf-clickhouse-url-s3-hdfs-cloud-metadata/) | verified | high | 2026-11-05 |
| [Cloudflare Pages 白名单绕过 + 浏览器 SSRF：让 bot 以 pages.dev 页面打内网服务](web-generic-ssrf-bot-pages-dev-allowlist-internal-service/) | verified | high | 2026-11-06 |
| [CordysCRM 第三方集成测试/编辑接口 URL 未校验：MAXKB 与 DataEase 配置分支均可触发服务端 SSRF](web-generic-ssrf-cordyscrm-thirdparty-integration-url/) | verified | high | 2026-11-05 |
| [Crawl4AI /crawl/stream 未授权 SSRF：流式端点绕过 validate_url_destination（CVE-2026-57573）](web-generic-ssrf-crawl4ai-stream-endpoint-unauth/) | verified | high | 2026-11-05 |
| [DeepAudit LLM 配置 API BASE URL 无校验：服务端向任意地址 POST /chat/completions（盲 SSRF）](web-generic-ssrf-deepaudit-llm-base-url-chat-completions/) | verified | medium | 2026-11-06 |
| [Dify <= 1.16.1 未授权 SSRF：remote-files/upload 在登录校验前拉取任意 URL](web-generic-ssrf-dify-remote-files-upload-unauth/) | verified | high | 2026-11-05 |
| [Directus CVE-2026-61835：文件导入用 0.0.0.0 绕过 IMPORT_IP_DENY_LIST 访问本机](web-generic-ssrf-directus-cve-2026-61835-zero-ip-bypass/) | verified | high | 2026-11-05 |
| [Directus Webhook Flow 匿名触发 request 操作以系统身份发起 SSRF](web-generic-ssrf-directus-anonymous-webhook-flow-request/) | verified | high | 2026-11-05 |
| [Directus 默认 IMPORT_IP_DENY_LIST 不覆盖私有网段：文件导入 SSRF 打 Docker 网关、宿主机与同网服务](web-generic-ssrf-directus-private-network-denylist-gap/) | verified | high | 2026-11-05 |
| [Directus 默认 IMPORT_IP_DENY_LIST 只拦 AWS metadata，国产云 metadata 经文件导入直通](web-generic-ssrf-directus-default-denylist-domestic-cloud-metadata/) | verified | high | 2026-11-05 |
| [EIS 办公平台 third/template Service.aspx：link 参数直拼 URL 导致前台盲 SSRF](web-generic-ssrf-eis-service-aspx-link-ssrf/) | verified | high | 2026-11-05 |
| [FE 系统 ProxyServletUtil url 参数直入 new URL/openConnection：有回显 SSRF 读取内网 HTTP 响应](web-generic-ssrf-fe-proxyservletutil-url-echo/) | verified | high | 2026-11-05 |
| [Go idna 尾分隔符构造绕过 SSRF 黑名单访问回环地址](web-generic-ssrf-golang-idna-ascii-punycode-blacklist-bypass/) | verified | high | 2026-11-04 |
| [gopher SSRF 伪造 FastCGI：PHP_VALUE 注入 auto_prepend_file 执行任意代码](web-generic-ssrf-gopher-fastcgi-fpm-auto-prepend/) | verified | high | 2026-11-05 |
| [Gopher SSRF 打内网 Flask：构造 POST 到 render_template_string 的 name 参数，SSTI 读环境变量拿 flag](web-generic-ssrf-gopher-internal-flask-ssti-env-read/) | verified | high | 2026-11-06 |
| [Host 头 SSRF 串联远程下载落盘 Web 目录：从 request.getServerName() 到 JSP GetShell](web-generic-ssrf-host-header-getservername-download-webroot-rce/) | verified | high | 2026-11-05 |
| [Host 头路由型 SSRF：负载均衡按可控 Host 转发到内网并访问管理面板](web-generic-ssrf-host-header-routing-ssrf/) | verified | high | 2026-11-05 |
| [J2eeFAST 集成 UEditor catchimage：source[] URL 未限制，十进制 IP 绕过 catcherLocalDomain 触发 SSRF](web-generic-ssrf-j2eefast-ueditor-catchimage/) | verified | medium | 2026-11-05 |
| [Langflow API Request / URL 组件只校验 URL 格式：工作流运行者经 httpx/RecursiveUrlLoader 触发内网 SSRF（CVE-2025-68477）](web-generic-ssrf-langflow-api-request-url-component-ssrf/) | verified | high | 2026-11-06 |
| [LobeChat botMessage 附件 fetchUrl 裸 fetch：任意注册用户经四个 bot 平台发起盲 SSRF](web-generic-ssrf-lobechat-botmessage-attachment-fetchurl/) | verified | high | 2026-11-05 |
| [Markdown 转 docx 的图片抓取未限制本地路径：绝对路径/file:// 把任意文件嵌入 word/media](web-generic-ssrf-docx-converter-image-local-file-read/) | verified | high | 2026-11-06 |
| [OA GetRawFile 接口仅黑名单过滤 url 参数，导致 SSRF 读取内网 HTTP 响应](web-generic-ssrf-oa-getrawfile-weak-blacklist/) | verified | high | 2026-11-05 |
| [PHP fsockopen SSRF：dict 探测端口后用 gopher 发送原始 MySQL 协议包执行 SQL](web-generic-ssrf-fsockopen-gopher-mysql-raw-protocol/) | verified | high | 2026-11-06 |
| [Python urlparse 与 urllib3 反斜杠解析分歧绕过域名后缀白名单 SSRF](web-generic-ssrf-python-urlparse-urllib3-backslash-bypass/) | verified | high | 2026-11-04 |
| [SPARQL SERVICE 子句 SSRF：查询引擎代服务端请求任意 URL](web-generic-ssrf-sparql-service-clause/) | verified | high | 2026-11-05 |
| [Spring MVC actionDownloadFile 未校验 url 参数：HttpEngine.downloadFromUrl 回显式 SSRF](web-generic-ssrf-spring-actiondownloadfile-httpengine-response-stream/) | verified | high | 2026-11-06 |
| [SSRF 打 Redis：inline 协议、CRLF 注入与认证 pipeline](web-generic-ssrf-redis-inline-protocol-crlf/) | verified | high | 2026-11-05 |
| [SSRF 短写 IP 127.1 绕过黑名单 + 302 重定向把 POST 转成 GET 访问内网](web-generic-ssrf-short-form-ip-302-post-to-get/) | verified | high | 2026-11-06 |
| [SSRF 经 301 重定向进入 gopher：localhost 端口扫描与任意 TCP 报文打 OMI](web-generic-ssrf-redirect-gopher-localhost-portscan-omi/) | verified | high | 2026-11-05 |
| [SSRF 读取云元数据获取临时凭证](cloud-metadata/) | draft | high | 2026-11-04 |
| [URL userinfo 混淆：用 user:pass@host 绕过前缀白名单 SSRF 与 WAF 关键词检测](web-generic-ssrf-url-userinfo-prefix-allowlist-bypass/) | verified | high | 2026-11-05 |
| [URL 解析器分歧导致主机白名单绕过 SSRF](web-generic-ssrf-url-parser-differential-allowlist-bypass/) | verified | high | 2026-11-04 |
| [vLLM MediaConnector 多模态 image_url SSRF：urlparse 白名单与 aiohttp WHATWG 解析分歧（CVE-2026-24779）](web-generic-ssrf-vllm-media-connector-urlparse-aiohttp-differential/) | verified | medium | 2026-11-06 |
| [Wallos testwebhooknotifications.php 未校验私有/保留 IP 的 SSRF（CVE-2026-30839）](web-generic-ssrf-wallos-testwebhook-notifications-private-ip/) | verified | high | 2026-11-05 |
| [允许上传 .url 快捷方式 + share 解析 URL：file:// 协议读取服务器本地文件](web-generic-ssrf-url-shortcut-upload-file-scheme-read/) | verified | high | 2026-11-06 |
| [后台模板缓存接口 curl_get 未限制协议：file:// 读取 config.php 与内网 SSRF](web-generic-ssrf-php-curl-get-file-scheme-config-read/) | verified | high | 2026-11-05 |
| [后台配置推送地址直接 new URL().openConnection()：盲 SSRF 打内网与 DNSLog 验证](web-generic-ssrf-configurable-push-url-blind/) | verified | high | 2026-11-05 |
| [后台预览面板 target_url 任意抓取：SSRF 访问 127.0.0.1 内部诊断路由回显 flag](web-generic-ssrf-preview-panel-target-url-localhost/) | verified | high | 2026-11-06 |
| [多层解码错位：完整 URL 编码的 DWORD 绕过 WAF 访问云 metadata](web-generic-ssrf-multi-layer-decode-dword-waf-bypass/) | verified | high | 2026-11-05 |
| [服务端 curl 执行用户 URL：gopher 构造原始 HTTP 请求绕过仅 localhost 管理校验](web-generic-ssrf-curl-gopher-loopback-admin/) | verified | high | 2026-11-05 |
| [禅道 AI 模型测试连接 base 参数无校验：服务端 curl 任意 URL 探测内网端口](web-generic-ssrf-zentao-ai-model-test-connection/) | verified | high | 2026-11-05 |
| [禅道后台 Webhook 支持 file:// 协议导致服务端任意文件读取](web-generic-ssrf-zentao-webhook-file-protocol-arbitrary-read/) | verified | high | 2026-11-05 |
| [等价 IP 表示绕过 SSRF 字符串黑名单](web-generic-ssrf-ip-notation-blacklist-bypass/) | verified | high | 2026-11-04 |
| [远程头像 URL 抓取未校验内网地址，SSRF 读取仅内网暴露的服务](web-generic-ssrf-avatar-urlopen-internal-service/) | verified | high | 2026-11-05 |
| [连接器测试接口 SSRF：IMAP 测试与网站抓取参数直连任意主机](web-generic-ssrf-connector-imap-website-test-endpoints/) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
