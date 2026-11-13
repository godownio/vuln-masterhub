# HTTP 请求走私

## 这层是什么

CL/TE、TE/TE、HTTP/2 降级与利用。

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
| [Apache mod_rewrite 代理场景 RewriteRule 目标参数 CRLF 注入：URL 编码的 %0d%0a 在转发时解码成新请求头，绕过 RequestHeader unset](web-generic-http-smuggling-apache-rewriterule-crlf-header-injection-bypass.md) | verified | high | 2026-11-08 |
| [CL.0 请求走私：后端忽略 Content-Length 时前端/后端请求边界不一致](web-generic-http-smuggling-cl0-backend-ignores-content-length.md) | verified | high | 2026-11-12 |
| [CL.TE 基础请求走私：前端按 Content-Length 放行整包、后端按 chunked 在 0 块终止，剩余字节成为下一请求前缀](web-generic-http-smuggling-cl-te-basic-chunk-prefix.md) | verified | high | 2026-11-12 |
| [Content-Encoding 压缩请求体：WAF 不解码而后端解码导致请求体检查绕过](web-generic-http-smuggling-content-encoding-request-body-waf-bypass.md) | verified | high | 2026-11-05 |
| [eBPF tc ingress 逐包关键字过滤绕过：TCP 分段打散 "flag" + TCP 头 0x25 随机丢包下 Range 小步重试](web-generic-http-smuggling-ebpf-tc-header-scan-percent-random-drop.md) | verified | medium | 2026-11-06 |
| [eBPF TC 无状态防火墙绕过：TCP 分段与 HTTP Range 双向规避](web-generic-http-smuggling-ebpf-tc-stateless-keyword-bypass.md) | verified | high | 2026-11-05 |
| [F5 BIG-IP CVE-2023-46747：AJP 请求走私到 /tmui/Control/form 未授权创建管理员，再经管理 API 执行命令](web-generic-http-smuggling-ajp-f5-bigip-cve-2023-46747-auth-bypass-rce.md) | verified | high | 2026-11-13 |
| [H2.CL 请求走私：前端降级 HTTP/2 时复用客户端注入的 Content-Length，后端按 CL=0 把剩余字节当下一请求](web-generic-http-smuggling-h2-cl-downgrade-injected-content-length.md) | verified | high | 2026-11-12 |
| [H2.TE 请求走私：HTTP/2 请求携带 transfer-encoding: chunked，前端未剥离即降级导致后端按分块解析错位](web-generic-http-smuggling-h2-te-downgrade-chunked.md) | verified | high | 2026-11-12 |
| [HAProxy CVE-2021-40346：Content-Length 头名整数溢出走私，绕过前端 ACL 访问内部 dev 子域](web-generic-http-smuggling-haproxy-cve-2021-40346-content-length-overflow.md) | verified | medium | 2026-11-08 |
| [HTTP/2 头值 CRLF 注入走私：前端剥离正常 TE 头却放过头值里的 \r\nTransfer-Encoding，降级后后端恢复分块解析](web-generic-http-smuggling-h2-crlf-header-value-te-bypass.md) | verified | high | 2026-11-12 |
| [HTTP/2 请求拆分（CRLF 注入）：在头值里塞入完整请求行，利用前端补齐的 \r\n\r\n 让后端把一次请求拆成两个](web-generic-http-smuggling-h2-request-splitting-crlf-host-header.md) | verified | high | 2026-11-12 |
| [HTTP/2 请求隧道 + 缓存投毒：把 JSON 端点的反射 XSS 嵌进 text/html 外层响应并缓存，访问主页即执行](web-generic-http-smuggling-h2-request-tunnelling-cache-poisoning-xss.md) | verified | high | 2026-11-12 |
| [HTTP/2 请求隧道绕过前端访问控制：走私嵌套请求并伪造前端内部认证头，读取 /admin 执行管理员操作](web-generic-http-smuggling-h2-request-tunnelling-access-control-bypass.md) | verified | high | 2026-11-12 |
| [TE.CL 基础请求走私：前端按 chunked 在 0 块截断、后端按 Content-Length 继续读取，剩余体字节成为下一请求](web-generic-http-smuggling-te-cl-basic-chunk-prefix.md) | verified | high | 2026-11-12 |
| [TE.TE 请求走私：重复/畸形 Transfer-Encoding 头诱导一端忽略分块解析，退化为 CL.TE 或 TE.CL](web-generic-http-smuggling-te-te-obfuscated-transfer-encoding.md) | verified | high | 2026-11-12 |
| [Varnish HTTP/1 管线残留：CL body 后的第二请求被复用连接转发（CVE-2022-23959 补丁路径正交）](web-generic-http-smuggling-varnish-pipeline-cl-residual.md) | verified | medium | 2026-11-05 |
| [响应队列中毒（H2.TE）：走私完整请求让后端多发一个响应，劫持后续用户的响应并捕获管理员会话](web-generic-http-smuggling-h2-response-queue-poisoning-session-capture.md) | verified | high | 2026-11-12 |
| [基于暂停的请求走私：利用后端读取超时在前端/后端连接上注入请求前缀](web-generic-http-smuggling-pause-based-desync-timeout.md) | verified | high | 2026-11-12 |
| [多成员 gzip 请求体解压范围错位：网关校验首 member、后端执行全部 member](web-generic-http-smuggling-gzip-multi-member-decompression-differential.md) | verified | high | 2026-11-04 |
| [客户端去同步（CSD）：浏览器 fetch 走私前缀污染连接并泄露受害者 Cookie](web-generic-http-smuggling-client-side-desync-cookie-leak.md) | verified | high | 2026-11-12 |
| [捕获其他用户请求：走私一个 Content-Length 大于实际 body 的存储型 POST，让下一受害请求被拼进评论字段并回显其 Cookie](web-generic-http-smuggling-capture-victim-requests-oversized-cl.md) | verified | high | 2026-11-12 |
| [探测前端请求重写并伪造内部头：走私 POST 让后端把下一请求的已重写头回显为参数值，再带该 IP 头访问 /admin](web-generic-http-smuggling-front-end-rewrite-probe-header-spoof.md) | verified | high | 2026-11-12 |
| [未知 Transfer-Encoding 解析差异走私：代理按 chunked 截断、Flask 按 Content-Length 读全 body 绕过 WAF](web-generic-http-smuggling-unknown-te-cl-differential.md) | verified | high | 2026-11-06 |
| [空 Content-Length + TE chunked 解析差异：前置代理拦截 /admin，走私第二个 GET 到后端渲染路由](web-generic-http-smuggling-empty-cl-chunked-admin-bypass.md) | verified | medium | 2026-11-06 |
| [请求走私投递反射型 XSS：把恶意 User-Agent 藏进走私请求，让下一受害者的响应执行脚本](web-generic-http-smuggling-reflected-xss-delivery.md) | verified | high | 2026-11-12 |
| [请求走私的差分响应确认：走私一个 GET /404 前缀，使紧随其后的正常请求返回 404](web-generic-http-smuggling-differential-response-confirmation.md) | verified | high | 2026-11-12 |
| [请求走私的时间延迟检测：构造后端等待不完整 chunk 的请求，以响应耗时判定 CL.TE/TE.CL](web-generic-http-smuggling-time-delay-detection.md) | verified | high | 2026-11-12 |
| [请求走私绕过前端访问控制：把带 Host: localhost 的 GET /admin 藏进 chunk，并用尾部 Content-Length 吸收后续请求头](web-generic-http-smuggling-front-end-acl-bypass-smuggled-request.md) | verified | high | 2026-11-12 |
| [走私伪造 mTLS 客户端证书身份头：前端校验并注入 X-SSL-CLIENT-CN，走私请求绕过覆盖直接以 administrator 到达后端](web-generic-http-smuggling-client-cert-cn-header-spoof.md) | verified | medium | 2026-11-12 |
| [连接状态攻击绕过 Host 校验：同一 keep-alive 连接先合法请求再打内网](web-generic-http-smuggling-host-connection-state-bypass.md) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
