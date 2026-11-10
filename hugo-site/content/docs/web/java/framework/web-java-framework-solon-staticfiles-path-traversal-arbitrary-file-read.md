---
id: web-java-framework-solon-staticfiles-path-traversal-arbitrary-file-read
title: Solon <=3.0.8 静态文件映射未过滤 ../：/assets/ 前缀拼接路径穿越读任意文件（CVE-2025-1584）
type: scenario
domain: web
path: web/java/framework
technique: static-file-path-prefix-traversal
tags:
- solon
- path-traversal
- arbitrary-file-read
- staticfiles
cve: CVE-2025-1584
affected_versions: <= 3.0.8（3.0.9 修复）
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-27
  verified_at: '2026-11-08T15:03:18+08:00'
  notes: 已对照原文核对：StaticMappings.find 前缀 startsWith 匹配后 substring 拼 FileStaticRepository、无 ../ 过滤，CVE-2025-1584 与 patch commit 一致；img/01 显示 /assets/../../../app/assets/dashboard.css 返回 200 读取成功，img/02 证实 requests 客户端规范化 .. 导致请求行变为 /app/app.jar，需原样发送路径的工程细节属实。affected_versions 按原文重设：原文明确 up to 3.0.8 受影响、3.0.9 修复，去除 patch hash 括号注释。未验证点：未复现 flag 获取步骤（原文明示但截图未含）。
url: /docs/web/java/framework/web-java-framework-solon-staticfiles-path-traversal-arbitrary-file-read/
draft: false
kb_aliases:
- Solon staticfiles path traversal
- CVE-2025-1584
---

# 一句话结论

Solon 框架（<= 3.0.8）的 `StaticMappings.find` 只用 `path.startsWith(pathPrefix)` 匹配静态资源前缀，随后把前缀之后的剩余路径原样交给 `FileStaticRepository.find` 拼接真实文件系统路径，全程无 `..` 过滤，攻击者请求 `/assets/../../../app/app.jar` 即可以 web 进程权限读取任意文件；在 CTF 场景中下载应用 jar 反编译得到硬编码 key 后命中后门路由拿 flag。

# 原理

`StaticMappings.find(path)` 遍历注册的 `StaticLocation`，匹配条件仅是 `path.startsWith(m.pathPrefix)`；命中后执行 `m.repository.find(path.substring(m.pathPrefix.length()))`。`FileStaticRepository.find` 用相对路径直接拼文件目录。整条链路没有任何对 `..` 段的规范化或拒绝检查，因此只要请求路径以注册前缀（如 `/assets/`）开头，前缀之后的任意穿越段都会原样落到 `new File("/app/assets", "../../../app/app.jar")` 这类解析上，由操作系统完成穿越。修复版（3.0.9）直接加了 `path.contains("/../") == false` 的 WAF 式检查。

利用有一步关键工程细节：用 Python `requests` 打不通，因为 urllib3/`urllib.parse.urljoin` 在客户端构造请求时会把 `..` 段规范化合并，`/assets/../../../app/app.jar` 被改写成 `/app/app.jar`（Burp 抓包确认请求行已是规范化路径，不再以 `/assets/` 开头，无法命中 location 且服务端也失去了穿越段），需要用 Java HttpClient/原生 socket 等不做路径规范化的客户端发原始路径。

# 触发条件

- 目标使用 Solon <= 3.0.8 且启用了静态文件映射（`StaticMappings.add("/xxx/", new FileStaticRepository(...))` 或默认静态文件服务）。
- 攻击者可访问该静态路由；无需认证。
- 客户端发出的请求路径必须保留 `../` 原始字节（不能用会规范化路径的 HTTP 库）。

# 利用步骤

1. 确认目标注册的静态前缀（默认或从源码/配置获取，如 `/assets/`）。
2. 用不规范化路径的客户端（Java HttpUtil、curl --path-as-is、原生 socket）请求 `/assets/../../../app/assets/dashboard.css` 验证穿越（返回 200 与文件内容）。
3. 变更穿越深度读取任意文件：`/assets/../../../app/app.jar` 下载应用 jar。
4. 反编译 jar 提取硬编码敏感值（如后门路由比较用的 key 常量）。
5. 用 key 请求受保护接口/后门路由（如 `/backdoor?key=...`）完成最终利用（读环境变量 FLAG）。

# PoC

```java
// Java 端：requests 类客户端会规范化 ..，用 Java 原样发送
String url = "http://target:port/assets/../../../app/app.jar";
HttpUtil.createGet(url).execute().writeBody(new File("app.jar"));
// curl 等价: curl --path-as-is http://target:port/assets/../../../app/app.jar -o app.jar
```

原文实测：`GET /assets/../../../app/assets/dashboard.css` 返回 200 OK（smart-http server，Content-Type text/css），jar 下载后反编译取得 realkey，提交 `/backdoor?key=<realkey>` 返回 flag。

# 变体与关联

- 客户端规范化是此类利用的普遍坑：Python requests/httpx、Go net/http 等默认会在发送前合并 `..`；对应绕过思路是 `--path-as-is`、原生 socket、或用 `%2e%2e%2f` 等编码变体（视服务端解码行为而定）。
- 与 Solon 框架其他利用卡（filter memshell、route memshell）同属 solon 攻击面；本卡是框架自带静态文件服务的未授权任意读。
- 同类 sink：一切「前缀匹配后 substring 拼文件路径」的静态资源实现（Spring 的 ResourceHandler 有单独的规范化逻辑可对比）。

# 检测与防御

- 升级 Solon >= 3.0.9（补丁加入 `path.contains("/../")` 拒绝）。
- 更彻底的修法是在 `FileStaticRepository.find` 内做 canonical path 校验：解析后确认结果仍位于仓库根目录内（防多级编码与符号链接）。
- WAF/网关侧对静态资源路径中的 `../`、`..%2f` 变体告警拦截。
- 检测：访问日志中出现以合法静态前缀开头但含 `..` 的 200 响应，或对 jar/war/class 等非常见静态资源的读取。
