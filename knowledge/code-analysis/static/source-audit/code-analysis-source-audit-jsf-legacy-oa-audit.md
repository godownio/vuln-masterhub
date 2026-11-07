---
id: code-analysis-source-audit-jsf-legacy-oa-audit
title: JSF 老 OA 源码审计：*.jsf→*.jsp 路由、ExtAbstractManagedBean 控制器与危险 Servlet 定位
type: scenario
domain: code-analysis
path: code-analysis/static/source-audit
technique: jsf-legacy-oa-source-audit
aliases:
- JSF OA 审计
- FacesServlet 路由审计
- ExtAbstractManagedBean 审计
- '*.jsf 映射 JSP'
- 老 OA 代码审计
- JSF 控制器定位
tags:
- code-audit
- java
- jsf
- faces
- oa
- servlet
- route-mapping
- source-audit
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V59
  verified_at: '2026-11-05T09:01:54+08:00'
  notes: 已对照原文与54张图核对：图02-04 web.xml FacesServlet映射*.jsf、DEFAULT_SUFFIX=.jsp；图05-08 h:commandButton action=#{dictionaryManagedBean...}、DictionaryManagedBean extends ExtAbstractManagedBean；图09-10 servlet-mapping清单与SessionFilter /workflow/pages/*；图11 JAF SQLExecutorFactory；图12-13 SessionFilter/UrlFCFilter映射；图27/31/36/39/44/49/52 危险servlet与sink。审计方法卡与原文一致，路径code-analysis/static/source-audit合法。未验证点：方法卡无独立PoC，仅rg命令示例；原文未给产品名/版本，未设affected_versions；frontmatter无sources/source_url。
---

## 一句话结论

面对基于 JSF 的旧 Java OA，先把 `FacesServlet`（映射 `*.jsf`）和 `javax.faces.DEFAULT_SUFFIX=.jsp` 还原成“请求 `/x/info.jsf` 实际渲染 `/x/info.jsp`”的真实路由，再用 `extends ExtAbstractManagedBean` 锁定 JSF 控制器（ManagedBean），用 `web.xml` 的 servlet/filter 映射枚举独立入口，最后按 `execute(`、`new RandomAccessFile`、`new FileInputStream`、`new DiskFileItemFactory()`、`.delete()` 等 sink 关键词收敛审计面。

## 原理

- **JSF 路由映射**：`web.xml` 中 `javax.faces.webapp.FacesServlet` 映射到 `*.jsf`，同时 `javax.faces.DEFAULT_SUFFIX` 配置为 `.jsp`。JSF 只把 `.jsf` 当作视图入口，实际渲染的是同路径的 `.jsp` 文件，因此审计时请求 `/admin/info.jsf` 应直接去读 `/admin/info.jsp`，而不是去找 `.jsf` 文件。
- **JSF 控制器识别**：视图里的 `<h:commandButton action="#{dictionaryManagedBean.searchBigDictionaryList}">` 通过 EL 调用后端 ManagedBean 方法。项目通常有统一基类，继承 `ExtAbstractManagedBean` 的类扮演 Controller 角色；全局搜索 `extends ExtAbstractManagedBean` 可一次列出所有业务入口 Bean，再逐个看其 public 方法是否被 JSP 的 `action`/`valueChangeListener` 引用。
- **多入口并存**：旧 OA 往往同时存在 JSF Bean、独立 `HttpServlet`（`web.xml` 的 `<servlet-mapping>`）、JSP 直出页面和 JSF 过滤器链。只看 JSF 会漏掉 `TransferDataServlet`、`LogFileDownloadServlet`、`CreatefwfromjoaServlet` 这类独立 servlet；只看 servlet 会漏掉 Bean 方法。
- **鉴权先建模**：先读 `web.xml` 的 `<filter>`/`<filter-mapping>`，确认每个 filter 保护哪些 `url-pattern`、对哪些 dispatcher 生效；再读 filter 源码，区分它取的是原始 `getRequestURI()` 还是规范化后的 `getServletPath()`。这一步决定后续漏洞是否“未授权可达”。
- **数据访问技术**：项目可能同时使用 MyBatis（`sqlmap-*.xml`、`#{}`/`${}`）和自研 JAF 框架的 `SQLExecutorFactory.getInstance().getSQLExecutor().execute(...)`。审计 SQL 注入时两种都要看：MyBatis 看 `${}`，自研执行器看 `Statement.execute` 的字符串拼接。
- **危险 sink 收敛**：在大量反编译 class 中按关键词扫，能快速定位文件读写、上传、删除、SQL 执行四类高风险点，再反向追参数来源。
- **为什么这样审计有效**：老 OA 的漏洞通常不是复杂逻辑漏洞，而是“请求参数 → 字符串拼接 → 危险 API”的直线链；先把路由和控制器映射建好，才能把 URL 参数准确接到 sink 上，避免在无关的框架胶水代码里浪费时间。

## 触发条件

- 拿到可反编译的 Java Web 项目（War/Jar/反编译 class），且项目使用 JSF（`FacesServlet`、`*.jsf`、`faces-config.xml`、`xhtml/jsp` 视图）。
- 项目规模较大，存在多个 ManagedBean、独立 servlet 和多种数据访问方式，人工逐文件阅读成本高。
- 审计目标是寻找可直接利用的注入、文件读写、上传、删除等场景，而不是只做合规检查。

## 利用步骤

1. 解压并反编译，按目录识别 `WEB-INF/web.xml`、`faces-config.xml`、`applicationContext*.xml`、`sqlmap-*.xml`。
2. 读 `web.xml`：记录 `FacesServlet` 的 `url-pattern`、`javax.faces.DEFAULT_SUFFIX`、所有 `<servlet>`/`<servlet-mapping>`、所有 `<filter>`/`<filter-mapping>`（含 `dispatcher`）。
3. 建立路由表：把每个 `*.jsf` 请求映射到对应 `.jsp`；把每个独立 servlet 的 `url-pattern` 与类名对应起来。
4. 搜索 `extends ExtAbstractManagedBean`，列出全部 ManagedBean；再在 JSP/XHTML 中搜 `#{beanName.method`，确认哪些 Bean 方法可被外部触发。
5. 按 sink 关键词扫危险点：
   - SQL：`.execute(`、`createStatement(`、`${`、字符串 `+` 拼 SQL；
   - 文件读：`new FileInputStream(`、`new RandomAccessFile(`、`new File(` + `getParameter`；
   - 上传：`DiskFileItemFactory`、`ServletFileUpload`、`FileItem.getFieldName()`、`getSfilename()`、`write(`；
   - 删除：`.delete()`、`Files.delete`、`removeFile`。
6. 对每个命中点回溯调用链到 `request.getParameter`/`FileItem`/JSF 绑定属性，确认参数可控性与鉴权可达性。
7. 记录完整链（入口 → 参数 → sink → 最终危害），再构造最小 PoC。

## PoC

审计命令示例（ripgrep，路径按项目调整）：

```bash
# 1. JSF 路由与默认后缀
rg -n "FacesServlet|DEFAULT_SUFFIX|url-pattern>\*\.jsf" -g 'web.xml'

# 2. 控制器清单
rg -n "extends ExtAbstractManagedBean" --glob '*.java'

# 3. 视图到 Bean 方法的绑定
rg -n "action=\"#\{" --glob '*.jsp' --glob '*.xhtml'

# 4. 危险 sink
rg -n "\.execute\(|new RandomAccessFile\(|new FileInputStream\(|DiskFileItemFactory|\.delete\(\)" --glob '*.java'
```

路由还原示例：

```text
请求 /admin/info.jsf
  --> FacesServlet（*.jsf）
  --> javax.faces.DEFAULT_SUFFIX=.jsp
  --> 实际渲染 /admin/info.jsp
```

## 变体与关联

- **视图技术差异**：`DEFAULT_SUFFIX` 也可能是 `.xhtml`；此时 `.jsf` 请求渲染的是 XHTML 视图，业务代码仍在 ManagedBean 中。按 `DEFAULT_SUFFIX` 实际值还原。
- **控制器基类差异**：并非所有 JSF 项目都用 `ExtAbstractManagedBean`；可改用 `@ManagedBean`/`@Named` 注解、`faces-config.xml` 的 `<managed-bean>` 或公共基类名来枚举。
- **过滤器差异**：同一套代码可能有多个鉴权 Filter（本类项目同时存在基于 `getRequestURI()` 的 `SessionFilter` 和基于 `getServletPath()` 的 `UrlFCFilter`），必须分别判断是否可绕过。
- 关联：[[web-generic-auth-oa-jsf-sessionfilter-loginjsf-semicolon-bypass]]（本审计方法定位到的鉴权绕过）；[[web-generic-sqli-oa-jsf-tranformdomoa-multipart-field-sqli]]、[[web-generic-file-inclusion-oa-logfiledownload-createfwfromjoa-arbitrary-read]]、[[web-generic-file-upload-oa-jsf-transferdata-attachfile-getfieldname-traversal]]、[[web-java-oa-download-servlet-followup-delete-arbitrary-file]]（同一代码库中由该方法定位到的具体场景）。
- 关联：[[web-java-deserialization-myfaces-client-viewstate-el]]（JSF 视图状态反序列化，属于 JSF 的另一类风险面）。

## 检测与防御

- **审计侧**：在代码审计清单中固定“JSF 路由还原 → ManagedBean 枚举 → servlet/filter 枚举 → sink 关键词扫描 → 参数回溯”五步；对每个 sink 建立可达性矩阵（是否需要登录、是否被 filter 保护、是否可从 `.jsf` 路由到达）。
- **开发侧**：JSF 视图不要直接绑定可执行危险操作的 Bean 方法；ManagedBean 方法内对参数做白名单/类型校验；独立 servlet 统一接入鉴权 Filter。
- **部署侧**：老 OA 若无法升级，至少把危险 servlet 从公网可达面移除，或在反向代理层限制其路径；上传/导出目录移出 Web 根。
- **检测侧**：监控对 `*.jsf;*`、`/pages/*.jsf;`、`*.jsf` 后接异常路径参数的请求；监控 JSP 渲染路由被非正常参数触发的文件读写与异常 SQL 日志。
