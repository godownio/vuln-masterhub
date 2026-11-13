---
id: web-java-component-seeyon-ctpsecurityfilter-servlet-auth-gap
title: 致远 OA CTPSecurityFilter 鉴权链：ServletAuthenticator 白名单只覆盖部分 servlet，其余落入无校验 defaultAuthenticator
type: scenario
domain: web
path: web/java/component
technique: seeyon-ctpsecurityfilter-servlet-authenticator-whitelist-gap
tags:
- seeyon
- oa
- java
- auth-bypass
- servlet
- filter
- webxml
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V625
  verified_at: '2026-11-12T22:16:43+08:00'
  notes: 已对照原文与全部15张图核对：图02 web.xml SecurityFilter映射*.do/*.jsp/*.jspx、图03 cfgHome/spring目录、图04 doFilter→authenticate、图05 AttackURIAuthenticator.isUnAttackUri分派与defaultAuthenticator兜底、图06 isServlet→ServletAuthenticator.accept、图07 accept逻辑(.psml结尾直接true，否则servlets列表startsWith)、图08 servlets(getAJAXMessageServlet/getAJAXOnlineServlet等)与anonymousWhiteList(login/sso、verifyCodeImage.jpg)均与卡片一致。图09 defaultAuthenticator：validate恒return true，authenticate仅contextPath根路径true其余false——卡片已如实标注该细节并保留原文『默认认证器无有效校验』结论，措辞谨慎。已修正触发条件中原文未提及的『A8/V8』产品版本猜测。版本：原文无标记，affected_versions不设。dedup：与rest-changepassword(isSpringController/isRest分派顺序)、xrdcontroller(登录后复制穿越)、thirdpartycontroller(@NeedlessCheckLogin)等既有致远卡为不同servlet/不同认证器/不同sink，非同链；dup-scan.json无涉及pair。原子性：本卡为CTPSecurityFilter/ServletAuthenticator白名单缺口这一通用鉴权根因与找法，与具体漏洞卡互补保留。
url: /docs/web/java/component/web-java-component-seeyon-ctpsecurityfilter-servlet-auth-gap/
draft: false
kb_aliases:
- 致远 OA 鉴权分析
- CTPSecurityFilter
- ServletAuthenticator
- defaultAuthenticator
- seeyon 未授权 servlet
- .psml 白名单
---

## 一句话结论

致远 OA 的核心认证入口是 `CTPSecurityFilter`（web.xml 中映射 `*.do`/`*.jsp`/`*.jspx` 及个别 servlet 路径）；其 `authenticate` 按 URI 类型分派到不同 Authenticator，而 servlet 类型由 `ServletAuthenticator.accept` 判定——只有 URI 以 `.psml` 结尾或以硬编码 `servlets` 列表中的名字开头才进入真正的 servlet 认证，web.xml 里定义但不在该列表的 servlet 会落入 `defaultAuthenticator`（`validate` 恒返回 true），从而成为无需登录即可调用的未授权入口。

## 原理

- **路由与过滤器的位置**：核心配置在 `/seeyon/WEB-INF/web.xml`；`CTPSecurityFilter` 是权限校验过滤器，同时映射 `.do/.jsp/.jspx` 与 `/wpsAssistServlet` 这类具体 servlet。Spring 路由定义在 `WEB-INF/cfgHome/spring/*.xml` 中（本系统用 xml 而非注解定义）。
- **认证分派链**：`doFilter` 调 `authenticate(request,response)`，先做 `isUnAttackUri` 检查，再按 URI 特征依次分派：Spring Controller → `controllerAuthenticator`；token → `tokenAuthenticator`；Ajax/Rest/V3xAjax/SOAP/JSP 各有认证器；`isServlet` → `ServletAuthenticator`；`webOfficeAuthenticator`；最后兜底 `defaultAuthenticator`。
- **白名单缺口**：`ServletAuthenticator.accept` 的逻辑是：URI 去掉 contextPath 后，若以 `.psml` 结尾直接返回 true；否则遍历静态列表 `servlets`（`getAJAXMessageServlet`、`getAJAXOnlineServlet` 等硬编码项），URI 以列表项开头才算 servlet 请求。web.xml 中注册的 servlet 数量多于该列表，未覆盖的 servlet 不进入 `ServletAuthenticator`，落到 `defaultAuthenticator`。
- **defaultAuthenticator 不做校验**：其 `validate` 直接 `return true`（authenticate 仅对 contextPath 根路径返回 true，其余记日志后返回 false，最终放行判断按过滤器对返回结果的处理执行）；原文结论是默认认证器未对 URI 做有效校验。这意味着"web.xml 有、列表没有"的 servlet 事实上没有登录门槛，攻击面取决于该 servlet 的业务逻辑是否敏感。
- **为什么可复用**：这是致远 OA 系列未授权漏洞的通用找法——先枚举 web.xml servlet 与 `ServletAuthenticator.servlets` 的差集，再逐个看差集 servlet 的 doGet/doPost 是否直接操作文件/数据库/登录态，即可定位新的未授权入口，而不必等待单个 CVE 公开。

## 触发条件

- 目标为致远 OA（Seeyon）中使用 `CTPSecurityFilter` + Spring xml 路由的版本（原文未标注具体版本，需以目标 web.xml 与反编译结果确认）。
- 目标 servlet 在 web.xml 中注册且可被外部访问，但不在 `ServletAuthenticator.servlets` 白名单中（或 URI 不满足白名单 startsWith 条件）。
- 该 servlet 的业务处理逻辑包含敏感操作（文件读写/上传、用户信息、配置修改等）。

## 利用步骤

1. 获取目标版本对应的 web.xml（`/seeyon/WEB-INF/web.xml`，可从安装包/源码或泄露文件获得），列出全部 `<servlet>` 与 `<servlet-mapping>`。
2. 反编译 `WEB-INF/lib` 中包含 `CTPSecurityFilter`/`ServletAuthenticator` 的 jar，提取 `servlets` 静态列表与 `defaultAuthenticator` 实现。
3. 求差集：web.xml 中注册 URL 模式减去 `.psml` 规则与 `servlets` 列表覆盖范围，得到走 defaultAuthenticator 的 servlet 集合。
4. 对差集中的每个 servlet 阅读 doGet/doPost/业务 Service，寻找可直接滥用的敏感逻辑（如 wpsAssistServlet 的 save 上传）。
5. 用未登录会话直接请求该 servlet 验证是否 200 且业务生效；再据此构造完整利用链。

## PoC

无独立请求 PoC（分析流程卡）。核心判断逻辑（原文反编译代码要点）：

```java
// ServletAuthenticator.accept
String uri = request.getRequestURI().substring(contextPath.length() + 1);
if (uri.endsWith(".psml")) return true;
for (String s : servlets) {          // 硬编码白名单：getAJAXMessageServlet 等
    if (uri.startsWith(s)) return true;
}
return false;                        // 不在白名单 -> 不进入 ServletAuthenticator

// defaultAuthenticator（兜底）
public boolean validate(String uri, HttpServletRequest req) { return true; }
```

## 变体与关联

- 关联：[[web-java-component-seeyon-wpsassistservlet-realfiletype-upload-traversal]]（本卡鉴权缺口的具体利用实例）；库内其他致远 OA 未授权/穿越卡：[[web-java-component-seeyon-rest-changepassword-dotdo-auth-bypass]]、[[web-java-component-seeyon-xrdcontroller-checkissign-file-copy-traversal]]、[[web-java-component-seeyon-ofd-unzip-zipslip-webshell-write]]、[[web-java-component-seeyon-officeservlet-imsgserver2000-file-read]]、[[web-java-component-seeyon-thirdpartycontroller-enc-arbitrary-user-login]]。
- 变体：`anonymousWhiteList`（login/sso、verifyCodeImage.jpg 等）是另一套匿名放行名单，同样值得核对；`.psml` 后缀直接放行规则可被结合文件解析/上传利用。

## 检测与防御

- 厂商侧：升级到修复版本，把全部 servlet 纳入统一鉴权（白名单改为按 servlet 名全量默认拒绝，或每个 servlet 内部强制校验会话）。
- 防护侧：WAF/网关对已知敏感 servlet 路径（wpsAssistServlet 等）默认拒绝未登录请求；对 OA 外网暴露面做资产测绘与补丁核对。
- 检测：审计访问日志中直接命中 servlet 路径（非 .do/.jsp）且无登录流程的请求；关注 `flag=save`、路径穿越字符（`../`）等特征。
- 边界：不同小版本的 servlets 列表与过滤器实现存在差异，需以目标版本反编译结果为准。
