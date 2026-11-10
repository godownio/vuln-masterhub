---
id: web-java-rce-godzilla-jsp-404-fake-response-findstr-custom-marker
title: 哥斯拉 JSP 马改模板返回伪 404 页 + 客户端 findStr 换自定义前后缀，抹掉 md5(pass+key) 前后 16 位的标准流量指纹
type: scenario
domain: web
path: web/java/rce
technique: godzilla-jsp-404-fake-response-custom-findstr
aliases:
- 哥斯拉流量特征规避
- Godzilla 伪404 响应
- 自定义 findStr 前后缀
- md5(pass+key) 指纹
- var Re<md5>_config 回显
- 哥斯拉 WAF 绕过
tags:
- java
- jsp
- webshell
- godzilla
- traffic-evasion
- waf-bypass
- findstr
- 404-fake-page
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:51:13+08:00'
  notes: 已对照原文核对：Cryption.init 里 findStrLeft/findStrRight 取 md5(pass+key) 前16/后16、decode 用 subMiddleStr 截取、JSP 模板 md5.substring(0,16)+base64(AES)+md5.substring(16) 的拼接、Z-Godzilla_ekp 把标记改为 var Re<md5前5位>_config= 与 ;、伪 404 用 response.setStatus(404)+Page not found，均与正文一致；注意原文两端标记大小写不一致（模板 .toLowerCase()、客户端未转小写），卡内照录未改，实际连通性未验证；本次核对未读取图片，BP 抓包与 404 回显截图未核实；未编译客户端/未对真实目标执行。
---

## 一句话结论

标准哥斯拉 JSP 马的响应把回显夹在 `md5(pass+key)` 的**前 16 位十六进制**和**后 16 位十六进制**之间，客户端 `findStr()` 也按这两个固定串截取，因此「md5 前缀 + Base64 密文 + md5 后缀」成为最稳的流量指纹；只要同时改服务端模板（把回显包进一段正常 HTML/JS，甚至直接 `response.setStatus(404)` 返回「Page not found」）和客户端 `findStrLeft/findStrRight`（换成 `var Re<md5(pass+key)[:5]>_config=` 到 `;` 这类半固定标记），就能让响应在流量侧看起来是一个 404 或普通前端页面，而连接与命令执行照常。

## 原理

- **协议对称性**：哥斯拉的 `Cryption` 在 `decode()` 里先 `functions.base64Decode(findStr(data))` 再 AES 解密；`findStr()` 实现为 `subMiddleStr(resp, findStrLeft, findStrRight)`，即只截取左右标记之间的字符串。左右标记在 `Cryption.init()` 里由 `md5(pass + key)` 生成：`substring(0,16)` 与 `substring(16)`。
- **为什么是指纹**：服务端模板固定写 `md5.substring(0,16) + base64(AES(回显)) + md5.substring(16)`，所以任何抓包都能看到「16 位大写十六进制 … Base64 … 16 位大写十六进制」这种结构；解码流程固定为「按左右标记截取 → Base64 → AES」，IDS/WAF 只要匹配这个结构就能判定为哥斯拉。
- **改两端即可**：模板与 `findStr` 是同一协议的两半，服务端换成任意 HTML（`<!DOCTYPE html><html>…<script>var ReXXXXX_config=<密文>;</script>…</html>`），客户端把 `findStrLeft` 改成 `"var Re" + md5prefix + "_config="`、`findStrRight` 改成 `";"`，两端一致后协议照旧可用，但外层已是正常页面结构。
- **更省事的伪装**：直接在模板里 `response.setStatus(404); response.getWriter().write("Page not found");` 再输出密文，命令回显仍能拿到，只是响应状态码与正文变成了 404 页——而防守方常按状态码过滤流量（只看 200）。
- **边界**：换 `findStr` 只改「外壳」，AES 加密、session 持久化 payload、首包大后续包小的行为特征都还在；模板伪装 404 也只影响流量外观，文件本身仍是 JSP 马。

## 触发条件

- 已获得哥斯拉源码（或反编译版）并能在本地重新编译客户端、生成配套 JSP 马。
- 目标可上传/落地 JSP 文件，且 Tomcat 等容器按 JSP 解析。
- 服务端未对响应正文做严格的内容类型/长度一致性校验，允许 JSP 自行 `setStatus(404)` 并输出任意 HTML。

## 利用步骤

1. 用哥斯拉生成一个 `JAVA_AES_BASE64`（或 `JAVA_AES_RAW`）载荷的 JSP 马，记下 `pass` 与 `key`。
2. 改服务端模板：在原本输出 `md5.substring(0,16)` 与 `md5.substring(16)` 的位置，改成输出一段正常 HTML/JS 外壳，把 `base64Encode(x(arrOut.toByteArray(), true))` 夹在自定义标记之间；需要更强隐蔽时在 try 开头加 `response.setStatus(404);` 并输出 `Page not found`。
3. 改客户端 `Cryption.init()` 的 `findStrLeft/findStrRight`：例如 `findStrLeft = "var Re" + md5Prefix + "_config="`（`md5Prefix = md5(pass+key).substring(0,5)`）、`findStrRight = ";"`，`md5Prefix` 用于让标记随 key 变化，避免变成新的固定字符串。
4. 重新编译客户端 jar，用新客户端连接目标，确认 `test()` 返回成功（连接测试会发两次相同流量，属正常）。
5. 抓包确认响应已是 404 页面或普通 HTML+JS 结构，标准哥斯拉指纹（md5 前后 16 位）消失。

## PoC

```jsp
<%
    // 伪 404 + 自定义标记外壳（放在原本输出 md5/回显的位置）
    response.setStatus(404);
    response.setContentType("text/html");
    response.getWriter().write("Page not found");
    response.getWriter().write("<script>var Re" + md5.substring(0, 5).toLowerCase() + "_config=");
    response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));
    response.getWriter().write(";</script>");
%>
```

```java
// 客户端：Cryption.init() 中的 findStr 相关逻辑
String findStrMd5 = functions.md5(this.pass + new String(this.key));
String md5Prefix   = findStrMd5.substring(0, 5);
this.findStrLeft   = ("var ReXXXXX_config=").replace("XXXXX", md5Prefix);
this.findStrRight  = ";";
```

```text
效果：响应为 HTTP/1.1 404 + “Page not found” + <script>var Re<md5前5位>_config=<Base64>;</script>
客户端仍能按 var Re..._config= 与 ; 截出密文并解密，命令回显正常。
```

## 变体与关联

- **只改状态码**：不换 `findStr`，仅 `response.setStatus(404)` + 在密文前后套一层 HTML，可绕过「只看 200」的流量过滤（原文实测命令回显仍是 404）。
- **标记随 key 变化**：固定 `var Rebdsek_config=`（把 `bdsek` 替换为 md5 前 5 位）比硬编码固定串更稳，避免新外壳又变成可匹配指纹。
- **请求侧同样可改**：客户端把 `pass=<Base64>` 的形态换成其它参数名/参数个数，或改用自定义 `Cryption`（如栅栏换位）把请求也从「参数=Base64」变成普通表单字段。
- 关联：标准哥斯拉 JSP 流量识别与解密（按 md5 前后缀截取 → Base64 → AES）是本卡的对照基线；PHP 侧自定义 Cryption 混淆流量是同一「改外壳不改协议」思路的另一实现。

## 检测与防御

- 检测不能只依赖「md5 前后 16 位」这一条：改为结构化识别「响应体 = 短十六进制 + 长 Base64 + 短十六进制」「Cookie 头形态异常」「首包体积远大于后续包」「同一 URL 同时被 GET/POST 且响应 Content-Type 与正文不符」等多特征打分。
- 重点看 404/403 响应的**体积与内容**：正常 404 页很小且固定，伪 404 里夹着长 Base64 或 script 变量，应告警。
- 服务端：禁止上传目录解析 JSP；对 JSP 文件做静态扫描（`defineClass`、`base64Decode`、`session.setAttribute("payload")` 组合）；开启 WAF 对响应方向的 Base64 长串检测。
- 应急：命中可疑 JSP 后导出文件比对 md5/session 写入逻辑，删除马并清理 session；结合访问日志定位上传入口。
