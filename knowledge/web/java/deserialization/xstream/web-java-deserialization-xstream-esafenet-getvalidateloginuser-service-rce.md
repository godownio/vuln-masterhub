---
id: web-java-deserialization-xstream-esafenet-getvalidateloginuser-service-rce
title: 亿赛通 GetValidateLoginUserService：请求体经 CodeDecoder 解密后直接 XStream 1.4.9 fromXML，ttt 头命令执行回显
type: scenario
domain: web
path: web/java/deserialization/xstream
technique: esafenet-getvalidateloginuser-xstream-fromxml-rce
aliases:
- 亿赛通 XStream 反序列化
- GetValidateLoginUserService
- 亿赛通 CDG XStream RCE
- ServiceUtil.getXMLFromRequest
- xstream-1.4.9
- CodeDecoder 解密 XML
tags:
- java
- esafenet
- cdg
- xstream
- deserialization
- rce
- servlet
- oa
cve: []
affected_versions: XStream 1.4.9
severity: critical
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V668
  verified_at: '2026-11-13T09:57:54+08:00'
  notes: '已对照原文与截图核对：WEB-INF/lib 存在 xstream-1.4.9.jar（原文显式称该版本存在反序列化漏洞，已 set-versions）；GetValidateLoginUserService.service 中 ServiceUtil.getXMLFromRequest 后直接 stream.fromXML；decodeString 走 CodeDecoder.getTransferUnEncriptString + Decode(ISO8859-1)；ttt: whoami 请求返回 nt authority\system（Content-Length 29724）。未验证点：截图将 servlet 映射路径打码、完整 payload 未公开，gadget 链与路径需按目标环境实测，未在原文之外复跑。'
---

## 一句话结论

亿赛通 CDG 的 `GetValidateLoginUserService` servlet 在 `service()` 中把请求体经 `ServiceUtil.getXMLFromRequest(request)`（内部 `CodeDecoder.getTransferUnEncriptString` + `CodeDecoder.Decode` 解密）还原成 XML 字符串后，直接 `stream.fromXML(toServerXML)`；classpath 中的 `xstream-1.4.9.jar` 存在反序列化利用链，攻击者按产品编码方式加密 XStream 恶意 XML 作为请求体，即可在服务端执行命令（原文以 `ttt: whoami` 请求返回 `nt authority\system` 验证）。

## 原理

- **依赖版本**：安装包 `WEB-INF/lib` 中存在 `xstream-1.4.9.jar`；XStream 1.4.9 未默认启用类型白名单，`fromXML` 可实例化任意可被 gadget 利用的类，构成反序列化 RCE 的经典前提。
- **入口代码**：`GetValidateLoginUserService.service(req, resp)` 中 `stream = ServiceUtil.getStream()`（构造 XStream 实例），`toServerXML = ServiceUtil.getXMLFromRequest(request)`，随后 `gvl = (GetValidateLoginUser1) stream.fromXML(toServerXML)`，异常被 catch 后仅记录日志/返回 ERROR，没有对 XML 内容做任何校验。
- **请求体解密**：`ServiceUtil.getXMLFromRequest` 调用 `getXMLFromRequest0(request).toString()` 后交给 `decodeString`；`decodeString` 先 `CodeDecoder.getTransferUnEncriptString(info)`，再按 ISO8859-1 取字节调用 `CodeDecoder.Decode(abyte2, nLength, abyte0)`，最后 `new String(abyte2)` 返回。即客户端不能直接发送明文 XML，必须按产品的编码/加密方式处理（原文正文称为先用 `CDGUtil.encode` 加密）。
- **利用**：把 XStream 反序列化 payload（XML 形式的 gadget 链，最终触发 ProcessBuilder/命令执行）按上述方式加密后作为 POST body 发送到该 servlet 的映射路径；原文截图中请求另带 `ttt: whoami` 头，响应体返回 `nt authority\system`，证明命令在 SYSTEM 权限下执行且输出可回显。
- **为什么有效**：服务端把“解密后”的客户端输入直接交给一个已知可被利用的 XStream 版本做反序列化，加密只是传输编码，不构成完整性或来源校验；任何能构造该编码的客户端都能送达任意 XML。
- **边界**：原文未公开完整 XStream payload 与 servlet 映射路径（截图打码），复现需自行从 `web.xml` 定位 `GetValidateLoginUserService` 映射并按目标 classpath 选择可用 XStream gadget；`decodeString` 的密钥/参数由产品实现决定，需用目标 jar 生成；xstream 1.4.9 在部分 JDK/依赖组合下 gadget 可用性不同。

## 触发条件

- 目标为亿赛通 CDG（CDGServer3），`WEB-INF/lib` 含 `xstream-1.4.9.jar`。
- `GetValidateLoginUserService` 的 servlet 映射可达（原文未给路径，需查 web.xml）。
- 服务端可加载可被 XStream 利用的 gadget 依赖（classpath 需满足具体链；原文环境为 Java 8）。
- 攻击者能调用产品 jar 的 `CodeDecoder`/编码函数（或复现其算法）生成加密 XML 请求体。

## 利用步骤

1. 审计安装包的 `web.xml`，找到 `GetValidateLoginUserService` 的 `url-pattern`；确认 `lib` 下 `xstream-1.4.9.jar`。
2. 使用 ysoserial 等工具生成 XStream 格式的反序列化 payload（XML），选择目标 classpath 可用的 gadget（如基于 ProcessBuilder 的链）。
3. 按 `CodeDecoder.getTransferUnEncriptString` + `CodeDecoder.Decode` 的逆过程加密 payload，作为 POST body。
4. 发送 `POST /CDGServer3/<映射路径>`，携带触发命令的请求头/参数（原文为 `ttt: whoami`），Content-Length 约 30KB。
5. 响应 200，body 返回命令输出（原文 `nt authority\system`）；替换命令即可继续利用。

## PoC

```http
POST /CDGServer3/<GetValidateLoginUserService 映射路径> HTTP/1.1
Host: 192.168.37.130:8443
Connection: close
ttt: whoami
Content-Length: 29724

<经 CodeDecoder/CDGUtil 编码的 XStream 反序列化 XML payload>
```

说明：原文截图将 servlet 路径打码、payload 为长密文，故此处以占位表示；关键点是 `ttt: whoami` 头与加密后的 XStream XML 请求体。响应体原文为 `nt authority\system`。未在原文之外复跑。

## 变体与关联

- [[web-java-component-esafenet-cdg-importpolicy-deserialization-rce]]：同产品 `dlpPolicy/importPolicy.do` 的原生 `byteToObject` 反序列化（DES 解密 + CC1），入口与反序列化库均不同。
- [[web-java-deserialization-xstream-weaver-workflowservicexml-unauth-rce]]：泛微 OA 的 XStream 1.3 未授权反序列化，同属“产品把请求 XML 直接 fromXML”模式。
- [[web-java-deserialization-xstream-type-permission-bypass]]：XStream 4 类型白名单绕过技巧，适用于目标升级但仍使用 XStream 的场景。
- 变体：XStream payload 可换 CVE-2021-29505 的 RegistryImpl_Stub/JRMP 二次反序列化思路；命令回显可改为 DNSLog 外带或写文件。
- 边界：映射路径、编码密钥与 gadget 依赖需按目标 jar/classpath 实测；若目标升级 XStream 并启用白名单则链失效。

## 检测与防御

- 检测：`GetValidateLoginUserService` 等 servlet 收到大体积（数十 KB）非明文 XML 的请求体，随后出现 Command/ProcessBuilder 子进程；响应体直接返回系统命令输出。
- 检测：classpath 存在 `xstream-1.4.9.jar` 且代码中 `fromXML` 处理 request 输入；可结合组件清单扫描。
- 防御：升级 XStream 并启用类型白名单（`allowTypes`/`denyTypes`），或改用安全 XML 解析；对入口增加鉴权与输入校验；限制服务端出网与外联；WAF 对异常大体积加密 POST 做告警。
- 响应：定位并删除被反序列化利用写入的载荷、排查同批请求与命令执行痕迹。
