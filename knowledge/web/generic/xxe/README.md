# XXE

## 这层是什么

XML 外部实体、盲 XXE、OOB 与绕过。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [Apache Tika PDF XFA 解析 XXE：extractAcroFormContent 默认开启触发外部实体（CVE-2025-66516）](web-generic-xxe-apache-tika-pdf-xfa-extractacroform.md) | verified | high | 2026-11-05 |
| [Artery ERP richclient.openForm 未授权 XXE：FormService 用 SAXReader 解析外部 XML 实体](web-generic-xxe-artery-erp-richclient-openform.md) | verified | high | 2026-11-07 |
| [data:text/xml;base64 上传包装 XXE：外部 DTD 参数实体把文件拼进 HTTP 请求外带](web-generic-xxe-data-uri-upload-external-dtd-oob.md) | verified | medium | 2026-11-07 |
| [dom4j DocumentHelper.parseText 解析请求 XML：XMLUtil.parseModXmlStr 有回显 XXE 文件读取](web-generic-xxe-dom4j-parsemodxmlstr-inband-read.md) | verified | medium | 2026-11-05 |
| [GeoServer WMS GetMap SLD 解析 XXE：SLDXmlRequestReader 传 null EntityResolver（CVE-2025-58360）](web-generic-xxe-geoserver-wms-getmap-sld.md) | verified | medium | 2026-11-05 |
| [Java XML 解析器默认允许外部实体导致有回显文件读取](web-generic-xxe-inband-file-read-default-insecure.md) | verified | high | 2026-11-05 |
| [Java XXE 用 netdoc/file 协议读取文件并列举目录](web-generic-xxe-java-netdoc-file-directory-listing.md) | verified | high | 2026-11-09 |
| [Java XXE 盲外带选 FTP：HTTP handler 拒绝 URL 换行，FTP 受 JDK 版本限制且匿名登录泄露 Java 版本](web-generic-xxe-java-ftp-oob-jdk-version.md) | verified | medium | 2026-11-09 |
| [Jelly 危险标签黑名单用同一份 XML 做校验：check 阶段 DocumentBuilderFactory 未禁 DTD，XXE 在校验时先行触发并 OOB 外带文件](web-generic-xxe-jelly-blacklist-check-documentbuilderfactory-parse.md) | verified | medium | 2026-11-09 |
| [JHSoft OA AddressImportPub.aspx 未加固 XmlDocument.LoadXml：DNSLog 外带验证 XXE](web-generic-xxe-jhsoft-addressimportpub-loadxml-dnslog.md) | verified | high | 2026-11-07 |
| [LangChain HTMLSectionSplitter 的 xslt_path 可控导致 XSLT document() XXE 任意文件读取（CVE-2025-6985）](web-generic-xxe-langchain-htmlsectionsplitter-xslt-document-file-read.md) | verified | high | 2026-11-06 |
| [lxml 解析可被属性污染写入的配置 XML：外部实体读文件（UTF-16BE 绕值级过滤）](web-generic-xxe-lxml-config-xml-pollution.md) | draft | medium | 2026-11-08 |
| [MetaCRM /services/ws CXF SOAP 服务 commonCheckServ 嵌套 XML XXE（盲外带）](web-generic-xxe-crm-cxf-soap-dom4j-nested-xml.md) | verified | high | 2026-11-07 |
| [Nacos-spring-context DefaultXmlConfigParse 未加固 DocumentBuilderFactory 导致配置 XML XXE](web-java-xxe-nacos-spring-context-config-parse.md) | verified | medium | 2026-11-05 |
| [OOXML/容器格式上传 XXE：docx/xlsx/pptx/odt/zip/PDF 内嵌 XML 部件被服务端解析时触发外部实体](web-generic-xxe-ooxml-container-upload.md) | verified | medium | 2026-11-08 |
| [SOAP 参数内嵌 XML 二次解析：JDOM SAXBuilder 未禁 DTD 导致 OOB XXE](web-generic-xxe-soap-parameter-nested-xml-saxbuilder-oob.md) | draft | medium | 2026-11-08 |
| [sobey-mchEditor AITaskBack 未授权 XXE：请求体直接交给 DocumentBuilderFactory 解析](web-generic-xxe-sobey-mcheditor-aitaskback-documentbuilderfactory.md) | verified | high | 2026-11-07 |
| [SVG 图片上传 XXE：image/svg+xml 解析外部实体读取任意文件](web-generic-xxe-svg-upload-inband-file-read.md) | verified | high | 2026-11-05 |
| [Ucum-java 的 DTD 未禁用导致 XXE：UcumEssenceService 构造参数与 XmlUtils.parseDOM 直接把外部 XML 流交给未配置的 DocumentBuilderFactory，可带内回显或打内网 HTTP](web-java-component-ucum-xmlutils-documentbuilderfactory-xxe.md) | verified | high | 2026-11-08 |
| [XML 上传点 XXE 过滤绕过：UTF-16BE 编码隐藏 DOCTYPE 并读取 SSH 私钥](web-generic-xxe-utf16be-encoding-filter-bypass.md) | verified | high | 2026-11-05 |
| [XXE + expect:// 包装器：PHP expect 扩展把外部实体解析升级为命令执行](web-generic-xxe-expect-wrapper-command-execution.md) | verified | medium | 2026-11-09 |
| [XXE + php://filter 双 Base64 链：SSRF 内网 LFI 读取源码与 flag](web-generic-xxe-php-filter-ssrf-internal-lfi-chain.md) | verified | high | 2026-11-06 |
| [XXE 关键字绕过：把 SYSTEM 的 file:// / http:// 目标塞进 data:// base64 外部参数实体](web-generic-xxe-data-uri-base64-hide-system-uri.md) | verified | medium | 2026-11-08 |
| [XXE 读含特殊字符文件：CDATA 实体包裹 + 外部 DTD 拼接 %start;%goodies;%end;](web-generic-xxe-cdata-parameter-entity-wrap.md) | verified | high | 2026-11-09 |
| [万户OA WeiXin!callback.action XXE：XMLParse.extract 未禁用外部实体，签名校验前解析](web-generic-xxe-whir-ezoffice-weixin-callback-xmlparse.md) | verified | high | 2026-11-07 |
| [东胜物流 UpdateCustomMainfast 未加固 XmlDocument.LoadXml 导致 XXE 文件读取](web-generic-xxe-dongsheng-logistics-custommainfast-loadxml.md) | verified | low | 2026-11-06 |
| [反射 XML 注释注入 XXE 驱动内网服务 SSRF 并二次读取文件](web-generic-xxe-reflected-xml-ssrf-internal-service.md) | verified | high | 2026-11-05 |
| [无外网盲 XXE：重定义目标本地 DTD 参数实体并借报错回显读取文件](web-generic-xxe-local-dtd-error-based.md) | verified | medium | 2026-11-09 |
| [未授权 SAML ACS 在签名校验前解析 XML 触发 XXE OOB](web-generic-xxe-saml-acs-parse-before-signature.md) | verified | high | 2026-11-05 |
| [盲 XXE 的 OOB 外带](oob-exfil.md) | draft | high | 2026-11-04 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
