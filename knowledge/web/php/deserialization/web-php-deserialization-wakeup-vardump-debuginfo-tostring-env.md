---
id: web-php-deserialization-wakeup-vardump-debuginfo-tostring-env
title: PHP 反序列化 POP 链新跳板：__wakeup 里的 var_dump 触发 __debugInfo，再经 echo 触发 __toString 读取环境变量
type: scenario
domain: web
path: web/php/deserialization
technique: php-wakeup-vardump-debuginfo-tostring-env-read
aliases:
- __debugInfo POP 链
- var_dump 触发 __debugInfo
- __debugInfo 触发 __toString
- 反序列化读 getenv FLAG
tags:
- php
- deserialization
- pop-chain
- magic-method
- debuginfo
- tostring
- env-leak
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:47:38+08:00'
  notes: 已对照原文核对；本次核对未读取图片；魔术方法链 wakeup->var_dump->__debugInfo->echo->__toString->getenv 与原文 ezphp 源码一致，PoC 对象图与正文 payload 相符；链尾实际返回 getenv(FLAG) 而非任意命令执行，危害限于环境变量泄露；原文为 CTF 题，无受影响版本
---

## 一句话结论

当入口类的 `__wakeup()` 对某个属性调用 `var_dump()`，而该属性对象的 `__debugInfo()` 里又对另一个对象做 `echo` 时，反序列化会自动走 `__wakeup → __debugInfo → __toString` 三个魔术方法；把链尾对象的 `__toString()` 返回值设为 `getenv(...)`（或任何敏感读取）即可在不出现任何显式危险函数调用的情况下把环境变量带进响应。

## 原理

- **`__wakeup` 是反序列化自动入口**：`unserialize()` 重建对象后会立刻调用该对象的 `__wakeup()`，无需业务代码显式调用，因此它是最常见的链头之一。
- **`var_dump()` 会调用 `__debugInfo()`**：PHP 5.6 起，`var_dump($obj)`、`print_r($obj)` 在对象定义了 `__debugInfo()` 时改用其返回数组作为调试输出，而不是遍历真实属性。也就是说 `__wakeup()` 里一句 `var_dump($this->log)` 就构成了“从链头进入另一类对象方法”的跳板。
- **`echo $obj` 会调用 `__toString()`**：`__debugInfo()` 内部再对该对象的属性做字符串拼接/`echo`，就会触发链尾对象的 `__toString()`。
- **为什么能读到敏感数据**：`__toString()` 只需 `return getenv("FLAG")`（或 `file_get_contents`、`phpinfo()` 等）即可；整条链上没有 `system`、`eval`、`include` 等关键字，静态审计只看 sink 名时容易漏掉。
- **链形**：`Logger::__wakeup()` → `var_dump($log)` → `DataProcessor::__debugInfo()` → `echo $processor` → `SensitiveData::__toString()` → `getenv("FLAG")` 回显。

## 触发条件

- 存在用户可控的 `unserialize()`（参数、Cookie、缓存、队列消息等）。
- 链上三个类都被自动加载且属性可控：链头类有 `__wakeup()` 且对属性做 `var_dump`/`print_r`，中间类有 `__debugInfo()` 且对属性做字符串化，链尾类有 `__toString()` 且返回敏感内容。
- 目标进程环境变量或可读文件中确实存在目标数据（本题 flag 在环境变量里）。

## 利用步骤

1. 审计源码，把所有 `__wakeup`/`__destruct`/`__toString`/`__debugInfo`/`__invoke` 列出来，标出“把属性当字符串用”“对属性做 var_dump/print_r”“对属性做函数调用”三类的落点。
2. 确认 `var_dump($this->x)` 的目标对象定义了 `__debugInfo()`；确认 `__debugInfo()` 中有 `echo $this->y` 之类会字符串化 `y` 的语句。
3. 按链序构造对象图：链头 `log = DataProcessor`，`DataProcessor->data` 置真值让分支走进 `echo $this->processor`，`processor = SensitiveData`。
4. 本地 `serialize()` 后 URL 编码，作为参数提交给反序列化入口。
5. 在响应中读取回显（本题直接返回环境变量 FLAG）。

## PoC

```php
<?php
class SensitiveData {
    public function __toString() { return getenv("FLAG"); }
}
class Logger {
    public $log;
    public function __wakeup() { var_dump($this->log); }   // 触发 __debugInfo
}
class DataProcessor {
    public $data;
    public $processor;
    public $errorHandler;
    public function __debugInfo() {
        $this->errorHandler = new ErrorHandler();
        if ($this->data) { echo $this->processor; }        // 触发 __toString
        else { echo ($this->errorHandler)(); }
    }
}

$p = new DataProcessor();
$p->data = 1;
$p->processor = new SensitiveData();
$l = new Logger();
$l->log = $p;
echo urlencode(serialize($l));
```

```text
GET /?data=<urlencode(serialize(Logger{log:DataProcessor{data:1,processor:SensitiveData}}))> HTTP/1.1
```

说明：PoC 为按原文给出的对象图还原，未在本机运行；`ErrorHandler` 类仅在 `data` 为假的分支用到，构造时不需要它存在。

## 变体与关联

- **跳板替换**：`print_r`、`var_export`（部分版本）、`debug_zval_dump` 等“调试输出”函数同样会走 `__debugInfo`；反序列化后若业务把对象交给 `json_encode`，则可能走 `JsonSerializable::jsonSerialize`。
- **字符串化触发点**：`echo`、字符串拼接、`preg_match`、`strlen`、`in_array`、`die()`/`exit()` 传对象都会触发 `__toString`。
- **链头替换**：`__destruct`（对象释放时自动调用）同样可用，且不依赖 `unserialize` 成功后的显式调用。
- **关联**：`web-php-deserialization-wakeup-pregmatch-tostring-get-invoke-read`（`__wakeup` 里 `preg_match` 触发 `__toString` 的另一形态，链尾是文件读）、`web-php-deserialization-destruct-tostring-set-invoke-pop-system`（`__destruct`→`__toString`→`__set`→`__invoke` 到 `system`）。
- **边界**：PHP 8 下 `__debugInfo` 仍会被 `var_dump` 调用；若目标类被 `__serialize`/`__unserialize` 覆盖或启用 `allowed_classes` 白名单，链不成立。

## 检测与防御

- **代码层**：不要在 `__wakeup`/`__destruct` 里对属性做 `var_dump`/`print_r`/`echo`；`__debugInfo` 与 `__toString` 不得返回环境变量、文件内容、配置等敏感值；对 `unserialize` 使用 `allowed_classes` 白名单，或改用 JSON。
- **数据层**：`unserialize` 的输入不要来自请求参数；必须传输对象时使用签名（HMAC）+ 固定类白名单，并校验签名后再反序列化。
- **检测**：请求参数/Cookie 中出现 `O:`、`s:`、`a:` 等序列化特征并与常规业务字段不符；响应体出现预期外的环境变量、密钥、路径；日志中出现 `__wakeup`/`__debugInfo` 相关的 `var_dump` 输出格式。
- **加固**：生产环境关闭 `display_errors`，避免调试输出直接进响应；对 `getenv`/`phpinfo`/`file_get_contents` 等函数做 RASP 级监控。
