---
id: web-php-deserialization-phar-prefix-filter-halt-compiler-rce
title: Phar 反序列化 RCE 链：php://filter 包裹绕过 ^phar:// 前缀检查 + 字符受限 eval + __halt_compiler 截断 + gzip 绕过上传内容检测
type: scenario
domain: web
path: web/php/deserialization
technique: phar-deserialization-prefix-bypass-restricted-eval
aliases:
- phar:// 前缀检查绕过
- php://filter resource=phar:// 触发反序列化
- __halt_compiler 截断 eval 拼接
- preg_replace 去字母后只留分号判等绕过
tags:
- php
- deserialization
- phar
- php-filter
- file-upload
- eval
- halt-compiler
- gzip-bypass
- rce
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-5
  verified_at: '2026-11-08T01:19:26+08:00'
  notes: 已对照原文核对：class.php 的 ^phar:// 前缀检查与字符受限 eval、php://filter 包裹绕过、gzip 绕过上传侧 __HALT_COMPILER 内容检测、__halt_compiler 截断均与原文及图20/22 system(ls) 成功输出一致；dedup rec=new 且 duplicate=0，dedup_review 理由成立（与 phar-read-uploaded-image-pop-chain 等候选在入口前缀检查、上传检测、eval 形态、触发条件与 PoC 上明显不同），按 append_scenario force add 合理；CTF 题无受影响版本标记；PoC 未独立执行
---

## 一句话结论

把恶意 `Phar` 包（metadata 为 `hacker` 对象）经 gzip 压缩绕过上传内容检测、改后缀为 png 上传；再用 `php://filter/read=convert.base64-encode/resource=phar:///tmp/xxx.png` 让 `file_get_contents()` 触发 Phar metadata 反序列化（phar:// 不在字符串开头，绕过 `^phar://` 前缀检查），进入 `hacker::__destruct()` 里字符受限的 `eval`：cmd 经两次 `preg_replace` 去掉字母/下划线/括号后只剩分号、被替换成 `hahaha` 满足判等，配合 `__halt_compiler()` 截断尾部拼接文本，执行任意命令读取 flag。

## 原理

- **Phar 反序列化触发**：`file_get_contents()` 等文件操作作用于 `phar://` 流时会解析 Phar 归档并把 metadata 反序列化；metadata 里的对象被还原，其 `__destruct()` 在对象销毁时执行。
- **前缀检查绕过**：`preg_match('/^phar:\/\//i', $_POST['file'])` 只要求字符串**不以** phar:// 开头。用 `php://filter/read=convert.base64-encode/resource=phar:///tmp/x.png` 作为最外层包装，phar:// 出现在 `resource=` 之后，正则不匹配；`php://filter` 与 phar 流可组合，读取时仍会触发 phar 解析。
- **上传 WAF 绕过**：上传点对文件内容做 `preg_match("/__HALT_COMPILER/i", FILE_CONTENTS)` 检测；把 phar 包 gzip 压缩后改后缀 png 上传，压缩后字节流中不再出现明文 `__HALT_COMPILER`，且 gzip 流仍可被 phar:// 识别（需按目标实现确认）。
- **受限字符 eval 绕过**：`__destruct()` 判等 `preg_replace('/;+/','hahaha', preg_replace('/[A-Za-z_\(\)]+/','', $this->cmd)) === 'hahaha'`。内层正则把 cmd 中所有字母、下划线、括号删除；若 cmd 只有 `字母(...);` 形式，删除后只剩一串分号 `;;`，外层把连续分号替换成 `hahaha`，判等成立。于是 `eval($this->cmd.'hahaha!')` 被执行——注意判等只检查"清理后的形态"，不限制原 cmd 内容。
- **`__halt_compiler()` 截断**：`eval` 拼接的尾部 `'hahaha!'` 会造成语法错误/干扰；在 cmd 末尾加 `__halt_compiler();` 让编译器停止解析，其后内容被当作纯文本忽略，保证前面的 `system(...)`/`highlight_file(...)` 正常执行。
- **无括号读文件**：cmd 允许字母但括号会被删（不影响 eval 执行的是原 cmd），用 `highlight_file(flag);__halt_compiler();` 高亮输出 flag 文件内容；或先 `system(ls)` 定位文件。
- 根因：Phar metadata 自动反序列化 + 对文件路径的黑名单只检查前缀 + 对代码执行输入做"形态过滤"而非语义校验。

## 触发条件

- 存在 `file_get_contents($_POST['file'])` 等接受用户可控路径、且支持流包装器的文件操作；
- 仅用 `^phar://` 前缀正则过滤路径，未禁止 `php://filter`/其它包装器组合；
- 可上传文件且知道上传后的路径；上传检测可被压缩绕过；
- 存在含 `__destruct()` 且会 `eval` 属性的类，且 PHP 允许 `phar://` 流、未禁用 `eval`/`system`/`highlight_file`。

## 利用步骤

1. 本地生成恶意 Phar：stub 用 `GIF89a<?php __HALT_COMPILER();?>`，metadata 为 `hacker` 对象，`cmd` 设为 `system(ls);__halt_compiler();`（或 `highlight_file(flag);__halt_compiler();`），并把 `$a` 引用指向 `$cmd` 以满足对象结构。
2. gzip 压缩 phar 包、改后缀为 png 上传，取得服务器保存路径（如 `/tmp/<hash>.png`）。
3. 提交 `file=php://filter/read=convert.base64-encode/resource=phar:///tmp/<hash>.png` 触发反序列化。
4. `__destruct` 判等通过后 `eval(cmd.'hahaha!')`，`__halt_compiler()` 截断尾部，命令执行/文件高亮输出。
5. 从 base64 解码后的响应中读取结果，必要时换 cmd 读取 flag 文件。

## PoC

```php
<?php
class hacker { public $a; public $cmd = ''; }
$phar = new Phar('phar.phar');
$phar->stopBuffering();
$phar->setStub('GIF89a' . '<?php __HALT_COMPILER();?>');
$phar->addFromString('test.txt', 'test');
$o = new hacker();
$o->cmd = 'highlight_file(flag);__halt_compiler();';
$o->a = &$o->cmd;
$phar->setMetadata($o);
$phar->stopBuffering();
?>
```

```text
POST file=php://filter/read=convert.base64-encode/resource=phar:///tmp/<uploaded>.png
```

说明：结构复现的通用 payload；phar 生成需在可写环境、目标需支持 phar 流与 gzip 识别，命令/文件名按目标调整；不访问、不执行。

## 变体与关联

- 变体：前缀检查可用 `compress.bzip2://`、`php://filter/.../resource=phar://`、大小写/多余斜杠、相对路径等其它包装器绕过。
- 变体：内容 WAF 可用 gzip/bzip2/zip 重打包、改 stub、把关键字拆分编码绕过；判等正则换其它等价写法时按"清理后只剩分号"构造 cmd。
- 变体：`__halt_compiler()` 可用 `exit`/注释符等其它截断方式尝试；读文件可换 `include`/`show_source`/`file_get_contents` 等无黑名单函数。
- 关联：[[web-php-deserialization-pop-wakeup-tostring-system-rce]]（反序列化 POP 链）；[[web-php-file-inclusion-php-filter-resource-check-bypass]]（php://filter 绕过路径检查）；文件上传 WAF 绕过类卡片。

## 检测与防御

- 检测：代码审计定位 `file_get_contents/fopen/file_exists` 等接收用户可控路径；请求中出现 `php://filter` 与 `phar://` 组合、`resource=phar`。
- 检测：上传文件含 Phar stub/`__HALT_COMPILER`/序列化对象特征；运行时 `phar` 流加载与异常 `eval`/`system` 子进程。
- 防御：对文件路径做协议白名单（只允许普通相对路径），禁止 `php://`/`phar://`/`compress.*://` 等流包装器；不要用"前缀匹配"做黑名单。
- 防御：上传内容检测在解压/规范化后做；禁止上传目录执行 PHP；`disable_functions` 限制 `eval`/命令函数。
- 防御：避免对不可信路径调用支持流包装器的文件函数；升级 PHP 并限制 `phar.readonly`/反序列化 metadata 处理。
