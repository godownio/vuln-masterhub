---
id: web-php-deserialization-ziparchive-overwrite-file-delete
title: ZipArchive::open OVERWRITE 作为反序列化原生类文件删除 sink：打开后不写入、对象销毁即删除目标文件
type: scenario
domain: web
path: web/php/deserialization
technique: ziparchive-overwrite-native-sink
tags:
- php
- deserialization
- ziparchive
- native-class
- arbitrary-file-delete
- pop-chain
- sink
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V372
  verified_at: '2026-11-09T06:03:40+08:00'
  notes: 已对照原文'ZipArchive 类删除文件'节：OVERWRITE=8、打开后不写入则文件被删、ByteCTF 2019 EZCMS 用例均与原文一致；本地 PHP 7.3.4 复跑 t3/t6：open 后文件仍在(size 1000)，close/unset+gc 后 file_exists=false，PoC 语义真实；另复跑 t5 确认 ZipArchive 可 serialize/unserialize 且序列化串含 status/statusSys/numFiles/filename/comment；卡把删除定位为需要 gadget 的任意文件删除 sink，属真实破坏面非纯理论；原文未给受影响版本，--clear；无图片、无 sources；dedup recommendation=new(0 duplicate)
url: /docs/web/php/deserialization/web-php-deserialization-ziparchive-overwrite-file-delete/
draft: false
kb_aliases:
- ZipArchive 删除文件
- ZipArchive::OVERWRITE
- 原生类任意文件删除
- PHP 反序列化文件删除
- EZCMS
---

## 一句话结论

当反序列化链能让攻击者可控的对象执行 `ZipArchive::open($path, ZipArchive::OVERWRITE)`（路径可控）时，`open` 会把目标文件当作新压缩包覆盖；由于后续没有写入任何条目，`ZipArchive` 对象被销毁/关闭时该文件被删除，形成任意文件删除 sink（原文提到 ByteCTF 2019 EZCMS 出现过该用法）。

## 原理

- **OVERWRITE 语义**：`ZipArchive::OVERWRITE`（值 8）表示“总是以一个新的压缩包开始，如果已存在则覆盖或删除”。`open` 对已存在路径建立新的归档上下文；在本机 PHP 7.3.4 的最小测试中，`open` 后文件仍在（大小暂未变化），对象 `unset`/脚本结束（或显式 `close`）且未添加任何条目时文件被删除。
- **原生类作为 sink**：`ZipArchive` 是 PHP zip 扩展提供的内置类，`open/close` 的副作用由 C 实现完成，不依赖应用代码里的 `unlink`。任何能调用对象方法且方法名/参数可控的 gadget（如 `__destruct` 里 `$this->obj->open($this->file, $this->mode)`、`call_user_func_array`、可变方法 `$obj->$method(...)`）都可以把 `ZipArchive` 当作“文件删除器”。
- **为什么不需要写文件**：删除不是 `open` 立即执行，而是归档对象销毁时的清理；只要链里执行到 `open(OVERWRITE)` 并让对象正常销毁，目标文件就会消失，不需要 `addFromString` 或显式 `close`。
- **对象可直接反序列化**：`ZipArchive` 自身可被 `serialize()`/`unserialize()`（公开属性 status/statusSys/numFiles/filename/comment 均出现在序列化串中）；也可由 gadget 通过 `new` 实例化后调用。
- **影响边界**：任意文件删除可删除安装锁、`.htaccess`、缓存/配置文件、日志等，导致重装/绕过安装锁/拒绝服务；单独不产生代码执行，但常作为链的收尾破坏或前置绕过（例如删掉 install.lock 后重装拿管理员）。

## 触发条件

- PHP 启用 zip 扩展，目标 PHP 7.x/8.x（`ZipArchive::OVERWRITE` 语义一致；本机在 PHP 7.3.4 验证）。
- 存在能把“攻击者可控对象 + 可控方法名/参数”连接起来的反序列化 gadget；或目标代码在 `__destruct`/`__wakeup`/`__call` 中固定调用 `open` 且参数来自属性。
- Web 进程对目标文件所在目录有删除/写权限（删除文件需要对父目录有写权限）。
- 目标文件存在或路径可被创建后再删除；对不存在的路径 Open 可能失败，不产生删除效果。

## 利用步骤

1. 审源码/链：搜索 `open(`、`->open`、`call_user_func_array`、`$obj->$method`、`__destruct` 中的方法调用，确认方法名与两个参数是否可控。
2. 选定要删除的目标路径（install.lock、.htaccess、配置/缓存文件、竞争条件下的临时文件）。
3. 构造对象图：把 gadget 的对象属性设为 `new ZipArchive()`（或在 payload 中直接放 `O:10:"ZipArchive":...`），路径设为目标文件，模式设为 `8`（OVERWRITE）。
4. 触发 gadget 的魔术方法（反序列化即触发 `__wakeup`/`__destruct`；或等待请求结束对象销毁）。
5. 请求结束后检查目标文件是否消失；若目标不存在/无权限，换路径或先通过上传/日志写入创建文件。
6. 与安装锁删除、缓存清除等前置绕过组合，扩大后续攻击面。

## PoC

本机语义验证（PHP 7.3.4，临时文件）：

```php
<?php
$f = '/tmp/victim.txt';
file_put_contents($f, str_repeat('A', 1000));
$z = new ZipArchive();
$z->open($f, ZipArchive::OVERWRITE);   // 目标被当作新归档
// 不 addFromString，不显式 close
unset($z);                              // 对象销毁时归档清理
clearstatcache();
var_dump(file_exists($f));              // false，文件已删除
```

链式调用形态（需目标存在对应 gadget）：

```php
class Gadget {
    public $zip;      // ZipArchive
    public $file;     // 目标路径
    public function __destruct() { $this->zip->open($this->file, 8); }
}
```

## 变体与关联

- 变体：模式值用数字 8 代替常量；用 `ZipArchive::CREATE`（不删除已有文件）或其他 flag 组合；`open` 由 `__call`/`__invoke`/可变方法转发；目标路径用相对路径/`..` 穿越。
- 关联：[[web-php-deserialization-native-class-array-walk-directory-read]]（原生类目录遍历 gadget）、[[web-php-deserialization-phar-sourcechain-zip-pgsql-sinks]]（ZipArchive::extractTo 作为 phar 触发面）、[[web-php-deserialization-maker-splfileobject-php-filter-read]]（SplFileObject 原生类文件读取）。
- 边界：无调用 gadget 时该 sink 不可达；删除文件需要父目录写权限；对只读文件系统/权限受限目录无效；`open` 失败时不会删除。

## 检测与防御

- **检测**：序列化输入/对象图中出现 `ZipArchive` 与数值 `8`/`OVERWRITE`；监控 Web 进程对敏感文件（install.lock、.htaccess、配置）的删除/创建归档行为；审计 `open` 调用的参数来源。
- **防御**：`unserialize()` 使用 `allowed_classes` 白名单，禁止 `ZipArchive` 等原生类；不要把可控对象方法调用接到 `open`；敏感文件放只读目录、父目录不可写；安装锁/配置文件使用服务端状态而非文件存在性判断。
- **加固**：Web 进程最小权限，目录权限分离；对上传/临时目录与代码/配置目录分开挂载。
