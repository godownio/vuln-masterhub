---
id: web-php-discuz-utility-convert-saveconfig-key-injection-webshell
title: Discuz! X3.5 utility/convert 配置导入把可控数组键写回 PHP 配置文件导致代码执行
type: scenario
domain: web
path: web/php/framework
technique: discuz-utility-convert-saveconfig-key-injection
tags:
- php
- discuz
- cms
- arbitrary-file-write
- config-injection
- webshell
- unauthenticated
cve: []
severity: high
confidence: low
status: draft
created: '2026-11-09'
updated: '2026-11-09'
url: /docs/web/php/framework/web-php-discuz-utility-convert-saveconfig-key-injection-webshell/
draft: false
kb_aliases:
- Discuz X3.5 utility convert 写马
- Discuz save_config_file 代码写入
- Discuz 配置导入 getshell
- do_config.inc.php 任意写入
- Discuz utility 目录未删除
---

## 一句话结论

Discuz! X3.5 安装包里附带的 `utility/convert/` 迁移工具（正式站点通常应删除）把 POST 的 `newconfig` 数组原样交给 `save_config_file()` 序列化成 PHP 配置文件：只要 `a=config` 且带上 `submit`、走 POST，`submitcheck()` 就放行，随后 `getvars()`/`buildarray()` 把数组键值拼进 `$_config[...] = ...;` 语句并用 `file_put_contents` 落地。攻击者用换行加注释截断语句、把 `eval(...)` 之类的 PHP 代码塞进键名，就能把恶意代码写进一个可访问的 PHP 配置文件，构成未授权写 webshell 的一条链。

## 原理

- **入口是工具目录而非业务逻辑**：`utility/convert/index.php` 按 `$action` 去包含 `./include/do_{$action}.inc.php`，`a=config` 进入 `do_config.inc.php`。`utility/` 是论坛从其他系统转换数据用的离线工具，部署后一般应删除；只要目录还在，它就独立于 Discuz 的登录态与权限体系对外提供服务。
- **`submitcheck()` 只做形式校验**：函数要求 `getgpc('submit')` 非空且 `$_REQUEST['method'] == 'post'` 才返回 true。它没有 token、没有 referer、没有登录判断，因此“POST + submit 参数”就等于“通过校验”。
- **数据库连不通不阻断写入**：`do_config.inc.php` 在 `submitcheck()` 通过后取 `$newconfig = getgpc('newconfig')`，对 `source`/`target` 的 `dbhost` 调 `mysql_connect_test()`；连接失败只是把错误塞进 `$error` 数组，随后照常调用 `save_config_file($configfile, $newconfig, $config_default)`。也就是说目标数据库根本不需要可达。
- **写入的内容由数组决定**：`save_config_file()` 先写死 `<?php $_config = array();`，再拼 `getvars(array('_config' => $config))` 的返回值，最后补 `// THE END // ?>` 后 `file_put_contents($filename, $content)`。`$config` 就是 `$newconfig` 经 `setdefault()` 用 `config.default.php` 的默认键补齐后的结果，用户提交的键值全部保留。
- **`getvars()`/`buildarray()` 是代码生成器而非序列化器**：`getvars()` 对数组值调用 `buildarray($val, 0, "\$key")`；`buildarray()` 逐层把数组渲染成 `$_config['a']['b'] = 'value';` 形式，层级键名通过 `$ks[$level] = $ks[$level-1]."['$key']"` 拼进代码。任何能进入这套拼接的键名/值都会变成 PHP 源码的一部分。
- **注入点在键名的注释行**：`buildarray()` 在 `$level == 0` 时会写一行 `// ---- CONFIG <KEY> ---- //`（`str_pad` 补横线）。键名如果带换行，就能跳出注释行，再用 `//` 把后半行的横线与分号注释掉，中间留出完整的 PHP 语句位置；示例把语句放在键名里（`\n\neval(...);//`），写入后即为可执行的 PHP。
- **为什么要先 `setdefault`**：`setdefault()` 递归补齐默认键（缺的键补默认值，数组继续递归），所以攻击者既要保证 `source`/`target` 存在（避免补值干扰），又要让恶意键名随数组一起进入 `$config`；补齐逻辑只增不删，恶意键不会被清掉。
- **不确定点**：原文引用的 `buildarray()`/`getvars()` 源码里都有键名白名单正则（`^[a-zA-Z0-9_\x7f-\xff]+$` 与标识符式正则），按这两条正则，含 `(`、`)`、`/` 的键名会被 `continue` 跳过。原文的成功截图说明目标版本的键名校验与所列代码不一致（或校验只作用于某层），因此实际利用前应先确认目标 `utility/convert/include/*.inc.php` 中 `buildarray()` 的键名判定；本卡按原文结论记录，PoC 未在本机复现。

## 触发条件

- 目标为 Discuz! X3.5（原文环境为 `Discuz_X3.5_SC_UTF8_20240520` 及其 `X3.5_utility_20230210` 工具包），且 `utility/convert/` 目录未删除、可被 Web 访问。
- `utility/convert/` 下的 `data/`、`config/` 等写入目录对 PHP 进程可写（工具自身要把配置写到 `$configfile`）。
- 目标版本的 `buildarray()` 能把攻击者键名拼进注释行（原文程序成立，见上文不确定点）。
- 无需登录、无需数据库可达。

## 利用步骤

1. 探测 `utility/convert/index.php` 是否存在（迁移工具首页通常可直接打开，`a=select`/`a=config` 等 `action` 可枚举）。
2. `a=config` 页面会展示数据库配置表单；确认表单以 POST 提交并带 `submit` 字段。
3. 构造 `newconfig` 数组，保留 `source`/`target` 的正常子键（`dbhost`、`dbuser`、`dbname`、`tablepre` 等）让流程走完，另加一个键名含换行与 `//` 注释的条目承载 PHP 代码。
4. POST 后 `save_config_file()` 重写配置文件；随后访问被写入的配置文件路径（工具默认写在 `utility/convert/` 下的配置文件名，如 `config.inc.php`），确认 PHP 代码被执行。
5. 若页面回显 `config_success` 并跳转，说明写入成功；若报数据库错误仍可能已写入（错误不阻断 `save_config_file`）。
6. 后续用一句话木马/命令执行维持访问，并清理迁移工具目录以降低被发现概率。

## PoC

原文的 POST 请求（`newconfig` 的键名承载代码，换行与 `//` 负责跳出注释）：

```http
POST /utility/convert/index.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Content-Length: 79

a=config&source=d7.2_x1.5&submit=yes&newconfig[%0a%0deval(phpinfo());//]=shushu
```

正常业务形态的对照请求（理解参数结构用，本身不含恶意键）：

```http
a=config&source=d7.2_x1.0&submit=yes&newconfig[source][dbhost]=localhost&newconfig[source][dbuser]=root&newconfig[source][dbpw]=&newconfig[source][dbname]=discuz&newconfig[source][tablepre]=cdb_&newconfig[source][pconnect]=1&newconfig[target][dbhost]=localhost&newconfig[target][dbuser]=root&newconfig[target][dbpw]=&newconfig[target][dbname]=discuzx&newconfig[target][tablepre]=pre_&newconfig[target][pconnect]=1&submit=
```

写入结果的结构（`save_config_file()` 生成）：

```php
<?php

$_config = array();
// ---- CONFIG SOURCE ---- //
$_config['source']['dbhost'] = 'localhost';
...
// ---- CONFIG <注入键> ---- //
<注入的 PHP 语句>
// ------------------  THE END  ------------------ //

?>
```

## 变体与关联

- **同源入口的其他 action**：`index.php` 用 `$action` 拼 `./include/do_{$action}.inc.php` 做包含，`a=source`（首页展示）、`a=config`（写配置）、`a=select` 等分支共用同一套无鉴权入口；`$action` 若未被白名单约束还存在本地文件包含面。
- **注入载体切换**：键名被过滤时可尝试值路径——`buildarray()` 对匹配 `^\-?[1-9]\d*$` 且长度 ≤12 的值不加引号直接写入，但该分支只允许数字与行尾换行，单独不足以执行代码，通常仍要回到键名注入。
- **同类“把用户数组渲染成 PHP 源码”的模式**：安装/升级/迁移脚本里的 `save_config`、`var_export` 风格写入、模板缓存写入；凡是“配置数组 → 代码文本”的转换点都值得按本卡思路审计。
- **关联**：CMS 后台/工具目录未删除导致的未授权写入见 [[web-php-wordpress-backup-sql-phpass-credential]] 一类“残留文件暴露”思路；写文件落点是否可执行取决于目录是否被 PHP handler 覆盖。

## 检测与防御

- **删除工具目录**：安装/迁移完成后立即删除 `utility/`（含 `convert/`），并在发布流程里做检查项。
- **入口收口**：`utility/` 目录在 Web 层直接拒绝访问；必须保留时加独立认证（HTTP Basic/IP 白名单）并只允许内网访问。
- **写入前校验**：`save_config_file()` 不应把用户数组渲染成 PHP 代码；改为固定键白名单 + `var_export()`/JSON 落盘，或写入不可执行的 `.php` 之外的路径。
- **禁用动态包含**：`$action` 用数组白名单映射到固定文件名，禁止拼接后 `include`。
- **检测**：对 `utility/convert/` 的访问日志（尤其 `a=config` 的 POST）、请求体中的 `newconfig[`、`%0a`、`eval(`、`//` 组合；配置目录出现新增/改写的 PHP 文件；Web 进程对工具目录的写操作。
- **权限**：Web 用户对站点目录只读，仅上传/缓存目录可写，降低任意写入落成可执行文件的概率。
