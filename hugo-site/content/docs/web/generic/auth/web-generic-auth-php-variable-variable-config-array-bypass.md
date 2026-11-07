---
id: web-generic-auth-php-variable-variable-config-array-bypass
title: PHP 变量变量覆盖 $config 对象为数组：array_merge + $$key 绕过 isAdmin 严格比较
type: scenario
domain: web
path: web/generic/auth
technique: php-variable-variable-config-array-auth-bypass
tags:
- php
- auth-bypass
- variable-variables
- type-juggling
- array-merge
- web
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V158
  verified_at: '2026-11-06T07:34:13+08:00'
  notes: 已对照原文 The_Gift 源码逐行核对：array_merge($_GET,$_POST) 后 foreach $$key 覆盖，$config 由 ConfigModel 对象变为 ['isAdmin'=>'true']，不传 user_api_key 可跳过 validateApiKey，is_array+=== 'true' 成立输出 FLAG；PoC ?config[isAdmin]=true 与代码一致。全文17张截图均已查看（多数属其他赛题），本题源码与结论无冲突。未验证点：未在本地 PHP 复跑；CTF 环境无产品版本，未设 affected_versions；frontmatter 无 sources/source_url。
url: /docs/web/generic/auth/web-generic-auth-php-variable-variable-config-array-bypass/
draft: false
kb_aliases:
- 变量变量覆盖
- $$key 变量覆盖
- config[isAdmin]=true
- array_merge 覆盖对象
- PHP 变量覆盖鉴权绕过
---

## 一句话结论

当 PHP 把 `$_GET`/`$_POST` 合并后以 `$$key = $value` 写入全局变量时，攻击者可用 `?config[isAdmin]=true` 把已实例化的配置对象整体覆盖成数组，使 `is_array($config) && $config['isAdmin'] === 'true'` 成立，绕过原本不可猜的 apiKey 校验并进入管理员分支。

## 原理

- `array_merge($_GET, $_POST)` 把所有请求参数并入一个关联数组，键名完全由用户控制；`foreach ($requestData as $key => $value) { $$key = $value; }` 是 PHP 的“变量变量”赋值，等价于在当前作用域创建或覆盖名为 `$key` 的变量。
- 攻击者传 `config[isAdmin]=true` 时，`$key` 为 `config`，`$value` 为数组 `['isAdmin' => 'true']`；原本保存 `ConfigModel` 实例的 `$config` 被整体替换为数组，对象及其中的 `$apiKey` 不再存在。
- 后续 `if (isset($user_api_key)) { $config->validateApiKey($user_api_key); }` 依赖请求中的 `user_api_key`；不传该项即可跳过。鉴权判断退化为 `is_array($config) && isset($config['isAdmin']) && $config['isAdmin'] === 'true'`，完全由请求参数满足。
- 严格比较 `=== 'true'` 之所以成立，是因为查询字符串参数值天然是字符串 `"true"`，不是布尔值。
- 根本原因：变量变量没有键名白名单、没有作用域隔离；`array_merge` 让 GET 可覆盖 POST 同名键；配置“对象/数组”的类型混淆使用户能控制鉴权判断的输入类型。

## 触发条件

- PHP 应用使用 `$$key`、`extract()`、`parse_str()` 等把请求参数导入变量。
- 被覆盖的变量参与后续鉴权/配置判断，且判断对数组类型和字符串值放行。
- 参数可通过 GET/POST 传入，且 GET 在合并顺序中覆盖 POST（本例 `array_merge($_GET, $_POST)` 中 GET 在前、POST 相同键覆盖 GET；不同键均可写入）。

## 利用步骤

1. 审计源码，定位 `array_merge($_GET, $_POST)` 与 `$$key = $value` 循环，确认参数键可任意。
2. 找到鉴权分支依赖的变量名（本例 `$config`），以及判断条件（`is_array` + `['isAdmin'] === 'true'`）。
3. 发送 `?config[isAdmin]=true`：`$_GET['config']` 是数组，循环后 `$config` 变为 `['isAdmin'=>'true']`。
4. 不提供 `user_api_key`，跳过对象方法调用；条件成立后执行 `die("Success".$FLAG)`。
5. 若目标用 `$config->isAdmin` 或 `=== true` 比较，改用 `extract($_POST)` 覆盖标量、或用 JSON body 触发 `json_decode` 后的布尔值，按实际代码调整。

## PoC

```http
GET /?config[isAdmin]=true HTTP/1.1
Host: target
```

简化复现代码：

```php
<?php
class ConfigModel {
    public $apiKey = '';
    public $isAdmin = false;
    public function __construct() {
        $this->apiKey = md5($_SERVER['REMOTE_ADDR'] . rand(1, 99999) . "S4ltY_String");
    }
    public function validateApiKey($inputKey) {
        if ($inputKey === $this->apiKey) { $this->isAdmin = true; return true; }
        return false;
    }
}
$config = new ConfigModel();
$requestData = array_merge($_GET, $_POST);
foreach ($requestData as $key => $value) { $$key = $value; }
if (isset($user_api_key)) { $config->validateApiKey($user_api_key); }
if (is_array($config) && isset($config['isAdmin']) && $config['isAdmin'] === 'true') {
    die("Success" . $FLAG);
}
```

## 变体与关联

- 变体：`extract($_REQUEST)`、`foreach ($_REQUEST as $k => $v) $$k = $v;`、老版本 `register_globals` 造成同类覆盖。
- 变体：覆盖 `$isAdmin`、`$role`、`$user` 等标量，直接跳过角色判断；或覆盖 `$GLOBALS` 中的配置数组。
- 变体：若判断使用 `=== true`，需要构造真正的布尔值（JSON body + `json_decode`、或 `config[isAdmin]=1` 配合弱比较 `==`）。
- 关联：PHP 类型混淆、HTTP 参数污染、`parse_str` 变量覆盖、Mass Assignment 的同源问题。

## 检测与防御

- 禁止对用户输入使用变量变量或 `extract()`；需要动态键时使用显式白名单映射。
- 使用 `$_GET['x'] ?? null`、`$_POST['x'] ?? null` 显式取值，配置对象不与请求变量同名。
- 鉴权状态放服务端 Session 或签名 token，不依赖请求可覆盖的变量或对象。
- 代码审计关键词：`$$`、`extract(`、`parse_str(`、`import_request_variables`、`register_globals`。
- 运行时监控：参数名含 `[` 且指向配置/权限变量名的请求；对数组型参数进入鉴权分支的行为告警。
