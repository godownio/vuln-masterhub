---
title: PHP 反序列化
weight: 1
---

# PHP 反序列化

## 这层是什么

POP 链、魔术方法、Phar 反序列化。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [Craft CMS CVE-2025-32432：generate-transform 的 handle 数组流入 Yii createObject，借 FnStream 析构调用任意函数](web-php-deserialization-craft-cms-cve-2025-32432-yii-createobject-fnstream/) | verified | medium | 2026-11-07 |
| [GatewayWorker session 反序列化 + Composer autoload 文件包含：低权限 worker 触发 root 进程加载恶意类](web-php-deserialization-gatewayworker-session-autoload-file-include-root/) | verified | high | 2026-11-07 |
| [GuzzleHttp\Psr7\FnStream 析构 gadget：__destruct 无参调用 _fn_close，绕过 __wakeup 经 DI/对象构造注入触发](web-php-deserialization-guzzle-fnstream-destruct-callable-gadget/) | verified | high | 2026-11-07 |
| [Joomla SqliteDriver 析构 + PHPMailer sendmailSend：反序列化链经 popen/tee 写 WebShell](web-php-deserialization-joomla-phpmailer-sendmail-file-write/) | verified | high | 2026-11-05 |
| [Laravel Reverb 经 Redis Pub/Sub 消息触发的无限制 unserialize 对象注入（CVE-2026-23524）](web-php-deserialization-laravel-reverb-redis-unserialize/) | verified | medium | 2026-11-05 |
| [Phar 反序列化后缀绕过：GIF8 stub 过图片头 + phar 内层 .php 过包含检查](web-php-deserialization-phar-gif8-stub-inner-php-suffix-bypass/) | verified | high | 2026-11-06 |
| [PHAR 反序列化：上传图片后缀文件经 file_get_contents phar:// 触发 POP 链](web-php-deserialization-phar-read-uploaded-image-pop-chain/) | verified | high | 2026-11-06 |
| [PHAR 反序列化：任意后缀上传文件经 phar:// 触发 __wakeup eval RCE](web-php-deserialization-phar-upload-jpg-wakeup-eval/) | verified | high | 2026-11-05 |
| [PHP 8 Serializable 接口嵌套反序列化继承 var_hash 导致 UAF](web-php-deserialization-serializable-nested-unserialize-var-hash-uaf/) | verified | medium | 2026-11-05 |
| [PHP __PHP_Incomplete_Class 往返序列化差异：绕过 serialize(unserialize($x)) != $x 校验并任意文件读取](web-php-deserialization-incomplete-class-roundtrip-bypass/) | verified | high | 2026-11-07 |
| [PHP __wakeup 属性数绕过（CVE-2016-7124）：序列化声明属性数大于实际即跳过重置](web-php-deserialization-wakeup-property-count-bypass/) | verified | high | 2026-11-06 |
| [PHP __wakeup 重置失效：属性引用别名（R:2）让 __destruct 写回命令后 eval](web-php-deserialization-wakeup-reference-alias-bypass/) | verified | high | 2026-11-06 |
| [PHP Error/Exception 内置类绕过 md5/sha1 强比较：__toString 同串不同对象 + eval 执行 payload](web-php-deserialization-error-exception-tostring-hash-bypass/) | verified | high | 2026-11-06 |
| [PHP ez_uns 三合一链：serialize/unserialize 尾部空格差异 + 重复键 GC 触发 __destruct + php://filter 目录穿越 include](web-php-deserialization-ez-uns-trailing-space-gc-php-filter-traversal/) | verified | high | 2026-11-06 |
| [PHP include 解析压缩 phar 容器绕过关键字过滤并写马](web-php-deserialization-compressed-phar-include-bypass/) | verified | medium | 2026-11-05 |
| [PHP mb_strpos/mb_substr 多字节偏移差异导致字符逃逸：绕过方括号黑名单注入序列化数据](web-php-deserialization-mbstrpos-mbsubstr-multibyte-offset-escape/) | verified | medium | 2026-11-06 |
| [PHP POP 链：__destruct→render→htmlspecialchars 触发 __toString→method_exists→FileReader 读文件](web-php-deserialization-destruct-tostring-htmlspecialchars-file-read/) | verified | high | 2026-11-06 |
| [PHP POP 链：__wakeup 的 preg_match 把对象转字符串，经 __toString→__get→is_callable→__invoke 读取任意文件](web-php-deserialization-wakeup-pregmatch-tostring-get-invoke-read/) | verified | high | 2026-11-06 |
| [PHP POP 链：双 md5 0e 弱比较触发 __set 回调链到 system](web-php-deserialization-double-md5-weak-compare-pop-chain/) | verified | high | 2026-11-06 |
| [PHP Session 反序列化 S 类型十六进制转义：把 admin 藏进 \61\64\6d\69\6e 绕过检测](web-php-deserialization-session-s-hex-escape-admin-forge/) | verified | medium | 2026-11-06 |
| [PHP session 处理器不一致注入 SoapClient：CRLF 头注入 + 本地 SSRF 把 flag 写回攻击者 session](web-php-deserialization-session-soapclient-crlf-ssrf/) | verified | high | 2026-11-06 |
| [PHP 原生类目录读取 POP 链：array_walk 以属性名为类名任意实例化 FilesystemIterator 遍历找 flag](web-php-deserialization-native-class-array-walk-directory-read/) | verified | medium | 2026-11-06 |
| [PHP 反序列化 __destruct 直连 system：base64 编码的 data 参数触发命令执行并写 eval WebShell](web-php-deserialization-destruct-system-webshell-base64/) | verified | high | 2026-11-07 |
| [PHP 反序列化 EXP：ReflectionClass 改写私有属性触发 __destruct 到 __toString 读文件](web-php-deserialization-reflection-private-property-payload/) | verified | high | 2026-11-05 |
| [PHP 反序列化 Maker 链：__toString → getInstance 动态 new SplFileObject + php://filter 读源码](web-php-deserialization-maker-splfileobject-php-filter-read/) | verified | high | 2026-11-07 |
| [PHP 反序列化 POP 链：__destruct→fetch→FileLogger 写任意路径 WebShell](web-php-deserialization-pop-filelogger-webshell/) | verified | high | 2026-11-05 |
| [PHP 反序列化 PromoManager __destruct 篡改 session 余额购买 flag](web-php-deserialization-destruct-session-balance-forge/) | verified | high | 2026-11-06 |
| [PHP 反序列化 S 十六进制转义绕过属性值字母黑名单执行 passthru](web-php-deserialization-s-hex-letter-blacklist-eval/) | verified | medium | 2026-11-06 |
| [PHP 反序列化变长字符逃逸：str_replace 短替换长 + Frieren/Himmel/Fern/Stark POP 链到 eval RCE](web-php-deserialization-str-replace-length-lengthening-pop-eval/) | verified | high | 2026-11-06 |
| [PHP 反序列化引用 R 绑定回调数组：__construct 重置 processor 后 action[0] 跟随引用执行任意方法](web-php-deserialization-reference-callback-array-constructor-reset/) | verified | medium | 2026-11-06 |
| [PHP 反序列化绕过 __wakeup 资源置空：三对象析构 + 构造器重入 + 引用调用 execute](web-php-deserialization-wakeup-resource-null-destruct-reentry/) | verified | high | 2026-11-06 |
| [PHP 反序列化过滤器只匹配小写 s：大写 S 十六进制转义绕过并触发 __toString 读文件](web-php-deserialization-capital-s-hex-escape-regex-filter-bypass/) | verified | high | 2026-11-06 |
| [PHP 反序列化魔术方法链：__destruct 起步经 __toString/__get/__call 到 eval，并用属性数绕过 __wakeup](web-php-deserialization-magic-chain-eval-wakeup-bypass/) | verified | high | 2026-11-05 |
| [PHP 反序列化黑名单以 O:/a: 开头：用 ArrayObject 等 C: 格式类包装绕过](web-php-deserialization-c-prefix-arrayobject-bypass/) | verified | medium | 2026-11-06 |
| [PHP 多对象析构顺序链：new 匿名类 → 注册全局函数 → 调用 include 读文件或 php://filter RCE](web-php-deserialization-multi-destruct-anonymous-class-global-function-chain/) | verified | medium | 2026-11-06 |
| [PHP 字符逃逸注入不可控 CtrlCase + POP 链 dbCtrl::login 任意 SQL 读取 admin 凭据](web-php-deserialization-char-escape-pop-dbctrl-sqli/) | verified | medium | 2026-11-06 |
| [PHP 序列化字符逃逸：str_replace 把 8 字符 amgoinvc 换成 4 字符 iscc，导致属性边界错位并伪造 admin123](web-php-deserialization-str-replace-length-shortening-escape/) | verified | high | 2026-11-06 |
| [PHP8 反序列化 __call 可变类/可变方法 sink：ReflectionFunction::invokeArgs 任意函数调用写 WebShell](web-php-deserialization-call-variable-class-method-reflection-invokeargs/) | verified | high | 2026-11-07 |
| [Roundcube CVE-2025-49113：上传参数污染 Session 自定义序列化，触发 preferences 二次反序列化 RCE](web-php-deser-roundcube-49113-session-injection-gpg-rce/) | verified | high | 2026-11-05 |
| [SimplePie memcached 缓存投毒 → PHP 对象注入 → 日志目录写 WebShell](web-php-deserialization-simplepie-memcache-poisoning/) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
