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
| [__unserialize 里把 $_GET 当可变函数 + array_shift 取出 callable 数组：一步进到 __toString，再用可变类/可变方法调 ReflectionFunction::invokeArgs](web-php-deserialization-unserialize-get-variable-function-array-shift-callable/) | verified | medium | 2026-11-09 |
| [__wakeup 里抛异常也拦不住反序列化：异常展开后对象析构仍执行 __destruct，静态标志位绕过第一轮分支直接进 sink](web-php-deserialization-wakeup-throw-still-destruct/) | draft | medium | 2026-11-09 |
| [CakePHP 5.1.4 新 POP 链：RejectedPromise::__destruct 字符串拼接 → ConstTypeNode::__toString → ORM\Table::__call → BehaviorRegistry::call 任意无参方法 → PHPUnit MockClass::generate 的 eval](web-php-deserialization-cakephp5-rejectedpromise-behaviorregistry-mockclass-eval/) | verified | medium | 2026-11-07 |
| [Craft CMS CVE-2025-32432：generate-transform 的 handle 数组流入 Yii createObject，借 FnStream 析构调用任意函数](web-php-deserialization-craft-cms-cve-2025-32432-yii-createobject-fnstream/) | verified | medium | 2026-11-07 |
| [extract($_POST) 覆盖同名变量跳过「同值即 die」分支，再用 __wakeup 把属性赋成未定义全局（null）让严格比较成立](web-php-deserialization-extract-overwrite-gate-undefined-global-null-compare/) | verified | high | 2026-11-08 |
| [fileowner() 直接作用于用户可控路径触发 phar:// 反序列化（图片信息查看器场景）](web-php-deserialization-fileowner-phar-trigger-photogallery/) | verified | high | 2026-11-08 |
| [GatewayWorker session 反序列化 + Composer autoload 文件包含：低权限 worker 触发 root 进程加载恶意类](web-php-deserialization-gatewayworker-session-autoload-file-include-root/) | verified | high | 2026-11-07 |
| [GuzzleHttp\Psr7\FnStream 析构 gadget：__destruct 无参调用 _fn_close，绕过 __wakeup 经 DI/对象构造注入触发](web-php-deserialization-guzzle-fnstream-destruct-callable-gadget/) | verified | high | 2026-11-07 |
| [Joomla 3 JDatabaseDriverMysqli + SimplePie 反序列化 RCE（CVE-2015-8562 变体）：disconnectHandlers 调 init 再以 assert 执行 feed_url](web-php-deserialization-joomla3-mysqli-simplepie-assert-rce/) | verified | high | 2026-11-09 |
| [Joomla 4 FormattedtextLogger __destruct 任意文件写入：path/format 可控，写日志头到 Web 目录](web-php-deserialization-joomla4-formattedtextlogger-file-write/) | verified | medium | 2026-11-09 |
| [Joomla SqliteDriver 析构 + PHPMailer sendmailSend：反序列化链经 popen/tee 写 WebShell](web-php-deserialization-joomla-phpmailer-sendmail-file-write/) | verified | high | 2026-11-05 |
| [Joomla 数据库 session 表注入触发反序列化：改 data 字段为 joomla|Base64 序列化串并重放 Cookie](web-php-deserialization-joomla-db-session-unserialize/) | verified | high | 2026-11-09 |
| [Laravel 11.x 反序列化 POP 链（CVE-2024-40075）：Monolog GroupHandler→Psy Hoa Stream→Termwind Element→Styles::format 任意函数写 WebShell](web-php-deserialization-laravel11-monolog-termwind-file-write/) | verified | medium | 2026-11-08 |
| [Laravel Reverb 经 Redis Pub/Sub 消息触发的无限制 unserialize 对象注入（CVE-2026-23524）](web-php-deserialization-laravel-reverb-redis-unserialize/) | verified | medium | 2026-11-05 |
| [phar 二进制无法直接上传时的落盘解法：把 phar 编成 =XX=00 文本塞进 session 文件，copy 到固定路径后用 base64/quoted-printable/iconv 多级 php://filter 还原再 phar:// 触发反序列化](web-php-deserialization-session-progress-phar-quotedprintable-filter-decode/) | verified | medium | 2026-11-09 |
| [PHAR 前缀过滤绕过：compress.bzip2://、compress.zlib://、php://filter/resource= 去掉外层前缀后仍进入 phar](web-php-deserialization-phar-prefix-wrapper-bypass/) | verified | high | 2026-11-08 |
| [Phar 反序列化 RCE 链：php://filter 包裹绕过 ^phar:// 前缀检查 + 字符受限 eval + __halt_compiler 截断 + gzip 绕过上传内容检测](web-php-deserialization-phar-prefix-filter-halt-compiler-rce/) | verified | high | 2026-11-08 |
| [Phar 反序列化后缀绕过：GIF8 stub 过图片头 + phar 内层 .php 过包含检查](web-php-deserialization-phar-gif8-stub-inner-php-suffix-bypass/) | verified | high | 2026-11-06 |
| [PHAR 反序列化源码调用链与冷门触发面：ZipArchive::extractTo、PDO pgsqlCopyFromFile/ToFile 等 php_stream_open_wrapper 调用者](web-php-deserialization-phar-sourcechain-zip-pgsql-sinks/) | verified | high | 2026-11-08 |
| [PHAR 反序列化：上传图片后缀文件经 file_get_contents phar:// 触发 POP 链](web-php-deserialization-phar-read-uploaded-image-pop-chain/) | verified | high | 2026-11-06 |
| [PHAR 反序列化：任意后缀上传文件经 phar:// 触发 __wakeup eval RCE](web-php-deserialization-phar-upload-jpg-wakeup-eval/) | verified | high | 2026-11-05 |
| [PHP 7.1+ 反序列化公有字段名直接赋值 private/protected 属性：免 \x00 前缀构造对象](web-php-deserialization-public-name-private-property-assign/) | verified | high | 2026-11-09 |
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
| [PHP 反序列化 POP 链新跳板：__wakeup 里的 var_dump 触发 __debugInfo，再经 echo 触发 __toString 读取环境变量](web-php-deserialization-wakeup-vardump-debuginfo-tostring-env/) | verified | medium | 2026-11-09 |
| [PHP 反序列化 POP 链：__destruct→fetch→FileLogger 写任意路径 WebShell](web-php-deserialization-pop-filelogger-webshell/) | verified | high | 2026-11-05 |
| [PHP 反序列化 POP 链：__wakeup 调属性 → __invoke → __toString → file_put_contents，hexdump 的 ASCII 列保留 <?= 短标签使写入文件仍可执行](web-php-deserialization-pop-hexdump-ascii-column-php-shorttag-webshell/) | verified | high | 2026-11-07 |
| [PHP 反序列化 POP 链：__wakeup→get_flag→对象字符串拼接触发 __toString→system 命令执行](web-php-deserialization-pop-wakeup-tostring-system-rce/) | verified | high | 2026-11-08 |
| [PHP 反序列化 PromoManager __destruct 篡改 session 余额购买 flag](web-php-deserialization-destruct-session-balance-forge/) | verified | high | 2026-11-06 |
| [PHP 反序列化 S 十六进制转义绕过属性值字母黑名单执行 passthru](web-php-deserialization-s-hex-letter-blacklist-eval/) | verified | medium | 2026-11-06 |
| [PHP 反序列化变长字符逃逸：str_replace 短替换长 + Frieren/Himmel/Fern/Stark POP 链到 eval RCE](web-php-deserialization-str-replace-length-lengthening-pop-eval/) | verified | high | 2026-11-06 |
| [PHP 反序列化四跳 POP 链：__destruct echo 触发 __toString、__toString 写未定义属性触发 __set、__set 调用变量函数触发 __invoke 到 system](web-php-deserialization-destruct-tostring-set-invoke-pop-system/) | verified | medium | 2026-11-08 |
| [PHP 反序列化引用 R 绑定回调数组：__construct 重置 processor 后 action[0] 跟随引用执行任意方法](web-php-deserialization-reference-callback-array-constructor-reset/) | verified | medium | 2026-11-06 |
| [PHP 反序列化提前析构：畸形序列化串/重复键/私有属性名长度错位让 __destruct 抢在 __wakeup 与异常退出之前](web-php-deserialization-premature-destruct-bypass/) | verified | high | 2026-11-08 |
| [PHP 反序列化绕过 __wakeup 资源置空：三对象析构 + 构造器重入 + 引用调用 execute](web-php-deserialization-wakeup-resource-null-destruct-reentry/) | verified | high | 2026-11-06 |
| [PHP 反序列化过滤器只匹配小写 s：大写 S 十六进制转义绕过并触发 __toString 读文件](web-php-deserialization-capital-s-hex-escape-regex-filter-bypass/) | verified | high | 2026-11-06 |
| [PHP 反序列化魔术方法链：__destruct 起步经 __toString/__get/__call 到 eval，并用属性数绕过 __wakeup](web-php-deserialization-magic-chain-eval-wakeup-bypass/) | verified | high | 2026-11-05 |
| [PHP 反序列化黑名单以 O:/a: 开头：用 ArrayObject 等 C: 格式类包装绕过](web-php-deserialization-c-prefix-arrayobject-bypass/) | verified | medium | 2026-11-06 |
| [PHP 多对象析构顺序链：new 匿名类 → 注册全局函数 → 调用 include 读文件或 php://filter RCE](web-php-deserialization-multi-destruct-anonymous-class-global-function-chain/) | verified | medium | 2026-11-06 |
| [PHP 字符逃逸注入不可控 CtrlCase + POP 链 dbCtrl::login 任意 SQL 读取 admin 凭据](web-php-deserialization-char-escape-pop-dbctrl-sqli/) | verified | medium | 2026-11-06 |
| [PHP 序列化字符逃逸：str_replace 把 8 字符 amgoinvc 换成 4 字符 iscc，导致属性边界错位并伪造 admin123](web-php-deserialization-str-replace-length-shortening-escape/) | verified | high | 2026-11-06 |
| [PHP8 反序列化 __call 可变类/可变方法 sink：ReflectionFunction::invokeArgs 任意函数调用写 WebShell](web-php-deserialization-call-variable-class-method-reflection-invokeargs/) | verified | high | 2026-11-07 |
| [Roundcube CVE-2025-49113：上传参数污染 Session 自定义序列化，触发 preferences 二次反序列化 RCE](web-php-deser-roundcube-49113-session-injection-gpg-rce/) | verified | high | 2026-11-05 |
| [Showdoc new_is_writeable 的 file 参数 phar:// 触发反序列化：Guzzle FileCookieJar 析构写 cookie 文件 getshell](web-php-deserialization-showdoc-new-is-writeable-phar-guzzle-filecookiejar-webshell/) | verified | high | 2026-11-08 |
| [SimplePie memcached 缓存投毒 → PHP 对象注入 → 日志目录写 WebShell](web-php-deserialization-simplepie-memcache-poisoning/) | verified | high | 2026-11-05 |
| [ThinkPHP 6 (<6.0.12) Model 链：__destruct lazySave→save→updateData→checkAllowFields→db 拼接触发 __toString](web-php-deserialization-thinkphp6-model-destruct-tostring-chain/) | verified | high | 2026-11-08 |
| [ThinkPHP 6 __toString 后链：Conversion.toArray 走 getAttr→getValue，withAttr 数组里的函数名被当回调执行](web-php-deserialization-thinkphp6-conversion-toarray-withattr-callback-rce/) | verified | high | 2026-11-08 |
| [ThinkPHP 6.0.0~6.0.13 Model 链：relationWrite→autoRelationUpdate→getRelation→save→setAttr 触发 Url.__toString，经 Channel/Store.serialize 落到 Request::param 的 filter 参数执行 system（CVE-2022-45982）](web-php-deserialization-thinkphp6-model-relationwrite-store-param-filter-system/) | verified | high | 2026-11-08 |
| [ThinkPHP 6.0.8 CacheStore 链：把缓存驱动的 serialize 选项设为 system，json_encode 后的 cache 被当 shell 词执行并落马（CVE-2021-36567）](web-php-deserialization-thinkphp6-flysystem-cachestore-serialize-system-rce/) | verified | high | 2026-11-08 |
| [ThinkPHP 6.0.8 Flysystem Cached Adapter 链：AbstractCache.__destruct→save→Adapter::write 把 cache 数组当文件内容写 WebShell（CVE-2021-36564）](web-php-deserialization-flysystem-adapter-cache-webshell/) | verified | high | 2026-11-08 |
| [ThinkPHP 8 反序列化链：ResourceRegister::__destruct → Resource::parseGroupRule → Pivot __toString → Conversion::getJsonValue 的 withAttr 回调 RCE](web-php-deserialization-thinkphp8-resourceregister-pivot-jsonvalue-withattr-rce/) | verified | high | 2026-11-08 |
| [ThinkPHP 8 反序列化链：ResourceRegister::__destruct → Resource::parseGroupRule → Pivot __toString → Validate::__call → Request::cookie 落到 filterValue call_user_func](web-php-deserialization-thinkphp8-resourceregister-pivot-validate-cookie-filtervalue-rce/) | verified | high | 2026-11-08 |
| [ThinkPHP ≤6.0.12 Model 链后段：checkAllowFields→db 拼接触发 Url::__toString→Output::__call→writeln→League\Flysystem\File::write→session File::write 写 WebShell（CVE-2022-33107）](web-php-deserialization-thinkphp6-model-destruct-checkallowfields-output-write-webshell/) | verified | high | 2026-11-08 |
| [ThinkPHP ≤6.0.13 Psr6Cache 链：pool→Channel.__call→record→Socket.save→Container.invoke 把 format_head 可调用数组当模板渲染，Php::display 内 eval 执行（CVE-2022-38352）](web-php-deserialization-thinkphp6-psr6cache-channel-socket-invoke-display-eval/) | verified | high | 2026-11-08 |
| [ThinkPHP 会话 ID 拼进 memcached 命令造成 CRLF 注入：写入伪造会话让框架反序列化，走 TP5 Windows→Pivot→Request filter 链执行 system](web-php-deserialization-thinkphp-memcached-crlf-session-poison-pivot-system-rce/) | verified | medium | 2026-11-09 |
| [unserialize 后用 == 弱比较判断键值：布尔 true 与任意非空字符串相等绕过校验](web-php-deserialization-weak-compare-bool-true/) | verified | high | 2026-11-08 |
| [ZhiCMS CVE-2024-0603 反序列化链：simple_html_dom 析构 clear → MemcachedDriver::clear 触发 __toString → Template::display extract 覆盖后 eval](web-php-deserialization-zhicms-cve-2024-0603-simple-html-dom-template-eval/) | verified | high | 2026-11-09 |
| [ZipArchive::open OVERWRITE 作为反序列化原生类文件删除 sink：打开后不写入、对象销毁即删除目标文件](web-php-deserialization-ziparchive-overwrite-file-delete/) | verified | medium | 2026-11-09 |
| [修改 Phar 序列化元数据后重算 SHA1 签名：属性数绕 __wakeup 再 gzip 上传过正则](web-php-deserialization-phar-edit-metadata-resign-sha1/) | verified | high | 2026-11-09 |
| [六跳 POP 链：__destruct 赋值触发 __set，echo 触发 __toString，读未定义属性触发 __get，isset 触发 __isset，调未定义方法触发 __call，最终进 __invoke 里 eval](web-php-deserialization-destruct-set-tostring-get-isset-call-invoke-eval/) | verified | medium | 2026-11-09 |
| [四层魔术方法接力 POP：__call 里 echo 属性触发 __toString，__toString 写属性触发 __set，__set 读属性触发 __get，最终 $$key 变量变量 + file_get_contents 任意文件读取](web-php-deserialization-call-tostring-set-get-variable-variable-file-read/) | draft | high | 2026-11-08 |
| [四类魔术方法串成 POP 链：__destruct→__toString→__get→__invoke 落到 call_user_func($_GET)](web-php-deserialization-destruct-tostring-get-invoke-call-user-func/) | draft | high | 2026-11-09 |
| [简单 POP 链：ping::__destruct 调 cup::cp eval 执行 system('cat /flag')](web-php-deserialization-destruct-cup-eval-pop/) | verified | medium | 2026-11-08 |
| [迅睿CMS 前台二维码接口 getimagesize 触发 PHAR 反序列化：CodeIgniter4 校验链 system 执行](web-php-deserialization-xunruicms-qrcode-getimagesize-phar-ci4-system/) | verified | high | 2026-11-08 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
