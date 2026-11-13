---
id: code-analysis-vuln-discovery-php-upload-condition-precedence-whitelist
title: 上传校验复合条件优先级错误：&& 只绑定最后一个 Content-Type 分支，扩展名白名单名存实亡
type: scenario
domain: code-analysis
path: code-analysis/vuln-discovery/pattern
technique: php-upload-condition-precedence-whitelist-bypass
aliases:
- 上传 && 优先级绕过
- 扩展名白名单只检查最后一个分支
- PHP 运算符优先级 上传
- Content-Type 信任 + 条件优先级
- move_uploaded_file 任意上传
tags:
- php
- file-upload
- operator-precedence
- content-type
- whitelist-bypass
- code-audit
- webshell
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V482
  verified_at: '2026-11-10T21:14:13+08:00'
  notes: 已对照原文与7张图核对（01.bin 实为 PNG 产品图、02 目录结构、03 HackBar 上传 aaa.php+image/jpeg 返回上传成功、04 setup.php data-src 泄露 ./user/headimg/...aaa.php、05 后台用户列表 XSS 弹窗、06.gif 首帧 rm.php?filew=../robots.txt 与 robots.txt 时间戳变化、07 脚本输出注册/上传成功 URL）：校验条件 A||B||C||D||(E&&in_array) 与原文代码逐字符一致，&& 优先级只绑定 webp 分支、move_uploaded_file 保留 .php 后缀、文件名随机前缀+原文件名、setup.php 路径发现均与原文一致；与既有纯 Content-Type 信任卡区别成立（本卡确有白名单但作用域错误），dedup top候选 related/new，非重复。原文未标产品版本，affected_versions 留空正确。未验证点：未在本机复现上传（原文已给出回显截图）。另：06.gif 为117帧动图，只核对了首帧与正文描述一致性。无 sources/source_url。
---

## 一句话结论

一段“看起来有扩展名白名单”的上传校验，因为把 `in_array($extension, $allowedExts)` 写在 `||` 链末尾并与最后一个 `Content-Type` 比较用 `&&` 连接，PHP 的运算符优先级让 `&&` 只绑定最后一个分支——等价于 `jpeg || png || jpg || gif || (webp && 扩展名在白名单)`；攻击者只要把 multipart 的 Content-Type 伪造成 `image/jpeg`，任意 `.php` 文件名都能通过并落盘执行。

## 原理

- **缺陷代码形态**：

  ```php
  if ($file["type"] == "image/jpeg" || $file["type"] == "image/png"
      || $file["type"] == "image/jpg" || $file["type"] == "image/gif"
      || $file["type"] == "image/webp" && in_array($extension, $allowedExts)) {
      // 校验通过
  }
  ```

- **优先级规则**：PHP 中 `&&` 高于 `||`，上述条件被解析为 `A || B || C || D || (E && in_array(...))`。扩展名白名单只对 `image/webp` 这个分支生效；其余四个分支只要 Content-Type 匹配就通过，与文件后缀无关。
- **Content-Type 可伪造**：`$_FILES["file"]["type"]` 来自 multipart part 的 Content-Type 头，完全由客户端控制；把 `.php` 文件的 part 写成 `Content-Type: image/jpeg` 即命中第一个分支。
- **落盘保留后缀**：示例上传目录为 `../user/headimg/`，文件名由随机数 + 时间 + md5 前缀拼接 `$file["name"]`，原始 `.php` 后缀保留；`move_uploaded_file` 写入后即可通过 Web 访问执行。
- **路径发现**：示例系统在 `setup.php` 页面渲染头像时输出 `data-src="./user/headimg/<随机前缀>aaa.php"`，攻击者访问该页面或按目录规律即可拿到实际路径。
- **为什么容易漏审**：代码表面包含 `$allowedExts` 与 `in_array`，容易被当作“已做后缀白名单”；实际只有最后那个 `&&` 分支受保护，误审成本很低。
- **同类变体**：把黑名单/白名单与多个 `||` 条件混写、用 `and/or`（优先级又不同于 `&&/||`）、或把 `in_array` 放在某个括号外，都可能产生同样的“只校验了部分分支”的效果。

## 触发条件

- 上传校验使用复合布尔表达式，扩展名检查只与其中一个 Content-Type 分支用 `&&` 连接。
- Content-Type 由客户端提交且未做服务端二次检测（文件头/内容）。
- 保存时保留原始文件名后缀，上传目录在 Web 可访问路径内且该后缀会被解析。
- 攻击者可注册/登录获得上传权限（示例系统可自行注册）。

## 利用步骤

1. 代码审计时搜索上传 Action 中的 `if` 条件，检查 `||`/`&&` 混用、`in_array`/`preg_match` 是否只挂在最后一个分支上。
2. 抓取正常图片上传请求，观察校验通过的 Content-Type 值与文件保存路径。
3. 把文件名改为 `aaa.php`，part 的 Content-Type 改为 `image/jpeg`，重放上传。
4. 若返回成功，访问上传目录/系统页面确认文件路径与脚本执行（如 `<?php phpinfo();?>`）。
5. 需要批量验证时，可脚本化“注册→登录→上传→解析页面取路径”的流程。

## PoC

最小 multipart 片段：

```http
POST /api/uploadavatar.php HTTP/1.1
Content-Type: multipart/form-data; boundary=----B

------B
Content-Disposition: form-data; name="file"; filename="aaa.php"
Content-Type: image/jpeg

<?php phpinfo();?>
------B--
```

等价于开发者的本意应为：

```php
if (in_array($extension, $allowedExts)
    && ($file["type"] == "image/jpeg" || $file["type"] == "image/png"
        || $file["type"] == "image/jpg" || $file["type"] == "image/gif"
        || $file["type"] == "image/webp")) {
```

## 变体与关联

- **变体**：只黑名单后缀但条件写错导致部分后缀不检查；`&&`/`||` 与 `and`/`or` 优先级差异导致括号外的检查失效；扩展名取 `end(explode(...))` 但文件名多后缀/大小写/空格绕过。
- **与纯 Content-Type 信任的区别**：纯信任型是“没有后缀检查”；本模式是“有后缀检查但只覆盖一个分支”，审计时更容易误判为安全。
- 关联：[[web-generic-file-upload-content-type-trust-bypass]]（只信任 Content-Type 的基础型）、[[web-generic-file-upload-php-array-end-count-order-bypass]]（PHP 数组取值错位导致扩展名检查失效）、[[web-generic-file-upload-dotnet-blacklist-only-asp-aspx]]（黑名单漏网）。
- 边界：如果服务端在保存前另做了文件头/内容检测、扩展名白名单独立校验，或上传目录不解析脚本，本绕过不成立。

## 检测与防御

- **代码审计**：对所有 `||` 与 `&&` 混用的安全判断加括号复核；确认白名单/黑名单检查作用于所有分支；搜索 `move_uploaded_file`、`SaveAs`、`FileOutputStream` 等落盘 sink 前的条件。
- **修复**：把扩展名白名单校验提前并用括号包住类型判断；不要信任 `$_FILES['type']`，用 `finfo`/`getimagesize` 检测真实内容；保存时重命名为固定安全后缀；上传目录移出 Web 根目录或禁止脚本执行。
- **检测信号**：上传请求的 Content-Type 与文件名后缀不一致（`.php` + `image/jpeg`）；上传目录出现脚本后缀文件；Web 访问日志中对 `headimg`/`upload` 目录下 `.php` 的访问。
