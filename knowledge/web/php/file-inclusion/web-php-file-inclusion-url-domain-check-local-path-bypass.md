---
id: web-php-file-inclusion-url-domain-check-local-path-bypass
title: URL 域名安全校验对本地路径失效：url=D:/1.txt 直入 file_get_contents 任意文件读取
type: scenario
domain: web
path: web/php/file-inclusion
technique: url-domain-check-local-absolute-path-bypass
aliases:
- isSafeDoman 绕过
- 域名白名单 不校验 scheme
- url 参数 本地路径 文件读取
- createFromUrl file_get_contents
- 绝对路径绕过域名校验
- 无 scheme 输入直达文件函数
tags:
- php
- file-read
- arbitrary-file-read
- file-get-contents
- url-parameter
- validation-bypass
- weak-domain-check
- swoole
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: duSoho v23.4.4
verification:
  verified_by: verifier-T2-3
  verified_at: '2026-11-08T00:28:45+08:00'
  notes: '已对照原文与 10 张图核对：图04 createFromUrlAction 源码（url=query->get、isSafeDoman($url)、$url=urldecode、file_get_contents、Readability parse 回显 title/body/thumb）与卡内数据流一致；图05 Burp GET /app.php/admin/article/createFromUrl?url=D:/1.txt 响应回显一串 1，与 PoC 一致；图01/02 为 depth<=3 与 depth=4 链清单，图03 为分链复现结论（#1 成功、#4 截断后写不进、#9 需判断文件存在且落点不在 web 根），卡内 skipped 理由与原文相符；图06-08 确认两处 file_put_contents 均未打通（冒号截断后内容为空、userCenter 写入 app/config 不在 Web 根），未成卡处理正确。已改 3 处措辞：isSafeDoman 实现未在原文给出（改为按调用点推断）、urldecode 后二次解码为通用风险提示（本条 PoC 未用编码载荷）、phar.readonly 表述按原文（默认未设置该指令、因此 phar 不可用）。affected_versions 保留 duSoho v23.4.4(原文标题)。dedup: duplicate 命中为卡片自身，其余仅 related/new（phar 读链、icpas 无校验 SSRF 等）。未验证点：未在靶场复跑、isSafeDoman 具体实现、allow_url_fopen 实际状态未验证。'
---

## 一句话结论

当「从 URL 抓取内容」的功能用一个只判域名的 `isSafeDoman($url)` 之类函数做安全校验，却把原始字符串直接交给 `file_get_contents` 时，校验与消费的语义完全不匹配：校验假设输入是 `http(s)://域名/...`，而 `file_get_contents` 同时接受**本地绝对路径**（Windows `D:/1.txt`、Linux `/etc/passwd`）与各类包装协议。传一个没有 scheme 的绝对路径即可绕过域名判断并直接读服务器本地文件。

## 原理

- 典型的「取回 URL 正文」实现：控制器 `createFromUrlAction` 取 `$request->query->get('url')` → `$isSafeDoman = $this->isSafeDoman($url)`（只做域名/主机判断或只拦明显内网域名）→ `$url = urldecode($url)` → `file_get_contents($url)`，然后把结果交给 `Readability` 解析出标题/正文/缩略图。
- 校验与 sink 的语言不一致是根因：`isSafeDoman` 只能用 `parse_url` 之类手段拿 host 做判断（原文只给调用点、未给该函数实现），而 `parse_url('D:/1.txt')` 的 path 是 `D:/1.txt`、没有 host；很多实现会因「无 host」而返回 true（不认为它是危险域名），或者干脆在校验前就因输入不含 `http://` 而提前 return true。之后 `file_get_contents` 走的是本地文件系统分支，直接读盘。
- 即使 host 校验做到了「域名在白名单内」，`urldecode` 在校验之后执行也会引入二次解码差异：先校验再解码，`%2f`、`%00`、`file%3A%2f%2f` 之类可以在校验后被还原成别的语义；若顺序相反（先解码再校验），则是「解码后仍可能被其它包装协议绕过」。此为通用风险提示，本条 PoC 未使用编码载荷，直接用裸路径 `D:/1.txt` 通过。
- `file_get_contents` 支持的协议面决定了危害上限：`file://` 与裸路径通常可用，`php://filter` 可读源码（base64 通道），`phar://` 要能做反序列化则需 `phar.readonly=Off`——原文环境因 `phar.readonly` 未关闭（phpstudy 默认不设置该指令）而放弃 phar 路径，只做文件读取，这个约束值得在利用前先确认。
- 响应回显是这类功能的天赋优势：抓取正文本来就要解析并展示（标题、正文摘要、缩略图），因此读取到的文件内容会直接出现在响应里，无需盲注或外带。

## 触发条件

- 应用存在「按 URL 抓取正文/生成文章/导入外链」的功能（`createFromUrl`、`fetch`、`preview`、`import`）。
- 安全校验只针对域名/主机或只拦特定 scheme，未对最终传给文件函数的字符串做协议白名单（仅允许 http/https）与本地路径拒绝。
- 攻击者可达该接口（本例为后台账号：需登录并带有效 `X-CSRF-Token`；低权限后台用户即可）。
- PHP 的 `allow_url_fopen` 开启（默认开启），进程对目标文件有读权限。

## 利用步骤

1. 定位接口与其参数（如 `GET /app.php/admin/article/createFromUrl?url=`），确认响应里会回显抓取到的标题/正文（说明内容被读入并解析）。
2. 传一个正常的 `http://` 外链，确认功能正常（基线）。
3. 换成无 scheme 的本地绝对路径：Windows `url=D:/1.txt`、Linux `url=/etc/passwd`；观察返回的标题/正文是否变成文件内容。
4. 若被拦，尝试 `url=file:///etc/passwd`、`url=%2fetc%2fpasswd`（利用先校验后 `urldecode` 的顺序差异）、`url=php://filter/convert.base64-encode/resource=/etc/passwd`。
5. 读取高价值文件：应用配置（`config/*.yml`、`*.php` 里的数据库口令）、`.env`、框架密钥；Windows 下读 `D:/` 盘下业务文件。
6. 若同环境存在任意文件上传，再评估 `phar://` 反序列化（需 `phar.readonly=Off`），否则只用读取能力。

## PoC

```http
GET /app.php/admin/article/createFromUrl?url=D:/1.txt HTTP/1.1
Host: target
Cookie: PHPSESSID=<session>; REMEMBERME=<...>
X-CSRF-Token: <token>
X-Requested-With: XMLHttpRequest
Referer: http://target/app.php/admin/setting/optimize
```

```text
# 响应中 Readability 解析出的 title/body 即 D:/1.txt 的内容（原文回显一串 1）
```

```http
GET /app.php/admin/article/createFromUrl?url=file:///etc/passwd HTTP/1.1
Host: target
Cookie: PHPSESSID=<session>
X-CSRF-Token: <token>
```

```php
// 漏洞代码形态
$url = $request->query->get('url');
$isSafeDoman = $this->isSafeDoman($url);   // 只判域名/主机
if ($url) {
    $url = urldecode($url);                 // 校验之后才解码
    $html = file_get_contents($url);        // 接受本地路径与任意包装协议
    $readability->parse($html);             // 内容被解析并回显
}
```

## 变体与关联

- 变体：`urldecode` 在校验之后 → 用 `%2f`/`%66ile`/`%00` 在校验后还原；校验之前解码则改用大小写（`FILE://`）与换行拆分绕过。
- 变体：只拦 `http://`/`https://` 之外的前缀时，用 `file://`、`php://filter`、`data://`、`phar://` 逐个试；`php://filter` 读源码最稳（base64 通道避免二进制截断）。
- 变体：把读取到的内容交给模板/解析器时可能升级：Readability 解析结果进编辑器 → 若允许 HTML 则可能是存储型 XSS；若目标把内容写入模板则可能进一步到 RCE。
- 关联：`[[web-generic-ssrf-icpas-rj-get-token-file-scheme]]` 是「完全不做校验」的同类入口；`[[web-php-deserialization-phar-read-uploaded-image-pop-chain]]` 是本卡在第 6 步（`phar.readonly=Off` 时）的升级方向；`[[web-generic-ssrf-php-preview-line-case-filter-lfi]]` 是「校验只覆盖第一行/大小写」的绕过变体。
- 边界：校验改为协议白名单（仅 http/https）+ 主机白名单 + 拒绝本地路径、且在任何解码之后执行时，链断；`allow_url_fopen=Off` 时 `file_get_contents` 对 URL 与本地路径的可用性会变化（本地路径仍可用）。

## 检测与防御

- 检测：抓取类接口的 `url` 参数出现无 scheme 的绝对路径、`file://`、`php://`、`phar://`、`data://`；响应正文与请求的外链内容不符（说明读到了本地文件）。
- 修复：对 `url` 参数只允许 `http`/`https` 且 `parse_url` 后 host 在白名单内；拒绝含 `://` 之外的包装协议与绝对路径；`urldecode` 应在校验之前完成，且校验对象是最终要传给文件函数的字符串。
- 加固：用 `curl` 显式设置协议、限制重定向与响应大小，替代 `file_get_contents`；抓取组件以低权限账号运行在独立网络域；对读取到的内容做长度/类型限制，避免敏感文件直接回显。
