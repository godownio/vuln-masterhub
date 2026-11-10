---
id: web-php-rce-escapeshellcmd-blacklist-env-flag-read
title: escapeshellcmd 之下仍能执行：黑名单只封读文件命令（cat/tac/nl/head/tail/read）而漏掉 env，两段 md5（松散 0e/数组 + 严格数组）过关后直接读环境变量拿 flag
type: scenario
domain: web
path: web/php/rce
technique: escapeshellcmd-name-blacklist-env-flag-read
tags:
- php
- rce
- command-injection
- escapeshellcmd
- waf-bypass
- blacklist
- md5
- magic-hash
- type-juggling
- env
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W4B
  verified_at: '2026-11-08T22:01:57+08:00'
  notes: 已对照原文核对（本次核对未读取图片，仅依据正文贴出的 ez_php 源码与 payload）：forbidden_commands = ['cat','tac','nl','more','less','head','tail','read']、shell_exec(escapeshellcmd($sign))、两段 md5 校验（第一段 == 松散、第二段 === 严格）与卡内一致；「ls / 与 cat /f* 都无 flag → 改读 env 拿到 flag」的落地路径也与原文一致。参数位置核对无误：usn/usn1/sign 走 GET、pwd/pwd1 走 POST，卡内 PoC 的分布正确。未验证点：①卡内用「数组传参 → md5(array) 返回 null → null === null」解释两段绕过，这在 PHP 7 下成立（原文环境），但 PHP 8 起 md5(array) 会抛 TypeError（fatal），该写法需按目标 PHP 版本确认，卡内未标注此边界；②原文未贴出两段 md5 的具体 payload（截图里只有结果），卡内 PoC 的 usn[]/pwd[] 数组写法属按源码推导；③未在原文容器复跑 env 读取。本次核对未读取图片。
url: /docs/web/php/rce/web-php-rce-escapeshellcmd-blacklist-env-flag-read/
draft: false
kb_aliases:
- escapeshellcmd 仍可执行
- 黑名单漏 env
- 两段 md5 校验绕过
- 0e 松散比较 + 数组严格比较
- flag 在环境变量里
- cnctf ezphp
---

## 一句话结论

`shell_exec(escapeshellcmd($sign))` 并不是安全边界：`escapeshellcmd` 只转义 `;|&$><()` 等**元字符**，不阻止执行单个命令，所以「黑名单封读文件命令」的思路一旦漏掉 `env`/`printenv` 就等于没封；再配上两段 md5 校验（松散 `==` 用 0e 魔术哈希或数组、严格 `===` 用数组返回 `null === null`）即可在拿到执行后直接读环境变量里的 flag。

## 原理

- **escapeshellcmd 的作用域**：它对字符串里所有 shell 元字符（`` ` ``、`;`、`|`、`&`、`$`、`>`、`<`、`(`、`)`、`\`、`'`、`"`、换行等）加反斜杠，从而阻断命令拼接/管道/重定向；但它**不检查命令本身**，`env`、`ls`、`id` 这类单词命令照常执行。因此「能执行什么」完全取决于后续的命令名黑名单，而不是 escapeshellcmd。
- **黑名单的盲区**：题目只封 `cat/tac/nl/more/less/head/tail/read` 这些「读文件」命令，目的是防止直接读 `/flag`；但 `env`、`printenv`、`ls`、`whoami` 不在表内。当 flag 被注入到容器环境变量时，`env` 一步到位——这属于「防御者只想到了一种数据来源」。
- **两段 md5 的语义差异**：第一段 `$usn != $pwd && md5($usn) == md5($pwd)` 是松散比较，两条路：① 0e 魔术哈希（`240610708` 与 `QNKCDZO` 的 md5 都是 `0e` 开头纯数字，`==` 下都当 0）；② 数组传参，`md5(array)` 返回 `null`，`null == null` 为真。第二段 `$usn1 !== $pwd1 && md5($usn1) === md5($pwd1)` 是严格字符串比较，0e 路线失效（两个哈希串不相等），但数组路线仍成立：两次 `md5(array)` 都得 `null`，`null === null` 为真。
- **为什么用数组而不是碰撞**：真碰撞（同 md5 不同明文）要准备二进制对，成本高且受限于传参形态；数组绕过是纯语法层，`a[]=1&a[]=2` 即得两个不同数组且哈希皆为 `null`，一次到位。**版本边界**：`md5(array)` 返回 `null` 只在 PHP 7.x 及更早成立；PHP 8 起 `md5()` 等字符串函数的数组入参会抛 `TypeError`（致命错误），此时只能改用 0e 魔术哈希对（例如 `240610708`/`QNKCDZO`，严格段再找同为 `0e` 前缀且 `===` 相等的真碰撞对）。
- **flag 的落地位置决定打法**：原文 `ls /`、`cat /f*` 都没有 flag，`whoami` 显示低权限（读不到 root 目录），说明 flag 不在文件系统常规位置；`env` 直接命中——所以这一步的关键是「换数据来源」，而不是继续绕命令黑名单。

## 触发条件

- PHP 应用把用户可控参数交给 `shell_exec`/`exec`/`system` 等执行，前置校验为「命令名子串黑名单」+ `escapeshellcmd`。
- 黑名单未覆盖通用的信息读取命令（`env`、`printenv`、`ls`、`whoami`、`ps`），或未禁止 `$()`/反引号之外的等价写法。
- 入口前还有 md5 类校验：至少一段是松散比较（可用 0e 或数组），或两段都用数组可过。
- 敏感数据（flag/凭据）位于环境变量或其它未被黑名单覆盖的数据源。

## 利用步骤

1. 读源码（本题 `highlight_file` 直接回显），确认四件事：md5 校验的运算符（`==` 还是 `===`）、命令执行函数、是否包了 `escapeshellcmd`、黑名单列表。
2. 过第一段松散比较：优先 `usn[]=1&pwd[]=2`（两个不同数组，`md5` 皆 `null`）；若参数形态不允许数组，改用 0e 对（`240610708` 与 `QNKCDZO`）。
3. 过第二段严格比较：只能用数组（`usn1[]=1&pwd1[]=2`），`null === null` 成立；0e 对在这里不成立。
4. 探测命令黑名单边界：先 `ls`，再 `whoami`、`id`、`ls -l /`，确认哪些命令名被拦、当前权限如何。
5. 换数据源：`cat /f*` 为空且目录无 flag 时，直接 `env` 或 `printenv`；仍不够时看 `ls /proc/self/environ`、`cat /proc/1/environ`（注意此时 `cat` 被拦，可用 `env`、`printenv`、`strings /proc/self/environ`，或 `xxd`）。
6. 复核 payload：确认 `sign` 里没有黑名单子串（`cat`/`tac`/`nl`/`more`/`less`/`head`/`tail`/`read`），且没有会被 `escapeshellcmd` 转义掉的元字符（否则命令被拼坏）。

## PoC

```http
POST /?usn[]=1&usn1[]=3&sign=env HTTP/1.1
Content-Type: application/x-www-form-urlencoded

pwd[]=2&pwd1[]=4
```

```text
# 校验链：
#   usn[]=1 / pwd[]=2   -> 两个不同数组，md5(array)=null，null == null    => 第一段通过
#   usn1[]=3 / pwd1[]=4 -> 两个不同数组，md5(array)=null，null === null   => 第二段通过
#   sign=env            -> 不含黑名单子串，escapeshellcmd 无需转义，shell_exec('env') 执行
#   （若走 0e 路线：第一段 usn=240610708&pwd=QNKCDZO，第二段仍必须用数组）
```

```php
// 目标校验逻辑（原文）
if ($usn != $pwd && md5($usn) == md5($pwd)) {
    if ($usn1 !== $pwd1 && md5($usn1) === md5($pwd1)) {
        $forbidden_commands = ['cat','tac','nl','more','less','head','tail','read'];
        foreach ($forbidden_commands as $f) { if (strpos(strtolower($sign), $f) !== false) die('lol'); }
        echo '<pre>' . shell_exec(escapeshellcmd($sign)) . '</pre>';
    }
}
```

## 变体与关联

- `escapeshellcmd` 的其它绕过面：它只转义元字符，**不转义空格与参数**，所以「危险的不是拼接而是命令选择」；若黑名单封了 `cat`，可用 `ls`、`find`、`grep`、`sort`、`awk`、`xxd`、`strings`、`tar`、`cp`、`env` 等未封命令完成同等目的。
- 与「引号拼接 + glob」卡的区别：那条针对 `stripos` 子串黑名单，用 `c''at /f*` 让 shell 自己做引号删除与通配展开；本卡的 `escapeshellcmd` 会把引号转义掉，那条技巧在此失效，必须换**命令**而不是换**写法**。
- 与「反斜杠转义」卡的区别：`ca\t /flag` 依赖 shell 对反斜杠的处理，`escapeshellcmd` 会把 `\` 再转义一层，同样失效。
- md5 侧关联：松散比较的 0e 魔术哈希与「数组 → null」两条路，与严格比较只能用数组；若应用用 `hash_equals`/`password_verify`，这两条全废。
- 数据源变体：flag 在环境变量（本题）、在 `/proc/1/environ`、在启动脚本、在 MySQL 变量、在 cloud metadata —— 黑名单往往只防「读文件」这一路。

## 检测与防御

- 检测：请求中出现 `sign=env`、`printenv`、`whoami`、`ls` 等非预期命令；参数以数组形式提交（`usn[]=`）打 md5 校验；`escapeshellcmd` 前后参数长度/字符集异常。
- 防御：不要把用户输入交给 `shell_exec`（用 `proc_open` + 参数数组，或干脆不执行外部命令）；`escapeshellcmd` 不能替代白名单，应改为「允许的命令与参数枚举」；命令名黑名单必须覆盖全部信息读取途径（`env`/`printenv`/`find`/`tar`/`cp`/`grep`/`xxd`/`strings`…），更好的做法是禁止执行；md5 校验改 `hash_equals(hash('sha256',...))`，并对参数做 `is_string` 强类型检查（数组直接拒绝）；flag/凭据不要放环境变量。
