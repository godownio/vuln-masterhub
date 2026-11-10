---
id: web-java-component-publiccms-template-replace-traversal-execscript-rce
title: PublicCMS 模板替换路径穿越改写预置脚本，配合 execScript 执行导致 RCE
type: scenario
domain: web
path: web/java/component
technique: publiccms-template-replace-traversal-execscript-rce
aliases:
- PublicCMS RCE
- cmsTemplate/replace
- replaceFileList 路径穿越
- sysSite/execScript
- sync.sh 替换
- PublicCMS 任意文件内容修改
- PublicCMS 代码审计
tags:
- java
- publiccms
- path-traversal
- arbitrary-file-write
- template
- rce
- cms
- execscript
affected_versions: PublicCMS V4.0.202302.e（原文源码版本）
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V276
  verified_at: '2026-11-07T23:50:43+08:00'
  notes: 已对照原文与 17 张图核对：img16 replaceFileList 的 Paths.get(dirPath,result.getPath()) 按行替换、img17 修复 diff getSafeFileName、原文 replace 请求 replaceList[0].path=../../script/sync.sh 与 execScript command=sync.sh、img15 执行脚本输出 current directory C:\data\publiccms / repo not config!（证明脚本执行功能可用）均一致。注意原文未展示替换后实际执行注入命令（open -a calculator.app）的回显截图，最终 RCE 为代码级链，卡片正文已注明，confidence medium 合理。
---

## 一句话结论

PublicCMS 后台 `/admin/cmsTemplate/replace` 把 `replaceList[].path` 直接与模板目录 `Paths.get(dirPath, path)` 拼接后按行读写文件，未做规范化与目录限制；攻击者用 `../../script/sync.sh` 跳出模板目录，把预置同步脚本中的内容替换为命令，再调用 `/admin/sysSite/execScript?command=sync.sh` 让系统复制并执行该脚本，即可在 Web 进程权限下 RCE（也可改写 SSH 公钥、计划任务等）。

## 原理

- **模板替换入口**：`CmsTemplateAdminController.replace` 接收 `TemplateReplaceParameters replaceList`、`word`、`replace`；计算 `filePath = siteComponent.getTemplateFilePath(site.getId(), "/")` 后调用 `CmsFileUtils.replaceFileList(filePath, replaceList, word, replace)`，最后清模板缓存并记录操作日志。
- **replaceFileList 的路径问题**：对每个替换项，代码执行 `File file = Paths.get(dirPath, result.getPath()).toFile();`，然后 `FileUtils.readLines(file)`、逐行 `line.replace(word, replace)`、`FileUtils.writeLines(file, list)`。没有 `normalize()`/`toRealPath()`/`startsWith(dirPath)` 校验，也没有限制扩展名与目标目录；`result.getPath()` 中的 `../` 可以逐级跳出模板目录，访问进程有权限的任意文件。
- **execScript 执行预置脚本**：站点后台提供“执行脚本”功能（`/admin/sysSite/execScript`），把预置在 PublicCMS 数据脚本目录中的脚本（如 `sync.bat`/`sync.sh`、`backupDB.bat`/`backupDB.sh`）复制到工作目录并执行；原文截图显示执行 `sync.bat` 时输出当前目录和 `repo not config!`。由于上一步可以改写这些脚本的内容，执行时就会运行攻击者注入的命令。
- **注入方式**：替换是按行把 `word` 替换为 `replace`，攻击者只需选择脚本中存在的字符串作为 `word`（原文用 `-echo`），把 `replace` 设为“原串 + 命令分隔符 + 恶意命令”（如 `-echo;open -a calculator.app`），写入后脚本下一行仍可保持原逻辑，命令在脚本执行时被 shell/bat 解释。
- **危害扩展**：该替换能力本质是“任意文件内容替换”，除脚本外还可改写 `~/.ssh/authorized_keys`、crontab、systemd 服务、其他启动脚本等，形成持久化；修复版在 `Paths.get` 外层加了 `CmsFileUtils.getSafeFileName(...)`，通过删除 `..` 阻断目录穿越。
- 攻击前提是已取得管理员会话与 CSRF token；这不是未授权漏洞，但后台文件替换/脚本执行组合把“内容编辑”提升为命令执行。

## 触发条件

- 目标为 PublicCMS（原文源码版本 V4.0.202302.e），攻击者拥有管理员账号/会话，并能获取 CSRF token。
- 后台模板替换功能可用，`replaceList[].path` 未做规范化/白名单校验。
- “执行脚本”功能可用，预置脚本目录存在且 Web 进程有执行权限（Linux `sh`/Windows `bat`）。
- 需要改写的文件对 Web 进程可读可写；脚本执行使用与 Web 进程相同或更高权限。
- 若使用原文的 macOS 示例，需对应脚本确实包含可替换的 `-echo` 等字符串；其他平台需按脚本内容选择 `word`。

## 利用步骤

1. 登录 PublicCMS 后台，获取 CSRF token（请求参数 `_csrf`）与管理员会话 Cookie。
2. 确认目标预置脚本：后台“站点 → 执行脚本”页面可见 `sync.bat`/`sync.sh`、`backupDB.bat`/`backupDB.sh` 等；对应文件位于数据脚本目录（原文路径 `<PublicCMS>/publiccms-parent/publiccms/data/publiccms/script`）。
3. 发送替换请求：`POST /admin/cmsTemplate/replace?navTabId=placeTemplate/list`，参数 `replaceList[0].path=../../script/sync.sh`、`replaceList[0].indexs=0`、`word=<脚本中已有字符串>`、`replace=<原串;恶意命令>`；路径穿越到脚本目录。
4. 校验替换结果：重新读取脚本/再次触发替换页面，确认目标行已变为注入内容；必要时调整 `word` 与 `indexs` 使替换命中正确行。
5. 触发执行：`POST /admin/sysSite/execScript?navTabId=sysSite/script`，`command=sync.sh&parameters=`（Windows 用 `sync.bat`），服务端复制并执行脚本，命令以 Web 用户权限运行。
6. 建立回连/读取结果：将命令改为反弹 shell 或写入文件；也可改 `authorized_keys`/crontab 做持久化。
7. 清理：恢复脚本原内容、删除上传/临时文件、修复后台弱口令与权限。

## PoC

替换模板文件（原文请求，路径穿越到脚本目录）：

```http
POST /admin/cmsTemplate/replace?navTabId=placeTemplate/list HTTP/1.1
Host: target:18080
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Cookie: <admin session>

_csrf=<token>&word=-echo&replace=-echo%3bopen+-a+calculator.app&replaceList%5B0%5D.path=../../script/sync.sh&replaceList%5B0%5D.indexs=0
```

执行脚本：

```http
POST /admin/sysSite/execScript?navTabId=sysSite/script HTTP/1.1
Host: target:18080
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Cookie: <admin session>

_csrf=<token>&command=sync.sh&parameters=
```

```text
# 原版 replaceFileList：
File file = Paths.get(dirPath, result.getPath()).toFile();  // path 可控，../ 穿越
readLines -> line.replace(word, replace) -> writeLines

# 修复版：
File file = Paths.get(dirPath, CmsFileUtils.getSafeFileName(result.getPath())).toFile();
// getSafeFileName: path.replace("..", "")
```

说明：原文给出了两端代码、替换与执行请求及 `execScript` 的执行输出，但未展示最终反弹 shell 截图；卡片将链路与前置条件写明，PoC 未在本机执行。

## 变体与关联

- 目标文件变体：预置 `sync.bat`/`sync.sh`、`backupDB.*` 等脚本；`~/.ssh/authorized_keys`、crontab、systemd unit、启动脚本、Web 模板自身等任意可写文件。
- 注入变体：按目标脚本内容选择 `word`，用 `;`、`&&`、`|`、换行等注入命令；Windows bat 用 `&`/`||`；也可直接替换整行/整段逻辑。
- 路径变体：`../../`、多级穿越、绝对路径（`Paths.get` 对绝对路径的处理因平台而异）、URL 编码；修复版只删除 `..`，其他变体是否仍可穿越需按版本实测，不能仅凭修复代码假定安全。
- 关联卡片：[[web-generic-file-inclusion-goldlib-download-items-traversal-read]]、[[web-java-component-halo-theme-savetpl-path-traversal-write]]（同类“模板/主题文件路径穿越写”）、[[web-generic-file-upload-template-relative-path-original-filename-arbitrary-write]]（上传侧任意写）、[[pentest-persistence-linux-shell-watchdog-pgrep-jitter-relaunch]]（脚本持久化思路）。
- 边界：没有管理员权限/CSRF token 时无法调用；替换接口被禁用、脚本执行功能关闭、脚本目录不可写、Web 用户无执行权限时链路失效；修复版 `getSafeFileName` 若部署则 `..` 被删除。

## 检测与防御

- 检测：`/admin/cmsTemplate/replace` 请求的 `replaceList[].path` 含 `../`、绝对路径或异常扩展名；替换后脚本目录文件内容变化；`/admin/sysSite/execScript` 短时间内的异常调用；Web 进程拉起 `sh`/`bash`/`cmd` 子进程；脚本目录出现新增/修改文件。
- 修复：对 `result.getPath()` 做 `normalize()`/`toRealPath()` 并校验 `startsWith(templateDir)`，拒绝绝对路径与 `..`；文件类型/目录白名单；不要用简单 `replace("..","")` 作为唯一防护。
- 加固：后台最小权限，管理员强口令 + MFA；CSRF token 校验；关闭不需要的“执行脚本”功能；脚本目录与模板目录对 Web 用户只读（执行功能单独提权/受控）；对脚本与模板做完整性监控。
- 响应：发现异常替换后恢复脚本、排查持久化（SSH keys、cron、服务）、轮换后台与系统凭据，并检查同批管理员账号是否被攻陷。
