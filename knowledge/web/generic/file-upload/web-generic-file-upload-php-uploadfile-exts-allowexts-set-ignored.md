---
id: web-generic-file-upload-php-uploadfile-exts-allowexts-set-ignored
title: PHP UploadFile 魔术方法 __set 只认 config 已有键：业务写 $upload->exts 被静默丢弃（正确键 allowExts），白名单为空导致任意文件上传
type: scenario
domain: web
path: web/generic/file-upload
technique: php-uploadfile-exts-config-key-set-ignored
aliases:
- $upload->exts 无效
- allowExts 与 exts
- UploadFile __set
- 上传后缀白名单被静默忽略
- ThinkPHP UploadFile 任意上传
- checkExt empty allowExts
tags:
- php
- thinkphp
- file-upload
- unrestricted-upload
- magic-method
- code-audit
- webshell
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V523
  verified_at: '2026-11-11T13:35:55+08:00'
  notes: 已对照原文与全部 16 图核对：UploadController 继承 Common\Controller\UploadController（图03）；uploadImg 中 $upload->exts = array(jpg,gif,png,jpeg)（图04）；autoCheck→check→checkExt 且 allowExts 默认 array(0)（图05-07）；改为 allowExts 后 config 变 array(4)（图08-09）。修正：1) 攻击面原称搜索命中的任意上传 action 均可利用，但图10 显示 StudentFaceController 使用 \Think\Upload（其 exts 是否有效需按框架版本核实），已加“须确认实例化为本文 UploadFile”限定；2) 原路由示例 /setting.php/index/uploadImg 与登录路由 /setting.php/index/login 的入口/控制器/方法格式矛盾，改为 /setting.php/upload/uploadImg 并注明以实际入口为准。原文未给出实际上传请求/响应，PoC 中 file 字段名为示意；未实测。dedup 候选（ThinkPHP 调试路径泄露、Yii2 saveAs 等）非同链，dup-scan 无涉及 pair。
---

## 一句话结论

PHP 上传类（ThinkPHP 3.x `UploadFile`）用 `public function __set($name,$value){ if(isset($this->config[$name])) $this->config[$name]=$value; }` 实现属性赋值，只接受 `$config` 里已存在的键；业务代码写成 `$upload->exts = array('jpg','gif','png','jpeg')`（正确键应为 `allowExts`）时赋值被静默丢弃，`checkExt()` 因 `empty($this->allowExts)` 直接返回 true，于是任意后缀文件都能上传——只要系统里存在 `$upload->exts =` 的上传接口，就存在任意文件上传。

## 原理

- **魔术方法静默失败**：`__set` 的 `if (isset($this->config[$name]))` 保证了只有 config 数组中已有的键才会被赋值；`exts` 不在默认 config（只有 `allowExts`、`allowTypes`、`maxSize`、`savePath` 等），所以 `$upload->exts=...` 既不改 config 也不报错。
- **默认 config 的语义**：`'allowExts' => array()` 注释“留空不作后缀检查”；`checkExt($ext)` 的实现是 `if(!empty($this->allowExts)) return in_array(strtolower($ext), $this->allowExts, true); return true;`——白名单为空即全部放行。
- **上传流程**：`upload()` → `autoCheck` 为 true 时调用 `check($file)` → 检查文件类型时调用 `checkExt($file['extension'])`；由于 allowExts 空，任意扩展名通过；随后按 `saveRule`（uniqid）命名并 `move_uploaded_file` 到 `savePath`，保留后缀。
- **为什么开发没发现**：`$upload->maxSize`、`$upload->savePath`、`$upload->saveRule` 等键都在 config 中，赋值正常生效；只有 `exts` 这种“看起来合理”的键被吞掉，代码审查/黑盒测试时很难从功能上察觉，只有单步调试查看 `$this->config` 才会发现。
- **攻击面**：文中搜索 `$upload->exts` 在多个控制器中命中（ActivitivesController、StudentFaceController 等）；但利用前须确认该控制器实例化的是本文的 `UploadFile`（config 无 `exts` 键）——截图中 StudentFaceController 使用的是 `\Think\Upload`，其 `exts` 是否有效需按所用 ThinkPHP 版本核实，不能一概而论。上传目录在 Web 根下且 PHP 可解析时可直接 getshell。

## 触发条件

- 系统使用该 UploadFile 类（ThinkPHP 3.x 或同结构封装），且业务代码用 `$upload->exts =` 而非 `allowExts` 设置后缀。
- 上传 action 可访问（登录/未登录均可，取决于系统）。
- 上传目录位于 Web 根下且允许 PHP 解析；`saveRule` 为 uniqid 等可预测/可回显命名。
- 服务端未在 Nginx/Apache 层禁 PHP 上传目录。

## 利用步骤

1. 源码审计：全局搜索 `$upload->exts` 与 `allowExts`，确认前者所在控制器/action。
2. 断点/调试确认 `$this->config['allowExts']` 为空数组（或直接黑盒尝试上传 `.php`）。
3. 找到上传接口路由（原文登录路由为 `/setting.php/index/login`，按同一“入口/控制器/方法”格式 uploadImg 应为 `/setting.php/upload/uploadImg`；入口与模块映射以实际系统为准），构造 multipart 上传 `1.php`，Content-Type 伪装 `image/png`。
4. 根据响应/`getUploadFileInfo()` 返回的 `savename`/`savepath` 拼接访问 URL，确认 PHP 执行。
5. 若被重命名规则拦截，尝试 `.phtml`/`.php5` 等可解析后缀或结合解析漏洞。

## PoC

```http
POST /setting.php/upload/uploadImg HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryQayVsySyhSwgpmLk

------WebKitFormBoundaryQayVsySyhSwgpmLk
Content-Disposition: form-data; name="file"; filename="1.php"
Content-Type: image/png

<?php phpinfo();?>
------WebKitFormBoundaryQayVsySyhSwgpmLk--
```

```text
# 源码对照：错误写法（本文系统）
$upload = new UploadFile();
$upload->exts = array('jpg','gif','png','jpeg');   // exts 不在 config，__set 静默忽略
# 正确写法（修复）
$upload->allowExts = array('jpg','gif','png','jpeg');
```

## 变体与关联

- 变体：其他“看似合理但不在 config”的键同样被忽略（如 `ext`、`allowExt`、`type`），审计时应以 config 键名为准。
- 变体：若 `autoCheck` 被显式设为 false，连 `check()` 都不走，任意上传更直接。
- 关联：[[web-php-framework-yii2-uploadedfile-saveas-unfiltered]]（另一框架上传类不做校验的同类问题）、[[web-php-wordpress-admin-weak-password-theme-editor-rce]]（后台写 PHP 的另一入口）。
- 边界：部署层若对上传目录禁 PHP、或在 `check()` 中另行做了 MIME/魔数校验，利用失败；`savePath` 不在 Web 根时需结合文件包含/下载。

## 检测与防御

- 检测：源码中 `$upload->exts` 与 `$upload->allowExts` 混用；上传目录新增 `.php`/`.phtml` 文件；`getUploadFileInfo()` 返回的扩展名异常。
- 防御：统一用 `allowExts`（并填写白名单）、开启 `autoCheck`；上传文件重命名为随机名+安全后缀并存到 Web 根外；上传目录关闭 PHP 解析；服务端做 MIME/魔数/图片重编码校验。
- 加固：对上传类做单元测试覆盖“错误配置键不生效”的场景；代码审计把 `->exts`、`->ext` 等疑似键列为高危搜索项。
