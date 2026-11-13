---
id: mobile-android-hybrid-apk-assets-www-js-aes-key-method-idor-enumeration
title: Hybrid APK assets/www H5 资源泄露 AES-CBC 密钥与隐藏 method 接口：篡改 method + org_id 遍历员工 PII
type: scenario
domain: mobile
path: mobile/android
technique: hybrid-apk-assets-www-js-aes-key-method-idor-enumeration
aliases:
- APK 改 ZIP 看 assets/www
- umi.js 找 AES key
- H5 加密密钥泄露
- method 篡改越权
- zyhyy 接口枚举
- org_id 爆破
- 免脱壳 APP 渗透
- 混合 APP 前端资源
tags:
- mobile
- android
- hybrid
- h5
- umi
- apk
- assets
- aes-cbc
- hardcoded-key
- idor
- enumeration
- pii
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V507
  verified_at: '2026-11-11T04:38:50+08:00'
  notes: 已对照13436原文与全部13图核对：图02 assets/www 目录；图03 /api/rest.json 166处；图04 mode 177处；图05 JS 中 AES mode=CBC/padding=Pkcs7、key/iv 由 Utf8.parse 字符串常量生成；图06 解密出 method/staff_code/sessionId/version/content；图07-08 zyhyy.qryOrgInfoByAreaId/qryStaffInfoByOrgId 与 area_id/staff_type/org_id 参数；图09-12 替换 method 加密发包并解出 staff_name/staff_phone/user_name；图13 Burp 遍历 org_id 以'该组织下没有人员信息/服务执行成功'区分命中。标题与一句话结论所述'加固APK仅保护DEX/SO、assets/www 原样打包'与原文'有壳脱壳失败+assets/www'一致；原理中'DEX 加壳只保护原生代码'措辞略泛（应指 DEX/SO 等原生侧），不影响技术判断，建议后续措辞修正为'只保护 DEX/SO 等原生侧'。dedup复核：与 web-generic-auth-frontend-aes-ecb-hardcoded-key-student-id-pii-enumeration（Web前端ECB+学号）、front-end-hardcoded-aes-ecb-traffic-decrypt（Web流量解密）、mobile-miniprogram-wxapkg-aes-cbc-sorted-sign-replay、mobile-miniprogram-custom-aes-key-sign-recompute-id-enumeration（wxapkg+签名/派生密钥）在载体、算法与接口维度不同，库内无 APK assets/www+method 分发篡改同类卡，非同链，保留。属移动APP场景非组件版本类，affected_versions 为空；无 sources/source_url；未执行任何请求/PoC。
---

## 一句话结论

加固的 APK 往往只保护 DEX/SO，`assets/www` 等目录下的 H5 资源仍原样打包；把 APK 改名 ZIP 取出 `umi.js` 等前端 JS，就能直接找到 AES-CBC 的 key/IV、请求加解密函数与后端 method 清单。解密流量后仅替换 JSON 中的 `method` 名称，即可调用 UI 不可达的隐藏接口；配合可预测的 `org_id`/`area_id` 遍历，可批量拉取组织架构与员工姓名、手机号等 PII。

## 原理

- **Hybrid APP 的资源边界**：混合开发 APP 用 WebView 加载 `assets/www`（或类似目录）下的本地 H5 页面；DEX 加壳只保护原生代码，打包工具默认把 Web 资源原样放进 APK。APK 本质是 ZIP，攻击者无需脱壳即可浏览这些资源。
- **前端密钥必然可见**：应用层加密在 JS 中实现，AES key 与 IV 必须以字符串常量或可推导形式下发到客户端；拿到 JS 的人可以还原算法并离线解密/加密任意请求。前端加密只是提高抓包阅读成本，不构成服务端授权。
- **method 分发接口暴露全部能力**：后端用 `{"method":"xxx.yyy","content":{...}}` 形式分发请求，前端 JS 中保存了所有 method 名称（包括 UI 未使用的隐藏接口）。攻击者搜索 method 前缀（原文为 `zyhyy.`）即可得到接口清单，把正常请求的 method 换成目标接口、按需补齐参数即可调用。
- **真正的漏洞是服务端对象级授权缺失**：`qryOrgInfoByAreaId`、`qryStaffInfoByOrgId` 一类接口只校验会话/员工号，按传入的 `area_id`/`org_id` 返回组织与人员信息，未校验调用者是否属于该组织；组织 ID 通常连续或可预测，配合 `hasNext` 分页即可遍历全量。
- **为什么整条链成立**：客户端资源（JS/密钥/接口名）不可信，服务端却把“接口名与参数由客户端提供”当作正常业务；只要服务端缺少对象级授权与频率限制，客户端的任何秘密都能转化为越权查询能力。
- **原文的“另类”点**：面对有壳且流量全加密的 APP，作者没有脱壳，而是走 APK 资源侧信道拿到 H5 的加密参数与接口清单，绕过了逆向加固的门槛。

## 触发条件

- 目标为 Hybrid/WebView 类 APP，含 `assets/www`、`assets/dist` 等 H5 资源目录，且这些资源未加密/未做完整性保护。
- APP 与后端之间的请求体/响应体使用前端 JS 实现的应用层加密（如 AES-CBC/ECB + Base64）。
- 后端采用 method 名称分发的统一入口（如 `/rest.json`），且 JS 中可枚举出隐藏 method。
- 服务端对组织/人员查询接口缺少对象级授权，`org_id`/`area_id` 等参数可预测或可遍历。
- 接口无频率限制/批量限制，响应包含姓名、手机号、账号等敏感字段。

## 利用步骤

1. 下载 APK，改后缀为 `.zip` 解压，浏览 `assets/www`（或 `assets/dist`、`assets/public`）目录，收集 `app.js`、`umi.js`、`chunk-*.js` 等前端 bundle。
2. 用格式化/美化工具处理压缩的 JS，正则搜索 `/api/`、`rest.json`、`requestWithContent`、`AES`、`CBC`、`ECB`、`mode`、`iv`、`key` 等关键字，定位加解密函数与请求封装。
3. 提取 key、IV、模式与填充（原文为 AES/CBC/PKCS7、key/IV 为 JS 中的字符串常量），在 Burp 加解密插件或本地脚本中验证：能解密抓到的请求/响应，得到含 `method` 与 `content` 的 JSON。
4. 在 JS 中搜索 method 前缀（原文为 `zyhyy.`），列出所有 `xxx.methodName` 调用及参数结构；重点关注组织、人员、通讯录、查询类接口。
5. 用有效会话构造请求：保留 `staff_code`/`sessionId` 等字段，替换 `method` 为目标接口，按 JS 中的参数名填 `area_id`、`staff_type`、`org_id` 等，加密后发送。
6. 先调用区域/组织查询拿到 `org_id`，再调用人员查询接口；对 `org_id` 做递增/字典遍历（Burp Intruder + 自动加密），按响应中“无人员信息/服务执行成功”区分命中与空结果。
7. 汇总命中的组织与员工 PII（姓名、手机号、账号、工号），统计影响范围并在授权范围内抽样验证，避免全量导出。

## PoC

```python
import base64, json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

KEY = b"<assets/www 前端 JS 中的 key 字符串>"
IV  = b"<assets/www 前端 JS 中的 iv 字符串>"

def enc(obj: dict) -> str:
    pt = json.dumps(obj, separators=(",", ":")).encode()
    return base64.b64encode(AES.new(KEY, AES.MODE_CBC, IV).encrypt(pad(pt, 16))).decode()

def dec(b64: str) -> dict:
    return json.loads(unpad(AES.new(KEY, AES.MODE_CBC, IV).decrypt(base64.b64decode(b64)), 16))

# 解密原始请求，确认 method 与参数结构
# dec("<抓包中的密文>") -> {"method": "zyhyy.qryNextOrgStructureView", "content": {...}}

# 替换为 JS 中枚举到的隐藏接口，构造加密请求
payload = enc({
    "method": "zyhyy.qryOrgInfoByAreaId",
    "content": {"area_id": "<areaId>", "staff_type": "<staffType>"},
})
```

```text
# 原文验证路径：
# 1) qryNextOrgStructureView/qryOrgStructureView 获取组织树与 org_id
# 2) qryOrgInfoByAreaId 按 area_id 获取组织详情
# 3) qryStaffInfoByOrgId 按 org_id 获取员工（staff_name/staff_phone/user_name）
# 4) 遍历 org_id：响应 "该组织下没有人员信息" 与 "服务执行成功" 可区分命中
```

## 变体与关联

- 变体：加密算法为 AES-ECB 或 CBC 固定 IV；key 可能藏在独立 config JS、由字符串拼接/编码得到，需在 JS 中还原而非只搜常量。
- 变体：method 分发接口可替换为写操作（修改/删除/导出），但需评估破坏性，授权测试中优先只读查询。
- 变体：小程序/快应用同样存在前端包内 JS 泄露密钥与接口清单的问题，入口换成 wxapkg 等包格式。
- 关联：[[web-generic-auth-frontend-aes-ecb-hardcoded-key-student-id-pii-enumeration]]（Web 前端 AES-ECB + 学号遍历 PII）、[[front-end-hardcoded-aes-ecb-traffic-decrypt]]（前端 JS 硬编码密钥解密流量）、[[mobile-android-webview-jsbridge-arbitrary-origin-credential-theft]]（WebView/JSBridge 攻击面）。
- 边界：H5 资源加密/混淆且密钥不在包内、服务端做对象级授权与限速、method 白名单按角色校验、ID 为不可预测 UUID 时，本链失效。

## 检测与防御

- 检测：APK 包内 `assets/www` 出现未加密的 JS bundle 与硬编码 key/IV 特征；同一会话短时间内大量不同 `org_id`/`area_id` 的加密查询；响应包含员工姓名、手机号等 PII 且调用者不属于该组织。
- 防御：不要把长期密钥与完整接口清单当作安全边界；服务端对每个对象查询做对象级授权（校验调用者所属组织/角色/租户），method 白名单按角色下发而非全量暴露。
- 加固：对 H5 资源做完整性校验与适度加密只能提高逆向成本，不能替代服务端授权；对查询接口做频率限制、分页上限与审计；敏感字段脱敏返回。
- 客户端：不要在 JS 中硬编码长期 key/IV；使用会话级密钥并绑定服务端认证；对 method 调用做签名与防重放。
