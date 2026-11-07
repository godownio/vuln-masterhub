---
id: web-generic-auth-face-liveness-background-replace-base64
title: 单图上传式人脸活体绕过：证件照替换背景后 Base64 提交通过 1:1 认证
type: scenario
domain: web
path: web/generic/auth
technique: face-liveness-bypass-background-replace-base64
tags:
- auth
- biometric
- liveness
- face-recognition
- base64
- bypass
- image
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V74
  verified_at: '2026-11-05T16:56:13+08:00'
  notes: 已对照原文与图06-10核对：请求体确为 {"openId":...,"base64":"data:image/jpeg;base64,..."}，实时照片报“活体认证失败:1:1检测未通过”，证件照直接提交活体失败，换实验室背景后返回 code:200、authenticationFlag:true 及 token，均一致。核对时已将未在原文出现的 /api/app/faceAuth 改为 <face-auth-endpoint> 占位，并把“同一图片可重放”改为条件表述。未验证点：活体模型为厂商特定、卡内 confidence=medium 合理；PoC 未复跑。
url: /docs/web/generic/auth/web-generic-auth-face-liveness-background-replace-base64/
draft: false
kb_aliases:
- 人脸活体绕过
- 证件照换背景过活体
- Base64 人脸认证伪造
- 1:1 人脸比对绕过
- 生物识别对抗
---

## 一句话结论

当身份认证把“摄像头拍照”退化为客户端上传一张 Base64 图片，且活体检测只基于这一张 RGB 图做场景/纹理判断时，攻击者用目标本人的证件照替换成真实场景背景后提交，可同时通过活体检测与 1:1 人脸比对，拿到认证 Token。

## 原理

- 正常的人脸核身应包含“活体检测 + 1:1 比对”两层：活体确认眼前是真人（动作、深度、红外、纹理、屏幕/纸张反射等），1:1 确认这张脸与证件库中的照片一致。
- 该实现把摄像头采集交给客户端：请求体为 `{"openId": "...", "base64": "data:image/jpeg;base64,..."}`，服务端只拿到一张静态 JPEG。没有随机动作挑战、没有视频流、没有深度/红外数据，也没有把图片与本次会话的 nonce 绑定（若缺少重放保护，同一图片可能被重放）。
- 单图活体常依赖图像统计特征：背景是否像真实拍摄环境、是否有屏幕摩尔纹、人脸纹理是否自然、光照是否一致。证件照通常是纯色（蓝/白）背景、正面免冠、光照均匀，容易被判为“非现场拍摄”；而把同一张脸的背景替换成实验室/室内场景后，图像的场景分布更接近现场照片，活体分数随之通过。
- 1:1 比对使用的是证件库中的证件照；攻击者直接使用目标本人的证件照，人脸特征天然一致，因此 1:1 不是障碍，真正的缺口是活体。
- 攻击链通常先通过其他漏洞（弱密码重置、越权下载）取得目标证件照，再用于人脸认证；证件照本身是静态的，不需要目标配合。
- 该绕过依赖具体厂商的活体模型，换环境可能失效；判断时应以“实时拍摄照片能过活体但 1:1 失败、证件照能过 1:1 但活体失败、换背景后两者都过”的差异作为诊断依据。

## 触发条件

- 人脸认证接口接受客户端上传的 Base64/图片，而不是服务端直接采集视频流。
- 活体检测仅基于单张 RGB 图像，没有动作挑战、深度、红外或设备证明。
- 图片未与一次性 nonce/会话绑定，或认证 Token 可重放。
- 攻击者已取得目标本人的证件照（来自系统内越权、公开泄露或其他渠道）。
- 目标人脸库与 1:1 比对使用的参考照片就是该证件照，或与证件照高度相似。

## 利用步骤

1. 抓取人脸认证请求，记录 `openId`、`base64`、`authenticationFlag` 等字段与响应结构。
2. 先用攻击者自己的实时照片测试：若提示“1:1 检测不通过”，说明比对对象是证件库照片，需要用目标本人的照片。
3. 用目标证件照直接 Base64 提交：若提示“活体检测不通过”，说明静态证件照被场景/纹理特征识别。
4. 对证件照做背景替换：保留人脸区域，把纯色证件背景替换为目标现场常见的室内/实验室背景，保持光照、分辨率、噪点自然；必要时做轻微的透视、模糊与 JPEG 二次压缩。
5. 将处理后的图片编码为 `data:image/jpeg;base64,...`，替换请求中的 `base64` 字段重新提交。
6. 观察响应：若 `authenticationFlag=true` 且返回 `token`，说明活体与 1:1 均通过；用该 Token 访问后续业务接口。
7. 若仍失败，调整背景场景、光线方向、图片尺寸与压缩质量，或尝试屏幕翻拍、打印照片等替代活体绕过方式（需按目标模型验证）。

## PoC

```http
POST /<face-auth-endpoint> HTTP/1.1
Host: target
Content-Type: application/json

{"openId":"<会话openId>","base64":"data:image/jpeg;base64,<替换背景后的证件照>"}
```

```json
{
  "msg": "操作成功",
  "code": 200,
  "data": {
    "token": "eyJhbGciOi...",
    "authenticationFlag": true
  }
}
```

```python
import base64, requests

with open("victim_id_photo_bg_replaced.jpg", "rb") as f:
    b64 = "data:image/jpeg;base64," + base64.b64encode(f.read()).decode()

r = requests.post("https://target/<face-auth-endpoint>",
                  json={"openId": open_id, "base64": b64}, timeout=15)
print(r.json())
```

说明：换背景属于图像处理/生成步骤，不是代码漏洞；PoC 仅展示请求形态。原文在特定厂商环境实测通过，其他活体模型可能失败。

## 变体与关联

- 变体：屏幕翻拍/打印照片对抗纹理与摩尔纹检测；高分辨率屏幕 + 适当距离可降低摩尔纹。
- 变体：视频注入/虚拟摄像头把预录视频流喂给客户端；或注入摄像头 API 直接返回伪造帧。
- 变体：深度伪造/换脸把攻击者人脸替换为目标人脸，用于 1:1 而不是活体。
- 关联：[[web-generic-auth-freshman-reset-id-last6-public-pii]]（先接管账号取得证件照，再用于人脸认证的完整链路）；[[web-generic-auth-wechat-miniprogram-sessionkey-encrypteddata-takeover]]（同类身份认证链路的其他绕过面）。
- 边界：服务端强制视频流/多帧、随机动作挑战、深度/红外摄像头、设备证明或人工复核时，单图换背景无效；若 1:1 参考照片与证件照不同，还需要先取得对应照片。

## 检测与防御

- 检测：认证请求中出现 `base64` 图片字段、图片可重放、同一图片多次提交；图片 EXIF/压缩特征与客户端相机不符；活体通过但设备/传感器信息缺失。
- 修复：服务端直接采集视频流或多帧图像，加入随机动作/光线挑战；使用深度、红外或 3D 结构光；将采集与一次性 nonce、设备证明绑定。
- 加固：对上传图片做活体模型升级（纹理、反射、摩尔纹、光照一致性），并结合风控评分与人工复核；认证 Token 一次性使用、短有效期。
- 数据侧：证件照属于高敏感 PII，禁止在普通业务接口明文返回；下载与查看需二次认证与审计。
