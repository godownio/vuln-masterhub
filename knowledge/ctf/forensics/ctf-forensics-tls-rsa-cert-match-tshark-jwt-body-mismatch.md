---
id: ctf-forensics-tls-rsa-cert-match-tshark-jwt-body-mismatch
title: 多证书 TLS 流量解密：RSA 参数 n 匹配证书、tshark 导入私钥、JWT 与请求体身份不一致统计越权
type: scenario
domain: ctf
path: ctf/forensics
technique: tls-pcap-rsa-cert-match-jwt-body-mismatch
aliases:
- TLS 多证书匹配
- RSA 参数合成私钥
- tshark tls.keys_list
- JWT payload 越权检测
- 请求体与 JWT 身份不一致
- pcap 解密
tags:
- ctf
- forensics
- tls
- rsa
- tshark
- jwt
- idor
- pcap
- network-forensics
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V162
  verified_at: '2026-11-06T14:05:27+08:00'
  notes: 已对照 91111 原文数据审计三题核对：params.csv 的 n=p*q 匹配证书、tshark tls.keys_list 解密、JWT payload 与请求体 username/phone 不一致统计均一致，答案 mAqY0WRHsV.pcap/13930079365/5 与原文一致。PoC 未在本机复跑。
---

## 一句话结论

面对一批 TLS pcap 和一份 `id,e,p,q` 参数表，可先对每组参数计算 `n=p·q`，从 pcap 中暴力提取 DER 证书并读取 RSA 公钥模数，按 n 匹配到对应私钥；生成 PEM 后用 `tshark -o tls.keys_list:0.0.0.0,443,http,key.pem` 解密 HTTP；再解析 Authorization 中的 JWT payload 与请求体（hex JSON）中的 username/phone，两者不一致即判定该账号在越权访问。

## 原理

- **TLS RSA 密钥交换的解密条件**：若握手使用 RSA key exchange，服务器用证书公钥加密 pre-master secret；拿到证书私钥即可解密。私钥由 p、q、e 计算：`n=p·q`，`d=e^{-1} mod (p-1)(q-1)`，再构造 CRT 参数。
- **证书匹配**：pcap 中证书是 DER 编码的 X.509，常以 `30 82` 开头（SEQUENCE，长形式长度）。遍历文件字节，尝试 `x509.load_der_x509_certificate`，取 `public_key().public_numbers().n`，与参数表算出的 n 逐一比对；相等即该 pcap 使用对应私钥。
- **tshark 解密**：`-o tls.keys_list:0.0.0.0,443,http,key.pem` 把私钥绑定到 443 端口的 HTTP 协议；`-Y http -T fields -e http.authorization -e http.file_data` 只输出认证头和请求体。若端口不是 443，需按实际端口调整。
- **JWT 负载**：JWT 为 `header.payload.signature`；payload 是 Base64URL 编码的 JSON。解码（补 `=` 填充）即可读 username/phone。签名通常不校验（题目只要求读身份）。
- **越权判定**：请求体是 hex 编码的 JSON，解码后含 username/phone；若 JWT 中的 username/phone 与请求体不一致，说明请求者在使用 A 的 token 操作 B 的数据，属于水平越权/IDOR。统计不同账号数量即为答案。
- **为什么可复用**：批量 pcap + 参数表 + 证书公钥匹配是 TLS 取证常见组合；JWT 与业务参数的“双身份”对比也是检测越权/代操作的有效启发式。

## 触发条件

- 提供多个 TLS pcap 与一组 RSA 参数（e,p,q）或私钥候选。
- pcap 使用 RSA key exchange（或可被私钥解密的 TLS 版本/套件），且证书在流量中可见。
- 解密后能拿到 HTTP 请求头/请求体（明文或 hex/base64 编码）。
- 业务使用 JWT 等携带身份的自包含令牌，且请求体中也带用户标识。

## 利用步骤

1. 读取参数表，计算每组 `n=p·q`；确定目标 id（如 285）的 n。
2. 遍历 pcap：扫描 `30 82`，尝试解析 DER 证书，取 RSA 公钥 n；与目标 n 比对，命中即得到对应 pcap。
3. 用 e、p、q 计算 d 与 CRT 参数，生成 PEM 私钥文件。
4. 用 tshark 导入私钥解密该 pcap：`-o tls.keys_list:0.0.0.0,443,http,key.pem`；提取 `http.authorization` 与 `http.file_data`。
5. 请求体若为 hex，先 `bytes.fromhex().decode()` 再 JSON 解析；JWT 取 payload 段 Base64URL 解码。
6. 比对 JWT 与请求体的 username/phone：不一致则计数；遍历所有可解密 pcap，输出越权账号总数。
7. 若 tshark 解不出，检查端口、TLS 版本、是否使用 ECDHE（无私钥可解）、私钥格式与证书是否匹配。

## PoC

证书 n 匹配：

```python
import csv, struct
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

def read_params(path):
    out = {}
    for row in csv.DictReader(open(path)):
        e, p, q, i = int(row['e']), int(row['p']), int(row['q']), int(row['id'])
        out[i] = {'e': e, 'p': p, 'q': q, 'n': p * q}
    return out

def find_cert_n(pcap_path):
    data = Path(pcap_path).read_bytes()
    for i in range(len(data) - 4):
        if data[i:i+2] == b'\x30\x82':
            length = struct.unpack('>H', data[i+2:i+4])[0]
            if 100 < length < 5000:
                try:
                    cert = x509.load_der_x509_certificate(data[i:i+4+length], default_backend())
                    pk = cert.public_key()
                    if isinstance(pk, rsa.RSAPublicKey):
                        return pk.public_numbers().n
                except Exception:
                    pass
    return None

params = read_params('params.csv')
target = params[285]['n']
for pcap in Path('pcap/pcap').glob('*.pcap'):
    if find_cert_n(pcap) == target:
        print('match:', pcap.name)
```

生成私钥并用 tshark 解密：

```python
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def gen_key(e, p, q):
    n = p * q
    d = pow(e, -1, (p - 1) * (q - 1))
    pub = rsa.RSAPublicNumbers(e, n)
    priv = rsa.RSAPrivateNumbers(p, q, d, d % (p - 1), d % (q - 1), pow(q, -1, p), pub)
    return priv.private_key(default_backend())

key = gen_key(params[285]['e'], params[285]['p'], params[285]['q'])
open('key_285.pem', 'wb').write(key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.TraditionalOpenSSL,
    serialization.NoEncryption(),
))
```

```bash
tshark -r mAqY0WRHsV.pcap \
  -o tls.keys_list:0.0.0.0,443,http,key_285.pem \
  -Y http -T fields -e http.authorization -e http.file_data
```

JWT 与请求体不一致统计：

```python
import json, base64

def decode_jwt(token):
    p = token.split('.')[1]
    p += '=' * (-len(p) % 4)
    return json.loads(base64.urlsafe_b64decode(p))

unauthorized = 0
for row in decrypted_rows:
    auth = row['authorization'].replace('Bearer ', '')
    jwt_data = decode_jwt(auth)
    body = json.loads(bytes.fromhex(row['file_data']).decode())
    if jwt_data.get('username') != body.get('username') or jwt_data.get('phone') != body.get('phone'):
        unauthorized += 1
print(unauthorized)
```

说明：原文答案为 pcap `mAqY0WRHsV.pcap`、王梅手机号 `13930079365`、越权账号数 `5`；PoC 未在本机复跑。

## 变体与关联

- **密钥匹配变体**：证书公钥 n 匹配、私钥文件指纹匹配、`tls.keys_list` 与 `SSLKEYLOGFILE` 两种解密方式；ECDHE 套件无法仅凭服务器私钥解密。
- **编码变体**：请求体可能是 hex、base64、form、protobuf；先识别 Content-Type 再解码。
- **越权判定变体**：JWT 与 query/body/path 中的 user_id 对比；JWT 中 role 与操作权限对比；同一 token 操作多个用户；响应中返回他人数据。
- **关联卡片**：[[ctf-forensics-http-unauth-api-audit]]（HTTP 未授权 API 审计）、[[web-generic-auth-jwt-signature-only-role-bypass]]（JWT 仅校验签名）、[[web-generic-auth-mall-cancel-user-order-idor]]（水平越权实例）、[[defense-forensics-behinder-jsp-md5-password-key-traffic-decrypt]]（流量解密）。
- **边界**：TLS 1.3/ECDHE 套件仅有服务器私钥不能解密；证书可能被压缩/分片，需重组 TLS 握手；JWT 字段缺失会误判，需按业务字段定义。

## 检测与防御

- **检测（防守方）**：监控同一 JWT 对多个 username/phone 的请求；对比 token 身份与请求体身份；对批量枚举/异常会话告警；审计 TLS 私钥的访问与导入。
- **防御**：JWT 中的身份与请求体身份必须由服务端绑定校验，不能信任客户端提交的 username/phone；所有对象访问做归属校验；JWT 使用强签名并校验 iss/aud/exp。
- **密钥管理**：服务器私钥应存放在 HSM/KMS，限制导出；pcap 中不应长期保留可解密私钥；定期轮换证书。
- **取证**：保留 pcap、证书链、参数表与解密脚本；记录匹配依据（n/指纹）与解密结果，确保可复现。
