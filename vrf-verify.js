const crypto = require('crypto');
const EC = require('elliptic').ec;
const BN = require('bn.js');

// secp256k1 曲线
const ec = new EC('secp256k1');
const curve = ec.curve;
const G = ec.g;
const n = ec.n;               // BN
const p = curve.p;            // BN

// ---------- 基础工具 ----------
function intToBytes(x, length = 32) {
    return x.toArrayLike(Buffer, 'be', length);
}

function sha256(data) {
    return crypto.createHash('sha256').update(data).digest();
}

function pointToBytes(P) {
    const xBuf = intToBytes(P.getX(), 32);
    const yBuf = intToBytes(P.getY(), 32);
    return Buffer.concat([Buffer.from([0x04]), xBuf, yBuf]);
}

function bytesToPoint(data) {
    if (data.length !== 65) {
        throw new Error('invalid point length');
    }
    if (data[0] !== 0x04) {
        throw new Error('only uncompressed point supported');
    }
    const xBN = new BN(data.slice(1, 33));
    const yBN = new BN(data.slice(33, 65));
    return curve.point(xBN, yBN);
}

// base64url 解码工具（JWK 使用 base64url）
function base64urlToBuffer(base64url) {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    return Buffer.from(base64, 'base64');
}

// ---------- X.509 Base64 公钥解析 ----------
function x509Base64ToPoint(publicKeyBase64) {
    const der = Buffer.from(publicKeyBase64, 'base64');

    try {
        // 使用 Node.js 内置 crypto 解析 SPKI 公钥（DER 格式）
        const pubKey = crypto.createPublicKey({
            key: der,
            format: 'der',
            type: 'spki',
        });

        // 导出 JWK，获取 x, y 坐标 (base64url 编码)
        const jwk = pubKey.export({ format: 'jwk' });

        if (jwk.kty !== 'EC' || jwk.crv !== 'secp256k1') {
            throw new Error('not secp256k1 public key');
        }

        const xBN = new BN(base64urlToBuffer(jwk.x).toString('hex'), 16);
        const yBN = new BN(base64urlToBuffer(jwk.y).toString('hex'), 16);

        // 返回曲线点
        return curve.point(xBN, yBN);
    } catch (err) {
        // 如果 crypto 方案失败（极少数环境），可备用手工解析 DER
        // 这里提供一份简单的手动提取 BIT STRING 的方法
        // SubjectPublicKeyInfo 结构：
        // SEQUENCE { AlgorithmIdentifier, BIT STRING (04 || x || y) }
        // 简单解析：找到 BIT STRING 标记 0x03 后跳过长度字节和 unused bits 字节
        let pos = der.indexOf(0x03, 2); // 跳过开头的 SEQUENCE
        if (pos === -1) throw new Error('Invalid SPKI');

        pos += 2; // 跳过 tag 和长度
        if (der[pos] === 0x00) pos++; // unused bits 必须为 0
        const pointBytes = der.slice(pos, pos + 65); // 非压缩点 65 字节
        return bytesToPoint(pointBytes);
    }
}

// ---------- hash_to_curve (对齐 Java 版本) ----------
function hashToCurve(seed) {
    let h = sha256(seed);

    while (true) {
        const xBN = new BN(h, 'be');
        try {
            // 尝试以压缩前缀 0x02 对应的偶数 y 构造点
            const P = curve.pointFromX(xBN, false);
            return P;
        } catch (e) {
            h = sha256(h);
        }
    }
}

// ---------- 挑战码 c = H(Y || H || Gamma || U || V) mod n ----------
function hashChallenge(publicKey, h, gamma, u, v) {
    const data = Buffer.concat([
        pointToBytes(publicKey),
        pointToBytes(h),
        pointToBytes(gamma),
        pointToBytes(u),
        pointToBytes(v),
    ]);
    const hash = sha256(data);
    return new BN(hash).mod(n);
}

// ---------- 核心验证 ----------
function vrfVerify(publicKeyBase64, seed, proof, randomOutput) {
    try {
        if (!Buffer.isBuffer(proof) || proof.length !== 129) return false;
        if (!Buffer.isBuffer(randomOutput) || randomOutput.length !== 32) return false;

        // 1. 公钥
        const publicKey = x509Base64ToPoint(publicKeyBase64);

        // 2. 拆解 proof：Gamma (65) || c (32) || s (32)
        const gammaBytes = proof.slice(0, 65);
        const cBytes = proof.slice(65, 97);
        const sBytes = proof.slice(97, 129);

        const gamma = bytesToPoint(gammaBytes);
        const c = new BN(cBytes, 'be');
        const s = new BN(sBytes, 'be');

        if (c.cmp(n) >= 0 || s.cmp(n) >= 0) return false;

        // 3. H = hash_to_curve(seed)
        const h = hashToCurve(seed);

        // 4. U = s·G + (n - c)·Y
        const sG = G.mul(s);
        const negCY = publicKey.mul(n.sub(c));
        const u = sG.add(negCY);

        // 5. V = s·H + (n - c)·Gamma
        const sH = h.mul(s);
        const negCGamma = gamma.mul(n.sub(c));
        const v = sH.add(negCGamma);

        // 6. 验证挑战码
        const cPrime = hashChallenge(publicKey, h, gamma, u, v);
        if (!cPrime.eq(c)) return false;

        // 7. 验证随机输出
        const expectedOutput = sha256(pointToBytes(gamma));
        if (!expectedOutput.equals(randomOutput)) return false;

        return true;
    } catch (e) {
        return false;
    }
}

// ---------- Hex 输入包装 ----------
function vrfVerifyHex(publicKeyBase64, seedStr, proofHex, randomOutputHex) {
    const seed = Buffer.from(seedStr, 'utf8');
    const proof = Buffer.from(proofHex, 'hex');
    const randomOutput = Buffer.from(randomOutputHex, 'hex');
    return vrfVerify(publicKeyBase64, seed, proof, randomOutput);
}

// ---------- 示例 ----------
if (require.main === module) {
    const publicKeyBase64 = "publicKeyBase64";
    const seed = "seed";

    const proofHex = "proofHex";
    const randomOutputHex = "randomOutputHex";

    const ok = vrfVerifyHex(publicKeyBase64, seed, proofHex, randomOutputHex);
    console.log("verify =", ok);
}
