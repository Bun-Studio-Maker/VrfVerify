import base64
import hashlib

from ecdsa import curves, ellipticcurve
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


# =========================================================
# secp256k1
# =========================================================
curve = curves.SECP256k1
G = curve.generator
n = curve.order
p = curve.curve.p()
a = curve.curve.a()
b = curve.curve.b()


# =========================================================
# 基础函数
# =========================================================
def int_to_bytes(x: int, length: int = 32) -> bytes:
    return x.to_bytes(length, "big")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def point_to_bytes(P: ellipticcurve.Point) -> bytes:
    """
    非压缩格式：
    04 || x(32) || y(32)
    """
    return b"\x04" + int_to_bytes(P.x()) + int_to_bytes(P.y())


def bytes_to_point(data: bytes) -> ellipticcurve.Point:
    if len(data) != 65:
        raise ValueError("invalid point length")

    if data[0] != 0x04:
        raise ValueError("only uncompressed point supported")

    x = int.from_bytes(data[1:33], "big")
    y = int.from_bytes(data[33:65], "big")

    if not curve.curve.contains_point(x, y):
        raise ValueError("point not on curve")

    return ellipticcurve.Point(curve.curve, x, y, n)


# =========================================================
# X.509 Base64 公钥解析
# =========================================================
def x509_base64_to_point(public_key_base64: str) -> ellipticcurve.Point:
    der = base64.b64decode(public_key_base64)

    pub = serialization.load_der_public_key(der)

    if not isinstance(pub, ec.EllipticCurvePublicKey):
        raise ValueError("not EC public key")

    nums = pub.public_numbers()

    return ellipticcurve.Point(curve.curve, nums.x, nums.y, n)


# =========================================================
# hash_to_curve
# 必须与 Java 保持一致
# seed || counter(4-byte big endian)
# =========================================================
def hash_to_curve(seed: bytes) -> ellipticcurve.Point:
    """
    完全对齐 Java 版本：

    h = sha256(seed)

    while True:
        candidate = 0x02 || h

        尝试作为 secp256k1 压缩点解码
        失败则 h = sha256(h)
    """
    h = sha256(seed)

    while True:
        x = int.from_bytes(h, "big")

        # secp256k1:
        # y^2 = x^3 + 7 mod p
        rhs = (pow(x, 3, p) + 7) % p

        # 只接受偶数 y（对应压缩前缀 0x02）
        y = pow(rhs, (p + 1) // 4, p)

        if (y * y) % p == rhs:
            if y & 1:
                y = p - y

            return ellipticcurve.Point(curve.curve, x, y, n)

        h = sha256(h)


# =========================================================
# challenge
# c = H(Y || H || Gamma || U || V) mod n
# =========================================================
def hash_challenge(
    public_key: ellipticcurve.Point,
    h: ellipticcurve.Point,
    gamma: ellipticcurve.Point,
    u: ellipticcurve.Point,
    v: ellipticcurve.Point,
) -> int:
    data = (
        point_to_bytes(public_key)
        + point_to_bytes(h)
        + point_to_bytes(gamma)
        + point_to_bytes(u)
        + point_to_bytes(v)
    )

    return int.from_bytes(sha256(data), "big") % n


# =========================================================
# 核心 verify
# =========================================================
def vrf_verify(
    public_key_base64: str,
    seed: bytes,
    proof: bytes,
    random_output: bytes,
) -> bool:
    try:
        if len(proof) != 129:
            return False

        if len(random_output) != 32:
            return False

        # 公钥
        public_key = x509_base64_to_point(public_key_base64)
        #print(public_key.x(), public_key.y())

        # proof 拆解
        gamma_bytes = proof[:65]
        c_bytes = proof[65:97]
        s_bytes = proof[97:129]

        gamma = bytes_to_point(gamma_bytes)

        c = int.from_bytes(c_bytes, "big")
        s = int.from_bytes(s_bytes, "big")

        if c >= n or s >= n:
            return False

        # H = hash_to_curve(seed)
        h = hash_to_curve(seed)

        print(h.x(), h.y())

        # U' = sG - cY
        u = s * G + (n - c) * public_key

        # V' = sH - cGamma
        v = s * h + (n - c) * gamma

        # c'
        c_prime = hash_challenge(public_key, h, gamma, u, v)

        if c_prime != c:
            return False

        # random output
        expected_output = sha256(point_to_bytes(gamma))

        if expected_output != random_output:
            return False

        return True

    except Exception:
        return False


# =========================================================
# Hex 输入包装
# =========================================================
def vrf_verify_hex(
    public_key_base64: str,
    seed: str,
    proof_hex: str,
    random_output_hex: str,
) -> bool:
    proof = bytes.fromhex(proof_hex)
    random_output = bytes.fromhex(random_output_hex)

    return vrf_verify(
        public_key_base64=public_key_base64,
        seed=seed.encode("utf-8"),
        proof=proof,
        random_output=random_output,
    )


# =========================================================
# 示例
# =========================================================
if __name__ == "__main__":
    public_key_base64 = "public_key_base64"
    seed = "seed"   # detId | timestamp

    proof_hex = "proof_hex"
    random_output_hex = "random_output_hex"

    ok = vrf_verify_hex(
        public_key_base64=public_key_base64,
        seed=seed,
        proof_hex=proof_hex,
        random_output_hex=random_output_hex,
    )

    print("verify =", ok)
