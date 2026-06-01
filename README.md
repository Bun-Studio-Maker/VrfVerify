# secp256k1 VRF Verify

基于 secp256k1 椭圆曲线实现的 VRF（Verifiable Random Function，可验证随机函数）验证器。
使用和测试数据请查看TestData.txt

该实现用于验证：

* VRF Proof 是否有效
* 随机输出是否可信
* 输出是否确实由指定私钥生成

适用于：

* 可验证随机数
* 区块链随机性
* 游戏开奖
* 防作弊系统
* 去中心化抽签
* Commit-Reveal 随机协议

---

# 算法基础

本实现基于：

* 椭圆曲线 secp256k1
* Schnorr Proof
* Fiat-Shamir Transform
* Hash-To-Curve
* SHA256

安全性依赖于：

* 椭圆曲线离散对数困难问题（ECDLP）
* SHA256 抗碰撞性

---

# 椭圆曲线

使用 secp256k1：

$$
y^2 = x^3 + 7 \pmod p
$$

其中：

* ( p ) 为有限域素数
* ( G ) 为生成元
* ( n ) 为生成元阶

---

# VRF 整体流程

## 1. 生成公钥

私钥：

$$
x
$$

公钥：

$$
Y = xG
$$

---

## 2. Hash To Curve

将输入 seed 映射到椭圆曲线点：

$$
H = HashToCurve(seed)
$$

实现方式：

1. 对 seed 进行 SHA256
2. 尝试将结果作为 x 坐标
3. 计算：

$$
rhs = x^3 + 7 \pmod p
$$

4. 求平方根：

$$
y = rhs^{\frac{p+1}{4}} \pmod p
$$

5. 若存在合法 y，则得到曲线点：

$$
H=(x,y)
$$

6. 若失败，则继续：

$$
h_{i+1}=SHA256(h_i)
$$

直到找到合法曲线点。

---

# VRF Proof 生成

## 1. 计算 VRF 输出点

$$
\Gamma = xH
$$

其中：

* ( x ) 为私钥
* ( H ) 为 HashToCurve(seed)

---

## 2. 生成随机 nonce

选择随机数：

$$
k
$$

---

## 3. 计算中间点

$$
U = kG
$$

$$
V = kH
$$

---

## 4. 计算 Challenge

$$
c = H(Y,H,\Gamma,U,V)
$$

其中：

* ( H() ) 表示 SHA256
* 所有点以字节形式拼接

---

## 5. 计算 Response

$$
s = k + cx \pmod n
$$

---

# Proof 结构

Proof 由以下部分组成：

| 字段    | 描述               |
| ----- | ---------------- |
| Gamma | VRF 输出点          |
| c     | Challenge        |
| s     | Schnorr Response |

总长度：

* Gamma：65 bytes
* c：32 bytes
* s：32 bytes

总计：

129 bytes

---

# 验证流程

验证者输入：

* 公钥
* seed
* proof
* random_output

---

## 1. 重新计算 H

$$
H = HashToCurve(seed)
$$

---

## 2. 计算：

$$
U' = sG - cY
$$

---

## 3. 计算：

$$
V' = sH - c\Gamma
$$

---

## 4. 重新计算 Challenge

$$
c' = H(Y,H,\Gamma,U',V')
$$

---

## 5. 验证

检查：

$$
c'=c
$$

若成立：

说明证明有效。

---

# 随机输出

最终随机输出为：

$$
randomOutput = SHA256(\Gamma)
$$

验证时：

重新计算：

$$
SHA256(\Gamma)
$$

并与输入的 random_output 比较。

---

# 安全特性

## 不可伪造

攻击者无法在不知道私钥的情况下构造合法 proof。

---

## 可公开验证

任意人仅凭：

* 公钥
* seed
* proof

即可验证结果。

---

## 输出确定性

同一：

* 私钥
* seed

一定生成相同随机输出。

---

## 输出不可预测

在 proof 发布前：

无法预测最终随机结果。

---

# 数学本质

该 VRF 本质上是：

* Schnorr 零知识证明
* 椭圆曲线离散对数
* Fiat-Shamir 非交互证明

的组合。

核心证明关系：

$$
Y=xG
$$

$$
\Gamma=xH
$$

验证：

$$
U'=sG-cY
$$

$$
V'=sH-c\Gamma
$$

以及：

$$
c'=H(Y,H,\Gamma,U',V')
$$

是否满足：

$$
c'=c
$$

---

# 适用场景

* 区块链随机数
* 游戏开奖
* NFT Mint 随机性
* 去中心化抽签
* 链上赌场
* 防作弊随机系统
* Leader Election
* 共识随机信标（Random Beacon）

---

# 输出说明

验证成功：

* Proof 合法
* Random Output 可信
* 输出由对应私钥生成

验证失败：

* Proof 被篡改
* Random Output 不匹配
* Seed 不一致
* 公钥不匹配
* 非法曲线点


# 目前提供python和nodejs两种脚本

python 版本  3.x 安装命令 pip install ecdsa cryptography

nodejs 版本  v14.x 安装命令 npm install elliptic bn.js 


测试数据

public_key_base64 = "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEJlcomRTDuVVIEE/kxf9iwFLNHnigb44o26F7OczOT/jVZnCBtT6tVa3BzTHZpvMr/Hb8um7PBN1LaDhZPUW5EA=="

seed = "9001062273548560654338|1778418819957"

proof_hex = "04035d6d8d943c6efcb5eb45692f02730eb0e379569137a458ac7de8758898bb0eae382739ed029789a1aaaa84216fc5dcf49af86622dad077c9ff1b0a84506ca8b7ca3e4c665d4daf8cf5e171513fb330074b72cdc08cb7aed232c09385b2e687b8d7a53242161359089357ef9860cb793fac0315dd4a168f1c150f2991ccf517"

random_output_hex = "8753c474e66827714eb7dc3c0ce6e7e1f5d59a46679006f3877325bb2eb56e74"
