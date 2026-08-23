# STUDY-0001 公钥基础设施 
 **作者 :**  **[羽兮](https://github.com/yuxi39 "羽兮的个人空间")**  
 **作品：**  **[公钥基础设施](https://github.com/yuxi39/qchat/blob/main/docs/zh/study/STUDY-0001-公钥基础设施.md)**  
 **类型 :**  **Document**  
 **链接 :**  *<https://github.com/yuxi39/qchat/blob/main/docs/zh/study/STUDY-0001-公钥基础设施.md>*  
 **许可 :**  **[CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/ "LICENSE Permission")**  
 **状态 :**  **学习中**  
 **创建 :**  *2026-08-23*  
 **版本 :**  **version 1.0**  
 **修改 :**  **初始版本**  
 **引用 :**  `羽兮 《公钥基础设施》 document v1.0 qchat:STUDY-0001 from:github.com license:"CC BY-SA 4.0"`  
```textplain
@cite 羽兮 《公钥基础设施》
type: document
version: 1.0
source: github.com/yuxi39/qchat/docs/zh/study/STUDY-0001-公钥基础设施.md
author: yuxi39
record: qchat:STUDY-0001
license: CC BY-SA 4.0
```
## 目录 
<!-- TOC -->

**[1 动机](#1-动机)**  
**[2 PKI 公钥基础设施](#2-pki-公钥基础设施)**  
&nbsp;&nbsp;**[2.1 密码学基础](#21-密码学基础)**  
&nbsp;&nbsp;&nbsp;&nbsp;**[2.1.1 对称加密算法](#211-对称加密算法)**  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**[2.1.1.1 分组密码算法](#2111-分组密码算法)**
<!-- /TOC -->

## 1 动机
**QChat** 是我设想的基于 **[QUIC(Quick UDP Internet Connections)][1]** 协议的一个聊天室应用小 **`demo`** 以便我能够更好地学习和理解 **[QUIC][1]** 协议的应用和原理。  
  
在基于 **[QUIC][1]** 的协议学习过程中困扰我许久的是一个基础性的问题：  
我到底该怎么配置好 **[QUIC][1]** 连接配置中的 **`tls.Config`** 让我的程序能够完成正确的 **[TLS(Transport Layer Security) 1.3][2]** 配置下的连接行为？  
  
于是，我首先参考了 **[quic-go](https://github.com/quic-go/quic-go "A QUIC implementation in pure Go")** 提供的 **`example`** 案例，去了解官方是怎么处理这让我头疼的 **[TLS 1.3][2]** 配置的。  
就像[这样](https://github.com/quic-go/quic-go/blob/master/example/main.go "quic-go/example/main.go"):  
```textplain
@cite quic-go "quic-go"
type: code
source: github.com/quic-go/quic-go
author: quic-go contributors
maintainer: marten-seemann
branch: master
revision: cf0c4ff
file: quic-go/example/main.go
license: MIT
security-policy: https://github.com/quic-go/quic-go/blob/master/SECURITY.md
relation: referenced-for-learning
```    
```go
key := flag.String("key", "", "TLS key (requires -cert option)")
cert := flag.String("cert", "", "TLS certificate (requires -key option)")
flag.Parse()

var certFile, keyFile string
if *key != "" && *cert != "" {
    keyFile = *key
    certFile = *cert
} else {
    certFile, keyFile = testdata.GetCertificatePaths()
}
for _, b := range bs {
    fmt.Println("listening on", b)
    bCap := b
    wg.Go(func() {
        var err error
        if *tcp {
            err = http3.ListenAndServeTLS(bCap, certFile, keyFile, handler)
        } else {
            server := http3.Server{
                Handler: handler,
                Addr:    bCap,
                QUICConfig: &quic.Config{
                    Tracer: qlog.DefaultConnectionTracer,
                },
            }
            err = server.ListenAndServeTLS(certFile, keyFile)
        }
        if err != nil {
            fmt.Println(err)
        }
    })
}
```  
> 用 **[HTTP3][3]** 的方式，看起来 **[TLS 1.3][2]** 的配置只需要把文件位置给指定好就可以了的样子  

可以看到配置放到 **[testdata](https://github.com/quic-go/quic-go/blob/master/internal/testdata/cert.go "testdata/cert.go")** 下面了，我贴一下具体的实现：   
```textplain
@cite quic-go "quic-go"
type: code
source: github.com/quic-go/quic-go
author: quic-go contributors
maintainer: marten-seemann
branch: master
revision: cf0c4ff
file: quic-go/internal/testdata/cert.go
license: MIT
security-policy: https://github.com/quic-go/quic-go/blob/master/SECURITY.md
relation: referenced-for-learning
```    
```go
package testdata

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path"
	"runtime"
)

var certPath string

func init() {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("Failed to get current frame")
	}

	certPath = path.Dir(filename)
}

// GetCertificatePaths returns the paths to certificate and key
func GetCertificatePaths() (string, string) {
	return path.Join(certPath, "cert.pem"), path.Join(certPath, "priv.key")
}

// GetTLSConfig returns a tls config for quic.clemente.io
func GetTLSConfig() *tls.Config {
	cert, err := tls.LoadX509KeyPair(GetCertificatePaths())
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	}
}

// AddRootCA adds the root CA certificate to a cert pool
func AddRootCA(certPool *x509.CertPool) {
	caCertPath := path.Join(certPath, "ca.pem")
	caCertRaw, err := os.ReadFile(caCertPath)
	if err != nil {
		panic(err)
	}
	if ok := certPool.AppendCertsFromPEM(caCertRaw); !ok {
		panic("Could not add root ceritificate to pool.")
	}
}

// GetRootCA returns an x509.CertPool containing (only) the CA certificate
func GetRootCA() *x509.CertPool {
	pool := x509.NewCertPool()
	AddRootCA(pool)
	return pool
}
```  
如果使用 **[openssl][4]** 的话，那会是很方便的事。  
使用命令生成一系列的证书文件，然后直接复制模板就直接可以使用了，不过如果在程序内调用的话，似乎一直 **[exec.command](https://pkg.go.dev/os/exec#Command "os.exec.Command Function")** 也不是很好的选择。  
为了满足我的 **QChat** 应用对于 **[TLS 1.3][2]** 的控制，也许我不得不去研究一下 **[PKI(Public key infrastructure)][5]** 获取更多知识。  
## 2 PKI 公钥基础设施  
### 2.1 密码学基础
加密是一类将合法参与者能够通过密钥加密、恢复明文，没有密钥的第三方在计算上无法从密文恢复明文或者将明文和密文关联起来的算法，这种可逆变换将信息的保密性问题归约到密钥的保密性问题上。  
简单来说就是把原始信息用密钥经过算法处理得到一串毫无意义的杂乱数据，但可以通过确定的密钥来将这杂乱数据反推回原始的数据，让通信以外的观察者看不到也猜不到通信内容的技术。  
> 现代加密技术通常以两种方式实现：[对称加密][6]和[非对称加密][7] *也叫[公钥加密][8]*
### 2.1.1 对称加密算法 
一个对称加密方案 $\Pi$ 由密钥生成算法 $Gen$ 、加密算法 $Enc$、解密算法 $Dec$ 组成:  

$$
\Pi=(Gen,Enc,Dec)
$$

对称加密算法的加密过程可描述为：加密算法 $Enc$ 使用密钥 $k$ 对明文消息 $m$ 进行加密运算得到密文 $c$  

$$
c=\mathsf{Enc}_k(m)
$$

对称加密算法的解密过程可描述为：解密算法 $Dec$ 使用密钥 $k$ 对密文消息 $c$ 进行解密运算得到明文 $m$  

$$
m=\mathsf{Dec}_k(c)
$$

一个正确的对称加密方案应满足使用密钥 $k$ 对明文消息 $m$ 经过加密和解密操作之后，结果仍为明文消息 $m$：

$$
\mathsf{Dec}_k(\mathsf{Enc}_k(m))=m
$$

对称加密算法的实现分为两种实现方式：[分组密码(Block Cipher)][9] 和 [流密码(Stream Cipher)][10]，实际系统中通常还需要 [工作模式(Mode of Operation)][11] 或者 [认证机制(AEAD)][12] 以满足安全场景的需要。  

#### 2.1.1.1 分组密码算法
密码学问题在于如何让信息只能被可靠的通信方获取。无论是小时候的简易密码本、[凯撒密码][13]、还是一些其他的古典保密通信方法，在应用上长期存在安全性依赖于加密、解密的方法不被人知晓，更像是一种智力游戏，在图灵的纪录片中，报纸上的密文悬赏破译就是这种加密方式。由于密码往往和军事行动、政治敏感信息以及商业秘密相关，以往的古典密码不仅对于明文进行混淆保护，连同加密和解密的方法也一并纳入机密中。  
在 19 世纪，Auguste Kerckhoffs 提出了 [Kerckhoffs原则][14] 描述了加密系统应该在除密钥外的一切系统细节都暴露给敌手的情况下仍然应该是安全的，奠定了现代密码设计中公开算法、依赖密钥安全这一核心原则。  
> 受 [Kerckhoffs原则][14] 的启发，我认为一个软件的设计也应该尽最大努力去遵循这一点：将复杂的系统收敛到简洁的语义实现问题上  

[Kerckhoffs原则][14] 打破了隐藏系统细节才能保证安全的传统密码观念，将密码系统的安全性核心归结于密钥的保密性，而不是算法本身的隐藏。该原则定义了什么是正确的加密系统，但并没有回答：一个公开的密码算法是如何保证通信安全的？  
围绕着这个问题的探讨推动了现代密码学理论的发展，其中现代密码学最重要的奠基人之一的美国数学家 [克劳德·香农(Claude Shannon)][15] 在 1949 年发表了论文 [《Communication Theory of Secrecy Systems》][16] 首次从数学角度系统分析了密码系统，将密码系统从博弈者的智力游戏带到了可形式化分析和研究的信息科学殿堂。
[克劳德·香农][15] 认为，一个安全的密码系统应该满足两个核心目标：  

**混淆(Confusion)**
- 使密钥与密文之间的统计关系变得复杂，使攻击者难以通过分析密文推导密钥 
- 通常通过非线性的替换操作实现  

**扩散(Diffusion)**
- 将明文中的统计学特征扩散到整个密文，使局部信息难以泄露
- 通常通过置换、线性变换等方式实现

[克劳德·香农][15] 分析了 [乘积密码(Product Cipher)][17] 并提出以 [乘积密码][17] 构建有效提升安全性的加密方法。[乘积密码][17] 通过结合简单运算来实现，比如结合 [替换(substitutions)][18] 和 [置换(permutations)][19] 实现。  
> [迭代乘积密码(Iterated product cipher)][17] 分多轮进行加密，每一轮都基于原始密钥派生出不同的子密钥。

基于 [克劳德·香农][15] 提出的乘积密码思想，现代密码学发展出了 [分组密码(Block Cipher)][9] 这一重要的密码学原语。  
[分组密码][9] 将明文划分为固定长度的数据块，通过控制密钥的可逆变换将每个明文块转换为对应的密文块。  

$$
\mathsf{E}:\{0,1\}^{k}\times\{0, 1\}^n \rightarrow \{0, 1\}^n
$$

> 基于密钥 $K$ , 加密函数 $\mathsf{E}_K$ 将长度为 $n$ bit 的明文块映射到长度为 $n$ bit 的密文块  
> $\{0, 1\}^k$ : 密钥空间 (key space)  
> $\{0, 1\}^n$ : 明文块空间 (plaintext block space)  
> $\{0, 1\}^n$ : 密文块空间 (ciphertext block space)  

$$
\mathsf{E}(K, M) = C
$$

> $K$ 是长度为 $k$ 的密钥，$M$ 是长度为 $n$ 的明文块，$C$ 是长度为 $n$ 的密文块  

例如 [AES(Advanced Encryption Standard)][20]：

$$
\mathsf{E}:\{0, 1\}^{k}\times\{0, 1\}^{128} \rightarrow \{0, 1\}^{128}, k\in\{128, 192, 256\}
$$

> block size 固定 128 bit, key 可以是 128、192 或 256 bit  

[分组密码][9] 思想在理论上解决了如何构造安全密码的问题，但真正推动现代密码学进入工程应用阶段的是将这些理论思想转化为标准化的算法实现的过程。[DES(Data Encryption Standard)][21] 是 [分组密码][9] 算法中最具有代表性的算法之一。  
[DES][21] 于 1977 年被美国国家标准局采纳为联邦信息处理标准，是第一个广泛应用的现代分组密码标准。  





[1]:https://en.wikipedia.org/wiki/QUIC "QUIC 维基百科"
[2]:https://en.wikipedia.org/wiki/Transport_Layer_Security#TLS_1.3 "TLS 1.3 维基百科"
[3]:https://en.wikipedia.org/wiki/HTTP/3 "HTTP3 维基百科"
[4]:https://en.wikipedia.org/wiki/OpenSSL "openssl 维基百科"
[5]:https://en.wikipedia.org/wiki/Public_key_infrastructure "PKI 维基百科"  
[6]:https://en.wikipedia.org/wiki/Symmetric-key_algorithm "Symmetric-key_algorithm 维基百科"
[7]:https://en.wikipedia.org/?title=Asymmetric_cryptography&redirect=no "Asymmetric_cryptography 维基百科" 
[8]:https://en.wikipedia.org/wiki/Public-key_cryptography "Public-key cryptography 维基百科"
[9]:https://en.wikipedia.org/wiki/Block_cipher "Block_cipher 维基百科"
[10]:https://en.wikipedia.org/wiki/Stream_cipher "Stream_cipher 维基百科"
[11]:https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation "Mode_of_Operation 维基百科"
[12]:https://en.wikipedia.org/wiki/Authenticated_encryption "AEAD 维基百科"
[13]:https://en.wikipedia.org/wiki/Caesar_cipher "Caesar_cipher 维基百科"
[14]:https://en.wikipedia.org/wiki/Kerckhoffs%27s_principle "Kerckhoffs原则 维基百科"
[15]:https://en.wikipedia.org/wiki/Claude_Shannon "Claude_Shannon 维基百科"
[16]:https://en.wikipedia.org/wiki/Communication_Theory_of_Secrecy_Systems "安全系统的通信理论 维基百科"
[17]:https://en.wikipedia.org/wiki/Product_cipher "乘积密码 维基百科"
[18]:https://en.wikipedia.org/wiki/Substitution_cipher "替换 维基百科"
[19]:https://en.wikipedia.org/wiki/Transposition_cipher "置换 维基百科"
[20]:https://en.wikipedia.org/wiki/Advanced_Encryption_Standard "AES 维基百科"  
[21]:https://en.wikipedia.org/wiki/Data_Encryption_Standard "DES 维基百科"
## 引用  


