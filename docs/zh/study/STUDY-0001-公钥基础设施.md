# STUDY-0001 公钥基础设施 
 **作者 :**  **[羽兮](https://github.com/yuxi39 "羽兮的个人空间")**  
 **作品：** **[公钥基础设施](https://github.com/yuxi39/qchat/blob/main/docs/zh/study/STUDY-0001-公钥基础设施.md)**  
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
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**[2.1.1.1 块密码算法](#2111-块密码算法)**
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
c=Enc_k(m)
$$

对称加密算法的解密过程可描述为：解密算法 $Dec$ 使用密钥 $k$ 对密文消息 $c$ 进行解密运算得到明文 $m$  

$$
m=Dec_k(c)
$$

一个正确的对称加密方案应满足使用密钥 $k$ 对明文消息 $m$ 经过加密和解密操作之后，结果仍为明文消息 $m$：

$$
Dec_k(Enc_k(m))=m
$$

对称加密算法的实现分为两种实现方式：[块密码(Block Cipher)][9] 和 [流密码(Stream Cipher)][10]，实际系统中通常还需要 [工作模式(Mode of Operation)][11] 或者 [认证机制(AEAD)][12] 以满足安全场景的需要。  

#### 2.1.1.1 块密码算法



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
## 引用  


