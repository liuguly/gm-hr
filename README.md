##说明

### 1. 依赖说明
- 核心依赖主要为两种
- bouncy castle密码套件所支持的椭圆曲线公钥算法
- gmsse 阿里的一个开源国密JSSE安全套接字扩展包，用于进行SSL+TLS通讯。
- 依赖如下：
```        
        <!--支持JDK1.5-1.8官方推荐： 
        http://www.bouncycastle.org/latest_releases.html-->
        <dependency>
             <groupId>org.bouncycastle</groupId>
             <artifactId>bcpkix-jdk15on</artifactId>
             <version>1.64</version>
         </dependency>
         <dependency>
             <groupId>org.bouncycastle</groupId>
             <artifactId>bcprov-ext-jdk15on</artifactId>
             <version>1.66</version>
         </dependency>
        <!-- 阿里巴巴国密JSSE -SDK -->
        <dependency>
            <groupId>com.aliyun</groupId>
            <artifactId>gmsse</artifactId>
            <version>1.0.0</version>
        </dependency>
```

### 2. 代码说明
#### 2.1 SignatureWithECDSA类

- 该类不借助证书，通过bouncy castle密码套件，利用椭圆曲线算法生成公钥私钥，进行签名验签操作。
- 私钥签名
- 公钥验签

#### 2.2 CertificateWithECC

- 该类借助国密证书，通过bouncy castle密码套件，直接从证书获取公钥

### 3. 证书说明

- base64-encoded-x.509.cer是一个国密公钥证书
- sm2cert.cer是对外发布的一个国密公钥证书
- sm2key.pem是对外隐藏的一个国密私钥证书与sm2cert.cer对应

### 测试用例
- 借助bouncy castle密码套件，证书的公私钥操作见TestGmCertificate类
- 借助阿里的国密JSSE密码套件，通过SSL+TLS进行国密证书测试验证见TestSSL类，
  Bouncy castle密钥套件不支持TLS

