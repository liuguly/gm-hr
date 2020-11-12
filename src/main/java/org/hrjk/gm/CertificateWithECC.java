package org.hrjk.gm;

import cn.hutool.core.io.resource.ResourceUtil;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * 从证书中获取密钥
 *
 * @author 刘欣
 * @version 1.0
 */
public class CertificateWithECC {

    private static final Logger LOGGER = LoggerFactory.getLogger(CertificateWithECC.class);

    /**
     * 公钥标识名称
     */
    public static final String PUBLIC_KEY = "ECDSAPublicKey";
    /**
     * 私钥标识名称
     */
    public static final String PRIVATE_KEY = "ECDSAPrivateKey";

    public CertificateWithECC(){
    }

    /**
     * 根据证书路径生成证书对象
     * @param certificatePath 证书路径
     * @return 证书对象
     */
    public Certificate getCertificate(String certificatePath)  {
        CertificateFactory certificateFactory = new CertificateFactory();
        Certificate certificate = null;
        //生成证书对象
        try(FileInputStream fileInputStream = new FileInputStream(certificatePath)){
            certificate =certificateFactory.engineGenerateCertificate(fileInputStream);
        } catch (CertificateException |IOException e) {
            if(e instanceof CertificateException){
                LOGGER.error("初始化证书引擎失败! err->{}", e.getMessage());
            }else {
                LOGGER.error("加载证书文件失败！ err->{}",e.getMessage());
            }
        }
        return certificate;
    }

    /**
     * 将证书转换成x509证书
     * @param certificatePath 证书路径
     * @return x509证书
     */
    public X509Certificate getX509Certificate(String certificatePath){
        X509Certificate x509Certificate = (X509Certificate)getCertificate(certificatePath);
        return x509Certificate;
    }

    /**
     * 从cer证书获取公钥
     * @param certificatePath 证书路径
     */
    public PublicKey getPublicKeyByCerFile(String certificatePath){
        X509Certificate x509Certificate = this.getX509Certificate(certificatePath);
        return x509Certificate.getPublicKey();
    }

    /**
     * 从pem证书获取公私钥
     */
    public Map<String,Object> initKeyByPemCertificate() throws IOException {
        Map<String,Object> result = new HashMap<>(15);
        String certPath = ResourceUtil.getResource("sm2key.pem").getPath();
        //PEM密钥对对象
        Object object = null;
        try (FileReader fileReader = new FileReader(certPath)){
            //构建Pem解析
            PEMParser pemParser = new PEMParser(fileReader);
            //解析读取pem文件
            object = pemParser.readObject();
            //关闭流
            pemParser.close();
        }
        //套用bouncy转换获取keyPair
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        //获取密钥对
        KeyPair keyPair = converter.getKeyPair((PEMKeyPair)object);
        //获取私钥
        ECPrivateKey privateKey =(ECPrivateKey) keyPair.getPrivate();
        //获取公钥
        ECPublicKey publicKey = (ECPublicKey)keyPair.getPublic();
        result.put(PUBLIC_KEY,publicKey);
        result.put(PRIVATE_KEY,privateKey);
        return result;
    }

    /**
     * 获取私钥
     * @param keyMap 密钥map
     * @return 私钥字节
     */
    public byte[] getPrivateKeyByPemFile(Map<String,Object> keyMap){
        Key key = (Key)keyMap.get(PRIVATE_KEY);
        return key.getEncoded();
    }

    /**
     * 获取公钥
     * @param keyMap 密钥map
     * @return 公钥字节
     */
    public byte[] getPublicKeyByPemFile(Map<String,Object> keyMap){
        Key key = (Key)keyMap.get(PUBLIC_KEY);
        return key.getEncoded();
    }



}
