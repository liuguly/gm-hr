package org.hrjk.gm;

import cn.hutool.core.io.resource.ResourceUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;


/**
 * 简单测试用例
 *
 * @author 刘欣
 * @version 1.0
 */
public class TestGmCertificate {

    private static final Logger LOGGER = LoggerFactory.getLogger(TestGmCertificate.class);

    //利用证书操作对象，并通过证书进行加密、解密、签名、验签
    private CertificateWithECC certificateWithECC = new CertificateWithECC();

    //不利用证书，通过椭圆曲线算法生成公私钥进行签名，验签
    private SignatureWithECDSA signatureWithECDSA = new SignatureWithECDSA();

    /**
     * 测试算法支持
     */
    @Test
    public void testProvider() {
        //获取bouncy castle密码套件提供者
        Provider provider = Security.getProvider("BC");
        LOGGER.info("提供者："+provider);
        for (Map.Entry<Object, Object> entry : provider.entrySet()) {
            //输出支持椭圆曲线签名算法的种类
            if ((entry.getKey() + "").contains("ECC")) {
                System.out.println(entry.getKey() + "=====" + entry.getValue());
            }
        }
    }

    /**
     * 不利用证书，通过椭圆曲线算法生成公私钥验证签名
     * @throws InvalidKeySpecException 无效key
     * @throws NoSuchAlgorithmException 无此算法
     * @throws InvalidKeyException  无效密钥
     * @throws SignatureException  签名异常
     */
    @Test
    public void testSign() throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Map<String,Object> keyMap = signatureWithECDSA.initKey();
        //公钥
        byte[] bytePublicKey = signatureWithECDSA.getPublicKey(keyMap);
        //私钥
        byte[] bytePrivateKey = signatureWithECDSA.getPrivateKey(keyMap);
        LOGGER.info("公钥\n:" + Base64.toBase64String(bytePublicKey));
        LOGGER.info("私钥\n:" + Base64.toBase64String(bytePrivateKey));

        //开始签名验签
        String sign = "ECDSA椭圆曲线数字签名";
        byte[] data = sign.getBytes();
        byte[] signValue = signatureWithECDSA.sign(data,bytePrivateKey);
        LOGGER.info("签名：\n"+signValue);
        //验证签名
        boolean status = signatureWithECDSA.verify(data,bytePublicKey,signValue);
        LOGGER.info("状态：\r"+status);
        Assertions.assertTrue(status);
    }

    //===================================================================证书测试开始================================================
    /**
     * 加载base64-encoded-x.509.cer证书，并打印信息
     */
    @Test
    public void printCerInfo(){
        String certPath = ResourceUtil.getResource("base64-encoded-x.509.cer").getPath();
        //证书非空
        X509Certificate x509Certificate = certificateWithECC.getX509Certificate(certPath);
        Assertions.assertNotNull(x509Certificate);
        PublicKey publicKey = x509Certificate.getPublicKey();
        //打印公钥
        LOGGER.info("公钥：\n"+Base64.toBase64String(publicKey.getEncoded()));
        //打印公钥算法
        Assertions.assertEquals("EC",publicKey.getAlgorithm());
    }

    /**
     * 加载sm2cert.cer证书，并打印信息
     */
    @Test
    public void printSm2CertInfo(){
        String certPath = ResourceUtil.getResource("sm2cert.cer").getPath();
        X509Certificate x509Certificate = certificateWithECC.getX509Certificate(certPath);
        PublicKey publicKey = x509Certificate.getPublicKey();
        //打印公钥
        LOGGER.info("公钥：\n"+Base64.toBase64String(publicKey.getEncoded()));
        //公钥算法
        Assertions.assertEquals("EC",publicKey.getAlgorithm());
        //序列号
        Assertions.assertEquals(18308786030880364627d,x509Certificate.getSerialNumber().doubleValue());
        //还可打印其它信息
    }

    /**
     * 测试从sm2key.pem证书获取的公钥，是否和对外发布的sm2cert.cer公钥证书，公钥是否一致
     */
    @Test
    public void testPublicKeyBetweenCerAndPem() throws IOException {
        //获取对外发布的sm2cert.cer证书公钥
        String cerPath = ResourceUtil.getResource("sm2cert.cer").getPath();
        PublicKey publicKey = certificateWithECC.getPublicKeyByCerFile(cerPath);
        String outPubKey = Base64.toBase64String(publicKey.getEncoded());
        LOGGER.info("从sm2cert.cer证书解析的公钥：\n"+outPubKey);

        Map<String,Object> keyMap = certificateWithECC.initKeyByPemCertificate();
        String publicKey1 = Base64.toBase64String(certificateWithECC.getPublicKeyByPemFile(keyMap));
        LOGGER.info("从sm2key.pem证书解析的公钥:\n"+publicKey1);

        //判断是否相等
        Assertions.assertEquals(outPubKey,publicKey1);
    }


    /**
     * 通过sm2key.pem的私钥进行加密-- sm2key.pem对外隐藏
     * 通过sm2cert.cer证书公钥解密-- sm2cert.cer对外发布
     */
    @Test
    public void encryptAndDecrypt() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {
        String data = "待加密数据-椭圆曲线公钥算法";
        Map<String,Object> keyMap = certificateWithECC.initKeyByPemCertificate();
        ECPublicKey publicKey = (ECPublicKey) keyMap.get(CertificateWithECC.PUBLIC_KEY);
        ECPrivateKey privateKey = (ECPrivateKey)keyMap.get(CertificateWithECC.PRIVATE_KEY);

        //公钥加密
        Cipher cipher = Cipher.getInstance("SM2WITHSHA256",new BouncyCastleProvider());
        cipher.init(Cipher.ENCRYPT_MODE,publicKey);
        byte[] encrypt = cipher.doFinal(data.getBytes());

        //私钥解密
        cipher.init(Cipher.DECRYPT_MODE,privateKey);
        byte[] decrypt = cipher.doFinal(encrypt);

        LOGGER.info("私钥解密后的数据："+new String(decrypt));
    }


    /**
     * 获取公钥，输出公钥信息
     */
    @Test
    public void getPublicKeyByCert() {
        String certPath = ResourceUtil.getResource("base64-encoded-x.509.cer").getPath();
        X509Certificate x509Certificate = certificateWithECC.getX509Certificate(certPath);
        PublicKey publicKey = x509Certificate.getPublicKey();
        String algorithm = publicKey.getAlgorithm();
        String format = publicKey.getFormat();
        Assertions.assertEquals("EC",algorithm);
        Assertions.assertEquals("X.509",format);
        LOGGER.info("公钥：\n"+Base64.toBase64String(publicKey.getEncoded()));
    }

    @Test
    public void getPublicKeyBySm2cert(){
        String certPath = ResourceUtil.getResource("sm2cert.cer").getPath();
        X509Certificate x509Certificate = certificateWithECC.getX509Certificate(certPath);
        PublicKey publicKey = x509Certificate.getPublicKey();
        String algorithm = publicKey.getAlgorithm();
        String format = publicKey.getFormat();
        Assertions.assertEquals("EC",algorithm);
        Assertions.assertEquals("X.509",format);
        LOGGER.info("公钥：\n"+Base64.toBase64String(publicKey.getEncoded()));
    }

}
