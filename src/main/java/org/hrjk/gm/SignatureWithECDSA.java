package org.hrjk.gm;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * 基于bouncy castle密码套件，不利用证书，直接生成公私钥进行签名和验签
 * @author 刘欣
 * @version 1.0
 */
public class SignatureWithECDSA {

    /**
     * 椭圆曲线数字签名密钥算法
     */
    private static final String KEY_ALGORITHM = "ECDSA";
    /**
     * 密钥长度
     * ECDH算法默认密钥长度为256，其范围在112到571之间
     */
    private static final int KEY_SIZE =256;

    /**
     * SHA1WITHECDSA
     * SHA1/CVC-ECDSA
     * SHA256WithECDSA
     * SHA512WithECDSA
     * 。。。。。。。。。。
     *
     * 通过此方法查看支持的基于密钥的消息摘要散列算法
     * {@link TestGm#testProvider()}
     */
    private static final String SIGNATURE_ALGORITHM = "SHA512WithECDSA";

    /**
     * 公钥
     */
    private static final String PUBLIC_KEY = "ECDSAPublicKey";
    /**
     * 私钥
     */
    private static final String PRIVATE_KEY = "ECDSAPrivateKey";

    public SignatureWithECDSA(){
        //加载bouncy castle密码套件
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 初始化密钥
     * @return 密钥map
     * @throws NoSuchAlgorithmException 不支持该算法
     */
    public Map<String,Object> initKey() throws NoSuchAlgorithmException {
        //利用椭圆曲线算法实例化密钥对生成器
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        //初始化密钥对生成器
        keyPairGenerator.initialize(KEY_SIZE);
        //生成密钥对
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
        //封装密钥
        Map<String,Object> result=  new HashMap<String, Object>(15);
        result.put(PUBLIC_KEY,publicKey);
        result.put(PRIVATE_KEY,privateKey);
        return result;
    }

    /**
     * 获取私钥
     * @param keyMap 密钥map
     * @return 私钥字节
     */
    public byte[] getPrivateKey(Map<String,Object> keyMap){
        Key key = (Key)keyMap.get(PRIVATE_KEY);
        return key.getEncoded();
    }

    /**
     * 获取公钥
     * @param keyMap 密钥map
     * @return 公钥字节
     */
    public byte[] getPublicKey(Map<String,Object> keyMap){
        Key key = (Key)keyMap.get(PUBLIC_KEY);
        return key.getEncoded();
    }

    /**
     * 签名
     * @param data 数据字节
     * @param bytePrivateKey 私钥字节
     * @return 签名值
     * @throws NoSuchAlgorithmException 无此算法
     * @throws InvalidKeySpecException  无效的key
     * @throws InvalidKeyException   无效的密钥
     * @throws SignatureException    签名异常
     */
    public byte[] sign(byte[] data,byte[] bytePrivateKey) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        //转换私钥材料
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(bytePrivateKey);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        //获取签名对象，带椭圆曲线密钥的散列函数
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateKey);
        //更新
        signature.update(data);
        //签名值
        return signature.sign();
    }

    /**
     * 验签
     * @param data 数据
     * @param bytePublicKey 公钥字节
     * @param sign 签名值
     * @return 验证结果
     * @throws NoSuchAlgorithmException 无此算法
     * @throws InvalidKeySpecException  无效key
     * @throws InvalidKeyException  无效的公钥
     * @throws SignatureException   签名异常
     */
    public boolean verify(byte[] data, byte[] bytePublicKey,byte[] sign) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(bytePublicKey);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        //实例化Signature
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(publicKey);
        //更新
        signature.update(data);
        //验证
        return signature.verify(sign);
    }


}
