package org.hrjk.gm;

import com.aliyun.gmsse.GMProvider;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.URL;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * 采用阿里的一个国密安全套接字扩展包类库JSSE
 * {@link github https://github.com/aliyun/gm-jsse}
 * @author 刘欣
 * @version 1.0
 */
public class TestSSL {

    private static final Logger LOGGER = LoggerFactory.getLogger(TestSSL.class);

    /**
     * 通过RestTemplate来测试
     * 采用阿里的一个国密安全套接字扩展包类库
     * @throws KeyStoreException 证书库
     * @throws NoSuchAlgorithmException 无此算法
     * @throws KeyManagementException 密钥管理异常
     */
    @Test
    public void restTemplate() throws KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        //添加阿里的安全套接字扩展包GMProvider, Bouncy castle不支持TLS
        SSLContext sslContext =  SSLContexts.custom().setProvider(new GMProvider()).loadTrustMaterial(null,new HrjkTrustStrategy()).build();
        SSLConnectionSocketFactory csf = new SSLConnectionSocketFactory(sslContext, new NoVerifyHostName());
        CloseableHttpClient httpClient = HttpClients.custom().setSSLSocketFactory(csf).build();
        HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
        requestFactory.setHttpClient(httpClient);
        RestTemplate restTemplate = new RestTemplate(requestFactory);
        String object =restTemplate.getForObject("https://192.168.11.60:445/",String.class);
        LOGGER.info(object);
    }
    /**
     * 通过HttpsURLConnection来测试
     * 采用阿里的一个国密安全套接字扩展包类库。
     * @throws NoSuchAlgorithmException 无此算法
     * @throws KeyManagementException 密钥管理异常
     * @throws IOException IO异常
     */
    @Test
    public void testGmSsl() throws NoSuchAlgorithmException, KeyManagementException, IOException {
        // init SSLSocketFactory
        GMProvider provider = new GMProvider();
        SSLContext sc = SSLContext.getInstance("TLS", provider);
        sc.init(null, new TrustManager[]{}, new SecureRandom());
        SSLSocketFactory ssf = sc.getSocketFactory();
        URL serverUrl = new URL("https://192.168.11.60:445/");
        HttpsURLConnection conn = (HttpsURLConnection) serverUrl.openConnection();
        conn.setRequestMethod("GET");
        // set SSLSocketFactory
        conn.setSSLSocketFactory(ssf);
        conn.connect();
        LOGGER.info("used cipher suite:{}",conn.getCipherSuite());
    }



    class NoVerifyHostName implements X509HostnameVerifier{
        @Override
        public void verify(String host, SSLSocket ssl) throws IOException {
            LOGGER.info("host:" + host);
        }
        @Override
        public void verify(String host, X509Certificate cert) throws SSLException {
            LOGGER.info("cert type: "+ cert.getType());
            LOGGER.info("cert sigAlgName: "+ cert.getSigAlgName());
            LOGGER.info("cert publicKey: "+ Base64.toBase64String(cert.getPublicKey().getEncoded()));
        }
        @Override
        public void verify(String host, String[] cns, String[] subjectAlts) throws SSLException {
        }
        @Override
        public boolean verify(String s, SSLSession sslSession) {
            return true;
        }
    }
    class HrjkTrustStrategy implements TrustStrategy{
        @Override
        public boolean isTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            for(X509Certificate x509Certificate : chain){
                //打印
                LOGGER.info("algName:"+x509Certificate.getSigAlgName());
                LOGGER.info("oid:"+x509Certificate.getSigAlgOID());
                LOGGER.info("IssuerDn:"+x509Certificate.getIssuerDN());
                LOGGER.info("type:"+x509Certificate.getType());
            }
            return true;
        }
    }
}
