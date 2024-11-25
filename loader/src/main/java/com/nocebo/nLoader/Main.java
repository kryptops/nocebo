package com.nocebo.nLoader;

import com.sun.tools.attach.VirtualMachine;
import com.sun.tools.attach.VirtualMachineDescriptor;

public class Main {
    //replaceable
    static public jarPath = "";

    public static void main(String[] args)
    {
        //passthrough


        ArrayList beforeList = getActiveVM();
        //start stub
        int jvmStubRes = initJVMStub(jarPath);
        ArrayList afterList = getActiveVM();

        VirtualMachineDescriptor targetVM = getTargetVM(beforeList, afterList);
        
    }

    public static int initJVMStub(String jarStubPath)
    {
        //runtimeexec
    }

    public static int attachJVMStub()
    {
        
    }

    public static ArrayList getActiveVM()
    {
        ArrayList activeVM = new ArrayList(VirtualMachine.list());
        return activeVM;
    }

    public static VirtualMachineDescriptor getTargetVM(ArrayList vmListBefore, ArrayList vmListAfter)
    {

    }
}
