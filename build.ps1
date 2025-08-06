cd ".\agent"


cmd /c '"C:\Program Files\Java\jdk1.8.0_202\bin\javac.exe" src\main\java\com\nocebo\nCore\*.java'
move-item -force .\src\main\java\com\nocebo\nCore\genLib.class ..\server\fileroot\genLib.class
move-item -force .\src\main\java\com\nocebo\nCore\autoLib.class ..\server\fileroot\autoLib.class
cd src\main\java
cmd /c '"C:\Program Files\Java\jdk1.8.0_202\bin\jar.exe" cfm ..\..\..\..\server\fileroot\lib\iAgent.jar ..\..\..\MANIFEST.TXT .\com\nocebo\nCore\*.class'
cd ..\..\..\..   

cd ".\loader"
cmd /c '"C:\Program Files\Java\jdk1.8.0_202\bin\javac.exe" src\main\java\com\nocebo\nLoader\*.java'
cd src\main\java
cmd /c '"C:\Program Files\Java\jdk1.8.0_202\bin\jar.exe" cfm ..\..\..\..\server\fileroot\lib\iLoader.jar ..\..\..\MANIFEST.txt .\com\nocebo\nLoader\*.class'
cd ..\..\..\..

cd ".\server\listener"
cmd /c ".\mvnw clean install"
cd ..\..
