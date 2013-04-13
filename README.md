instant_messenger
=================
How to run Client and Server in Terminal:
Go to Instant_Messenger/
Server:-
Compile: javac src/common/*.java src/server/*.java
Run: java -cp src server.Server

Client:-
Compile: javac src/common/*.java src/client/*.java
Run: java -cp src client.Client

-d directory: To specify where to put class files during compilation
: -> Use colon as separater on Unix(MacOS or Linux)
; -> Use semicolon as separater on Windows
-cp directory: Specify the classpath, where to search for the files.
