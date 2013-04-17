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

OR 
Compile all into bin folder:
javac -d bin src/common/*.java src/server/*.java src/client/*.java
Run:
java -cp bin server.Server
java -cp bin client.Client

*Note: Make sure your current directory is Instant_Messenger

Optional Command line arguments -:
java server.Server serverPort

java client.Client clientPort
java client.Client clientPort serverIP 
java client.Client clientPort serverIP serverPort

Config File(Incase, not using command line) -:
1) Specify the server port in server.cfg file
2) Specify the client port and server Ip in client.cfg
3) Change client port each time, you want to run new client.
4) Configuration files helps server and client locates server public keys.

Useful Information:
-d directory: To specify where to put class files during compilation
: -> Use colon as separater on Unix(MacOS or Linux)
; -> Use semicolon as separater on Windows
-cp directory: Specify the classpath, where to search for the files.
package.MainClass -> java package.MainClass to excute and javac to compile.

Contact us at:
Mandeep Singh: singman@husky.neu.edu
Srivatsa Srivatsa: srivatsa@ccs.neu.edu
