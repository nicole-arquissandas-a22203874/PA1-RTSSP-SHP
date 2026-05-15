# PA1 – Part 1:

Setup/Run:
1. first go to Part1-RTSSP directory and compile everything using: javac src/*.java 
2. On src directory open 1 terminal run the server :java RTSSPServer
3. On src directory open another terminal and run the box(proxy): java RTSSPProxy
4. open vlc and add udp://@127.0.0.1:7777 and click emission

Notes:
- To choose which movie to stream go to config.properties
- Supported ciphersuites:AES/GCM/NoPadding;ChaCha20-Poly1305;AES/CTR/NoPadding;AES/CBC/PKCS5Padding       

