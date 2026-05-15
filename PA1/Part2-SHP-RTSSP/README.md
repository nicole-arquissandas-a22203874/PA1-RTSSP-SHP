# PA1 – Part 2

Setup/Run:
1. First in the src directory generate the certificates/truststore using the comands(in the directory KEYTOOL)
1. On Part2-SHP-RTSSP directory and compile everything using: javac src/*.java
2. On src directory open 1 terminal run the server :java SHPRTSSPServer
3. On src directory open another terminal and run the box(proxy): java SHPRTSSPProxy
4. open vlc and add udp://@127.0.0.1:7777 and click emission

Notes:
- to choose what movie box send to server go to config.properties
- to choose what ciphersuit server selects from box proposed chiphersuits list go to server.properties
- Supported ciphersuites:AES/GCM/NoPadding;ChaCha20-Poly1305;AES/CTR/NoPadding;AES/CBC/PKCS5Padding       


