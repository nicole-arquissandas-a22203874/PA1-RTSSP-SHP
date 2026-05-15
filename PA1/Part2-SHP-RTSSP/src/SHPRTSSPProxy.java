import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.Certificate;
import java.util.*;


public class SHPRTSSPProxy {

    private static final int RECV_BUFFER   = 8192;
    private static final int HANDSHAKE_TO  = 15_000;
    private static final int STREAM_TO     = 30_000;

    // seerver will pick from these cipher suites
    private static final String PROPOSED_SUITES =
            "AES/GCM/NoPadding,ChaCha20-Poly1305,AES/CTR/NoPadding,AES/CBC/PKCS5Padding";

    public static void main(String[] args) throws Exception {

        Properties props = loadProperties("config.properties");
        String remote     = props.getProperty("remote");
        String localDeliv = props.getProperty("localdelivery");
        String movieName  = props.getProperty("movie", "cars.dat");
        String ksPath     = props.getProperty("keystore",   "certs/box.p12");
        String ksPass     = props.getProperty("keystorepass","password");
        String ksAlias    = props.getProperty("keystorealias","box");
        String tsPath     = props.getProperty("truststore", "certs/box-truststore.p12");
        String tsPass     = props.getProperty("truststorepass","password");

        InetSocketAddress serverAddr = parseAddr(remote);
        InetSocketAddress vlcAddr    = parseAddr(localDeliv);

        System.out.println("[SHP-Proxy] Server   : " + serverAddr);
        System.out.println("[SHP-Proxy] VLC addr : " + vlcAddr);
        System.out.println("[SHP-Proxy] Movie    : " + movieName);

        // Load box identity
        KeyStore boxKs = SHPHandshakeUtils.loadKeyStore(ksPath, ksPass);
        PrivateKey boxPrivKey   = SHPHandshakeUtils.getPrivateKey(boxKs, ksAlias, ksPass);
        byte[]     boxCertBytes = SHPHandshakeUtils.getCertBytes(boxKs, ksAlias);
        KeyStore   boxTruststore = SHPHandshakeUtils.loadKeyStore(tsPath, tsPass);
        System.out.println("[SHP-Proxy] Identity loaded: alias=" + ksAlias);

        DatagramSocket proxySocket = new DatagramSocket();
        DatagramSocket outSocket   = new DatagramSocket();
        byte[] recvBuf = new byte[RECV_BUFFER];


        //  SHP HANDSHAKE


        //   Generate ephemeral ECDH key pair
        KeyPair boxECDH = SHPHandshakeUtils.generateEphemeralKeyPair();
        byte[]  boxECDHPubBytes = boxECDH.getPublic().getEncoded();
        byte[]  clientNonce     = SHPHandshakeUtils.generateNonce();

        //  Build and send CLIENT_HELLO
        ByteArrayOutputStream bodyBuf = new ByteArrayOutputStream();
        DataOutputStream      bodyDos = new DataOutputStream(bodyBuf);
        SHPMessage.writeString(bodyDos, movieName);
        SHPMessage.writeBytes (bodyDos, boxECDHPubBytes);
        SHPMessage.writeBytes (bodyDos, boxCertBytes);
        SHPMessage.writeString(bodyDos, PROPOSED_SUITES);
        SHPMessage.writeBytes (bodyDos, clientNonce);
        byte[] clientHelloBody = bodyBuf.toByteArray();
        byte[] clientSig = SHPHandshakeUtils.sign(boxPrivKey, clientHelloBody);

        byte[] clientHelloMsg = SHPMessage.buildClientHello(
                movieName, boxECDHPubBytes, boxCertBytes,
                PROPOSED_SUITES, clientNonce, clientSig);

        System.out.println("[SHP-Proxy] -> CLIENT_HELLO");
        proxySocket.send(new DatagramPacket(clientHelloMsg, clientHelloMsg.length, serverAddr));

        //  Receive and validate SERVER_HELLO
        proxySocket.setSoTimeout(HANDSHAKE_TO);
        DatagramPacket shPkt = new DatagramPacket(recvBuf, recvBuf.length);
        proxySocket.receive(shPkt);
        proxySocket.setSoTimeout(0);

        byte[] rawSH = Arrays.copyOf(shPkt.getData(), shPkt.getLength());
        SHPMessage sh = SHPMessage.parse(rawSH);

        if (sh.type != SHPMessage.TYPE_SERVER_HELLO) {
            System.err.println("[SHP-Proxy] Expected SERVER_HELLO, got: " + sh.type);
            System.exit(1);
        }
        System.out.println("[SHP-Proxy] <- SERVER_HELLO");

        // Verify server certificate trusted
        Certificate serverCert = SHPHandshakeUtils.decodeCertificate(sh.certificate);
        if (!SHPHandshakeUtils.isCertificateTrusted(boxTruststore, serverCert)) {
            System.err.println("[SHP-Proxy] Server certificate NOT trusted. Aborting.");
            System.exit(1);
        }
        System.out.println("[SHP-Proxy] Server certificate trusted");

        // Verify SERVER_HELLO signature
        PublicKey serverPubKey = serverCert.getPublicKey();
        if (!SHPHandshakeUtils.verify(serverPubKey, sh.bodyBytes, sh.signature)) {
            System.err.println("[SHP-Proxy] SERVER_HELLO signature INVALID. Aborting.");
            System.exit(1);
        }
        System.out.println("[SHP-Proxy]  SERVER_HELLO signature valid");

        // Verify server's response to our nonce
        if (!SHPHandshakeUtils.verifyNonceResponse(serverPubKey, clientNonce, sh.nonceResponse)) {
            System.err.println("[SHP-Proxy] Server nonce response INVALID. Aborting.");
            System.exit(1);
        }
        System.out.println("[SHP-Proxy] Server nonce response valid");

        String selectedSuite = sh.ciphersuites;
        byte[] serverNonce   = sh.nonce;
        System.out.println("[SHP-Proxy] Negotiated suite: " + selectedSuite);

        // Derive session keys
        PublicKey serverECDHPub = SHPHandshakeUtils.decodePublicKey(sh.ecdhPublicKey);
        byte[]    sharedSecret  = SHPHandshakeUtils.ecdhSharedSecret(
                                      boxECDH.getPrivate(), serverECDHPub);
        CryptoConfig sessionCfg = SHPHandshakeUtils.deriveSessionConfig(
                                      sharedSecret, clientNonce, serverNonce, selectedSuite);
        System.out.println("[SHP-Proxy]  Session keys derived (ECDH + HKDF-SHA256)");

        // Build and send CSSP
        byte[] clientNonceResp = SHPHandshakeUtils.signNonce(boxPrivKey, serverNonce);
        byte[] csspPlain       = SHPMessage.buildCSSPPlaintext(clientNonceResp);
        byte[] csspEncrypted   = CryptoUtils.encrypt(sessionCfg, csspPlain);
        byte[] csspMsg         = SHPMessage.buildCSSP(csspEncrypted);

        proxySocket.send(new DatagramPacket(csspMsg, csspMsg.length, serverAddr));
        System.out.println("[SHP-Proxy] -> CSSP sent");
        System.out.println("[SHP-Proxy] -- SHP HANDSHAKE COMPLETE -- Awaiting stream...\n");


        //  RTSSP STREAM RECEIVE
        proxySocket.setSoTimeout(STREAM_TO);
        int  framesOk   = 0, framesFail = 0;
        long totalBytes = 0;
        long t0 = System.nanoTime();

        try {
            while (true) {
                DatagramPacket inPkt = new DatagramPacket(recvBuf, recvBuf.length);
                proxySocket.receive(inPkt);

                byte[] data = Arrays.copyOf(inPkt.getData(), inPkt.getLength());
                if (data.length < RTSSPPacket.HEADER_SIZE) continue;

                byte type    = RTSSPPacket.getType(data);
                byte[] payload = RTSSPPacket.getPayload(data, data.length);

                if (type == RTSSPPacket.TYPE_CONTROL) {
                    if (RTSSPPacket.getControlSubtype(payload) == RTSSPPacket.CTRL_FINISH) {
                        System.out.println("\n[SHP-Proxy] <- FINISH received.");
                        break;
                    }
                } else if (type == RTSSPPacket.TYPE_DATA) {
                    try {
                        byte[] plaintext = CryptoUtils.decrypt(sessionCfg, payload);
                        totalBytes += plaintext.length;
                        outSocket.send(new DatagramPacket(plaintext, plaintext.length, vlcAddr));
                        framesOk++;
                        System.out.print(".");
                    } catch (Exception e) {
                        framesFail++;
                        System.err.printf("%n[SHP-Proxy] Decrypt FAILED frame #%d: %s%n",
                                          framesOk + framesFail, e.getMessage());
                    }
                }
            }
        } catch (SocketTimeoutException e) {
            System.out.println("\n[SHP-Proxy] Stream timeout - movie finished.");
        }

        proxySocket.close();
        outSocket.close();

        long durationS = Math.max(1, (System.nanoTime() - t0) / 1_000_000_000L);
        System.out.println("Proxy Statistics:");
        System.out.println("Movie: " + movieName);
        System.out.println("Cipher: " + selectedSuite);
        System.out.println("Duration: " + durationS + " s");
        System.out.println("FPS: "+ framesOk / durationS);

    }

    private static InetSocketAddress parseAddr(String s) {
        String[] p = s.split(":");
        return new InetSocketAddress(p[0].trim(), Integer.parseInt(p[1].trim()));
    }

    private static Properties loadProperties(String filename) throws IOException {
        Properties props = new Properties();
        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = br.readLine()) != null) {
                String t = line.trim();
                if (!t.startsWith("//") && !t.startsWith("#")) sb.append(line).append('\n');
            }
        }
        props.load(new StringReader(sb.toString()));
        return props;
    }
}
