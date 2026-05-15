import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.Certificate;
import java.util.*;
import java.util.concurrent.*;


public class SHPRTSSPServer {

    private static final int    RECV_BUFFER = 65536;



    private static DatagramSocket serverSocket;
    private static String         moviesDir;
    private static PrivateKey     serverPrivKey;
    private static byte[]         serverCertBytes;
    private static KeyStore       serverTruststore;
    private static String serverCiphersuite;

    private static final ConcurrentHashMap<String, BlockingQueue<byte[]>> pendingHandshakes
            = new ConcurrentHashMap<>();

    public static void main(String[] args) throws Exception {

        Properties props = loadProperties("server.properties");
        int    port    = Integer.parseInt(props.getProperty("port", "8888"));
        moviesDir      = props.getProperty("moviesdir",  "movies/");
        String ksPath  = props.getProperty("keystore",   "certs/server.p12");
        String ksPass  = props.getProperty("keystorepass","password");
        String ksAlias = props.getProperty("keystorealias","server");
        String tsPath  = props.getProperty("truststore", "certs/server-truststore.p12");
        String tsPass  = props.getProperty("truststorepass","password");
        serverCiphersuite = props.getProperty("ciphersuite", "AES/GCM/NoPadding");
        KeyStore ks = SHPHandshakeUtils.loadKeyStore(ksPath, ksPass);
        serverPrivKey    = SHPHandshakeUtils.getPrivateKey(ks, ksAlias, ksPass);
        serverCertBytes  = SHPHandshakeUtils.getCertBytes(ks, ksAlias);
        serverTruststore = SHPHandshakeUtils.loadKeyStore(tsPath, tsPass);
        System.out.println("[SHP-Server] Identity loaded: alias=" + ksAlias);

        serverSocket = new DatagramSocket(port);

        System.out.println("[SHP-Server] Listening on UDP port " + port);

        System.out.println("[SHP-Server] Waiting for SHP handshakes...\n");

        byte[] buf = new byte[RECV_BUFFER];

        while (true) {
            DatagramPacket pkt = new DatagramPacket(buf, buf.length);
            serverSocket.receive(pkt);

            byte[] data = Arrays.copyOf(pkt.getData(), pkt.getLength());
            String fromKey = pkt.getSocketAddress().toString();
            SocketAddress fromAddr = pkt.getSocketAddress();

            if (data.length == 0) continue;

            byte firstByte = data[0];

            if (firstByte == SHPMessage.TYPE_CLIENT_HELLO) {
                //  create a queue for this client and start a thread
                BlockingQueue<byte[]> queue = new LinkedBlockingQueue<>();
                pendingHandshakes.put(fromKey, queue);
                queue.put(data); // put the CLIENT_HELLO into the queue

                final SocketAddress clientAddr = fromAddr;
                final String clientKey = fromKey;
                new Thread(() -> {
                    try {
                        handleHandshake(clientAddr, clientKey, queue);
                    } catch (Exception e) {
                        System.err.println("[SHP-Server] Handshake error from "
                                + clientAddr + ": " + e.getMessage());
                        e.printStackTrace();
                    } finally {
                        pendingHandshakes.remove(clientKey);
                    }
                }, "shp-" + fromKey).start();

            } else if (firstByte == SHPMessage.TYPE_CSSP) {
                // Route CSSP to the waiting handshake thread
                BlockingQueue<byte[]> queue = pendingHandshakes.get(fromKey);
                if (queue != null) {
                    queue.put(data);
                } else {
                    System.out.println("[SHP-Server] Unexpected CSSP from " + fromKey);
                }

            } else if (firstByte == RTSSPPacket.TYPE_CONTROL) {

                System.out.println("[SHP-Server] Unexpected RTSSP control from " + fromKey);
            }
        }
    }


    // SHP Handshake runs in its own thread, reads from queue

    private static void handleHandshake(SocketAddress from, String fromKey,
                                        BlockingQueue<byte[]> queue) throws Exception {

        // Read CLIENT_HELLO from queue
        byte[] rawCH = queue.poll(15, TimeUnit.SECONDS);
        if (rawCH == null) throw new RuntimeException("Timeout waiting for CLIENT_HELLO");

        System.out.println("[SHP-Server] <- CLIENT_HELLO from " + from);

        SHPMessage ch = SHPMessage.parse(rawCH);

        //  Verify client certificate is trusted
        Certificate clientCert = SHPHandshakeUtils.decodeCertificate(ch.certificate);
        if (!SHPHandshakeUtils.isCertificateTrusted(serverTruststore, clientCert)) {
            System.err.println("[SHP-Server] Client certificate NOT trusted. Rejecting.");
            return;
        }
        System.out.println("[SHP-Server]   Client certificate trusted");

        //  Verify CLIENT_HELLO signature
        PublicKey clientPubKey = clientCert.getPublicKey();
        if (!SHPHandshakeUtils.verify(clientPubKey, ch.bodyBytes, ch.signature)) {
            System.err.println("[SHP-Server] CLIENT_HELLO signature INVALID. Rejecting.");
            return;
        }
        System.out.println("[SHP-Server]   CLIENT_HELLO signature valid");

        // Check movie exists
        File movieFile = new File(moviesDir + ch.movieName);
        if (!movieFile.exists()) {
            System.err.println("[SHP-Server] Movie not found: " + ch.movieName);
            return;
        }

        //  Select ciphersuite
        String selected = selectCiphersuite(ch.ciphersuites);
        if (selected == null) {
            System.err.println("[SHP-Server] No common ciphersuite. Rejected.");
            return;
        }
        System.out.println("[SHP-Server]   Selected ciphersuite: " + selected);

        //  Generate server ephemeral ECDH key pair
        KeyPair serverECDH = SHPHandshakeUtils.generateEphemeralKeyPair();
        byte[]  serverECDHPubBytes = serverECDH.getPublic().getEncoded();

        //  Generate server nonce and sign client's nonce
        byte[] serverNonce   = SHPHandshakeUtils.generateNonce();
        byte[] nonceResponse = SHPHandshakeUtils.signNonce(serverPrivKey, ch.nonce);

        //  Build SERVER_HELLO body and sign it
        ByteArrayOutputStream bodyBuf = new ByteArrayOutputStream();
        DataOutputStream      bodyDos = new DataOutputStream(bodyBuf);
        SHPMessage.writeString(bodyDos, ch.movieName);
        SHPMessage.writeBytes (bodyDos, serverECDHPubBytes);
        SHPMessage.writeBytes (bodyDos, serverCertBytes);
        SHPMessage.writeString(bodyDos, selected);
        SHPMessage.writeBytes (bodyDos, serverNonce);
        SHPMessage.writeBytes (bodyDos, nonceResponse);
        byte[] serverHelloBody = bodyBuf.toByteArray();
        byte[] serverSig = SHPHandshakeUtils.sign(serverPrivKey, serverHelloBody);

        byte[] serverHelloMsg = SHPMessage.buildServerHello(
                ch.movieName, serverECDHPubBytes, serverCertBytes,
                selected, serverNonce, nonceResponse, serverSig);

        serverSocket.send(new DatagramPacket(serverHelloMsg, serverHelloMsg.length, from));
        System.out.println("[SHP-Server] -> SERVER_HELLO sent");

        // Derive session keys
        PublicKey clientECDHPub = SHPHandshakeUtils.decodePublicKey(ch.ecdhPublicKey);
        byte[]    sharedSecret  = SHPHandshakeUtils.ecdhSharedSecret(
                serverECDH.getPrivate(), clientECDHPub);
        CryptoConfig sessionCfg = SHPHandshakeUtils.deriveSessionConfig(
                sharedSecret, ch.nonce, serverNonce, selected);
        System.out.println("[SHP-Server]   Session keys derived (ECDH + HKDF-SHA256)");

        // Wait for CSSP  from the queue
        System.out.println("[SHP-Server]   Waiting for CSSP...");
        byte[] rawCSSP = queue.poll(15, TimeUnit.SECONDS);
        if (rawCSSP == null) throw new RuntimeException("Timeout waiting for CSSP");

        SHPMessage cssp = SHPMessage.parse(rawCSSP);
        if (cssp.type != SHPMessage.TYPE_CSSP) {
            System.err.println("[SHP-Server] Expected CSSP, got: " + cssp.type);
            return;
        }

        // Decrypt CSSP payload
        byte[] csspPlain  = CryptoUtils.decrypt(sessionCfg, cssp.encryptedPayload);
        byte[][] csspFields = SHPMessage.parseCSSPPlaintext(csspPlain);
        byte[] clientNonceResp = csspFields[0];
        String readyStr        = new String(csspFields[1]);

        // Verify client's nonce response
        if (!SHPHandshakeUtils.verifyNonceResponse(clientPubKey, serverNonce, clientNonceResp)) {
            System.err.println("[SHP-Server] CSSP nonce response INVALID. Aborting.");
            return;
        }
        if (!"READY".equals(readyStr)) {
            System.err.println("[SHP-Server] CSSP READY string missing.");
            return;
        }

        System.out.println("[SHP-Server] <- CSSP verified");
        System.out.println("[SHP-Server] -- SHP HANDSHAKE COMPLETE -- Starting stream...\n");

        //  Stream
        streamMovie(from, ch.movieName, sessionCfg);
    }


    // RTSSP Streaming
    private static void streamMovie(SocketAddress dest, String movieName,
                                    CryptoConfig cfg) throws Exception {
        System.out.printf("[SHP-Server] >> Streaming: %s  cipher=%s%n",
                movieName, cfg.ciphersuite);

        DataInputStream g = new DataInputStream(
                new FileInputStream(new File(moviesDir + movieName)));
        byte[] frameBuf = new byte[4096];
        int count = 0; long totalOut = 0;
        long t0 = System.nanoTime(), q0 = 0;

        while (g.available() > 0) {
            int  size = g.readShort();
            long ts   = g.readLong();
            if (count == 0) q0 = ts;
            count++;
            g.readFully(frameBuf, 0, size);

            byte[] enc = CryptoUtils.encrypt(cfg, Arrays.copyOf(frameBuf, size));
            byte[] pkt = RTSSPPacket.buildPacket(RTSSPPacket.TYPE_DATA, enc);

            long sleepMs = ((ts - q0) - (System.nanoTime() - t0)) / 1_000_000L;
            if (sleepMs > 0) Thread.sleep(sleepMs);

            serverSocket.send(new DatagramPacket(pkt, pkt.length, dest));
            totalOut += pkt.length;
            System.out.print(":");
        }
        g.close();

        byte[] finPkt = RTSSPPacket.buildPacket(RTSSPPacket.TYPE_CONTROL,
                RTSSPPacket.buildControlPayload(RTSSPPacket.CTRL_FINISH, movieName));
        serverSocket.send(new DatagramPacket(finPkt, finPkt.length, dest));

        long durationS = Math.max(1, (System.nanoTime() - t0) / 1_000_000_000L);
        System.out.println("Server Statistics:");
        System.out.println("Movie: "    + movieName);
        System.out.println("Cipher: "   + cfg.ciphersuite);
        System.out.println("Frames: "   + count);
        System.out.println("Duration: " + durationS + " s");
        System.out.println("FPS: "      + count / durationS);


    }



    private static String selectCiphersuite(String clientList) {
        for (String c : clientList.split(",")) {
            if (serverCiphersuite.equalsIgnoreCase(c.trim())) return serverCiphersuite;
        }
        return null; // client doesn't support what server wants
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
