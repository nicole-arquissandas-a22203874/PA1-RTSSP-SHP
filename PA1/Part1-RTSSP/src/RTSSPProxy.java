import java.io.*;
import java.net.*;
import java.util.*;

public class RTSSPProxy {

    private static final int RECV_BUFFER     = 8192;
    private static final int HANDSHAKE_TO_MS = 10_000;   // 10 s timeout for control replies
    private static final int STREAM_TO_MS    = 30_000;   // 30 s timeout between data packets

    //
    public static void main(String[] args) throws Exception {

        //  Load config.properties
        Properties props = loadProperties("config.properties");
        String remote       = props.getProperty("remote");        // server host:port
        String localDeliv   = props.getProperty("localdelivery"); // VLC host:port
        String movieName    = props.getProperty("movie", "cars.dat");
        String cryptoFile   = props.getProperty("cryptoconfig", "cryptoconfig.conf");

        InetSocketAddress serverAddr = parseAddr(remote);
        InetSocketAddress vlcAddr    = parseAddr(localDeliv);

        System.out.println("[Proxy] Remote server : " + serverAddr);
        System.out.println("[Proxy] Local delivery: " + vlcAddr);
        System.out.println("[Proxy] Requested movie: " + movieName);

        // Load crypto config
        Map<String, CryptoConfig> cryptoConfigs = CryptoConfigParser.parse(cryptoFile);
        CryptoConfig cfg = CryptoConfigParser.getConfigForMovie(cryptoConfigs, movieName);
        if (cfg == null) {
            System.err.println("[Proxy] ERROR: no crypto config for '" + movieName + "'");
            System.err.println("[Proxy] Available configs: " + cryptoConfigs.keySet());
            System.exit(1);
        }
        System.out.println("[Proxy] Cipher suite: " + cfg);

        //Sockets
        DatagramSocket proxySocket = new DatagramSocket();   // to/from server
        DatagramSocket outSocket   = new DatagramSocket();   // to VLC
        byte[] recvBuf = new byte[RECV_BUFFER];

        // 1: REQUEST_MOVIE
        System.out.println("\n[Proxy] -> REQUEST_MOVIE: " + movieName);
        sendControl(proxySocket, serverAddr, RTSSPPacket.CTRL_REQUEST_MOVIE, movieName);

        // 2: Wait for RESPONSE_OK / ERROR
        proxySocket.setSoTimeout(HANDSHAKE_TO_MS);
        DatagramPacket rsp = new DatagramPacket(recvBuf, recvBuf.length);
        proxySocket.receive(rsp);

        byte[] rspData    = Arrays.copyOf(rsp.getData(), rsp.getLength());
        byte[] rspPayload = RTSSPPacket.getPayload(rspData, rspData.length);
        byte   rspSub     = RTSSPPacket.getControlSubtype(rspPayload);
        String rspParams  = RTSSPPacket.getControlParams(rspPayload);

        System.out.printf("[Proxy]<-%s: %s%n",
                          RTSSPPacket.subtypeName(rspSub), rspParams);

        if (rspSub == RTSSPPacket.CTRL_RESPONSE_ERROR) {
            System.err.println("[Proxy] Server rejected request: " + rspParams);
            System.exit(1);
        }
        if (rspSub != RTSSPPacket.CTRL_RESPONSE_OK) {
            System.err.println("[Proxy] Unexpected response: " + rspSub);
            System.exit(1);
        }

        // 3: START_MOVIE
        System.out.println("[Proxy]-> START_MOVIE: " + movieName);
        sendControl(proxySocket, serverAddr, RTSSPPacket.CTRL_START_MOVIE, movieName);

        // 4: Receive encrypted stream, decrypt
        System.out.println("[Proxy] Streaming started. Forwarding to " + vlcAddr + "\n");
        proxySocket.setSoTimeout(STREAM_TO_MS);

        int  framesOk   = 0;
        int  framesFail = 0;
        long totalBytes = 0;
        long t0         = System.nanoTime();

        try {
            while (true) {
                DatagramPacket inPkt = new DatagramPacket(recvBuf, recvBuf.length);
                proxySocket.receive(inPkt);

                byte[] data = Arrays.copyOf(inPkt.getData(), inPkt.getLength());
                if (data.length < RTSSPPacket.HEADER_SIZE) continue;

                byte   type    = RTSSPPacket.getType(data);
                byte[] payload = RTSSPPacket.getPayload(data, data.length);

                if (type == RTSSPPacket.TYPE_CONTROL) {
                    byte sub = RTSSPPacket.getControlSubtype(payload);
                    if (sub == RTSSPPacket.CTRL_FINISH) {
                        System.out.println("\n[Proxy] <- FINISH received.");
                        break;
                    }
                    System.out.println("[Proxy] <- Control: " + RTSSPPacket.subtypeName(sub));

                } else if (type == RTSSPPacket.TYPE_DATA) {
                    try {
                        byte[] plaintext = CryptoUtils.decrypt(cfg, payload);
                        totalBytes += plaintext.length;

                        // Forward plaintext frame to media player
                        outSocket.send(new DatagramPacket(
                                plaintext, plaintext.length, vlcAddr));
                        framesOk++;
                        System.out.print(".");

                    } catch (Exception e) {
                        framesFail++;
                        System.err.printf("%n[Proxy] Decryption FAILED frame #%d: %s%n",
                                          framesOk + framesFail, e.getMessage());
                    }
                }
            }
        } catch (SocketTimeoutException e) {
            System.out.println("\n[Proxy] Stream timeout — assuming movie finished.");
        }

        proxySocket.close();
        outSocket.close();

        //statistics
        long durationNs = System.nanoTime() - t0;
        long durationS  = Math.max(1, durationNs / 1_000_000_000L);
        System.out.println("Proxy Statistics:");
        System.out.println("Movie: "+ movieName);
        System.out.println("Duration: "   + durationS + " s");
        System.out.println("Cipher: "+ cfg.ciphersuite);
        System.out.println("FPS: "+ framesOk / durationS);


    }

  //helpers

    private static void sendControl(DatagramSocket sock, InetSocketAddress dest,
                                    byte subtype, String params) throws Exception {
        byte[] payload = RTSSPPacket.buildControlPayload(subtype, params);
        byte[] packet  = RTSSPPacket.buildPacket(RTSSPPacket.TYPE_CONTROL, payload);
        sock.send(new DatagramPacket(packet, packet.length, dest));
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
                String trimmed = line.trim();
                if (!trimmed.startsWith("//") && !trimmed.startsWith("#")) {
                    sb.append(line).append('\n');
                }
            }
        }
        props.load(new StringReader(sb.toString()));
        return props;
    }
}
