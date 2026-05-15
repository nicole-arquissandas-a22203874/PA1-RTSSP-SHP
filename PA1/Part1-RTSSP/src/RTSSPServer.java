import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;


public class RTSSPServer {


    private static final int    DEFAULT_PORT      = 8888;
    private static final int    RECV_BUFFER       = 8192;
    private static final String DEFAULT_MOVIES    = "movies/";
    private static final String DEFAULT_CRYPTCONF = "cryptoconfig.conf";

    //  State
    private static DatagramSocket          serverSocket;
    private static Map<String, CryptoConfig> cryptoConfigs;
    private static String                  moviesDir;

    //movieName keyed by client address — requests waiting for START_MOVIE
    private static final Map<String, String> pendingRequests = new ConcurrentHashMap<>();


    public static void main(String[] args) throws Exception {

        // Load server.properties
        Properties props = loadProperties("server.properties");
        int    port       = Integer.parseInt(props.getProperty("port",       String.valueOf(DEFAULT_PORT)));
        moviesDir         = props.getProperty("moviesdir",  DEFAULT_MOVIES);
        String cryptoFile = props.getProperty("cryptoconfig", DEFAULT_CRYPTCONF);

        //Load crypto configurations
        cryptoConfigs = CryptoConfigParser.parse(cryptoFile);
        System.out.println("[Server] Loaded crypto configs: " + cryptoConfigs.keySet());

        // Bind UDP socket
        serverSocket = new DatagramSocket(port);
        System.out.println("[Server] RTSSP Server listening on UDP port " + port);

        System.out.println("[Server] Waiting for Box connections...\n");

        byte[] recvBuf = new byte[RECV_BUFFER];

        //  Main receive loop
        while (true) {
            DatagramPacket inPacket = new DatagramPacket(recvBuf, recvBuf.length);
            serverSocket.receive(inPacket);

            byte[] data = Arrays.copyOf(inPacket.getData(), inPacket.getLength());
            SocketAddress from = inPacket.getSocketAddress();

            if (data.length < RTSSPPacket.HEADER_SIZE) continue;   // malformed

            byte type = RTSSPPacket.getType(data);
            if (type != RTSSPPacket.TYPE_CONTROL) continue;        // only control here

            byte[] payload = RTSSPPacket.getPayload(data, data.length);
            byte   sub     = RTSSPPacket.getControlSubtype(payload);
            String params  = RTSSPPacket.getControlParams(payload);

            System.out.printf("[Server] <- %s from %s%n",
                              RTSSPPacket.subtypeName(sub), from);

            switch (sub) {
                case RTSSPPacket.CTRL_REQUEST_MOVIE:
                    handleRequest(from, params);
                    break;
                case RTSSPPacket.CTRL_START_MOVIE:
                    handleStart(from, params);
                    break;
                default:
                    System.out.println("[Server] Ignoring unexpected control sub-type: " + sub);
            }
        }
    }



    private static void handleRequest(SocketAddress from, String movieName) throws Exception {
        movieName = movieName.trim();
        File f = new File(moviesDir + movieName);

        if (!f.exists()) {
            sendControl(from, RTSSPPacket.CTRL_RESPONSE_ERROR, "Movie not found: " + movieName);
            System.out.println("[Server] Movie not found: " + movieName);
            return;
        }

        CryptoConfig cfg = CryptoConfigParser.getConfigForMovie(cryptoConfigs, movieName);
        if (cfg == null) {
            sendControl(from, RTSSPPacket.CTRL_RESPONSE_ERROR,
                        "No crypto config for: " + movieName);
            System.out.println("[Server] No crypto config for: " + movieName);
            return;
        }

        pendingRequests.put(from.toString(), movieName);
        sendControl(from, RTSSPPacket.CTRL_RESPONSE_OK, movieName);
        System.out.println("[Server] -> RESPONSE_OK for: " + movieName);
    }

    private static void handleStart(SocketAddress from, String movieName) {
        String key = from.toString();
        if (!pendingRequests.containsKey(key)) {
            System.out.println("[Server] START_MOVIE without prior REQUEST from " + from);
            return;
        }
        String approved = pendingRequests.remove(key);
        CryptoConfig cfg = CryptoConfigParser.getConfigForMovie(cryptoConfigs, approved);

        // Stream in a dedicated thread so we can accept more clients
        new Thread(() -> {
            try {
                streamMovie(from, approved, cfg);
            } catch (Exception e) {
                System.err.println("[Server] Streaming error for " + from + ": " + e.getMessage());
            }
        }, "stream-" + from).start();
    }



    private static void streamMovie(SocketAddress dest, String movieName,
                                    CryptoConfig cfg) throws Exception {

        System.out.printf("%n[Server] -> Starting stream: %s -> %s  [%s]%n",
                          movieName, dest, cfg.ciphersuite);

        File movieFile = new File(moviesDir + movieName);
        DataInputStream g     = new DataInputStream(new FileInputStream(movieFile));

        byte[] frameBuf = new byte[4096];
        int    count    = 0;
        long   totalOut = 0;
        long   t0       = System.nanoTime();
        long   q0       = 0;

        while (g.available() > 0) {
            // Read one frame: Short size | Long timestamp | byte[size] frame
            int  size = g.readShort();
            long ts   = g.readLong();
            if (count == 0) q0 = ts;
            count++;
            g.readFully(frameBuf, 0, size);

            byte[] plaintext = Arrays.copyOf(frameBuf, size);

            // Encrypt frame -> RTSSP DATA payload
            byte[] encPayload = CryptoUtils.encrypt(cfg, plaintext);
            byte[] packet= RTSSPPacket.buildPacket(RTSSPPacket.TYPE_DATA, encPayload);


            long now = System.nanoTime();
            long sleepMs = ((ts - q0) - (now - t0)) / 1_000_000L;
            if (sleepMs > 0) Thread.sleep(sleepMs);

            serverSocket.send(new DatagramPacket(packet, packet.length, dest));
            totalOut += packet.length;
            System.out.print(":");
        }
        g.close();

        // Send FINISH control message
        sendControl(dest, RTSSPPacket.CTRL_FINISH, movieName);
        System.out.println("\n[Server] -> FINISH sent.");

        // Statistics
        long durationNs = System.nanoTime() - t0;
        long durationS  = Math.max(1, durationNs / 1_000_000_000L);
        System.out.println("Server Statistics:");
        System.out.println("Movie: " + movieName);
        System.out.println("Cipher: "+ cfg.ciphersuite);
        System.out.println("Frames: " + count);
        System.out.println("Duration: " + durationS + " s");
        System.out.println("FPS: " + count / durationS);



    }


    private static void sendControl(SocketAddress dest, byte subtype, String params)
            throws Exception {
        byte[] payload = RTSSPPacket.buildControlPayload(subtype, params);
        byte[] packet  = RTSSPPacket.buildPacket(RTSSPPacket.TYPE_CONTROL, payload);
        serverSocket.send(new DatagramPacket(packet, packet.length, dest));
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
