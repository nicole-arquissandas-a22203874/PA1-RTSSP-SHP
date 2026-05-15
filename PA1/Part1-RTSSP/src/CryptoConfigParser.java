import java.io.*;
import java.util.*;


public class CryptoConfigParser {


     // Parse the given file and return a map of config-block-name -> CryptoConfig


    public static Map<String, CryptoConfig> parse(String filename) throws IOException {
        Map<String, CryptoConfig> configs = new LinkedHashMap<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line;
            String currentKey = null;
            CryptoConfig current = null;

            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("//") || line.startsWith("#")) continue;

                if (line.startsWith("<") && !line.startsWith("</")) {
                    // Opening tag...  <cars.dat.encrypted>
                    currentKey = line.substring(1, line.length() - 1).trim();
                    current    = new CryptoConfig();

                } else if (line.startsWith("</")) {
                    // Closing tag
                    if (currentKey != null && current != null) {
                        configs.put(currentKey, current);
                    }
                    currentKey = null;
                    current    = null;

                } else if (current != null && line.contains(":")) {
                    int colon = line.indexOf(':');
                    String field = line.substring(0, colon).trim().toLowerCase();
                    String value = line.substring(colon + 1).trim();

                    switch (field) {
                        case "ciphersuite": current.ciphersuite   = value;             break;
                        case "key":         current.key           = hexToBytes(value); break;
                        case "hmac":        current.hmacAlgorithm = value; break;
                        case "mackey":      current.macKey        = hexToBytes(value); break;
                    }
                }
            }
        }
        return configs;
    }


     // Find the CryptoConfig for a given movie filename.
     // Tries exact match first, then "moviename.encrypted" suffix, then prefix match.

    public static CryptoConfig getConfigForMovie(Map<String, CryptoConfig> configs,
                                                  String movieName) {
        if (configs.containsKey(movieName))                    return configs.get(movieName);
        if (configs.containsKey(movieName + ".encrypted"))     return configs.get(movieName + ".encrypted");
        // prefix match ( "cars.dat" matches "cars.dat.encrypted")
        for (Map.Entry<String, CryptoConfig> e : configs.entrySet()) {
            if (e.getKey().startsWith(movieName)) return e.getValue();
        }
        return null;
    }

    // Internal helpers

    //Convert a hex string  to a byte array
    public static byte[] hexToBytes(String hex) {
        hex = hex.replaceAll("\\s+", "");
        if (hex.length() % 2 != 0)
            throw new IllegalArgumentException("Odd length hex string: " + hex);
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }


}
