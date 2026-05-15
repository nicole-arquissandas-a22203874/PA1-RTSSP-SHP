
public class CryptoConfig {


    public String ciphersuite;
    public byte[] key;
    public String hmacAlgorithm;
    public byte[] macKey;


    public boolean isAEAD() {
        if (ciphersuite == null) return false;
        String cs = ciphersuite.toUpperCase();
        return cs.contains("GCM") || cs.contains("POLY1305");
    }


    public int getIVSize() {
        if (isAEAD()) return 12;
        return 16;
    }

    public String getKeyAlgorithm() {
        if (ciphersuite != null && ciphersuite.toUpperCase().startsWith("CHACHA20")) {
            return "ChaCha20";
        }
        return "AES";
    }


    public int getHMACSize() {
        if (hmacAlgorithm == null) return 0;
        if (hmacAlgorithm.toUpperCase().contains("256")) return 32;
        if (hmacAlgorithm.toUpperCase().contains("512")) return 64;
        return 32; // default
    }

    @Override
    public String toString() {
        return "CryptoConfig{cipher=" + ciphersuite
                + (hmacAlgorithm != null ? ", hmac=" + hmacAlgorithm : "")
                + "}";
    }
}
