import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.Arrays;

public class CryptoUtils {

    private static final SecureRandom RNG = new SecureRandom();


    public static byte[] encrypt(CryptoConfig config, byte[] plaintext) throws Exception {
        return config.isAEAD()
                ? encryptAEAD(config, plaintext)
                : encryptNonAEAD(config, plaintext);
    }


    public static byte[] decrypt(CryptoConfig config, byte[] data) throws Exception {
        return config.isAEAD()
                ? decryptAEAD(config, data)
                : decryptNonAEAD(config, data);
    }



    private static byte[] encryptAEAD(CryptoConfig config, byte[] plaintext) throws Exception {
        byte[] nonce = new byte[12];          // 12byte nonce for GCM and Poly1305
        RNG.nextBytes(nonce);

        Cipher cipher = Cipher.getInstance(config.ciphersuite);
        SecretKeySpec keySpec = new SecretKeySpec(config.key, config.getKeyAlgorithm());

        if (config.ciphersuite.toUpperCase().contains("GCM")) {
            // AES/GCM/NoPadding – 128bit authentication tag
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new GCMParameterSpec(128, nonce));
        } else {
            // ChaCha20-Poly1305 – Iv with 12byte nonce
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(nonce));
        }

        byte[] ciphertext = cipher.doFinal(plaintext);   // includes 16byte auth tag

        //  nonce(12) ‖ ciphertext+tag
        byte[] out = new byte[12 + ciphertext.length];
        System.arraycopy(nonce,      0, out,  0,  12);
        System.arraycopy(ciphertext, 0, out, 12, ciphertext.length);
        return out;
    }

    private static byte[] decryptAEAD(CryptoConfig config, byte[] data) throws Exception {
        if (data.length < 12 + 16)  // nonce + min authtag
            throw new IllegalArgumentException("AEAD payload too short: " + data.length);

        byte[] nonce      = Arrays.copyOfRange(data,  0, 12);
        byte[] ciphertext = Arrays.copyOfRange(data, 12, data.length);

        Cipher cipher = Cipher.getInstance(config.ciphersuite);
        SecretKeySpec keySpec = new SecretKeySpec(config.key, config.getKeyAlgorithm());

        if (config.ciphersuite.toUpperCase().contains("GCM")) {
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new GCMParameterSpec(128, nonce));
        } else {
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(nonce));
        }

        // AEADBadTagException thrown automatically on tag mismatch
        return cipher.doFinal(ciphertext);
    }


    private static byte[] encryptNonAEAD(CryptoConfig config, byte[] plaintext) throws Exception {
        byte[] iv = new byte[16];           // 16byte IV for CTR and CBC
        RNG.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(config.ciphersuite);
        SecretKeySpec keySpec = new SecretKeySpec(config.key, config.getKeyAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
        byte[] ciphertext = cipher.doFinal(plaintext);

        if (config.hmacAlgorithm != null && config.macKey != null) {
            // HMAC over (iv ‖ ciphertext)
            byte[] hmac = computeHMAC(config, iv, ciphertext);

            // iv(16) ‖ ciphertext ‖ hmac(32)
            byte[] out = new byte[16 + ciphertext.length + hmac.length];
            System.arraycopy(iv,         0, out,                         0,  16);
            System.arraycopy(ciphertext, 0, out,                        16,  ciphertext.length);
            System.arraycopy(hmac,       0, out, 16 + ciphertext.length,     hmac.length);
            return out;
        } else {
            // No integrity (confidentiality only)
            throw new SecurityException(
                    "Non-AEAD cipher '" + config.ciphersuite + "' requires hmac and mackey " +
                            "in cryptoconfig.conf.");
        }
    }

    private static byte[] decryptNonAEAD(CryptoConfig config, byte[] data) throws Exception {
        if (config.hmacAlgorithm == null || config.macKey == null) {
            throw new SecurityException(
                    "Non-AEAD cipher '" + config.ciphersuite + "' requires hmac and mackey " +
                            "in cryptoconfig.conf. Confidentiality-only is not permitted.");
        }
        int hmacLen = config.getHMACSize();

        if (data.length < 16 + hmacLen)
            throw new IllegalArgumentException("Non-AEAD payload too short: " + data.length);

        byte[] iv         = Arrays.copyOfRange(data,  0, 16);
        byte[] ciphertext = Arrays.copyOfRange(data, 16, data.length - hmacLen);


        // Verify HMAC before decrypting
        byte[] receivedHmac = Arrays.copyOfRange(data, data.length - hmacLen, data.length);
        byte[] expectedHmac = computeHMAC(config, iv, ciphertext);

        if (!MessageDigest.isEqual(expectedHmac, receivedHmac)) {
            throw new SecurityException(
                    "HMAC verification failed! Packet may have been tampered with.");
        }


        Cipher cipher = Cipher.getInstance(config.ciphersuite);
        SecretKeySpec keySpec = new SecretKeySpec(config.key, config.getKeyAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
        return cipher.doFinal(ciphertext);
    }

    private static byte[] computeHMAC(CryptoConfig config, byte[] iv, byte[] ciphertext)
            throws Exception {
        Mac mac = Mac.getInstance(config.hmacAlgorithm);
        mac.init(new SecretKeySpec(config.macKey, config.hmacAlgorithm));
        mac.update(iv);
        mac.update(ciphertext);
        return mac.doFinal();
    }
}