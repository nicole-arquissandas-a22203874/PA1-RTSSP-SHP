import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Enumeration;
import javax.crypto.*;
import javax.crypto.spec.*;

public class SHPHandshakeUtils {

    //  EC parameters
    private static final String EC_CURVE    = "secp256r1";
    private static final String ECDH_ALG    = "ECDH";
    private static final String ECDSA_ALG   = "SHA256withECDSA";
    private static final String KDF_HMAC    = "HmacSHA256";


     //KEY GENERATION

     //Generate a fresh ephemeral ECDH key pair on secp256r1.
     //Called once per session for forward secrecy.

    public static KeyPair generateEphemeralKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec(EC_CURVE), new SecureRandom());
        return kpg.generateKeyPair();
    }


     // Reconstruct an EC PublicKey from its encoded bytes.
    public static PublicKey decodePublicKey(byte[] encoded) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("EC");
        return kf.generatePublic(new X509EncodedKeySpec(encoded));
    }

    //KEY AGREEMENT ECDH

    //Perform ECDH with own ephemeral private key and peers ephemeral public key.
    //Returns the raw shared secret bytes (32 bytes for secp256r1).
    public static byte[] ecdhSharedSecret(PrivateKey myPrivKey, PublicKey peerPubKey)
            throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance(ECDH_ALG);
        ka.init(myPrivKey);
        ka.doPhase(peerPubKey, true);
        return ka.generateSecret();
    }


  //KEY DERIVATION
    public static CryptoConfig deriveSessionConfig(byte[] sharedSecret,
                                                   byte[] clientNonce,
                                                   byte[] serverNonce,
                                                   String ciphersuite) throws Exception {

        byte[] salt = concat(clientNonce, serverNonce);
        byte[] prk  = hmacSHA256(salt, sharedSecret);


        byte[] encKey = expandKey(prk, "RTSSP-ENC-KEY", 1, 32);
        byte[] macKey = expandKey(prk, "RTSSP-MAC-KEY", 2, 32);

        CryptoConfig cfg = new CryptoConfig();
        cfg.ciphersuite = ciphersuite;
        cfg.key         = encKey;

        if (!cfg.isAEAD()) {
            // Separate MAC needed for CTR / CBC modes
            cfg.hmacAlgorithm = "HmacSHA256";
            cfg.macKey        = macKey;
        }
        return cfg;
    }


    // ECDSA SIGNING/VERIFICATION

    // Sign data with a private key
    public static byte[] sign(PrivateKey privKey, byte[] data) throws Exception {
        Signature sig = Signature.getInstance(ECDSA_ALG);
        sig.initSign(privKey);
        sig.update(data);
        return sig.sign();
    }

    // Verify signature. Returns true if valid
    public static boolean verify(PublicKey pubKey, byte[] data, byte[] signature)
            throws Exception {
        Signature sig = Signature.getInstance(ECDSA_ALG);
        sig.initVerify(pubKey);
        sig.update(data);
        return sig.verify(signature);
    }


     //Sign the peers nonce (challengeresponse).
     //This proves possession of the private key AND ties the response to this session.
    public static byte[] signNonce(PrivateKey privKey, byte[] peerNonce) throws Exception {
        return sign(privKey, peerNonce);
    }


     // Verify the challengeresponse -did the peer sign our nonce with their private key
    public static boolean verifyNonceResponse(PublicKey peerPubKey,
                                               byte[] ourNonce,
                                               byte[] nonceResponse) throws Exception {
        return verify(peerPubKey, ourNonce, nonceResponse);
    }

    // KEYSTORE/TRUSTSTORE HELPERS

    public static KeyStore loadKeyStore(String path, String password) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(path)) {
            ks.load(fis, password.toCharArray());
        }
        return ks;
    }

   //get the first private key found in a KeyStore
    public static PrivateKey getPrivateKey(KeyStore ks, String alias, String password)
            throws Exception {
        return (PrivateKey) ks.getKey(alias, password.toCharArray());
    }

    //get  bytes of the first certificate in a KeyStore
    public static byte[] getCertBytes(KeyStore ks, String alias) throws Exception {
        Certificate cert = ks.getCertificate(alias);
        return cert.getEncoded();                // der format
    }

    //Reconstruct a Certificate from DER bytes
    public static Certificate decodeCertificate(byte[] derBytes) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return cf.generateCertificate(new java.io.ByteArrayInputStream(derBytes));
    }


     //Verify that a given certificate is trusted by the provided truststore.
     //This checks whether the truststore contains an exact copy of the certificate
    public static boolean isCertificateTrusted(KeyStore truststore, Certificate cert)
            throws Exception {
        return truststore.getCertificateAlias(cert) != null;
    }



    public static byte[] generateNonce() {
        byte[] nonce = new byte[32];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }


    // Private HKDF helpers
    private static byte[] expandKey(byte[] prk, String info, int counter, int len)
            throws Exception {
        byte[] infoBytes = info.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] input = new byte[infoBytes.length + 1];
        System.arraycopy(infoBytes, 0, input, 0, infoBytes.length);
        input[infoBytes.length] = (byte) counter;
        byte[] full = hmacSHA256(prk, input);
        return Arrays.copyOf(full, Math.min(len, full.length));
    }

    private static byte[] hmacSHA256(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance(KDF_HMAC);
        mac.init(new SecretKeySpec(key, KDF_HMAC));
        return mac.doFinal(data);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0,        a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
