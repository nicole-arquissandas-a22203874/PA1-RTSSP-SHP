import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class SHPMessage {

    // Message type constants
    public static final byte TYPE_CLIENT_HELLO = 0x01;
    public static final byte TYPE_SERVER_HELLO = 0x02;
    public static final byte TYPE_CSSP         = 0x03;   // change cipher suite + start Protocol

    // Parsed fields common to CLIENT_HELLO and SERVER_HELLO
    public byte   type;
    public String movieName;
    public byte[] ecdhPublicKey;
    public byte[] certificate;
    public String ciphersuites;       // comma separated list (CLIENT_HELLO) or single (SERVER_HELLO)
    public byte[] nonce;              // 32 random bytes
    public byte[] nonceResponse;      // signature of the peers nonce (SERVER_HELLO / CSSP)
    public byte[] signature;          // signature over everything else in the body
    public byte[] encryptedPayload;   // used in CSSP (encrypted with derived keys)

    public byte[] bodyBytes;   // the signed portion, saved for signature verification
    // Serialization

     // Body (signed): movieName | ecdhPublicKey | certificate | ciphersuites | nonce
     // Full message: type | bodyLen | body | signatureLen | signature

    public static byte[] buildClientHello(String movieName, byte[] ecdhPubKey,
                                          byte[] certBytes, String ciphersuites,
                                          byte[] nonce, byte[] signature) throws IOException {
        ByteArrayOutputStream bodyBuf = new ByteArrayOutputStream();
        DataOutputStream      body    = new DataOutputStream(bodyBuf);
        writeString(body, movieName);
        writeBytes (body, ecdhPubKey);
        writeBytes (body, certBytes);
        writeString(body, ciphersuites);
        writeBytes (body, nonce);
        byte[] bodyBytes = bodyBuf.toByteArray();

        return buildMessage(TYPE_CLIENT_HELLO, bodyBytes, signature);
    }


     //Body (signed): movieName | ecdhPublicKey | certificate | selectedCiphersuite | nonce | nonceResponse

    public static byte[] buildServerHello(String movieName, byte[] ecdhPubKey,
                                          byte[] certBytes, String selectedCiphersuite,
                                          byte[] nonce, byte[] nonceResponse,
                                          byte[] signature) throws IOException {
        ByteArrayOutputStream bodyBuf = new ByteArrayOutputStream();
        DataOutputStream      body    = new DataOutputStream(bodyBuf);
        writeString(body, movieName);
        writeBytes (body, ecdhPubKey);
        writeBytes (body, certBytes);
        writeString(body, selectedCiphersuite);
        writeBytes (body, nonce);
        writeBytes (body, nonceResponse);
        byte[] bodyBytes = bodyBuf.toByteArray();

        return buildMessage(TYPE_SERVER_HELLO, bodyBytes, signature);
    }


     //  CSSP (Change Cipher Suite and Start Protocol).
     // Sent encrypted; payload is: nonceResponse | "READY"
     //The whole encrypted blob is wrapped in a CSSP message.

    public static byte[] buildCSSP(byte[] encryptedPayload) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        DataOutputStream      dos = new DataOutputStream(buf);
        dos.writeByte(TYPE_CSSP);
        dos.writeInt(encryptedPayload.length);
        dos.write(encryptedPayload);
        return buf.toByteArray();
    }


    // Deserialization


    public static SHPMessage parse(byte[] raw) throws IOException {
        SHPMessage msg = new SHPMessage();
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(raw));
        msg.type = dis.readByte();

        int bodyLen = dis.readInt();
        byte[] body = new byte[bodyLen];
        dis.readFully(body);
        msg.bodyBytes = body;

        if (msg.type == TYPE_CSSP) {
            msg.encryptedPayload = body;
            return msg;
        }

        // Parse body fields
        DataInputStream bdis = new DataInputStream(new ByteArrayInputStream(body));
        msg.movieName   = readString(bdis);
        msg.ecdhPublicKey = readBytes(bdis);
        msg.certificate   = readBytes(bdis);
        msg.ciphersuites  = readString(bdis);
        msg.nonce         = readBytes(bdis);
        if (msg.type == TYPE_SERVER_HELLO) {
            msg.nonceResponse = readBytes(bdis);
        }

        // Signature follows the body in the outer message
        msg.signature = readBytes(new DataInputStream(dis));
        return msg;
    }


    // CSSP payload helpers (pre encryption/post decryption)

    // Build the plaintext CSSP payload: nonceResponse | "READY"
    public static byte[] buildCSSPPlaintext(byte[] nonceResponse) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(buf);
        writeBytes (dos, nonceResponse);
        writeString(dos, "READY");
        return buf.toByteArray();
    }

    //Parse decrypted CSSP payload. Returns {nonceResponse, readyString}
    public static byte[][] parseCSSPPlaintext(byte[] plain) throws IOException {
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(plain));
        byte[] nonceResp  = readBytes(dis);
        String readyStr   = readString(dis);
        return new byte[][] { nonceResp, readyStr.getBytes(StandardCharsets.UTF_8) };
    }


    // Internal helpers

    private static byte[] buildMessage(byte type, byte[] body, byte[] signature)
            throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        DataOutputStream      dos = new DataOutputStream(buf);
        dos.writeByte(type);
        dos.writeInt(body.length);
        dos.write(body);
        writeBytes(dos, signature);
        return buf.toByteArray();
    }

    static void writeString(DataOutputStream dos, String s) throws IOException {
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        dos.writeInt(b.length);
        dos.write(b);
    }

    static void writeBytes(DataOutputStream dos, byte[] data) throws IOException {
        dos.writeInt(data.length);
        dos.write(data);
    }

    static String readString(DataInputStream dis) throws IOException {
        int len = dis.readInt();
        byte[] b = new byte[len];
        dis.readFully(b);
        return new String(b, StandardCharsets.UTF_8);
    }

    static byte[] readBytes(DataInputStream dis) throws IOException {
        int len = dis.readInt();
        byte[] b = new byte[len];
        dis.readFully(b);
        return b;
    }
}
