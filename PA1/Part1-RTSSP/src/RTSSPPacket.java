
public class RTSSPPacket {

    // ──
    //Content types
    public static final byte TYPE_CONTROL = 0x16;
    public static final byte TYPE_DATA    = 0x17;

    // Protocol version
    public static final byte VERSION_MAJOR = 0x01;
    public static final byte VERSION_MINOR = 0x00;

    // Control message subtypes
    public static final byte CTRL_REQUEST_MOVIE   = 0x01;
    public static final byte CTRL_RESPONSE_OK     = 0x02;
    public static final byte CTRL_RESPONSE_ERROR  = 0x03;
    public static final byte CTRL_START_MOVIE     = 0x04;
    public static final byte CTRL_FINISH          = 0x05;

    // Header size
    public static final int HEADER_SIZE = 5;

   //Packet contruction
    // UDP payload:  [type | ver_maj | ver_min | lenHi | lenLo | payload...]

    public static byte[] buildPacket(byte type, byte[] payload) {
        byte[] packet = new byte[HEADER_SIZE + payload.length];
        packet[0] = type;
        packet[1] = VERSION_MAJOR;
        packet[2] = VERSION_MINOR;
        packet[3] = (byte) ((payload.length >> 8) & 0xFF);
        packet[4] = (byte)  (payload.length       & 0xFF);
        System.arraycopy(payload, 0, packet, HEADER_SIZE, payload.length);
        return packet;
    }

    // Read content type from a raw packet byte array
    public static byte getType(byte[] packet) {
        return packet[0];
    }

    //Extract the payload bytes from a raw packet
    public static byte[] getPayload(byte[] packet, int packetLen) {
        int payloadLen = ((packet[3] & 0xFF) << 8) | (packet[4] & 0xFF);
        payloadLen = Math.min(payloadLen, packetLen - HEADER_SIZE); // safety
        byte[] payload = new byte[payloadLen];
        System.arraycopy(packet, HEADER_SIZE, payload, 0, payloadLen);
        return payload;
    }


    // Control message helpers

    //Build a control payload: [subtype byte | UTF-8 params...]
    public static byte[] buildControlPayload(byte subtype, String params) {
        byte[] paramBytes = (params != null && !params.isEmpty())
                ? params.getBytes(java.nio.charset.StandardCharsets.UTF_8)
                : new byte[0];
        byte[] payload = new byte[1 + paramBytes.length];
        payload[0] = subtype;
        System.arraycopy(paramBytes, 0, payload, 1, paramBytes.length);
        return payload;
    }

    //First byte of a control payload is the subtype
    public static byte getControlSubtype(byte[] payload) {
        return payload[0];
    }

    //Remaining bytes of a CONTROL payload decoded as UTF-8 string
    public static String getControlParams(byte[] payload) {
        if (payload.length <= 1) return "";
        return new String(payload, 1, payload.length - 1,
                          java.nio.charset.StandardCharsets.UTF_8);
    }


    public static String subtypeName(byte subtype) {
        switch (subtype) {
            case CTRL_REQUEST_MOVIE:  return "REQUEST_MOVIE";
            case CTRL_RESPONSE_OK:    return "RESPONSE_OK";
            case CTRL_RESPONSE_ERROR: return "RESPONSE_ERROR";
            case CTRL_START_MOVIE:    return "START_MOVIE";
            case CTRL_FINISH:         return "FINISH";
            default:                  return "UNKNOWN(0x" + Integer.toHexString(subtype & 0xFF) + ")";
        }
    }
}
