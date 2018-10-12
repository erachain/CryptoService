package tx;

import com.google.common.primitives.Bytes;
import com.google.common.primitives.Ints;
import com.google.common.primitives.Longs;
import crypto.Base58;
import crypto.Crypto;
import org.glassfish.jersey.message.internal.OutboundJaxrsResponse;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import utils.Pair;
import webserver.ApiCrypto;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;


public class SendTX {

    private static final int KEY_LENGTH = 8;
    private static final int AMOUNT_LENGTH = 8;
    private static final int REFERENCE_LENGTH = 8;
    private static final int AMOUNT_DEFAULT_SCALE = 8;
    private static final int TIMESTAMP_LENGTH = 8;
    private static final int IS_TEXT_LENGTH = 1;
    private static final int DATA_SIZE_LENGTH = 4;
    private static final int ENCRYPTED_LENGTH = 1;
    private static final int TYPE_LENGTH = 4;
    private static final int HASH_LENGTH = 32;
    private static final int SIGNATURE_LENGTH = 64;
    private static final int SCALE_MASK = 31;
    private static final int SCALE_MASK_HALF = (SCALE_MASK + 1) >> 1;
    private byte[] encrypted;
    private byte[] isText;
    private byte[] creator;
    private byte[] recipient;
    private byte[] type;
    private byte[] signature;
    private String head;
    private String data;
    private BigDecimal amount;
    private long timestamp;
    private long reference;
    private long key;
    private byte feePow;
    private int port;
    private byte[] privateKeyCreator;
    private byte[] publicKeyRecipient;

    public SendTX() {
    }
    public SendTX(byte[] data) {
        this.parseTX(data);
    }

    public SendTX(String creator, String privateKeyString, String recipient, String publicKeyRecipient, String head, String data, BigDecimal amount, long timestamp,
                  long key, byte feePow, byte encrypt) {
        byte[] type = new byte[4];
        type[0] = (byte) 31;
        type[1] = (byte) 0;
        if (amount.compareTo(new BigDecimal(0)) > 0) {
            type[2] = (byte) 0;
        } else {
            type[2] = (byte) -127;
        }
        if (head != null || data != null) {
            type[3] = (byte) 0;
        } else {
            type[3] = (byte) -127;
        }
        this.port = 9066;
        this.setTX(encrypt, (byte) 1, creator, privateKeyString, recipient, publicKeyRecipient, type, head, data, amount, timestamp, key, feePow);
    }

    private void setTX(byte encrypted, byte isText, String creator, String privateKeyString, String recipient, String publicKeyRecipient, byte[] type, String head,
                       String data, BigDecimal amount, long timestamp, long key, byte feePow) {

        this.publicKeyRecipient = Base58.decode(publicKeyRecipient);
        this.privateKeyCreator = Base58.decode(privateKeyString);
        this.type = type;
        this.timestamp = timestamp;
        this.reference = (long) 0;
        this.creator = Base58.decode(creator);
        this.feePow = feePow;
        this.recipient = Base58.decode(recipient);
        this.key = key;
        this.amount = amount;
        this.head = head;
        this.data = data;
        this.encrypted = new byte[]{encrypted};
        this.isText = new byte[]{isText};
    }

    private void parseTX(byte[] data) {

        // READ TYPE
        this.type = Arrays.copyOfRange(data, 0, TYPE_LENGTH);
        int position = TYPE_LENGTH;

        // READ TIMESTAMP
        byte[] timestampBytes = Arrays.copyOfRange(data, position, position + TIMESTAMP_LENGTH);
        timestampBytes = Bytes.ensureCapacity(timestampBytes, TIMESTAMP_LENGTH, 0);
        this.timestamp = Longs.fromByteArray(timestampBytes);
        position += TIMESTAMP_LENGTH;

        // READ REFERENCE
        byte[] referenceBytes = Arrays.copyOfRange(data, position, position + REFERENCE_LENGTH);
        referenceBytes = Bytes.ensureCapacity(referenceBytes, TIMESTAMP_LENGTH, 0);
        this.reference = Longs.fromByteArray(referenceBytes);
        position += TIMESTAMP_LENGTH;

        // READ CREATOR
        this.creator = Arrays.copyOfRange(data, position, position + HASH_LENGTH);
        position += HASH_LENGTH;

        // READ FEE POWER
        byte[] feePowBytes = Arrays.copyOfRange(data, position, position + 1);
        this.feePow = feePowBytes[0];
        position += 1;

        // READ SIGNATURE
        this.signature = Arrays.copyOfRange(data, position, position + SIGNATURE_LENGTH);
        position += SIGNATURE_LENGTH;

        // READ RECIPIENT
        this.recipient = Arrays.copyOfRange(data, position, position + 25);
        position += 25;

        long key = 0;
        BigDecimal amount = null;
        if (this.type[2] >= 0) {
            // IF here is AMOUNT

            // READ KEY
            byte[] keyBytes = Arrays.copyOfRange(data, position, position + KEY_LENGTH);
            key = Longs.fromByteArray(keyBytes);
            position += KEY_LENGTH;

            // READ AMOUNT
            byte[] amountBytes = Arrays.copyOfRange(data, position, position + AMOUNT_LENGTH);
            amount = new BigDecimal(new BigInteger(amountBytes), AMOUNT_DEFAULT_SCALE);
            position += AMOUNT_LENGTH;


            // CHECK ACCURACY of AMOUNT
            if (this.type[3] != -1) {
                // not use old FLAG from vers 2
                int accuracy = this.type[3] & SCALE_MASK;
                if (accuracy > 0) {
                    if (accuracy >= SCALE_MASK_HALF) {
                        accuracy -= SCALE_MASK + 1;
                    }

                    // RESCALE AMOUNT
                    amount = amount.scaleByPowerOfTen(-accuracy);
                }
            }

        }

        // HEAD LEN
        int headLen = Byte.toUnsignedInt(data[position]);
        position++;

        // HEAD
        byte[] headBytes = Arrays.copyOfRange(data, position, position + headLen);
        this.head = new String(headBytes, StandardCharsets.UTF_8);
        position += headLen;

        // DATA +++
        if (this.type[3] >= 0) {
            // IF here is DATA
            // READ DATA SIZE
            byte[] dataSizeBytes = Arrays.copyOfRange(data, position, position + DATA_SIZE_LENGTH);
            int dataSize = Ints.fromByteArray(dataSizeBytes);
            position += DATA_SIZE_LENGTH;

            // READ DATA
            byte[] dataBytes = Arrays.copyOfRange(data, position, position + dataSize);
            if (Arrays.equals(this.encrypted, new byte[]{0}))
                this.data = new String(dataBytes, StandardCharsets.UTF_8);
            else
                this.data = Base58.encode(dataBytes);
            position += dataSize;

            // READ ENCRYPTED FLAG
            this.encrypted = Arrays.copyOfRange(data, position, position + ENCRYPTED_LENGTH);
            position += ENCRYPTED_LENGTH;

            this.isText = Arrays.copyOfRange(data, position, position + IS_TEXT_LENGTH);
            //   position += IS_TEXT_LENGTH;
        }
    }

    public byte[] toBytes(boolean withSign) throws Exception {

        byte[] data = new byte[0];

        // WRITE TYPE
        data = Bytes.concat(data, this.type);

        // WRITE TIMESTAMP
        byte[] timestampBytes = Longs.toByteArray(this.timestamp);
        timestampBytes = Bytes.ensureCapacity(timestampBytes, TIMESTAMP_LENGTH, 0);
        data = Bytes.concat(data, timestampBytes);

        // refrence field is unused
        byte[] referenceBytes = Longs.toByteArray(this.reference);
        referenceBytes = Bytes.ensureCapacity(referenceBytes, TIMESTAMP_LENGTH, 0);
        data = Bytes.concat(data, referenceBytes);

        // WRITE CREATOR
        data = Bytes.concat(data, this.creator);

        // WRITE FEE POWER
        byte[] feePowBytes = new byte[1];
        feePowBytes[0] = this.feePow;
        data = Bytes.concat(data, feePowBytes);

        // SIGNATURE
        if (withSign)
            data = Bytes.concat(data, this.signature);

        // WRITE RECIPIENT
        data = Bytes.concat(data, this.recipient);

        if (!this.amount.equals(BigDecimal.ZERO)) {

            // WRITE KEY
            byte[] keyBytes = Longs.toByteArray(key);
            keyBytes = Bytes.ensureCapacity(keyBytes, KEY_LENGTH, 0);
            data = Bytes.concat(data, keyBytes);

            // CALCULATE ACCURACY of AMOUNT
            int different_scale = this.amount.scale() - AMOUNT_DEFAULT_SCALE;
            BigDecimal amountBase;
            if (different_scale != 0) {
                // RESCALE AMOUNT
                amountBase = this.amount.scaleByPowerOfTen(different_scale);
                if (different_scale < 0)
                    different_scale += SCALE_MASK + 1;

                // WRITE ACCURACY of AMOUNT
                data[3] = (byte) (data[3] | different_scale);
            } else {
                amountBase = this.amount;
            }

            //WRITE AMOUNT
            byte[] amountBytes = Longs.toByteArray(amountBase.unscaledValue().longValue());
            amountBytes = Bytes.ensureCapacity(amountBytes, AMOUNT_LENGTH, 0);

            //byte[] amountBytes = this.amount.unscaledValue().toByteArray();
            //byte[] fill = new byte[AMOUNT_LENGTH - amountBytes.length];
            //amountBytes = Bytes.concat(fill, amountBytes);
            data = Bytes.concat(data, amountBytes);
        }

        // WRITE HEAD
        byte[] headBytes = this.head.getBytes(StandardCharsets.UTF_8);
        // HEAD SIZE
        data = Bytes.concat(data, new byte[]{(byte) headBytes.length});
        // HEAD
        data = Bytes.concat(data, headBytes);

        if (this.data != null) {
            // WRITE DATA SIZE

            byte[] dataBytes = this.data.getBytes(Charset.forName("UTF-8"));

            byte[] dataByte;

            if (Arrays.equals(this.encrypted, new byte[]{1})) {
                Object result = new ApiCrypto().encrypt("{\"message\":" + this.data + ", " +
                        "\"publicKey\":\"" + Base58.encode(publicKeyRecipient) + "\"," +
                        "\"privateKey\":\"" + Base58.encode(privateKeyCreator) + "\"}");
                Object encrypt = ((OutboundJaxrsResponse) result).getEntity();
                JSONParser jsonParser = new JSONParser();
                JSONObject jsonObject = (JSONObject) jsonParser.parse(encrypt.toString());
                dataByte = Base58.decode(jsonObject.get("encrypted").toString());

            } else
                dataByte = dataBytes;



            byte[] dataSizeBytes = Ints.toByteArray(dataByte.length);
            data = Bytes.concat(data, dataSizeBytes);

            // WRITE DATA
            data = Bytes.concat(data, dataByte);

            // WRITE ENCRYPTED
            data = Bytes.concat(data, this.encrypted);

            // WRITE ISTEXT
            data = Bytes.concat(data, this.isText);
        }

        // PORT
        if (!withSign)
            data = Bytes.concat(data, Ints.toByteArray(this.port));

        return data;
    }

    public void sign(Pair<byte[], byte[]> keysPir) throws Exception {
        this.signature = Crypto.getInstance().sign(keysPir, this.toBytes(false));
    }
}
