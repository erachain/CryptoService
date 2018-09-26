package webserver;

import com.google.common.primitives.Bytes;
import com.google.common.primitives.Ints;
import com.google.common.primitives.Longs;
import crypto.Base58;
import crypto.Crypto;
import crypto.Ed25519;
import org.glassfish.jersey.message.internal.OutboundJaxrsResponse;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import tx.SendTX;
import utils.Pair;
import webserver.ApiCrypto;
import webserver.SetSettingFile;

import java.io.IOException;
import java.math.BigDecimal;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Random;

import static org.junit.Assert.*;

public class ApiCryptoTest extends SetSettingFile {

    private static final String MESSAGE = "Test message for check encrypt/decrypt";
    private static final String SEED_RECIPIENT = "8HsDxvcaRfi13CMYPoEBTCKo7C8FSSyq1mBsEBAJTtEV";
    private static final String SEED_CREATOR = "8HsDxvcaRfi13CMYPoEBTCKo7C8FSSyq1mBsEBAJTtEV";
    private static String SEED_ACCOUNT1;
    private static String SEED_ACCOUNT2;
    private static String Account1_privateKey;
    private static String Account1_publicKey;
    private static String Account2_privateKey;
    private static String Account2_publicKey;
    private String MESSAGE_ENCRYPT;
    private String SIGN;

    /**
     * Before init test generate two seed and key Pair for each seed
     */
    @Before
    public void initSeed() throws ParseException {

        byte[] seedAccount1 = new byte[32];
        new Random().nextBytes(seedAccount1);
        SEED_ACCOUNT1 = Base58.encode(seedAccount1);

        byte[] seedAccount2 = new byte[32];
        new Random().nextBytes(seedAccount2);
        SEED_ACCOUNT2 = Base58.encode(seedAccount2);

        Object result = new ApiCrypto().GenerateKeyPair(SEED_ACCOUNT1);
        Object keysObject = ((OutboundJaxrsResponse) result).getEntity();
        JSONParser jsonParser = new JSONParser();
        JSONObject jsonObject = (JSONObject) jsonParser.parse(keysObject.toString());

        Account1_privateKey = jsonObject.get("privateKey").toString();
        Account1_publicKey = jsonObject.get("publicKey").toString();

        Object result2 = new ApiCrypto().GenerateKeyPair(SEED_ACCOUNT2);
        Object keysObject2 = ((OutboundJaxrsResponse) result2).getEntity();
        JSONParser jsonParser2 = new JSONParser();
        JSONObject jsonObject2 = (JSONObject) jsonParser2.parse(keysObject2.toString());

        Account2_privateKey = jsonObject2.get("privateKey").toString();
        Account2_publicKey = jsonObject2.get("publicKey").toString();
        try {
            new SetSettingFile().SettingFile();
        } catch (Exception e) {
        }
    }

    @Test
    public void generateSeed() throws Exception {
        Object result = new ApiCrypto().GenerateSeed();
        Object seed = ((OutboundJaxrsResponse) result).getEntity();
        JSONParser jsonParser = new JSONParser();
        JSONObject jsonObject = (JSONObject) jsonParser.parse(seed.toString());
        Assert.assertTrue(jsonObject.keySet().contains("seed"));
    }

    @Test
    public void generateKeyPair() throws ParseException {
        Object result = new ApiCrypto().GenerateKeyPair(SEED_ACCOUNT1);
        Object keysObject = ((OutboundJaxrsResponse) result).getEntity();
        JSONParser jsonParser = new JSONParser();
        JSONObject jsonObject = (JSONObject) jsonParser.parse(keysObject.toString());

        Assert.assertTrue(jsonObject.keySet().contains("privateKey"));
        Assert.assertTrue(jsonObject.keySet().contains("publicKey"));
        Assert.assertNotNull(jsonObject.get("publicKey"));
        Assert.assertNotNull(jsonObject.get("privateKey"));
    }

    @Test
    public void encrypt() throws Exception {

        Object result = new ApiCrypto().Encrypt("{\"message\":\"" + MESSAGE + "\", " +
                "\"publicKey\":\"" + Account2_publicKey + "\"," +
                "\"privateKey\":\"" + Account1_privateKey + "\"}");
        Object encrypt = ((OutboundJaxrsResponse) result).getEntity();
        JSONParser jsonParser = new JSONParser();
        JSONObject jsonObject = (JSONObject) jsonParser.parse(encrypt.toString());
        MESSAGE_ENCRYPT = jsonObject.get("encrypted").toString();

        Assert.assertNotNull(jsonObject.get("encrypted"));
    }

    @Test
    public void decrypt() throws Exception {
        if (MESSAGE_ENCRYPT == null)
            encrypt();

        Object result = new ApiCrypto().Decrypt("{\"message\": \"" + MESSAGE_ENCRYPT +
                "\",\"publicKey\":\"" + Account1_publicKey + "\",\n" +
                "\"privateKey\":\"" + Account2_privateKey + "\"}");

        Object encrypt = ((OutboundJaxrsResponse) result).getEntity();
        JSONParser jsonParser = new JSONParser();
        JSONObject jsonObject = (JSONObject) jsonParser.parse(encrypt.toString());

        if (jsonObject.get("Error") != null)
            fail("Cannot decrypt in current keys. Check public and private key.");

        Assert.assertEquals(jsonObject.get("decrypted").toString(), MESSAGE);
        Assert.assertNotNull(jsonObject.get("decrypted"));
    }

    @Test
    public void sign() throws Exception {
        Object result = new ApiCrypto().Sign("{\"publicKey\":\"" + Account1_publicKey + "\",\n" +
                "\"privateKey\":\"" + Account1_privateKey + "\"," +
                " \"message\":\"" + MESSAGE + "\"}");

        Object sign = ((OutboundJaxrsResponse) result).getEntity();
        JSONParser jsonParser = new JSONParser();
        JSONObject jsonObject = (JSONObject) jsonParser.parse(sign.toString());

        Assert.assertNotNull(jsonObject.get("signature"));
        SIGN = jsonObject.get("signature").toString();
    }

    @Test
    public void verifySignature() throws Exception {
        if (SIGN == null)
            sign();

        Object result = new ApiCrypto().VerifySignature("{\"publicKey\":\"" + Account1_publicKey + "\"," +
                "\"signature\":\"" + SIGN + "\"," +
                "\"message\":\"" + MESSAGE + "\"}");

        Object sign = ((OutboundJaxrsResponse) result).getEntity();
        JSONParser jsonParser = new JSONParser();
        JSONObject jsonObject = (JSONObject) jsonParser.parse(sign.toString());

        Assert.assertTrue(Boolean.parseBoolean(jsonObject.get("signatureVerify").toString()));

    }

    @Test
    public void sharedSecret() {
        byte[] sharedSecret1 =
                Ed25519.getSharedSecret(Base58.decode(Account2_publicKey), Base58.decode(Account1_privateKey));
        byte[] sharedSecret2 =
                Ed25519.getSharedSecret(Base58.decode(Account1_publicKey), Base58.decode(Account2_privateKey));

        Assert.assertEquals(Base58.encode(sharedSecret1), Base58.encode(sharedSecret2));
    }

    @Test
    public void generateAccount() throws Exception {

        Object result = new ApiCrypto().generateAccount("{\"seed\":\"2UiJ8Fte8bvuZSFjhdEtJ2etVvbirNRDTu8KEs9BFxch\",\"nonce\":4}");
        Object value = ((OutboundJaxrsResponse) result).getEntity();
        JSONParser jsonParser = new JSONParser();

        JSONObject jsonObject = (JSONObject) jsonParser.parse(value.toString());
        assertNotNull(jsonObject);
        assertEquals(Integer.parseInt(jsonObject.get("numAccount").toString()), 4);
        assertEquals(jsonObject.get("accountSeed"), "6MerziUEfzicW2bzTogjmP4E4tZK7wnwAvoWurktmTHj");
        assertEquals(jsonObject.get("publicKey"), "CeMcZK4P6no5YzpTbgakBH66Brf27FYybrVeDsMj2ZNd");
        assertEquals(jsonObject.get("privateKey"), "L1u9aTnn3jnrjTEdVT5kGbbNxM5GcVSmWC7pf9mu5zYGnE1RpgpZjfYvMKFqypKKmdRvSo79G2hMvSvVCKmnmvf");
        assertEquals(jsonObject.get("account"), "75aS9viw8C5rxa78AqutzLiMzwM9RS7pTk");
    }

    /**
     * In test hardcore set ip address node for sent telegram
     *
     * @throws Exception
     */
    @Test
    public void generateTelegram() throws Exception {
        JSONObject jsonObject = new JSONObject();
        ArrayList arrayListRecipient = new ArrayList();
        for (int i = 1; i < 5; i++) {
            int nonce = i;
            byte[] nonceBytes = Ints.toByteArray(Integer.valueOf(nonce) - 1);
            byte[] accountSeedConcat = Bytes.concat(nonceBytes, Base58.decode(SEED_RECIPIENT), nonceBytes);
            byte[] accountSeed = Crypto.getInstance().doubleDigest(accountSeedConcat);
            utils.Pair<byte[], byte[]> keyPair = Crypto.getInstance().createKeyPair(accountSeed);
            String address = Crypto.getInstance().getAddress(keyPair.getB());
            arrayListRecipient.add(address);
        }


        ArrayList arrayListCreator = new ArrayList();
        for (int i = 1; i < 10; i++) {
            int nonce = i;
            byte[] nonceBytes = Ints.toByteArray(Integer.valueOf(nonce) - 1);
            byte[] accountSeedConcat = Bytes.concat(nonceBytes, Base58.decode(SEED_CREATOR), nonceBytes);
            byte[] accountSeed = Crypto.getInstance().doubleDigest(accountSeedConcat);
            utils.Pair<byte[], byte[]> keyPair = Crypto.getInstance().createKeyPair(accountSeed);
            String address = Crypto.getInstance().getAddress(keyPair.getB());
            arrayListCreator.add(address);
        }
        JSONObject message = new JSONObject();

        Random random = new Random();
        for (int i = 0; i < 1; i++) {
            long date = System.currentTimeMillis();
            Object recipient = arrayListRecipient.get(random.nextInt(4));
            Object creator = arrayListCreator.get(random.nextInt(9));
            int user = random.nextInt(33465666);
            int expire = random.nextInt(1243555959);
            int randomPrice = random.nextInt(10000);

            String phone = String.valueOf(random.nextInt(999 - 100) + 100) +
                    String.valueOf(random.nextInt(999 - 100) + 100) +
                    String.valueOf(random.nextInt(9999 - 1000) + 1000);

            message.put("data", date);
            message.put("order", random.nextInt(52193287));
            message.put("user", user);
            message.put("curr", "643");
            message.put("sum", randomPrice);
            message.put("phone", phone);
            message.put("expire", expire);

            jsonObject.put("sender", creator);
            jsonObject.put("recipient", recipient);


            jsonObject.put("title", phone);
            jsonObject.put("encrypt", "false");
            jsonObject.put("password", "123456789");
            jsonObject.put("message", message);

            ResponseValueAPI("http://89.235.184.251:9068/telegrams/send", "POST", jsonObject.toJSONString());
        }
    }

    @Test
    public void Sometest2() {
        String publicKeyString = "8HsDxvcaRfi13CMYPoEBTCKo7C8FSSyq1mBsEBAJTtEV";
        byte[] publicKey = Base58.decode(publicKeyString);
        byte[] privateKey = Base58.decode("pCN9sfvm8SQqB4m8fyrU17R7j2NYm9poerkJj9uTgMQQeygALqKPRCpUQZunMaoPfWfhpbMr6GooMRR3CCbgKjr");

        SendTX tx = new SendTX(publicKeyString, "7Dpv5Gi8HjCBgtDN1P1niuPJQCBQ5H8Zob",
                "head text", "data text", BigDecimal.ZERO, System.currentTimeMillis(),0l,(byte)1);

        tx.sign(new Pair<byte[], byte[]>(privateKey, privateKey));
        System.out.println(Base58.encode(tx.toBytes(true)));
    }

    @Ignore
    @Test
    public void Sometest() throws IOException {
        byte[] transactionType = new byte[]{(byte)31, (byte)0, (byte)0, (byte)0};
        //  byte[] timestamp = Base58.decode(String.valueOf(System.currentTimeMillis()));
        byte[] timestamp = Longs.toByteArray(System.currentTimeMillis());
        byte[] reference = Longs.toByteArray(0L);
        byte[] publicKey = Base58.decode("8HsDxvcaRfi13CMYPoEBTCKo7C8FSSyq1mBsEBAJTtEV");
        byte[] privateKey = Base58.decode("pCN9sfvm8SQqB4m8fyrU17R7j2NYm9poerkJj9uTgMQQeygALqKPRCpUQZunMaoPfWfhpbMr6GooMRR3CCbgKjr");

        byte[] feepow = new byte[]{(byte) 0};
        byte[] recipient = Base58.decode("7Dpv5Gi8HjCBgtDN1P1niuPJQCBQ5H8Zob");

        byte[] assetKey = Longs.toByteArray(2L);

        String originalMessage = "{date:1537448519}";
        byte[] message = originalMessage.getBytes();

        byte[] amount = Longs.toByteArray(10L);
        byte[] title = Base58.decode("12345678");
        byte[] titleLength = new byte[]{(byte) title.length};
        byte[] messageLength = new byte[]{(byte) message.length};
        byte[] isText = new byte[]{(byte) 0};
        byte[] port = Ints.toByteArray(9066);

        byte[] resultSign;
        resultSign = Bytes.concat(transactionType, timestamp);
        resultSign = Bytes.concat(resultSign, reference);
        resultSign = Bytes.concat(resultSign, publicKey);
        resultSign = Bytes.concat(resultSign, feepow);
        resultSign = Bytes.concat(resultSign, recipient);
        resultSign = Bytes.concat(resultSign, assetKey);
        resultSign = Bytes.concat(resultSign, amount);
        resultSign = Bytes.concat(resultSign, titleLength);
        resultSign = Bytes.concat(resultSign, title);
        resultSign = Bytes.concat(resultSign, messageLength);
        resultSign = Bytes.concat(resultSign, message);
        resultSign = Bytes.concat(resultSign, new byte[]{(byte) 0}); //  0 - is not encrypt
        resultSign = Bytes.concat(resultSign, isText);
        resultSign = Bytes.concat(resultSign, port);

        Pair pair = new Pair<>();
        pair.setA(privateKey);
        pair.setB(publicKey);
        System.out.println("bytecode to sign:" + Base58.encode(resultSign));
        byte[] sign = Crypto.getInstance().sign(pair, resultSign);
        System.out.println("Sign1: " + Base58.encode(sign));

        byte[] resultToSend;
        resultToSend = Bytes.concat(transactionType, timestamp);
        resultToSend = Bytes.concat(resultToSend, reference);
        resultToSend = Bytes.concat(resultToSend, publicKey);
        resultToSend = Bytes.concat(resultToSend, feepow);
        resultToSend = Bytes.concat(resultToSend, sign);
        resultToSend = Bytes.concat(resultToSend, recipient);
        resultToSend = Bytes.concat(resultToSend, assetKey);
        resultToSend = Bytes.concat(resultToSend, amount);
        resultToSend = Bytes.concat(resultToSend, titleLength);
        resultToSend = Bytes.concat(resultToSend, title);
        resultToSend = Bytes.concat(resultToSend, messageLength);
        resultToSend = Bytes.concat(resultToSend, message);
        resultToSend = Bytes.concat(resultToSend, new byte[]{(byte)0}); //  0 - is not encrypt
        resultToSend = Bytes.concat(resultToSend, isText);

        System.out.println("Byte code to send: " + Base58.encode(resultToSend));
        byte[] sign2 = Crypto.getInstance().sign(pair, Bytes.concat(resultToSend, port));
        System.out.println("sign2: " + Base58.encode(sign2));

    }

    public byte[] longToBytes(long x) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(x);
        return buffer.array();
    }
}