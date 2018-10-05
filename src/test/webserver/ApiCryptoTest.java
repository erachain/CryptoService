package webserver;

import com.google.common.primitives.Bytes;
import com.google.common.primitives.Ints;
import crypto.Base58;
import crypto.Crypto;
import crypto.Ed25519;
import org.glassfish.jersey.message.internal.OutboundJaxrsResponse;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import tx.SendTX;
import utils.Pair;

import java.math.BigDecimal;
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

    /**
     * Test generation byte code. Custom settings creator recipient.
     *
     * @throws Exception
     */
    @Test
    public void GeneratyByteCode() throws Exception {
        // FROM:
        String creator = "7FAxosYza2B4X9GcbxGWgKW8QXUZKQystx";
        String privateKeyCreator = "5BMJVxNYHUBWkZKrcbL4stq2i975auVqmhpUmmu4d3vR15dvF7BMkzz1sDidRqTKsrCeiNFCPA9uss6P3TxqszMY";
        String publicKeyCreator = "AQyCxEXLewJvqzLegTW41xF3qjnTCr7tVvT6639WJsKb";
        // TO: seed: "FwLWGTTDEjTmJPQqrWwAWoi8dT5zwrmZiRkLUoQVkzRy"
        String recipient = "7Dpv5Gi8HjCBgtDN1P1niuPJQCBQ5H8Zob";
        String publicKeyRecipient = "2M9WSqXrpmRzaQkxjcWKnrABabbwqjPbJktBDbPswgL7";

        byte[] publicKeyCreatorByte = Base58.decode(publicKeyCreator);
        byte[] privateKeyCreatorByte = Base58.decode(privateKeyCreator);
        long timestamp = ntp.NTP.getTime();

        String title = "9029700190";
        byte encrypt = 1;

        // --- SET MESSAGE VALUES
        long orderDate = System.currentTimeMillis();
        String orderNumber = "ORDER #13";
        String orderUser = title;
        double orderAmount = 1.30;
        long orderAssetKey = 643L;
        String orderTitle = "COINS STORE INVOICE";
        String orderDetails = "Набор монет из драгоценных металлов";
        String orderDescription = "Оплата интернет заказа. НДС не облагается.";
        Integer expire = 35;

        JSONObject jsonObj = new JSONObject();
        jsonObj.put("date", orderDate);
        jsonObj.put("order", orderNumber);
        jsonObj.put("user", orderUser);
        jsonObj.put("curr", orderAssetKey);
        jsonObj.put("sum", orderAmount);
        jsonObj.put("title", orderTitle);
        jsonObj.put("details", orderDetails);
        jsonObj.put("description", orderDescription);
        jsonObj.put("expire", expire);

        String message = jsonObj.toJSONString();
        System.out.println(message);

        SendTX tx = new SendTX(publicKeyCreator, privateKeyCreator, recipient, publicKeyRecipient, title, message,
                BigDecimal.ZERO,
                //BigDecimal.valueOf(orderAmount),
                timestamp, orderAssetKey, (byte)0, encrypt);

        tx.sign(new Pair<>(privateKeyCreatorByte, publicKeyCreatorByte));
        System.out.println("Bytecode to send:\n" + Base58.encode(tx.toBytes(true)));
    }
}