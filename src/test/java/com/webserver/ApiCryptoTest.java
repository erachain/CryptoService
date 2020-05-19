package com.webserver;

import com.crypto.Base58;
import com.crypto.Crypto;
import com.crypto.Ed25519;
import com.google.common.primitives.Bytes;
import com.google.common.primitives.Ints;
import com.tx.SendTX;
import com.utils.Pair;
import com.utils.StringRandomGen;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.http.ResponseEntity;

import java.lang.reflect.Field;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Random;

import static org.junit.Assert.*;

public class ApiCryptoTest extends SetSettingFile {

    private static String MESSAGE = "Test message for check encrypt and decrypt";
    private static String SEED_RECIPIENT = "8HsDxvcaRfi13CMYPoEBTCKo7C8FSSyq1mBsEBAJTtEV";
    private static String SEED_CREATOR = "8HsDxvcaRfi13CMYPoEBTCKo7C8FSSyq1mBsEBAJTtEV";
    private static String SEED_ACCOUNT1;
    private static String SEED_ACCOUNT2;
    private static String Account1_privateKey;
    private static String Account1_publicKey;
    private static String Account2_privateKey;
    private static String Account2_publicKey;
    private String MESSAGE_ENCRYPT;
    private String SIGN;
    private Boolean status;
    /*
     * Variable for testing generate byte code
     * */
    // creator and recipient
    String seed_creator=  "ASiXB5ddkaFZ4rKNWh68bb5Cmpu1oXj6fEPJqdQ8xJX7";

    String creator = "7FAxosYza2B4X9GcbxGWgKW8QXUZKQystx";
    String privateKeyCreator = "5BMJVxNYHUBWkZKrcbL4stq2i975auVqmhpUmmu4d3vR15dvF7BMkzz1sDidRqTKsrCeiNFCPA9uss6P3TxqszMY";
    String publicKeyCreator = "AQyCxEXLewJvqzLegTW41xF3qjnTCr7tVvT6639WJsKb";
    String PublicKeyCreatorTest;

    // TO:
    String recipient = "7Dpv5Gi8HjCBgtDN1P1niuPJQCBQ5H8Zob";
    String recipientTest;

    String publicKeyRecipient = "2M9WSqXrpmRzaQkxjcWKnrABabbwqjPbJktBDbPswgL7";
    String publicKeyRecipientTest;

    String title = "9029700190";
    String titleTest;

    byte encrypt = 0;

    // SET MESSAGE VALUES
    long orderDate = System.currentTimeMillis();
    long orderDateTest;

    String orderNumber = "ORDER #13";
    String orderNumberTest;
    String orderUser = title;
    String orderUserTest;
    double orderAmount = 1.30;
    double orderAmountTest;
    long orderAssetKey = 643L;
    long orderAssetKeyTest;
    String orderTitle = "COINS STORE INVOICE";
    String orderTitleTest;
    String orderDetails = "Набор монет из драгоценных металлов";
    String orderDetailsTest;
    String orderDescription = "Оплата интернет заказа. НДС не облагается.";
    String orderDescriptionTest;
    Integer expire = 35;
    Integer expireTest;

    String byteCode;

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

        Object result = new ApiCrypto().generateKeyPair(SEED_ACCOUNT1);
        Object keysObject = ((ResponseEntity) result).getBody();
        JSONParser jsonParser = new JSONParser();
        JSONObject jsonObject = (JSONObject) jsonParser.parse(keysObject.toString());

        Account1_privateKey = jsonObject.get("privateKey").toString();
        Account1_publicKey = jsonObject.get("publicKey").toString();

        Object result2 = new ApiCrypto().generateKeyPair(SEED_ACCOUNT2);
        Object keysObject2 = ((ResponseEntity) result2).getBody();
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
        Object result = new ApiCrypto().generateSeed();
        Object seed = ((ResponseEntity) result).getBody();
        JSONParser jsonParser = new JSONParser();
        JSONObject jsonObject = (JSONObject) jsonParser.parse(seed.toString());
        Assert.assertTrue(jsonObject.keySet().contains("seed"));
    }

    @Test
    public void generateKeyPair() throws ParseException {
        Object result = new ApiCrypto().generateKeyPair(SEED_ACCOUNT1);
        Object keysObject = ((ResponseEntity) result).getBody();
        JSONParser jsonParser = new JSONParser();
        JSONObject jsonObject = (JSONObject) jsonParser.parse(keysObject.toString());

        Assert.assertTrue(jsonObject.keySet().contains("privateKey"));
        Assert.assertTrue(jsonObject.keySet().contains("publicKey"));
        Assert.assertNotNull(jsonObject.get("publicKey"));
        Assert.assertNotNull(jsonObject.get("privateKey"));
    }

    @Test
    public void encrypt() throws Exception {

        Object result = new ApiCrypto().encrypt((JSONObject) new JSONParser().parse("{\"message\":\"" + MESSAGE + "\", " +
                "\"publicKey\":\"" + Account2_publicKey + "\"," +
                "\"privateKey\":\"" + Account1_privateKey + "\"}"));
        Object encrypt = ((ResponseEntity) result).getBody();
        JSONParser jsonParser = new JSONParser();
        JSONObject jsonObject = (JSONObject) jsonParser.parse(encrypt.toString());
        MESSAGE_ENCRYPT = jsonObject.get("encrypted").toString();

        Assert.assertNotNull(jsonObject.get("encrypted"));
    }

    @Test
    public void decrypt() throws Exception {
        if (MESSAGE_ENCRYPT == null)
            encrypt();

        Object result = new ApiCrypto().decrypt((JSONObject) new JSONParser().parse("{\"message\": \"" + MESSAGE_ENCRYPT +
                "\",\"publicKey\":\"" + Account1_publicKey + "\",\n" +
                "\"privateKey\":\"" + Account2_privateKey + "\"}"));

        Object encrypt = ((ResponseEntity) result).getBody();
        JSONParser jsonParser = new JSONParser();
        JSONObject jsonObject = (JSONObject) jsonParser.parse(encrypt.toString());

        if (jsonObject.get("Error") != null)
            fail("Cannot decrypt in current keys. Check public and private key.");

        Assert.assertEquals(jsonObject.get("decrypted").toString(), MESSAGE);
        Assert.assertNotNull(jsonObject.get("decrypted"));
    }

    @Test
    public void sign() throws Exception {
        Object result = new ApiCrypto().sign((JSONObject) new JSONParser().parse("{\"publicKey\":\"" + Account1_publicKey + "\"," +
                "\"privateKey\":\"" + Account1_privateKey + "\"," +
                " \"message\":\""+ Base58.encode(MESSAGE.getBytes("UTF-8")) + "\"}"));

        Object sign = ((ResponseEntity) result).getBody();
        JSONParser jsonParser = new JSONParser();
        JSONObject jsonObject = (JSONObject) jsonParser.parse(sign.toString());

        Assert.assertNotNull(jsonObject.get("signature"));
        SIGN = jsonObject.get("signature").toString();
    }

    @Test
    public void verifySignature() throws Exception {
        if (SIGN == null)
            sign();

        initSeed();

        Object result = new ApiCrypto().verifySignature((JSONObject) new JSONParser().parse("{\"publicKey\":\"" + Account1_publicKey + "\"," +
                "\"signature\":\"" + SIGN + "\"," +
                "\"message\":\"" + MESSAGE + "\"}"));

        Object sign = ((ResponseEntity) result).getBody();
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

        Object result = new ApiCrypto().generateAccount((JSONObject) new
                JSONParser().parse("{\"seed\":\"2UiJ8Fte8bvuZSFjhdEtJ2etVvbirNRDTu8KEs9BFxch\",\"nonce\":4}"));

        Object value = ((ResponseEntity) result).getBody();
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
    @Ignore
    @Test
    public void generateTelegram() {
        JSONObject jsonObject = new JSONObject();
        ArrayList arrayListRecipient = new ArrayList();
        for (int i = 1; i < 5; i++) {
            int nonce = i;
            byte[] nonceBytes = Ints.toByteArray(Integer.valueOf(nonce) - 1);
            byte[] accountSeedConcat = Bytes.concat(nonceBytes, Base58.decode(SEED_RECIPIENT), nonceBytes);
            byte[] accountSeed = Crypto.getInstance().doubleDigest(accountSeedConcat);
            Pair<byte[], byte[]> keyPair = Crypto.getInstance().createKeyPair(accountSeed);
            String address = Crypto.getInstance().getAddress(keyPair.getB());
            arrayListRecipient.add(address);
        }


        ArrayList arrayListCreator = new ArrayList();
        for (int i = 1; i < 10; i++) {
            int nonce = i;
            byte[] nonceBytes = Ints.toByteArray(Integer.valueOf(nonce) - 1);
            byte[] accountSeedConcat = Bytes.concat(nonceBytes, Base58.decode(SEED_CREATOR), nonceBytes);
            byte[] accountSeed = Crypto.getInstance().doubleDigest(accountSeedConcat);
            Pair<byte[], byte[]> keyPair = Crypto.getInstance().createKeyPair(accountSeed);
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

            //  ResponseValueAPI("http://89.235.184.251:9068/telegrams/send", "POST", jsonObject.toJSONString());
        }
    }
    /**
     * Test generation byte code. Custom settings creator recipient.
     *
     * @throws Exception
     */
    @Test
    public void generatyByteCode() throws Exception {
        // FROM:
        String creator = "7FAxosYza2B4X9GcbxGWgKW8QXUZKQystx";
        String privateKeyCreator = "5BMJVxNYHUBWkZKrcbL4stq2i975auVqmhpUmmu4d3vR15dvF7BMkzz1sDidRqTKsrCeiNFCPA9uss6P3TxqszMY";
        String publicKeyCreator = "AQyCxEXLewJvqzLegTW41xF3qjnTCr7tVvT6639WJsKb";
        // TO: seed: "FwLWGTTDEjTmJPQqrWwAWoi8dT5zwrmZiRkLUoQVkzRy"
        String recipient = "7Dpv5Gi8HjCBgtDN1P1niuPJQCBQ5H8Zob";
        String publicKeyRecipient = "2M9WSqXrpmRzaQkxjcWKnrABabbwqjPbJktBDbPswgL7";

        byte[] publicKeyCreatorByte = Base58.decode(publicKeyCreator);
        byte[] privateKeyCreatorByte = Base58.decode(privateKeyCreator);
        long timestamp = com.ntp.NTP.getTime();

        String title = "9029700190";
        byte encrypt = 1;

        // --- SET MESSAGE VALUES
        long orderDate = System.currentTimeMillis();
        String orderNumber = "ORDER #13";
        String orderUser = title;
        double orderAmount = 1.30;
        long orderAssetKey = 643L;

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

        SendTX tx = new SendTX(this.publicKeyCreator, this.privateKeyCreator, this.recipient, this.publicKeyRecipient, title, message,
                BigDecimal.ZERO,
                //BigDecimal.valueOf(orderAmount),
                timestamp, orderAssetKey, (byte)0, encrypt);

        tx.sign(new Pair<>(privateKeyCreatorByte, publicKeyCreatorByte));
        String byteCode = Base58.encode(tx.toBytes(true));
        Assert.assertNotNull(byteCode);

        this.byteCode = byteCode;

        System.out.println("Bytecode to send:\n" + byteCode);
    }

    @Test
    public void verifyByteCode() throws Exception {
        if (byteCode == null)
            generatyByteCode();

        SendTX sendTXParse = new SendTX(Base58.decode(byteCode));

        Field creator = (SendTX.class.getDeclaredField("creator"));
        creator.setAccessible(true);
        Assert.assertEquals(Base58.encode((byte[]) creator.get(sendTXParse)), this.publicKeyCreator);

        Field recipient = (SendTX.class.getDeclaredField("recipient"));
        recipient.setAccessible(true);
        Assert.assertEquals(Base58.encode((byte[]) recipient.get(sendTXParse)), this.recipient);

        Field reference = (SendTX.class.getDeclaredField("reference"));
        reference.setAccessible(true);
        Assert.assertEquals(new Long(reference.get(sendTXParse).toString()), new Long(0));

        Field head = (SendTX.class.getDeclaredField("head"));
        head.setAccessible(true);
        Assert.assertEquals(head.get(sendTXParse).toString(), this.title);

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

        String d = "";
    }

    @Ignore
    @Test
    public void generateTelegramRandomPeer() throws Exception {

        this.status = true;
        Random random = new Random();
        JSONObject jsonObject = new JSONObject();
        ArrayList<String> arrayListRecipient = new ArrayList<>();
        Pair<byte[], byte[]> KeyPairRecipient = null;
        for (int i = 1; i < 5; i++) {
            int nonce = i;
            byte[] nonceBytes = Ints.toByteArray(Integer.valueOf(nonce) - 1);
            byte[] accountSeedConcat = Bytes.concat(nonceBytes, Base58.decode(SEED_RECIPIENT), nonceBytes);
            byte[] accountSeed = Crypto.getInstance().doubleDigest(accountSeedConcat);
            KeyPairRecipient = Crypto.getInstance().createKeyPair(accountSeed);
            String address = Crypto.getInstance().getAddress(KeyPairRecipient.getB());
            arrayListRecipient.add(address);
        }

        Pair<byte[], byte[]> finalKeyPairRecipient = KeyPairRecipient;
        // Thread thread = new Thread(() -> {
        do {
            int currentPeer = random.nextInt(ADDRESS_API.size());
            long timestamp = com.ntp.NTP.getTime();
            Pair<byte[], byte[]> keyPairCreator = null;
            String byteCode = "";
            String seedPeer = new ArrayList<String>(ADDRESS_API.keySet()).get(currentPeer);
            String ipPeeer = ADDRESS_API.get(seedPeer).toString();

            ArrayList<String> arrayListCreator = new ArrayList<>();
            for (int i = 1; i < 10; i++) {
                int nonce = i;
                byte[] nonceBytes = Ints.toByteArray(Integer.valueOf(nonce) - 1);
                byte[] accountSeedConcat = Bytes.concat(nonceBytes, Base58.decode(seedPeer), nonceBytes);
                byte[] accountSeed = Crypto.getInstance().doubleDigest(accountSeedConcat);
                keyPairCreator = Crypto.getInstance().createKeyPair(accountSeed);
                String address = Crypto.getInstance().getAddress(keyPairCreator.getB());
                arrayListCreator.add(address);
            }

            JSONObject message = new JSONObject();
            if (this.status == true) {
                Integer typeTelegram = random.nextInt(3);
                String user = "", expire = "", randomPrice = "", phone = "", order = "";
                String encrypt = "false";
                long date = System.currentTimeMillis();
                Object recipient = arrayListRecipient.get(random.nextInt(4));
                Object creator = arrayListCreator.get(random.nextInt(9));
                StringRandomGen randomString = new StringRandomGen();
                // correct message
                if (typeTelegram == 1) {
                    user = String.valueOf(random.nextInt(33465666));
                    phone = String.valueOf(random.nextInt(999 - 100) + 100) +
                            String.valueOf(random.nextInt(999 - 100) + 100) +
                            String.valueOf(random.nextInt(9999 - 1000) + 1000);
                    expire = String.valueOf(random.nextInt(1243555959));
                    randomPrice = String.valueOf(random.nextInt(10000));
                    order = String.valueOf(random.nextInt(52193287));
                    if (random.nextInt(2) == 1)
                        encrypt = String.valueOf(random.nextBoolean());
                    // all wrong message
                } else if (typeTelegram == 0) {

                    user = randomString.generateRandomString();
                    expire = randomString.generateRandomString();
                    phone = randomString.generateRandomString();
                    randomPrice = randomString.generateRandomString();
                    order = randomString.generateRandomString();
                    encrypt = (randomString.generateRandomString());

                }
                // random message
                else if (typeTelegram == 2) {

                    Integer countField = random.nextInt(8);
                    for (int i = 0; i < countField; i++) {
                        String keyS = randomString.generateRandomString();
                        String val = randomString.generateRandomString();
                        message.put(keyS, val);
                    }
                    jsonObject.put("message", message);
                    message.put("curr", "643");

                    switch (random.nextInt(3)) {
                        case 0:
                            jsonObject.put("encrypt", "false");
                            break;
                        case 1:
                            jsonObject.put("encrypt", "true");
                            break;
                    }
                    jsonObject.put("title", randomString.generateRandomString());
                    jsonObject.put("password", "123456789");
                }

                jsonObject.put("sender", creator);
                jsonObject.put("recipient", recipient);

                if (typeTelegram == 1 || typeTelegram == 0) {
                    message.put("data", date);
                    message.put("order", order);
                    message.put("user", user);
                    message.put("curr", "643");
                    message.put("sum", randomPrice);
                    message.put("phone", phone);
                    message.put("expire", expire);
                    jsonObject.put("message", message);
                    jsonObject.put("title", ipPeeer);
                    jsonObject.put("encrypt", encrypt);
                    jsonObject.put("password", "123456789");


                    SendTX tx = new SendTX(Base58.encode(keyPairCreator.getB()),
                            Base58.encode(keyPairCreator.getA()),
                            recipient.toString(),
                            Base58.encode(finalKeyPairRecipient.getB()),
                            ipPeeer,
                            message.toJSONString(),
                            BigDecimal.ZERO,
                            //BigDecimal.valueOf(orderAmount),
                            timestamp, orderAssetKey, (byte) 0, encrypt == "true" ? (byte) 1 : (byte) 0);


                    tx.sign(keyPairCreator);
                    byteCode = Base58.encode(tx.toBytes(true));
                }

                String resSend = null;
                try {

                    if (ipPeeer == "207.154.242.242" || ipPeeer == "138.197.178.85:9067") {

                    }
                    if (byteCode != "") {
                        try {
                            resSend = ResponseValueAPI("http://" + ipPeeer + ":" + API_PORT + "/api/broadcasttelegram/" + byteCode, "GET", byteCode);
                        } catch (Exception e) {
                            System.out.println(ipPeeer + " byteCode for peer: " + byteCode);
                        }
                    }


                } catch (Exception e) {
                    e.printStackTrace();
                }
                JSONParser jsonParser = new JSONParser();
                JSONObject object = null;
                try {
                    // object = (JSONObject) jsonParser.parse(resSend.replace("null", ""));
                } catch (Exception e) {
                    String d = "";
                }


               /* if (object.get("error") != null) {
                    //TODO return Error result
                }*/
                Thread.sleep(100);
            } else {
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        } while (true);


        // thread.start();

        // JSONObject result = new JSONObject();
        //result.put("status sending telegrams", this.status);

    }
}