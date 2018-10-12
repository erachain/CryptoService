package webserver;

import com.google.common.primitives.Bytes;
import com.google.common.primitives.Ints;
import crypto.AEScrypto;
import crypto.Base58;
import crypto.Crypto;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tx.SendTX;
import utils.Pair;

import javax.ws.rs.*;
import javax.ws.rs.core.Response;
import java.math.BigDecimal;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;

@Path("crypto")
public class ApiCrypto extends SetSettingFile {
    private static Thread thread;
    final static private Logger LOGGER = LoggerFactory.getLogger(ApiCrypto.class);
    public static Boolean status;
    @GET
    public Response Default() {
        JSONObject jsonObject = new JSONObject();

        jsonObject.put("crypto/generateSeed", "generateSeed, GET");
        jsonObject.put("crypto/generateSeed/{seed}", "Generate key pair, GET");
        jsonObject.put("crypto/encrypt", "encrypt message, POST. Body request: {\"message\": \"test message for encrypt and decrypt\",\"publicKey\":\"{publicKey}\",\"privateKey\":\"{privateKey}\"}");
        jsonObject.put("crypto/decrypt", "decrypt message, POST. Body request: {\"message\": \"{encrypt message Base58}\", \"publicKey\":\"{publicKey}\",\"privateKey\":\"{privateKey}\"}");
        jsonObject.put("crypto/sign", "sign, POST. Body request: {\"message\": \"{sign this}\", \"publicKey\":\"{publicKey}\",\"privateKey\":\"{privaeKey}\"}");
        jsonObject.put("crypto/verifySignature", "Verify sign, POST. Body request: {\"message\": \"{message}\", \"publicKey\":\"{publicKey}\",\"signature\":\"{sign}\"}");


        return Response.status(200)
                .header("Content-Type", "application/json; charset=utf-8")
                .header("Access-Control-Allow-Origin", "*")
                .entity(jsonObject.toJSONString())
                .build();


    }

    /**
     * Generate random seed in Base Base58
     *
     * @return JSON string seed in encode Base58
     *
     * <h2>Example request</h2>
     * http://127.0.0.1:8080/crypto/generateSeed
     *
     * <h2>Example response</h2>
     * {"seed":"D9FFKCjo4cG2jL9FrZmXCKfQypZG8AdbnF7vtm5Aqou9"}
     */
    @GET
    @Path("generateSeed")
    public Response generateSeed() {
        LOGGER.info("ss");
        byte[] seed = new byte[32];
        new Random().nextBytes(seed);
        String seedBase58 = Base58.encode(seed);

        JSONObject jsonObject = new JSONObject();
        jsonObject.put("seed", seedBase58);

        return Response.status(200).header("Content-Type", "application/json; charset=utf-8")
                .header("Access-Control-Allow-Origin", "*")
                .entity(jsonObject.toJSONString())
                .build();
    }

    /**
     * Generate key pair by master key
     *
     * <h2>Example request</h2>
     * GET
     * <br>
     * http://127.0.0.1:8080/crypto/generateKeyPair/9hXpWzA6vfn7MkwrjxF2ZAHHuCsevDTauQ4in2hAfSNH
     *
     * <h2>Example response</h2>
     * {"publicKey":"BHJAVuNsvcjWy6jaaF85HHYzr9Up9rA4BW3xseUBs9Un",
     * "privateKey":"4XeFFL279quugYpvkqSPHwsK68jumG7C9CWz7QzSWJapjSB1FGiSDSawg65YZorRt2GbAP25gGv8ooduMxWpp7HD"}
     *
     * @param seed is a {@link #generateSeed()} master key for generating key pair
     * @return key pair. Public key - byte[32], Private key - byte[64]
     */
    @GET
    @Path("generateKeyPair/{seed}")
    public Response generateKeyPair(@PathParam("seed") String seed) {

        Pair<byte[], byte[]> keyPair = Crypto.getInstance().createKeyPair(Base58.decode(seed));

        JSONObject jsonObject = new JSONObject();
        jsonObject.put("publicKey", Base58.encode(keyPair.getB()));
        jsonObject.put("privateKey", Base58.encode(keyPair.getA()));

        return Response.status(200).header("Content-Type", "application/json; charset=utf-8")
                .header("Access-Control-Allow-Origin", "*")
                .entity(jsonObject.toJSONString())
                .build();
    }

    /**
     * encrypt message by using my private key and there public key.
     * {@link #generateKeyPair(String)}.
     *
     * @param encrypt is JSON contains keys and message for encrypt
     * @return JSON string contains encode Base58 message
     * @throws Exception
     */
    @POST
    @Path("encrypt")
    public Response encrypt(String encrypt) throws Exception {

        JSONParser jsonParser = new JSONParser();
        JSONObject jsonObject = (JSONObject) jsonParser.parse(encrypt);

        String message = jsonObject.get("message").toString();

        byte[] publicKey = Base58.decode(jsonObject.get("publicKey").toString());
        byte[] privateKey = Base58.decode(jsonObject.get("privateKey").toString());

        String result = Base58.encode(AEScrypto.dataEncrypt(message.getBytes(Charset.forName("UTF-8")), privateKey, publicKey));
        JSONObject jsonObjectResult = new JSONObject();
        jsonObjectResult.put("encrypted", result);
        return Response.status(200).header("Content-Type", "application/json; charset=utf-8")
                .header("Access-Control-Allow-Origin", "*")
                .entity(jsonObjectResult.toJSONString())
                .build();
    }

    /**
     * decrypt message
     *
     * @param decrypt Json row contain keys and message for decrypt
     * @return Json string. if the decryption was successful, it will return the message in coding UTF-8.
     * If cannot decrypt return error.
     * @throws Exception
     */
    @POST
    @Path("decrypt")
    public Response decrypt(String decrypt) throws Exception {

        JSONParser jsonParser = new JSONParser();
        JSONObject jsonObject = (JSONObject) jsonParser.parse(decrypt);
        byte[] message = Base58.decode(jsonObject.get("message").toString());
        byte[] publicKey = Base58.decode(jsonObject.get("publicKey").toString());
        byte[] privateKey = Base58.decode(jsonObject.get("privateKey").toString());
        JSONObject jsonObjectResult = new JSONObject();
        byte[] result = AEScrypto.dataDecrypt(message, privateKey, publicKey);

        if (result == null)
            jsonObjectResult.put("Error", "Cannot decrypt. Invalid keys.");
        else
            jsonObjectResult.put("decrypted", new String(result, StandardCharsets.UTF_8));

        return Response.status(200).header("Content-Type", "application/json; charset=utf-8")
                .header("Access-Control-Allow-Origin", "*")
                .entity(jsonObjectResult.toJSONString())
                .build();
    }

    /**
     * Get signature
     *
     * @param toSign JSON string contains {@link #generateKeyPair(String)} keyPair for sign and message
     * @return
     * @throws Exception
     */
    @POST
    @Path("sign")
    public Response sign(String toSign) throws Exception {

        JSONParser jsonParser = new JSONParser();
        JSONObject jsonObject = (JSONObject) jsonParser.parse(toSign);
        String message = jsonObject.get("message").toString();

        Pair<byte[], byte[]> pair = new Pair<>();
        pair.setA(Base58.decode(jsonObject.get("privateKey").toString()));
        pair.setB(Base58.decode(jsonObject.get("publicKey").toString()));
        byte[] sign = Crypto.getInstance().sign(pair, Base58.decode(message));

        JSONObject jsonObjectSign = new JSONObject();
        jsonObjectSign.put("signature", Base58.encode(sign));

        return Response.status(200).header("Content-Type", "application/json; charset=utf-8")
                .header("Access-Control-Allow-Origin", "*")
                .entity(jsonObjectSign.toJSONString())
                .build();
    }

    /**
     * Verify signature
     *
     * @param toVerifySign contains there public key, signature and message.
     * @return JSON string contains
     * @throws Exception
     */
    @POST
    @Path("verifySignature")
    public Response verifySignature(String toVerifySign) throws Exception {
        JSONParser jsonParser = new JSONParser();
        JSONObject jsonObject = (JSONObject) jsonParser.parse(toVerifySign);

        byte[] publicKey = Base58.decode(jsonObject.get("publicKey").toString());
        byte[] signature = Base58.decode(jsonObject.get("signature").toString());
        byte[] message = Base58.decode(jsonObject.get("signature").toString());

        boolean statusVerify = Crypto.getInstance().verify(publicKey, signature, message);

        JSONObject jsonObjectResult = new JSONObject();
        jsonObjectResult.put("signatureVerify", statusVerify);

        return Response.status(200).header("Content-Type", "application/json; charset=utf-8")
                .header("Access-Control-Allow-Origin", "*")
                .entity(jsonObjectResult.toJSONString())
                .build();
    }

    /**
     * Generate account by master seed and number account
     *
     * @param value JSON value: seed and nonce
     * @return JSON
     * <h2>Example request</h2>
     * http://127.0.0.1:8181/crypto/generateAccount
     * <p>
     * in body
     * <p>
     * {"seed":"2UiJ8Fte8bvuZSFjhdEtJ2etVvbirNRDTu8KEs9BFxch","nonce": 4}
     * <h2>Example response</h2>
     * {"accountSeed":"6mAg3iU1QEmq672So76QtdnsmdnGNqR7ngss8SLCzkpq",
     * "privateKey":"5BMJVxNYHUBWkZKrcbL4stq2i975auVqmhpUmmu4d3vR15dvF7BMkzz1sDidRqTKsrCeiNFCPA9uss6P3TxqszMY",
     * "numAccount":1,
     * "publicKey":"AQyCxEXLewJvqzLegTW41xF3qjnTCr7tVvT6639WJsKb",
     * "account":"7FAxosYza2B4X9GcbxGWgKW8QXUZKQystx"}
     * @throws ParseException
     */
    @POST
    @Path("generateAccount")
    public Response generateAccount(String value) throws ParseException {
        JSONParser jsonParser = new JSONParser();
        JSONObject jsonObject = (JSONObject) jsonParser.parse(value);


        Integer nonce = Integer.valueOf(jsonObject.get("nonce").toString());
        String seed = jsonObject.get("seed").toString();
        JSONObject jsonObjectResult = new JSONObject();

        byte[] nonceBytes = Ints.toByteArray(Integer.valueOf(nonce) - 1);
        byte[] accountSeedConcat = Bytes.concat(nonceBytes, Base58.decode(seed), nonceBytes);
        byte[] accountSeed = Crypto.getInstance().doubleDigest(accountSeedConcat);

        Pair<byte[], byte[]> keyPair = Crypto.getInstance().createKeyPair(accountSeed);

        String address = Crypto.getInstance().getAddress(keyPair.getB());

        jsonObjectResult.put("numAccount", nonce);
        jsonObjectResult.put("accountSeed", Base58.encode(accountSeed));
        jsonObjectResult.put("publicKey", Base58.encode(keyPair.getB()));
        jsonObjectResult.put("privateKey", Base58.encode(keyPair.getA()));
        jsonObjectResult.put("account", address);

        return Response.status(200).header("Content-Type", "application/json; charset=utf-8")
                .header("Access-Control-Allow-Origin", "*")
                .entity(jsonObjectResult.toJSONString())
                .build();
    }

    /**
     * Generate random telegram. Wallet seed sender and wallet seed recipient set in setting.json.
     * If status true all telegram will sending. Status false suspending thread sending telegram.
     *
     * @param ip address where the message will be sent with port
     * @param sleep delay between sending telegrams
     * @param status status send telegram
     *
     * <h2>Example request</h2>
     * http://127.0.0.1:8181/crypto/generateTelegram?&ip=127.0.0.1:9068&sleep=10&status=true
     * <h2>Example response</h2>
     * {"status sending telegrams", "true"}
     *
     * @return List telegram in JSON format
     */
    @GET
    @Path("generateTelegram")
    public Response generateTelegram(@QueryParam("ip") String ip,
                                     @QueryParam("sleep") Integer sleep,
                                     @QueryParam("status") Boolean status) {
        //  final StatusSending statusSending = new StatusSending();


        this.status = status;
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


        thread = new Thread(() -> {
            do {
                if (this.status == true) {

                    long date = System.currentTimeMillis();
                    Object recipient = arrayListRecipient.get(random.nextInt(4));
                    Object creator = arrayListCreator.get(random.nextInt(9));
                    int user = random.nextInt(33465666);
                    int expire = random.nextInt(1243555959);
                    int randomPrice = random.nextInt(10000);

                    String phone = String.valueOf(random.nextInt(999 - 100) + 100) +
                            String.valueOf(random.nextInt(999 - 100) + 100) +
                            String.valueOf(random.nextInt(9999 - 1000) + 1000);

                    message.put("date", date);
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

                    String resSend = null;
                    try {
                        resSend = ResponseValueAPI("http://" + ip + "/telegrams/send", "POST", jsonObject.toJSONString());
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    JSONParser jsonParser = new JSONParser();

                    JSONObject object = null;
                    try {
                        object = (JSONObject) jsonParser.parse(resSend.replace("null", ""));
                    } catch (ParseException e) {
                        e.printStackTrace();
                    }
                    if (object.get("error") != null) {
                        Response.status(200).header("Content-Type", "application/json; charset=utf-8")
                                .header("Access-Control-Allow-Origin", "*")
                                .entity(object.toJSONString())
                                .build();
                    }
                    try {
                        Thread.sleep(sleep);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                } else {
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
            } while (true);
        });

        thread.start();

        JSONObject result = new JSONObject();
        result.put("status sending telegrams", this.status);
        return Response.status(200).header("Content-Type", "application/json; charset=utf-8")
                .header("Access-Control-Allow-Origin", "*")
                .entity(result.toJSONString())
                .build();
    }

    /**
     * Method set status sending telegram.
     * True is set start. False stop
     *
     * @param status set status stop/start sending telegram
     * @return
     */
    @GET
    @Path("stopGenerate")
    public Response stopGenerateTelegram(@QueryParam("status") Boolean status) {
        this.status = status;

        JSONObject jsonObjectResult = new JSONObject();
        jsonObjectResult.put("status sending telegrams", this.status);
        return Response.status(200).header("Content-Type", "application/json; charset=utf-8")
                .header("Access-Control-Allow-Origin", "*")
                .entity(jsonObjectResult.toJSONString())
                .build();
    }

    @POST
    @Path("sendTelegram")
    public Response sendTelegram() {
        JSONObject jsonObject = new JSONObject();

        byte[] transactionType = new byte[]{31, 0, 0, 0};
        Long timestamp = Long.parseLong(new Timestamp(System.currentTimeMillis()).toString());


        return Response.status(200).header("Content-Type", "application/json; charset=utf-8")
                .header("Access-Control-Allow-Origin", "*")
                .entity(jsonObject.toJSONString())
                .build();
    }

    @GET
    @Path("decode/{message}")
    public Response decode(@PathParam("message") String message) {
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("decodeBase58", Arrays.toString(Base58.decode(message)));
        return Response.status(200).header("Content-Type", "application/json; charset=utf-8")
                .header("Access-Control-Allow-Origin", "*")
                .entity(jsonObject.toJSONString())
                .build();
    }

    @GET
    @Path("encode/{message}")
    public Response encode(@PathParam("message") String message) {
        JSONObject jsonObject = new JSONObject();

        String[] charString = (message.replace("[", "")
                .replace("]", "")).split(",");

        byte[] bytes = new byte[]{};
        for (String val : charString) {
            byte[] temp = new byte[]{Byte.valueOf((val.replace('"', ' ')).trim())};
            bytes = Bytes.concat(bytes, temp);
        }

        jsonObject.put("encodeBase58", Base58.encode(bytes));
        return Response.status(200).header("Content-Type", "application/json; charset=utf-8")
                .header("Access-Control-Allow-Origin", "*")
                .entity(jsonObject.toJSONString())
                .build();
    }

    /**
     * Generate byte code.
     *
     * @param value JSON string contains param for generate byte code
     * @return JSON string with byte code
     *
     * <h2>Example request</h2>
     * {
     *   "recipient": "7Dpv5Gi8HjCBgtDN1P1niuPJQCBQ5H8Zob",
     *   "creator":"7FAxosYza2B4X9GcbxGWgKW8QXUZKQystx",
     *   "title": "9160010011",
     *   "orderNumber": "ORDER #1",
     *   "orderUser": "9160010011",
     *   "details": "Оплата интернет заказа. НДС не облагается",
     *   "description": "заказ",
     *   "expire": 35,
     *   "amount": 15.06,
     *   "encrypt": true,
     *   "keyAsset":643,
     *   "publicKeyCreator": "AQyCxEXLewJvqzLegTW41xF3qjnTCr7tVvT6639WJsKb",
     *   "privateKeyCreator": "5BMJVxNYHUBWkZKrcbL4stq2i975auVqmhpUmmu4d3vR15dvF7BMkzz1sDidRqTKsrCeiNFCPA9uss6P3TxqszMY",
     *   "publicKeyRecipient":"2M9WSqXrpmRzaQkxjcWKnrABabbwqjPbJktBDbPswgL7"
     * }
     *
     * <h2>Example response</h2>
     * {
     * "byteCode": "65EM4ncMSGkeqTEU4X5g21Mb78Z7sYoGRQzdjasXCuoPWDmxVUVR6dsemqFGQXS4E37ap7jSNwmKTtBfHUhzd9ZHvN
     * jgmmFmXBXwFBmTgYFccsDR3US5977NwaoZXryGy8DoMUqSyEwbbjQPtofi7qqv2ShxoZfiMo3V6h1aaAPNLcTnSm9cyrRFh2ukDS1Hf
     * AC9QQPu7fiHVXnS6gefCgmfM6Q7zKetRhH6XYf4Md8JkTw3d6V5Z2gcp1s1h6aNUiVTyJ68BEvi7eaMNEzsPHmjZEhoZdegLwMnBSGu
     * qrddSRLjyQybGEL2HgWMbV5Nd6wzabRCrgXSKTXSiEEokk3wp4W1MR45v9dutwihmWye5xwu1vhyBFWJ6LrmKnuCHQchjX2x3koPv2M
     * EQeT6tGZBPHRVPLT2xxbsaRZuRbExEXpM3BaENEQCwEsUiHgYH4V7tkjazDMwqKULmsWLwaFmdVjv6H6CkdPE1ti3LXtEDdSFZxRh5v
     * cv29XuTx1xnr2pogF9v4WVSdZJcyyp72WoTZoGWMDtTsL4pphNKXQR2Qrc"
     * }
     */
    @POST
    @Path("generateByteCode")
    public Response generateByteCode(String value) throws Exception {
        JSONParser jsonParser = new JSONParser();
        JSONObject jsonParse = (JSONObject) jsonParser.parse(value);

        String recipient = jsonParse.get("recipient").toString();
        String creator = jsonParse.get("creator").toString();
        String title = jsonParse.get("title").toString();
        String orderNumber = jsonParse.get("orderNumber").toString();
        String orderUser = jsonParse.get("orderUser").toString();
        String details = jsonParse.get("details").toString();
        String description = jsonParse.get("description").toString();
        int expire = Integer.valueOf(jsonParse.get("expire").toString());
        double amount = Double.parseDouble(jsonParse.get("amount").toString());
        long timestamp = ntp.NTP.getTime();
        byte encrypt = Boolean.parseBoolean(jsonParse.get("encrypt").toString()) ? (byte) 1 : (byte) 0;
        String publicKeyCreator = jsonParse.get("publicKeyCreator").toString();
        String privateKeyCreator = jsonParse.get("privateKeyCreator").toString();
        String publicKeyRecipient= jsonParse.get("publicKeyRecipient").toString();
        long key = Long.parseLong(jsonParse.get("keyAsset").toString());
        JSONObject jsonMessage = new JSONObject();

        jsonMessage.put("date", System.currentTimeMillis());
        jsonMessage.put("order", orderNumber);
        jsonMessage.put("user", title);
        jsonMessage.put("curr", key);
        jsonMessage.put("sum", amount);
        jsonMessage.put("title", title);
        jsonMessage.put("details", details);
        jsonMessage.put("description", description);
        jsonMessage.put("expire", expire);

        SendTX tx = new SendTX(publicKeyCreator, privateKeyCreator, recipient, publicKeyRecipient,
                title, jsonMessage.toJSONString(),
                BigDecimal.valueOf(amount),
                timestamp, key, (byte) 0, encrypt);

        tx.sign(new Pair<>(Base58.decode(privateKeyCreator), Base58.decode(publicKeyCreator)));
        String byteCode = Base58.encode(tx.toBytes(true));

        JSONObject jsonObject = new JSONObject();
        jsonObject.put("byteCode", byteCode);
        return Response.status(200).header("Content-Type", "application/json; charset=utf-8")
                .header("Access-Control-Allow-Origin", "*")
                .entity(jsonObject.toJSONString())
                .build();
    }
}
