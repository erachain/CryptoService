package com.webserver;

import com.Pair;
import com.StringRandomGen;
import com.crypto.AEScrypto;
import com.crypto.Base58;
import com.crypto.Crypto;
import com.google.common.primitives.Bytes;
import com.google.common.primitives.Ints;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Random;

@Controller
@RequestMapping("/crypto")
@CrossOrigin
@SuppressWarnings("unchecked")
public class ApiCrypto {
    private static Thread thread;
      Logger LOGGER = LoggerFactory.getLogger(ApiCrypto.class);
    public static Boolean status;

    @RequestMapping(method = RequestMethod.GET, produces = "application/json; charset=utf-8")
    @ResponseStatus(code = HttpStatus.OK)
    @ResponseBody
    public ResponseEntity Default() {
        JSONObject jsonObject = new JSONObject();

        jsonObject.put("crypto/generateSeed", "GenerateSeed, GET");
        jsonObject.put("crypto/generateSeed/{seed}", "Generate key pair, GET");
        jsonObject.put("crypto/encrypt", "Encrypt message, POST. Body request: {\"message\": \"test message for encrypt and decrypt\",\"publicKey\":\"{publicKey}\",\"privateKey\":\"{privateKey}\"}");
        jsonObject.put("crypto/decrypt", "Decrypt message, POST. Body request: {\"message\": \"{encrypt message Base58}\", \"publicKey\":\"{publicKey}\",\"privateKey\":\"{privateKey}\"}");
        jsonObject.put("crypto/sign", "Sign, POST. Body request: {\"message\": \"{sign this}\", \"publicKey\":\"{publicKey}\",\"privateKey\":\"{privaeKey}\"}");
        jsonObject.put("crypto/verifySignature", "Verify sign, POST. Body request: {\"message\": \"{message}\", \"publicKey\":\"{publicKey}\",\"signature\":\"{sign}\"}");

        return ResponseEntity.ok(jsonObject.toJSONString());
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
    @RequestMapping(value = "generateSeed", method = RequestMethod.GET,
            produces = "application/json; charset=utf-8")
    public ResponseEntity GenerateSeed() {
        byte[] seed = new byte[32];
        new Random().nextBytes(seed);
        String seedBase58 = Base58.encode(seed);

        JSONObject jsonObject = new JSONObject();
        jsonObject.put("seed", seedBase58);

        return ResponseEntity.ok(jsonObject);
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
     * @param seed is a {@link #GenerateSeed()} master key for generating key pair
     * @return key pair. Public key - byte[32], Private key - byte[64]
     */
    @RequestMapping(value = "generateKeyPair/{seed}", method = RequestMethod.GET,
            produces = "application/json; charset=utf-8")
    public ResponseEntity generateKeyPair(@PathVariable("seed") String seed) {

        Pair<byte[], byte[]> keyPair = Crypto.getInstance().createKeyPair(Base58.decode(seed));

        JSONObject jsonObject = new JSONObject();
        jsonObject.put("publicKey", Base58.encode(keyPair.getB()));
        jsonObject.put("privateKey", Base58.encode(keyPair.getA()));

        return ResponseEntity.ok(jsonObject.toJSONString());
    }

    /**
     * Encrypt message by using my private key and there public key.
     * {@link #generateKeyPair(String)}.
     *
     * @param jsonObject is JSON contains keys and message for encrypt
     * @return JSON string contains encode Base58 message
     * @throws Exception
     */
    @RequestMapping(value = "encrypt", method = RequestMethod.POST,
            produces = "application/json; charset=utf-8")
    public ResponseEntity encrypt(@RequestBody JSONObject jsonObject) {

        String message = jsonObject.get("message").toString();

        byte[] publicKey = Base58.decode(jsonObject.get("publicKey").toString());
        byte[] privateKey = Base58.decode(jsonObject.get("privateKey").toString());

        String result = Base58.encode(AEScrypto.dataEncrypt(message.getBytes(), privateKey, publicKey));
        JSONObject jsonObjectResult = new JSONObject();
        jsonObjectResult.put("encrypted", result);

        return ResponseEntity.ok(jsonObjectResult.toJSONString());
    }

    /**
     * Decrypt message
     *
     * @param decrypt Json row contain keys and message for decrypt
     * @return Json string. if the decryption was successful, it will return the message in coding UTF-8.
     * If cannot decrypt return error.
     * @throws Exception
     */
    @RequestMapping(value = "decrypt", method = RequestMethod.POST,
            produces = "application/json; charset=utf-8")
    public ResponseEntity decrypt(@RequestBody JSONObject decrypt) throws Exception {

        JSONObject jsonObject = decrypt;
        byte[] message = Base58.decode(jsonObject.get("message").toString());
        byte[] publicKey = Base58.decode(jsonObject.get("publicKey").toString());
        byte[] privateKey = Base58.decode(jsonObject.get("privateKey").toString());
        JSONObject jsonObjectResult = new JSONObject();
        byte[] result = AEScrypto.dataDecrypt(message, privateKey, publicKey);

        if (result == null)
            jsonObjectResult.put("Error", "Cannot decrypt. Invalid keys.");
        else
            jsonObjectResult.put("decrypted", new String(result, StandardCharsets.UTF_8));

        return ResponseEntity.ok(jsonObjectResult.toJSONString());
    }

    /**
     * Get signature
     *
     * @param toSign JSON string contains {@link #generateKeyPair(String)} keyPair for sign and message
     * @return
     * @throws Exception
     */
    @RequestMapping(value = "sign", method = RequestMethod.POST,
            produces = "application/json; charset=utf-8")
    public ResponseEntity sign(@RequestBody JSONObject toSign) throws Exception {

        // JSONParser jsonParser = new JSONParser();
        JSONObject jsonObject = toSign;
        String message = jsonObject.get("message").toString();

        Pair<byte[], byte[]> pair = new Pair<>();
        pair.setA(Base58.decode(jsonObject.get("privateKey").toString()));
        pair.setB(Base58.decode(jsonObject.get("publicKey").toString()));
        byte[] sign = Crypto.getInstance().sign(pair, message.getBytes());

        JSONObject jsonObjectSign = new JSONObject();
        jsonObjectSign.put("signature", Base58.encode(sign));

        return ResponseEntity.ok(jsonObjectSign.toJSONString());
    }

    /**
     * Verify signature
     *
     * @param toVerifySign contains there public key, signature and message.
     * @return JSON string contains
     * @throws Exception
     */
    @RequestMapping(value = "verifySignature", method = RequestMethod.POST,
            produces = "application/json; charset=utf-8")
    public ResponseEntity verifySignature(@RequestBody JSONObject toVerifySign) throws Exception {

        JSONObject jsonObject = toVerifySign;

        byte[] publicKey = Base58.decode(jsonObject.get("publicKey").toString());
        byte[] signature = Base58.decode(jsonObject.get("signature").toString());
        byte[] message = jsonObject.get("message").toString().getBytes();

        boolean statusVerify = Crypto.getInstance().verify(publicKey, signature, message);

        JSONObject jsonObjectResult = new JSONObject();
        jsonObjectResult.put("signatureVerify", statusVerify);

        return ResponseEntity.ok(jsonObjectResult.toJSONString());
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
    @RequestMapping(value = "generateAccount", method = RequestMethod.POST,
            produces = "application/json; charset=utf-8")

    public ResponseEntity generateAccount(@RequestBody JSONObject value) throws ParseException {

        JSONObject jsonObject = value;
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

        return ResponseEntity.ok(jsonObjectResult.toJSONString());
    }

    /**
     * Generate random telegram. Wallet seed sender and wallet seed recipient set in setting.json.
     * If status true all telegram will sending. Status false suspending thread sending telegram.
     *
     * @param count  count telegram for send
     * @param ip     address where the message will be sent with port
     * @param sleep  delay between sending telegrams
     * @param status status send telegram
     *
     *               <h2>Example request</h2>
     *               http://127.0.0.1:8181/crypto/generateTelegram?count=10&ip=127.0.0.1:9068&sleep=10status=true
     *
     *               <h2>Example response</h2>
     *               {"status sending telegrams", "true"}
     * @return List telegram in JSON format
     */
    @RequestMapping(value = "generateTelegram", method = RequestMethod.GET,
            produces = "application/json; charset=utf-8")
    @SuppressWarnings("unchecked")
    public ResponseEntity generateTelegram(@RequestParam("count") Integer count,
                                           @RequestParam("ip") String ip,
                                           @RequestParam("sleep") Integer sleep,
                                           @RequestParam("status") Boolean status) {

        this.status = status;
        JSONObject jsonObject = new JSONObject();
        ArrayList<String> arrayListRecipient = new ArrayList<>();
        for (int i = 1; i < 5; i++) {
            int nonce = i;
            byte[] nonceBytes = Ints.toByteArray(Integer.valueOf(nonce) - 1);
            byte[] accountSeedConcat = Bytes.concat(nonceBytes, Base58.decode(SetSettingFile.SEED_RECIPIENT), nonceBytes);
            byte[] accountSeed = Crypto.getInstance().doubleDigest(accountSeedConcat);
            Pair<byte[], byte[]> keyPair = Crypto.getInstance().createKeyPair(accountSeed);
            String address = Crypto.getInstance().getAddress(keyPair.getB());
            arrayListRecipient.add(address);
        }

        ArrayList<String> arrayListCreator = new ArrayList<>();
        for (int i = 1; i < 10; i++) {
            int nonce = i;
            byte[] nonceBytes = Ints.toByteArray(Integer.valueOf(nonce) - 1);
            byte[] accountSeedConcat = Bytes.concat(nonceBytes, Base58.decode(SetSettingFile.SEED_CREATOR), nonceBytes);
            byte[] accountSeed = Crypto.getInstance().doubleDigest(accountSeedConcat);
            Pair<byte[], byte[]> keyPair = Crypto.getInstance().createKeyPair(accountSeed);
            String address = Crypto.getInstance().getAddress(keyPair.getB());
            arrayListCreator.add(address);
        }


        Random random = new Random();


        thread = new Thread(() -> {
            do {
                LOGGER.debug("send");
                JSONObject message = new JSONObject();
                if (this.status == true) {
                    Integer typeTelegram = random.nextInt(3);
                    String user = "", expire = "", randomPrice = "", phone = "", order = "";
                    String encrypt = "false";

                    long date = System.currentTimeMillis();
                    Object recipient = arrayListRecipient.get(random.nextInt(4));
                    Object creator = arrayListCreator.get(random.nextInt(9));
                    StringRandomGen randomString = new StringRandomGen();
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

                    } else if (typeTelegram == 0) {

                        user = randomString.generateRandomString();
                        expire = randomString.generateRandomString();
                        phone = randomString.generateRandomString();
                        randomPrice = randomString.generateRandomString();
                        order = randomString.generateRandomString();
                        encrypt = (randomString.generateRandomString());

                    } else if (typeTelegram == 2) {

                        Integer countField = random.nextInt(8);
                        for (int i = 0; i < countField; i++) {
                            String key = randomString.generateRandomString();
                            String val = randomString.generateRandomString();
                            message.put(key, val);
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
                        jsonObject.put("title", phone);
                        jsonObject.put("encrypt", encrypt);
                        jsonObject.put("password", "123456789");
                    }

                    String resSend = null;
                    try {
                        resSend = SetSettingFile.ResponseValueAPI("http://" + ip + "/telegrams/send", "POST", jsonObject.toJSONString());
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
                        //TODO return Error result
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
        return ResponseEntity.ok(result.toJSONString());
    }

    /**
     * Method set status sending telegram.
     * True is set start. False stop
     *
     * @param status set status stop/start sending telegram
     * @return
     */
    @RequestMapping(value = "stopGenerate", method = RequestMethod.GET,
            produces = "application/json; charset=utf-8")

    public ResponseEntity stopGenerateTelegram(@RequestParam("status") Boolean status) {

        this.status = status;
        JSONObject jsonObjectResult = new JSONObject();
        jsonObjectResult.put("status sending telegrams", this.status);
        return ResponseEntity.ok(jsonObjectResult.toJSONString());
    }
}
