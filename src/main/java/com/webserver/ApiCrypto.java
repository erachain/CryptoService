package com.webserver;

import com.crypto.AEScrypto;
import com.crypto.Base58;
import com.crypto.Crypto;
import com.google.common.primitives.Bytes;
import com.google.common.primitives.Ints;
import com.ntp.NTP;
import com.tx.SendTX;
import com.utils.Pair;
import com.utils.StringRandomGen;
import org.json.simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigDecimal;
import java.net.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static com.webserver.SetSettingFile.*;

@Controller
@RequestMapping("/crypto")
@CrossOrigin
@SuppressWarnings("unchecked")
public class ApiCrypto {
    private static Thread thread;
    final static private Logger LOGGER = LoggerFactory.getLogger(ApiCrypto.class);
    private static Boolean status = false;
    private static Integer delay = Integer.MAX_VALUE;
    private static Integer countSend = 0;
    private static long startTime;
    private static long endTime;
    private AtomicLong num = new AtomicLong(0);
    long orderAssetKey = 643L;

    @RequestMapping(method = RequestMethod.GET, produces = "application/json; charset=utf-8")
    @ResponseStatus(code = HttpStatus.OK)
    @ResponseBody
    public ResponseEntity Default() {
        JSONObject jsonObject = new JSONObject();

        jsonObject.put("crypto/generateSeed", "generateSeed, GET");
        jsonObject.put("crypto/generateSeed/{seed}", "Generate key pair, GET");
        jsonObject.put("crypto/encrypt", "encrypt message, POST. Body request: {\"message\": \"test message for encrypt and decrypt\",\"publicKey\":\"{publicKey}\",\"privateKey\":\"{privateKey}\"}");
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
     * http://127.0.0.1:8181/crypto/generateSeed
     *
     * <h2>Example response</h2>
     * {"seed":"D9FFKCjo4cG2jL9FrZmXCKfQypZG8AdbnF7vtm5Aqou9"}
     */
    @GetMapping(value = "generateSeed",
            produces = "application/json; charset=utf-8")
    public ResponseEntity generateSeed() {
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
     * http://127.0.0.1:8181/crypto/generateKeyPair/9hXpWzA6vfn7MkwrjxF2ZAHHuCsevDTauQ4in2hAfSNH
     *
     * <h2>Example response</h2>
     * {"publicKey":"BHJAVuNsvcjWy6jaaF85HHYzr9Up9rA4BW3xseUBs9Un",
     * "privateKey":"4XeFFL279quugYpvkqSPHwsK68jumG7C9CWz7QzSWJapjSB1FGiSDSawg65YZorRt2GbAP25gGv8ooduMxWpp7HD"}
     *
     * @param seed is a {@link #generateSeed()} master key for generating key pair
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
     * encrypt message by using my private key and there public key.
     * {@link #generateKeyPair(String)}.
     *
     * @param jsonObject is JSON contains keys and message for encrypt
     * @return JSON string contains encode Base58 message
     */
    @RequestMapping(value = "encrypt", method = RequestMethod.POST,
            produces = "application/json; charset=utf-8")
    public ResponseEntity encrypt(@RequestBody JSONObject jsonObject) {

        String message = jsonObject.get("message").toString();

        byte[] publicKey = Base58.decode(jsonObject.get("publicKey").toString());
        byte[] privateKey = Base58.decode(jsonObject.get("privateKey").toString());

        String result = Base58.encode(AEScrypto.dataEncrypt(message.getBytes(Charset.forName("UTF-8")), privateKey, publicKey));
        JSONObject jsonObjectResult = new JSONObject();
        jsonObjectResult.put("encrypted", result);

        return ResponseEntity.ok(jsonObjectResult.toJSONString());
    }

    /**
     * decrypt message
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

        if (result == null) {
            jsonObjectResult.put("Error", "Cannot decrypt. Invalid keys.");
        } else {
            jsonObjectResult.put("decrypted", new String(result, StandardCharsets.UTF_8));
        }

        return ResponseEntity.ok(jsonObjectResult.toJSONString());
    }

    /**
     * Get signature
     *
     * @param toSign JSON string contains {@link #generateKeyPair(String)} keyPair for sign and message
     * @return
     */
    @RequestMapping(value = "sign", method = RequestMethod.POST,
            produces = "application/json; charset=utf-8")
    public ResponseEntity sign(@RequestBody JSONObject toSign) {

        JSONObject jsonObject = toSign;
        String message = jsonObject.get("message").toString();

        Pair<byte[], byte[]> pair = new Pair<>();
        pair.setA(Base58.decode(jsonObject.get("privateKey").toString()));
        pair.setB(Base58.decode(jsonObject.get("publicKey").toString()));
        byte[] sign = Crypto.getInstance().sign(pair, Base58.decode(message));

        JSONObject jsonObjectSign = new JSONObject();
        jsonObjectSign.put("signature", Base58.encode(sign));

        return ResponseEntity.ok(jsonObjectSign.toJSONString());
    }

    /**
     * Verify signature
     *
     * @param toVerifySign contains there public key, signature and message.
     * @return JSON string contains
     */
    @RequestMapping(value = "verifySignature", method = RequestMethod.POST,
            produces = "application/json; charset=utf-8")
    public ResponseEntity verifySignature(@RequestBody JSONObject toVerifySign) {

        JSONObject jsonObject = toVerifySign;

        byte[] publicKey = Base58.decode(jsonObject.get("publicKey").toString());
        byte[] signature = Base58.decode(jsonObject.get("signature").toString());
        byte[] message = Base58.decode(jsonObject.get("message").toString());

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
     */
    @RequestMapping(value = "generateAccount", method = RequestMethod.POST,
            produces = "application/json; charset=utf-8")
    public ResponseEntity generateAccount(@RequestBody JSONObject value) {

        JSONObject jsonObject = value;
        Integer nonce = Integer.valueOf(jsonObject.get("nonce").toString());
        String seed = jsonObject.get("seed").toString();
        JSONObject jsonObjectResult = new JSONObject();

        byte[] nonceBytes = Ints.toByteArray(nonce - 1);
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
     * In the setting.json set ip and seed wallet nodes.
     *
     * @param param  JSON param
     *
     *               <h2>Example request</h2>
     *               http://127.0.0.1:8181/crypto/generator/start
     *
     *       body
     *     {"delay": 100}
     *
     *               <h2>Example response</h2>
     *               {"status sending telegrams", "true", "delay": 100}
     * @return List telegram in JSON format
     */
    @RequestMapping(value = "generator/start", method = RequestMethod.POST,
            produces = "application/json; charset=utf-8")
    @SuppressWarnings("unchecked")
    public ResponseEntity generateTelegram(@RequestBody JSONObject param) throws UnknownHostException {

        long t = System.currentTimeMillis();
        LOGGER.info(String.valueOf(System.currentTimeMillis()));

        String localAddress = InetAddress.getLocalHost().getHostAddress();

        status = true;
        delay = 0;
        Random random = new Random();
        JSONObject jsonObject = new JSONObject();
        ArrayList<String> arrayListRecipient = new ArrayList<>();
        Pair<byte[], byte[]> keyPairRecipient = null;
        for (int nonce = 1; nonce < 5; nonce++) {
            byte[] nonceBytes = Ints.toByteArray(nonce - 1);
            byte[] accountSeedConcat = Bytes.concat(nonceBytes, Base58.decode(SEED_RECIPIENT), nonceBytes);
            byte[] accountSeed = Crypto.getInstance().doubleDigest(accountSeedConcat);
            keyPairRecipient = Crypto.getInstance().createKeyPair(accountSeed);
            String address = Crypto.getInstance().getAddress(keyPairRecipient.getB());
            arrayListRecipient.add(address);
        }

        if (endTime != 0)
            endTime = 0;

        if (countSend != 0)
            countSend = 0;

        startTime = System.currentTimeMillis();
        Pair<byte[], byte[]> finalKeyPairRecipient = keyPairRecipient;
        thread = new Thread(() -> {
            do {

                int currentPeer = random.nextInt(10);
                long timestamp = com.ntp.NTP.getTime();
                Pair<byte[], byte[]> keyPairCreator = null;
                String byteCode = "";
                String isPeer = "";//new ArrayList<String>(PEERS.keySet()).get(currentPeer);
                String seedPeer = "asd";//PEERS.get(isPeer).toString();

                ArrayList<String> arrayListCreator = new ArrayList<>();
                for (int nonce = 1; nonce < 10; nonce++) {
                    byte[] nonceBytes = Ints.toByteArray(nonce - 1);
                    byte[] accountSeedConcat = Bytes.concat(nonceBytes, Base58.decode(seedPeer), nonceBytes);
                    byte[] accountSeed = Crypto.getInstance().doubleDigest(accountSeedConcat);
                    keyPairCreator = Crypto.getInstance().createKeyPair(accountSeed);
                    String address = Crypto.getInstance().getAddress(keyPairCreator.getB());
                    arrayListCreator.add(address);
                }

                JSONObject message = new JSONObject();
                if (status) {

                    int typeTelegram = random.nextInt(2);
                    String user = "";
                    String expire = "";
                    String randomPrice = "";
                    String phone = "";
                    String order = "";

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
                    }
                    else if (typeTelegram == 0) {

                        user = randomString.generateRandomString();
                        expire = randomString.generateRandomString();
                        phone = randomString.generateRandomString();
                        randomPrice = randomString.generateRandomString();
                        order = randomString.generateRandomString();
                        encrypt = (randomString.generateRandomString());
                    }

                    if (typeTelegram == 1 || typeTelegram == 0) {
                        message.put("data", date);
                        message.put("order", order);
                        message.put("user", user);
                        message.put("curr", "643");
                        message.put("sum", randomPrice);
                        message.put("phone", phone);
                        message.put("expire", expire);
                        jsonObject.put("message", message);
                        jsonObject.put("title", isPeer);
                        jsonObject.put("encrypt", encrypt);
                        jsonObject.put("password", "123456789");

                        SendTX tx = new SendTX(Base58.encode(keyPairCreator.getB()),
                                Base58.encode(keyPairCreator.getA()),
                                recipient.toString(),
                                Base58.encode(finalKeyPairRecipient.getB()),
                                "Ip creator to recipient: " + localAddress + "->" + isPeer,
                                message.toJSONString(),
                                BigDecimal.ZERO,
                                //BigDecimal.valueOf(orderAmount),
                                timestamp, orderAssetKey, (byte) 0, encrypt == "true" ? (byte) 1 : (byte) 0);

                        try {
                            tx.sign(keyPairCreator);
                            byteCode = Base58.encode(tx.toBytes(true));
                            LOGGER.info(byteCode);

                            LOGGER.info(String.valueOf(num.getAndIncrement()));

                        } catch (Exception e) {
                            LOGGER.error(String.valueOf(e));
                        }
                    }
                    try {

                        if (!byteCode.isEmpty()) {
                            try {
                                postTransaction(byteCode);
                                countSend++;
                            }
                            catch (Exception e) {
                                LOGGER.error(isPeer + " byteCode for peer: " + byteCode);
                            }
                        }

                    } catch (Exception e) {
                        LOGGER.info(String.valueOf(e));
                    }

                }
            } while (true);
        });

        thread.start();


        return ResponseEntity.ok().build();
    }

    private void postTransaction(String byteCode) throws IOException {

        URL myurl = new URL("http://127.0.0.1:8080/transaction/proc");
        HttpURLConnection con = (HttpURLConnection) myurl.openConnection();

        con.setDoOutput(true);
        con.setRequestMethod("POST");
        con.setRequestProperty("User-Agent", "Java client");
        con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
        con.setRequestProperty("Accept-Charset", "UTF-8");

        String urlParameters = "trans_token=" + byteCode;
        byte[] postData = urlParameters.getBytes(StandardCharsets.UTF_8);

        try (DataOutputStream wr = new DataOutputStream(con.getOutputStream())) {
            wr.write(postData);
        }

        StringBuilder content;

        try (BufferedReader in = new BufferedReader(
                new InputStreamReader(con.getInputStream(), "UTF8"))) {

            String line;
            content = new StringBuilder();

            while ((line = in.readLine()) != null) {
                content.append(line);
                content.append(System.lineSeparator());
            }
        }

    }

}
