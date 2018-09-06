package webserver;


import com.google.common.primitives.Bytes;
import com.google.common.primitives.Ints;
import crypto.AEScrypto;
import crypto.Base58;
import crypto.Crypto;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import utils.Pair;

import javax.ws.rs.*;
import javax.ws.rs.core.Response;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Random;

@Path("crypto")
public class ApiCrypto {

    @GET
    public Response Default() {
        JSONObject jsonObject = new JSONObject();

        jsonObject.put("crypto/generateSeed", "GenerateSeed, GET");
        jsonObject.put("crypto/generateSeed/{seed}", "Generate key pair, GET");
        jsonObject.put("crypto/encrypt", "Encrypt message, POST. Body request: {\"message\": \"test message for encrypt and decrypt\",\"publicKey\":\"{publicKey}\",\"privateKey\":\"{privateKey}\"}");
        jsonObject.put("crypto/decrypt", "Decrypt message, POST. Body request: {\"message\": \"{encrypt message Base58}\", \"publicKey\":\"{publicKey}\",\"privateKey\":\"{privateKey}\"}");
        jsonObject.put("crypto/sign", "Sign, POST. Body request: {\"message\": \"{sign this}\", \"publicKey\":\"{publicKey}\",\"privateKey\":\"{privaeKey}\"}");
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
    public Response GenerateSeed() {

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
     * @param seed is a {@link #GenerateSeed()} master key for generating key pair
     * @return key pair. Public key - byte[32], Private key - byte[64]
     */
    @GET
    @Path("generateKeyPair/{seed}")
    public Response GenerateKeyPair(@PathParam("seed") String seed) {

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
     * Encrypt message by using my private key and there public key.
     * {@link #GenerateKeyPair(String)}.
     *
     * @param encrypt is JSON contains keys and message for encrypt
     * @return JSON string contains encode Base58 message
     * @throws Exception
     */
    @POST
    @Path("encrypt")
    public Response Encrypt(String encrypt) throws Exception {

        JSONParser jsonParser = new JSONParser();
        JSONObject jsonObject = (JSONObject) jsonParser.parse(encrypt);

        String message = jsonObject.get("message").toString();

        byte[] publicKey = Base58.decode(jsonObject.get("publicKey").toString());
        byte[] privateKey = Base58.decode(jsonObject.get("privateKey").toString());

        String result = Base58.encode(AEScrypto.dataEncrypt(message.getBytes(), privateKey, publicKey));
        JSONObject jsonObjectResult = new JSONObject();
        jsonObjectResult.put("encrypted", result);
        return Response.status(200).header("Content-Type", "application/json; charset=utf-8")
                .header("Access-Control-Allow-Origin", "*")
                .entity(jsonObjectResult.toJSONString())
                .build();
    }

    /**
     * Decrypt message
     *
     * @param decrypt Json row contain keys and message for decrypt
     * @return Json string. if the decryption was successful, it will return the message in coding UTF-8.
     * If cannot decrypt return error.
     * @throws Exception
     */
    @POST
    @Path("decrypt")
    public Response Decrypt(String decrypt) throws Exception {

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
     * @param toSign JSON string contains {@link #GenerateKeyPair(String)} keyPair for sign and message
     * @return
     * @throws Exception
     */
    @POST
    @Path("sign")
    public Response Sign(String toSign) throws Exception {

        JSONParser jsonParser = new JSONParser();
        JSONObject jsonObject = (JSONObject) jsonParser.parse(toSign);
        String message = jsonObject.get("message").toString();

        Pair<byte[], byte[]> pair = new Pair<>();
        pair.setA(Base58.decode(jsonObject.get("privateKey").toString()));
        pair.setB(Base58.decode(jsonObject.get("publicKey").toString()));
        byte[] sign = Crypto.getInstance().sign(pair, message.getBytes());

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
    public Response VerifySignature(String toVerifySign) throws Exception {
        JSONParser jsonParser = new JSONParser();
        JSONObject jsonObject = (JSONObject) jsonParser.parse(toVerifySign);

        byte[] publicKey = Base58.decode(jsonObject.get("publicKey").toString());
        byte[] signature = Base58.decode(jsonObject.get("signature").toString());
        byte[] message = jsonObject.get("message").toString().getBytes();

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
        JSONObject jsonObjecttResult = new JSONObject();

        byte[] nonceBytes = Ints.toByteArray(Integer.valueOf(nonce) - 1);
        byte[] accountSeedConcat = Bytes.concat(nonceBytes, Base58.decode(seed), nonceBytes);
        byte[] accountSeed = Crypto.getInstance().doubleDigest(accountSeedConcat);

        Pair<byte[], byte[]> keyPair = Crypto.getInstance().createKeyPair(accountSeed);

        String address = Crypto.getInstance().getAddress(keyPair.getB());

        jsonObjecttResult.put("numAccount", nonce);
        jsonObjecttResult.put("accountSeed", Base58.encode(accountSeed));
        jsonObjecttResult.put("publicKey", Base58.encode(keyPair.getB()));
        jsonObjecttResult.put("privateKey", Base58.encode(keyPair.getA()));
        jsonObjecttResult.put("account", address);

        return Response.status(200).header("Content-Type", "application/json; charset=utf-8")
                .header("Access-Control-Allow-Origin", "*")
                .entity(jsonObjecttResult.toJSONString())
                .build();
    }

    /**
     * Generate random telegram
     *
     * @param count count telegram for send
     */
    @GET
    @Path("generateTelegram")
    public void generateTelegram(@QueryParam("count") Integer count) {
        JSONObject jsonObject = new JSONObject();

        ArrayList arrayList = new ArrayList() {{
            add("79MXsjo9DEaxzu6kSvJUauLhmQrB4WogsH");
            add("73FU5sBnioJVdhM6Ab9Zj665AwqkoP9o1p");
            add("7Dpv5Gi8HjCBgtDN1P1niuPJQCBQ5H8Zob");
            add("772byjS19xS7MJRMP6xw6wZsM8faRwXLYE");
            add("7LAF61f9hXhZwjDyusAVWWTbRfrJ1B4ef7");

        }};
        for (int i = 0; i < count; i++) {
int random = new Random().nextInt();

        }

    }
}
