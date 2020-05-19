package com.webserver;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

@Configuration
public class SetSettingFile {
    static Integer SERVER_PORT;
    static String SERVER_BIND;
    static ArrayList<String> WHITE_LIST = new ArrayList<>();
    static String SEED_CREATOR;
    static String SEED_RECIPIENT;
    static boolean DEVELOP_USE = true;
    static public Integer NET_PORT = DEVELOP_USE? 9066 : 9046;
    static Integer API_PORT = DEVELOP_USE? 9067 : 9047;
    static Integer RPC_PORT = DEVELOP_USE? 9068 : 9048;
    static Map ADDRESS_API = new HashMap();
    static Map ADDRESS_RPC = new HashMap();
    static Map NODES_RPC = new HashMap();
    private final static Logger LOGGER = LoggerFactory.getLogger(SetSettingFile.class);

    /**
     * Create setting file if not exist and read file.
     *
     * @throws Exception
     */
    @Bean
    public String SettingFile() throws Exception {
        File setting = new File("setting.json");

        if (!setting.exists()) {
            JSONObject jsonObject = new JSONObject();
            FileWriter fileWriter = new FileWriter("setting.json");

            NODES_RPC = DEVELOP_USE? new HashMap() {{
                // IP - PUBLIC KEY + PASSWORD
                put("46.101.108.143", "123456789"); // era-59
                put("207.154.246.66", "123456789"); // era-60
                put("207.154.242.242", "123456789"); // era-61
                put("138.197.178.85", "123456789"); // era-62
                put("89.235.184.251", "123456789"); // idSys
            }} : new HashMap() {{
                // IP - PUBLIC KEY + PASSWORD
                put("138.68.186.214", "123456789");
                put("193.42.145.120", "123456789");
            }};

            /**
             * test node (era 59,60,61,62,idSys)
             */
            ADDRESS_API = DEVELOP_USE? new HashMap() {{
                // IP - PUBLIC KEY + PASSWORD
                put("ADdtwo8XHwfbsNiTSikrpFHiHBANqUrBMJQxhvg4JRgV", "46.101.108.143"); // era-59
                put("ABRjfyP7zVdtuuhEaTogtcJNUdU1hcop4zG4z2JiVjhR", "207.154.246.66"); // era-60
                put("9EVLYvNzyxMdGcKJ39ousJbTxGkAvoiLuTaJZdfPcdyX", "207.154.242.242"); // era-61
                put("6Z7wVN265F8WDFJHF2vWRPgryHs4jZp6oNuqoojwrQm7", "138.197.178.85"); // era-62
                put("FwLWGTTDEjTmJPQqrWwAWoi8dT5zwrmZiRkLUoQVkzRy", "89.235.184.251"); // idSys
            }} : new HashMap() {{
                // IP - PUBLIC KEY + PASSWORD
                put("ADdtwo8XHwfbsNiTSikrpFHiHBANqUrBMJQxhvg4JRgV", "138.68.186.214");
                put("ABRjfyP7zVdtuuhEaTogtcJNUdU1hcop4zG4z2JiVjhR", "193.42.145.120");
            }};

            ADDRESS_RPC = DEVELOP_USE? new HashMap<String, String[]>() {{
                // era-59
                put("7NjNvwnoYwDztZqn3BjtkWDTCeRBegYfoG", new String[]{"46.101.108.143", "123456789"});
                put("7CvpXXALviZPkZ9Yn27NncLVz6SkxMA8rh", new String[]{"46.101.108.143", "123456789"});

                // era-60
                put("7QCd1S8ryKo1dcdH4UMbSZ9dTr9YmmLTF4", new String[]{"207.154.246.66", "123456789"});
                put("7MPgHYphmXEj1HdvyGW1MpEDmwbVaGUEvY", new String[]{"207.154.246.66", "123456789"});

                // era-61
                put("7LAasb629P8JZQkT5ug4Ff1f9CAMSmgTQr", new String[]{"207.154.242.242", "123456789"});
                put("7S1iFFPHhQGVT7cgoeemetqGgndNJELZga", new String[]{"207.154.242.242", "123456789"});

                // era-62
                put("7PEJZdCYjUjCJzeET9T8mCKjhK6xVmeZ1v", new String[]{"138.197.178.85", "123456789"});
                put("7GeTNHQrnfpCt7QxVrBgzwgnxrwNGvPqiC", new String[]{"138.197.178.85", "123456789"});

                // idSys - возможно тут стоит защита от ДОСС атка и ответ ноды задерживаеется
                // и поэтому тес торрмозится надолго - на 10 минут почти - и идет волнами
                ////////////////// ДА ВСЕ НОДЫ банят друг друга при больших нагрузках
                put("7KUwY7UfA9mjT9zXtgQFKEuXPcWZujPhNZ", new String[]{"89.235.184.251", "123456789"});
                put("74sgz2vMmakR38ZAsbCSckSFCD8WiPidKg", new String[]{"89.235.184.251", "123456789"});



            }} : new HashMap() {{
                    put("7LbRHMdbqCWYHyaahvce2TfdDhFMhzXFXe", new String[]{"138.68.232.232", "checkit"});
                    put("7AoUKTECTPeLc9Y6XfMESP4wRUctYih9AE", new String[]{"138.68.232.232", "checkit"});

                    put("77Pcv8oZChayKZvdt3dNjAVSryvp1JaPoh", new String[]{"138.68.161.215", "checkit"});
                    put("74xteUZYb8fXvEJCHZjRtUU7MySFxbrS2a", new String[]{"138.68.161.215", "checkit"});

                    put("7PJkqtHLhmXL24J9wiXLzfA3JxceWYWdyH", new String[]{"138.68.174.208", "checkit"});
                    put("7QbhYbB6aDmwTFsQGkp4VDSUUCeJQnkTZC", new String[]{"138.68.174.208", "checkit"});

                    put("7QmyokwesG4mri3qR5VcrXQvnPAAsEksVN", new String[]{"46.101.22.105", "checkit"});
                    put("7Qu6qfRofWVshLTkJyiA5G4eDJqzMyKFiE", new String[]{"46.101.22.105", "checkit"});

                    put("7Qz677DcyMNZewiLt6rRv4fzWLMnwNxAHK", new String[]{"46.101.12.64", "checkit"});
                    put("7GhvmVa3NTEPrUT1bLkzg6rsKp8Z8ooy2e", new String[]{"46.101.12.64", "checkit"});

                    put("7Hq68MfBaw2TSsbuF9GXueQJSzuHLuH7yn", new String[]{"46.101.14.242", "checkit"});
                    put("7AuPRntEtBY2qM2ujR75HoN2Db4kr1zMRR", new String[]{"46.101.14.242", "checkit"});

                    put("75PusANxJ4mptCVk8xtrxiXMQCbHSpziai", new String[]{"188.166.174.231", "checkit"});
                    put("7PfvDaFK3tW8vVgZtqVyNJKqr2yCu7jaeA", new String[]{"188.166.174.231", "checkit"});

                    put("7M5r8FYrHv8SG5YotJA1pzYNoGMZiXFKuc", new String[]{"46.101.22.105", "checkit"});
                    put("7GwTd1LBkhZeAczhaLhg3QGF7ME6LG27gR", new String[]{"46.101.22.105", "checkit"});

                    put("7NL9XsM1gkqmwWyaGXbqvvuCKDcfnnBsxw", new String[]{"138.197.143.167", "checkit"});
                    put("75L4UFRv7QRHvaZw2LvaXbh7PoBr8LWWT7", new String[]{"138.197.143.167", "checkit"});

                    put("79Bgh3wL1tDWU1SeiJ93k2gu2xVaoPPjHa", new String[]{"138.68.225.51", "checkit"});
                    put("7JdL2f8o1X12fyFCJa8NTsrY5kStwjqxQb", new String[]{"138.68.225.51", "checkit"});

                }} ;

            JSONObject nodes_rpc = new JSONObject();
            for (Object key: NODES_RPC.keySet()) {
                nodes_rpc.put((String) key, (String) NODES_RPC.get((String) key));
            }

            JSONObject wallets_api = new JSONObject();
            for (Object key: ADDRESS_API.keySet()) {
                wallets_api.put((String) key, (String) ADDRESS_API.get((String) key));
            }

            JSONObject wallets_rpc = new JSONObject();
            for (Object key: ADDRESS_RPC.keySet()) {
                String[] info = (String[]) ADDRESS_RPC.get((String) key);
                JSONArray array = new JSONArray();
                array.add(info[0]);
                array.add(info[1]);
                wallets_rpc.put((String) key, array);
            }

            ArrayList<String> arrayList = new ArrayList<>();
            jsonObject.put("bind", "127.0.0.1");
            arrayList.add("127.0.0.1");
            jsonObject.put("port", "8181");
            jsonObject.put("ip", arrayList);
            jsonObject.put("nodes_rpc", new JSONObject(nodes_rpc));
            jsonObject.put("wallets_api", new JSONObject(wallets_api));
            jsonObject.put("wallets_rpc", new JSONObject(wallets_rpc));
            jsonObject.put("seed_creator", "FwLWGTTDEjTmJPQqrWwAWoi8dT5zwrmZiRkLUoQVkzRy");
            jsonObject.put("seed_recipient","3mhnpNULsG8qKgwFresGvY5uVw1ETXSgS4cPx7avZjpP");
            fileWriter.write(jsonObject.toJSONString());
            fileWriter.flush();
            fileWriter.close();
        }

        try {
            BufferedReader bufferedReader = new BufferedReader(new FileReader(setting));
            String line;
            String fileSetting = "";

            while ((line = bufferedReader.readLine()) != null) {
                fileSetting += line;
            }

            JSONParser jsonParser = new JSONParser();
            JSONObject jsonObject = (JSONObject) jsonParser.parse(fileSetting);
            SERVER_BIND = jsonObject.get("bind").toString();
            SERVER_PORT = Integer.parseInt(jsonObject.get("port").toString());
            SEED_CREATOR = jsonObject.get("seed_creator").toString();
            LOGGER.info("CREATOR: " + SEED_CREATOR);
            SEED_RECIPIENT=jsonObject.get("seed_recipient").toString();
            LOGGER.info("RECIPIENT: " + SEED_RECIPIENT);
            JSONArray jsonArray = (JSONArray) jsonObject.get("ip");
            JSONObject jsonArrayNodes_RPC = (JSONObject) jsonObject.get("nodes_rpc");
            JSONObject jsonArrayWallets_API = (JSONObject) jsonObject.get("wallets_api");
            JSONObject jsonArrayWallets_RPC = (JSONObject) jsonObject.get("wallets_rpc");

            for (Object aJsonArray : jsonArray) {
                WHITE_LIST.add(aJsonArray.toString());
            }

            for (Object key : jsonArrayNodes_RPC.keySet()) {
                NODES_RPC.put(key, jsonArrayNodes_RPC.get(key));
            }

            for (Object key : jsonArrayWallets_API.keySet()) {
                ADDRESS_API.put(key, jsonArrayWallets_API.get(key));
            }

            for (Object key : jsonArrayWallets_RPC.keySet()) {
                ADDRESS_RPC.put(key, jsonArrayWallets_RPC.get(key));
            }

        } catch (Exception e) {
            throw new Exception(e);
        }
        return "";
    }

    public static String ResponseValueAPI(String urlNode, String requestMethod, String value) throws Exception {

        URL obj = new URL(urlNode);
        HttpURLConnection con = (HttpURLConnection) obj.openConnection();

        con.setRequestMethod(requestMethod.toUpperCase());
        con.setConnectTimeout(1000);
        switch (requestMethod.toUpperCase()) {
            case "GET":
                con.setRequestMethod("GET");
                con.setDoOutput(true);
                break;
            case "POST":
                con.setRequestMethod("POST");
                con.setDoOutput(true);
                con.getOutputStream().write(value.getBytes(StandardCharsets.UTF_8));
                con.getOutputStream().flush();
                break;
        }
        con.getOutputStream().close();

        BufferedReader in = new BufferedReader(
                new InputStreamReader(con.getInputStream()));
        String inputLine;
        StringBuffer response = new StringBuffer();

        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
            response.append(in.readLine());
        }
        in.close();

        String str = response.toString();

        // почемуто на конце добавляется null
        if (str.endsWith("null")) {
            int cutInx = str.lastIndexOf("null");
            str = str.substring(0, cutInx);
        }

        return str;
    }
}
