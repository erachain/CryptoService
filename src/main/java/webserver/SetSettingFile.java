package webserver;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

public class SetSettingFile {
    static Integer SERVER_PORT;
    static String SERVER_BIND;
    static ArrayList<String> WHITE_LIST = new ArrayList<>();
    static String SEED_CREATOR;
    static String SEED_RECIPIENT;
    final static private Logger LOGGER = LoggerFactory.getLogger(SetSettingFile.class);

    /**
     * Create setting file if not exist and read file.
     *
     * @throws Exception
     */
    public void SettingFile() throws Exception {
        File setting = new File("setting.json");

        if (!setting.exists()) {
            JSONObject jsonObject = new JSONObject();
            FileWriter fileWriter = new FileWriter("setting.json");

            ArrayList<String> arrayList = new ArrayList<>();
            jsonObject.put("bind", "127.0.0.1");
            arrayList.add("127.0.0.1");
            jsonObject.put("port", "8181");
            jsonObject.put("ip", arrayList);
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

            for (Object aJsonArray : jsonArray) {
                WHITE_LIST.add(aJsonArray.toString());
            }
        } catch (Exception e) {
            throw new Exception(e);
        }
    }

    public String ResponseValueAPI(String urlNode, String requestMethod, String value) throws Exception {

        URL obj = new URL(urlNode);
        HttpURLConnection con = (HttpURLConnection) obj.openConnection();

        con.setRequestMethod(requestMethod.toUpperCase());

        switch (requestMethod.toUpperCase()) {
            case "GET":
                con.setRequestMethod("GET");
                break;
            case "POST":
                con.setRequestMethod("POST");
                con.setDoOutput(true);
                con.getOutputStream().write(value.getBytes(StandardCharsets.UTF_8));
                con.getOutputStream().flush();
                con.getOutputStream().close();
                break;
        }

        BufferedReader in = new BufferedReader(
                new InputStreamReader(con.getInputStream()));
        String inputLine;
        StringBuffer response = new StringBuffer();

        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
            response.append(in.readLine());
        }
        in.close();
        return response.toString();
    }
}
