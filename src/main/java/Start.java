import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import webserver.SetSettingFile;
import webserver.WebServer;

import java.io.IOException;
import java.net.URL;
import java.sql.Timestamp;
import java.util.Enumeration;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

public class Start {
    final static private Logger LOGGER = LoggerFactory.getLogger(Start.class.getName());

    public static void main(String args[]) throws Exception {
        LOGGER.info("Started Build " + getManifestInfo());

        new SetSettingFile().SettingFile();
        WebServer webServer = new WebServer();
        try {
            webServer.start();
        } catch (Exception e) {
            LOGGER.error(e.toString());
            System.exit(1);

        } finally {
            webServer.stop();
        }
    }

    private static String getManifestInfo() throws IOException {
        Enumeration<URL> resources = Thread.currentThread()
                .getContextClassLoader()
                .getResources("META-INF/MANIFEST.MF");
        while (resources.hasMoreElements()) {
            try {
                Manifest manifest = new Manifest(resources.nextElement().openStream());
                Attributes attributes = manifest.getMainAttributes();
                String implementationTitle = attributes.getValue("Implementation-Title");
                if (implementationTitle != null) { // && implementationTitle.equals(applicationName))
                    String implementationVersion = attributes.getValue("Implementation-Version");
                    String buildTime = attributes.getValue("Build-Time");
                    if (buildTime == null) {
                        buildTime = new Timestamp(System.currentTimeMillis()).toString();
                    }
                    return implementationVersion + " build " + buildTime;
                }
            } catch (IOException e) {
                System.out.println(e.getMessage());
            }
        }
        return "Current Version";
    }
}
