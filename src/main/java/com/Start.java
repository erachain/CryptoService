package com;

import org.apache.log4j.PropertyConfigurator;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Enumeration;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

@SpringBootApplication
public class Start {
    // static org.apache.log4j.Logger LOGGER = Logger.getLogger(Start.class.getName());

    public static void main(String args[]) throws Exception {

        SpringApplication.run(Start.class);

        System.out.println("Build info: " + getManifestInfo());

        File log4j = new File("log4j.properties");
        if (log4j.exists()) {
            PropertyConfigurator.configure(log4j.getAbsolutePath());
        } else {
            try (InputStream inputStream = ClassLoader.class.getResourceAsStream("/log4j/log4j.default")) {
                PropertyConfigurator.configure(inputStream);
                //        LOGGER.error("log4j.properties not found: " + log4j.getAbsolutePath() + ", using default.");
            } catch (Exception e) {
                System.out.println("Error: missing configuration log4j file.");
                System.exit(-1);
            }
        }
    }

    public static String getManifestInfo() throws IOException {
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
                    return implementationVersion + " build " + buildTime;
                }
            } catch (IOException e) {
                System.out.println(e.getMessage());
            }
        }
        return "Current Version";
    }
}
