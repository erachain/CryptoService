package com;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.IOException;
import java.net.URL;
import java.util.Enumeration;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

@SpringBootApplication
public class Start {
    private static final Logger LOGGER = LoggerFactory.getLogger(Start.class);

    public static void main(String args[]) throws Exception {
        LOGGER.info("Started Build " + getManifestInfo());

        SpringApplication.run(Start.class);
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
