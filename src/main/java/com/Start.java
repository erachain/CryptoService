package com;

import org.apache.log4j.PropertyConfigurator;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.web.servlet.DispatcherServletAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.web.servlet.DispatcherServlet;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Enumeration;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

@SpringBootApplication
public class Start {

    @Bean(name = DispatcherServletAutoConfiguration.DEFAULT_DISPATCHER_SERVLET_BEAN_NAME)
    public DispatcherServlet dispatcherServlet() {
        return new Logging();
    }

    public static void main(String args[]) throws Exception {

        SpringApplication.run(Start.class);

        System.out.println("Build info: " + getManifestInfo());
        File log4j = new File("src\\main\\resources\\log4j.properties");
        if (log4j.exists()) {
            PropertyConfigurator.configure(log4j.getAbsolutePath());
        }
        else {
            try (InputStream inputStream = ClassLoader.class.getResourceAsStream("/log4j/log4j.default")) {
                PropertyConfigurator.configure(inputStream);
            }
            catch (Exception e) {
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
                if (implementationTitle != null) {
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
