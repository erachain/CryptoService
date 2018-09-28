package webserver;

import org.eclipse.jetty.server.NCSARequestLog;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.DefaultHandler;
import org.eclipse.jetty.server.handler.HandlerList;
import org.eclipse.jetty.server.handler.InetAccessHandler;
import org.eclipse.jetty.server.handler.RequestLogHandler;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.RolloverFileOutputStream;
import org.eclipse.jetty.util.log.Log;
import org.glassfish.jersey.media.multipart.MultiPartFeature;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.util.HashSet;
import java.util.Set;

import static org.eclipse.jetty.servlet.ServletContextHandler.NO_SESSIONS;


public class WebServer extends SetSettingFile {
    private Server server;
    final static private Logger LOGGER = LoggerFactory.getLogger(WebServer.class);

    public WebServer() throws IOException {

        //CREATE WEB SERVER
        server = new Server(new InetSocketAddress(SERVER_BIND,SERVER_PORT));

        Set<Class<?>> s = new HashSet<>();
        s.add(ApiCrypto.class);
        ResourceConfig config = new ResourceConfig(s);
        config.register(MultiPartFeature.class);

        //CREATE CONTAINER
        ServletContainer container = new ServletContainer(config);

        //CREATE CONTEXT
        ServletContextHandler context = new ServletContextHandler(NO_SESSIONS);
        context.setContextPath("/");
        context.addServlet(new ServletHolder(container), "/*");

        //CREATE WHITELIST
        InetAccessHandler accessHandler = new InetAccessHandler();
        String[] whiteList = new String[WHITE_LIST.size()];
        for (int i = 0; i < WHITE_LIST.size(); i++) {
            whiteList[i] = WHITE_LIST.get(i);
        }
        accessHandler.include(whiteList);
        accessHandler.setHandler(context);

        //CONFIGURE LOGGING
        RolloverFileOutputStream os = null;
        try {
            os = new RolloverFileOutputStream("yyyy_mm_dd_crypto.log", true);
        } catch (IOException e) {
            throw e;
        }
        PrintStream logStream = new PrintStream(os);
        System.setOut(logStream);
        System.setErr(logStream);

        //CREATE REQUEST LOG HANDLER
        NCSARequestLog requestLog = new NCSARequestLog(os.getDatedFilename());
        requestLog.setExtended(true);
        RequestLogHandler requestLogHandler = new RequestLogHandler();
        requestLogHandler.setRequestLog(requestLog);
        requestLog.setAppend(true);

        HandlerList mainHandlers = new HandlerList();
        mainHandlers.addHandler(accessHandler);
        mainHandlers.addHandler(new DefaultHandler());

        requestLogHandler.setHandler(mainHandlers);

        HandlerList topLevelHandlers = new HandlerList();
        topLevelHandlers.addHandler(requestLogHandler);

        server.setHandler(topLevelHandlers);
    }

    public void start() throws Exception {
        try {
            //START WEB
            LOGGER.info("Start web server");
            Log.getRootLogger().info("Embedded logging started", new Object[]{});
            server.start();
            server.join();
        } catch (Exception e) {
            LOGGER.error("Error while starting Jetty ", e);
            //FAILED TO START WEB
            throw e;
        }
    }

    public void stop() throws Exception {
        try {
            //STOP RPC
            LOGGER.info("Stop web server");
            server.stop();
        } catch (Exception e) {
            //FAILED TO STOP WEB
            LOGGER.error("Error while stopping Jetty ", e);
            throw e;
        }
    }
}
