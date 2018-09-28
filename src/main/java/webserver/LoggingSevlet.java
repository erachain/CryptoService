package webserver;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet(urlPatterns = "/")
public class LoggingSevlet extends HttpServlet {
    static Logger LOGGER = LoggerFactory.getLogger(LoggingSevlet.class);

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setContentType("text/plain");
        resp.setStatus(HttpServletResponse.SC_OK);
        resp.getWriter().println("LoggingServlet called");
        LOGGER.info("-- LoggingServlet called --");
        System.out.println(req.getParts());
        super.doGet(req, resp);
    }
}
