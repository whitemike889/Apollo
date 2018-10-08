/*
 * Copyright © 2018 Apollo Foundation
 */

package com.apollocurrency.aplwallet.apl.http;

import com.apollocurrency.aplwallet.apl.Apl;
import com.apollocurrency.aplwallet.apl.Constants;
import com.apollocurrency.aplwallet.apl.crypto.Crypto;
import com.apollocurrency.aplwallet.apl.peer.Peers;
import com.apollocurrency.aplwallet.apl.util.Convert;
import com.apollocurrency.aplwallet.apl.util.ThreadPool;
import com.apollocurrency.aplwallet.apl.util.UPnP;
import java.io.FileNotFoundException;
import org.eclipse.jetty.security.ConstraintMapping;
import org.eclipse.jetty.security.ConstraintSecurityHandler;
import org.eclipse.jetty.security.SecurityHandler;
import org.eclipse.jetty.server.handler.ContextHandler;
import org.eclipse.jetty.server.handler.DefaultHandler;
import org.eclipse.jetty.server.handler.HandlerList;
import org.eclipse.jetty.server.handler.ResourceHandler;
import org.eclipse.jetty.server.handler.gzip.GzipHandler;
import org.eclipse.jetty.servlet.DefaultServlet;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.servlets.CrossOriginFilter;
import org.eclipse.jetty.util.security.Constraint;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.slf4j.Logger;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.math.BigInteger;
import java.net.*;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.eclipse.jetty.util.resource.Resource;
import org.eclipse.jetty.server.ResourceService;
import static org.slf4j.LoggerFactory.getLogger;


public class WebResourceService extends ResourceService {
    
    private static final Logger LOG = getLogger(WebResourceService.class);
    
    protected void NotFound(HttpServletRequest request, HttpServletResponse response)
    {
       
        LOG.info("Reached_SRAKAAA");
        try
        {
            sendWelcome(null, request.getPathInfo(), false, true, request, response);
        }
        catch (ServletException e)
        {
        
        }
        catch (IOException e)
        {
            
        }
    }
    
    @Override
    public boolean doGet(HttpServletRequest request, HttpServletResponse response)
    {
         LOG.info("Reached_SRAKAAA");
        try
            
        {
            
            if (super.doGet(request, response) == false)
            {
                LOG.info("Reached_SRAKAAA");
                sendWelcome(null, request.getPathInfo(), false, true, request, response);
            
            
            }
           
        }
        catch (ServletException e)
            {   
        
            }
            catch (IOException e)
            {
            
            }
        return false;
    }
    
}
