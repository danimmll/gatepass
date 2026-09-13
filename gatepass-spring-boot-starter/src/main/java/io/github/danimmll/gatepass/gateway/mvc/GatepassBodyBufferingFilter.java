package io.github.danimmll.gatepass.gateway.mvc;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.core.Ordered;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Lets {@link GatepassGatewayMvcHeadersFilter} sign request bodies in Spring Cloud Gateway Server MVC.
 *
 * <p>Gateway MVC proxies the body straight from the servlet request, so a body read to sign it would be gone by the
 * time it is forwarded. This filter wraps each request so its body can be read into memory once, when a route needs it
 * signed, and forwarded from there. Bodies of routes that are not signed keep streaming. It runs last, so that its
 * wrapper is the request the gateway proxies.
 */
public class GatepassBodyBufferingFilter extends OncePerRequestFilter implements Ordered {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        filterChain.doFilter(new BufferedBodyRequest(request), response);
    }

    @Override
    public int getOrder() {
        return Ordered.LOWEST_PRECEDENCE;
    }

}
