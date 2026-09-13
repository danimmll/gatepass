package io.github.danimmll.gatepass.it.gatewaymvc;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.ServerResponse;

import static org.springframework.cloud.gateway.server.mvc.filter.BeforeFilterFunctions.stripPrefix;
import static org.springframework.cloud.gateway.server.mvc.filter.BeforeFilterFunctions.uri;
import static org.springframework.cloud.gateway.server.mvc.filter.LoadBalancerFilterFunctions.lb;
import static org.springframework.cloud.gateway.server.mvc.filter.RetryFilterFunctions.retry;
import static org.springframework.cloud.gateway.server.mvc.handler.GatewayRouterFunctions.route;
import static org.springframework.cloud.gateway.server.mvc.handler.HandlerFunctions.http;
import static org.springframework.web.servlet.function.RequestPredicates.path;

@SpringBootApplication
public class GatewayMvcTestApplication {

    /** An internal service found through service discovery; the /api prefix is gateway-only. */
    @Bean
    RouterFunction<ServerResponse> ordersRoute() {
        return route("orders").route(path("/api/orders/**"), http())
                .before(stripPrefix(1))
                .filter(lb("orders"))
                .build();
    }

    /** The same service behind a route that retries once when it answers with a server error. */
    @Bean
    RouterFunction<ServerResponse> flakyRoute() {
        return route("flaky").route(path("/api/flaky/**"), http())
                .before(stripPrefix(1))
                .filter(lb("orders"))
                // Gateway MVC 4.3 counts the first attempt in this number and 5.0 does not: 2 means a retry in both.
                .filter(retry(2))
                .build();
    }

    /** Something that is not one of ours. */
    @Bean
    RouterFunction<ServerResponse> externalRoute(@Value("${test.backend-url}") String backendUrl) {
        return route("external").route(path("/external/**"), http())
                .before(uri(backendUrl))
                .build();
    }

}
