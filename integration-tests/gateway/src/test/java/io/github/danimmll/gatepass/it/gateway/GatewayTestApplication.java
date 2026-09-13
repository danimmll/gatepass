package io.github.danimmll.gatepass.it.gateway;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;

@SpringBootApplication
public class GatewayTestApplication {

    @Bean
    RouteLocator routes(RouteLocatorBuilder builder, @Value("${test.backend-url}") String backendUrl) {
        return builder.routes()
                // An internal service found through service discovery; the /api prefix is gateway-only.
                .route("orders", route -> route.path("/api/orders/**").filters(filter -> filter.stripPrefix(1))
                        .uri("lb://orders"))
                // The same service behind a route that retries once when it answers 503.
                .route("flaky", route -> route.path("/api/flaky/**")
                        .filters(filter -> filter.stripPrefix(1)
                                .retry(retry -> retry.setRetries(1).setStatuses(HttpStatus.SERVICE_UNAVAILABLE)))
                        .uri("lb://orders"))
                // Something that is not one of ours.
                .route("external", route -> route.path("/external/**").uri(backendUrl))
                .build();
    }

}
