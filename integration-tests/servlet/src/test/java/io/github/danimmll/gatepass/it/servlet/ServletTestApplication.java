package io.github.danimmll.gatepass.it.servlet;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import io.github.danimmll.gatepass.web.InboundRules;

/**
 * A service that calls itself through Feign, so the same process is both the sender and the receiver.
 */
@SpringBootApplication
@EnableFeignClients(clients = { ServletTestApplication.OrdersClient.class, ServletTestApplication.PrefixedClient.class,
        ServletTestApplication.ThirdPartyClient.class })
public class ServletTestApplication {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(auth -> auth.requestMatchers("/secured").authenticated().anyRequest().permitAll())
                .httpBasic(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable)
                .build();
    }

    @RestController
    static class OrdersController {

        @GetMapping("/orders/{id}")
        String order(@PathVariable("id") String id) {
            return "order " + id;
        }

        @GetMapping("/orders")
        String page(@RequestParam("page") String page) {
            return "page " + page;
        }

        @PostMapping("/orders")
        String create(@RequestBody String body) {
            return "created " + body;
        }

        @PostMapping(value = "/forms", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        String form(@RequestParam("item") String item, @RequestParam("size") String size) {
            return "form " + item + " " + size;
        }

        @GetMapping("/api")
        String apiRoot() {
            return "api root";
        }

        @GetMapping("/secured")
        String secured() {
            return "secured";
        }

        @GetMapping("/caller")
        String caller(@RequestAttribute(name = InboundRules.CALLER_ATTRIBUTE, required = false) String caller) {
            return "caller " + caller;
        }

        @GetMapping("/admin/reindex")
        String reindex() {
            return "reindexed";
        }

        @GetMapping("/public/secure")
        String secure(HttpServletRequest request) {
            return String.valueOf(request.isSecure());
        }

    }

    @FeignClient(name = "orders", url = "${test.self-url}")
    interface OrdersClient {

        @GetMapping("/orders/{id}")
        String order(@PathVariable("id") String id);

        @GetMapping("/orders")
        String page(@RequestParam("page") String page);

        @PostMapping(value = "/orders", consumes = "text/plain")
        String create(@RequestBody String body);

        @GetMapping("/caller")
        String caller();

    }

    /** Its base URL carries a path, and its only method is mapped to that path itself. */
    @FeignClient(name = "prefixed", url = "${test.self-url}", path = "/api")
    interface PrefixedClient {

        @GetMapping
        String root();

    }

    /** Stands in for a client of someone else's API: not listed in gatepass.feign.clients. */
    @FeignClient(name = "third-party", url = "${test.self-url}")
    interface ThirdPartyClient {

        @GetMapping("/orders/{id}")
        String order(@PathVariable("id") String id);

    }

}
