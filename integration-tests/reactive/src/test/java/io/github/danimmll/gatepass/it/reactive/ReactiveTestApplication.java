package io.github.danimmll.gatepass.it.reactive;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import io.github.danimmll.gatepass.web.InboundRules;

@SpringBootApplication
public class ReactiveTestApplication {

    @RestController
    static class OrdersController {

        @GetMapping("/orders/{id}")
        Mono<String> order(@PathVariable("id") String id) {
            return Mono.just("order " + id);
        }

        @GetMapping("/orders")
        Mono<String> page(@RequestParam("page") String page) {
            return Mono.just("page " + page);
        }

        @PostMapping("/orders")
        Mono<String> create(@RequestBody String body) {
            return Mono.just("created " + body);
        }

        @GetMapping("/caller")
        Mono<String> caller(@RequestAttribute(name = InboundRules.CALLER_ATTRIBUTE, required = false) String caller) {
            return Mono.just("caller " + caller);
        }

        @GetMapping("/admin/reindex")
        Mono<String> reindex() {
            return Mono.just("reindexed");
        }

        @GetMapping("/public/scheme")
        Mono<String> scheme(ServerHttpRequest request) {
            return Mono.just(request.getURI().getScheme() + " " + (request.getSslInfo() != null));
        }

    }

}
