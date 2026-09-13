package io.github.danimmll.gatepass.gateway.mvc;

import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.cloud.client.DefaultServiceInstance;
import org.springframework.cloud.client.loadbalancer.DefaultRequest;
import org.springframework.cloud.client.loadbalancer.DefaultResponse;
import org.springframework.cloud.client.loadbalancer.EmptyResponse;
import org.springframework.cloud.client.loadbalancer.RequestData;
import org.springframework.cloud.client.loadbalancer.RequestDataContext;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.util.LinkedMultiValueMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

class GatepassLoadBalancerMarkerTest {

    private final GatepassLoadBalancerMarker marker = new GatepassLoadBalancerMarker();

    @Test
    void marksTheRequestOnceAnInstanceHasBeenChosen() {
        Map<String, Object> attributes = new HashMap<>();

        this.marker.onStartRequest(request(attributes),
                new DefaultResponse(new DefaultServiceInstance("orders-1", "orders", "localhost", 8080, false)));

        assertThat(attributes).containsEntry(GatepassGatewayMvcHeadersFilter.LOAD_BALANCED_ATTRIBUTE, true);
    }

    @Test
    void leavesTheRequestAloneWhenNoInstanceWasFound() {
        Map<String, Object> attributes = new HashMap<>();

        this.marker.onStartRequest(request(attributes), new EmptyResponse());

        assertThat(attributes).isEmpty();
    }

    @Test
    void ignoresClientsWhoseAttributesAreReadOnly() {
        assertThatNoException().isThrownBy(() -> this.marker.onStartRequest(request(Collections.emptyMap()),
                new DefaultResponse(new DefaultServiceInstance("orders-1", "orders", "localhost", 8080, false))));
    }

    private static DefaultRequest<Object> request(Map<String, Object> attributes) {
        RequestData data = new RequestData(HttpMethod.GET, URI.create("http://orders/a"), new HttpHeaders(),
                new LinkedMultiValueMap<>(), attributes);
        return new DefaultRequest<>(new RequestDataContext(data));
    }

}
