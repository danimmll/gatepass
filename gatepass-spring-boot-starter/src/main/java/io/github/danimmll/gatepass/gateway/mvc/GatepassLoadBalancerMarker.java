package io.github.danimmll.gatepass.gateway.mvc;

import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.loadbalancer.CompletionContext;
import org.springframework.cloud.client.loadbalancer.LoadBalancerLifecycle;
import org.springframework.cloud.client.loadbalancer.Request;
import org.springframework.cloud.client.loadbalancer.RequestDataContext;
import org.springframework.cloud.client.loadbalancer.Response;

/**
 * Marks the requests Spring Cloud Gateway Server MVC load balances, so that {@link GatepassGatewayMvcHeadersFilter}
 * signs {@code lb://} routes by default and nothing else.
 *
 * <p>Gateway MVC hands the load balancer the request's own attribute map, and the load balancer hands it to its
 * lifecycle callbacks: this puts a flag in it once an instance has been chosen.
 */
public class GatepassLoadBalancerMarker implements LoadBalancerLifecycle<Object, Object, ServiceInstance> {

    @Override
    public void onStart(Request<Object> request) {
    }

    @Override
    public void onStartRequest(Request<Object> request, Response<ServiceInstance> lbResponse) {
        if (lbResponse.hasServer() && request.getContext() instanceof RequestDataContext context) {
            try {
                context.getClientRequest().getAttributes().put(GatepassGatewayMvcHeadersFilter.LOAD_BALANCED_ATTRIBUTE,
                        Boolean.TRUE);
            }
            catch (UnsupportedOperationException ex) {
                // Another kind of client, with read-only attributes: not a gateway request, nothing to mark.
            }
        }
    }

    @Override
    public void onComplete(CompletionContext<Object, ServiceInstance, Object> completionContext) {
    }

}
