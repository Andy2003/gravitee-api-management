/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.gateway.platform.providers;

import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.buffer.Buffer;
import io.gravitee.gateway.core.processor.StreamableProcessor;
import io.gravitee.gateway.flow.FlowProvider;
import io.gravitee.gateway.flow.FlowResolver;
import io.gravitee.gateway.flow.policy.PolicyChainFactory;
import io.gravitee.gateway.platform.OrganizationFlowProvider;
import io.gravitee.gateway.policy.ConfigurablePolicyChainProvider;
import io.gravitee.gateway.policy.PolicyChainOrder;
import io.gravitee.gateway.policy.StreamType;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * @author Guillaume CUSNIEUX (guillaume.cusnieux at graviteesource.com)
 * @author GraviteeSource Team
 */
public class OnRequestPlatformPolicyChainProvider extends ConfigurablePolicyChainProvider {

    private final StreamType streamType = StreamType.ON_REQUEST;

    private final FlowResolver flowResolver;
    private final PolicyChainFactory policyChainFactory;

    private FlowProvider flowProvider;

    public OnRequestPlatformPolicyChainProvider(FlowResolver flowResolver, PolicyChainFactory policyChainFactory) {
        this.flowResolver = flowResolver;
        this.policyChainFactory = policyChainFactory;
    }

    @Override
    public StreamableProcessor<ExecutionContext, Buffer> provide(ExecutionContext context) {
        return getFlowProvider().provide(context);
    }

    private FlowProvider getFlowProvider() {
        if (this.flowProvider == null) {
            flowProvider = new OrganizationFlowProvider(streamType, flowResolver, policyChainFactory);
        }
        return flowProvider;
    }

    @Override
    public StreamType getStreamType() {
        return streamType;
    }

    @Override
    public PolicyChainOrder getChainOrder() {
        return PolicyChainOrder.BEFORE_API;
    }
}
