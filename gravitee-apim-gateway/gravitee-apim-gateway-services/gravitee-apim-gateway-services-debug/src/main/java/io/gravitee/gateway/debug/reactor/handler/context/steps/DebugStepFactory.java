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
package io.gravitee.gateway.debug.reactor.handler.context.steps;

import io.gravitee.definition.model.PolicyScope;
import io.gravitee.gateway.policy.StreamType;

/**
 * @author Yann TAVERNIER (yann.tavernier at graviteesource.com)
 * @author GraviteeSource Team
 */
public class DebugStepFactory {

    public static DebugStep<?> createExecuteDebugStep(String policyId, StreamType streamType, String uuid) {
        if (StreamType.ON_REQUEST.equals(streamType)) {
            return new DebugRequestStep(policyId, streamType, uuid, PolicyScope.ON_REQUEST);
        } else {
            return new DebugResponseStep(policyId, streamType, uuid, PolicyScope.ON_RESPONSE);
        }
    }

    public static DebugStep<?> createStreamDebugStep(String policyId, StreamType streamType, String uuid) {
        if (StreamType.ON_REQUEST.equals(streamType)) {
            return new DebugRequestStep(policyId, streamType, uuid, PolicyScope.ON_REQUEST_CONTENT);
        } else {
            return new DebugResponseStep(policyId, streamType, uuid, PolicyScope.ON_RESPONSE_CONTENT);
        }
    }
}
