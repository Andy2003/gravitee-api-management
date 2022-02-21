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
package io.gravitee.rest.api.management.rest.resource;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.rest.api.model.ApiKeyEntity;
import java.util.List;
import javax.ws.rs.core.GenericType;
import javax.ws.rs.core.Response;

import io.gravitee.rest.api.model.SubscriptionEntity;
import org.junit.Before;
import org.junit.Test;

/**
 * @author GraviteeSource Team
 */
public class ApplicationSubscriptionApikeysResourceTest extends AbstractResourceTest {

    private static final String APPLICATION_ID = "my-application";
    private static final String SUBSCRIPTION_ID = "my-subscription";

    @Override
    protected String contextPath() {
        return "applications/" + APPLICATION_ID + "/subscriptions/" + SUBSCRIPTION_ID + "/apikeys";
    }

    @Before
    public void setUp() {
        reset(apiKeyService);
    }

    @Test
    public void get_should_return_apikeys_list_from_service_with_http_200() {
        ApiKeyEntity apiKeyFromService = new ApiKeyEntity();
        apiKeyFromService.setId("test-id");
        List<ApiKeyEntity> apiKeysFromService = List.of(apiKeyFromService);
        when(apiKeyService.findBySubscription(SUBSCRIPTION_ID)).thenReturn(apiKeysFromService);

        Response response = envTarget().request().get();

        assertEquals(HttpStatusCode.OK_200, response.getStatus());
        assertEquals(apiKeysFromService, response.readEntity(new GenericType<List<ApiKeyEntity>>() {}));
    }

    @Test
    public void post_on_renew_should_return_renew_apikeys_and_return_http_201_with_location_header() {
        ApiKeyEntity renewedApiKey = new ApiKeyEntity();
        SubscriptionEntity subscription = new SubscriptionEntity();

        renewedApiKey.setId("test-id");
        when(apiKeyService.renew(subscription)).thenReturn(renewedApiKey);

        Response response = envTarget("/_renew").request().post(null);

        assertEquals(HttpStatusCode.CREATED_201, response.getStatus());
        assertEquals(renewedApiKey, response.readEntity(ApiKeyEntity.class));
        assertTrue(
            response.getLocation().toString().endsWith("/applications/my-application/subscriptions/my-subscription/apikeys/test-id")
        );
    }
}
