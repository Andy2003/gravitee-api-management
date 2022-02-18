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
package io.gravitee.rest.api.service.impl;

import static io.gravitee.repository.management.model.ApiKey.AuditEvent.*;
import static io.gravitee.repository.management.model.Audit.AuditProperties.*;
import static java.util.stream.Collectors.*;
import static org.apache.commons.lang3.StringUtils.*;

import io.gravitee.repository.exceptions.TechnicalException;
import io.gravitee.repository.management.api.ApiKeyRepository;
import io.gravitee.repository.management.api.search.ApiKeyCriteria;
import io.gravitee.repository.management.model.ApiKey;
import io.gravitee.repository.management.model.ApiKeyMode;
import io.gravitee.repository.management.model.Audit;
import io.gravitee.rest.api.model.*;
import io.gravitee.rest.api.model.api.ApiEntity;
import io.gravitee.rest.api.model.key.ApiKeyQuery;
import io.gravitee.rest.api.model.subscription.SubscriptionQuery;
import io.gravitee.rest.api.service.*;
import io.gravitee.rest.api.service.common.GraviteeContext;
import io.gravitee.rest.api.service.common.UuidString;
import io.gravitee.rest.api.service.exceptions.*;
import io.gravitee.rest.api.service.notification.ApiHook;
import io.gravitee.rest.api.service.notification.NotificationParamsBuilder;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author Nicolas GERAUD (nicolas.geraud at graviteesource.com)
 * @author GraviteeSource Team
 */
@Component
public class ApiKeyServiceImpl extends TransactionalService implements ApiKeyService {

    /**
     * Logger.
     */
    private final Logger LOGGER = LoggerFactory.getLogger(ApiKeyServiceImpl.class);

    @Autowired
    private ApiKeyRepository apiKeyRepository;

    @Autowired
    private SubscriptionService subscriptionService;

    @Autowired
    private ApiKeyGenerator apiKeyGenerator;

    @Autowired
    private ApplicationService applicationService;

    @Autowired
    private ApiService apiService;

    @Autowired
    private PlanService planService;

    @Autowired
    private AuditService auditService;

    @Autowired
    private NotifierService notifierService;

    @Override
    public ApiKeyEntity generate(String subscription) {
        return generate(subscription, null);
    }

    @Override
    public ApiKeyEntity generate(String subscription, String customApiKey) {
        try {
            LOGGER.debug("Generate an API Key for subscription {}", subscription);

            ApiKey apiKey = generateForSubscription(subscription, customApiKey);
            apiKey = apiKeyRepository.create(apiKey);

            //TODO: Send a notification to the application owner

            // Audit
            createAuditLog(apiKey, null, APIKEY_CREATED, apiKey.getCreatedAt());

            return convert(apiKey);
        } catch (TechnicalException ex) {
            LOGGER.error("An error occurs while trying to generate an API Key for {}", subscription, ex);
            throw new TechnicalManagementException(
                String.format("An error occurs while trying to generate an API Key for %s", subscription),
                ex
            );
        }
    }

    @Override
    public ApiKeyEntity renew(String subscription) {
        return renew(subscription, null);
    }

    @Override
    public ApiKeyEntity renew(String subscription, String customApiKey) {
        try {
            LOGGER.debug("Renew API Key for subscription {}", subscription);

            ApiKey newApiKey = generateForSubscription(subscription, customApiKey);
            newApiKey = apiKeyRepository.create(newApiKey);

            Instant expirationInst = newApiKey.getCreatedAt().toInstant().plus(Duration.ofHours(2));
            Date expirationDate = Date.from(expirationInst);

            // Previously generated keys should be set as revoked
            // Get previously generated keys to set their expiration date
            Set<ApiKey> oldKeys = apiKeyRepository.findBySubscription(subscription);
            for (ApiKey oldKey : oldKeys) {
                ApiKeyEntity oldKeyEntity = convert(oldKey);
                if (!oldKey.equals(newApiKey) && !oldKeyEntity.isExpired()) {
                    setExpiration(expirationDate, oldKeyEntity, oldKey);
                }
            }

            // Audit
            createAuditLog(newApiKey, null, APIKEY_RENEWED, newApiKey.getCreatedAt());

            // Notification
            triggerNotifierService(ApiHook.APIKEY_RENEWED, newApiKey);

            return convert(newApiKey);
        } catch (TechnicalException ex) {
            LOGGER.error("An error occurs while trying to renew an API Key for {}", subscription, ex);
            throw new TechnicalManagementException(
                String.format("An error occurs while trying to renew an API Key for %s", subscription),
                ex
            );
        }
    }

    /**
     * Generate an {@link ApiKey} from a subscription
     *
     * @param subscription
     * @return An Api Key
     */
    private ApiKey generateForSubscription(String subscription) {
        return generateForSubscription(subscription, null);
    }

    /**
     * Generate an {@link ApiKey} from a subscription. If no custom API key, then generate a new one.
     *
     * @param subscription
     * @param customApiKey
     * @return An Api Key
     */
    private ApiKey generateForSubscription(String subscription, String customApiKey) {
        SubscriptionEntity subscriptionEntity = subscriptionService.findById(subscription);

        if (isNotEmpty(customApiKey) && !canCreate(customApiKey, subscriptionEntity)) {
            throw new ApiKeyAlreadyExistingException();
        }

        Date now = new Date();
        if (subscriptionEntity.getEndingAt() != null && subscriptionEntity.getEndingAt().before(now)) {
            throw new SubscriptionClosedException(subscription);
        }

        ApiKey apiKey = new ApiKey();
        apiKey.setId(UuidString.generateRandom());
        apiKey.setSubscriptions(List.of(subscription));
        apiKey.setApplication(subscriptionEntity.getApplication());
        apiKey.setCreatedAt(new Date());
        apiKey.setUpdatedAt(apiKey.getCreatedAt());
        apiKey.setKey(isNotEmpty(customApiKey) ? customApiKey : apiKeyGenerator.generate());

        // By default, the API Key will expire when subscription is closed
        apiKey.setExpireAt(subscriptionEntity.getEndingAt());

        return apiKey;
    }

    @Override
    public void revoke(String keyId, boolean notify) {
        try {
            ApiKey key = apiKeyRepository.findById(keyId).orElseThrow(ApiKeyNotFoundException::new);
            revoke(key, notify);
        } catch (TechnicalException e) {
            String message = String.format("An error occurs while trying to revoke a key with id %s", keyId);
            LOGGER.error(message, e);
            throw new TechnicalManagementException(message, e);
        }
    }

    @Override
    public void revoke(ApiKeyEntity apiKeyEntity, boolean notify) {
        revoke(apiKeyEntity.getId(), notify);
    }

    private void revoke(ApiKey key, boolean notify) throws TechnicalException {
        LOGGER.debug("Revoke API Key with id {}", key.getId());

        checkApiKeyExpired(key);

        ApiKey previousApiKey = new ApiKey(key);
        key.setRevoked(true);
        key.setUpdatedAt(new Date());
        key.setRevokedAt(key.getUpdatedAt());

        apiKeyRepository.update(key);

        // Audit
        createAuditLog(key, previousApiKey, APIKEY_REVOKED, key.getUpdatedAt());

        // notify
        if (notify) {
            triggerNotifierService(ApiHook.APIKEY_REVOKED, key);
        }
    }

    @Override
    public ApiKeyEntity reactivate(ApiKeyEntity apiKeyEntity) {
        try {
            ApiKey key = apiKeyRepository.findById(apiKeyEntity.getId()).orElseThrow(ApiKeyNotFoundException::new);

            LOGGER.debug("Reactivate API Key id {}", apiKeyEntity.getId());

            if (!key.isRevoked() && !convert(key).isExpired()) {
                throw new ApiKeyAlreadyActivatedException();
            }

            ApiKey previousApiKey = new ApiKey(key);
            key.setRevoked(false);
            key.setUpdatedAt(new Date());
            key.setRevokedAt(null);

            // If this is not a shared API key,
            // Get the subscription to get ending date and set key expiration date
            if (!apiKeyEntity.getApplication().getApiKeyMode().equals(ApiKeyMode.SHARED.name())) {
                SubscriptionEntity subscription = subscriptionService.findById(key.getSubscriptions().get(0));
                if (subscription.getStatus() != SubscriptionStatus.PAUSED && subscription.getStatus() != SubscriptionStatus.ACCEPTED) {
                    throw new SubscriptionNotActiveException(subscription);
                }
                key.setExpireAt(subscription.getEndingAt());
            }

            ApiKey updated = apiKeyRepository.update(key);

            // Audit
            createAuditLog(key, previousApiKey, APIKEY_REACTIVATED, key.getUpdatedAt());

            return convert(updated);
        } catch (TechnicalException ex) {
            LOGGER.error("An error occurs while trying to reactivate an api key", ex);
            throw new TechnicalManagementException("An error occurs while trying to reactivate an api key", ex);
        }
    }

    private void checkApiKeyExpired(ApiKey key) {
        if (key.isRevoked() || convert(key).isExpired()) {
            throw new ApiKeyAlreadyExpiredException();
        }
    }

    @Override
    public ApiKeyEntity findById(String keyId) {
        try {
            return apiKeyRepository.findById(keyId).map(this::convert).orElseThrow(() -> new ApiKeyNotFoundException());
        } catch (TechnicalException e) {
            String message = String.format("An error occurs while trying to find a key with id %s", keyId);
            LOGGER.error(message, e);
            throw new TechnicalManagementException(message, e);
        }
    }

    @Override
    public List<ApiKeyEntity> findByKey(String apiKey) {
        try {
            LOGGER.debug("Find API Keys by key");
            return apiKeyRepository.findByKey(apiKey).stream().map(this::convert).collect(toList());
        } catch (TechnicalException e) {
            LOGGER.error("An error occurs while finding API keys", e);
            throw new TechnicalManagementException("An error occurs while finding API keys", e);
        }
    }

    @Override
    public List<ApiKeyEntity> findBySubscription(String subscription) {
        try {
            LOGGER.debug("Find API Keys for subscription {}", subscription);

            SubscriptionEntity subscriptionEntity = subscriptionService.findById(subscription);
            Set<ApiKey> keys = apiKeyRepository.findBySubscription(subscriptionEntity.getId());
            return keys.stream().map(this::convert).sorted((o1, o2) -> o2.getCreatedAt().compareTo(o1.getCreatedAt())).collect(toList());
        } catch (TechnicalException ex) {
            LOGGER.error("An error occurs while finding API keys for subscription {}", subscription, ex);
            throw new TechnicalManagementException(
                String.format("An error occurs while finding API keys for subscription %s", subscription),
                ex
            );
        }
    }

    @Override
    public ApiKeyEntity findByKeyAndApi(String apiKey, String apiId) {
        try {
            LOGGER.debug("Find an API Key by key for API {}", apiId);
            ApiKey key = apiKeyRepository.findByKeyAndApi(apiKey, apiId).orElseThrow(() -> new ApiKeyNotFoundException());
            return convert(key);
        } catch (TechnicalException ex) {
            LOGGER.error("An error occurs while trying to find an API Key for API {}", apiId, ex);
            throw new TechnicalManagementException(String.format("An error occurs while trying to find an API Key for API %s", apiId), ex);
        }
    }

    @Override
    public List<ApiKeyEntity> findByApplication(String applicationId) {
        try {
            return apiKeyRepository.findByApplication(applicationId).stream().map(this::convert).collect(toList());
        } catch (TechnicalException ex) {
            LOGGER.error("An error occurs while trying to find API Keys for application {}", applicationId, ex);
            throw new TechnicalManagementException(
                String.format("An error occurs while trying to find API Keys for application %s", applicationId),
                ex
            );
        }
    }

    @Override
    public ApiKeyEntity update(ApiKeyEntity apiKeyEntity) {
        try {
            LOGGER.debug("Update API Key with id {}", apiKeyEntity.getId());
            ApiKey key = apiKeyRepository.findById(apiKeyEntity.getId()).orElseThrow(() -> new ApiKeyNotFoundException());

            checkApiKeyExpired(key);

            key.setSubscriptions(apiKeyEntity.getSubscriptionIds());
            key.setPaused(apiKeyEntity.isPaused());
            if (apiKeyEntity.getExpireAt() != null) {
                setExpiration(apiKeyEntity.getExpireAt(), apiKeyEntity, key);
            } else {
                key.setUpdatedAt(new Date());
                apiKeyRepository.update(key);
            }

            return convert(key);
        } catch (TechnicalException ex) {
            LOGGER.error("An error occurs while updating an API Key with id {}", apiKeyEntity.getId(), ex);
            throw new TechnicalManagementException(
                String.format("An error occurs while updating an API Key with id %s", apiKeyEntity.getId()),
                ex
            );
        }
    }

    @Override
    public ApiKeyEntity updateDaysToExpirationOnLastNotification(ApiKeyEntity apiKeyEntity, Integer value) {
        try {
            return apiKeyRepository
                .findById(apiKeyEntity.getId())
                .map(
                    dbApiKey -> {
                        dbApiKey.setDaysToExpirationOnLastNotification(value);
                        try {
                            return apiKeyRepository.update(dbApiKey);
                        } catch (TechnicalException ex) {
                            LOGGER.error("An error occurs while trying to update ApiKey with id {}", dbApiKey.getId(), ex);
                            throw new TechnicalManagementException(
                                String.format("An error occurs while trying to update ApiKey with id %s", dbApiKey.getId()),
                                ex
                            );
                        }
                    }
                )
                .map(this::convert)
                .orElseThrow(ApiKeyNotFoundException::new);
        } catch (TechnicalException ex) {
            LOGGER.error("An error occurs while trying to update apiKey", ex);
            throw new TechnicalManagementException("An error occurs while trying to update apiKey", ex);
        }
    }

    @Override
    public boolean canCreate(String apiKey, SubscriptionEntity subscription) {
        LOGGER.debug("Check if an API Key can be created for subscription {}", subscription.getId());

        // TODO: make environment a parameter
        ApplicationEntity application = applicationService.findById(GraviteeContext.getCurrentEnvironment(), subscription.getApplication());

        if (!application.getApiKeyMode().equals(ApiKeyMode.SHARED.name())) {
            try {
                return apiKeyRepository
                    .findByKey(apiKey)
                    .stream()
                    .noneMatch(
                        existingKey ->
                            !existingKey.getApplication().equals(application.getId()) ||
                            (
                                existingKey.getApplication().equals(application.getId()) &&
                                existingKey.getSubscriptions().contains(subscription.getId())
                            )
                    );
            } catch (TechnicalException ex) {
                String message = String.format(
                    "An error occurs while checking if API Key can be created for api %s and application %s",
                    subscription.getApi(),
                    subscription.getApplication()
                );
                LOGGER.error(message, ex);
                throw new TechnicalManagementException(message, ex);
            }
        }
        // TODO what if we are running in SHARED mode ?
        return false;
    }

    @Override
    public boolean canCreate(String apiKey, String apiId, String applicationId) {
        SubscriptionQuery query = new SubscriptionQuery();
        query.setApi(apiId);
        query.setApplication(applicationId);

        SubscriptionEntity subscription = subscriptionService
            .search(query)
            .stream()
            .findFirst()
            .orElseThrow(
                () -> new TechnicalManagementException("Unable to find subscription for API " + apiId + " and application " + applicationId)
            );

        return canCreate(apiKey, subscription);
    }

    @Override
    public Collection<ApiKeyEntity> search(ApiKeyQuery query) {
        try {
            LOGGER.debug("Search api keys {}", query);

            ApiKeyCriteria.Builder builder = toApiKeyCriteriaBuilder(query);

            return apiKeyRepository.findByCriteria(builder.build()).stream().map(this::convert).collect(toList());
        } catch (TechnicalException ex) {
            LOGGER.error("An error occurs while trying to search api keys: {}", query, ex);
            throw new TechnicalManagementException(String.format("An error occurs while trying to search api keys: {}", query), ex);
        }
    }

    @Override
    public void delete(String apiKey) {
        /*
        try {
            LOGGER.debug("Delete API Key {}", apiKey);
            Optional<ApiKey> optKey = apiKeyRepository.de(apiKey);
            if (!optKey.isPresent()) {
                throw new ApiKeyNotFoundException();
            }

            ApiKey key = optKey.get();

            setExpiration(apiKeyEntity.getExpireAt(), key);

            return convert(key);
        } catch (TechnicalException ex) {
            LOGGER.error("An error occurs while trying to update a key {}", apiKey, ex);
            throw new TechnicalManagementException("An error occurs while trying to update a key " + apiKey, ex);
        }
        */
    }

    private void setExpiration(Date expirationDate, ApiKeyEntity apiKeyEntity, ApiKey key) throws TechnicalException {
        final Date now = new Date();

        if (now.after(expirationDate)) {
            expirationDate = now;
        }

        key.setUpdatedAt(now);
        if (!key.isRevoked()) {
            // If API key is not shared
            // The expired date must be <= than the subscription end date
            if (!apiKeyEntity.getApplication().getApiKeyMode().equals(ApiKeyMode.SHARED.name())) {
                SubscriptionEntity subscription = subscriptionService.findById(key.getSubscriptions().get(0));
                if (
                    subscription.getEndingAt() != null &&
                    (expirationDate == null || subscription.getEndingAt().compareTo(expirationDate) < 0)
                ) {
                    expirationDate = subscription.getEndingAt();
                }
            }

            ApiKey oldkey = new ApiKey(key);
            key.setExpireAt(expirationDate);
            key.setDaysToExpirationOnLastNotification(null);
            apiKeyRepository.update(key);

            //notify
            NotificationParamsBuilder paramsBuilder = new NotificationParamsBuilder();
            if (key.getExpireAt() != null && now.before(key.getExpireAt())) {
                paramsBuilder.expirationDate(key.getExpireAt());
            }
            triggerNotifierService(ApiHook.APIKEY_EXPIRED, key, paramsBuilder);

            // Audit
            createAuditLog(key, oldkey, APIKEY_EXPIRED, key.getUpdatedAt());
        } else {
            apiKeyRepository.update(key);
        }
    }

    private ApiKeyEntity convert(ApiKey apiKey) {
        ApiKeyEntity apiKeyEntity = new ApiKeyEntity();

        apiKeyEntity.setId(apiKey.getId());
        apiKeyEntity.setKey(apiKey.getKey());
        apiKeyEntity.setCreatedAt(apiKey.getCreatedAt());
        apiKeyEntity.setExpireAt(apiKey.getExpireAt());
        apiKeyEntity.setExpired(apiKey.getExpireAt() != null && new Date().after(apiKey.getExpireAt()));
        apiKeyEntity.setRevoked(apiKey.isRevoked());
        apiKeyEntity.setRevokedAt(apiKey.getRevokedAt());
        apiKeyEntity.setUpdatedAt(apiKey.getUpdatedAt());

        apiKeyEntity.setSubscriptions(subscriptionService.findByIdIn(apiKey.getSubscriptions()));

        // TODO: make environment a parameter
        apiKeyEntity.setApplication(applicationService.findById(GraviteeContext.getCurrentEnvironment(), apiKey.getApplication()));

        apiKeyEntity.setDaysToExpirationOnLastNotification(apiKey.getDaysToExpirationOnLastNotification());

        return apiKeyEntity;
    }

    private ApiKeyCriteria.Builder toApiKeyCriteriaBuilder(ApiKeyQuery query) {
        return new ApiKeyCriteria.Builder()
            .includeRevoked(query.isIncludeRevoked())
            .plans(query.getPlans())
            .from(query.getFrom())
            .to(query.getTo())
            .expireAfter(query.getExpireAfter())
            .expireBefore(query.getExpireBefore());
    }

    // TODO: refactor to avoid querying repositories
    private void createAuditLog(ApiKey key, ApiKey previousApiKey, ApiKey.AuditEvent event, Date eventDate) {
        ApplicationEntity application = applicationService.findById(GraviteeContext.getCurrentEnvironment(), key.getApplication());

        if (!application.getApiKeyMode().equals(io.gravitee.rest.api.model.ApiKeyMode.SHARED)) {
            SubscriptionEntity subscription = subscriptionService.findByIdIn(key.getSubscriptions()).get(0);

            Map<Audit.AuditProperties, String> properties = new LinkedHashMap<>();
            properties.put(API_KEY, key.getKey());
            properties.put(API, subscription.getApi());
            properties.put(APPLICATION, key.getApplication());

            auditService.createApiAuditLog(subscription.getApi(), properties, event, eventDate, previousApiKey, key);
        }
    }

    private void triggerNotifierService(ApiHook apiHook, ApiKey key) {
        triggerNotifierService(apiHook, key, new NotificationParamsBuilder());
    }

    private void triggerNotifierService(ApiHook apiHook, ApiKey key, NotificationParamsBuilder paramsBuilder) {
        ApplicationEntity application = applicationService.findById(GraviteeContext.getCurrentEnvironment(), key.getApplication());

        if (!application.getApiKeyMode().equals(ApiKeyMode.SHARED.name())) {
            SubscriptionEntity subscription = subscriptionService.findByIdIn(key.getSubscriptions()).get(0);
            PlanEntity plan = planService.findById(subscription.getPlan());
            ApiModelEntity api = apiService.findByIdForTemplates(subscription.getApi());
            PrimaryOwnerEntity owner = application.getPrimaryOwner();
            Map<String, Object> params = paramsBuilder.application(application).plan(plan).api(api).owner(owner).apikey(key).build();
            notifierService.trigger(apiHook, api.getId(), params);
        }
    }
}
