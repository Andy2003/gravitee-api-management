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
package io.gravitee.repository.mongodb.management.internal.key;

import static com.mongodb.client.model.Aggregates.*;
import static com.mongodb.client.model.Filters.*;

import com.mongodb.client.AggregateIterable;
import io.gravitee.repository.management.api.search.ApiKeyCriteria;
import io.gravitee.repository.mongodb.management.internal.model.ApiKeyMongo;
import java.util.*;
import org.bson.Document;
import org.bson.conversions.Bson;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Sort;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class ApiKeyMongoRepositoryImpl implements ApiKeyMongoRepositoryCustom {

    @Autowired
    private MongoTemplate mongoTemplate;

    @Override
    public List<ApiKeyMongo> search(ApiKeyCriteria filter) {
        Query query = new Query();

        if (!filter.isIncludeRevoked()) {
            query.addCriteria(Criteria.where("revoked").is(false));
        }

        if (filter.getPlans() != null) {
            query.addCriteria(Criteria.where("plan").in(filter.getPlans()));
        }

        // set range query
        if (filter.getFrom() != 0 && filter.getTo() != 0) {
            query.addCriteria(Criteria.where("updatedAt").gte(new Date(filter.getFrom())).lt(new Date(filter.getTo())));
        }

        if (filter.getExpireAfter() > 0 || filter.getExpireBefore() > 0) {
            // Need to mutualize the instantiation of this filter otherwise mongo driver is throwing an error, when
            // using multiple `Criteria.where("expireAt").xxx` with the same query
            Criteria expireAtCriteria = Criteria.where("expireAt");

            if (filter.getExpireAfter() > 0) {
                expireAtCriteria = expireAtCriteria.gte(new Date(filter.getExpireAfter()));
            }
            if (filter.getExpireBefore() > 0) {
                expireAtCriteria = expireAtCriteria.lte(new Date(filter.getExpireBefore()));
            }

            query.addCriteria(expireAtCriteria);
        }

        query.with(Sort.by(Sort.Direction.DESC, "updatedAt"));

        return mongoTemplate.find(query, ApiKeyMongo.class);
    }

    @Override
    public List<ApiKeyMongo> findByKeyAndApi(String key, String api) {
        List<Bson> pipeline = List.of(
            lookup("subscriptions", "subscriptions", "_id", "sub"),
            unwind("$sub"),
            match(eq("key", key)),
            match(eq("sub.api", api))
        );

        AggregateIterable<Document> aggregate = mongoTemplate
            .getCollection(mongoTemplate.getCollectionName(ApiKeyMongo.class))
            .aggregate(pipeline);

        return getListFromAggregate(aggregate);
    }

    @Override
    public List<ApiKeyMongo> findByPlan(String plan) {
        List<Bson> pipeline = new ArrayList<>();
        pipeline.add(lookup("subscriptions", "subscriptions", "_id", "sub"));
        pipeline.add(unwind("$sub"));
        pipeline.add(match(eq("sub.plan", plan)));

        AggregateIterable<Document> aggregate = mongoTemplate
            .getCollection(mongoTemplate.getCollectionName(ApiKeyMongo.class))
            .aggregate(pipeline);

        return getListFromAggregate(aggregate);
    }

    private List<ApiKeyMongo> getListFromAggregate(AggregateIterable<Document> aggregate) {
        ArrayList<ApiKeyMongo> apiKeys = new ArrayList<>();
        for (Document doc : aggregate) {
            ApiKeyMongo apiKeyMongo = new ApiKeyMongo();
            apiKeyMongo.setId(doc.getString("_id"));
            apiKeyMongo.setKey(doc.getString("key"));
            apiKeyMongo.setSubscriptions(new HashSet<>(doc.getList("subscriptions", String.class, List.of())));
            apiKeyMongo.setApplication(doc.getString("application"));
            apiKeyMongo.setCreatedAt(doc.getDate("createdAt"));
            apiKeyMongo.setUpdatedAt(doc.getDate("updatedAt"));
            apiKeyMongo.setRevoked(doc.getBoolean("revoked"));
            apiKeyMongo.setPaused(doc.getBoolean("paused"));
            apiKeys.add(apiKeyMongo);
        }
        return apiKeys;
    }
}
