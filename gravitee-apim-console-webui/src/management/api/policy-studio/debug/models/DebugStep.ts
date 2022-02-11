/*
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
interface DebugStep<T> {
  policyInstanceId: string;
  policyId: string;
  scope: PolicyScope;
  status: 'COMPLETED' | 'ERROR';
  duration: number;
  policyOutput: T;
}

export type PolicyScope = 'ON_REQUEST' | 'ON_REQUEST_CONTENT' | 'ON_RESPONSE' | 'ON_RESPONSE_CONTENT';

export type RequestDebugStep = DebugStep<{
  headers?: Record<string, string[]>;
  parameters?: Record<string, string>;
  pathParameters?: Record<string, string>;
  method?: string;
  path?: string;
  contextPath?: string;
  attributes?: Record<string, boolean | number | string>;
  body?: string;
}>;

export type ResponseDebugStep = DebugStep<{
  headers?: Record<string, string[]>;
  statusCode?: number;
  reason?: string;
  attributes?: Record<string, boolean | number | string>;
  body?: string;
}>;