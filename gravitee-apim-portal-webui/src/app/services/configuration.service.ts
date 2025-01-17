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
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { FeatureEnum } from '../model/feature.enum';
import { applyTheme } from '@gravitee/ui-components/src/lib/theme';

@Injectable({
  providedIn: 'root',
})
export class ConfigurationService {
  private config: any;

  constructor(private http: HttpClient) {}

  public get(key: string, defaultValue?: any) {
    const value = key.split('.').reduce((prev, curr) => prev && prev[curr], this.config);
    if (value == null) {
      return defaultValue;
    }
    return value;
  }

  public load() {
    return new Promise((resolve) => {
      this.http.get('./assets/config.json').subscribe((configJson: any) => {
        document.documentElement.style.setProperty('--gv-theme-loader', `url('${configJson.loaderURL}')`);

        if (configJson.baseURL.endsWith('/')) {
          configJson.baseURL = configJson.baseURL.slice(0, -1);
        }

        this.http
          .get(configJson.baseURL + '/theme')
          .toPromise()
          .then((theme) => {
            applyTheme(theme);
          });

        this.http.get(configJson.baseURL + '/configuration').subscribe(
          (configPortal) => {
            this.config = this._deepMerge(configJson, configPortal);
            resolve(true);
          },
          () => resolve(false),
        );
      });
    });
  }

  public hasFeature(feature: FeatureEnum): boolean {
    return this.get(feature);
  }

  _deepMerge(target, source) {
    for (const key of Object.keys(source)) {
      if (source[key] instanceof Object && key in target) {
        Object.assign(source[key], this._deepMerge(target[key], source[key]));
      }
    }
    Object.assign(target || {}, source);
    return target;
  }
}
