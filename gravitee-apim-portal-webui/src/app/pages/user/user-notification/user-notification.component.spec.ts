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
import { mockProvider } from '@ngneat/spectator/jest';
import { createComponentFactory, Spectator } from '@ngneat/spectator/jest';
import { UserTestingModule } from '../../../test/user-testing-module';
import { UserNotificationComponent } from './user-notification.component';
import { SafePipe } from '../../../pipes/safe.pipe';
import { CUSTOM_ELEMENTS_SCHEMA } from '@angular/core';
import { RouterTestingModule } from '@angular/router/testing';
import { HttpClientTestingModule } from '@angular/common/http/testing';
import { UserService } from '../../../../../projects/portal-webclient-sdk/src/lib';
import { Observable } from 'rxjs';

describe('UserNotificationComponent', () => {
  const createComponent = createComponentFactory({
    component: UserNotificationComponent,
    imports: [UserTestingModule, HttpClientTestingModule, RouterTestingModule],
    schemas: [CUSTOM_ELEMENTS_SCHEMA],
    declarations: [SafePipe],
    providers: [
      mockProvider(UserService, {
        getCurrentUserNotifications: () => new Observable(),
      }),
    ],
  });

  let spectator: Spectator<UserNotificationComponent>;
  let component;

  beforeEach(() => {
    spectator = createComponent();
    component = spectator.component;
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
