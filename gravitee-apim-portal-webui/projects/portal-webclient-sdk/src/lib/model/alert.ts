/**
 * Gravitee.io Portal Rest API
 * API dedicated to the devportal part of Gravitee
 *
 * Contact: contact@graviteesource.com
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */
import { AlertType } from './alertType';
import { AlertTimeUnit } from './alertTimeUnit';


export interface Alert {
    /**
     * Unique identifier of an alert.
     */
    id?: string;
    /**
     * true, if alert is enabled
     */
    enabled?: boolean;
    type?: AlertType;
    /**
     * Alert description
     */
    description?: string;
    /**
     * Http status code to trigger the alert
     */
    status_code?: string;
    /**
     * Percent to trigger the alert on status code
     */
    status_percent?: number;
    /**
     * Response time to trigger the alert
     */
    response_time?: number;
    /**
     * Compute alert on selected duration
     */
    duration?: number;
    time_unit?: AlertTimeUnit;
}

