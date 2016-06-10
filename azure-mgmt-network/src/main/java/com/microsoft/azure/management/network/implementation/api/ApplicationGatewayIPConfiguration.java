/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See License.txt in the project root for
 * license information.
 */

package com.microsoft.azure.management.network.implementation.api;

import com.microsoft.azure.SubResource;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.microsoft.rest.serializer.JsonFlatten;

/**
 * IP configuration of application gateway.
 */
@JsonFlatten
public class ApplicationGatewayIPConfiguration extends SubResource {
    /**
     * Gets or sets the reference of the subnet resource.A subnet from where
     * appliation gateway gets its private address.
     */
    @JsonProperty(value = "properties.subnet")
    private SubResource subnet;

    /**
     * Gets or sets Provisioning state of the application gateway subnet
     * resource Updating/Deleting/Failed.
     */
    @JsonProperty(value = "properties.provisioningState")
    private String provisioningState;

    /**
     * Gets name of the resource that is unique within a resource group. This
     * name can be used to access the resource.
     */
    private String name;

    /**
     * A unique read-only string that changes whenever the resource is updated.
     */
    private String etag;

    /**
     * Get the subnet value.
     *
     * @return the subnet value
     */
    public SubResource subnet() {
        return this.subnet;
    }

    /**
     * Set the subnet value.
     *
     * @param subnet the subnet value to set
     * @return the ApplicationGatewayIPConfiguration object itself.
     */
    public ApplicationGatewayIPConfiguration withSubnet(SubResource subnet) {
        this.subnet = subnet;
        return this;
    }

    /**
     * Get the provisioningState value.
     *
     * @return the provisioningState value
     */
    public String provisioningState() {
        return this.provisioningState;
    }

    /**
     * Set the provisioningState value.
     *
     * @param provisioningState the provisioningState value to set
     * @return the ApplicationGatewayIPConfiguration object itself.
     */
    public ApplicationGatewayIPConfiguration withProvisioningState(String provisioningState) {
        this.provisioningState = provisioningState;
        return this;
    }

    /**
     * Get the name value.
     *
     * @return the name value
     */
    public String name() {
        return this.name;
    }

    /**
     * Set the name value.
     *
     * @param name the name value to set
     * @return the ApplicationGatewayIPConfiguration object itself.
     */
    public ApplicationGatewayIPConfiguration withName(String name) {
        this.name = name;
        return this;
    }

    /**
     * Get the etag value.
     *
     * @return the etag value
     */
    public String etag() {
        return this.etag;
    }

    /**
     * Set the etag value.
     *
     * @param etag the etag value to set
     * @return the ApplicationGatewayIPConfiguration object itself.
     */
    public ApplicationGatewayIPConfiguration withEtag(String etag) {
        this.etag = etag;
        return this;
    }

}