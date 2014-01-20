/**
 * 
 * Copyright (c) Microsoft and contributors.  All rights reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * 
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

// Warning: This code was generated by a tool.
// 
// Changes to this file may cause incorrect behavior and will be lost if the
// code is regenerated.

package com.microsoft.windowsazure.management.sql.models;

import com.microsoft.windowsazure.core.OperationResponse;
import java.net.InetAddress;

/**
* A standard service response including an HTTP status code and request ID.
*/
public class FirewallRuleUpdateResponse extends OperationResponse
{
    private InetAddress endIPAddress;
    
    /**
    * Gets or sets the ending IP address applied to this rule.
    * @return The EndIPAddress value.
    */
    public InetAddress getEndIPAddress()
    {
        return this.endIPAddress;
    }
    
    /**
    * Gets or sets the ending IP address applied to this rule.
    * @param endIPAddressValue The EndIPAddress value.
    */
    public void setEndIPAddress(final InetAddress endIPAddressValue)
    {
        this.endIPAddress = endIPAddressValue;
    }
    
    private String name;
    
    /**
    * Gets or sets the name of the Firewall Rule.
    * @return The Name value.
    */
    public String getName()
    {
        return this.name;
    }
    
    /**
    * Gets or sets the name of the Firewall Rule.
    * @param nameValue The Name value.
    */
    public void setName(final String nameValue)
    {
        this.name = nameValue;
    }
    
    private InetAddress startIPAddress;
    
    /**
    * Gets or sets the beginning IP address applied to this rule.
    * @return The StartIPAddress value.
    */
    public InetAddress getStartIPAddress()
    {
        return this.startIPAddress;
    }
    
    /**
    * Gets or sets the beginning IP address applied to this rule.
    * @param startIPAddressValue The StartIPAddress value.
    */
    public void setStartIPAddress(final InetAddress startIPAddressValue)
    {
        this.startIPAddress = startIPAddressValue;
    }
    
    private String state;
    
    /**
    * Gets or sets the state of the rule.
    * @return The State value.
    */
    public String getState()
    {
        return this.state;
    }
    
    /**
    * Gets or sets the state of the rule.
    * @param stateValue The State value.
    */
    public void setState(final String stateValue)
    {
        this.state = stateValue;
    }
    
    private String type;
    
    /**
    * Gets or sets the type of resource.
    * @return The Type value.
    */
    public String getType()
    {
        return this.type;
    }
    
    /**
    * Gets or sets the type of resource.
    * @param typeValue The Type value.
    */
    public void setType(final String typeValue)
    {
        this.type = typeValue;
    }
}
