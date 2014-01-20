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

package com.microsoft.windowsazure.management.scheduler.models;

/**
* Parameters supplied to intrinsic settings for a job.
*/
public class JobCollectionIntrinsicSettings
{
    private JobCollectionPlan plan;
    
    /**
    * The plan of the resource.
    * @return The Plan value.
    */
    public JobCollectionPlan getPlan()
    {
        return this.plan;
    }
    
    /**
    * The plan of the resource.
    * @param planValue The Plan value.
    */
    public void setPlan(final JobCollectionPlan planValue)
    {
        this.plan = planValue;
    }
    
    private JobCollectionQuota quota;
    
    /**
    * Quota settings for the job collection.
    * @return The Quota value.
    */
    public JobCollectionQuota getQuota()
    {
        return this.quota;
    }
    
    /**
    * Quota settings for the job collection.
    * @param quotaValue The Quota value.
    */
    public void setQuota(final JobCollectionQuota quotaValue)
    {
        this.quota = quotaValue;
    }
}
