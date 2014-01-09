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

package com.microsoft.windowsazure.scheduler.models;

import java.net.URI;
import java.util.HashMap;

/**
* Request for a http or https action type.
*/
public class JobHttpRequest
{
    private String body;
    
    /**
    * HTTP request body.
    */
    public String getBody() { return this.body; }
    
    /**
    * HTTP request body.
    */
    public void setBody(String body) { this.body = body; }
    
    private HashMap<String, String> headers;
    
    /**
    * pair of strings representing header name value pairs.
    */
    public HashMap<String, String> getHeaders() { return this.headers; }
    
    /**
    * pair of strings representing header name value pairs.
    */
    public void setHeaders(HashMap<String, String> headers) { this.headers = headers; }
    
    private String method;
    
    /**
    * http method e.g. GET, PUT, POST, DELETE.
    */
    public String getMethod() { return this.method; }
    
    /**
    * http method e.g. GET, PUT, POST, DELETE.
    */
    public void setMethod(String method) { this.method = method; }
    
    private URI uri;
    
    /**
    * uri of the endpoint to invoke.
    */
    public URI getUri() { return this.uri; }
    
    /**
    * uri of the endpoint to invoke.
    */
    public void setUri(URI uri) { this.uri = uri; }
    
    /**
    * Initializes a new instance of the JobHttpRequest class.
    *
    */
    public JobHttpRequest()
    {
        this.headers = new HashMap<String, String>();
    }
}