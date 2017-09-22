//
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//

package com.microsoft.azure.keyvault.jose;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.microsoft.azure.serializer.AzureJacksonMapperAdapter;

public class JweHeader
{
    public String Kid;

    public String KeyWrapAlgorithm;

    public String EncryptionAlgorithm;

    // TODO: Extended data
    //[JsonExtensionData]
    //protected Map<String, Object> ExtensionData { get; set; }

    public static JweHeader fromString( String json ) throws JweFormatException
    {
        AzureJacksonMapperAdapter mapperAdapter = new AzureJacksonMapperAdapter();
        ObjectMapper              mapper        = mapperAdapter.getObjectMapper();

        try {
			return mapper.readValue(json, JweHeader.class );
		} catch (JsonParseException e) {
			throw new JweFormatException();
		} catch (JsonMappingException e) {
			throw new JweFormatException();
		} catch (IOException e) {
			throw new JweFormatException();
		}
    }

    @Override
    public String toString()
    {
        AzureJacksonMapperAdapter mapperAdapter = new AzureJacksonMapperAdapter();
        ObjectMapper              mapper        = mapperAdapter.getObjectMapper();
        
        try {
            return mapper.writeValueAsString(this);
        } catch (JsonGenerationException e) {
            throw new IllegalStateException(e);
        } catch (JsonMappingException e) {
            throw new IllegalStateException(e);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    public static JweHeader fromCompactHeader( String compactHeader ) throws JweFormatException
    {
        try
        {
			return fromString( new String( Base64.decodeBase64( compactHeader ), "UTF-8" ) );
		}
        catch (UnsupportedEncodingException e)
        {
        	throw new JweFormatException( e.getMessage() );
        }
    }

    public String toCompactHeader() throws JweFormatException
    {
        try
        {
			return Base64.encodeBase64URLSafeString( toString().getBytes("UTF-8") );
		}
        catch (UnsupportedEncodingException e)
        {
        	throw new JweFormatException( e.getMessage() );
		}
    }
}
