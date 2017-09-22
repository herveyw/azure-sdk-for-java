//
// Copyright © Microsoft Corporation, All Rights Reserved
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
// ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
// PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
//
// See the Apache License, Version 2.0 for the specific language
// governing permissions and limitations under the License.

package com.microsoft.azure.keyvault.jose;

import java.util.Map;

public class JweObject
{
    //[JsonProperty( PropertyName = "protected", DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default )]
    public String Protected;

    //[JsonProperty( PropertyName = "unprotected", DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default )]
    public JweHeader Unprotected;

    //[JsonProperty( PropertyName = "encrypted_key", DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default )]
    public String EncryptedKey;

    //[JsonProperty( PropertyName = "iv", DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default )]
    public String Iv;

    //[JsonProperty( PropertyName = "ciphertext", DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default )]
    public String Ciphertext;

    //[JsonProperty( PropertyName = "tag", DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default )]
    public String Tag;

    //[JsonProperty( PropertyName = "aad", DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default )]
    public String AuthenticationData;

    //[JsonExtensionData]
    protected Map<String, Object> ExtensionData;

    public String toCompactJwe()
    {
        if ( Protected == null || EncryptedKey == null || Iv == null || Ciphertext == null )
            throw new IllegalStateException( "JWE object is not complete" );

        return Protected + "." + EncryptedKey + "." + Iv + "." + Ciphertext + "." + Tag;
    }
    
    public static JweObject fromCompactJwe( String compactJwe ) throws JweFormatException {
    	return fromCompactJwe( compactJwe, true );
    }

    public static JweObject fromCompactJwe( String compactJwe, Boolean parseProtected ) throws JweFormatException
    {
        if ( Strings.isNullOrEmpty( compactJwe ) )
            throw new IllegalArgumentException( "jwe" );

        String components[] = compactJwe.split( "." );

        if ( components == null || components.length != 5 )
            throw new JweFormatException();

        JweObject result = new JweObject();
        
        result.Protected    = components[0];
        result.Unprotected  = parseProtected ? JweHeader.fromCompactHeader( components[0] ) : null;
        result.EncryptedKey = components[1];
        result.Iv           = components[2];
        result.Ciphertext   = components[3];
        result.Tag          = components[4];
        
        return result;
    }
}
