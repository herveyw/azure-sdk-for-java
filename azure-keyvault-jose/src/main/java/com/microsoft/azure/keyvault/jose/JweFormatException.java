//
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//

package com.microsoft.azure.keyvault.jose;

public class JweFormatException extends Exception
{
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public JweFormatException() {
    	super( "Bad JWE Serialization value" );
    }

    public JweFormatException( String message ) {
    	super( message );
    }
}