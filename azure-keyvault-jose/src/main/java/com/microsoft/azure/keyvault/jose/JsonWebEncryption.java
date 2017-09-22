//
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//

package com.microsoft.azure.keyvault.jose;

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.Executors;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;

import com.google.common.util.concurrent.AsyncFunction;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.microsoft.azure.keyvault.core.IKey;
import com.microsoft.azure.keyvault.core.IKeyResolver;
import com.microsoft.azure.keyvault.cryptography.SymmetricKey;

public final class JsonWebEncryption
{
    private final static String DirectAlgorithm = "dir";

    private static final SecureRandom _rng = new SecureRandom();

    /// <summary>
    /// Protects the specified plaintext using the provided key in Direct Key Management Mode. The
    /// data encryption algorithm and key should be a symmetric algorithm.
    /// </summary>
    /// <param name="dataEncryptionKey">The data encryption key</param>
    /// <param name="dataEncryptionAlgorithm">The data encryption algorithm</param>
    /// <param name="plaintext">The data to protect</param>
    /// <returns>A Flattened JWE object</returns>
    public static ListenableFuture<JweObject> ProtectAsync( IKey dataEncryptionKey, String dataEncryptionAlgorithm, byte[] plaintext ) throws JweFormatException
    {
        if ( dataEncryptionKey == null )
            throw new IllegalArgumentException( "dataEncryptionKey" );

        if ( dataEncryptionAlgorithm == null )
            throw new IllegalArgumentException( "dataEncryptionAlgorithm" );

        if ( plaintext == null )
            throw new IllegalArgumentException( "plaintext" );

        // Create protected header specifying encryption parameters.
        JweHeader unprotectedHeader = CreateHeader( DirectAlgorithm, dataEncryptionAlgorithm, dataEncryptionKey.getKid() );
        // Encode the protected header to Base64URL of the UTF8 bytes of the header text
        String    protectedHeader   = unprotectedHeader.toCompactHeader();
        // The authenticated data is the ASCII bytes of the encoded protected header
        byte[] authenticationData;
        
		try {
			authenticationData = protectedHeader.getBytes("US-ASCII");
		} catch (UnsupportedEncodingException e) {
			throw new JweFormatException( e.getMessage() );
		}


        // In Direct Encryption mode, the content encryption key is the key provided
        // by the caller and there is no wrapped key in the output. The provided must
        // be a symmetric encryption key.

        // Encrypt the plaintext
        byte[] iv                                      = GenerateIv();
        Triple<byte[], byte[], String> encryptedResult = dataEncryptionKey.encryptAsync( plaintext, iv, authenticationData, dataEncryptionAlgorithm );

        return Futures.immediateFuture( CreateJwe( protectedHeader, unprotectedHeader, null, encryptedResult.getLeft(), iv, encryptedResult.getMiddle() ) );
    }

    /// <summary>
    /// Protects the specified plaintext using the provided key encryption key. A randomly generated 
    /// data encryption key is used to encrypt the plaintext and then is protected using the key
    /// encryption key.
    /// </summary>
    /// <param name="keyEncryptionKey">The key encryption key</param>
    /// <param name="keyEncryptionAlgorithm">The key encryption algorithm</param>
    /// <param name="dataEncryptionAlgorithm">The data encryption algorithm</param>
    /// <param name="plaintext">The data to protect</param>
    /// <returns>A compressed form JSON Web Encryption object</returns>
    public static ListenableFuture<JweObject> ProtectAsync( IKey keyEncryptionKey, String keyEncryptionAlgorithm, String dataEncryptionAlgorithm, byte[] plaintext )
    {
        ListenableFuture<JweObject> result = null;

        // Generate sufficient key material for any of the possible algorithms
        byte[] dataEncryptionKey = GenerateKey( 512 >> 3 );

        try
        {
            result = ProtectAsync( keyEncryptionKey, keyEncryptionAlgorithm, dataEncryptionKey, dataEncryptionAlgorithm, plaintext );
        }
        finally
        {
            // Ensure key material is not hanging around.
        	Arrays.fill(dataEncryptionKey, (byte)0);
        }

        return result;
    }


    /// <summary>
    /// Protects the specified plaintext using the provided key encryption and data encryption keys.
    /// The keyEncryptionAlgorithm defines how the content encryption key (CEK) is protected and the
    /// dataEncryptionAlgorithm defines how the plaintext is encrypted.
    /// </summary>
    /// <param name="keyEncryptionKey">The root protection key</param>
    /// <param name="keyEncryptionAlgorithm">The key encryption algorithm</param>
    /// <param name="dataEncryptionKey">The data encryption key</param>
    /// <param name="dataEncryptionAlgorithm">The data encryption algorithm</param>
    /// <param name="plaintext">The data to protect</param>
    /// <returns>A Flattened JWE object</returns>
    public static ListenableFuture<JweObject> ProtectAsync( IKey keyEncryptionKey, final String keyEncryptionAlgorithm, final byte[] dataEncryptionKey, final String dataEncryptionAlgorithm, final byte[] plaintext )
    {
        if ( keyEncryptionKey == null )
            throw new IllegalArgumentException( "keyEncryptionKey" );

        if ( keyEncryptionAlgorithm == null )
            throw new IllegalArgumentException( "keyEncryptionAlgorithm" );

        if ( dataEncryptionKey == null )
            throw new IllegalArgumentException( "dataEncryptionKey" );

        if ( dataEncryptionAlgorithm == null )
            throw new IllegalArgumentException( "dataEncryptionAlgorithm" );

        if ( plaintext == null )
            throw new IllegalArgumentException( "plaintext" );

        // Create protected header specifying encryption parameters.

        final JweHeader unprotectedHeader  = CreateHeader( keyEncryptionAlgorithm, dataEncryptionAlgorithm, keyEncryptionKey.getKid() );
        // Encode the protected header to Base64URL of the UTF8 bytes of the header text
        final String    protectedHeader    = unprotectedHeader.toCompactHeader();
        // The authenticated data is the ASCII bytes of the encoded protected header
        final byte[]    authenticationData = protectedHeader.getBytes("US-ASCII");

        // In Key Wrapping mode, the key encryption key is used to
        // protect the data encryption key and the encrypted key
        // is carried in the final package.
        ListenableFuture<Pair<byte[],String>>            wrapResult    = keyEncryptionKey.wrapKeyAsync( dataEncryptionKey, keyEncryptionAlgorithm );
        
        // Transform the wrapped key result into the encryption result
        ListenableFuture<Triple<byte[], byte[], String>> encryptResult = Futures.transform(wrapResult, new AsyncFunction<Pair<byte[],String>, Triple<byte[], byte[], String>>() {
        	
        	@Override
        	public ListenableFuture<Triple<byte[], byte[], String>> apply(Pair<byte[],String> wrapResult) {
        		
                    byte[] wrappedKey = wrapResult.getLeft();

                    // Encrypt the plaintext
                    byte[]       iv   = GenerateIv();
                    
                    return new SymmetricKey( "cek", dataEncryptionKey ).encryptAsync( plaintext, iv, authenticationData, dataEncryptionAlgorithm );
                }
        	} );

        // Transform the encryption result into the JWE
        Futures.transform(Triple<byte[], byte[], String>, new AsyncFunction<Triple<byte[], byte[], String>, JweObject>() {
        	public ListenableFuture<JweObject> apply(Triple<byte[], byte[], String> previousResult ) {
                return Futures.immediateFuture( CreateJwe( protectedHeader, unprotectedHeader, wrappedKey, previousResult.getLeft(), iv, previousResult.getMiddle() ) );
        	}
        });
        
    }

    /// <summary>
    /// Protects the specified plaintext using the provided key in Direct Key Management Mode.
    /// </summary>
    /// <param name="dataEncryptionKey">The data encryption key</param>
    /// <param name="dataEncryptionAlgorithm">The data encryption algorithm</param>
    /// <param name="plaintext">The data to protect</param>
    /// <returns>A compressed form JSON Web Encryption object</returns>
    public static ListenableFuture<String> ProtectCompactAsync( IKey dataEncryptionKey, final String dataEncryptionAlgorithm, final byte[] plaintext ) throws JweFormatException
    {
         ListenableFuture<JweObject> protectResult = ProtectAsync( dataEncryptionKey, dataEncryptionAlgorithm, plaintext );
         
         return Futures.transform( protectResult, new AsyncFunction<JweObject, String>() {
        	 public ListenableFuture<String> apply( JweObject jwe ) {
        		 return Futures.immediateFuture( jwe.toCompactJwe() );
        	 }
         });
    }

    /// <summary>
    /// Protects the specified plaintext using the provided key encryption key. A randomly generated 
    /// data encryption key is used to encrypt the plaintext and then is protected using the key
    /// encryption key.
    /// </summary>
    /// <param name="keyEncryptionKey">The key encryption key</param>
    /// <param name="keyEncryptionAlgorithm">The key encryption algorithm</param>
    /// <param name="dataEncryptionAlgorithm">The data encryption algorithm</param>
    /// <param name="plaintext">The data to protect</param>
    /// <returns>A compressed form JSON Web Encryption object</returns>
    public static ListenableFuture<String> ProtectCompactAsync( IKey keyEncryptionKey, final String keyEncryptionAlgorithm, final String dataEncryptionAlgorithm, final byte[] plaintext )
    {
        ListenableFuture<JweObject> protectResult = ProtectAsync( keyEncryptionKey, keyEncryptionAlgorithm, dataEncryptionAlgorithm, plaintext );
        
        return Futures.transform( protectResult, new AsyncFunction<JweObject, String>() {
       	 public ListenableFuture<String> apply( JweObject jwe ) {
       		 return Futures.immediateFuture( jwe.toCompactJwe() );
       	 }
        });
    }

    /// <summary>
    /// Protects the specified plaintext using the provided key encryption and data encryption keys.
    /// The keyEncryptionAlgorithm defines how the content encryption key (CEK) is protected and the
    /// dataEncryptionAlgorithm defines how the plaintext is encrypted.
    /// </summary>
    /// <param name="keyEncryptionKey">The root protection key</param>
    /// <param name="keyEncryptionAlgorithm">The key encryption algorithm</param>
    /// <param name="dataEncryptionKey">The data encryption key</param>
    /// <param name="dataEncryptionAlgorithm">The data encryption algorithm</param>
    /// <param name="plaintext">The data to protect</param>
    /// <returns>A compressed form JSON Web Encryption object</returns>
    public static ListenableFuture<String> ProtectCompactAsync( IKey keyEncryptionKey, final String keyEncryptionAlgorithm, final byte[] dataEncryptionKey, final String dataEncryptionAlgorithm, final byte[] plaintext )
    {
        ListenableFuture<JweObject> protectResult = ProtectAsync( keyEncryptionKey, keyEncryptionAlgorithm, dataEncryptionKey, dataEncryptionAlgorithm, plaintext );
        
        return Futures.transform( protectResult, new AsyncFunction<JweObject, String>() {
       	 public ListenableFuture<String> apply( JweObject jwe ) {
       		 return Futures.immediateFuture( jwe.toCompactJwe() );
       	 }
        });
    }

    public static ListenableFuture<byte[]> UnprotectAsync( IKeyResolver keyResolver, JweObject jwe ) throws JweFormatException, JweKeyNotFoundException
    {
        if ( keyResolver == null )
            throw new IllegalArgumentException( "keyResolver" );

        if ( jwe == null )
            throw new IllegalArgumentException( "jwe" );

        String    protectedHeaderEncoded;
        JweHeader protectedHeader;
        String    encryptedKeyEncoded;
        byte[] iv;
        byte[] ciphertext;
        byte[] authenticationTag;

        try
        {
            // Deserialize the header. For security, we ignore jwe.Unprotected.
            protectedHeaderEncoded = jwe.Protected;
            protectedHeader        = JweHeader.fromCompactHeader( protectedHeaderEncoded );

            // Extract other values.
            encryptedKeyEncoded = jwe.EncryptedKey;
            iv                  = Base64.decodeBase64( jwe.Iv );
            ciphertext          = Base64.decodeBase64( jwe.Ciphertext );
            authenticationTag   = Base64.decodeBase64( jwe.Tag );
        }
        catch ( IllegalArgumentException ex /* Property is empty String or null. */ )
        {
            throw new JweFormatException();
        }

        if ( protectedHeader == null ||
             Strings.isNullOrEmpty( protectedHeader.KeyWrapAlgorithm ) ||
             Strings.isNullOrEmpty( protectedHeader.EncryptionAlgorithm ) ||
             Strings.isNullOrEmpty( protectedHeader.Kid ) )
            throw new JweFormatException();

        // Step 1: Resolve the protection key
        IKey baseKey = keyResolver.resolveKeyAsync( protectedHeader.Kid ).get();

        if ( baseKey == null )
            throw new JweKeyNotFoundException( String.format( "The resolver was unable to resolve key with Kid=%s", protectedHeader.Kid ) );

        // Step 2: Unwrap the CEK according to the specified Key Management Mode
        IKey dataEncryptionKey;

        switch ( protectedHeader.KeyWrapAlgorithm.toLowerCase() )
        {
            case DirectAlgorithm:
                {
                    // Direct Encryption
                    if ( !Strings.isNullOrEmpty( encryptedKeyEncoded ) )
                        throw new JweFormatException( "Bad JWE value: uses direct encryption, but contains wrapped key." );

                    dataEncryptionKey = baseKey;
                }
                break;

            default:
                {
                    // Some form of Key Wrapping algorithm
                    if ( Strings.isNullOrEmpty( encryptedKeyEncoded ) )
                        throw new JweFormatException( "Bad JWE value: algorithm requires wrapped key, but one was not informed." );

                    byte[] encryptedKey           = Base64.decodeBase64( encryptedKeyEncoded );
                    byte[] dataEncryptionKeyBytes = baseKey.unwrapKeyAsync( encryptedKey, protectedHeader.KeyWrapAlgorithm ).get();

                    if ( dataEncryptionKeyBytes == null )
                        throw new JweFormatException( "Unable to unwrap encryption key" );

                    dataEncryptionKey = new SymmetricKey( "cek", dataEncryptionKeyBytes );
                }
                break;
        }

        // Step 2: Decrypt
        return dataEncryptionKey.decryptAsync( ciphertext, iv, protectedHeaderEncoded.getBytes("US-ASCII"), authenticationTag, protectedHeader.EncryptionAlgorithm );
    }

    public static ListenableFuture<byte[]> UnprotectCompactAsync( IKeyResolver keyResolver, String compactJwe ) throws JweFormatException
    {
        if ( keyResolver == null )
            throw new IllegalArgumentException( "keyResolver" );

        if ( Strings.isNullOrEmpty( compactJwe ) )
            throw new IllegalArgumentException( "compactJwe" );

        JweObject jwe = JweObject.fromCompactJwe( compactJwe, false );

        return UnprotectAsync( keyResolver, jwe );
    }

    private static byte[] GenerateIv()
    {
        byte[] iv = new byte[16];
        _rng.nextBytes( iv );
        return iv;
    }

    private static byte[] GenerateKey( int keySizeInBytes )
    {
        byte[] key = new byte[keySizeInBytes];

        _rng.nextBytes( key );

        return key;
    }

    private static JweHeader CreateHeader( String keyWrapAlgorithm, String dataEncryptionAlgorithm, String keyIdentifier )
    {
        // Create the unprotected header
        JweHeader header = new JweHeader();

        header.Kid                 = keyIdentifier;
        header.KeyWrapAlgorithm    = keyWrapAlgorithm;
        header.EncryptionAlgorithm = dataEncryptionAlgorithm;

        return header;
    }

    private static JweObject CreateJwe( String protectedHeader, JweHeader unprotectedHeader, byte[] wrappedKey, byte[] ciphertext, byte[] iv, byte[] authenticationTag )
    {
        JweObject result = new JweObject();

        result.Protected       = protectedHeader;
        result.Unprotected     = unprotectedHeader;
        result.EncryptedKey    = wrappedKey == null ? null : Base64.encodeBase64URLSafeString( wrappedKey );
        result.Ciphertext      = Base64.encodeBase64URLSafeString( ciphertext );
        result.Iv              = Base64.encodeBase64URLSafeString( iv );
        result.Tag             = Base64.encodeBase64URLSafeString( authenticationTag );
        
        return result;
    }

}
