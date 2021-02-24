using System;
using PInvoke;
using static PInvoke.BCrypt;
using System.Security.Cryptography;

namespace EternalPatchManifest
{
    /// <summary>
    /// Note that AES GCM encryption is included on .NET Core 3.0 and beyond, but not in the full .NET Framework
    /// This implementation requires PInvoke.BCrypt, and relies on the Windows CNG BCrypt library which
    /// is only available on Windows Vista or later. Note also the requirement for unsafe code.
    /// </summary>
    public unsafe static class AesGcm
    {
        /// <summary>
        /// Encrypts the data using AES-GCM
        /// </summary>
        /// <param name="pbData">data to encrypt</param>
        /// <param name="pbKey">key to use for encryption</param>
        /// <param name="pbNonce">GCM nonce</param>
        /// <param name="pbTag">GCM authentication tag</param>
        /// <param name="pbAuthData">associated autentication data</param>
        /// <returns>the encrypted data</returns>
        public unsafe static byte[] GcmEncrypt(byte[] pbData, byte[] pbKey, byte[] pbNonce, byte[] pbTag, byte[] pbAuthData = null)
        {
            pbAuthData = pbAuthData ?? new byte[0];

            NTSTATUS status = 0;

            using (var provider = BCryptOpenAlgorithmProvider(AlgorithmIdentifiers.BCRYPT_AES_ALGORITHM))
            {
                BCryptSetProperty(provider, PropertyNames.BCRYPT_CHAINING_MODE, ChainingModes.Gcm);

                var tagLengths = BCryptGetProperty<BCRYPT_AUTH_TAG_LENGTHS_STRUCT>(provider, PropertyNames.BCRYPT_AUTH_TAG_LENGTH);

                if (pbTag.Length < tagLengths.dwMinLength ||
                    pbTag.Length > tagLengths.dwMaxLength ||
                    (pbTag.Length - tagLengths.dwMinLength) % tagLengths.dwIncrement != 0)
                {
                    throw new ArgumentException("Invalid tag length");
                }

                using (var key = BCryptGenerateSymmetricKey(provider, pbKey))
                {
                    var authInfo = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO.Create();

                    fixed (byte* pTagBuffer = pbTag)
                    fixed (byte* pNonce = pbNonce)
                    fixed (byte* pAuthData = pbAuthData)
                    {
                        authInfo.pbNonce = pNonce;
                        authInfo.cbNonce = pbNonce.Length;
                        authInfo.pbTag = pTagBuffer;
                        authInfo.cbTag = pbTag.Length;
                        authInfo.pbAuthData = pAuthData;
                        authInfo.cbAuthData = pbAuthData.Length;

                        // Initialize cipher text byte count
                        int pcbCipherText = pbData.Length;

                        // Allocate cipher text buffer
                        byte[] pbCipherText = new byte[pcbCipherText];

                        fixed (byte* plainText = pbData)
                        fixed (byte* cipherText = pbCipherText)
                        {
                            // Encrypt the data
                            status = BCryptEncrypt(
                               key,
                               plainText,
                               pbData.Length,
                               &authInfo,
                               null,
                               0,
                               cipherText,
                               pbCipherText.Length,
                               out pcbCipherText,
                               0);
                        }

                        if (status != NTSTATUS.Code.STATUS_SUCCESS)
                        {
                            throw new CryptographicException($"BCryptEncrypt failed result {status:X} ");
                        }

                        return pbCipherText;
                    }
                }
            }
        }

        /// <summary>
        /// Denrypts the data using AES-GCM
        /// </summary>
        /// <param name="pbData">data to decrypt</param>
        /// <param name="pbKey">key to use for decryption</param>
        /// <param name="pbNonce">GCM nonce</param>
        /// <param name="pbTag">GCM authentication tag to verify</param>
        /// <param name="pbAuthData">associated autentication data</param>
        /// <returns>the decrypted data</returns>
        public unsafe static byte[] GcmDecrypt(byte[] pbData, byte[] pbKey, byte[] pbNonce, byte[] pbTag, byte[] pbAuthData = null)
        {
            pbAuthData = pbAuthData ?? new byte[0];

            NTSTATUS status = 0;

            using (var provider = BCryptOpenAlgorithmProvider(AlgorithmIdentifiers.BCRYPT_AES_ALGORITHM))
            {
                BCryptSetProperty(provider, PropertyNames.BCRYPT_CHAINING_MODE, ChainingModes.Gcm);

                var tagLengths = BCryptGetProperty<BCRYPT_AUTH_TAG_LENGTHS_STRUCT>(provider, PropertyNames.BCRYPT_AUTH_TAG_LENGTH);

                if (pbTag.Length < tagLengths.dwMinLength ||
                    pbTag.Length > tagLengths.dwMaxLength ||
                    (pbTag.Length - tagLengths.dwMinLength) % tagLengths.dwIncrement != 0)
                {
                    throw new ArgumentException("Invalid tag length");
                }

                using (var key = BCryptGenerateSymmetricKey(provider, pbKey))
                {
                    var authInfo = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO.Create();

                    fixed (byte* pTagBuffer = pbTag)
                    fixed (byte* pNonce = pbNonce)
                    fixed (byte* pAuthData = pbAuthData)
                    {
                        authInfo.pbNonce = pNonce;
                        authInfo.cbNonce = pbNonce.Length;
                        authInfo.pbTag = pTagBuffer;
                        authInfo.cbTag = pbTag.Length;
                        authInfo.pbAuthData = pAuthData;
                        authInfo.cbAuthData = pbAuthData.Length;

                        // Initialize cipher text byte count
                        int pcbPlaintext = pbData.Length;

                        // Allocate plaintext buffer
                        byte[] pbPlaintext = new byte[pcbPlaintext];

                        fixed (byte* ciphertext = pbData)
                        fixed (byte* plaintext = pbPlaintext)
                        {
                            // Decrypt the data
                            status = BCryptDecrypt(
                               key,
                               ciphertext,
                               pbData.Length,
                               &authInfo,
                               null,
                               0,
                               plaintext,
                               pbPlaintext.Length,
                               out pcbPlaintext,
                               0);
                        }

                        if (status == NTSTATUS.Code.STATUS_AUTH_TAG_MISMATCH)
                        {
                            throw new CryptographicException("BCryptDecrypt auth tag mismatch");
                        }
                        else if (status != NTSTATUS.Code.STATUS_SUCCESS)
                        {
                            throw new CryptographicException($"BCryptDecrypt failed result {status:X} ");
                        }

                        return pbPlaintext;
                    }
                }
            }
        }
    }
}