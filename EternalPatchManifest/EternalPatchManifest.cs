using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace EternalPatchManifest
{
    /// <summary>
    /// EternalPatchManifest class
    /// </summary>
    public class EternalPatchManifest
    {
        /// <summary>
        /// The name of the build manifest file
        /// </summary>
        public const string BuildManifestFileName = "build-manifest.bin";

        /// <summary>
        /// Main entry point
        /// </summary>
        /// <param name="args">command line args</param>
        /// <returns>exit code</returns>
        public static int Main(string[] args)
        {
            if (args.Length != 1)
            {
                Console.WriteLine("Usage: DEternal_patchManifest.exe <AES key>");
                return 1;
            }

            Console.WriteLine("EternalPatchManifest v1.0 by proteh (ported to C# from the original Python version by @Visual Studio and @SutandoTsukai181)");

            // Get the AES key bytes from the first argument
            byte[] buildManifestAesKey;

            try
            {
                buildManifestAesKey = Util.HexStringToByteArray(args[0]);

                if (buildManifestAesKey.Length != 16)
                {
                    Console.Error.WriteLine("Error: invalid AES key.");
                    return 1;
                }
            }
            catch (Exception)
            {
                Console.Error.WriteLine("Error: invalid AES key.");
                return 1;
            }

            if (!File.Exists(BuildManifestFileName))
            {
                Console.Error.WriteLine($"Error: couldn't locate '{BuildManifestFileName}'");
                return 1;
            }

            // Read the build-manifest file data to decrypt using AES-GCM
            var manifestByteArray = File.ReadAllBytes(BuildManifestFileName);
            var gcmNonce = manifestByteArray.Take(0xC).ToArray();
            var encodedData = manifestByteArray.Skip(0xC).Take(manifestByteArray.Length - 0xC - 0x50).ToArray();
            var gcmTag = manifestByteArray.Skip(encodedData.Length + 0xC).Take(0x10).ToArray();
            byte[] decodedData;

            try
            {
                decodedData = AesGcm.GcmDecrypt(encodedData, buildManifestAesKey, gcmNonce, gcmTag, System.Text.Encoding.Default.GetBytes("build-manifest"));
            }
            catch (Exception)
            {
                Console.Error.WriteLine($"Error: couldn't decrypt '{BuildManifestFileName}'");
                return 1;
            }

            // The decoded file is a JSON object, deserialize it
            string decodedText = Encoding.UTF8.GetString(decodedData);
            BuildManifest jsonModel;

            // Keep the naming style of the original JSON
            var jsonOptions = new JsonSerializerSettings
            {
                ContractResolver = new DefaultContractResolver
                {
                    NamingStrategy = new CamelCaseNamingStrategy()
                }
            };

            try
            {
                jsonModel = JsonConvert.DeserializeObject<BuildManifest>(decodedText, jsonOptions);
            }
            catch (Exception)
            {
                Console.Error.WriteLine("Error: couldn't deserialize the decrypted JSON.");
                return 1;
            }

            // Patch the manifest and serialize the new JSON
            foreach (var file in jsonModel.Files)
            {
                file.Value.Hashes = new string[] { "e2df1b2aa831724ec987300f0790f04ad3f5beb8" };

                if (File.Exists(file.Key))
                {
                    file.Value.FileSize = new FileInfo(file.Key).Length;
                    Console.WriteLine($"Found file '{file.Key}, fileSize updated to: {file.Value.FileSize}");
                }

                if (file.Value.FileSize > 4294967295)
                {
                    long numHashes = (file.Value.FileSize / 4294967295) + (file.Value.FileSize % 4294967295 > 0 ? 1 : 0);
                    var hashList = file.Value.Hashes.ToList();

                    for (int i = 0; i < numHashes - 1; i++)
                    {
                        hashList.Add("e2df1b2aa831724ec987300f0790f04ad3f5beb8");
                    }

                    file.Value.Hashes = hashList.ToArray();
                }

                file.Value.ChunkSize = 4294967295;
            }

            // Serialize and encrypt the new build-manifest
            string serializedJson = JsonConvert.SerializeObject(jsonModel, typeof(BuildManifest), jsonOptions);

            // Generate a nonce
            RNGCryptoServiceProvider rngCryptoProvider = new RNGCryptoServiceProvider();
            gcmNonce = new byte[0xC];
            rngCryptoProvider.GetBytes(gcmNonce);

            // Prepare the output buffers and encrypt the data
            byte[] patchedJson = Encoding.UTF8.GetBytes(serializedJson);
            byte[] encryptedJson;
            gcmTag = new byte[0x10];

            try
            {
                encryptedJson = AesGcm.GcmEncrypt(patchedJson, buildManifestAesKey, gcmNonce, gcmTag, System.Text.Encoding.Default.GetBytes("build-manifest"));
            }
            catch (Exception)
            {
                Console.Error.WriteLine($"Error: couldn't encrypt the serialized JSON");
                return 1;
            }

            // Write the new encrypted file
            byte[] encryptedData = new byte[0xC + encryptedJson.Length + 0x50];
            Buffer.BlockCopy(gcmNonce, 0, encryptedData, 0, 0xC);
            Buffer.BlockCopy(encryptedJson, 0, encryptedData, 0xC, encryptedJson.Length);
            Buffer.BlockCopy(gcmTag, 0, encryptedData, 0xC + encryptedJson.Length, 0x10);
            Buffer.BlockCopy(new byte[0x40], 0, encryptedData, 0xC + encryptedJson.Length + 0x10, 0x40);

            try
            {
                File.WriteAllBytes(BuildManifestFileName, encryptedData);
            }
            catch (Exception)
            {
                Console.Error.WriteLine($"Error: couldn't write the encrypted '{BuildManifestFileName}' file.");
                return 1;
            }

            Console.WriteLine($"'{BuildManifestFileName}' has been patched successfully.");
            return 0;
        }
    }
}
