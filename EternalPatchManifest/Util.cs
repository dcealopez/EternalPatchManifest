using System;

namespace EternalPatchManifest
{
    /// <summary>
    /// Miscellaneous utility functions
    /// </summary>
    public static class Util
    {
        /// <summary>
        /// Converts the given hexadecimal string to a byte array
        /// </summary>
        /// <param name="hexString">hex string to convert</param>
        /// <returns>resulting byte array</returns>
        public static byte[] HexStringToByteArray(string hexString)
        {
            byte[] bytes = new byte[hexString.Length / 2];

            for (int i = 0; i < hexString.Length; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);
            }

            return bytes;
        }
    }
}
