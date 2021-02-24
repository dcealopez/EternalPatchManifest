using System.Collections.Generic;

namespace EternalPatchManifest
{
    /// <summary>
    /// Build Manifest JSON object representation
    /// </summary>
    public class BuildManifest
    {
        /// <summary>
        /// Hash method
        /// </summary>
        public string Hash { get; set; }

        /// <summary>
        /// File list
        /// </summary>
        public Dictionary<string, BuildManifestFile> Files { get; set; }
    }

    /// <summary>
    /// File data
    /// </summary>
    public class BuildManifestFile
    {
        /// <summary>
        /// The size of the file
        /// </summary>
        public long FileSize { get; set; }

        /// <summary>
        /// Hashes per chunk
        /// </summary>
        public string[] Hashes { get; set; }

        /// <summary>
        /// The size of each chunk
        /// </summary>
        public long ChunkSize { get; set; }
    }
}
