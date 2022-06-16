using System.Security.Cryptography;
using System.Text;

namespace RENAME_TO_PROJECT_NAME.Repositories.Helpers
{
    public static class KeyGenerator
    {
        internal static readonly char[] chars =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".ToCharArray();

        public static string GetUniqueKey(int size)
        {
            byte[] data = new byte[4 * size];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(data);
            }
            StringBuilder result = new StringBuilder(size);
            for (int i = 0; i < size; i++)
            {
                var rnd = BitConverter.ToUInt32(data, i * 4);
                var idx = rnd % chars.Length;

                result.Append(chars[idx]);
            }

            return result.ToString();
        }
    }
        
}
