using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace HashConverter
{
    public class Program
    {
        private const string V2Charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";
        private const int BitMask8Bit = 0xff;

        private static readonly byte[] LotusMagicTable =
        {
            0xbd, 0x56, 0xea, 0xf2, 0xa2, 0xf1, 0xac, 0x2a, 0xb0, 0x93, 0xd1, 0x9c, 0x1b, 0x33, 0xfd, 0xd0, 0x30, 0x04,
            0xb6, 0xdc, 0x7d, 0xdf, 0x32, 0x4b, 0xf7, 0xcb, 0x45, 0x9b, 0x31, 0xbb, 0x21, 0x5a, 0x41, 0x9f, 0xe1, 0xd9,
            0x4a, 0x4d, 0x9e, 0xda, 0xa0, 0x68, 0x2c, 0xc3, 0x27, 0x5f, 0x80, 0x36, 0x3e, 0xee, 0xfb, 0x95, 0x1a, 0xfe,
            0xce, 0xa8, 0x34, 0xa9, 0x13, 0xf0, 0xa6, 0x3f, 0xd8, 0x0c, 0x78, 0x24, 0xaf, 0x23, 0x52, 0xc1, 0x67, 0x17,
            0xf5, 0x66, 0x90, 0xe7, 0xe8, 0x07, 0xb8, 0x60, 0x48, 0xe6, 0x1e, 0x53, 0xf3, 0x92, 0xa4, 0x72, 0x8c, 0x08,
            0x15, 0x6e, 0x86, 0x00, 0x84, 0xfa, 0xf4, 0x7f, 0x8a, 0x42, 0x19, 0xf6, 0xdb, 0xcd, 0x14, 0x8d, 0x50, 0x12,
            0xba, 0x3c, 0x06, 0x4e, 0xec, 0xb3, 0x35, 0x11, 0xa1, 0x88, 0x8e, 0x2b, 0x94, 0x99, 0xb7, 0x71, 0x74, 0xd3,
            0xe4, 0xbf, 0x3a, 0xde, 0x96, 0x0e, 0xbc, 0x0a, 0xed, 0x77, 0xfc, 0x37, 0x6b, 0x03, 0x79, 0x89, 0x62, 0xc6,
            0xd7, 0xc0, 0xd2, 0x7c, 0x6a, 0x8b, 0x22, 0xa3, 0x5b, 0x05, 0x5d, 0x02, 0x75, 0xd5, 0x61, 0xe3, 0x18, 0x8f,
            0x55, 0x51, 0xad, 0x1f, 0x0b, 0x5e, 0x85, 0xe5, 0xc2, 0x57, 0x63, 0xca, 0x3d, 0x6c, 0xb4, 0xc5, 0xcc, 0x70,
            0xb2, 0x91, 0x59, 0x0d, 0x47, 0x20, 0xc8, 0x4f, 0x58, 0xe0, 0x01, 0xe2, 0x16, 0x38, 0xc4, 0x6f, 0x3b, 0x0f,
            0x65, 0x46, 0xbe, 0x7e, 0x2d, 0x7b, 0x82, 0xf9, 0x40, 0xb5, 0x1d, 0x73, 0xf8, 0xeb, 0x26, 0xc7, 0x87, 0x97,
            0x25, 0x54, 0xb1, 0x28, 0xaa, 0x98, 0x9d, 0xa5, 0x64, 0x6d, 0x7a, 0xd4, 0x10, 0x81, 0x44, 0xef, 0x49, 0xd6,
            0xae, 0x2e, 0xdd, 0x76, 0x5c, 0x2f, 0xa7, 0x1c, 0xc9, 0x09, 0x69, 0x9a, 0x83, 0xcf, 0x29, 0x39, 0xb9, 0xe9,
            0x4c, 0xff, 0x43, 0xab
        };

        public static void Main()
        {
            const string wordBuf = "Password1!"; // Input
            const string hashTarget = "(GWAcsGfvOwCBnPBeLQwm)"; // Expected hash result of Input
            
            Console.WriteLine($"Password: {wordBuf}");

            List<byte> savedKey = Encoding.ASCII.GetBytes(wordBuf).ToList();

            List<byte> state = DominoBigMd(ref savedKey, savedKey.Count);

            var hash = $"({BitConverter.ToString(state.ToArray()).Replace("-", string.Empty)})";
            Console.WriteLine($"Domino 5 Hash: {hash}");

            const int offset = 2;
            string base64Part = hashTarget.Substring(offset, hashTarget.Length - offset - 1);
            byte[] salt6Buf = Domino6Decode(base64Part);
            
            savedKey = salt6Buf.Concat(Encoding.ASCII.GetBytes(hash)).ToList();
            state = DominoBigMd(ref savedKey, 34);
            
            List<byte> saltAndHashBytes = salt6Buf.ToList();
            saltAndHashBytes.AddRange(state);
            var tempHash = $"(G{DominoEncode(saltAndHashBytes)})";
            Console.WriteLine($"Domino 6 Hash: {tempHash}");

            if (hashTarget.StartsWith("(G"))
            {
                Console.WriteLine(tempHash == hashTarget
                    ? "Success, Domino 6 hash matches target hash!"
                    : $"Hash {tempHash} does not match target {hashTarget}");
            }
            else
            {
                Console.WriteLine("TODO: Domino 8 Hash");
            }
        }

        // Helper - going to leave until we've done Domino 8.
        private static void PrintArray<T>(string prefix, IEnumerable<T> array)
        {
            Console.WriteLine($"{prefix}{(!string.IsNullOrEmpty(prefix) ? ": " : "")}{string.Join(" ", array)}");
        }

        private static List<byte> DominoBigMd(ref List<byte> savedKey, int size)
        {
            savedKey = savedKey.Take(size).ToList();
            
            var state = new List<byte>(Enumerable.Repeat<byte>(0, 16));
            var checksum = new List<byte>(Enumerable.Repeat<byte>(0, 16)); // Size "defined" by the loop in LotusTransformPassword

            int currentPosition;
            for (currentPosition = 0; currentPosition + 16 < size; currentPosition += 16)
            {
                List<byte> currentBlock = savedKey.Skip(currentPosition).Take(16).ToList();
                MdTransform(ref state, ref checksum, ref currentBlock);
            }

            int left = size - currentPosition;
            List<byte> block = savedKey.Skip(currentPosition).Take(16).ToList();

            Pad16(ref block, left);
            MdTransform(ref state, ref checksum, ref block);
            MdTransformNoRecalc(ref state, ref checksum);
            
            return state;
        }

        private static void MdTransform(ref List<byte> state, ref List<byte> checksum, ref List<byte> block)
        {
            MdTransformNoRecalc(ref state, ref block);
            LotusTransformPassword(ref block, ref checksum);
        }

        private static void MdTransformNoRecalc(ref List<byte> state, ref List<byte> block)
        {
            var x = new List<byte>();
            x.AddRange(state);
            x.AddRange(block);

            for (var i = 0; i < 16; i++)
            {
                x.Add(Convert.ToByte(x[0 + i] ^ x[16 + i]));
            }

            LotusMix(ref x);

            for (var i = 0; i < 16; i++)
            {
                state[i] = x[i];
            }
        }

        private static void LotusMix(ref List<byte> x)
        {
            byte p = 0;

            for (var i = 0; i < 18; i++)
            {
                for (byte j = 0; j < 48; j++)
                {
                    p = Convert.ToByte((p + 48 - j) & BitMask8Bit);
                    p = Convert.ToByte(x[j] ^ LotusMagicTable[p]);
                    x[j] = p;
                }
            }
        }

        private static void LotusTransformPassword(ref List<byte> block, ref List<byte> checksum)
        {
            byte t = checksum[15];

            for (var i = 0; i < 16; i++)
            {
                t ^= block[i];

                byte c = LotusMagicTable[t];
                checksum[i] ^= c;

                t = checksum[i];
            }
        }

        private static void Pad16(ref List<byte> block, int offset)
        {
            int value = 16 - offset;

            for (int i = offset; i < 16; i++)
            {
                block.Add((byte)value);
            }
        }

        private static byte[] Domino6Decode(string base64Part)
        {
            var decoded = new byte[base64Part.Length];
            var index = 0;

            for (var i = 0; i < base64Part.Length; i += 4)
            {
                int substringLength = i + 4 > base64Part.Length ? base64Part.Length - i : 4;
                int num = DominoBase64Decode(base64Part.Substring(i, substringLength), substringLength);

                decoded[index++] = Convert.ToByte((num >> 16) & BitMask8Bit);
                decoded[index++] = Convert.ToByte((num >> 8) & BitMask8Bit);
                decoded[index++] = Convert.ToByte(num & BitMask8Bit);
            }

            byte[] salt = decoded.Take(5).ToArray();
            int byte10 = salt[3] - 4;
            if (byte10 < 0)
                byte10 += 256;

            salt[3] = Convert.ToByte(byte10);
            return salt;
        }

        private static int DominoBase64Decode(string stringPart, int iterations)
        {
            var ret = 0;
            var i = 1;

            while (i <= iterations)
            {
                int index = V2Charset.IndexOf(stringPart[iterations - i]) & 0x3f;
                ret += index << (6 * (i - 1));
                i += 1;
            }

            return ret;
        }

        private static string DominoEncode(IList<byte> final)
        {
            int byte10 = final[3] + 4;
            if (byte10 > 255)
            {
                byte10 -= 256;
            }

            final[3] = (byte) byte10;

            var passwd = string.Empty;

            for (var i = 0; i < 15; i += 3)
            {
                passwd += DominoBase64Encode((final[i] << 16) | (final[i+1] << 8) | final[i+2], 4);
            }

            return passwd.Remove(passwd.Length - 1, 1);
        }

        private static string DominoBase64Encode(int v, int n)
        {
            var ret = "";

            while (n - 1 >= 0)
            {
                n -= 1;
                ret = V2Charset.Substring(v & 0x3f, 1) + ret;
                v >>= 6;
            }

            return ret;
        }
    }
}
