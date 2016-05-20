using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Hang.Client
{
    public class ChunkParser
    {
        MemoryStream buffer = new MemoryStream();
        public ChunkParser()
        {

        }

        private string bestEffortDecode(byte[] data)
        {
            return UTF8Encoding.UTF8.GetString(data);
        }

        public string GetChunks(byte[] newData)
        {
            buffer.Write(newData, 0, newData.Length);

            while(true)
            {
                byte[] byteArray = new byte[buffer.Length];
                buffer.Read(byteArray, 0, (int)buffer.Length);
                string buf_decoded = bestEffortDecode(byteArray);
                byte[] buf_utf16 = Encoding.Unicode.GetBytes(buf_decoded);
            }
        }
    }
}
