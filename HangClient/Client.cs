using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;

using Windows.Storage;
using System.IO;
using System.Net.Http;

namespace Hang.Client
{
    public class HangoutClient
    {
        BrowserChannel browserChannel = new BrowserChannel();
        public HangoutClient()
        {
            
        }

        public async Task Connect()
        {
            await browserChannel.Connect();
        }

        bool activeClientState = false;
        DateTime lastActive = DateTime.Now;

        public void SetActive()
        {
            if(!activeClientState && DateTime.Now - lastActive > TimeSpan.FromSeconds(60))
            {
                
            }

        }
    }
}
