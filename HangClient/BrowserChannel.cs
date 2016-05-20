using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Windows.Foundation;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Google.Apis.Auth;
using Google.Apis.Auth.OAuth2;
using Google.Apis.Auth.OAuth2.Responses;
using System.Threading;

namespace Hang.Client
{
    public class BrowserChannel
    {
        HttpClient client;
        CookieContainer cookieContainer = new CookieContainer();
        HttpClientHandler handler = new HttpClientHandler();

        public BrowserChannel()
        {
            handler.CookieContainer = cookieContainer;
            client = new HttpClient(handler);
        }

        TokenResponse token;

        //LEN_REGEX = re.compile(r'([0-9]+)\n', re.MULTILINE)

        string originUrl = "https://talkgadget.google.com";
        string channelUrlPrefix = "https://0.client-channel.google.com/client-channel/";
        string OAUTH2_SCOPE = "https://www.google.com/accounts/OAuthLogin";
        string OAUTH2_CLIENT_ID = "936475272427.apps.googleusercontent.com";
        string OAUTH2_CLIENT_SECRET = "KWsJlkaMn1jGLxQpWxMnOox-";
        string OAUTH2_LOGIN_URL = "https://accounts.google.com/o/oauth2/auth?";
        string OAUTH2_TOKEN_REQUEST_URL = "https://accounts.google.com/o/oauth2/token";
        int connectTimeout = 30;

        public bool IsConnected { get; internal set; }
        string Sid;
        string GSessionId;
        ChunkParser chunkParser;

        Uri CookieUri;
        UserCredential credential;
        public async Task Login()
        {
            credential = await GoogleWebAuthorizationBroker.AuthorizeAsync(
                new Uri("ms-appx:///Assets/client_secrets.json"),
                new[] { OAUTH2_SCOPE },
                "user",
                CancellationToken.None);
            token = credential.Token;

        }

        public async Task Logout()
        {

        }

        public async Task Connect()
        {
            await Login();
            bool cookiesReceived = false;
            while (!cookiesReceived)
            {
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token.AccessToken);
                var response = await client.GetAsync("https://accounts.google.com/accounts/OAuthLogin?source=hangups&issueuberauth=1");
                var responseText = await response.Content.ReadAsStringAsync();

                response = await client.GetAsync("https://accounts.google.com/MergeSession?service=mail&continue=http://www.google.com&uberauth=" + responseText);
                responseText = await response.Content.ReadAsStringAsync();
                IEnumerable<string> cookies;
                if (response.Headers.TryGetValues("set-cookie", out cookies))
                {
                    cookiesReceived = true;
                    foreach (var c in cookies)
                    {
                        cookieContainer.SetCookies(response.RequestMessage.RequestUri, c);
                        CookieUri = response.RequestMessage.RequestUri;
                    }
                } else {
                    Debug.WriteLine("No cookies received");
                    cookiesReceived = false;
                    CancellationToken token = new CancellationToken();
                    await GoogleWebAuthorizationBroker.ReauthorizeAsync(credential, token);
                }
            }

            listen();
        }

        private async Task listen()
        {
            int maxRetries = 5;
            int retries = maxRetries;
            bool needNewSid = true;
            while(retries >= 0)
            {
                if (retries + 1 < maxRetries)
                {
                    await Task.Delay((int)(1000 * Math.Pow(2, (maxRetries - retries))));
                }
                if(needNewSid)
                {
                    await fetchChannelSid();
                    needNewSid = false;
                }
                chunkParser =new ChunkParser();
                bool success = await longPollRequest();
                if (!success)
                    needNewSid = true;
                await Task.Delay(1000);
            }
        }

        private async Task<bool> longPollRequest()
        {
            setHeaders();
            // URL parameters
            List<KeyValuePair<string, string>> param = new List<KeyValuePair<string, string>>();
            param.Add(new KeyValuePair<string, string>("VER", "8"));
            param.Add(new KeyValuePair<string, string>("gsessionid", GSessionId));
            param.Add(new KeyValuePair<string, string>("RID", "rpc"));
            param.Add(new KeyValuePair<string, string>("t", "1"));
            param.Add(new KeyValuePair<string, string>("SID", Sid));
            param.Add(new KeyValuePair<string, string>("CI", "0"));
            param.Add(new KeyValuePair<string, string>("ctype", "hangouts"));
            param.Add(new KeyValuePair<string, string>("TYPE", "xmlhttp"));
            string query = await new FormUrlEncodedContent(param).ReadAsStringAsync();
            string uri = channelUrlPrefix + "channel/bind?" + query;
            Debug.WriteLine("Requesting: " + uri);
            var res = await client.GetAsync(uri);

            Debug.WriteLine(String.Format("Received status code {0}. Response: {1}", res.StatusCode, await res.Content.ReadAsStringAsync()));
            if (res.StatusCode == HttpStatusCode.BadRequest)
                return false;
            return true;
        }

        private async Task fetchChannelSid()
        {
            Debug.WriteLine("Requesting new gsessionid and SID...");
            Sid = "";
            GSessionId = "";
            var response = await sendMaps(null);
            string responseString = await response.Content.ReadAsStringAsync();
            responseString = Regex.Replace(responseString, @"[0-9]+\n", "");
            dynamic responseObject = JArray.Parse(responseString);
            Sid = (string)responseObject[0][1][1];
            Debug.WriteLine("New SID is " + Sid);
            GSessionId = (string)responseObject[1][1][0].gsid;
            Debug.WriteLine("New gsessionidparam is " + GSessionId);
        }

        private async Task<HttpResponseMessage> sendMaps(List<KeyValuePair<string, string>> maps)
        {
            // URL parameters
            List<KeyValuePair<string, string>> param = new List<KeyValuePair<string, string>>();
            param.Add(new KeyValuePair<string, string>("VER", "8"));
            param.Add(new KeyValuePair<string, string>("RID", "81188"));
            param.Add(new KeyValuePair<string, string>("ctype", "hangouts"));
            if(GSessionId.Length > 0)
                param.Add(new KeyValuePair<string, string>("gsessionid", GSessionId));
            if(Sid.Length > 0)
                param.Add(new KeyValuePair<string, string>("SID", Sid));
            string query = await new FormUrlEncodedContent(param).ReadAsStringAsync();

            string uri = channelUrlPrefix + "channel/bind?" + query;

            List<KeyValuePair<string, string>> data = new List<KeyValuePair<string, string>>();
            setHeaders();
            if (maps != null)
            {
                // dater
                data.Add(new KeyValuePair<string, string>("count", maps.Count.ToString()));
                data.Add(new KeyValuePair<string, string>("ofs", "0"));

                int i = 0;
                foreach (KeyValuePair<string, string> map in maps)
                {
                    data.Add(new KeyValuePair<string, string>(String.Format("req{0}_{1}", i, map.Key), map.Value));
                }
                FormUrlEncodedContent content = new FormUrlEncodedContent(data);
                Debug.WriteLine(String.Format("Sending content: {0} to {1}", await content.ReadAsStringAsync(), uri));
                return await client.PostAsync(uri, content);
            }
            else {
                data.Add(new KeyValuePair<string, string>("count", "0"));
                Debug.WriteLine(String.Format("Sending content: (EMPTY) to {0}", uri));
                return await client.PostAsync(uri, new FormUrlEncodedContent(data));
            }


        }
        HashAlgorithmProvider hashAlgorithmProvider = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Sha1);

        private void setHeaders()
        {
            int timeMilliseconds = (int)(DateTime.Now.Ticks / TimeSpan.TicksPerMillisecond);
            string cookieString = "";
            if (CookieUri == null)
                return;

            foreach (Cookie cookie in cookieContainer.GetCookies(CookieUri))
            {
                cookieString = cookie.Value;
            }
            
            var bufferString = CryptographicBuffer.ConvertStringToBinary(cookieString, BinaryStringEncoding.Utf8);
            var bufferHash = hashAlgorithmProvider.HashData(bufferString);
            string hexHash = CryptographicBuffer.EncodeToHexString(bufferHash);
            string sapiSidHash = String.Format("{0}_{1}", timeMilliseconds, hexHash);
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("SAPISIDHASH", sapiSidHash);
            client.DefaultRequestHeaders.TryAddWithoutValidation("x-goog-authuser", "0");
            client.DefaultRequestHeaders.TryAddWithoutValidation("x-origin", "https://hangouts.google.com");
            Debug.WriteLine("Setting headers...");
            foreach(var header in client.DefaultRequestHeaders)
            {
                Debug.WriteLine(String.Format("header: {0}: {1}", header.Key, header.Value.First()));
            }
        }

        private void parseSidResponse()
        {

        }

    }
}
