using Windows.UI.ViewManagement;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Hang.Client;
namespace Hang.Views
{
    public sealed partial class MainPage : Page
    {
        HangoutClient client;
        public MainPage()
        {
            InitializeComponent();
            client = new HangoutClient();
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            client.Connect();
        }
    }
}
