using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;

namespace AuthSample.Pages.Security
{
    public class LoginViewModel
    {
        public LoginViewModel(AppSettings settings)
        {
            DataSources = settings.DataSources.Sources.Select(d => d.Name);
            SelectedDataSource = settings.DataSources.Sources.FirstOrDefault(d => d.IsDefault).Name;
            DataSourcesEnabled = !settings.DataSources.IsLocked;
        }

        //für serialisierung notwendig.
        public LoginViewModel()
        {
                
        }

        public void Clear()
        {
            UserName = null;
            Password = null;
        }

        [Required]
        public string UserName { get; set; }

        [Required]
        public string Password { get; set; }

        public IEnumerable<string> DataSources { get; set; }

        public string SelectedDataSource { get; set; }

        public bool DataSourcesEnabled { get; set; }
    }
}
