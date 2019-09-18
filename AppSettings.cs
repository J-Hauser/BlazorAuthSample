using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthSample
{
    public class AppSettings
    {
        public DataSources DataSources { get; set; }
    }

    public class DataSources
    {
        public List<DataSource> Sources { get; set; }

        public bool IsLocked { get; set; }
    }

    public class DataSource
    {
        public string Name { get; set; }
        public bool IsDefault { get; set; }

    }
}
