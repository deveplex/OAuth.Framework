using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

    public class AuthorizeViewModel
    {
        public string AppId { get; set; }
        public string Response_Type { get; set; }
        public string Scope { get; set; }
        public string State { get; set; }
        public string Redirect_Uri { get; set; }
    }
