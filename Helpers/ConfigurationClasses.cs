using System;
using System.Collections.Generic;

namespace Casperinc.IdentityProvider.Helpers
{
    public class Host
    {
        public Dictionary<string, EndPoint> Endpoints {get; set;}
    }

    public class EndPoint
    {
        public bool IsEnabled {get; set;}
        public string Address {get; set;}
        public int Port {get; set;}
        public Certificate Certificate {get; set;}

    }

    public class Certificate
    {
        public string Source {get; set;}
        public string Path {get; set;}
        public string Password {get; set;}

    }


    public class OpenIdDict
    {
        public string IssuingAuthority {get; set;}
        public Certificate Certificate {get; set;}
        public string AuthorizationEndpoint {get; set;}
        public string TokenEndpoint {get; set;}
        public string IntrospectionEndPoint {get; set;}

        public Dictionary<string, Client> Clients {get; set;}

    }
 
    public class Client
    {
       public string ClientId  {get; set;}
       public string ClientSecret  {get; set;}
       public string DisplayName  {get; set;}
       public string[] Scopes  {get; set;}
    }





}