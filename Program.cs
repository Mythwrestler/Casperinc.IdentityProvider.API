using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Casperinc.IdentityProvider.Helpers;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Casperinc.IdentityProvider
{
    public class Program
    {
        public static void Main(string[] args)
        {
            BuildWebHost(args).Run();
        }

        public static IWebHost BuildWebHost(string[] args)

        {
            var configuration = new ConfigurationBuilder().AddCommandLine(args).Build();

            return WebHost.CreateDefaultBuilder(args)
                    .UseKestrel(SetHosts)
                    .UseStartup<Startup>()
                    .Build();
        }

        private static void SetHosts(Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServerOptions options)
        {
            var configuration = (IConfiguration)options.ApplicationServices.GetService(typeof(IConfiguration));
            var host = configuration.GetSection("Kestrel_Server").Get<Host>();

            foreach (var endpointKvp in host.Endpoints)
            {
                var endpointName = endpointKvp.Key;
                var endpoint = endpointKvp.Value;
                if (endpoint.IsEnabled)
                {
                    LoadHost(options, endpoint);
                }
            }

        }

        private static void LoadHost(Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServerOptions options, Helpers.EndPoint endPoint)
        {
            var address = IPAddress.Parse(endPoint.Address);
            options.Listen(address, endPoint.Port, listenOption =>
            {
                if (endPoint.Certificate != null)
                {
                    switch (endPoint.Certificate.Source)
                    {
                        case "File":
                            listenOption.UseHttps(endPoint.Certificate.Path, endPoint.Certificate.Password);
                            break;
                        default:
                            throw new NotImplementedException($"File is the only acceptable certificate format");
                    }
                }
            });

            options.UseSystemd();
        }




    }
}
