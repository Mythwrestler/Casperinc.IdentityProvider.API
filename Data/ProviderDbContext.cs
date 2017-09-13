using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Casperinc.IdentityProvider.Data.Models;

namespace Casperinc.IdentityProvider.Data
{
    public class ProviderDbContext : IdentityDbContext<User>
    {
        public ProviderDbContext(DbContextOptions options) : base(options)
        { }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

        }
    }
}
