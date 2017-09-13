using System.Threading.Tasks;
using Casperinc.IdentityProvider.Data.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Casperinc.IdentityProvider.Data
{
    public class UserSeed
    {
        private ProviderDbContext _dbContext;
        private UserManager<User> _userManager;
        private RoleManager<IdentityRole> _roleManager;

        public UserSeed(ProviderDbContext dbContext,
            RoleManager<IdentityRole> roleManager,
            UserManager<User> userManager)
        {
            _dbContext = dbContext;
            _roleManager = roleManager;
            _userManager = userManager;
        }

		public async Task SeedAsync()
		{
			_dbContext.Database.EnsureCreated();

			if (await _dbContext.Users.CountAsync() == 0)
			{
				await CreateUserAsync();
			}

		}



        private async Task CreateUserAsync()
        {

			string role_Administrators = "Administrators";
			string role_Registered = "Registered";

			// Create Roles
			if (!await _roleManager.RoleExistsAsync(role_Administrators))
			{
				await _roleManager.CreateAsync(new IdentityRole(role_Administrators));
			}
			if (!await _roleManager.RoleExistsAsync(role_Registered))
			{
				await _roleManager.CreateAsync(new IdentityRole(role_Registered));
			}

			// Create the "Admin" ApplicationUser account (if it does not exist)
			var user_admin = new User()
			{
				UserName = "Admin",
				Email = "admin@casperinc.expert"
			};

			// Insert "Admin" into the Database and assign "Administrator" Role
			if (await _userManager.FindByIdAsync(user_admin.Id) == null)
			{
				await _userManager.CreateAsync(user_admin, "Pass4Admin");
				await _userManager.AddToRoleAsync(user_admin, role_Administrators);
				//Mark Email as confirmed and remove Account Lock
				user_admin.EmailConfirmed = true;
				user_admin.LockoutEnabled = false;
			}
			await _dbContext.SaveChangesAsync();
        }


    }
}
