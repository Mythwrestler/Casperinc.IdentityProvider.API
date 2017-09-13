using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.AspNetCore.Identity;

namespace Casperinc.IdentityProvider.Data.Models
{
    public class User : IdentityUser
    {

		public string DisplayName { get; set; }

		[Required]
		[DatabaseGenerated(DatabaseGeneratedOption.Identity)]
		public DateTime CreatedDate { get; set; }

		[Required]
		[DatabaseGenerated(DatabaseGeneratedOption.Computed)]
		public DateTime UpdatedDate { get; set; }

        public User()
        {
        }

	}

}
