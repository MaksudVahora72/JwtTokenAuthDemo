using JwtTokenAuthDemo.Entities;
using Microsoft.EntityFrameworkCore;

namespace JwtTokenAuthDemo.Data
{
    public class ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : DbContext(options)
    {
        public DbSet<User> Users { get; set; }
    }
}
