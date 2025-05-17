using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using JwtTokenAuthDemo.Entities;
using JwtTokenAuthDemo.Models;
using JwtTokenAuthDemo.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace JwtTokenAuthDemo.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(IAuthService authService) : Controller
    {
        public static User user = new();

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDTO request)
        {
            var user  = await authService.RegisterAsync(request);
            if (user is null)
                return BadRequest("Username already exists!");

            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<TokenResponseDTO>> Login(UserDTO request)
        {
            var result = await authService.LoginAsync(request);
            if(result is null)
                return BadRequest("Invalid username / password !");

            return Ok(result);
        }

        [HttpPost("refresh-token")]
        public async Task<ActionResult<TokenResponseDTO>> RefreshToken(RefreshTokenRequestDTO request)
        {
            var result = await authService.RefreshTokenAsync(request);
            if(result is null || result.AccessToken is null || result.RefreshToken is null)
                return Unauthorized("Invalid refresh token!");
            
            return Ok(result);
        }

        [Authorize]
        [HttpGet]
        public IActionResult AuthenticatedOnlyEndPoint()
        {
            return Ok("You are not authenticated!");
        }

        [Authorize(Roles = "Admin, Super")]
        [HttpGet("admin-only")]
        public IActionResult AdminOnlyEndPoint()
        {
            return Ok("You are admin!");
        }

    }
}
