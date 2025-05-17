using JwtTokenAuthDemo.Entities;
using JwtTokenAuthDemo.Models;

namespace JwtTokenAuthDemo.Services
{
    public interface IAuthService
    {
        Task<User?> RegisterAsync(UserDTO request);

        Task<TokenResponseDTO?> LoginAsync(UserDTO request);
    
        Task<TokenResponseDTO?> RefreshTokenAsync(RefreshTokenRequestDTO request);
    }
}
