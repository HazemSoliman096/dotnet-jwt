using System.Text;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

namespace Ayth {
  public class JwtAuthenticationManager {
    private readonly string key = String.Empty;
    private readonly IDictionary<string, string> users = new Dictionary<string, string>()
      {{"test", "password"},{"test1", "pwd"}};

    public JwtAuthenticationManager(string key) {
      this.key = key;
    }

    public string Authenticate(string username, string password) {
      if(!users.Any(u => u.Key == username && u.Value == password)) {
        return "Bad login";
      }

      JwtSecurityTokenHandler tokenHandler = new();
      byte[] tokenKey = Encoding.ASCII.GetBytes(key);
      SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor {
        Subject = new ClaimsIdentity(new Claim[] {
          new Claim(ClaimTypes.Name, username)
        }),
        Expires = DateTime.UtcNow.AddHours(1),
        SigningCredentials = new SigningCredentials(
          new SymmetricSecurityKey(tokenKey),
          SecurityAlgorithms.HmacSha256Signature
        )};

        SecurityToken token = tokenHandler.CreateToken(tokenDescriptor);
      return tokenHandler.WriteToken(token);
    }
  }
}