using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using RENAME_TO_PROJECT_NAME.Models.Users;
using RENAME_TO_PROJECT_NAME.Data;
using RENAME_TO_PROJECT_NAME.Data.Entities;
using RENAME_TO_PROJECT_NAME.Models.RefreshTokenModel;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using RENAME_TO_PROJECT_NAME.Repositories.Helpers;
using System.Web;
using RENAME_TO_PROJECT_NAME.Services;
using Microsoft.AspNetCore.WebUtilities;
using RENAME_TO_PROJECT_NAME.Exceptions;
using RENAME_TO_PROJECT_NAME.Models.Common;
using RENAME_TO_PROJECT_NAME.Models;
using Microsoft.Extensions.Logging;

namespace RENAME_TO_PROJECT_NAME.Repositories
{
    public class UserRepository : IUserRepository
    {
        private readonly AppDbContext _context;
        private readonly UserManager<User> _userManager;
        private readonly RoleManager<Role> _roleManager;
        private readonly SignInManager<User> _signInManager;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly AppSettings _appSettings;
        private readonly ClaimsPrincipal _user;
        private readonly IMailService _mailer;
        private readonly ILogger<UserRepository> _logger;

        public UserRepository(
            AppDbContext context,
            UserManager<User> userManager,
            RoleManager<Role> roleManager,
            SignInManager<User> signInManager,
            IHttpContextAccessor httpContextAccessor,
            IOptions<AppSettings> appSettings,
            IMailService mailer,
            ILogger<UserRepository> logger)
        {
            _context = context;
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
            _httpContextAccessor = httpContextAccessor;
            _appSettings = appSettings.Value;
            _user = _httpContextAccessor.HttpContext.User;
            _mailer = mailer;
            _logger = logger;
        }

        public async Task<GetListModel<GetUserModel>> GetUsers(int number, int page)
        {
            List<GetUserModel> users = await _context.Users
                .Include(x => x.UserRoles).ThenInclude(x => x.Role)
                .Select(x => MakeModel.MakeGetUserModel(x))
                .AsNoTracking()
                .ToListAsync();

            if (users.Count == 0)
            {
                throw new AppException("NotFoundExeption", "Geen gebruikers gevonden.", this.GetType().Name, "GetUsers", "404");
            }

            return MakeModel.MakeGetListModel(number, page, users);
        }

        public async Task<GetUserModel> GetUser(Guid id, bool camefrompost = false)
        {
            if (!_user.IsInRole("QrWalletAdmin") && !_user.IsInRole("EventAdmin") && !camefrompost)
            {
                if (_user.Identity.Name != id.ToString())
                {
                    throw new AppException("ForbiddenException", "U mag deze gebruiker niet ophalen.", this.GetType().Name, "GetUser", "403");
                }
            }

            User user = await _context.Users
                .Include(x => x.UserRoles).ThenInclude(x => x.Role).AsNoTracking()
                .FirstOrDefaultAsync(x => x.Id == id);

            if (user == null)
            {
                throw new AppException("NotFoundException", "Gebruiker niet gevonden.", this.GetType().Name, "GetUser", "404");
            }

            return MakeModel.MakeGetUserModel(user);
        }

        public async Task<GetUserModel> PostUser(PostUserModel postUserModel)
        {
            if(postUserModel.Password != postUserModel.ConfirmPassword)
            {
                throw new AppException("IdentityException", "Wachtwoorden komen niet overeen", this.GetType().Name, "PostUser", "409");
            }

            var usersWithEmail = await _context.Users.Where(x => x.Email == postUserModel.Email).ToListAsync();

            if (usersWithEmail.Count >= 1)
            {
                throw new AppException("IdentityException", $"Gebruiker met dit email bestaat al.", this.GetType().Name, "PostUser", "409");
            }

            User user = new User
            {
                UserName = postUserModel.Email,
                Firstname = postUserModel.Firstname,
                Lastname = postUserModel.Lastname,
                Email = postUserModel.Email,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };

            if (_user.IsInRole("EventAdmin"))
            {
                var adminUser = await _context.Users.FirstOrDefaultAsync(u => u.Id == Guid.Parse(_user.Identity.Name));

                if(adminUser == null)
                {
                    throw new AppException("NotFoundException", $"Gebruiker met dit email bestaat al.", this.GetType().Name, "PostUser", "409");
                }

            }

            IdentityResult userResult = await _userManager.CreateAsync(user, postUserModel.Password);

            if (!userResult.Succeeded)
            {
                throw new AppException("EntityError", userResult.Errors.First().Description, this.GetType().Name, "PostUser", "400");
            }

            try
            {
                if (postUserModel.Roles == null || !_user.IsInRole("QrWalletAdmin"))
                {
                    await _userManager.AddToRoleAsync(user, "Visitor");
                }
                else
                {
                    await _userManager.AddToRolesAsync(user, SanitizeRoles(postUserModel.Roles));
                }
            }
            catch (Exception e)
            {
                await _userManager.DeleteAsync(user);
                throw new AppException("IdentityError", e.Message, this.GetType().Name, "PostUser", "400");
            }

            return await GetUser(user.Id, true);
        }

        public async Task PutUser(Guid id, PutUserModel putUserModel)
        {
            bool isAdmin = true;
            if (!_user.IsInRole("QrWalletAdmin") && !_user.IsInRole("EventAdmin"))
            {
                isAdmin = false;
                if(_user.Identity.Name != id.ToString())
                {
                    throw new AppException("ForbiddenExeption", "U mag deze gebruiker niet aanpassen.", this.GetType().Name, "PutUser", "403");
                }
            }

            User user = await _context.Users.FirstOrDefaultAsync(x => x.Id == id);

            if (user == null)
            {
                throw new AppException("NotFoundException", "Gebruiker niet gevonden.", this.GetType().Name, "PutUser", "404");
            }

            if (_user.IsInRole("EventAdmin"))
            {
                var adminUser = await _context.Users.FirstOrDefaultAsync(u => u.Id == Guid.Parse(_user.Identity.Name));

                if(adminUser == null)
                {
                    throw new AppException("NotFoundException", "Admin Gebruiker niet gevonden.", this.GetType().Name, "PutUser", "404");
                }
            }

            var usersWithEmail = await _context.Users.Where(x => x.Email == putUserModel.Email).ToListAsync();
            if (usersWithEmail.Count >= 1)
            {
                foreach(User u in usersWithEmail)
                {
                    if(id != u.Id)
                    {
                        //throw new EmailException("Kan het email adres niet veranderen naar: {0}", this.GetType().Name, "PutUser", "400", putUserModel.Email);
                        throw new AppException("IdentityException", "Kan uw email adres niet verandanderen in gekozen email adres.", this.GetType().Name, "PutUser", "409");
                    }
                }
            }
           
            if (putUserModel.Roles == null)
            {
                throw new AppException("EntityException","Gebruiker moet minstens 1 rol hebben.", this.GetType().Name, "PutUser", "409");
            }

            if(putUserModel.Email != user.Email)
            {
                user.EmailConfirmed = false;

                await SendConfirmMail(user, putUserModel.Email);
            }

            if (isAdmin)
            {
                await _userManager.RemoveFromRolesAsync(user, await _userManager.GetRolesAsync(user));
            }

            user.Firstname = putUserModel.Firstname;
            user.Lastname = putUserModel.Lastname;
            user.Email = putUserModel.Email;
            user.UserName = putUserModel.Email;

            user.UpdatedAt = DateTime.UtcNow;

            if (isAdmin)
            {
                await _userManager.AddToRolesAsync(user, SanitizeRoles(putUserModel.Roles));
            }
            

            IdentityResult result = await _userManager.UpdateAsync(user);
            
        }

        private List<string> SanitizeRoles(ICollection<string> roles)
        {
            List<string> _roles = (List<string>)roles;
            if (!_user.IsInRole("QrWalletAdmin") && roles.Contains("QrWalletAdmin"))
            {
                throw new AppException("ForbiddenException", "U mag deze rol niet toekennen aan deze gebruiker.", this.GetType().Name, "PutUser", "403");
            }
            if (roles.Contains("EventAdmin") || roles.Contains("QrWalletAdmin"))
            {
                _roles.RemoveAll(r => r.Contains("Can"));
                _roles.RemoveAll(r => r.Equals("EventStaff"));

                if (_roles.Contains("QrWalletAdmin"))
                {
                    _roles.RemoveAll(r => r.Equals("EventAdmin"));
                }
            }

            return _roles;
        }

        public async Task PatchUser(Guid id, PatchUserModel patchUserModel)
        {
            if (_user.Identity.Name != id.ToString())
            {
                throw new AppException("ForbiddenException", "U mag deze gebruiker's wachtwoord niet aanpassen.", this.GetType().Name, "PatchUser", "403");
            }


            if (patchUserModel.NewPassword != patchUserModel.NewConfirmPassword)
            {
                throw new AppException("IdentityException", "Wachtwoorden komen niet overeen", this.GetType().Name, "PostUser", "400");
            }

            /*if (_user.Claims.Where(x => x.Type.Contains("role")).Count() == 1 &&
                 _user.IsInRole("Klant") &&
                 _user.Identity.Name != id.ToString())
            {
                throw new AppException("Forbidden","Forbidden to change this user password.", this.GetType().Name, "PatchUser", "403");
            }*/

            User user = await _context.Users.FirstOrDefaultAsync(x => x.Id == id);

            if (user == null)
            {
                throw new AppException("NotFoundException", "Gebruiker niet gevonden.", this.GetType().Name, "PatchUser", "404");
            }

            user.UpdatedAt = DateTime.UtcNow;
            
            IdentityResult result = await _userManager.ChangePasswordAsync(user, patchUserModel.CurrentPassword, patchUserModel.NewPassword);

            if (!result.Succeeded)
            {
                throw new AppException("IdentityException", result.Errors.First().Description, this.GetType().Name, "PatchUser", "400");
            }
        }

        public async Task DeleteUser(Guid id)
        {
            if (!_user.IsInRole("QrWalletAdmin"))
            {
                if (_user.Identity.Name != id.ToString())
                {
                    throw new AppException("Forbidden","U mag deze gebruiker niet verwijderen.", this.GetType().Name, "DeleteUser", "403");
                }
            }
            else
            {
                var users = _userManager.Users;

               
                //var admins = users.Select(x => x.Roles.Contains("Administrator")).ToList();

                if (users.Where(u => u.UserRoles.Any(r => r.Role.Name.Equals("QrWalletAdmin"))).Count() == 1)
                {
                    throw new AppException("EntityException","Deze gebruiker is de laatste administrator, gelieve eerst een andere administrator aan te stellen.", this.GetType().Name, "DeletUser", "409");
                }

            }

           
                //User user = await _userManager.FindByIdAsync(id.ToString());

                User user = await _context.Users.FirstOrDefaultAsync(x => x.Id == id);

                if (user == null)
                {
                    throw new AppException("EntityException","Gebruiker niet gevonden.", this.GetType().Name, "DeleteUser", "404");
                }
            
        }

        public async Task<List<GetRefreshTokenModel>> GetUserRefreshTokens(Guid id)
        {
            List<GetRefreshTokenModel> refreshTokens = await _context.RefreshTokens
                .Where(x => x.UserId == id)
                .Select(x => new GetRefreshTokenModel
                {
                    Id = x.Id,
                    Token = x.Token,
                    Expires = x.Expires,
                    IsExpired = x.IsExpired,
                    Created = x.Created,
                    CreatedByIp = x.CreatedByIp,
                    Revoked = x.Revoked,
                    RevokedByIp = x.RevokedByIp,
                    ReplacedByToken = x.ReplacedByToken,
                    IsActive = x.IsActive
                })
                .AsNoTracking()
                .ToListAsync();

            if (refreshTokens.Count == 0)
            {
                throw new AppException("NotFound", "Geen refreshtoken gevonden.", this.GetType().Name, "GetUserRefreshTokens", "404");
            }

            return refreshTokens;
        }

        public async Task ConfirmEmail(PostConfirmEmailModel postConfirmEmailModel)
        {
            
            if (string.IsNullOrWhiteSpace(postConfirmEmailModel.Email) || string.IsNullOrWhiteSpace(postConfirmEmailModel.Token))
            {
                throw new AppException("ParameterException", "Email of token is leeg of ongeldig.", this.GetType().Name, "ConfirmEmail", "400");
            }

            User user = await _userManager.FindByEmailAsync(postConfirmEmailModel.Email);

            if(user == null)
            {
                throw new AppException("ParameterException", "Email of token is leeg of ongeldig.", this.GetType().Name, "ConfirmEmail", "400");
            }

            var urldecoded = HttpUtility.UrlDecode(postConfirmEmailModel.Token).Replace(' ', '+');

            IdentityResult result = await _userManager.ConfirmEmailAsync(user, urldecoded);

            if (!result.Succeeded)
            {
                throw new AppException("ParameterException", "Er ging iets mis bij het bevestigen van je email adres. Probeer het later opnieuw.", this.GetType().Name, "ConfirmEmail", "400");
            }
            
        }

        public async Task ResendEmail(PostResendEmailModel postResendEmailModel)
        {
           
            if (string.IsNullOrWhiteSpace(postResendEmailModel.Email))
            {
                throw new AppException("ParameterException", "Email is leeg of ongeldig.", this.GetType().Name, "ConfirmEmail", "400");
            }

            User user = await _userManager.FindByEmailAsync(postResendEmailModel.Email);

            if (user == null)
            {
                throw new AppException("ParameterException", "Email is leeg of ongeldig.", this.GetType().Name, "ConfirmEmail", "400");
            }

            await SendConfirmMail(user, user.Email);
        }

        private async Task SendConfirmMail(User user, string to)
        {
            var verificantionToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);

            if (user.EmailConfirmed)
            {
                return;
            }

            //await _mailer.SendConfirmEmailMail(user.Firstname, to, verificantionToken, user.PreferedLocale);
           
        }

        public async Task ForgotPassword(PostForgotPasswordModel postForgotPasswordModel)
        {

            if (String.IsNullOrWhiteSpace(postForgotPasswordModel.Email))
            {
                throw new AppException("ParameterException", "Email is leeg of ongeldig.", this.GetType().Name, "PostForgotPassword", "400");
            }

            User user = await _userManager.FindByEmailAsync(postForgotPasswordModel.Email);

            if (user == null)
            {
                _logger.LogInformation($"Een gebruiker probeerde het wachtwoord voor {postForgotPasswordModel.Email} te herstellen.");
                return;
            }

            try
            {
                var resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);

                //await _mailer.SendPasswordResetMail(user.Firstname, postForgotPasswordModel.Email, resetToken, user.PreferedLocale);
                    
            }
            catch(Exception ex)
            {
                _logger.LogError(ex, "Een fout is opgetreden bij het verzenden van de ForgotPassword email.");
                throw new AppException("Er ging iets mis bij het verzenden van de wachtwoord herstel mail, probeer het later opnieuw.", this.GetType().Name, "ForgotPassword", "500");
            }
            
        }

        public async Task ResetPassword(PostResetPasswordModel postResetPasswordModel)
        {
            if (String.IsNullOrWhiteSpace(postResetPasswordModel.Email))
            {
                throw new AppException("ParameterException","Email is leeg of ongeldig.", this.GetType().Name, "PostForgotPassword", "400");
            }

            if (String.IsNullOrWhiteSpace(postResetPasswordModel.Token))
            {
                throw new AppException("ParameterException", "Token is leeg of ongeldig.", this.GetType().Name, "PostForgotPassword", "400");
            }

            if (postResetPasswordModel.Password != postResetPasswordModel.ConfirmPassword)
            {
                throw new AppException("ParameterException", "Wachtwoorden komen niet overeen", this.GetType().Name, "PostForgotPassword", "400");
            }

            User user = await _userManager.FindByEmailAsync(postResetPasswordModel.Email);

            if (user == null)
            {
                throw new AppException("Er ging iets mis bij het herstellen van je wachtwoord, probeer het later opnieuw.", this.GetType().Name, "PostForgotPassword", "500");
            }

            IdentityResult result = await _userManager.ResetPasswordAsync(user, postResetPasswordModel.Token, postResetPasswordModel.Password);

            if (!result.Succeeded)
            {
                throw new AppException("Er ging iets mis bij het herstellen van je wachtwoord, probeer het later opnieuw.", this.GetType().Name, "ResetPassword", "500");
            }
                
        }


        // JWT Methods
        // ===========

        public async Task<PostAuthenticateResponseModel> RegisterUser(PostRegistrationModel postRegistrationModel, string ipAdress)
        {
            if (postRegistrationModel.Password != postRegistrationModel.ConfirmPassword)
            {
                throw new AppException("IdentityException", "Wachtwoorden komen niet overeen", this.GetType().Name, "RegisterUser", "400");
            }

            var usersWithEmail = await _context.Users.Where(x => x.Email == postRegistrationModel.Email).ToListAsync();

            if (usersWithEmail.Count >= 1)
            {
                throw new AppException("IdentityException", $"Gebruiker met dit email bestaat al.", this.GetType().Name, "RegisterUser", "409");
            }

            User user = new User
            {
                UserName = postRegistrationModel.Email,
                Firstname = postRegistrationModel.Firstname,
                Lastname = postRegistrationModel.Lastname,
                Email = postRegistrationModel.Email,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };

            IdentityResult userResult = await _userManager.CreateAsync(user, postRegistrationModel.Password);

            if (!userResult.Succeeded)
            {
                throw new AppException("IdentityException", userResult.Errors.First().Description, this.GetType().Name, "RegisterUser", "500");
            }

            try
            {
                await _userManager.AddToRoleAsync(user, "Visitor");
            }
            catch (Exception e)
            {
                await _userManager.DeleteAsync(user);
                throw new AppException("IdentityException", e.Message, this.GetType().Name, "RegisterUser", "500");
            }

            await SendConfirmMail(user, user.Email);

            return await Authenticate(new PostAuthenticateRequestModel { Email = user.Email, Password = postRegistrationModel.Password }, ipAdress);
        }

        public async Task<PostAuthenticateResponseModel> Authenticate(PostAuthenticateRequestModel postAuthenticateRequestModel, string ipAddress)
        {
            User user = await _userManager.Users
                .Include(x => x.RefreshTokens)
                .FirstOrDefaultAsync(x => x.Email == postAuthenticateRequestModel.Email);

            if (user == null)
            {
                throw new AppException("UsernameException", "Ongeldige login gegevens.", this.GetType().Name, "Authenticate", "401");
            }

            // Verify password when user was found by UserName
            SignInResult signInResult = await _signInManager.CheckPasswordSignInAsync(user, postAuthenticateRequestModel.Password, lockoutOnFailure: false);

            if (!signInResult.Succeeded)
            {
                throw new AppException("PasswordException", "Ongeldige login gegevens.", this.GetType().Name, "Authenticate", "401");
            }

            // Authentication was successful so generate JWT and refresh tokens
            string jwtToken = await GenerateJwtToken(user);
            RefreshToken refreshToken = GenerateRefreshToken(ipAddress, _appSettings.RefreshTokenLifetime != 0 ? _appSettings.RefreshTokenLifetime : 7);

            // save refresh token
            user.RefreshTokens.Add(refreshToken);

            await _userManager.UpdateAsync(user);

            return new PostAuthenticateResponseModel
            {
                Id = user.Id,
                Firstname = user.Firstname,
                Lastname = user.Lastname,
                Email = user.Email,
                JwtToken = jwtToken,
                RefreshToken = refreshToken.Token,
                Roles = await _userManager.GetRolesAsync(user)
            };
        }

        public async Task<PostAuthenticateResponseModel> RefreshToken(string token, string ipAddress)
        {
            User user = await _userManager.Users
                .Include(x => x.RefreshTokens)
                .FirstOrDefaultAsync(x => x.RefreshTokens.Any(t => t.Token == token));

            if (user == null)
            {
                throw new AppException("TokenException", "Geen gebruiker gevonden met deze token.", this.GetType().Name, "RefreshToken", "401");
            }

            RefreshToken refreshToken = user.RefreshTokens.Single(x => x.Token == token);

            // Refresh token is no longer active
            if (!refreshToken.IsActive)
            {
                throw new AppException("RefreshTokenException", "Refresh token is niet langer geldig.", this.GetType().Name, "RefreshToken", "401");
            };

            // Replace old refresh token with a new one
            RefreshToken newRefreshToken = GenerateRefreshToken(ipAddress, _appSettings.RefreshTokenLifetime != 0 ? _appSettings.RefreshTokenLifetime : 7);
            refreshToken.Revoked = DateTime.UtcNow;
            refreshToken.RevokedByIp = ipAddress;
            refreshToken.ReplacedByToken = newRefreshToken.Token;

            // Generate new jwt
            string jwtToken = await GenerateJwtToken(user);

            user.RefreshTokens.Add(newRefreshToken);

            await _userManager.UpdateAsync(user);

            return new PostAuthenticateResponseModel
            {
                Id = user.Id,
                Firstname = user.Firstname,
                Lastname = user.Lastname,
                Email = user.Email,
                JwtToken = jwtToken,
                RefreshToken = newRefreshToken.Token,
                Roles = await _userManager.GetRolesAsync(user)
            };
        }

        public async Task RevokeToken(string token, string ipAddress)
        {
            User user = await _userManager.Users
                .Include(x => x.RefreshTokens)
                .FirstOrDefaultAsync(x => x.RefreshTokens.Any(t => t.Token == token));

            if (user == null)
            {
                throw new AppException("TokenException", "Geen gebruiker gevonden met deze token.", this.GetType().Name, "RefreshToken", "401");
            }

            RefreshToken refreshToken = user.RefreshTokens.Single(x => x.Token == token);

            // Refresh token is no longer active
            if (!refreshToken.IsActive)
            {
                throw new AppException("RefreshTokenException", "Refresh token is niet langer geldig.", this.GetType().Name, "RefreshToken", "401");
            };

            // Revoke token and save
            refreshToken.Revoked = DateTime.UtcNow;
            refreshToken.RevokedByIp = ipAddress;

            await _userManager.UpdateAsync(user);
        }

        // JWT helper methods
        // ==================

        private async Task<string> GenerateJwtToken(User user)
        {
            var roleNames = await _userManager.GetRolesAsync(user).ConfigureAwait(false);

            List<Claim> claims = new();
            claims.Add(new Claim(ClaimTypes.Name, user.Id.ToString()));
            claims.Add(new Claim("Firstname", user.Firstname));
            claims.Add(new Claim("Lastname", user.Lastname));
            claims.Add(new Claim("Email", user.Email));

            foreach (string roleName in roleNames)
            {
                claims.Add(new Claim(ClaimTypes.Role, roleName));
            }

            JwtSecurityTokenHandler tokenHandler = new();
            byte[] key = Encoding.ASCII.GetBytes(_appSettings.Secret);
            SecurityTokenDescriptor tokenDescriptor = new()
            {
                Issuer = "Qr Wallet API",
                Subject = new ClaimsIdentity(claims.ToArray()),
                Expires = DateTime.UtcNow.AddMinutes(_appSettings.JwtLifetime != 0 ? _appSettings.JwtLifetime : 5),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            SecurityToken token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private static RefreshToken GenerateRefreshToken(string ipAddress, int days)
        {
            using var rng = RandomNumberGenerator.Create();
            byte[] randomBytes = new byte[64];
            rng.GetBytes(randomBytes);
            return new RefreshToken
            {
                Token = Convert.ToBase64String(randomBytes),
                Expires = DateTime.UtcNow.AddDays(days), // cookie and refresh token lifetime must be the same
                Created = DateTime.UtcNow,
                CreatedByIp = ipAddress
            };
        }

    }
}
