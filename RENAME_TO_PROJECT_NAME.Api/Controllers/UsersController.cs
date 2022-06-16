using RENAME_TO_PROJECT_NAME.Repositories;
using RENAME_TO_PROJECT_NAME.Models.Users;
using RENAME_TO_PROJECT_NAME.Exceptions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Net;
using RENAME_TO_PROJECT_NAME.Models.RefreshTokenModel;
using RENAME_TO_PROJECT_NAME.Api.Helpers;
using RENAME_TO_PROJECT_NAME.Models.Common;

namespace RENAME_TO_PROJECT_NAME.Api.Controllers
{
    [Authorize(AuthenticationSchemes = "Bearer")]
    [ApiController]
    [Route("api/[controller]")]
    [Produces("application/json")]
    [Consumes("application/json")]
    public class UsersController : ControllerBase
    {
        private readonly IUserRepository _userRepository;
        private readonly ILogger<UsersController> _logger;

        public UsersController(IUserRepository userRepository, ILogger<UsersController> logger)
        {
            _userRepository = userRepository;
            _logger = logger;
        }

        /// <summary>
        /// Get a list of all users.
        /// </summary>
        /// <remarks>
        /// Sample request:
        ///
        ///     GET /api/users
        ///
        /// </remarks>
        /// <returns>a GetListModel with users</returns>
        /// <response code="200">Returns the list of users</response>
        /// <response code="404">No users were found</response> 
        /// <response code="401">Unauthorized - Invalid JWT token</response> 
        /// <response code="403">Forbidden - Required role assignment is missing</response> 
        [HttpGet]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [Authorize(Roles = "QrWalletAdmin, EventAdmin")]
        public async Task<ActionResult<GetListModel<GetUserModel>>> GetUsers(int number = -1, int page = 1)
        {
            try
            {
                GetListModel<GetUserModel> users = await _userRepository.GetUsers(number, page);

                return users;
            }
            catch (AppException e)
            {
                return ErrorHelper.HandleAppException<GetListModel<GetUserModel>>(e, _logger, this);
            }
            catch (Exception e)
            {
                return ErrorHelper.HandleException<GetListModel<GetUserModel>>(e, _logger, this);
            }
        }

        /// <summary>
        /// Get details of a user.
        /// </summary>
        /// <remarks>
        /// Sample request:
        ///
        ///     GET /api/users/{id}
        ///
        /// </remarks>
        /// <param name="id">User id</param>     
        /// <returns>A GetUserModel</returns>
        /// <response code="200">Returns the user</response>
        /// <response code="404">The user could not be found</response> 
        /// <response code="400">The id is not a valid Guid</response> 
        /// <response code="401">Unauthorized - Invalid JWT token</response> 
        /// <response code="403">Forbidden - requested user id does not match with authenticated user id</response> 
        [HttpGet("{id}")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [Authorize(Roles = "QrWalletAdmin, EventAdmin, EventStaff, Visitor")]
        public async Task<ActionResult<GetUserModel>> GetUser(string id)
        {
            try
            {
                if (!Guid.TryParse(id, out Guid userId))
                {
                    throw new AppException("GuidException", "Ongeldig Guid formaat", this.GetType().Name, "GetUser", "400");
                }

                GetUserModel user = await _userRepository.GetUser(userId, false);

                return user;
            }
            catch (AppException e)
            {
                return ErrorHelper.HandleAppException<GetUserModel>(e, _logger, this);
            }
            catch (Exception e)
            {
                return ErrorHelper.HandleException<GetUserModel>(e, _logger, this);
            }
        }

        /// <summary>
        /// Creates a user.
        /// </summary>
        /// <remarks>
        /// Sample request:
        ///
        ///     POST /api/users
        ///     {
        ///        "Firstname": "Dries",
        ///        "Lastname": "Bruggeman",
        ///        "Email": "dries@bruggeman.com",
        ///        "Password": "_Azerty123",
        ///        "ConfirmPassword": "_Azerty123",
        ///        "Roles": [
        ///            "Visitor"
        ///        ]
        ///     }
        ///
        /// </remarks>
        /// <param name="postUserModel"></param>
        /// <returns>A newly created user</returns>
        /// <response code="201">Returns the newly created user</response>
        /// <response code="400">If something went wrong while saving into the database</response>   
        [HttpPost]
        [ProducesResponseType(StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [Authorize(Roles = "QrWalletAdmin, EventAdmin")]
        public async Task<ActionResult<GetUserModel>> PostUser(PostUserModel postUserModel)
        {
            try
            {
                GetUserModel user = await _userRepository.PostUser(postUserModel);

                return CreatedAtAction(nameof(GetUser), new { id = user.Id }, user);
            }
            catch (AppException e)
            {
                return ErrorHelper.HandleAppException<GetUserModel>(e, _logger, this);
            }
            catch (Exception e)
            {
                return ErrorHelper.HandleException<GetUserModel>(e, _logger, this);
            }
        }

        /// <summary>
        /// Updates a user.
        /// </summary>
        /// <remarks>
        /// Sample request:
        ///
        ///     PUT /api/users/{id}
        ///     {
        ///        "Firstname": "Dries",
        ///        "Lastname": "Bruggeman",
        ///        "Email": "dries@bruggeman.com",
        ///        "Roles": [
        ///            "Klant"
        ///        ]
        ///     }
        ///
        /// </remarks>
        /// <param name="id"></param>     
        /// <param name="putUserModel"></param>    
        /// <response code="204">Returns no content</response>
        /// <response code="404">The user could not be found</response> 
        /// <response code="400">The id is not a valid Guid or something went wrong while saving into the database</response> 
        /// <response code="401">Unauthorized - Invalid JWT token</response> 
        /// <response code="403">Forbidden - requested user id does not match with authenticated user id</response> 
        [HttpPut("{id}")]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [Authorize(Roles = "QrWalletAdmin, Visitor")]
        public async Task<IActionResult> PutUser(string id, PutUserModel putUserModel)
        {
            try
            {
                if (!Guid.TryParse(id, out Guid userId))
                {
                    throw new AppException("GuidException", "Ongeldig Guid formaat", this.GetType().Name, "PutUser", "400");
                }

                await _userRepository.PutUser(userId, putUserModel);

                return NoContent();
            }
            catch (AppException e)
            {
                return ErrorHelper.HandleAppException(e, _logger, this);
            }
            catch (Exception e)
            {
                return ErrorHelper.HandleException(e, _logger, this);
            }
        }

        /// <summary>
        /// Updates a user password.
        /// </summary>
        /// <remarks>
        /// Sample request:
        ///
        ///     PATCH /api/users/{id}
        ///     {
        ///        "CurrentPassword": "_Azerty123",
        ///        "NewPassword": "Azerty123!",
        ///        "ConfirmNewPassword": "Azerty123!"
        ///     }
        ///
        /// </remarks>
        /// <param name="id"></param>     
        /// <param name="patchUserModel"></param>    
        /// <response code="204">Returns no content</response>
        /// <response code="404">The user could not be found</response> 
        /// <response code="400">The id is not a valid Guid or the current password does not match or the new password is not conform the password rules</response> 
        /// <response code="401">Unauthorized - Invalid JWT token</response> 
        /// <response code="403">Forbidden - requested user id does not match with authenticated user id</response> 
        [HttpPatch("{id}")]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [Authorize(Roles = "QrWalletAdmin, EventAdmin, EventStaff, Visitor")]
        public async Task<IActionResult> PatchUser(string id, PatchUserModel patchUserModel)
        {
            try
            {
                if (!Guid.TryParse(id, out Guid userId))
                {
                    throw new AppException("GuidException", "Ongeldig Guid formaat", this.GetType().Name, "PatchUser", "400");
                }

                await _userRepository.PatchUser(userId, patchUserModel);

                return NoContent();
            }
            catch (AppException e)
            {
                return ErrorHelper.HandleAppException(e, _logger, this);
            }
            catch (Exception e)
            {
                return ErrorHelper.HandleException(e, _logger, this);
            }
        }

        /// <summary>
        /// Deletes a user.
        /// </summary>
        /// <remarks>
        /// Sample request:
        ///
        ///     DELETE /api/users/{id}
        ///
        /// </remarks>
        /// <param name="id"></param>     
        /// <response code="204">Returns no content</response>
        /// <response code="404">The user could not be found</response> 
        /// <response code="400">The id is not a valid Guid</response> 
        /// <response code="401">Unauthorized - Invalid JWT token</response> 
        /// <response code="403">Forbidden - Required role assignment is missing</response> 
        [HttpDelete("{id}")]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [Authorize(Roles = "QrWalletAdmin, Visitor")]
        public async Task<IActionResult> DeleteUser(string id)
        {
            try
            {
                if (!Guid.TryParse(id, out Guid userId))
                {
                    throw new AppException("GuidException", "Ongeldig Guid formaat", this.GetType().Name, "DeleteUser", "400");
                }

                await _userRepository.DeleteUser(userId);

                return NoContent();
            }
            catch (AppException e)
            {
                return ErrorHelper.HandleAppException(e, _logger, this);
            }
            catch (Exception e)
            {
                return ErrorHelper.HandleException(e, _logger, this);
            }
        }

        // Confirm Email
        // ==================

        /// <summary>
        /// Confirm a users email address.
        /// </summary>
        /// <remarks>
        /// Sample request:
        ///
        ///     POST /api/users/confirm-email
        ///     {
        ///         "email": "dries@bruggeman.org"
        ///     }
        ///
        /// </remarks>  
        /// <response code="200">Returns OK</response>
        /// <response code="404">The user could not be found</response> 
        /// <response code="400">Email is empty or invalid</response> 
        [HttpGet("confirm-email/{email}/{token}")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [AllowAnonymous]
        public async Task<ContentResult> ConfirmEmail(string email, string token)
        {
            Console.WriteLine("Email: " + email);
            Console.WriteLine("Token: " + token);

            try
            {
                await _userRepository.ConfirmEmail(new PostConfirmEmailModel
                {
                    Email = email,
                    Token = token
                });

                string contents = await System.IO.File.ReadAllTextAsync("ConfirmationPages/confirmemail.html");

                return new ContentResult
                {
                    StatusCode = StatusCodes.Status200OK,
                    ContentType = "text/html",
                    Content = contents
                };
            }
            catch (Exception e)
            {

                Console.WriteLine(e.Message);
                string contents = await System.IO.File.ReadAllTextAsync("ConfirmationPages/confirmemailfailed.html");

                return new ContentResult
                {
                    StatusCode = StatusCodes.Status400BadRequest,
                    ContentType = "text/html",
                    Content = contents
                };
            }
        }

        /// <summary>
        /// Resends a confirmation email to the users email address
        /// </summary>
        /// Sample request:
        ///
        ///     POST /api/users/forgot-password
        ///     {
        ///        "Email": "dries@bruggeman.com",
        ///     }       
        /// 
        /// <param name="postResendEmailModel">Contains user email address</param>
        /// <response code="200">Returns OK</response>
        /// <response code="404">The user could not be found</response> 
        /// <response code="400">Email is empty or invalid</response> 
        /// <response code="401">The user is nog logged in</response>
        [HttpPost("resend-confirmation")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [Authorize]
        public async Task<IActionResult> PostResendConfirmEmail(PostResendEmailModel postResendEmailModel)
        {
            try
            {
                await _userRepository.ResendEmail(postResendEmailModel);

                return Ok();
            }
            catch (AppException e)
            {
                return ErrorHelper.HandleAppException(e, _logger, this);
            }
            catch (Exception e)
            {
                return ErrorHelper.HandleException(e, _logger, this);
            }
        }


        // Password reset
        // ==================

        /// <summary>
        /// Generates and sends an email with a password reset token
        /// </summary>
        /// Sample request:
        ///
        ///     POST /api/users/forgot-password
        ///     {
        ///        "Email": "dries@bruggeman.com",
        ///     }       
        ///  
        /// <param name="postForgotPasswordModel">Contains users email address</param>
        /// <response code="200">Returns OK</response>
        /// <response code="400">Email is empty or invalid</response> 
        [HttpPost("forgot-password")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [AllowAnonymous]
        public async Task<IActionResult> PostForgotPassword(PostForgotPasswordModel postForgotPasswordModel)
        {
            try
            {
                await _userRepository.ForgotPassword(postForgotPasswordModel);

                return Ok();
            }
            catch (AppException e)
            {
                return ErrorHelper.HandleAppException(e, _logger, this);
            }
            catch (Exception e)
            {
                return ErrorHelper.HandleException(e, _logger, this);
            }
        }

        /// <summary>
        /// Resets the users password to a new password using password reset token
        /// </summary>
        /// Sample request:
        ///
        ///     POST /api/users/reset-password
        ///     {
        ///        "Email": "dries@bruggeman.com",
        ///        "Password": "_Azerty123",
        ///        "ConfrimPassword": "_Azerty123",
        ///        "Token": TOKEN
        ///     }       
        ///     
        /// <param name="postResetPasswordModel">Contains users email address, new password and reset token</param>
        /// <response code="200">Returns OK</response>
        /// <response code="400">Email is empty or invalid</response> 
        [HttpPost("reset-password")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [AllowAnonymous]
        public async Task<IActionResult> PostResetPassword(PostResetPasswordModel postResetPasswordModel)
        {
            try
            {
                await _userRepository.ResetPassword(postResetPasswordModel);

                return Ok();
            }
            catch (AppException e)
            {
                return ErrorHelper.HandleAppException(e, _logger, this);
            }
            catch (Exception e)
            {
                return ErrorHelper.HandleException(e, _logger, this);
            }
        }

        /// <summary>
        /// Creates a user and authenticates afterwards.
        /// </summary>
        /// <remarks>
        /// Sample request:
        ///
        ///     POST /api/users
        ///     {
        ///        "Firstname": "Dries",
        ///        "Lastname": "Bruggeman",
        ///        "Email": "dries@bruggeman.com",
        ///        "Password": "_Azerty123",
        ///        "ConfirmPassword": "_Azerty123",
        ///        "InviteCode": ""
        ///     }
        ///
        /// </remarks>
        /// <param name="postRegistrationModel"></param>
        /// <returns>A newly registered user with bearear token</returns>
        /// <response code="201">Returns the newly created user</response>
        /// <response code="400">If something went wrong while saving into the database</response>   
        [HttpPost("register")]
        [ProducesResponseType(StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [AllowAnonymous]
        public async Task<ActionResult<PostAuthenticateResponseModel>> RegisterUser(PostRegistrationModel postRegistrationModel)
        {
            try
            {
                var user = await _userRepository.RegisterUser(postRegistrationModel, IpAddress());

                SetTokenCookie(user.RefreshToken);

                return CreatedAtAction(nameof(Authenticate), user);
            }
            catch (AppException e)
            {
                return ErrorHelper.HandleAppException<PostAuthenticateResponseModel>(e, _logger, this);
            }
            catch (Exception e)
            {
                return ErrorHelper.HandleException<PostAuthenticateResponseModel>(e, _logger, this);
            }
        }

        // JWT Action Methods
        // ==================

        /// <summary>
        /// Authenticates a user.
        /// </summary>
        /// <remarks>
        /// Sample request:
        ///
        ///     POST /api/users/authenticate
        ///     {
        ///        "Email": "dries@bruggeman.com",
        ///        "Password": "_Azerty123"
        ///     }
        ///
        /// </remarks>
        /// <param name="postAuthenticateRequestModel"></param>
        /// <returns>Details of authenticated user, an JWT token and a refresh token</returns>
        /// <response code="200">Returns the authenticated user with tokens</response>
        /// <response code="401">Incorrect credentials</response>   
        [AllowAnonymous]
        [HttpPost("authenticate")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<ActionResult<PostAuthenticateResponseModel>> Authenticate(PostAuthenticateRequestModel postAuthenticateRequestModel)
        {
            try
            {
                PostAuthenticateResponseModel postAuthenticateResponseModel = await _userRepository.Authenticate(postAuthenticateRequestModel, IpAddress());

                SetTokenCookie(postAuthenticateResponseModel.RefreshToken);

                return postAuthenticateResponseModel;
            }
            catch (AppException e)
            {
                return ErrorHelper.HandleAppException<PostAuthenticateResponseModel>(e, _logger, this);
            }
            catch (Exception e)
            {
                return ErrorHelper.HandleException<PostAuthenticateResponseModel>(e, _logger, this);
            }
        }

        /// <summary>
        /// Removes the HTTP only refresh cookie and invalidates the refresh token
        /// </summary>
        /// <remarks>
        /// Sample request:
        ///
        ///     POST /api/users/logout
        ///
        /// </remarks>
        /// <response code="204">The refresh token cookie has been overwritten and token revoked</response>
        /// <response code="401">Incorrect credentials</response>   
        [AllowAnonymous]
        [HttpPost("logout")]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> Logout()
        {
            try
            {
                if (!string.IsNullOrEmpty(Request.Cookies["QrWallet.RefreshToken"]))
                {
                    await _userRepository.RevokeToken(Request.Cookies["QrWallet.RefreshToken"], IpAddress());
                }

                RemoveTokenCookie();

                return NoContent();
            }
            catch (AppException e)
            {
                return ErrorHelper.HandleAppException(e, _logger, this);
            }
            catch (Exception e)
            {
                return ErrorHelper.HandleException(e, _logger, this);
            }
        }

        /// <summary>
        /// Renew tokens.
        /// </summary>
        /// <remarks>
        /// Sample request:
        ///
        ///     POST /api/users/refresh-token
        ///
        /// </remarks>
        /// <returns>Details of authenticated user, a new JWT token and a new refresh token</returns>
        /// <response code="200">Returns the authenticated user with new tokens</response>
        /// <response code="401">Invalid refresh token</response>   
        [AllowAnonymous]
        [HttpPost("refresh-token")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<ActionResult<PostAuthenticateResponseModel>> RefreshToken()
        {
            try
            {
                string refreshToken = Request.Cookies["QrWallet.RefreshToken"];

                PostAuthenticateResponseModel postAuthenticateResponseModel = await _userRepository.RefreshToken(refreshToken, IpAddress());

                SetTokenCookie(postAuthenticateResponseModel.RefreshToken);

                return postAuthenticateResponseModel;
            }
            catch (AppException e)
            {
                return ErrorHelper.HandleAppException<PostAuthenticateResponseModel>(e, _logger, this);
            }
            catch (Exception e)
            {
                return ErrorHelper.HandleException<PostAuthenticateResponseModel>(e, _logger, this);
            }
        }

        /// <summary>
        /// Revoke token.
        /// </summary>
        /// <remarks>
        /// Sample request:
        ///
        ///     POST /api/users/revoke-token
        ///     {
        ///        "Token": "Some token"
        ///     }
        ///
        /// </remarks>
        /// <response code="200">Disables a refresh token</response>
        /// <response code="400">No token present in body or cookie</response>   
        /// <response code="401">No user found with this token or refresh token is no longer active</response>   
        /// <response code="401">Unauthorized - Invalid JWT token</response> 
        /// <response code="403">Forbidden - Required role assignment is missing</response> 
        [HttpPost("revoke-token")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [Authorize(Roles = "QrWalletAdmin")]
        public async Task<IActionResult> RevokeToken(PostRevokeTokenRequestModel postRevokeTokenRequestModel)
        {
            try
            {
                // Accept token from request body or cookie
                string token = postRevokeTokenRequestModel.Token ?? Request.Cookies["QrWallet.RefreshToken"];

                if (string.IsNullOrEmpty(token))
                {
                    throw new AppException("RefreshTokenException", "Refresh token is required.", this.GetType().Name, "RevokeToken", "400");
                }

                await _userRepository.RevokeToken(token, IpAddress());

                return Ok();
            }
            catch (AppException e)
            {
                return ErrorHelper.HandleAppException(e, _logger, this);
            }
            catch (Exception e)
            {
                return ErrorHelper.HandleException(e, _logger, this);
            }
        }

        /// <summary>
        /// Get a list of all refresh tokens of a user.
        /// </summary>
        /// <remarks>
        /// Sample request:
        ///
        ///     GET /api/users/{id}/refresh-tokens
        ///
        /// </remarks>
        /// <returns>List of GetRefreshTokenModel</returns>
        /// <response code="200">Returns the list of refresh tokens</response>
        /// <response code="404">No refresh tokens were found</response> 
        /// <response code="400">The id is not a valid Guid</response> 
        /// <response code="401">Unauthorized - Invalid JWT token</response> 
        /// <response code="403">Forbidden - Required role assignment is missing</response> 
        [HttpGet("{id}/refresh-tokens")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [Authorize(Roles = "QrWalletAdmin")]
        public async Task<ActionResult<List<GetRefreshTokenModel>>> GetUserRefreshTokens(string id)
        {
            try
            {
                if (!Guid.TryParse(id, out Guid userId))
                {
                    throw new AppException("GuidException", "Ongeldig Guid formaat", this.GetType().Name, "GetUserRefreshTokens", "400");
                }

                List<GetRefreshTokenModel> refreshTokens = await _userRepository.GetUserRefreshTokens(userId);

                return refreshTokens;
            }
            catch (AppException e)
            {
                return ErrorHelper.HandleAppException<List<GetRefreshTokenModel>>(e, _logger, this);
            }
            catch (Exception e)
            {
                return ErrorHelper.HandleException<List<GetRefreshTokenModel>>(e, _logger, this);
            }
        }

        // JWT helper methods
        // ==================

        private void SetTokenCookie(string token)
        {
            CookieOptions cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.UtcNow.AddDays(7), // cookie and refresh token lifetime must be the same
                IsEssential = true,
                SameSite = SameSiteMode.None,
                Secure = true
            };

            Response.Cookies.Append("QrWallet.RefreshToken", token, cookieOptions);
        }

        private void RemoveTokenCookie()
        {
            CookieOptions cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.UtcNow.AddDays(7), // cookie and refresh token lifetime must be the same
                IsEssential = true,
                SameSite = SameSiteMode.None,
                Secure = true
            };

            Response.Cookies.Delete("QrWallet.RefreshToken", cookieOptions);
        }

        private string IpAddress()
        {
            if (Request.Headers.ContainsKey("X-Forwarded-For"))
            {
                return Request.Headers["X-Forwarded-For"];
            }
            else
            {
                return HttpContext.Connection.RemoteIpAddress.MapToIPv4().ToString();
            }
        }

    }
}