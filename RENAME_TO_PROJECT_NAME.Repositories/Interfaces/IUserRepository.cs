using RENAME_TO_PROJECT_NAME.Models.Common;
using RENAME_TO_PROJECT_NAME.Models.RefreshTokenModel;
using RENAME_TO_PROJECT_NAME.Models.Users;

namespace RENAME_TO_PROJECT_NAME.Repositories
{
    public interface IUserRepository
    {
        Task<GetListModel<GetUserModel>> GetUsers(int number, int page);
        Task<GetUserModel> GetUser(Guid id, bool camefrompost);
        Task<GetUserModel> PostUser(PostUserModel postUserModel);
        Task PutUser(Guid id, PutUserModel putUserModel);
        Task PatchUser(Guid id, PatchUserModel patchUserModel);
        Task DeleteUser(Guid id);

        // Confirm Email

        Task ConfirmEmail(PostConfirmEmailModel postConfirmEmailModel);
        Task ResendEmail(PostResendEmailModel postResendEmailModel);

        // Reset Password
        Task ForgotPassword(PostForgotPasswordModel postForgotPasswordModel);
        Task ResetPassword(PostResetPasswordModel postResetPasswordModel);

        Task<List<GetRefreshTokenModel>> GetUserRefreshTokens(Guid id);

        // JWT methods

        Task<PostAuthenticateResponseModel> Authenticate(PostAuthenticateRequestModel postAuthenticateRequestModel, string ipAddress);
        Task<PostAuthenticateResponseModel> RegisterUser(PostRegistrationModel postRegistrationModel, string ipAddress);
        Task<PostAuthenticateResponseModel> RefreshToken(string token, string ipAddress);
        Task RevokeToken(string token, string ipAddress);
    }
}
