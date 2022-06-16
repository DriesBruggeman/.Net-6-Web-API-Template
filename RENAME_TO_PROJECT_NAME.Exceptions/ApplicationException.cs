using System.Text.Json.Serialization;
using RENAME_TO_PROJECT_NAME.Exceptions;

namespace RENAME_TO_PROJECT_NAME.Exceptions
{
    [JsonConverter(typeof(AppExceptionConverter))]
    public class AppException : Exception
    {
        public ApplicationError ApplicationError { get; }

        public AppException(string message, string sourceClass, string sourceMethod, string status) : base(message)
        {
            ApplicationError = new ApplicationError
            {
                Type = this.GetType().Name,
                Message = message,
                SourceClass = sourceClass,
                SourceMethod = sourceMethod,
                Status = status
            };
        }

        public AppException(string type, string message, string sourceClass, string sourceMethod, string status) : base(message)
        {
            ApplicationError = new ApplicationError
            {
                Type = type,
                Message = message,
                SourceClass = sourceClass,
                SourceMethod = sourceMethod,
                Status = status
            };
        }

        public void SetReference(string reference)
        {
            ApplicationError.Reference = reference;
        }
    }
}
