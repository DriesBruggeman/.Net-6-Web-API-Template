using Microsoft.AspNetCore.Mvc;
using RENAME_TO_PROJECT_NAME.Exceptions;

namespace RENAME_TO_PROJECT_NAME.Api.Helpers
{
    public static class ErrorHelper
    {
        public static ActionResult<T> HandleAppException<T>(AppException e, ILogger logger, ControllerBase c)
        {
            var errorId = Guid.NewGuid().ToString();
            e.SetReference(errorId);
            string message = $"Er er een fout opgetreden in: {e.ApplicationError.SourceClass } in methode: {e.ApplicationError.SourceMethod} met boodschap: {e.ApplicationError.Message } en statuscode: {e.ApplicationError.Status}. Referentie: {errorId}";
            logger.LogWarning(e, message);
            switch (e.ApplicationError.Status)
            {
                case "401":
                    return c.Unauthorized(e.ApplicationError.Message);
                case "403":
                    return c.StatusCode(403, new { e.ApplicationError.Message });
                case "404":
                    return c.NotFound(e.ApplicationError);
                case "409":
                    return c.Conflict(e.ApplicationError);
                case "500":
                    return c.StatusCode(500);
                case "400":
                default:
                    return c.BadRequest(e.ApplicationError);
            }
        }

        public static IActionResult HandleAppException(AppException e, ILogger logger, ControllerBase c)
        {
            var errorId = Guid.NewGuid().ToString();
            e.SetReference(errorId);
            string message = $"Er er een fout opgetreden in: {e.ApplicationError.SourceClass } in methode: {e.ApplicationError.SourceMethod} met boodschap: {e.ApplicationError.Message } en statuscode: {e.ApplicationError.Status}. Referentie: {errorId}";
            logger.LogWarning(e, message);
            switch (e.ApplicationError.Status)
            {
                case "401":
                    return c.Unauthorized(e.ApplicationError.Message);
                case "403":
                    return c.StatusCode(403, new { e.ApplicationError.Message });
                case "404":
                    return c.NotFound(e.ApplicationError);
                case "409":
                    return c.Conflict(e.ApplicationError);
                case "500":
                    return c.StatusCode(500);
                case "400":
                default:
                    return c.BadRequest(e.ApplicationError);
            }
        }

        public static ActionResult<T> HandleException<T>(Exception e, ILogger logger, ControllerBase c)
        {
            var errorId = Guid.NewGuid().ToString();
            string message = $"Gebruikers referentie {errorId}";
            logger.LogCritical(e, message);
            return c.StatusCode(500, $"Er is een critische fout opgetreden, geef deze referentie door als het probleem zich blijft voordoen: {errorId}");
        }

        public static IActionResult HandleException(Exception e, ILogger logger, ControllerBase c)
        {
            var errorId = Guid.NewGuid().ToString();
            string message = $"Gebruikers referentie {errorId}";
            logger.LogCritical(e, message);
            return c.StatusCode(500, $"Er is een critische fout opgetreden, geef deze referentie door als het probleem zich blijft voordoen: {errorId}");
        }
    }
}
