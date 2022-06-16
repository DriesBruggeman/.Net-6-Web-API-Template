using RENAME_TO_PROJECT_NAME.Exceptions;
using Microsoft.AspNetCore.Mvc;
using RENAME_TO_PROJECT_NAME.Repositories;
using RENAME_TO_PROJECT_NAME.Models.Roles;
using Microsoft.AspNetCore.Authorization;
using RENAME_TO_PROJECT_NAME.Models.Common;
using RENAME_TO_PROJECT_NAME.Api.Helpers;

namespace RENAME_TO_PROJECT_NAME.Api.Controllers
{
    [Authorize(AuthenticationSchemes = "Bearer")]
    [ApiController]
    [Route("api/[controller]")]
    [Produces("application/json")]
    [Consumes("application/json")]
    [Authorize(Roles = "QrWalletAdmin, EventAdmin")]
    public class RolesController : ControllerBase
    {
        private readonly IRoleRepository _roleRepository;
        private readonly ILogger<RolesController> _logger;

        public RolesController(IRoleRepository repo, ILogger<RolesController> logger)
        {
            _roleRepository = repo;
            _logger = logger;
        }

        /// <summary>
        /// Get all roles
        /// </summary>
        /// <remarks>
        /// Sample request:
        ///
        ///     GET /api/roles/
        ///
        /// </remarks>
        /// <param name="number">Number of roles per page</param>    
        /// <param name="page">Number of pages</param>    
        /// <returns>A GetListModel with roles</returns>
        /// <response code="200">Returns the pagination model with Roles</response>
        /// <response code="400">Invalid request</response>
        /// <response code="404">No profiles could not be found</response> 
        /// <response code="401">Unauthorized - Invalid or misssing JWT token</response> 
        /// <response code="403">Forbidden - the authenticated user is not an administrator</response> 
        [HttpGet()]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        public async Task<ActionResult<GetListModel<GetRoleModel>>> GetRoles(int number = -1, int page = 0)
        {
            try
            {
                GetListModel<GetRoleModel> Roles = await _roleRepository.GetRoles(number, page);

                return Roles;
            }
            catch (AppException e)
            {
                return ErrorHelper.HandleAppException<GetListModel<GetRoleModel>>(e, _logger, this);
            }
            catch (Exception e)
            {
                return ErrorHelper.HandleException<GetListModel<GetRoleModel>>(e, _logger, this);
            }
        }

        /// <summary>
        /// Get a role by its id
        /// </summary>
        /// <remarks>
        /// Sample request:
        ///
        ///     GET /api/roles/{id}
        ///
        /// </remarks>
        /// <param name="id">Profile id</param>    
        /// <returns>A GetRoleModel</returns>
        /// <response code="200">Returns a Role</response>
        /// <response code="400">Invalid request</response>
        /// <response code="404">No profiles could not be found</response> 
        /// <response code="401">Unauthorized - Invalid or misssing JWT token</response> 
        /// <response code="403">Forbidden - the authenticated user is not an administrator</response> 
        [HttpGet("{id}")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        public async Task<ActionResult<GetRoleModel>> GetRole(string id)
        {
            try
            {
                if (!Guid.TryParse(id, out Guid RoleId))
                {
                    throw new AppException("GuidException", "Ongeldig Guid formaat", this.GetType().Name, "GetRole", "400");
                }

                GetRoleModel Role = await _roleRepository.GetRole(RoleId);

                return Role;
            }
            catch (AppException e)
            {
                return ErrorHelper.HandleAppException<GetRoleModel>(e, _logger, this);
            }
            catch (Exception e)
            {
                return ErrorHelper.HandleException<GetRoleModel>(e, _logger, this);
            }
        }
    }
}
