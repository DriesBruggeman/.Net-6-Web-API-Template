using RENAME_TO_PROJECT_NAME.Data.Entities;
using RENAME_TO_PROJECT_NAME.Models.Common;
using RENAME_TO_PROJECT_NAME.Models.Users;

namespace RENAME_TO_PROJECT_NAME.Repositories.Helpers
{
    public static class MakeModel
    {
        //Originele code van Yves Blancqueart - Mediatheek januari 2021
        public static GetListModel<T> MakeGetListModel<T>(int number, int page, List<T> models)
        {
            int total = models.Count();
            int pages = number == -1 ? 1 : Convert.ToInt32(Math.Ceiling(Convert.ToDouble(total) / Convert.ToDouble(number)));

            //Page should not be negative
            page = page <= 0 ? 1 : page;
            //Page should not be higher than total amount of pages
            page = page > pages ? pages : page;

            int previous = page - 1 == 0 ? 1 : page - 1;
            int next = page + 1 > pages ? pages : page + 1;
            int startIndex = (page - 1) * number;
            int count = number > total - startIndex ? total - startIndex : number;

            return new GetListModel<T>
            {
                Models = number == -1 ? models.GetRange(0, total) : models.GetRange(startIndex, count),
                Total = total,
                Number = number == -1 ? total : number,
                Pages = pages,
                Previous = previous,
                Page = page,
                Next = next
            };
        }

        public static GetUserModel MakeGetUserModel(User user)
        {
            return new GetUserModel
            {
                Id = user.Id,
                Lastname = user.Lastname,
                Firstname = user.Firstname,
                Email = user.Email,
                Roles = user.UserRoles.Select(x => x.Role.Name).ToList()
            };
        }
        
    }

}
