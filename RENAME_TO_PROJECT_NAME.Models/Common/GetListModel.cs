namespace RENAME_TO_PROJECT_NAME.Models.Common
{
    public class GetListModel<T>
    {
        public ICollection<T> Models { get; set; }
        public int Total { get; set; }
        public int Number { get; set; }
        public int Pages { get; set; }
        public int Previous { get; set; }
        public int Page { get; set; }
        public int Next { get; set; }
    }
}
