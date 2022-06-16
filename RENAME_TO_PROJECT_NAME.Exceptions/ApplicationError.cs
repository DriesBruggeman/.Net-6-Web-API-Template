namespace RENAME_TO_PROJECT_NAME.Exceptions
{
    public class ApplicationError
    {
        public string Type { get; set; }
        public string Message { get; set; }
        public string SourceClass { get; set; }
        public string SourceMethod { get; set; }
        public string Status { get; set; }
        public string Reference { get; set; }
    }
}
