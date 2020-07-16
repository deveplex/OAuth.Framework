
namespace Microsoft.Identity
{
    public interface IPasswordHasher
    {
        string HashPassword(string password);
    }
}
