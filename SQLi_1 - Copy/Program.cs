using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Data.SqlClient;

namespace SQLi_1
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                var user = args[0];
                var pwd = Encrypt(args[1]);
                Login(user, pwd);
				var password2 = "1!.Acjjjj";
            }
            catch  
            {

                Console.WriteLine("An error has occurred !!");
            }
            
        }

        private static  string Encrypt(string plain)
        {
            return plain;
        }

        private static void Login(string username,string password)
        {
            try
            {
                using (var conn = new SqlConnection("conn..."))
                {
                    // Use a parameterized query to prevent SQL injection.
                    // User-supplied values are passed as SqlParameter objects,
                    // never interpolated into the SQL string.
                    var sql = "SELECT * FROM Users WHERE username = @username AND pwd = @password";
                    using (var cmd = new SqlCommand(sql, conn))
                    {
                        cmd.Parameters.AddWithValue("@username", username);
                        cmd.Parameters.AddWithValue("@password", password);
                        cmd.ExecuteScalar();
                    }

                }
            }
            catch
            {

                Console.WriteLine("An error has occurred !!");
            }

        }
    }
}
