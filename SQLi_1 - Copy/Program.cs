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
                    // User-supplied values are bound as SqlParameter objects and
                    // never interpolated into the query string.
                    var sql = "SELECT * FROM Users WHERE username = @username AND pwd = @pwd";
                    using (var cmd = new SqlCommand(sql, conn))
                    {
                        cmd.Parameters.Add("@username", System.Data.SqlDbType.NVarChar, 256).Value = username;
                        cmd.Parameters.Add("@pwd", System.Data.SqlDbType.NVarChar, 256).Value = password;
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
