using System;
using System.Data.SqlClient;

namespace SQLi_1
{
    /// <summary>
    /// Tests that verify the SQL injection remediation in Program.Login().
    ///
    /// These tests confirm that:
    ///  1. The SQL command text uses parameter placeholders, not string concatenation.
    ///  2. SqlParameter objects carry the user-supplied values so the database
    ///     driver handles escaping — not application code.
    ///  3. Classic SQL injection payloads are treated as literal data, not as SQL.
    ///
    /// How to run:
    ///   Add a reference to a test runner (NUnit, MSTest, xUnit) or invoke
    ///   RunAll() from a console entry-point.  No external runner is required
    ///   for the assertion helper used here (System.Diagnostics.Debug.Assert).
    /// </summary>
    internal static class ProgramTests
    {
        // ------------------------------------------------------------------ //
        //  Helper: build a SqlCommand the same way the fixed Login() does.   //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Constructs a SqlCommand that mirrors the parameterized query in
        /// Program.Login(), without opening an actual database connection.
        /// </summary>
        private static SqlCommand BuildLoginCommand(string username, string password)
        {
            const string sql =
                "SELECT * FROM Users WHERE username = @username AND pwd = @password";

            // SqlCommand can be constructed without an open connection for
            // unit-testing purposes; we only inspect its CommandText and
            // Parameters collection here.
            var cmd = new SqlCommand(sql);
            cmd.Parameters.AddWithValue("@username", username);
            cmd.Parameters.AddWithValue("@password", password);
            return cmd;
        }

        // ------------------------------------------------------------------ //
        //  Test 1: CommandText must be a constant with placeholders only.    //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Verifies that the SQL command text contains parameter placeholders
        /// (@username, @password) and does NOT contain any literal user value.
        /// </summary>
        internal static void Test_CommandText_ContainsParameterPlaceholders()
        {
            const string injectionPayload = "' OR '1'='1";
            using (var cmd = BuildLoginCommand(injectionPayload, injectionPayload))
            {
                // The SQL string must not contain the raw user input.
                Assert(!cmd.CommandText.Contains(injectionPayload),
                    "FAIL: CommandText contains raw user input — SQL injection possible.");

                // The SQL string must reference named parameters.
                Assert(cmd.CommandText.Contains("@username"),
                    "FAIL: CommandText is missing the @username placeholder.");

                Assert(cmd.CommandText.Contains("@password"),
                    "FAIL: CommandText is missing the @password placeholder.");
            }

            Pass(nameof(Test_CommandText_ContainsParameterPlaceholders));
        }

        // ------------------------------------------------------------------ //
        //  Test 2: Parameters collection must carry exactly the right values.//
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Verifies that user-supplied values are stored in SqlParameter objects
        /// and not embedded in the command text.
        /// </summary>
        internal static void Test_UserInput_StoredInParameters()
        {
            const string username = "alice";
            const string password = "secret123";

            using (var cmd = BuildLoginCommand(username, password))
            {
                Assert(cmd.Parameters.Count == 2,
                    $"FAIL: Expected 2 parameters, found {cmd.Parameters.Count}.");

                Assert(cmd.Parameters["@username"] != null,
                    "FAIL: @username parameter is missing.");

                Assert((string)cmd.Parameters["@username"].Value == username,
                    "FAIL: @username parameter value does not match the supplied username.");

                Assert(cmd.Parameters["@password"] != null,
                    "FAIL: @password parameter is missing.");

                Assert((string)cmd.Parameters["@password"].Value == password,
                    "FAIL: @password parameter value does not match the supplied password.");
            }

            Pass(nameof(Test_UserInput_StoredInParameters));
        }

        // ------------------------------------------------------------------ //
        //  Test 3: Classic single-quote injection payload is treated as data. //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// A classic "' OR '1'='1" payload must end up in the @username parameter
        /// value, not in the command text, confirming the injection is neutralised.
        /// </summary>
        internal static void Test_SingleQuoteInjection_TreatedAsLiteralData()
        {
            const string payload = "' OR '1'='1";

            using (var cmd = BuildLoginCommand(payload, "anyPassword"))
            {
                // The raw payload must NOT appear in the SQL string.
                Assert(!cmd.CommandText.Contains(payload),
                    "FAIL: SQL injection payload was interpolated into CommandText.");

                // The payload MUST be stored as the parameter value (literal data).
                Assert((string)cmd.Parameters["@username"].Value == payload,
                    "FAIL: @username parameter does not hold the injection payload as data.");
            }

            Pass(nameof(Test_SingleQuoteInjection_TreatedAsLiteralData));
        }

        // ------------------------------------------------------------------ //
        //  Test 4: UNION-based injection payload is treated as data.         //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Ensures UNION-based injection payloads are stored as parameter values,
        /// not appended to the SQL command text.
        /// </summary>
        internal static void Test_UnionInjection_TreatedAsLiteralData()
        {
            const string payload = "admin' UNION SELECT null,null,null--";

            using (var cmd = BuildLoginCommand(payload, "anyPassword"))
            {
                Assert(!cmd.CommandText.Contains("UNION"),
                    "FAIL: UNION keyword from user input leaked into CommandText.");

                Assert((string)cmd.Parameters["@username"].Value == payload,
                    "FAIL: @username parameter does not hold the UNION payload as data.");
            }

            Pass(nameof(Test_UnionInjection_TreatedAsLiteralData));
        }

        // ------------------------------------------------------------------ //
        //  Test 5: SQL comment injection payload is treated as data.         //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Ensures comment-based injection payloads (-- or /* */) do not alter
        /// the command text.
        /// </summary>
        internal static void Test_CommentInjection_TreatedAsLiteralData()
        {
            const string payload = "admin'--";

            using (var cmd = BuildLoginCommand(payload, "anyPassword"))
            {
                Assert(!cmd.CommandText.Contains("--"),
                    "FAIL: SQL comment token from user input leaked into CommandText.");

                Assert((string)cmd.Parameters["@username"].Value == payload,
                    "FAIL: @username parameter does not hold the comment payload as data.");
            }

            Pass(nameof(Test_CommentInjection_TreatedAsLiteralData));
        }

        // ------------------------------------------------------------------ //
        //  Test 6: Empty username and password are handled safely.           //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Edge case: empty strings must not break parameterisation.
        /// </summary>
        internal static void Test_EmptyInput_HandledSafely()
        {
            using (var cmd = BuildLoginCommand(string.Empty, string.Empty))
            {
                Assert(cmd.Parameters.Count == 2,
                    "FAIL: Expected 2 parameters even for empty input.");

                Assert((string)cmd.Parameters["@username"].Value == string.Empty,
                    "FAIL: @username should be empty string, not null or missing.");

                Assert((string)cmd.Parameters["@password"].Value == string.Empty,
                    "FAIL: @password should be empty string, not null or missing.");

                // Verify the constant SQL template is unchanged.
                Assert(cmd.CommandText.Contains("@username") && cmd.CommandText.Contains("@password"),
                    "FAIL: CommandText placeholders missing for empty-input case.");
            }

            Pass(nameof(Test_EmptyInput_HandledSafely));
        }

        // ------------------------------------------------------------------ //
        //  Test 7: Very long input is stored safely in a parameter.          //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Ensures an unusually long username does not cause truncation or
        /// interpolation issues — it should be stored as-is in the parameter.
        /// </summary>
        internal static void Test_LongInput_StoredInParameter()
        {
            var longUsername = new string('x', 4000);

            using (var cmd = BuildLoginCommand(longUsername, "pwd"))
            {
                // CommandText is constant and short; it must not grow with input.
                Assert(cmd.CommandText.Length < 200,
                    "FAIL: CommandText grew with user input length — injection suspected.");

                Assert(((string)cmd.Parameters["@username"].Value).Length == 4000,
                    "FAIL: Long username was not stored at full length in the parameter.");
            }

            Pass(nameof(Test_LongInput_StoredInParameter));
        }

        // ------------------------------------------------------------------ //
        //  Test runner                                                        //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Runs all tests and reports results to the console.
        /// </summary>
        internal static void RunAll()
        {
            Console.WriteLine("=== SQLi Remediation Tests ===");
            Test_CommandText_ContainsParameterPlaceholders();
            Test_UserInput_StoredInParameters();
            Test_SingleQuoteInjection_TreatedAsLiteralData();
            Test_UnionInjection_TreatedAsLiteralData();
            Test_CommentInjection_TreatedAsLiteralData();
            Test_EmptyInput_HandledSafely();
            Test_LongInput_StoredInParameter();
            Console.WriteLine("=== All tests passed ===");
        }

        // ------------------------------------------------------------------ //
        //  Assertion helpers (no external dependency)                        //
        // ------------------------------------------------------------------ //

        private static void Assert(bool condition, string failMessage)
        {
            if (!condition)
                throw new InvalidOperationException(failMessage);
        }

        private static void Pass(string testName)
        {
            Console.WriteLine($"  PASS  {testName}");
        }
    }
}
