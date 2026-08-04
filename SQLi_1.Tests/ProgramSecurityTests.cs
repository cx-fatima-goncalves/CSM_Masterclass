using System;
using System.IO;
using System.Text.RegularExpressions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SQLi_1.Tests
{
    /// <summary>
    /// Security regression tests for CWE-244 (Heap Inspection) remediation.
    ///
    /// The vulnerability was: a plaintext password was assigned to a local variable
    /// (password3) inside a catch block and never cleared from memory.  This fix
    /// removes the dead assignment entirely.
    ///
    /// Tests here verify that no plaintext password literal is present in the
    /// Program.cs source and that the Main method's error-handling path does not
    /// expose any sensitive value.
    /// </summary>
    [TestClass]
    public class ProgramSecurityTests
    {
        // Path to the source file under test, relative to the solution root.
        // Adjust if the test runner working directory differs.
        private static readonly string ProgramCsRelativePath =
            Path.Combine("..", "SQLi_1", "Program.cs");

        private string _programCsContent;

        [TestInitialize]
        public void LoadSourceFile()
        {
            // Resolve the path relative to the test binary's directory so the
            // test can be run from any working directory.
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string fullPath = Path.GetFullPath(
                Path.Combine(baseDir, "..", "..", "..", ProgramCsRelativePath));

            if (File.Exists(fullPath))
            {
                _programCsContent = File.ReadAllText(fullPath);
            }
            else
            {
                // Fallback: try relative to current directory (CI environments)
                string fallback = Path.GetFullPath(
                    Path.Combine(Directory.GetCurrentDirectory(), ProgramCsRelativePath));
                _programCsContent = File.Exists(fallback)
                    ? File.ReadAllText(fallback)
                    : null;
            }
        }

        // ---------------------------------------------------------------
        // CWE-244 Heap Inspection: no hardcoded password in catch block
        // ---------------------------------------------------------------

        /// <summary>
        /// Verifies that the vulnerable variable 'password3' no longer exists in
        /// the source.  The SAST finding was specifically about this variable.
        /// </summary>
        [TestMethod]
        [TestCategory("Security")]
        [TestCategory("CWE-244")]
        public void NoCwe244_Password3VariableRemoved()
        {
            if (_programCsContent == null)
            {
                Assert.Inconclusive("Source file could not be located; skipping static check.");
                return;
            }

            bool containsPassword3 = _programCsContent.Contains("password3");
            Assert.IsFalse(
                containsPassword3,
                "CWE-244: 'password3' variable still present in Program.cs. " +
                "Plaintext password in a never-cleared local variable is a heap-inspection risk.");
        }

        /// <summary>
        /// Verifies that the specific hardcoded credential value that was stored in
        /// 'password3' no longer appears anywhere in the source file.
        /// </summary>
        [TestMethod]
        [TestCategory("Security")]
        [TestCategory("CWE-244")]
        public void NoCwe244_HardcodedCredentialValueRemoved()
        {
            if (_programCsContent == null)
            {
                Assert.Inconclusive("Source file could not be located; skipping static check.");
                return;
            }

            // The literal value that was assigned to password3 before remediation.
            // After the fix it must not appear anywhere in the source.
            bool containsHardcodedCredential = _programCsContent.Contains("1!.Acjjjj");
            Assert.IsFalse(
                containsHardcodedCredential,
                "CWE-244: The hardcoded credential value '1!.Acjjjj' is still present " +
                "in Program.cs. Remove the literal to eliminate heap-inspection risk.");
        }

        /// <summary>
        /// Verifies that the catch block in Main does NOT define any local variable
        /// whose name contains 'password' (case-insensitive) with an assigned string
        /// literal, which would be the pattern flagged by the SAST rule.
        /// </summary>
        [TestMethod]
        [TestCategory("Security")]
        [TestCategory("CWE-244")]
        public void NoCwe244_NoCatchBlockPasswordVariable()
        {
            if (_programCsContent == null)
            {
                Assert.Inconclusive("Source file could not be located; skipping static check.");
                return;
            }

            // Pattern: 'var <name-containing-password> = "<literal>"' inside any block.
            // This is intentionally broad to catch regressions where the variable is
            // renamed but the anti-pattern is re-introduced.
            var pattern = new Regex(
                @"var\s+\w*[Pp]assword\w*\s*=\s*""[^""]+""",
                RegexOptions.IgnoreCase);

            bool hasPasswordAssignment = pattern.IsMatch(_programCsContent);
            Assert.IsFalse(
                hasPasswordAssignment,
                "CWE-244 regression: a local variable whose name contains 'password' " +
                "is assigned a string literal in Program.cs. This is a heap-inspection risk.");
        }

        // ---------------------------------------------------------------
        // Functional: error-handling path outputs the expected message
        // ---------------------------------------------------------------

        /// <summary>
        /// Verifies that the Main method's catch block still writes the expected
        /// error message to stdout, confirming the error-handling logic was not
        /// accidentally removed during remediation.
        /// </summary>
        [TestMethod]
        [TestCategory("Functional")]
        public void Main_WithNoArguments_WritesErrorMessage()
        {
            // Redirect Console.Out so we can inspect what is written.
            var originalOut = Console.Out;
            using (var writer = new StringWriter())
            {
                Console.SetOut(writer);
                try
                {
                    // Call Main with an empty array; this will trigger the catch
                    // block because args[0] will throw IndexOutOfRangeException.
                    Program.Main(new string[0]);
                }
                finally
                {
                    Console.SetOut(originalOut);
                }

                string output = writer.ToString();
                StringAssert.Contains(
                    output,
                    "An error has occurred !!",
                    "The catch block in Main should still print the error message after remediation.");
            }
        }

        /// <summary>
        /// Verifies that the catch block output does NOT contain any sensitive
        /// credential information — confirming that removing 'password3' did not
        /// inadvertently redirect it to the console.
        /// </summary>
        [TestMethod]
        [TestCategory("Security")]
        [TestCategory("CWE-244")]
        public void Main_ErrorOutput_ContainsNoSensitiveData()
        {
            var originalOut = Console.Out;
            using (var writer = new StringWriter())
            {
                Console.SetOut(writer);
                try
                {
                    Program.Main(new string[0]);
                }
                finally
                {
                    Console.SetOut(originalOut);
                }

                string output = writer.ToString();

                Assert.IsFalse(
                    output.Contains("password"),
                    "The error output must not contain the word 'password'.");

                Assert.IsFalse(
                    output.Contains("1!.Acjjjj"),
                    "The error output must not contain the previously hardcoded credential value.");
            }
        }
    }
}
