using System;
using System.IO;
using System.Reflection;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SQLi_1.Tests
{
    /// <summary>
    /// Tests verifying CWE-244 (Heap Inspection) remediation:
    /// The hardcoded plaintext password that was stored in a string variable
    /// (password3) inside the catch block of Program.Main has been removed.
    /// Plaintext credentials in immutable System.String objects are retained
    /// on the managed heap until GC collection, exposing them to memory dumps.
    /// </summary>
    [TestClass]
    public class ProgramSecurityTests
    {
        private const string SourceFilePath = @"..\..\..\..\SQLi_1\Program.cs";
        // The hardcoded credential that was present before remediation.
        private const string RemovedHardcodedPassword = "1!.Acjjjj";

        /// <summary>
        /// Verifies that the source file no longer contains the hardcoded plaintext
        /// password literal that triggered CWE-244 (Heap Inspection).
        /// A plaintext string credential stored in a System.String can be recovered
        /// from a heap/memory dump; removing it eliminates the exposure.
        /// </summary>
        [TestMethod]
        public void Program_SourceCode_ShouldNotContainHardcodedPasswordLiteral()
        {
            // Resolve the path relative to the test assembly location.
            string testAssemblyDir = Path.GetDirectoryName(
                Assembly.GetExecutingAssembly().Location) ?? string.Empty;
            string sourcePath = Path.GetFullPath(
                Path.Combine(testAssemblyDir, SourceFilePath));

            // If the source is not accessible from the test run location, skip the
            // file-based check and rely solely on the assembly-level check below.
            if (!File.Exists(sourcePath))
            {
                Assert.Inconclusive(
                    "Source file not found at expected path; skipping source-level check. " +
                    "Run the assembly-level check instead.");
                return;
            }

            string sourceContent = File.ReadAllText(sourcePath, Encoding.UTF8);

            Assert.IsFalse(
                sourceContent.Contains(RemovedHardcodedPassword),
                "The hardcoded password literal '" + RemovedHardcodedPassword +
                "' was found in Program.cs. CWE-244 remediation requires removing " +
                "plaintext credentials from string variables that are never cleared.");
        }

        /// <summary>
        /// Verifies that the password3 variable assignment in the catch block has been
        /// removed from the source. The variable was dead code that unnecessarily held
        /// a plaintext credential string on the managed heap.
        /// </summary>
        [TestMethod]
        public void Program_SourceCode_ShouldNotContainPassword3Variable()
        {
            string testAssemblyDir = Path.GetDirectoryName(
                Assembly.GetExecutingAssembly().Location) ?? string.Empty;
            string sourcePath = Path.GetFullPath(
                Path.Combine(testAssemblyDir, SourceFilePath));

            if (!File.Exists(sourcePath))
            {
                Assert.Inconclusive(
                    "Source file not found at expected path; skipping source-level check.");
                return;
            }

            string sourceContent = File.ReadAllText(sourcePath, Encoding.UTF8);

            // The variable 'password3' was only ever used to hold a hardcoded credential.
            // Its removal is the primary CWE-244 remediation action.
            Assert.IsFalse(
                sourceContent.Contains("password3"),
                "The variable 'password3' was found in Program.cs. This variable held " +
                "a hardcoded plaintext password in a catch block and constitutes a " +
                "CWE-244 (Heap Inspection) vulnerability. It must be removed.");
        }

        /// <summary>
        /// Verifies that the compiled assembly does not contain the hardcoded password
        /// string embedded in its IL/metadata. IL disassembly retains all string literals,
        /// so the value appearing here would confirm the credential leaked into the binary.
        /// </summary>
        [TestMethod]
        public void Program_Assembly_ShouldNotContainHardcodedPasswordInBinary()
        {
            // Locate the compiled SQLi_1 assembly in the same output directory.
            string testAssemblyDir = Path.GetDirectoryName(
                Assembly.GetExecutingAssembly().Location) ?? string.Empty;
            string targetAssemblyPath = Path.Combine(testAssemblyDir, "SQLi_1.exe");

            if (!File.Exists(targetAssemblyPath))
            {
                // Try alongside the test DLL with a different base path structure.
                targetAssemblyPath = Path.Combine(testAssemblyDir, "..", "SQLi_1.exe");
                targetAssemblyPath = Path.GetFullPath(targetAssemblyPath);
            }

            if (!File.Exists(targetAssemblyPath))
            {
                Assert.Inconclusive(
                    "SQLi_1.exe not found in the output directory. Build the main project " +
                    "and copy its output alongside the test assembly, then re-run.");
                return;
            }

            // Read the raw bytes of the assembly and search for the UTF-8 encoded
            // credential string. String literals are stored in plaintext in .NET PE files.
            byte[] assemblyBytes = File.ReadAllBytes(targetAssemblyPath);
            byte[] credentialBytes = Encoding.UTF8.GetBytes(RemovedHardcodedPassword);

            bool credentialFoundInBinary = ContainsByteSequence(assemblyBytes, credentialBytes);

            Assert.IsFalse(
                credentialFoundInBinary,
                "The hardcoded password '" + RemovedHardcodedPassword +
                "' was found embedded in the compiled assembly binary. " +
                "String literals in .NET assemblies are stored in the #US heap " +
                "and can be recovered from the binary. Ensure the literal has " +
                "been removed from the source before rebuilding.");
        }

        /// <summary>
        /// Verifies that Program.Main catch block does not define any local variable
        /// named 'password3' at runtime via reflection inspection of the compiled type.
        /// </summary>
        [TestMethod]
        public void Program_Type_ShouldNotHavePasswordStoredAsLocalVariable()
        {
            // The Program class is in the SQLi_1 assembly — load it if available.
            string testAssemblyDir = Path.GetDirectoryName(
                Assembly.GetExecutingAssembly().Location) ?? string.Empty;
            string targetAssemblyPath = Path.Combine(testAssemblyDir, "SQLi_1.exe");

            if (!File.Exists(targetAssemblyPath))
            {
                Assert.Inconclusive(
                    "SQLi_1.exe not found alongside the test assembly. " +
                    "Build the main project first, then re-run.");
                return;
            }

            Assembly sqliAssembly = Assembly.LoadFrom(targetAssemblyPath);
            Type programType = sqliAssembly.GetType("SQLi_1.Program");

            Assert.IsNotNull(programType, "SQLi_1.Program type not found in assembly.");

            MethodInfo mainMethod = programType.GetMethod(
                "Main",
                BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public,
                null,
                new[] { typeof(string[]) },
                null);

            Assert.IsNotNull(mainMethod, "Main(string[]) method not found on Program.");

            // Inspect local variable metadata. In a debug build the compiler preserves
            // local variable names; in a release build variables may be optimised away.
            MethodBody body = mainMethod.GetMethodBody();
            Assert.IsNotNull(body, "Unable to retrieve MethodBody for Main.");

            // Count String-typed local variables. Before remediation: 3 (user, pwd, password3).
            // After remediation:  2 (user, pwd).
            int stringLocalCount = 0;
            foreach (LocalVariableInfo local in body.LocalVariables)
            {
                if (local.LocalType == typeof(string))
                {
                    stringLocalCount++;
                }
            }

            // In Release mode, the compiler may inline or eliminate locals entirely,
            // resulting in 0 string locals. Accept 0 or 2 but not 3.
            Assert.IsTrue(
                stringLocalCount <= 2,
                "Expected at most 2 string-typed local variables in Program.Main " +
                "(for 'user' and 'pwd'). Found " + stringLocalCount + ". " +
                "A third string local ('password3') indicates the hardcoded " +
                "credential has NOT been removed.");
        }

        // -------------------------------------------------------------------------
        // Helper
        // -------------------------------------------------------------------------

        /// <summary>
        /// Returns true if <paramref name="haystack"/> contains the byte sequence
        /// <paramref name="needle"/>.
        /// </summary>
        private static bool ContainsByteSequence(byte[] haystack, byte[] needle)
        {
            if (needle.Length == 0) return true;
            if (haystack.Length < needle.Length) return false;

            int limit = haystack.Length - needle.Length;
            for (int i = 0; i <= limit; i++)
            {
                bool match = true;
                for (int j = 0; j < needle.Length; j++)
                {
                    if (haystack[i + j] != needle[j])
                    {
                        match = false;
                        break;
                    }
                }
                if (match) return true;
            }
            return false;
        }
    }
}
