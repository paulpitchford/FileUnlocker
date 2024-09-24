using System.Management;
using Microsoft.Extensions.Configuration;
using System.Runtime.Versioning;
using Spectre.Console;

// An application to unlock a file on a remote server using WMI
// This application is designed to be run on a Windows server
// It uses WMI to query for processes locking a file and terminate them
// It then attempts to unlock the file by resetting the NTFS alternate data stream
// The application uses Spectre.Console for user interaction and configuration
// It supports command line arguments and a configuration file
// The configuration file is optional and can be used to store the file path, username, and password

namespace FileUnlocker
{
    class Program
    {
        [SupportedOSPlatform("windows")]
        static void Main(string[] args)
        {
            // Check for help argument
            if (args.Length == 1 && (args[0] == "/?" || args[0].ToLower() == "/help"))
            {
                ShowHelp();
                return;
            }

            // Load configuration from appsettings.json
            var config = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                .Build();

            // Get file path and credentials from command line arguments or configuration
            string? filePath = GetArgument(args, "-f") ?? config["FilePath"];
            string? username = GetArgument(args, "-u") ?? config["Username"];
            string? password = GetArgument(args, "-p") ?? config["Password"];

            // Inform the user that settings have been found
            if (!string.IsNullOrEmpty(filePath) && !string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
            {
                AnsiConsole.MarkupLine("[green]{0} > Server and user details found from settings.[/]", DateTime.Now);
                AnsiConsole.MarkupLine("[yellow]{0} > To override these settings, start the app with the /? argument to change these details.[/]", DateTime.Now);
            }

            // If details are missing, prompt the user for them
            if (string.IsNullOrEmpty(filePath) || string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                AnsiConsole.MarkupLine("[yellow]{0} > Missing details. Please provide the following information:[/]", DateTime.Now);

                if (string.IsNullOrEmpty(filePath))
                {
                    filePath = AnsiConsole.Ask<string>("Enter the file path:");
                }

                if (string.IsNullOrEmpty(username))
                {
                    username = AnsiConsole.Ask<string>("Enter the username:");
                }

                if (string.IsNullOrEmpty(password))
                {
                    // Prompt the user for the password and mask the input
                    password = AnsiConsole.Prompt(
                        new TextPrompt<string>("Enter the password:")
                            .PromptStyle("red")
                            .Secret());
                }

                // Save the details to appsettings.json
                SaveSettings(filePath, username, password);
            }

            // Unlock the file
            UnlockFile(filePath, username, password);
        }

        // Helper method to get command line argument value
        static string? GetArgument(string[] args, string name)
        {
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == name && i + 1 < args.Length)
                {
                    return args[i + 1];
                }
            }
            return null;
        }

        // Method to unlock the file on the remote server
        [SupportedOSPlatform("windows")]
        static void UnlockFile(string filePath, string username, string password)
        {
            try
            {
                AnsiConsole.MarkupLine("[green]{0} > Starting to unlock the file...[/]", DateTime.Now);

                // Determine if the path is a UNC path or a local path
                bool isUncPath = filePath.StartsWith(@"\\");
                string serverName;

                if (isUncPath)
                {
                    // Extract server name from UNC path
                    serverName = new Uri(filePath).Host;
                }
                else
                {
                    // For local paths, use the local machine name
                    serverName = Environment.MachineName;
                }

                // Ensure the file path is correctly formatted for WMI
                string wmiFilePath = filePath.Replace("\\", "\\\\");

                AnsiConsole.MarkupLine("[blue]{0} > Extracted server name: {1}[/]", DateTime.Now, serverName);

                // Connect to the remote server
                ManagementScope scope;
                if (isUncPath)
                {
                    ConnectionOptions options = new ConnectionOptions
                    {
                        Username = username,
                        Password = password
                    };

                    string scopePath = $"\\\\{serverName}\\root\\cimv2";
                    AnsiConsole.MarkupLine("[blue]{0} > Connection scope: {1}[/]", DateTime.Now, scopePath);

                    scope = new ManagementScope(scopePath, options);
                }
                else
                {
                    string scopePath = $"\\\\{serverName}\\root\\cimv2";
                    AnsiConsole.MarkupLine("[blue]{0} > Connection scope: {1}[/]", DateTime.Now, scopePath);

                    scope = new ManagementScope(scopePath);
                }

                AnsiConsole.Status()
                    .Start($"Connecting to server {serverName} as {username}...", ctx =>
                    {
                        ctx.Spinner(Spinner.Known.Dots2);
                        ctx.SpinnerStyle(Style.Parse("green"));
                        try
                        {
                            scope.Connect();
                        }
                        catch (UnauthorizedAccessException ex)
                        {
                            AnsiConsole.MarkupLine("[red]{0} > Access denied: {1}[/]", DateTime.Now, ex.Message);
                            AnsiConsole.MarkupLine("[red]{0} > Please check the username and password.[/]", DateTime.Now);
                            throw;
                        }
                        catch (Exception ex)
                        {
                            AnsiConsole.MarkupLine("[red]{0} > Error connecting to server: {1}[/]", DateTime.Now, ex.Message);
                            throw;
                        }
                    });

                AnsiConsole.MarkupLine("[green]{0} > Connected to server {1}.[/]", DateTime.Now, serverName);

                // Check if the file exists on the remote server
                ObjectQuery fileQuery = new ObjectQuery($"SELECT * FROM CIM_DataFile WHERE Name = '{wmiFilePath}'");
                ManagementObjectSearcher fileSearcher = new ManagementObjectSearcher(scope, fileQuery);

                ManagementObjectCollection files = fileSearcher.Get();
                if (files.Count == 0)
                {
                    AnsiConsole.MarkupLine("[red]{0} > File not found: {1}[/]", DateTime.Now, filePath);
                    return;
                }

                AnsiConsole.MarkupLine("[green]{0} > File found: {1}[/]", DateTime.Now, filePath);

                // Query for the locked file
                ObjectQuery query = new ObjectQuery($"SELECT * FROM Win32_Process WHERE CommandLine LIKE '%{wmiFilePath}%'");
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query);

                AnsiConsole.Status()
                    .Start("Querying for the locked file...", ctx =>
                    {
                        ctx.Spinner(Spinner.Known.Dots);
                        ctx.SpinnerStyle(Style.Parse("green"));
                        ManagementObjectCollection processes = searcher.Get();

                        // Terminate the process locking the file
                        foreach (ManagementObject process in processes)
                        {
                            AnsiConsole.MarkupLine("[yellow]{0} > Terminating process ID: {1}[/]", DateTime.Now, process["ProcessId"]);
                            process.InvokeMethod("Terminate", null);
                        }
                    });

                AnsiConsole.MarkupLine("[green]{0} > File unlocked successfully.[/]", DateTime.Now);
            }
            catch (UnauthorizedAccessException ex)
            {
                AnsiConsole.MarkupLine("[red]{0} > Access denied: {1}[/]", DateTime.Now, ex.Message);
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine("[red]{0} > Error unlocking file: {1}[/]", DateTime.Now, ex.Message);
            }
        }

        // Method to show help information
        static void ShowHelp()
        {
            var table = new Table();
            table.AddColumn("Option");
            table.AddColumn("Description");

            table.AddRow("[yellow]-f <filePath>[/]", "Specifies the path to the file to be unlocked.");
            table.AddRow("[yellow]-u <username>[/]", "Specifies the username for the remote server.");
            table.AddRow("[yellow]-p <password>[/]", "Specifies the password for the remote server.");
            table.AddRow("[yellow]/? or /help[/]", "Displays this help message.");

            AnsiConsole.Write(
                new Panel(table)
                    .Header("[green]Help[/]")
                    .Border(BoxBorder.Rounded)
                    .BorderStyle(Style.Parse("green"))
                    .Padding(1, 1)
            );
        }

        // Method to save settings to appsettings.json
        static void SaveSettings(string filePath, string username, string password)
        {
            var settings = new
            {
                FilePath = filePath,
                Username = username,
                Password = password
            };

            string json = System.Text.Json.JsonSerializer.Serialize(settings, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText("appsettings.json", json);
            AnsiConsole.MarkupLine("[green]{0} > Settings saved to appsettings.json.[/]", DateTime.Now);
        }
    }
}
