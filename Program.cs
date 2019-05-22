using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Collections.Generic;
using System.Linq;

namespace hmac
{
    /// <summary>
    ///  Класс Program
    ///  основной класс программы
    ///  для входящего файла рассчитывает HMACSHA256
    ///  и записывает в поле {S:{MDG:"%hashcode%"}}
    ///  SWIFT сообщения
    /// </summary>
    class Program
    {
        private static string FIRST_SYMBOL = "\x01";
        private static string LAST_SYMBOL = "\x03";

        private static string LOG_PATH = AppDomain.CurrentDomain.BaseDirectory + "log.txt";

        private static System.Threading.Mutex mutex = new System.Threading.Mutex(false, "hmac");

        /// <summary>
        /// Метод Main() является
        /// входной точкой работы программы
        /// </summary>
        /// <param name="args">args[0] - файл, для которого нужно рассчитать HMACSHA256</param>
        static void Main(string[] args)
        {
            if (args.Length > 0)
            {
                try
                {
                    string filePath = args[0];

                    string sourceMessage = File.ReadAllText(filePath);

                    IniReader iniReader = new IniReader(AppDomain.CurrentDomain.BaseDirectory + "hmac.ini");

                    string key = iniReader.GetValue("Key");

                    string HMAC = GetHMACSHA256(sourceMessage, key);

                    string messageToWrite = $"{FIRST_SYMBOL}{sourceMessage}" + "{S:{MDG:" + HMAC + "}}" + LAST_SYMBOL;

                    while (messageToWrite.Length % 512 != 0)
                    {
                        messageToWrite += " ";
                    }

                    File.WriteAllText(filePath, messageToWrite);
                    Log($@"Для файла '{filePath}' рассчитан хэш.");

                    if (iniReader.GetKeys("").Contains("Path"))
                    {
                        string destDirName = iniReader.GetValue("Path");

                        if (destDirName.Length == 0) Log("Указан пустой путь для копирования.");

                        string sourceFileName = Path.GetFullPath(filePath);
                        string destFileName = Path.Combine(destDirName, Path.GetFileName(filePath));

                        File.Move(sourceFileName, destFileName);
                        Log($"Файл перемещён '{destFileName}'.");
                    }
                }
                catch (Exception e)
                {
                    Log(e.Message);
                }
            }
            else
            {
                Log("Не указан путь к файлу.");
            }
        }

        private static string GetHMACSHA256(string data, string key)
        {
            byte[] bKey = Encoding.ASCII.GetBytes(key);
            using (HMACSHA256 hmac = new HMACSHA256(bKey))
            {
                byte[] bStr = Encoding.ASCII.GetBytes(data);
                byte[] bHash = hmac.ComputeHash(bStr);
                return BitConverter.ToString(bHash).Replace("-", string.Empty);
            }
        }

        public static void Log(string message)
        {
            mutex.WaitOne();
            using (System.IO.StreamWriter writer = new StreamWriter(LOG_PATH, true))
            {
                writer.AutoFlush = true;
                writer.WriteLine($"{DateTime.Now}\t{message}");
            }
            mutex.ReleaseMutex();
        }
    }

    class IniReader
    {
        Dictionary<string, Dictionary<string, string>> ini = new Dictionary<string, Dictionary<string, string>>(StringComparer.InvariantCultureIgnoreCase);

        public IniReader(string file)
        {
            var txt = File.ReadAllText(file);

            Dictionary<string, string> currentSection = new Dictionary<string, string>(StringComparer.InvariantCultureIgnoreCase);

            ini[""] = currentSection;

            foreach (var line in txt.Split(new[] { "\n" }, StringSplitOptions.RemoveEmptyEntries)
                                   .Where(t => !string.IsNullOrWhiteSpace(t))
                                   .Select(t => t.Trim()))
            {
                if (line.StartsWith(";"))
                    continue;

                if (line.StartsWith("[") && line.EndsWith("]"))
                {
                    currentSection = new Dictionary<string, string>(StringComparer.InvariantCultureIgnoreCase);
                    ini[line.Substring(1, line.LastIndexOf("]") - 1)] = currentSection;
                    continue;
                }

                var idx = line.IndexOf("=");
                if (idx == -1)
                    currentSection[line] = "";
                else
                    currentSection[line.Substring(0, idx)] = line.Substring(idx + 1);
            }
        }

        public string GetValue(string key)
        {
            return GetValue(key, "", "");
        }

        public string GetValue(string key, string section)
        {
            return GetValue(key, section, "");
        }

        public string GetValue(string key, string section, string @default)
        {
            if (!ini.ContainsKey(section))
                return @default;

            if (!ini[section].ContainsKey(key))
                return @default;

            return ini[section][key];
        }

        public string[] GetKeys(string section)
        {
            if (!ini.ContainsKey(section))
                return new string[0];

            return ini[section].Keys.ToArray();
        }

        public string[] GetSections()
        {
            return ini.Keys.Where(t => t != "").ToArray();
        }
    }
}
