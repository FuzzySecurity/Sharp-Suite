using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using SQLite;

namespace Canary
{
    class Program
    {
        public static DateTime ConvertToDateTime(string chromeTime)
        {
            DateTime epoch = new DateTime(1601, 1, 1);
            try
            {
                double dateCreatedRaw = double.Parse(chromeTime);
                double secsFromEpoch = dateCreatedRaw / 1000000;
                if (secsFromEpoch > TimeSpan.MaxValue.TotalSeconds)
                {
                    // handle timestamps over the allowed range
                    return new DateTime(DateTime.MaxValue.Ticks);
                }
                if (secsFromEpoch < 0)
                {
                    secsFromEpoch = 0;
                }
                return epoch.Add(TimeSpan.FromSeconds(secsFromEpoch)).ToLocalTime();
            }
            catch
            {
                // in case the parsing fails
                return epoch;
            }
        }

        public static String GetHistoryPath(Int32 iBrowser)
        {
            String sFileHist = String.Empty;
            if (iBrowser == 0)
            {
                sFileHist = String.Format("{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History", System.Environment.GetEnvironmentVariable("USERPROFILE"));
            } else
            {
                sFileHist = String.Format("{0}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History", System.Environment.GetEnvironmentVariable("USERPROFILE"));
            }
            
            if (File.Exists(sFileHist))
            {
                return sFileHist;
            } else
            {
                return String.Empty;
            }
        }

        public static void GetBrowserHist(String sHistPath, Int32 iLimit=0)
        {
            // convert to a file:/// uri path type so we can do lockless opening
            Uri uri = new Uri(sHistPath);
            string loginDataFilePathUri = String.Format("{0}?nolock=1", uri.AbsoluteUri);

            bool someResults = false;
            SQLiteConnection database = null;

            try
            {
                database = new SQLiteConnection(loginDataFilePathUri, SQLiteOpenFlags.ReadOnly | SQLiteOpenFlags.OpenUri, false);
            }
            catch (Exception e)
            {
                Console.WriteLine("[!] {0}", e.InnerException.Message);
                return;
            }

            string query = "SELECT url, title, visit_count, cast(last_visit_time as text) as last_visit_time FROM urls ORDER BY visit_count DESC";
            List<SQLiteQueryRow> results = database.Query2(query, false);
            foreach (SQLiteQueryRow row in results)
            {
                DateTime lastVisit = ConvertToDateTime(row.column[3].Value.ToString());
                if (iLimit != 0)
                {
                    TimeSpan tWhen = DateTime.Now.Subtract(lastVisit);
                    if ((Int32)Math.Round(tWhen.TotalDays) > iLimit)
                    {
                        continue;
                    }
                }
                Console.WriteLine("\nURL             : " + row.column[0].Value);
                // We do some hax here because of potential console beeping
                Console.WriteLine("title           : " + Encoding.ASCII.GetString(Encoding.ASCII.GetBytes(row.column[1].Value.ToString())));
                Console.WriteLine("visit_count     : " + row.column[2].Value);
                Console.WriteLine("last_visit_time : " + lastVisit);
            }

            database.Close();
        }

        static void Main(string[] args)
        {
            int cHelp = Array.FindIndex(args, s => new Regex(@"(?i)(-|--|/)(h|Help)$").Match(s).Success);
            int cLimit = Array.FindIndex(args, s => new Regex(@"(?i)(-|--|/)(l|Limit)$").Match(s).Success);
            int cBrowser = Array.FindIndex(args, s => new Regex(@"(?i)(-|--|/)(b|Browser)$").Match(s).Success);
            int iBrowser = 0;
            if (cHelp != -1)
            {
                Console.WriteLine(@" __               ");
                Console.WriteLine(@"/   _ __  _  __ \/");
                Console.WriteLine(@"\__(_|| |(_| |  / ");
                Console.WriteLine("\n  -h(--Help)       Show this help message.");
                Console.WriteLine("  -l(--Limit)      Limit results to the past x days.");
                Console.WriteLine("  -b(--Browser)    Chrome (default) or Edge (new chromium Edge).");
            } else
            {
                if (cBrowser != -1)
                {
                    if (args[(cBrowser + 1)].ToLower() == "edge")
                    {
                        iBrowser = 1;
                    }
                }
                if (cLimit != -1)
                {
                    try
                    {
                        Int32 iLimit = int.Parse(args[(cLimit + 1)]);
                        if (!String.IsNullOrEmpty(GetHistoryPath(iBrowser)))
                        {
                            GetBrowserHist(GetHistoryPath(iBrowser), iLimit);
                        } else
                        {
                            Console.WriteLine("[!] History file not found..");
                        }
                    } catch
                    {
                        Console.WriteLine("[!] Invalid value passed to -l(--Limit)..");
                        return;
                    }
                } else
                {
                    if (!String.IsNullOrEmpty(GetHistoryPath(iBrowser)))
                    {
                        GetBrowserHist(GetHistoryPath(iBrowser));
                    } else
                    {
                        Console.WriteLine("[!] History file not found..");
                    }
                }
            }
            
        }
    }
}
