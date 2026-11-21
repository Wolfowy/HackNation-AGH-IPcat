using System.Text;

namespace WebScan.Server.Modules.Networks;

/// <summary>Minimal RFC 4180 CSV reader/writer (quoted fields, doubled quotes, embedded separators and line breaks).</summary>
internal static class Csv
{
    public static List<List<string>> Parse(string text)
    {
        var rows = new List<List<string>>();
        var row = new List<string>();
        var field = new StringBuilder();
        var inQuotes = false;
        var fieldStarted = false;

        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (inQuotes)
            {
                if (c != '"') field.Append(c);
                else if (i + 1 < text.Length && text[i + 1] == '"') { field.Append('"'); i++; }
                else inQuotes = false;
                continue;
            }

            switch (c)
            {
                case '"' when field.Length == 0:
                    inQuotes = true;
                    fieldStarted = true;
                    break;
                case ',':
                    row.Add(field.ToString());
                    field.Clear();
                    fieldStarted = true;
                    break;
                case '\r' or '\n':
                    if (c == '\r' && i + 1 < text.Length && text[i + 1] == '\n') i++;
                    EndRow();
                    break;
                default:
                    field.Append(c);
                    fieldStarted = true;
                    break;
            }
        }
        if (inQuotes) throw new FormatException("Unterminated quoted field.");
        EndRow();
        return rows;

        void EndRow()
        {
            if (fieldStarted || row.Count > 0)
            {
                row.Add(field.ToString());
                rows.Add(row);
            }
            row = [];
            field.Clear();
            fieldStarted = false;
        }
    }

    public static string Write(IEnumerable<IReadOnlyList<string?>> rows)
    {
        var sb = new StringBuilder();
        foreach (var row in rows)
        {
            sb.AppendJoin(',', row.Select(Escape));
            sb.Append("\r\n");
        }
        return sb.ToString();
    }

    private static string Escape(string? value)
    {
        value ??= "";
        var needsQuotes = value.AsSpan().IndexOfAny(",\"\r\n") >= 0 || value != value.Trim();
        return needsQuotes ? $"\"{value.Replace("\"", "\"\"")}\"" : value;
    }
}
