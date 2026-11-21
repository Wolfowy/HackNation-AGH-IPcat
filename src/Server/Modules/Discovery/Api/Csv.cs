using System.Text;

namespace WebScan.Server.Modules.Discovery.Api;

/// <summary>RFC 4180 CSV (CRLF, quoted fields) with spreadsheet formula-injection protection.</summary>
public static class Csv
{
    /// <summary>Escapes one cell: cells starting with = + - @ (or tab/CR) get a leading apostrophe; fields with , " CR LF are quoted.</summary>
    public static string Escape(string? value)
    {
        if (string.IsNullOrEmpty(value)) return "";
        if (value[0] is '=' or '+' or '-' or '@' or '\t' or '\r') value = "'" + value;
        return value.IndexOfAny([',', '"', '\r', '\n']) >= 0 ? $"\"{value.Replace("\"", "\"\"")}\"" : value;
    }

    public static string Write(IReadOnlyList<string> header, IEnumerable<IReadOnlyList<string?>> rows)
    {
        var sb = new StringBuilder();
        sb.Append(string.Join(',', header.Select(Escape))).Append("\r\n");
        foreach (var row in rows) sb.Append(string.Join(',', row.Select(Escape))).Append("\r\n");
        return sb.ToString();
    }

    /// <summary>Parses RFC 4180 text (quoted fields, escaped quotes, embedded newlines; CRLF or LF). Blank lines are skipped.</summary>
    public static List<List<string>> Parse(string text)
    {
        var rows = new List<List<string>>();
        var row = new List<string>();
        var field = new StringBuilder();
        var quoted = false;
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (quoted)
            {
                if (c != '"') field.Append(c);
                else if (i + 1 < text.Length && text[i + 1] == '"') { field.Append('"'); i++; }
                else quoted = false;
                continue;
            }
            switch (c)
            {
                case '"' when field.Length == 0: quoted = true; break;
                case ',': row.Add(field.ToString()); field.Clear(); break;
                case '\r': break;
                case '\n': EndRow(); break;
                default: field.Append(c); break;
            }
        }
        if (field.Length > 0 || row.Count > 0) EndRow();
        return rows;

        void EndRow()
        {
            row.Add(field.ToString());
            field.Clear();
            if (row.Count > 1 || row[0].Length > 0) rows.Add(row);
            row = [];
        }
    }
}
