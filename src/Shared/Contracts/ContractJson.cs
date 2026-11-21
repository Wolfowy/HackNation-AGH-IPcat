using System.Text.Json;
using System.Text.Json.Serialization;

namespace WebScan.Contracts;

/// <summary>Wire format for every contract: camelCase, enums as strings, nulls omitted.</summary>
public static class ContractJson
{
    public static readonly JsonSerializerOptions Options = Configure(new JsonSerializerOptions(JsonSerializerDefaults.Web));

    public static JsonSerializerOptions Configure(JsonSerializerOptions options)
    {
        options.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
        options.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
        if (!options.Converters.Any(c => c is JsonStringEnumConverter))
            options.Converters.Add(new JsonStringEnumConverter());
        return options;
    }
}
