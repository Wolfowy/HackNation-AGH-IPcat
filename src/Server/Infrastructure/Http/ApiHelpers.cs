using Microsoft.AspNetCore.Http;

namespace WebScan.Server.Infrastructure.Http;

/// <summary>
/// Collects field errors for minimal API endpoints and turns them into an RFC 7807 validation problem (422, <c>errors</c> dict).
/// </summary>
public sealed class ValidationErrors
{
    private readonly Dictionary<string, List<string>> _errors = new(StringComparer.Ordinal);

    public bool IsValid => _errors.Count == 0;

    public ValidationErrors Add(string field, string message)
    {
        if (!_errors.TryGetValue(field, out var list)) _errors[field] = list = [];
        list.Add(message);
        return this;
    }

    /// <summary>Adds <paramref name="message"/> when <paramref name="condition"/> is false.</summary>
    public ValidationErrors Require(bool condition, string field, string message) => condition ? this : Add(field, message);

    public IReadOnlyDictionary<string, string[]> ToDictionary() => _errors.ToDictionary(e => e.Key, e => e.Value.ToArray());

    public IEnumerable<string> Messages => _errors.SelectMany(e => e.Value.Select(m => $"{e.Key}: {m}"));

    public IResult ToResult() => Results.ValidationProblem(ToDictionary(), statusCode: StatusCodes.Status422UnprocessableEntity);

    public static IResult Single(string field, string message) => new ValidationErrors().Add(field, message).ToResult();
}

/// <summary>Paged list response: <c>{ items, total, page, pageSize }</c>.</summary>
public sealed record PagedResult<T>(IReadOnlyList<T> Items, int Total, int Page, int PageSize);

public static class Paging
{
    public const int DefaultPageSize = 50;
    public const int MaxPageSize = 500;

    /// <summary>Clamps query values: page ≥ 1, 1 ≤ pageSize ≤ <see cref="MaxPageSize"/>.</summary>
    public static (int Page, int PageSize, int Skip) Normalize(int? page, int? pageSize)
    {
        var p = Math.Max(page ?? 1, 1);
        var size = Math.Clamp(pageSize ?? DefaultPageSize, 1, MaxPageSize);
        return (p, size, (p - 1) * size);
    }
}
