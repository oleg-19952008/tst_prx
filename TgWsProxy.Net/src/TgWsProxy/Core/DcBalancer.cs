using System.Text;
using TgWsProxy.Configuration;

namespace TgWsProxy.Core;

/// <summary>
/// Balances CF-proxy domains between DCs — port of
/// Python <c>proxy/balancer.py::_Balancer</c>. Thread-safe (Python relied on
/// the single-threaded event loop; here all state is behind one lock).
/// </summary>
public sealed class DcBalancer
{
    private static readonly int[] KnownDcs = { 1, 2, 3, 4, 5, 203 };

    private readonly object _lock = new();
    private List<string> _domains = new();
    private Dictionary<int, string> _dcToDomain = new();

    /// <summary>Python <c>update_domains_list</c>: no-op if the multiset is unchanged.</summary>
    public void UpdateDomainsList(IReadOnlyList<string> domainsList)
    {
        lock (_lock)
        {
            if (DomainsEqualUnordered(_domains, domainsList))
                return;

            _domains = domainsList.ToList();
            if (_domains.Count == 0)
            {
                _dcToDomain.Clear();
                return;
            }
            _dcToDomain = KnownDcs.ToDictionary(dc => dc, _ => PickRandom(_domains));
        }
    }

    /// <summary>Python <c>update_domain_for_dc</c>; returns true when switched.</summary>
    public bool UpdateDomainForDc(int dcId, string domain)
    {
        lock (_lock)
        {
            if (_dcToDomain.TryGetValue(dcId, out var cur) && cur == domain)
                return false;
            _dcToDomain[dcId] = domain;
            return true;
        }
    }

    /// <summary>
    /// Python <c>get_domains_for_dc</c>: current domain first, then the rest shuffled.
    /// </summary>
    public IReadOnlyList<string> GetDomainsForDc(int dcId)
    {
        string? current;
        List<string> shuffled;
        lock (_lock)
        {
            _dcToDomain.TryGetValue(dcId, out current);
            shuffled = _domains.ToList();
        }
        Shuffle(shuffled);
        var result = new List<string>(shuffled.Count + 1);
        if (current is not null)
            result.Add(current);
        result.AddRange(shuffled.Where(d => d != current));
        return result;
    }

    public IReadOnlyList<string> Domains
    {
        get { lock (_lock) return _domains.ToList(); }
    }

    private static bool DomainsEqualUnordered(List<string> a, IReadOnlyList<string> b)
    {
        if (a.Count != b.Count) return false;
        var counter = new Dictionary<string, int>();
        foreach (var d in a) counter[d] = counter.GetValueOrDefault(d) + 1;
        foreach (var d in b)
        {
            if (!counter.TryGetValue(d, out var n) || n == 0) return false;
            counter[d] = n - 1;
        }
        return true;
    }

    private static string PickRandom(List<string> list) =>
        list[RandomNumberGenerator.GetInt32(list.Count)];

    /// <summary>Fisher–Yates with a CSPRNG index (matches random.shuffle semantics well enough).</summary>
    internal static void Shuffle(List<string> list)
    {
        for (int i = list.Count - 1; i > 0; i--)
        {
            int j = RandomNumberGenerator.GetInt32(i + 1);
            (list[i], list[j]) = (list[j], list[i]);
        }
    }
}
