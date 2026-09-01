using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SessionGuard.Core.Authz;
using SessionGuard.Core.Http;
using SessionGuard.Core.Pki;
using SessionGuard.Core.Proxy;
using SessionGuard.Core.Vault;

namespace SessionGuard.E2E;

public static class Program
{
    private const string ProtectedHost = "api.example.test";
    private const string OpenHost = "other.example.test";
    private const string WildLogin = "login.sg.test";
    private const string WildApi = "api2.sg.test";

    private static readonly List<(string name, bool ok, string detail)> Results = new();

    public static async Task<int> Main(string[] args)
    {
        if (args.Length > 0 && args[0] == "--rogue")
            return await RogueAsync(args);

        return await RunSuiteAsync();
    }

    // ------------------------------------------------------------ the suite

    private static async Task<int> RunSuiteAsync()
    {
        EnsureHostsEntries();

        await using var service = new MockService(ProtectedHost);
        service.Start();
        await using var openService = new MockService(OpenHost);
        openService.Start();
        await using var wildService = new MockService(WildLogin, WildApi);
        wildService.Start();

        var sealer = new EphemeralSealer();
        var vault = new SessionVault(sealer);
        var lease = new PresenceLease();
        var authorizer = new PeerAuthorizer(new ProcNetPeerResolver(), lease);
        var ca = new CertificateAuthority(new InMemoryCaStore());

        // Upstream validation stays enabled; the mock's own root is pinned so the
        // callback proves it is doing real chain work rather than returning true.
        var pinned = new X509Certificate2Collection { service.RootCertificate,
                                                      openService.RootCertificate,
                                                      wildService.RootCertificate };
        RemoteCertificateValidationCallback upstream = (_, cert, _, _) =>
        {
            if (cert is null) return false;
            var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.AddRange(pinned);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            return chain.Build(new X509Certificate2(cert));
        };

        var options = new ProxyOptions(0, new[] { ProtectedHost, "*.sg.test" }, upstream);
        await using var proxy = new ProxyEngine(options, vault, authorizer, ca);
        var log = new List<string>();
        proxy.Observed += e => { lock (log) log.Add(e.ToString()); Console.WriteLine("  [proxy] " + e); };
        proxy.Start();

        string proxyUrl = $"http://127.0.0.1:{proxy.ListenPort}";
        string baseUrl = $"https://{ProtectedHost}:{service.Port}";

        var jar = new CookieContainer();
        using var client = MakeClient(proxyUrl, ca.Root, jar);

        // 0 ------------------------------------------- header/cookie units
        Section("0. Header and cookie handling");
        RunUnitChecks();

        // 1 ----------------------------------------------------- login
        Section("1. Login through the guard");
        authorizer.TryOpenLease(Environment.ProcessId, TimeSpan.FromMinutes(5), out _);

        var login = await client.PostAsync($"{baseUrl}/login",
            new StringContent("{}", Encoding.UTF8, "application/json"));
        Check("login succeeds", login.StatusCode == HttpStatusCode.OK,
              $"HTTP {(int)login.StatusCode}");

        var jarCookies = jar.GetCookies(new Uri(baseUrl)).Cast<Cookie>().ToList();
        Check("browser jar holds no session cookie",
              jarCookies.All(c => c.Name != "sessionid"),
              $"jar=[{string.Join(",", jarCookies.Select(c => c.Name))}]");
        Check("all Set-Cookie values captured into the vault",
              vault.Count(ProtectedHost) == 2,
              $"{vault.Count(ProtectedHost)} cookie(s): " +
              string.Join(",", vault.Names(ProtectedHost)));

        // 2 --------------------------------------------- authorized use
        Section("2. Authorized use, keep-alive, framing");
        var me = await client.GetAsync($"{baseUrl}/me");
        string meBody = await me.Content.ReadAsStringAsync();
        Check("authorized request is authenticated",
              me.StatusCode == HttpStatusCode.OK && meBody.Contains("srecko"),
              $"HTTP {(int)me.StatusCode} {meBody}");

        bool allOk = true;
        for (int i = 0; i < 5; i++)
        {
            var r = await client.GetAsync($"{baseUrl}/me");
            if (r.StatusCode != HttpStatusCode.OK) { allOk = false; break; }
        }
        Check("five more requests on the same connection all authenticate", allOk);
        Check("rolling refresh recorded new versions",
              vault.RefreshCount >= 6, $"refreshes={vault.RefreshCount}");

        // A body that literally contains a header line must survive untouched:
        // header editing that searches the whole buffer corrupts payloads.
        string payload = $"{{\"note\":\"{MockService.BodyMarker}\\r\\n\\r\\npadding\"}}";
        var echo = await client.PostAsync($"{baseUrl}/echo",
            new StringContent(payload, Encoding.UTF8, "application/json"));
        string echoBody = await echo.Content.ReadAsStringAsync();
        int expected = Encoding.UTF8.GetByteCount(payload);
        Check("request body containing a header line arrives byte-exact",
              echoBody.Contains($"\"len\":{expected}") && echoBody.Contains("\"marker\":true"),
              $"expected len={expected}, got {echoBody}");

        var bulk = await client.GetAsync($"{baseUrl}/bulk");
        string bulkBody = await bulk.Content.ReadAsStringAsync();
        int lines = bulkBody.Split('\n', StringSplitOptions.RemoveEmptyEntries).Length;
        Check("chunked body of 4000 lines arrives intact", lines == 4000,
              $"{lines} lines, {bulkBody.Length} bytes");

        // 3 ------------------------------------------- unprotected host
        Section("3. Unprotected traffic is untouched");
        var openJar = new CookieContainer();
        using var openClient = MakeClient(proxyUrl, openService.RootCertificate, openJar);
        var openLogin = await openClient.PostAsync(
            $"https://{OpenHost}:{openService.Port}/login",
            new StringContent("{}", Encoding.UTF8, "application/json"));
        var openCookies = openJar.GetCookies(
            new Uri($"https://{OpenHost}:{openService.Port}")).Cast<Cookie>().ToList();
        Check("tunnelled host still works", openLogin.StatusCode == HttpStatusCode.OK,
              $"HTTP {(int)openLogin.StatusCode}");
        Check("its cookies reach the client normally",
              openCookies.Any(c => c.Name == "sessionid"),
              $"jar=[{string.Join(",", openCookies.Select(c => c.Name))}]");
        Check("nothing from it entered the vault", vault.Count(OpenHost) == 0);

        // 4 ---------------------------------------------- lease closed
        Section("4. No presence lease = no authority");
        lease.Close();
        var denied = await client.GetAsync($"{baseUrl}/me");
        Check("request without a lease is refused by the service",
              denied.StatusCode == HttpStatusCode.Unauthorized,
              $"HTTP {(int)denied.StatusCode}");
        Check("the connection itself still works (network not broken)",
              denied.Headers is not null);

        // 5 ------------------------------------------ process lineage
        Section("5. Process lineage");
        authorizer.TryOpenLease(Environment.ProcessId, TimeSpan.FromMinutes(5), out _);

        string caPem = Path.Combine(Path.GetTempPath(), "sessionguard-e2e-root.pem");
        File.WriteAllText(caPem, ExportPem(ca.Root));

        // A real browser opens its sockets from a child process (Chromium's
        // network service), so a direct descendant of the pinned process must
        // be authorized or the guard denies the browser it was unlocked for.
        var (childStatus, childOut) = await RunChildAsync(
            proxy.ListenPort, $"{baseUrl}/me", caPem, detached: false);
        Check("descendant of the pinned process is authorized",
              childStatus == 200, $"HTTP {childStatus} {childOut}");

        // The same binary, reparented away from us, is not in the family.
        var (rogueStatus, rogueOut) = await RunChildAsync(
            proxy.ListenPort, $"{baseUrl}/me", caPem, detached: true);
        Check("unrelated process gets no session even with the lease open",
              rogueStatus == 401, $"HTTP {rogueStatus} {rogueOut}");

        var stillMine = await client.GetAsync($"{baseUrl}/me");
        Check("the pinned process is unaffected",
              stillMine.StatusCode == HttpStatusCode.OK,
              $"HTTP {(int)stillMine.StatusCode}");

        // 5b ------------------------------------------- path scoping
        Section("5b. Cookie Path scoping");
        await client.GetAsync($"{baseUrl}/adminsetup");
        var atRoot = await client.GetAsync($"{baseUrl}/cookies");
        var atAdmin = await client.GetAsync($"{baseUrl}/admin/cookies");
        string rootNames = await atRoot.Content.ReadAsStringAsync();
        string adminNames = await atAdmin.Content.ReadAsStringAsync();
        Check("a cookie scoped to /admin is not sent to /cookies",
              !rootNames.Contains("adm"), rootNames);
        Check("it is sent to /admin/cookies", adminNames.Contains("adm"), adminNames);

        // 5c --------------------------------------- server-side revocation
        Section("5c. Sign-out actually signs out");
        int before = vault.Count(ProtectedHost);
        await client.PostAsync($"{baseUrl}/logout", new StringContent(""));
        Check("Max-Age=0 removes the cookie from the vault",
              !vault.Names(ProtectedHost).Contains("sessionid"),
              $"before={before} now=[{string.Join(",", vault.Names(ProtectedHost))}]");
        var afterLogout = await client.GetAsync($"{baseUrl}/me");
        Check("the session is really gone",
              afterLogout.StatusCode == HttpStatusCode.Unauthorized,
              $"HTTP {(int)afterLogout.StatusCode}");

        // 5d ------------------------------------- wildcard hosts + Domain
        Section("5d. Wildcard hosts and cookie Domain");

        var wildJar = new CookieContainer();
        using var wildClient = MakeClient(proxyUrl, ca.Root, wildJar);
        string loginUrl = $"https://{WildLogin}:{wildService.Port}";
        string apiUrl = $"https://{WildApi}:{wildService.Port}";

        var dl = await wildClient.PostAsync($"{loginUrl}/domainlogin", new StringContent(""));
        Check("*.sg.test intercepts a subdomain it never listed explicitly",
              dl.StatusCode == HttpStatusCode.OK, $"HTTP {(int)dl.StatusCode}");
        Check("both cookies captured from the login subdomain",
              vault.Count(WildLogin) == 2,
              $"scopes=[{string.Join(",", vault.Scopes)}]");

        var atOther = await wildClient.GetAsync($"{apiUrl}/cookies");
        string otherNames = await atOther.Content.ReadAsStringAsync();
        Check("Domain=.sg.test cookie follows to another subdomain",
              otherNames.Contains("sid"), otherNames);
        Check("host-only cookie does not follow",
              !otherNames.Contains("local"), otherNames);

        int beforeBad = vault.Count(WildLogin);
        var bad = await wildClient.GetAsync($"{loginUrl}/badscope");
        Check("a cookie scoped to an unrelated domain is refused",
              vault.Count(WildLogin) == beforeBad,
              $"names=[{string.Join(",", vault.Names(WildLogin))}]");
        // The client's own jar drops it too — an out-of-scope Domain is invalid
        // for any correct cookie implementation. What must be true is that the
        // guard passed the header on instead of swallowing it, so the decision
        // stays with the browser. That is visible in the response headers.
        bool headerSurvived = bad.Headers.TryGetValues("Set-Cookie", out var sc) &&
                              sc.Any(v => v.Contains("evil="));
        Check("but the header still reaches the browser, not swallowed by the guard",
              headerSurvived,
              bad.Headers.TryGetValues("Set-Cookie", out var sc2)
                  ? string.Join(" | ", sc2) : "(no Set-Cookie header)");

        // 6 ------------------------------------------------ sealed at rest
        Section("6. Vault contents are sealed");
        byte[] probe = Encoding.ASCII.GetBytes("SUPER-SECRET-SESSION-VALUE");
        var blob = sealer.Seal(probe);
        Check("sealed blob does not contain the plaintext",
              IndexOf(blob, probe) < 0, $"blob={blob.Length} bytes");
        var round = new byte[sealer.MaxPlaintextLength(blob)];
        int n2 = sealer.Unseal(blob, round);
        Check("sealed blob round-trips", round.AsSpan(0, n2).SequenceEqual(probe));

        // ---------------------------------------------------------- report
        int passed = Results.Count(r => r.ok);
        Console.WriteLine();
        Console.WriteLine(new string('=', 74));
        Console.WriteLine($"  {passed}/{Results.Count} checks passed");
        Console.WriteLine(new string('=', 74));
        foreach (var r in Results.Where(r => !r.ok))
            Console.WriteLine($"  FAILED: {r.name} — {r.detail}");
        return passed == Results.Count ? 0 : 1;
    }

    /// <summary>
    /// Direct checks on the pieces that quietly broke in earlier drafts:
    /// "Cookie" matching inside "Set-Cookie", and Set-Cookie attributes being
    /// stored as if they were part of the credential.
    /// </summary>
    private static void RunUnitChecks()
    {
        var head = new HeaderBlock(
            "GET / HTTP/1.1\r\nHost: x\r\nSet-Cookie: a=1\r\nCookie: b=2\r\nAccept: */*"u8);

        Check("Cookie lookup does not match Set-Cookie",
              head.TryGetValue("Cookie"u8, out int cs, out int cl) &&
              Encoding.ASCII.GetString(head.Span.Slice(cs, cl)) == "b=2",
              Encoding.ASCII.GetString(head.Span.Slice(cs, cl)));

        head.RemoveAll("Cookie"u8);
        string after = Encoding.ASCII.GetString(head.Span);
        Check("removing Cookie leaves Set-Cookie intact",
              after.Contains("Set-Cookie: a=1") && !after.Contains("Cookie: b=2"),
              after.Replace("\r\n", " | "));
        Check("removing the middle header keeps the rest well formed",
              after.Contains("Host: x") && after.Contains("Accept: */*"));

        head.Append("Cookie"u8, "z=9"u8);
        Check("appended header is found back",
              head.TryGetValue("Cookie"u8, out int zs, out int zl) &&
              Encoding.ASCII.GetString(head.Span.Slice(zs, zl)) == "z=9");
        head.Dispose();

        var setCookie = "sessionid=abc123; Path=/; HttpOnly; Secure; SameSite=Lax"u8;
        bool parsed = CookieBytes.TryParseSetCookie(setCookie, out Range nr, out Range vr);
        string pname = Encoding.ASCII.GetString(setCookie[nr]);
        string pvalue = Encoding.ASCII.GetString(setCookie[vr]);
        Check("Set-Cookie parses to name and value only, attributes dropped",
              parsed && pname == "sessionid" && pvalue == "abc123",
              $"{pname}={pvalue}");

        var names = new List<string>();
        CookieBytes.ForEachRequestCookie("a=1; b=2;c=3"u8, (n, v) =>
            names.Add($"{Encoding.ASCII.GetString(n)}={Encoding.ASCII.GetString(v)}"));
        Check("request cookie header splits into pairs",
              string.Join(",", names) == "a=1,b=2,c=3", string.Join(",", names));

        var set = new ProtectedHostSet(new[] { "*.tiktok.com", "exact.example" });
        Check("*.tiktok.com covers subdomains and the bare domain",
              set.Matches("www.tiktok.com") && set.Matches("webcast.tiktok.com") &&
              set.Matches("tiktok.com") && set.Matches("a.b.tiktok.com"));
        Check("and does not over-match",
              !set.Matches("nottiktok.com") && !set.Matches("tiktok.com.evil.net") &&
              !set.Matches("example"));
        Check("exact entries still work",
              set.Matches("exact.example") && !set.Matches("x.exact.example"));

        Check("a host may scope a cookie to its own parent domain",
              DomainRules.MayScopeTo("www.tiktok.com", ".tiktok.com", out _));
        Check("a host may not scope a cookie to someone else's domain",
              !DomainRules.MayScopeTo("www.tiktok.com", "example.com", out _));
        Check("and not to a bare top-level label",
              !DomainRules.MayScopeTo("www.tiktok.com", "com", out _));
    }

    // ------------------------------------------------------------- helpers

    private static HttpClient MakeClient(string proxyUrl, X509Certificate2 trustRoot,
                                         CookieContainer jar)
    {
        var handler = new HttpClientHandler
        {
            Proxy = new WebProxy(proxyUrl) { BypassProxyOnLocal = false },
            UseProxy = true,
            UseCookies = true,
            CookieContainer = jar,
            ServerCertificateCustomValidationCallback = (_, cert, _, _) =>
            {
                if (cert is null) return false;
                var chain = new X509Chain();
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.Add(trustRoot);
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                return chain.Build(new X509Certificate2(cert));
            },
        };
        return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
    }

    /// <summary>
    /// Runs the request in another process. detached:false leaves it a direct
    /// child of this process (what a browser's network-service child looks
    /// like); detached:true reparents it away via a shell that exits, so it is
    /// genuinely outside our process family.
    /// </summary>
    private static async Task<(int status, string output)> RunChildAsync(
        int proxyPort, string url, string caPem, bool detached)
    {
        string exe = Environment.ProcessPath!;
        var argv = new List<string>();
        if (Path.GetFileNameWithoutExtension(exe) is "dotnet")
            argv.Add(System.Reflection.Assembly.GetEntryAssembly()!.Location);
        argv.AddRange(new[] { "--rogue", proxyPort.ToString(), url, caPem });

        if (!detached)
        {
            var psi = new ProcessStartInfo
            {
                FileName = exe,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            foreach (var a in argv) psi.ArgumentList.Add(a);
            using var p = Process.Start(psi)!;
            string so = await p.StandardOutput.ReadToEndAsync();
            string se = await p.StandardError.ReadToEndAsync();
            await p.WaitForExitAsync();
            return Parse(so, se);
        }

        string outFile = Path.Combine(Path.GetTempPath(),
            $"sessionguard-detached-{Guid.NewGuid():N}.txt");
        string quoted = string.Join(" ", argv.Select(a => $"'{a}'"));
        var shell = new ProcessStartInfo("/bin/sh")
        {
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        shell.ArgumentList.Add("-c");
        // The shell exits immediately, so the worker is reparented to init and
        // is no longer a descendant of this test process.
        shell.ArgumentList.Add($"nohup '{exe}' {quoted} > '{outFile}' 2>&1 &");
        using (var sh = Process.Start(shell)!)
            await sh.WaitForExitAsync();

        for (int i = 0; i < 120; i++)
        {
            await Task.Delay(250);
            if (!File.Exists(outFile)) continue;
            string text;
            try { text = File.ReadAllText(outFile); } catch { continue; }
            if (text.Trim().Length > 0) return Parse(text, "");
        }
        return (-1, "detached child produced no output");
    }

    private static (int, string) Parse(string stdout, string stderr)
    {
        string line = stdout.Trim().Split('\n').LastOrDefault()?.Trim() ?? "";
        if (int.TryParse(line.Split(' ').FirstOrDefault(), out int status))
            return (status, line);
        return (-1, $"stdout='{stdout.Trim()}' stderr='{stderr.Trim()}'");
    }

    private static async Task<int> RogueAsync(string[] args)
    {
        // Stands in for an infostealer: same machine, same user, its own pid.
        int proxyPort = int.Parse(args[1]);
        string url = args[2];
        var root = new X509Certificate2(PemToDer(File.ReadAllText(args[3])));
        using var client = MakeClient($"http://127.0.0.1:{proxyPort}", root,
                                      new CookieContainer());
        try
        {
            var r = await client.GetAsync(url);
            Console.WriteLine($"{(int)r.StatusCode} {(await r.Content.ReadAsStringAsync()).Trim()}");
            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"-1 {ex.GetType().Name}: {ex.Message}");
            return 1;
        }
    }

    private static string ExportPem(X509Certificate2 cert) =>
        "-----BEGIN CERTIFICATE-----\n" +
        Convert.ToBase64String(cert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks) +
        "\n-----END CERTIFICATE-----\n";

    private static byte[] PemToDer(string pem)
    {
        var body = pem.Replace("-----BEGIN CERTIFICATE-----", "")
                      .Replace("-----END CERTIFICATE-----", "")
                      .Replace("\r", "").Replace("\n", "").Trim();
        return Convert.FromBase64String(body);
    }

    private static int IndexOf(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle) =>
        haystack.IndexOf(needle);

    private static void EnsureHostsEntries()
    {
        const string path = "/etc/hosts";
        if (!File.Exists(path)) return;
        string text = File.ReadAllText(path);
        var missing = new[] { ProtectedHost, OpenHost, WildLogin, WildApi }
            .Where(h => !text.Contains(h)).ToArray();
        if (missing.Length == 0) return;
        try
        {
            File.AppendAllText(path,
                "\n" + string.Join("\n", missing.Select(h => $"127.0.0.1 {h}")) + "\n");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  (could not add hosts entries: {ex.Message})");
        }
    }

    private static void Section(string title)
    {
        Console.WriteLine();
        Console.WriteLine($"--- {title} " + new string('-', Math.Max(4, 66 - title.Length)));
    }

    private static void Check(string name, bool ok, string detail = "")
    {
        Results.Add((name, ok, detail));
        Console.WriteLine($"  {(ok ? "PASS" : "FAIL")}  {name}" +
                          (detail.Length > 0 ? $"  — {detail}" : ""));
    }
}
