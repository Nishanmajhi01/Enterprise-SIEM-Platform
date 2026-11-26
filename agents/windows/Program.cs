using System.Diagnostics.Eventing.Reader;
using System.Net.Http.Json;
using System.Text.Json;
using System.Security.Cryptography;
using System.Text;

var directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "NexusSIEM-Agent");
using var config = JsonDocument.Parse(File.ReadAllText(Path.Combine(directory, "config.json")));
var endpoint = config.RootElement.GetProperty("url").GetString();
var allowLabHttp = config.RootElement.GetProperty("allowLabHttp").GetBoolean();
var bytes = ProtectedData.Unprotect(File.ReadAllBytes(Path.Combine(directory, "key.bin")), null, DataProtectionScope.LocalMachine);
var key = Encoding.UTF8.GetString(bytes);
CryptographicOperations.ZeroMemory(bytes);
if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var uri) ||
    (uri.Scheme != "https" && !(uri.Scheme == "http" &&
      allowLabHttp)) ||
    string.IsNullOrWhiteSpace(key))
{
    Console.Error.WriteLine("Invalid agent configuration. HTTPS required unless explicitly enabled for a trusted lab.");
    return;
}
using var client = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(20) };
client.DefaultRequestHeaders.Add("x-api-key", key);
Directory.CreateDirectory(directory);
var channels = new[] { "Security", "System", "Application", "Microsoft-Windows-Windows Defender/Operational" };
using var cancellation = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cancellation.Cancel(); };
var heartbeatUri = new Uri(uri.AbsoluteUri.TrimEnd('/') + "/heartbeat");
var nextHeartbeat = DateTimeOffset.MinValue;
while (!cancellation.IsCancellationRequested)
{
    if (DateTimeOffset.UtcNow >= nextHeartbeat)
    {
        try
        {
            using var heartbeat = await client.PostAsJsonAsync(heartbeatUri, new { hostname = Environment.MachineName }, cancellation.Token);
            heartbeat.EnsureSuccessStatusCode();
            File.WriteAllText(Path.Combine(directory, "last-heartbeat.txt"), DateTimeOffset.UtcNow.ToString("o"));
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { break; }
        catch (Exception ex) { Console.Error.WriteLine($"Heartbeat: {ex.GetType().Name}"); }
        nextHeartbeat = DateTimeOffset.UtcNow.AddSeconds(60);
    }
    foreach (var channel in channels)
    {
        if (cancellation.IsCancellationRequested) break;
        try
        {
            var path = Path.Combine(directory, channel.Replace('/', '_') + ".checkpoint");
            long cursor;
            if (!File.Exists(path))
            {
                using var latest = new EventLogReader(new EventLogQuery(channel, PathType.LogName) { ReverseDirection = true });
                using var record = latest.ReadEvent();
                cursor = record?.RecordId ?? 0;
                File.WriteAllText(path, cursor.ToString());
            }
            else cursor = long.Parse(File.ReadAllText(path));
            var query = new EventLogQuery(channel, PathType.LogName, $"*[System[EventRecordID > {cursor}]]");
            using var reader = new EventLogReader(query);
            for (int i = 0; i < 100 && !cancellation.IsCancellationRequested; i++)
            {
                using var record = reader.ReadEvent();
                if (record == null) break;
                if (record.RecordId is not long id) continue;
                string? message;
                try { message = record.FormatDescription(); }
                catch (EventLogException) { message = null; }
                var payload = new {
                    eventType = channel == "Security" ? "WINDOWS_SECURITY" : "WINDOWS_EVENT",
                    hostname = Environment.MachineName,
                    channel, eventId = record.Id, recordId = id,
                    provider = record.ProviderName,
                    eventTime = record.TimeCreated?.ToUniversalTime(),
                    message = message ?? $"Windows event {record.Id}",
                    severity = record.Level is 1 or 2 ? "MEDIUM" : "LOW"
                };
                using var response = await client.PostAsJsonAsync(uri, payload, cancellation.Token);
                response.EnsureSuccessStatusCode();
                File.WriteAllText(path + ".tmp", id.ToString());
                File.Move(path + ".tmp", path, true);
                File.WriteAllText(Path.Combine(directory, "last-success.txt"), DateTimeOffset.UtcNow.ToString("o"));
            }
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { break; }
        catch (Exception ex) { Console.Error.WriteLine($"{channel}: {ex.GetType().Name}; will retry."); }
    }
    try { await Task.Delay(TimeSpan.FromSeconds(10), cancellation.Token); }
    catch (OperationCanceledException) { break; }
}
