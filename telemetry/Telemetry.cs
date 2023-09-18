using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using BBRAPIModules;

namespace DevMinersBBModules;

/// Uploads the configured module list to a <see cref="https://github.com/TheDevMinerTV/bb-telemetry-api/pkgs/container/bb-telemetry-api">telemetry server</see>.
/// 
/// Developer contact:
///   Email: devminer@devminer.xyz
///   Discord: @anna_devminer
public class Telemetry : BattleBitModule
{
    public static Configuration Configuration { get; set; } = null!;
    private readonly FieldInfo _modulesField;
    private Client? _client;

    public Telemetry()
    {
        var modulesField =
            typeof(RunnerServer).GetField("modules", BindingFlags.NonPublic | BindingFlags.Instance);
        if (modulesField == null)
            throw new Exception("Could not find modules field on RunnerServer");

        _modulesField = modulesField;
    }

    public override async Task OnConnected()
    {
        if (Configuration == null) throw new Exception("Configuration isn't loaded yet");

        var modules = GetModules();
        if (modules == null) throw new Exception("Could not get modules");

        var moduleInfos = (from module in modules
            let moduleName = module.GetType().ToString()
            let version = module.GetType().Assembly.GetName().Version!.ToString()
            select new ModuleInfo(moduleName, version)).ToList();

        var uri = new Uri(Configuration.TelemetryEndpoint);
        _client = new Client(uri, moduleInfos);
        await _client.Start();
    }

    public override Task OnDisconnected()
    {
        _client?.Stop();

        return Task.CompletedTask;
    }

    private List<BattleBitModule> GetModules() => (List<BattleBitModule>)_modulesField.GetValue(Server)!;
}

public class Configuration : ModuleConfiguration
{
    // "Official" server, operated by @anna_devminer
    public string TelemetryEndpoint = "tcp://raw.devminer.xyz:65500";
}

class Client
{
    private readonly TcpClient _socket = new();
    private readonly Uri _uri;
    private readonly List<ModuleInfo> _modules;
    private readonly CancellationTokenSource _connectionCancellation = new();

    public Client(Uri uri, List<ModuleInfo> modules)
    {
        _uri = uri;
        _modules = modules;
    }

    public async Task Start()
    {
        await _socket.ConnectAsync(_uri.Host, _uri.Port);

        await SendPacket(new HandshakeRequestPacket(_modules));

        Task.Run(ReadLoop, _connectionCancellation.Token);
    }

    public void Stop()
    {
        _connectionCancellation.Cancel();
    }

    private async Task SendPacket(IPacket packet)
    {
        var s = _socket.GetStream();
        var p = new WrappedPacket(packet);
        await s.WriteAsync(p.Encode(), _connectionCancellation.Token);
    }

    private async Task ReadLoop()
    {
        var s = _socket.GetStream();
        var buffer = new byte[4096];

        while (true)
        {
            if (_connectionCancellation.IsCancellationRequested) return;

            var n = await s.ReadAsync(buffer, 0, buffer.Length, _connectionCancellation.Token);
            if (n <= 0)
            {
                _connectionCancellation.Cancel();
                return;
            }

            if (n < WrappedPacket.DataLengthSize) continue;

            var rawPacket = new byte[n];
            Array.Copy(buffer, rawPacket, n);

            var dataLength = BinaryPrimitives.ReadUInt16BigEndian(rawPacket);
            if (dataLength > WrappedPacket.DataLengthSize + WrappedPacket.PacketTypeLength + n) continue;

            var packetType = (PacketType)buffer[WrappedPacket.DataLengthSize];
            var data = new byte[n - WrappedPacket.DataLengthSize];
            Array.Copy(buffer, WrappedPacket.DataLengthSize, data, 0, data.Length);

            switch (packetType)
            {
                case PacketType.HandshakeResponsePacket:
                {
                    var response = HandshakeResponsePacket.Decode(data);

                    using var h = new HMACSHA256(response.Key);
                    var hash = h.ComputeHash(Encoding.UTF8.GetBytes(string.Join("", _modules)));

                    await SendPacket(new StartRequestPacket(hash));

                    break;
                }

                case PacketType.StartResponsePacket:
                {
                    Console.WriteLine("Telemetry client connected");

                    Task.Run(PingLoop, _connectionCancellation.Token);

                    break;
                }

                case PacketType.HandshakeRequestPacket:
                case PacketType.StartRequestPacket:
                case PacketType.HeartbeatRequestPacket:
                    // if this happens, then the server fucked up LOL
                    break;

                default:
                {
                    Console.WriteLine($"Unknown packet type: {packetType}");

                    break;
                }
            }
        }
    }

    private async Task PingLoop()
    {
        while (true)
        {
            if (_connectionCancellation.IsCancellationRequested) return;

            await SendPacket(new HeartbeatRequestPacket());

            await Task.Delay(30 * 1000);
        }
    }
}

internal readonly struct ModuleInfo
{
    private readonly string _name;
    private readonly string _version;

    public ModuleInfo(string name, string version)
    {
        _name = name;
        _version = version;
    }

    public override string ToString() => $"{_name} {_version}";

    public int GetEncodedLength() =>
        NetworkUtils.EncodedStringLength(_name) + NetworkUtils.EncodedStringLength(_version);

    public byte[] Encode()
    {
        var buf = new byte[GetEncodedLength()];

        var buf2 = NetworkUtils.EncodeString(_name);
        buf2.CopyTo(buf, 0);
        NetworkUtils.EncodeString(_version).CopyTo(buf, buf2.Length);

        return buf;
    }
}

internal static class NetworkUtils
{
    public static int EncodedStringLength(string s) => 2 + Encoding.UTF8.GetByteCount(s);

    public static byte[] EncodeString(string s)
    {
        var len = Encoding.UTF8.GetByteCount(s);
        var buf = new byte[2 + len];

        BinaryPrimitives.WriteUInt16BigEndian(buf, (ushort)len);
        Encoding.UTF8.GetBytes(s).CopyTo(buf, 2);

        return buf;
    }
}

internal enum PacketType : byte
{
    HandshakeRequestPacket = 1,
    HandshakeResponsePacket = 2,
    StartRequestPacket = 3,
    StartResponsePacket = 4,
    HeartbeatRequestPacket = 5
}

internal interface IPacket
{
    public PacketType Type();
    public byte[] Encode();
}

internal class WrappedPacket
{
    public const int DataLengthSize = 2;
    public const int PacketTypeLength = 1;

    private IPacket Inner { get; }

    public WrappedPacket(IPacket inner) => Inner = inner;

    public byte[] Encode()
    {
        var inner = Inner.Encode();

        var dataLength = inner.Length;
        var length = DataLengthSize + PacketTypeLength + dataLength;

        var buf = new byte[length];

        BinaryPrimitives.WriteUInt16BigEndian(buf, (ushort)dataLength);
        buf[DataLengthSize] = (byte)Inner.Type();
        inner.CopyTo(buf, DataLengthSize + PacketTypeLength);

        return buf;
    }
}

internal class HandshakeRequestPacket : IPacket
{
    private List<ModuleInfo> Modules { get; }

    public HandshakeRequestPacket(List<ModuleInfo> modules) => Modules = modules;
    public PacketType Type() => PacketType.HandshakeRequestPacket;

    public byte[] Encode()
    {
        var moduleCount = Modules.Count;
        var length = 2 + Modules.Sum(module => module.GetEncodedLength());

        var offset = 0;

        var buf = new byte[length];
        BinaryPrimitives.WriteUInt16BigEndian(buf, (ushort)moduleCount);
        offset += 2;

        foreach (var module in Modules)
        {
            var encoded = module.Encode();
            encoded.CopyTo(buf, offset);
            offset += encoded.Length;
        }

        return buf;
    }
}

internal class HandshakeResponsePacket
{
    public byte[] Key { get; }

    private HandshakeResponsePacket(byte[] key) => Key = key;

    public static HandshakeResponsePacket Decode(byte[] buf)
    {
        var key = new byte[32];
        Array.Copy(buf, 1, key, 0, buf.Length - 1);

        return new HandshakeResponsePacket(key);
    }
}

internal class StartRequestPacket : IPacket
{
    private readonly byte[] _hmac;
    public StartRequestPacket(byte[] hmac) => _hmac = hmac;
    public PacketType Type() => PacketType.StartRequestPacket;
    public byte[] Encode() => _hmac;
}

internal class HeartbeatRequestPacket : IPacket
{
    public PacketType Type() => PacketType.HeartbeatRequestPacket;
    public byte[] Encode() => Array.Empty<byte>();
}