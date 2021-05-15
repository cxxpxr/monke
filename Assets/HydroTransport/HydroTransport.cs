using Mirror;
using System;
using UnityEngine;
using System.Collections.Generic;
using Sodium;

public enum OpCodes : byte
{
    ServerPublicKey = 0,
    ClientPublicKey = 1,
    Data = 2,

}

public class HydroTransport : Transport
{

    [Header("Connection Variables")]
    public Transport CommunicationTransport;

    private KeyPair _keyPair = default(KeyPair);
    private Dictionary<int, byte[]> _serverSessions;
    private byte[] _serverPublicKey;

    private byte[] _clientSendBuffer;

    private void Start()
    {
        _clientSendBuffer = new byte[CommunicationTransport.GetMaxPacketSize()];
        SetupCallbacks();
    }

    private void SetupCallbacks()
    {
        CommunicationTransport.OnServerConnected = OnServerConnect;
        CommunicationTransport.OnServerDisconnected = OnServerDisconnect;
        CommunicationTransport.OnServerDataReceived = OnServerDataReceive;
        CommunicationTransport.OnServerError = (i, e) => OnServerError?.Invoke(i, e);

        CommunicationTransport.OnClientDataReceived = OnClientDataReceive;
        CommunicationTransport.OnClientDisconnected = () => OnClientDisconnected?.Invoke();
        CommunicationTransport.OnClientError = (e) => OnClientError?.Invoke(e);
    }

    void GenerateInitialKeyPair()
    {
        _keyPair = PublicKeyBox.GenerateKeyPair();
    }

    private void OnServerConnect(int conn)
    {
        int pos = 0;
        _clientSendBuffer.WriteByte(ref pos, (byte)OpCodes.ServerPublicKey);
        _clientSendBuffer.WriteBytes(ref pos, _keyPair.PublicKey);
        CommunicationTransport.ServerSend(conn, 0, new ArraySegment<byte>(_clientSendBuffer, 0, pos));
    }

    void OnServerDataReceive(int conn, ArraySegment<byte> data, int channel)
    {
        try
        {
            var rawData = data.Array;
            int pos = data.Offset;

            OpCodes opcode = (OpCodes)rawData.ReadByte(ref pos);

            switch (opcode)
            {
                case OpCodes.ClientPublicKey:
                    byte[] clientPublicKey = rawData.ReadBytes(ref pos);

                    _serverSessions.Add(conn, clientPublicKey);

                    OnServerConnected?.Invoke(conn);
                    break;
                case OpCodes.Data:
                    byte[] mirrorData = rawData.ReadBytes(ref pos);
                    byte[] nonce = rawData.ReadBytes(ref pos);

                    if (_serverSessions.ContainsKey(conn))
                    {
                        byte[] outputData = PublicKeyBox.Open(mirrorData, nonce, _keyPair.PrivateKey, _serverSessions[conn]);

                        OnServerDataReceived?.Invoke(conn, new ArraySegment<byte>(outputData), channel);
                    }

                    break;
            }
        }
        catch (Exception e)
        {
            Debug.LogError("Error: " + e);
        }
    }

    void OnServerDisconnect(int conn)
    {
        if (_serverSessions.ContainsKey(conn))
            _serverSessions.Remove(conn);

        OnServerDisconnected?.Invoke(conn);
    }

    private void OnClientDataReceive(ArraySegment<byte> data, int channel)
    {
        try
        {
            var rawData = data.Array;
            int pos = data.Offset;

            OpCodes opcode = (OpCodes)rawData.ReadByte(ref pos);

            switch (opcode)
            {
                case OpCodes.ServerPublicKey:
                    _serverPublicKey = rawData.ReadBytes(ref pos);

                    pos = 0;
                    _clientSendBuffer.WriteByte(ref pos, (byte)OpCodes.ClientPublicKey);
                    _clientSendBuffer.WriteBytes(ref pos, _keyPair.PublicKey);
                    CommunicationTransport.ClientSend(Channels.Reliable, new ArraySegment<byte>(_clientSendBuffer, 0, pos));

                    OnClientConnected?.Invoke();

                    break;
                case OpCodes.Data:
                    byte[] mirrorData = rawData.ReadBytes(ref pos);
                    byte[] nonce = rawData.ReadBytes(ref pos);

                    byte[] outputData = PublicKeyBox.Open(mirrorData, nonce, _keyPair.PrivateKey, _serverPublicKey);
                    OnClientDataReceived?.Invoke(new ArraySegment<byte>(outputData), channel);

                    break;
            }
        }
        catch(Exception e)
        {
            Debug.LogError("Error: " + e);
        }
    }

    public override bool Available() => CommunicationTransport.Available();

    public override void ClientConnect(string address)
    {
        GenerateInitialKeyPair();
        CommunicationTransport.ClientConnect(address);
    }

    public override bool ClientConnected() => CommunicationTransport.ClientConnected();

    public override void ClientDisconnect()
    {
        CommunicationTransport.ClientDisconnect();
    }

    public override void ClientEarlyUpdate() => CommunicationTransport.ClientEarlyUpdate();

    public override void ClientLateUpdate() => CommunicationTransport.ClientLateUpdate();

    public override void ClientSend(int channelId, ArraySegment<byte> segment)
    {
        if (_serverPublicKey != null)
        {
            int pos = 0;
            _clientSendBuffer.WriteByte(ref pos, (byte)OpCodes.Data);
            byte[] realData = new byte[segment.Count];
            Buffer.BlockCopy(segment.Array, segment.Offset, realData, 0, segment.Count);
            byte[] nonce = PublicKeyBox.GenerateNonce();

            _clientSendBuffer.WriteBytes(ref pos, PublicKeyBox.Create(realData, nonce, _keyPair.PrivateKey, _serverPublicKey));
            _clientSendBuffer.WriteBytes(ref pos, nonce);
            CommunicationTransport.ClientSend(channelId, new ArraySegment<byte>(_clientSendBuffer, 0, pos));
        }
    }

    public override int GetMaxPacketSize(int channelId = 0) => CommunicationTransport.GetMaxPacketSize(channelId);

    public override bool ServerActive() => CommunicationTransport.ServerActive();

    public override bool ServerDisconnect(int connectionId) => CommunicationTransport.ServerDisconnect(connectionId);

    public override string ServerGetClientAddress(int connectionId) => CommunicationTransport.ServerGetClientAddress(connectionId);

    public override void ServerSend(int connectionId, int channelId, ArraySegment<byte> segment)
    {
        if (_serverSessions.ContainsKey(connectionId))
        {
            int pos = 0;
            _clientSendBuffer.WriteByte(ref pos, (byte)OpCodes.Data);
            byte[] realData = new byte[segment.Count];
            Buffer.BlockCopy(segment.Array, segment.Offset, realData, 0, segment.Count);
            byte[] nonce = PublicKeyBox.GenerateNonce();

            _clientSendBuffer.WriteBytes(ref pos, PublicKeyBox.Create(realData, nonce, _keyPair.PrivateKey, _serverSessions[connectionId]));
            _clientSendBuffer.WriteBytes(ref pos, nonce);
            CommunicationTransport.ServerSend(connectionId, channelId, new ArraySegment<byte>(_clientSendBuffer, 0, pos));
        }
    }

    public override void ServerEarlyUpdate() => CommunicationTransport.ServerEarlyUpdate();

    public override void ServerLateUpdate() => CommunicationTransport.ServerLateUpdate();

    public override void ServerStart()
    {
        GenerateInitialKeyPair();
        _serverSessions = new Dictionary<int, byte[]>();
        CommunicationTransport.ServerStart();
    }

    public override void ServerStop() => CommunicationTransport.ServerStop();

    public override Uri ServerUri() => CommunicationTransport.ServerUri();

    public override void Shutdown() => CommunicationTransport.Shutdown();
}

public static class HydroTools
{
    public static void WriteByte(this byte[] data, ref int position, byte value)
    {
        data[position] = value;
        position += 1;
    }

    public static byte ReadByte(this byte[] data, ref int position)
    {
        byte value = data[position];
        position += 1;
        return value;
    }

    public static void WriteBool(this byte[] data, ref int position, bool value)
    {
        unsafe
        {
            fixed (byte* dataPtr = &data[position])
            {
                bool* valuePtr = (bool*)dataPtr;
                *valuePtr = value;
                position += 1;
            }
        }
    }

    public static bool ReadBool(this byte[] data, ref int position)
    {
        bool value = BitConverter.ToBoolean(data, position);
        position += 1;
        return value;
    }

    public static void WriteString(this byte[] data, ref int position, string value)
    {
        data.WriteInt(ref position, value.Length);
        for (int i = 0; i < value.Length; i++)
            data.WriteChar(ref position, value[i]);
    }

    public static string ReadString(this byte[] data, ref int position)
    {
        string value = default;

        int stringSize = data.ReadInt(ref position);

        for (int i = 0; i < stringSize; i++)
            value += data.ReadChar(ref position);

        return value;
    }

    public static void WriteBytes(this byte[] data, ref int position, byte[] value)
    {
        data.WriteInt(ref position, value.Length);
        for (int i = 0; i < value.Length; i++)
            data.WriteByte(ref position, value[i]);
    }

    public static byte[] ReadBytes(this byte[] data, ref int position)
    {
        int byteSize = data.ReadInt(ref position);

        byte[] value = new byte[byteSize];

        for (int i = 0; i < byteSize; i++)
            value[i] = data.ReadByte(ref position);

        return value;
    }

    public static void WriteChar(this byte[] data, ref int position, char value)
    {
        unsafe
        {
            fixed (byte* dataPtr = &data[position])
            {
                char* valuePtr = (char*)dataPtr;
                *valuePtr = value;
                position += 2;
            }
        }
    }

    public static char ReadChar(this byte[] data, ref int position)
    {
        char value = BitConverter.ToChar(data, position);
        position += 2;
        return value;
    }

    public static void WriteInt(this byte[] data, ref int position, int value)
    {
        unsafe
        {
            fixed (byte* dataPtr = &data[position])
            {
                int* valuePtr = (int*)dataPtr;
                *valuePtr = value;
                position += 4;
            }
        }
    }

    public static int ReadInt(this byte[] data, ref int position)
    {
        int value = BitConverter.ToInt32(data, position);
        position += 4;
        return value;
    }
}

