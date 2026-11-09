<#
.SYNOPSIS
Exercise restoration frame handling for host parity qualification.
.DESCRIPTION
The fixture encodes fixed control frames, reads opaque DATA bodies, and checks canonical JSON
spelling in memory. Live capture owns identity, clock and phase checks.
#>

if (-not ('Atlaso.RestorationControlFrames' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Buffers.Binary;
using System.Text.Json;

namespace Atlaso
{
    public static class RestorationControlFrames
    {
        private const int HeaderSize = 10;
        private const int MaxDataSize = 393216;
        private const int MaxDataDepth = 3;
        private const long MaxUtcMilliseconds = 253402300799999;

        public static void RequireCanonicalData(byte[] data)
        {
            if (data != null && data.Length >= 2 && data.Length <= MaxDataSize && HasCompactAscii(data))
            {
                try
                {
                    if (IsCanonicalObject(data))
                        return;
                }
                catch (JsonException)
                {
                    // Parser diagnostics may include bytes from the candidate.
                }
            }
            throw new FormatException("Invalid canonical restoration DATA.");
        }

        private static bool HasCompactAscii(ReadOnlySpan<byte> data)
        {
            bool quoted = false;
            bool escaped = false;
            foreach (byte value in data)
            {
                if (value < 0x20 || value > 0x7e || (value == ' ' && !quoted))
                    return false;
                if (escaped)
                    escaped = false;
                else if (value == '"')
                    quoted = !quoted;
                else if (value == '\\' && quoted)
                    escaped = true;
            }
            return !quoted;
        }

        private static bool IsCanonicalObject(ReadOnlySpan<byte> data)
        {
            var reader = new Utf8JsonReader(data, new JsonReaderOptions { MaxDepth = MaxDataDepth });
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
                return false;

            // Each object has its own preceding property name in the original ASCII bytes.
            Span<int> nameOffsets = stackalloc int[MaxDataDepth + 1];
            Span<int> nameLengths = stackalloc int[MaxDataDepth + 1];
            nameLengths[1] = -1;
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.StartObject:
                        nameLengths[reader.CurrentDepth + 1] = -1;
                        break;
                    case JsonTokenType.PropertyName:
                        int depth = reader.CurrentDepth;
                        ReadOnlySpan<byte> name = reader.ValueSpan;
                        if (reader.ValueIsEscaped || (nameLengths[depth] >= 0 &&
                            data.Slice(nameOffsets[depth], nameLengths[depth]).SequenceCompareTo(name) >= 0))
                            return false;
                        nameOffsets[depth] = (int)reader.TokenStartIndex + 1;
                        nameLengths[depth] = name.Length;
                        break;
                    case JsonTokenType.Number:
                        if (!IsCanonicalInteger(reader.ValueSpan))
                            return false;
                        break;
                    case JsonTokenType.String:
                        if (reader.ValueIsEscaped && !HasCanonicalEscapes(reader.ValueSpan))
                            return false;
                        break;
                }
            }
            return reader.TokenType == JsonTokenType.EndObject && reader.BytesConsumed == data.Length;
        }

        private static bool IsCanonicalInteger(ReadOnlySpan<byte> number)
        {
            if (number[0] == '-')
            {
                number = number.Slice(1);
                if (number[0] == '0')
                    return false;
            }
            // The JSON reader has already rejected malformed numbers and leading zeros.
            foreach (byte digit in number)
            {
                if (digit < '0' || digit > '9')
                    return false;
            }
            return true;
        }

        private static bool HasCanonicalEscapes(ReadOnlySpan<byte> value)
        {
            // The JSON reader has already checked escape syntax and lengths.
            for (int index = 0; index < value.Length; index++)
            {
                if (value[index] != '\\')
                    continue;
                switch (value[++index])
                {
                    case (byte)'"':
                    case (byte)'\\':
                    case (byte)'b':
                    case (byte)'f':
                    case (byte)'n':
                    case (byte)'r':
                    case (byte)'t':
                        break;
                    case (byte)'u':
                        int codeUnit = 0;
                        for (int digit = 0; digit < 4; digit++)
                        {
                            byte hex = value[++index];
                            if (hex >= '0' && hex <= '9')
                                codeUnit = (codeUnit << 4) + hex - '0';
                            else if (hex >= 'a' && hex <= 'f')
                                codeUnit = (codeUnit << 4) + hex - 'a' + 10;
                            else
                                return false;
                        }
                        // Python uses the short escapes above for these controls.
                        if ((codeUnit >= 0x20 && codeUnit < 0x7f) ||
                            codeUnit == 8 || codeUnit == 9 || codeUnit == 10 || codeUnit == 12 || codeUnit == 13)
                            return false;
                        break;
                    default:
                        return false;
                }
            }
            return true;
        }

        public static byte[] ReadData(byte expectedKind, Func<int, byte[]> read, Action requireBudget)
        {
            if (expectedKind != 2 && expectedKind != 4)
                throw new ArgumentException("Expected CHECKPOINT or COMPLETE.");
            ArgumentNullException.ThrowIfNull(read);
            ArgumentNullException.ThrowIfNull(requireBudget);

            byte[] header = ReadExact(HeaderSize, read, requireBudget);
            if (!header.AsSpan(0, 4).SequenceEqual("ARCP"u8) || header[4] != 1 || header[5] != expectedKind)
                throw new FormatException("Invalid restoration DATA header.");

            uint bodySize = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(6, 4));
            if (bodySize < 2 || bodySize > MaxDataSize)
                throw new FormatException("Invalid restoration DATA length.");

            return ReadExact((int)bodySize, read, requireBudget);
        }

        private static byte[] ReadExact(int length, Func<int, byte[]> read, Action requireBudget)
        {
            byte[] bytes = new byte[length];
            int offset = 0;
            while (offset < length)
            {
                int remaining = length - offset;
                requireBudget();
                byte[] prefix = read(remaining);
                requireBudget();
                if (prefix == null || prefix.Length == 0 || prefix.Length > remaining)
                    throw new System.IO.IOException("Invalid restoration DATA read progress.");
                prefix.AsSpan().CopyTo(bytes.AsSpan(offset));
                offset += prefix.Length;
            }
            return bytes;
        }

        private static byte[] CreateFrame(byte kind, int bodySize)
        {
            byte[] frame = new byte[HeaderSize + bodySize];
            frame[0] = (byte)'A';
            frame[1] = (byte)'R';
            frame[2] = (byte)'C';
            frame[3] = (byte)'P';
            frame[4] = 1;
            frame[5] = kind;
            BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(6, 4), (uint)bodySize);
            return frame;
        }

        private static void CopyField(byte[] field, byte[] frame, int offset, int width)
        {
            if (field == null || field.Length != width)
                throw new ArgumentException("Restoration control field has the wrong width.");
            field.AsSpan().CopyTo(frame.AsSpan(HeaderSize + offset, width));
        }

        public static byte[] EncodeGo(byte[] run, byte[] nonce, byte[] captureIntent, byte[] launchIntent,
            byte[] processReceipt, byte[] boot, long deadlineCounter, long frequency, long deadlineUtcMs,
            long sampleCounter, long sampleUtcMs)
        {
            if (deadlineCounter < 0 || sampleCounter < 0 || frequency <= 0 ||
                deadlineUtcMs < 0 || deadlineUtcMs > MaxUtcMilliseconds ||
                sampleUtcMs < 0 || sampleUtcMs > MaxUtcMilliseconds)
                throw new ArgumentException("Restoration control clock field is out of range.");

            byte[] frame = CreateFrame(1, 200);
            CopyField(run, frame, 0, 16);
            CopyField(nonce, frame, 16, 16);
            CopyField(captureIntent, frame, 32, 32);
            CopyField(launchIntent, frame, 64, 32);
            CopyField(processReceipt, frame, 96, 32);
            CopyField(boot, frame, 128, 32);
            BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(HeaderSize + 160, 8), (ulong)deadlineCounter);
            BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(HeaderSize + 168, 8), (ulong)frequency);
            BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(HeaderSize + 176, 8), (ulong)deadlineUtcMs);
            BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(HeaderSize + 184, 8), (ulong)sampleCounter);
            BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(HeaderSize + 192, 8), (ulong)sampleUtcMs);
            return frame;
        }

        public static byte[] EncodeAck(byte[] run, byte[] nonce, byte[] captureIntent,
            byte[] baselineDigest, byte[] checkpointReceipt)
        {
            byte[] frame = CreateFrame(3, 128);
            CopyField(run, frame, 0, 16);
            CopyField(nonce, frame, 16, 16);
            CopyField(captureIntent, frame, 32, 32);
            CopyField(baselineDigest, frame, 64, 32);
            CopyField(checkpointReceipt, frame, 96, 32);
            return frame;
        }
    }
}
'@
}
