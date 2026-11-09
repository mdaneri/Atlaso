<#
.SYNOPSIS
Encode the two fixed restoration control frames for host parity qualification.
.DESCRIPTION
The encoder writes in-memory bytes for synthetic tests. Live capture owns identity, clock and phase checks.
#>

if (-not ('Atlaso.RestorationControlFrames' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Buffers.Binary;

namespace Atlaso
{
    public static class RestorationControlFrames
    {
        private const int HeaderSize = 10;
        private const long MaxUtcMilliseconds = 253402300799999;

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
