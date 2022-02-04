using System;
using System.Collections.Concurrent;

namespace DarkBot.HackDetect
{
    public class UserTextState
    {
        public string lastMessage;
        public long expireTime;
        public ulong lastChannel;
        public ConcurrentDictionary<ulong, ConcurrentQueue<Tuple<ulong, ulong>>> duplicateMessages = new ConcurrentDictionary<ulong, ConcurrentQueue<Tuple<ulong, ulong>>>();
    }
}