using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using DarkBot;
using Discord;
using Discord.Rest;
using Discord.WebSocket;

namespace DarkBot.HackDetect
{
    public class HackDetect : BotModule
    {
        private long nextGarbageCollect;
        private ConcurrentDictionary<ulong, UserTextState> textStates = new ConcurrentDictionary<ulong, UserTextState>();
        private Dictionary<ulong, ulong> serverJailRoles = new Dictionary<ulong, ulong>();
        private Dictionary<ulong, ulong> notifyChannels = new Dictionary<ulong, ulong>();
        private HashSet<ulong> serverBanOk = new HashSet<ulong>();
        private DiscordSocketClient _client = null;
        private const int BOT_THRESHOLD = 5;

        public Task Initialize(IServiceProvider service)
        {
            LoadDatabase();
            _client = service.GetService(typeof(DiscordSocketClient)) as DiscordSocketClient;
            _client.Ready += OnReady;
            _client.MessageReceived += HandleMessage;
            _client.SlashCommandExecuted += HandleCommand;
            return Task.CompletedTask;
        }

        public async Task OnReady()
        {
            await SetupCommands();
        }

        public async Task HandleCommand(SocketSlashCommand command)
        {
            if (command.CommandName != "hackdetect")
            {
                return;
            }

            SocketGuildChannel sgc = command.Channel as SocketGuildChannel;
            if (sgc == null)
            {
                await command.RespondAsync("HackDetect commands only work inside a guild");
                return;
            }

            SocketGuildUser sgu = command.User as SocketGuildUser;
            if (sgu == null)
            {
                await command.RespondAsync("HackDetect commands only work inside a guild");
                return;
            }

            SocketGuild sg = sgc.Guild;

            if (!sgu.GuildPermissions.Administrator && !sgu.GuildPermissions.ManageChannels)
            {
                await command.RespondAsync("This command is an admin only command");
                return;
            }

            SocketSlashCommandDataOption option = command.Data.Options.FirstOrDefault<SocketSlashCommandDataOption>();

            if (option == null)
            {
                Log(LogSeverity.Error, "Command error");
                await command.RespondAsync("Command error");
            }
            else
            {
                if (option.Name == "setrole")
                {
                    SocketSlashCommandDataOption val = option.Options.First();
                    SocketRole jailRole = val.Value as SocketRole;
                    serverJailRoles[sg.Id] = jailRole.Id;
                    Log(LogSeverity.Info, $"{sg.Name} jail role now set to '{jailRole.Name}'");
                    await command.RespondAsync($"Guild jail role now set to '{jailRole.Name}'");
                    SaveDatabase();
                }
                if (option.Name == "unsetrole")
                {
                    if (serverJailRoles.ContainsKey(sg.Id))
                    {
                        Log(LogSeverity.Info, $"{sg.Name} jailing is now disabled");
                        await command.RespondAsync($"Jailing is now disabled");
                        serverJailRoles.Remove(sg.Id);
                        SaveDatabase();
                    }
                    else
                    {
                        Log(LogSeverity.Info, $"{sg.Name} jailing is already disabled");
                        await command.RespondAsync($"Jailing is already disabled");
                    }
                }
                if (option.Name == "setnotify")
                {
                    SocketSlashCommandDataOption val = option.Options.First();
                    SocketTextChannel stc = val.Value as SocketTextChannel;
                    if (stc == null)
                    {
                        Log(LogSeverity.Info, $"{sg.Name} notify channel setup error, needs to be a text channel");
                        await command.RespondAsync($"Notify channel setup error, needs to be a text channel");
                        return;
                    }
                    notifyChannels[sg.Id] = stc.Id;
                    Log(LogSeverity.Info, $"{sg.Name} notification channel now set to '{stc.Name}'");
                    await command.RespondAsync($"Notification channel now set to <#{stc.Id}>");
                    SaveDatabase();
                }
                if (option.Name == "unsetnotify")
                {
                    if (notifyChannels.ContainsKey(sg.Id))
                    {
                        Log(LogSeverity.Info, $"{sg.Name} notifications are now disabled");
                        await command.RespondAsync($"Notifications are now disabled");
                        notifyChannels.Remove(sg.Id);
                        SaveDatabase();
                    }
                    else
                    {
                        Log(LogSeverity.Info, $"{sg.Name} notifications are already disabled");
                        await command.RespondAsync($"Notifications are already disabled");
                    }
                }
                if (option.Name == "ban")
                {
                    bool newState = !serverBanOk.Contains(sg.Id);
                    if (newState)
                    {
                        serverBanOk.Add(sg.Id);
                        Log(LogSeverity.Info, $"{sg.Name} HackDetect is now allowed to ban bots");
                        await command.RespondAsync($"HackDetect is now allowed to ban bots");
                    }
                    else
                    {
                        serverBanOk.Remove(sg.Id);
                        Log(LogSeverity.Info, $"{sg.Name} HackDetect is no longer allowed to ban bots");
                        await command.RespondAsync($"HackDetect is no longer allowed to ban bots");
                    }
                    SaveDatabase();
                }
                if (option.Name == "disable")
                {
                    if (serverBanOk.Contains(sg.Id))
                    {
                        serverBanOk.Remove(sg.Id);
                    }
                    if (serverJailRoles.ContainsKey(sg.Id))
                    {
                        serverJailRoles.Remove(sg.Id);
                    }
                    if (notifyChannels.ContainsKey(sg.Id))
                    {
                        notifyChannels.Remove(sg.Id);
                    }
                    Log(LogSeverity.Info, $"{sg.Name} HackDetect will no longer take any action in this server");
                    await command.RespondAsync($"HackDetect will no longer take any action in this server");
                    SaveDatabase();
                }
                if (option.Name == "config")
                {
                    Log(LogSeverity.Info, $"{sg.Name} HackDetect showing config");
                    StringBuilder response = new StringBuilder();
                    if (serverBanOk.Contains(sg.Id))
                    {
                        response.AppendLine("HackDetect is allowed to ban users");
                    }
                    else
                    {
                        response.AppendLine("HackDetect is not allowed to ban users");
                    }
                    if (serverJailRoles.ContainsKey(sg.Id))
                    {
                        SocketRole sr = sg.GetRole(serverJailRoles[sg.Id]);
                        if (sr != null)
                        {
                            response.AppendLine($"HackDetect is jailing with role: {sr.Name}");
                        }
                        else
                        {
                            response.AppendLine($"HackDetect is configured to jail but the role is missing!");
                        }
                    }
                    else
                    {
                        response.AppendLine($"HackDetect is not jailing");
                    }
                    if (notifyChannels.ContainsKey(sg.Id))
                    {
                        response.AppendLine($"HackDetect will notify in channel <#{notifyChannels[sg.Id]}>");
                    }
                    else
                    {
                        response.AppendLine($"HackDetect does not have notifications enabled");
                    }
                    await command.RespondAsync(response.ToString());
                    SaveDatabase();
                }
            }
        }

        public async Task HandleMessage(SocketMessage message)
        {
            GarbageCollect();
            SocketUserMessage sum = message as SocketUserMessage;
            SocketGuildChannel sgc = message.Channel as SocketGuildChannel;

            //Have to be in a guild
            if (sum == null || sgc == null)
            {
                return;
            }

            //Bots are ok because they are only allowed by admins
            if (sum.Author.IsBot)
            {
                return;
            }

            //Have to be in a guild. This should never error though...
            SocketGuildUser sgu = sum.Author as SocketGuildUser;
            if (sgu == null)
            {
                return;
            }

            //Grab the user tracking
            UserTextState uts = null;

            if (textStates.ContainsKey(sum.Author.Id))
            {
                uts = textStates[sum.Author.Id];
            }
            else
            {
                uts = new UserTextState();
                textStates[sum.Author.Id] = uts;
            }
            ConcurrentQueue<Tuple<ulong, ulong>> duplicateMessages = null;
            if (uts.duplicateMessages.ContainsKey(sgu.Guild.Id))
            {
                duplicateMessages = uts.duplicateMessages[sgu.Guild.Id];
            }
            else
            {
                duplicateMessages = new ConcurrentQueue<Tuple<ulong, ulong>>();
                uts.duplicateMessages[sgu.Guild.Id] = duplicateMessages;
            }


            //Don't detect null strings because this could just be meme reposting
            if (message.Content != uts.lastMessage || message.Content == null || message.Content == string.Empty)
            {
                uts.lastMessage = message.Content;
                duplicateMessages.Clear();
            }

            //Add the message and check
            if (message.Channel.Id != uts.lastChannel)
            {
                duplicateMessages.Enqueue(new Tuple<ulong, ulong>(message.Channel.Id, message.Id));
            }

            if (duplicateMessages.Count >= BOT_THRESHOLD)
            {
                await BotDetected(sgu, duplicateMessages);
            }

            //Update timestamp and last channel
            uts.expireTime = DateTime.UtcNow.Ticks + (5 * TimeSpan.TicksPerMinute);
            uts.lastChannel = sgc.Id;
        }

        private async Task BotDetected(SocketGuildUser user, ConcurrentQueue<Tuple<ulong, ulong>> duplicateMessages)
        {
            SocketTextChannel stc = null;
            if (notifyChannels.ContainsKey(user.Guild.Id))
            {
                stc = user.Guild.GetTextChannel(notifyChannels[user.Guild.Id]);
            }
            //Get message history
            Log(LogSeverity.Info, $"HackDetect deleting messages from {user.Id}");
            foreach (Tuple<ulong, ulong> channelMessagePair in duplicateMessages)
            {
                SocketTextChannel sc = _client.GetChannel(channelMessagePair.Item1) as SocketTextChannel;
                if (sc == null)
                {
                    continue;
                }
                try
                {
                    Log(LogSeverity.Info, $"Trying to delete {channelMessagePair.Item2}");
                    await sc.DeleteMessageAsync(channelMessagePair.Item2);
                }
                catch
                {
                    Log(LogSeverity.Info, $"Failed to delete {channelMessagePair.Item2}");
                }
            }
            duplicateMessages.Clear();
            //Ignore admins
            if (user.GuildPermissions.Administrator || user.GuildPermissions.ManageChannels)
            {
                if (stc != null)
                {
                    Log(LogSeverity.Info, $"{user.Id}, <@{user.Id}> has been detected as a bot but is an admin, ignoring");
                    await stc.SendMessageAsync($"{user.Id}, <@{user.Id}> has been detected as a bot but is an admin, ignoring");
                }
                return;
            }
            if (serverBanOk.Contains(user.Guild.Id))
            {
                await user.BanAsync(1, "Bot detected");
                if (stc != null)
                {
                    Log(LogSeverity.Info, $"{user.Nickname}, <@{user.Id}> has been detected as a bot and was banned");
                    await stc.SendMessageAsync($"{user.Nickname}, <@{user.Id}> has been detected as a bot and was banned");
                }
                return;
            }
            if (serverJailRoles.ContainsKey(user.Guild.Id))
            {
                await user.RemoveRolesAsync(user.Roles);
                SocketRole jailRole = user.Guild.GetRole(serverJailRoles[user.Guild.Id]);
                if (jailRole != null)
                {
                    await user.AddRoleAsync(jailRole);
                    if (stc != null)
                    {
                        Log(LogSeverity.Info, $"{user.Nickname}, <@{user.Id}> has been detected as a bot and was jailed");
                        await stc.SendMessageAsync($"{user.Nickname}, <@{user.Id}> has been detected as a bot and was jailed");
                    }
                }
                else
                {
                    if (stc != null)
                    {
                        Log(LogSeverity.Info, $"{user.Nickname}, <@{user.Id}> has been detected as a bot but the jail role is missing");
                        await stc.SendMessageAsync($"{user.Nickname}, <@{user.Id}> has been detected as a bot but the jail role is missing");
                    }
                }
                return;
            }
            if (stc != null)
            {
                Log(LogSeverity.Info, $"{user.Nickname}, <@{user.Id}> has been detected as a bot but jailing or banning is not setup");
                await stc.SendMessageAsync($"{user.Nickname}, <@{user.Id}> has been detected as a bot but jailing or banning is not setup");
            }
        }

        private void GarbageCollect()
        {
            long currentTime = DateTime.UtcNow.Ticks;
            if (nextGarbageCollect > currentTime)
            {
                return;
            }
            nextGarbageCollect = currentTime + (1 * TimeSpan.TicksPerMinute);
            foreach (KeyValuePair<ulong, UserTextState> kvp in textStates)
            {
                if (kvp.Value.expireTime > currentTime)
                {
                    textStates.TryRemove(kvp.Key, out _);
                }
            }
        }

        private async Task SetupCommands()
        {
            foreach (SocketApplicationCommand sac in await _client.GetGlobalApplicationCommandsAsync())
            {
                if (sac.Name == "hackdetect")
                {
                    Log(LogSeverity.Info, "Commands already registered");
                    return;
                }
            }
            Log(LogSeverity.Info, "Setting up commands");
            SlashCommandBuilder scb = new SlashCommandBuilder();
            scb.WithName("hackdetect");
            scb.WithDescription("Set jail role for users");
            SlashCommandOptionBuilder notifySet = new SlashCommandOptionBuilder();
            notifySet.WithName("setnotify");
            notifySet.WithDescription("Setup the notification channel");
            notifySet.WithType(ApplicationCommandOptionType.SubCommand);
            notifySet.AddOption("value", ApplicationCommandOptionType.Channel, "The notification channel", isRequired: true, channelTypes: new List<ChannelType>() { ChannelType.Text });
            SlashCommandOptionBuilder jailSet = new SlashCommandOptionBuilder();
            jailSet.WithName("setrole");
            jailSet.WithDescription("Setup the jail role");
            jailSet.WithType(ApplicationCommandOptionType.SubCommand);
            jailSet.AddOption("value", ApplicationCommandOptionType.Role, "The jail role", isRequired: true);
            scb.AddOption(jailSet);
            scb.AddOption("unsetrole", ApplicationCommandOptionType.SubCommand, "Disable jailing");
            scb.AddOption(notifySet);
            scb.AddOption("unsetnotify", ApplicationCommandOptionType.SubCommand, "Disable notifications");
            scb.AddOption("ban", ApplicationCommandOptionType.SubCommand, "Bans bots instead");
            scb.AddOption("disable", ApplicationCommandOptionType.SubCommand, "Disables hack detect");
            scb.AddOption("config", ApplicationCommandOptionType.SubCommand, "Shows the bot config");

            await _client.CreateGlobalApplicationCommandAsync(scb.Build());

            Log(LogSeverity.Info, "Commands registered");
        }

        private void SaveDatabase()
        {
            StringBuilder sb = new StringBuilder();
            foreach (KeyValuePair<ulong, ulong> kvp in serverJailRoles)
            {
                sb.AppendLine($"{kvp.Key}={kvp.Value}");
            }
            DataStore.Save("HackRole-Jail", sb.ToString());

            StringBuilder sb2 = new StringBuilder();
            foreach (ulong serverOK in serverBanOk)
            {
                sb2.AppendLine(serverOK.ToString());
            }
            DataStore.Save("HackRole-Ban", sb2.ToString());

            StringBuilder sb3 = new StringBuilder();
            foreach (KeyValuePair<ulong, ulong> kvp in notifyChannels)
            {
                sb3.AppendLine($"{kvp.Key}={kvp.Value}");
            }
            DataStore.Save("HackRole-Notify", sb3.ToString());
        }

        private void LoadDatabase()
        {
            string jailData = DataStore.Load("HackRole-Jail");
            if (jailData != null)
            {
                serverJailRoles.Clear();
                using (StringReader sr = new StringReader(jailData))
                {
                    string currentLine = null;
                    while ((currentLine = sr.ReadLine()) != null)
                    {
                        if (currentLine.Length > 1 && currentLine.Contains("="))
                        {
                            string[] splits = currentLine.Split('=');
                            serverJailRoles.Add(ulong.Parse(splits[0]), ulong.Parse(splits[1]));
                        }
                    }
                }
            }


            string banData = DataStore.Load("HackRole-Ban");
            if (banData != null)
            {
                serverBanOk.Clear();
                using (StringReader sr = new StringReader(banData))
                {
                    string currentLine = null;
                    while ((currentLine = sr.ReadLine()) != null)
                    {
                        if (currentLine.Length > 1)
                        {
                            serverBanOk.Add(ulong.Parse(currentLine));
                        }
                    }
                }
            }

            string notifyData = DataStore.Load("HackRole-Notify");
            if (notifyData != null)
            {
                notifyChannels.Clear();
                using (StringReader sr = new StringReader(notifyData))
                {
                    string currentLine = null;
                    while ((currentLine = sr.ReadLine()) != null)
                    {
                        if (currentLine.Length > 1 && currentLine.Contains("="))
                        {
                            string[] splits = currentLine.Split('=');
                            notifyChannels.Add(ulong.Parse(splits[0]), ulong.Parse(splits[1]));
                        }
                    }
                }
            }
        }

        private void Log(LogSeverity severity, string text)
        {
            LogMessage logMessage = new LogMessage(severity, "HackDetect", text);
            Program.LogAsync(logMessage);
        }
    }
}
