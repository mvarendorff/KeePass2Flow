dotnet publish Flow.Launcher.Plugin.KeePass2Flow -c Release -r win-x64 --no-self-contained
Compress-Archive -LiteralPath Flow.Launcher.Plugin.KeePass2Flow/bin/Release/win-x64/publish -DestinationPath Flow.Launcher.Plugin.KeePass2Flow/bin/KeePass2Flow.zip -Force
