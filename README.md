Flow.Launcher.Plugin.KeePass2Flow
==================

A plugin for the [Flow launcher](https://github.com/Flow-Launcher/Flow.Launcher) to connect to [KeePass2](https://keepass.info) through the KeePassRPC plugin.

### Usage

1. Configure both your databases and the path to KeePass2 in the Plugin settings.
2. Make sure you have [KeePassRPC](https://github.com/kee-org/keepassrpc/releases/tag/v1.16.0) installed in your KeePass2 installation.

```
# Used in the authentication process between this plugin and KeePassRPC
kp auth <password>

# Open one of your configured databases by name (uses KeePassRPC if connected successfully or the configured KeePass2 installation otherwise)
kp open <database>

# Search any password in your open database(s)
kp <search>
```
