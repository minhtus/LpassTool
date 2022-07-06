# Hammerspoon Lastpass Tool

A small utility to display password from Lastpass in a chooser built on [Hammerspoon](http://www.hammerspoon.org)

## Prerequisites

### Hammerspoon

You can simply download it at https://www.hammerspoon.org

Or install it using brew

```shell
brew install --cask hammerspoon
```

### Lastpass CLI

Details in the Lastpass CLI GitHub repo https://github.com/lastpass/lastpass-cli

Prefer installation method: using brew

```shell
brew install lastpass-cli
```

## Installation

1. Using SpoonInstall (prefer method)

Open the Hammerspoon configuration and add these lines to install and load the spoon.

*Notes: You must have [SpoonInstall](https://www.hammerspoon.org/Spoons/SpoonInstall.html) available*

```lua
-- Install the spoon
spoonInstall.repos.LpassTool = {
   url = 'https://github.com/minhtus/LpassTool',
   desc = 'LpassTool spoon repository',
   branch = 'master',
}
-- Load and start the spoon
spoonInstall:andUse('LpassTool', { repo = 'LpassTool', start = true })
```

2. Download the spoon directly

Download the [LpassTool spoon](https://github.com/minhtus/LpassTool/raw/master/Spoons/LpassTool.spoon.zip). Unzip it and open the spoon.

Hammerspoon should prompt that the newly installed spoon is now available.

Open the Hammerspoon configuration and add these lines to load the spoon.

```lua
-- Load the spoon
hs.loadSpoon('LpassTool')
-- Start the spoon
spoon.LpassTool:start()
```

## Usage

* Make sure Hammerspoon is started (You should see the Hammerspoon icon on your toolbar).
* Make sure Hammerspoon has the *Accessibility* permissions.

Open the Hammerspoon configuration and add your key bindings preference.

*Notes: This must be added after the spoon is installed and loaded*

```lua
spoon.LpassTool:bindHotkeys({
   toggle_chooser = { { 'ctrl', 'alt', 'cmd' }, 'p' }
})
```
