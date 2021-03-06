--- === LpassTool ===
---
--- Utility for getting password from lastpass using provided cli, and display a chooser for autofill password.


local obj={}
obj.__index = obj

-- Metadata
obj.name = "LpassTool"
obj.version = "0.1"
obj.author = "Nguyen Minh Tu <mtn9811@gmail.com>"
obj.homepage = "https://github.com/minhtus/LpassTool"
obj.license = "MIT - https://opensource.org/licenses/MIT"


-- Internal variable - Chooser/menu object
obj.selectorobj = nil
-- Internal variable - Store previous focused window
obj.prevFocusedWindow = nil
-- Internal variable - Timer object to sync last pass changes
obj.timer = nil
--- LpassTool.frequency
--- Variable
--- Speed in seconds to sync changes
obj.frequency = 300
--- LpassTool.logger
--- Variable
--- Logger instance
obj.logger = hs.logger.new('LpassTool')

-- key mapping for parsing keychain output
local keychainMapping = {
    acct = "account",
    type = "class",
    ["0x00000007"] = "label",
    svce = "service",
    password = "password"
}


--- ==== Keychain ===============================================================================================
---
--- Region for function and method interacting with Apple keychain

-- Parse output from keychain to a friendly format
local function parseKeyVal(k, v)
    local name = keychainMapping[k]

    if  name ~= nil then
        v,_ = string.gsub(v, '"(.*)"', "%1") -- remove quotes
        return name, v
    end
end


-- Save Lastpass master password to keychain
function obj:_saveMasterPassword(accountName, password)
    local _, status, _, rc = hs.execute('security add-generic-password -a '..accountName..' -s hammerspoon.'..self.name..' -U -w "'..password..'"')
    if not status or rc ~= 0 then
        hs.dialog.alert('Failed to persist master password into keychain')
        self.logger.e('Error when saving master password to Apple keychain')
    end
end


-- Get Lastpass master password from keychain
function obj:_getMasterPassword()
    local credentials = {}
    local result, status, _, rc = hs.execute('security 2>&1 find-generic-password -g -l hammerspoon.'..self.name)
    if status and rc == 0 then
        for line in string.gmatch(result, '([^\n]+)\n') do
            k,v = string.match(line, "^%s+(.*) ?<.*>=(.*)$")
            if k ~= nil then
                k,_ = string.gsub(k, '"(.*)"', "%1") -- remove quotes
                k,_ = string.gsub(k , "%s$", "") -- trim leading space
                if v ~= "<NULL>" then
                    local name, val = parseKeyVal(k,v)
                    if name ~= nil then
                        credentials[name] = val
                    end
                end
            else
                k,v = string.match(line, "^(%S+): (.*)$")
                if k ~= nil then
                    local name, val = parseKeyVal(k,v)
                    if name ~= nil then
                        credentials[name] = val
                    end
                end
            end
        end
        return credentials
    end
end

--- === Lastpass region ================================================================================================
---
--- Region for functions and methods interacting with Lastpass CLI

-- Get Lastpass login status
function obj:_lpassStatus()
    local _, status, _, rc = hs.execute('lpass status', true)
    if status and rc == 0 then
        return true
    elseif rc == 1 then
        self.logger.d('Not logged in.')
        return false
    else
        hs.dialog.alert('Error! Did you install Lastpass CLI?')
        self.logger.e('Error! Please check for lpass cli whether it exist in PATH yet?')
    end
end


-- Async wrapper of Lastpass login TODO find a true non-blocking way
function obj:_asyncLpassLogin(email, password)
    local co = coroutine.create(self._lpassLogin)
    local _, result = coroutine.resume(co, nil, email, password)
    return result
end


-- Login to Lastpass cli
function obj:_lpassLogin(email, password)
    self.logger.df('logging in with account %s', email)
    local _, status, _, rc = hs.execute('echo "'..password..'" | LPASS_DISABLE_PINENTRY=1 lpass login '..email, true)
    if status and rc == 0 then
        return true
    else
        self.logger.e('Failed to login to lpass')
        return false
    end
end


-- List Lastpass items
function obj:_lpassLs(sync)
    sync = sync or false
    local result, status, type, rc
    if sync then
        result, status, type, rc = hs.execute('lpass ls --sync=now', true)
    else
        result, status, type, rc = hs.execute('lpass ls --sync=no', true)
    end
    if status and rc == 0 then
        return self:_parseLpassLs(result)
    else
        if not sync then
            return self:_lpassLs(true)
        end
        self.logger.e('Failed to list lpass')
    end
end


-- Parse `lpass ls` output
function obj:_parseLpassLs(value)
    local result = { }
    for k, v in string.gmatch(value, '([^\n]+) %[id: (%d+)%]\n') do
        result[k] = v
    end
    return result
end


-- Parse `lpass show` output
function obj:_parseLpassShow(value)
    local result = string.match(value, '\n[Pp]assword: ([^\n]+)\n')
    if result ~= nil and result ~= '' then
        return result
    end
    return string.match(value, '\npasswd: ([^\n]+)\n')
end

--- === Main region ====================================================================================================
---
--- Region for main LpassTool application

--- LpassTool:_tryAutoLogin()
--- Method
--- Try to login with keychain credentials
---
--- Parameters:
---  * promptIfFailed - whether to prompt user for input if not found credentials from keychain
function obj:_tryAutoLogin(promptIfFailed)
    promptIfFailed = promptIfFailed or false
    local credentials = self:_getMasterPassword()
    if not credentials and promptIfFailed then
        self:promptLogin()
    else
        -- TODO make it async here
        local success = self:_lpassLogin(credentials.account, credentials.password)
        if not success then
            self.logger.e('Error logging in with credentials from keychain')
        end
    end
end


--- LpassTool:_trySyncLastPass()
--- Method
--- Sync last pass changes with credentials from keychain if session expired
---
--- Parameters:
---  * None
function obj:_trySyncLastPass()
    self.logger.d('Syncing lastpass')
    local _, status, _, rc = self:_lpassLs(true)
    if status and rc == 0 then
        return true
    else
        self:_tryAutoLogin()
        self:_lpassLs(true)
    end
end

--- LpassTool:_populateChooser()
--- Method
--- Fill in the password chooser
---
--- Parameters:
---  * None
function obj:_populateChooser()
    menuData = {}

    local items = self:_lpassLs()
    for k,v in pairs(items) do
        local dashIndex = k:find('/')
        local namespace = k:sub(1,dashIndex - 1)
        local title = k:sub(dashIndex + 1, #k)
        table.insert(menuData, {
            text = title,
            subText = namespace,
            uuid = v
        })
    end
    self.logger.df("Returning menuData = %s", hs.inspect(menuData))
    return menuData
end


--- LpassTool:_trySyncLastPass()
--- Method
--- Process the selected item from the chooser
---
--- Parameters:
---  * value - lastpass item id
function obj:_processSelectedItem(value)
    if self.prevFocusedWindow ~= nil then
        self.prevFocusedWindow:focus()
    end
    if value ~= nil then
        local result, status, _, rc = hs.execute('lpass show '..value.uuid..' --sync=no', true)
        if status and rc == 0 then
            local passwd = self:_parseLpassShow(result)
            hs.eventtap.keyStrokes(passwd)
        else
            self.logger.e('Error getting password: '..result)
        end
    end
end


--- LpassTool:promptLogin()
--- Method
--- Prompt user for Lastpass credentials
---
--- Parameters:
---   * None
function obj:promptLogin()
    local _, email = hs.dialog.textPrompt('Email', 'Please login to Lastpass!', '', 'Proceed', '')
    local _, loginPasswd = hs.dialog.textPrompt('Password', 'Login as: '..email, '', 'Login', '', true)
    local success = self:_lpassLogin(email, loginPasswd)
    if success then
        self:_saveMasterPassword(email, loginPasswd)
        hs.alert.show('Logged in as '..email)
    else
        local selected = hs.dialog.blockAlert('ERROR', 'Unable to login to Lastpass account '..email..'!', 'Try again', 'Cancel', 'warning')
        if selected == 'Try again' then
            self:promptLogin()
        end
        self.logger.e('Error logging in with provided credentials')
    end
end


--- LpassTool:start()
--- Method
--- Start the pass chooser and the sync timer
---
--- Parameters:
---  * None
function obj:start()
    -- init passwd chooser
    self.selectorobj = hs.chooser.new(hs.fnutils.partial(self._processSelectedItem, self))
    self.selectorobj:choices(hs.fnutils.partial(self._populateChooser, self))
    -- init sync timer
    self.timer = hs.timer.new(self.frequency, hs.fnutils.partial(self._trySyncLastPass, self))
    self.timer:start()
    -- check for lpass status and prompt login
    if not self:_lpassStatus() then
        self:_tryAutoLogin(true)
        self:_lpassLs(true)
    end
end


--- LpassTool:showChooser()
--- Method
--- Display the password chooser
---
--- Parameters:
---  * None
function obj:showChooser()
    if self.selectorobj ~= nil then
        self.selectorobj:refreshChoicesCallback()
        self.prevFocusedWindow = hs.window.focusedWindow()
        self.selectorobj:show()
    else
        hs.notify.show("LpassTool not properly initialized", "Did you call LpassTool:start()?", "")
    end
end


--- LpassTool:toggleChooser()
--- Method
--- Show/hide the passwd chooser
---
--- Parameters:
---  * None
function obj:toggleChooser()
    if self.selectorobj:isVisible() then
        self.selectorobj:hide()
    else
        self:showChooser()
    end
end


--- LpassTool:bindHotkeys(mapping)
--- Method
--- Binds hotkeys for LpassTool
---
--- Parameters:
---  * mapping - A table containing hotkeys for the following items:
---   * toggle_chooser - Show/hide the password chooser
function obj:bindHotkeys(mapping)
    local def = {
        toggle_chooser = hs.fnutils.partial(self.toggleChooser, self),
    }
    hs.spoons.bindHotkeysToSpec(def, mapping)
    obj.mapping = mapping
end


return obj
