script_name("RandomVehicle_siren")
script_author("dmitriyewich")
script_url("https://vk.com/dmitriyewichmods", 'https://github.com/dmitriyewich/RandomVehicle')
script_properties('work-in-pause', 'forced-reloading-only')
script_version("0.1")

local lffi, ffi = pcall(require, 'ffi')
local lmemory, memory = pcall(require, 'memory')

-- AUTHOR main hooks lib: RTD/RutreD(https://www.blast.hk/members/126461/)
ffi.cdef[[
    int VirtualProtect(void* lpAddress, unsigned long dwSize, unsigned long flNewProtect, unsigned long* lpflOldProtect);
    void* VirtualAlloc(void* lpAddress, unsigned long dwSize, unsigned long  flAllocationType, unsigned long flProtect);
    int VirtualFree(void* lpAddress, unsigned long dwSize, unsigned long dwFreeType);
]]
local function copy(dst, src, len)
    return ffi.copy(ffi.cast('void*', dst), ffi.cast('const void*', src), len)
end
local buff = {free = {}}
local function VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect)
    return ffi.C.VirtualProtect(ffi.cast('void*', lpAddress), dwSize, flNewProtect, lpflOldProtect)
end
local function VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect, blFree)
    local alloc = ffi.C.VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect)
    if blFree then
        table.insert(buff.free, function()
            ffi.C.VirtualFree(alloc, 0, 0x8000)
        end)
    end
    return ffi.cast('intptr_t', alloc)
end
--JMP HOOKS
local jmp_hook = {hooks = {}}
function jmp_hook.new(cast, callback, hook_addr, size, trampoline, org_bytes_tramp)
    jit.off(callback, true) --off jit compilation | thx FYP
    local size = size or 5
    local trampoline = trampoline or false
    local new_hook, mt = {}, {}
    local detour_addr = tonumber(ffi.cast('intptr_t', ffi.cast(cast, callback)))
    local old_prot = ffi.new('unsigned long[1]')
    local org_bytes = ffi.new('uint8_t[?]', size)
    copy(org_bytes, hook_addr, size)
    if trampoline then
        local alloc_addr = VirtualAlloc(nil, size + 5, 0x1000, 0x40, true)
        local trampoline_bytes = ffi.new('uint8_t[?]', size + 5, 0x90)
        if org_bytes_tramp then
            local i = 0
            for byte in org_bytes_tramp:gmatch('(%x%x)') do
                trampoline_bytes[i] = tonumber(byte, 16)
                i = i + 1
            end
        else
            copy(trampoline_bytes, org_bytes, size)
        end
        trampoline_bytes[size] = 0xE9
        ffi.cast('int32_t*', trampoline_bytes + size + 1)[0] = hook_addr - tonumber(alloc_addr) - size + (size - 5)
        copy(alloc_addr, trampoline_bytes, size + 5)
        new_hook.call = ffi.cast(cast, alloc_addr)
        mt = {__call = function(self, ...)
            return self.call(...)
        end}
    else
        new_hook.call = ffi.cast(cast, hook_addr)
        mt = {__call = function(self, ...)
            self.stop()
            local res = self.call(...)
            self.start()
            return res
        end}
    end
    local hook_bytes = ffi.new('uint8_t[?]', size, 0x90)
    hook_bytes[0] = 0xE9
    ffi.cast('int32_t*', hook_bytes + 1)[0] = detour_addr - hook_addr - 5
    new_hook.status = false
    local function set_status(bool)
        new_hook.status = bool
        VirtualProtect(hook_addr, size, 0x40, old_prot)
        copy(hook_addr, bool and hook_bytes or org_bytes, size)
        VirtualProtect(hook_addr, size, old_prot[0], old_prot)
    end
    new_hook.stop = function() set_status(false) end
    new_hook.start = function() set_status(true) end
    new_hook.start()
    if org_bytes[0] == 0xE9 or org_bytes[0] == 0xE8 then
        print('[WARNING] rewrote another hook'.. (trampoline and ' (old hook was disabled, through trampoline)' or ''))
    end
    table.insert(jmp_hook.hooks, new_hook)
    return setmetatable(new_hook, mt)
end
--JMP HOOKS
--DELETE HOOKS
addEventHandler('onScriptTerminate', function(scr)
    if scr == script.this then
        for i, hook in ipairs(jmp_hook.hooks) do
            if hook.status then
                hook.stop()
            end
        end
        for i, free in ipairs(buff.free) do
            free()
        end
    end
end)
--DELETE HOOKS

local config = {}

if doesFileExist("moonloader/config/RandomVehicle.json") then
    local f = io.open("moonloader/config/RandomVehicle.json")
    config = decodeJson(f:read("*a"))
    f:close()
else
	thisScript():unload()
end

tbs = {config.vehicle[tostring(407)] ~= nil and config.vehicle[tostring(407)] or {407}, config.vehicle[tostring(427)] ~= nil and config.vehicle[tostring(427)] or {427}, config.vehicle[tostring(433)] ~= nil and config.vehicle[tostring(433)] or {433}, config.vehicle[tostring(490)] ~= nil and config.vehicle[tostring(490)] or {490}, config.vehicle[tostring(528)] ~= nil and config.vehicle[tostring(528)] or {528}, config.vehicle[tostring(596)] ~= nil and config.vehicle[tostring(596)] or {596}, config.vehicle[tostring(597)] ~= nil and config.vehicle[tostring(597)] or {597}, config.vehicle[tostring(598)] ~= nil and config.vehicle[tostring(598)] or {598}, config.vehicle[tostring(599)] ~= nil and config.vehicle[tostring(599)] or {599}, config.vehicle[tostring(601)] ~= nil and config.vehicle[tostring(601)] or {601}}
 
local res = {}
 
for t = 1, #tbs do
    for i = 1, #tbs[ t ] do
        table.insert( res, tbs[ t ][ i ] )
    end
end

function UsesSiren(this)
	for i = 1, #res do
		if res[i] == getCarModel(getVehiclePointerHandle(this)) then
			return true
		end
	end
	return UsesSiren(this)
end

function main()

	if not doesFileExist(getGameDirectory() .."\\modloader\\RandomVehicle\\RandomVehicle.txt") then thisScript():unload() end
	
	repeat wait(0) until memory.read(0xC8D4C0, 4, false) == 9
	repeat wait(0) until fixed_camera_to_skin()

	UsesSiren = jmp_hook.new("bool(__thiscall*)(uintptr_t)", UsesSiren, 0x6D8470)

	wait(-1)
end
 
function fixed_camera_to_skin() -- проверка на приклепление камеры к скину
	return (memory.read(getModuleHandle('gta_sa.exe') + 0x76F053, 1, false) >= 1 and true or false)
end