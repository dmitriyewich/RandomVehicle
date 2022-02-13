script_name("RandomVehicle")
script_author("dmitriyewich")
script_url("https://vk.com/dmitriyewichmods", 'https://github.com/dmitriyewich/RandomVehicle')
script_properties('work-in-pause', 'forced-reloading-only')
script_version("0.3.1")

require "lib.moonloader"
local lffi, ffi = pcall(require, 'ffi')
local lmemory, memory = pcall(require, 'memory')

local lencoding, encoding = pcall(require, 'encoding')
encoding.default = 'CP1251'
u8 = encoding.UTF8

local folder_fla = getGameDirectory() ..'\\data\\gtasa_vehicleAudioSettings.cfg'
local folder_txt =  getGameDirectory() .."\\modloader\\RandomVehicle\\RandomVehicle.txt"

changelog = [[
	RandomVehicle v0.1
		- Релиз
	RandomVehicle v0.2
		- Изменен метод смены модели
		- Добавлен стандартный тюнинг для авто(без него крашило)
		- Добавлен carcols.dat, чтобы был
	RandomVehicle v0.3
		- Добавлена поддержка handling.cfg
		- Изменен метод подключения звука на плагин Vehicle Audio Editor Ultimate от Alexander Blade
		- Добавлен второй скрипт RandomVehicle_siren, для включения звука сирен у новых полицейских машин
		- Изменена структура настроек машины, теперь все настройки находятся в папке settings, для каждой машины свой .txt файл
	RandomVehicle v0.3.1
		- 
]]

-- AUTHOR main hooks lib: RTD/RutreD(https://www.blast.hk/members/126461/)
ffi.cdef[[
    int VirtualProtect(void* lpAddress, unsigned long dwSize, unsigned long flNewProtect, unsigned long* lpflOldProtect);
    void* VirtualAlloc(void* lpAddress, unsigned long dwSize, unsigned long  flAllocationType, unsigned long flProtect);
    int VirtualFree(void* lpAddress, unsigned long dwSize, unsigned long dwFreeType);
	void free(void *ptr);
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
--VMT HOOKS
local vmt_hook = {hooks = {}}
function vmt_hook.new(vt)
    local new_hook = {}
    local org_func = {}
    local old_prot = ffi.new('unsigned long[1]')
    local virtual_table = ffi.cast('intptr_t**', vt)[0]
    new_hook.this = virtual_table
    new_hook.hookMethod = function(cast, func, method)
        jit.off(func, true) --off jit compilation | thx FYP
        org_func[method] = virtual_table[method]
        VirtualProtect(virtual_table + method, 4, 0x4, old_prot)
        virtual_table[method] = ffi.cast('intptr_t', ffi.cast(cast, func))
        VirtualProtect(virtual_table + method, 4, old_prot[0], old_prot)
        return ffi.cast(cast, org_func[method])
    end
    new_hook.unHookMethod = function(method)
        VirtualProtect(virtual_table + method, 4, 0x4, old_prot)
        -- virtual_table[method] = org_func[method]
        local alloc_addr = VirtualAlloc(nil, 5, 0x1000, 0x40, false)
        local trampoline_bytes = ffi.new('uint8_t[?]', 5, 0x90)
        trampoline_bytes[0] = 0xE9
        ffi.cast('int32_t*', trampoline_bytes + 1)[0] = org_func[method] - tonumber(alloc_addr) - 5
        copy(alloc_addr, trampoline_bytes, 5)
        virtual_table[method] = ffi.cast('intptr_t', alloc_addr)
        VirtualProtect(virtual_table + method, 4, old_prot[0], old_prot)
        org_func[method] = nil
    end
    new_hook.unHookAll = function()
        for method, func in pairs(org_func) do
            new_hook.unHookMethod(method)
        end
    end
    table.insert(vmt_hook.hooks, new_hook.unHookAll)
    return new_hook
end
--VMT HOOKS
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
--CALL HOOKS
local call_hook = {hooks = {}}
function call_hook.new(cast, callback, hook_addr)
	if ffi.cast('uint8_t*', hook_addr)[0] ~= 0xE8 then return end
    jit.off(callback, true) --off jit compilation | thx FYP
    local new_hook = {}
    local detour_addr = tonumber(ffi.cast('intptr_t', ffi.cast(cast, callback)))
    local void_addr = ffi.cast('void*', hook_addr)
    local old_prot = ffi.new('unsigned long[1]')
    local org_bytes = ffi.new('uint8_t[?]', 5)
    ffi.copy(org_bytes, void_addr, 5)
    local hook_bytes = ffi.new('uint8_t[?]', 5, 0xE8)
    ffi.cast('uint32_t*', hook_bytes + 1)[0] = detour_addr - hook_addr - 5
	new_hook.call = ffi.cast(cast, ffi.cast('intptr_t*', hook_addr + 1)[0] + hook_addr + 5)
    new_hook.status = false
    local function set_status(bool)
        new_hook.status = bool
        ffi.C.VirtualProtect(void_addr, 5, 0x40, old_prot)
        ffi.copy(void_addr, bool and hook_bytes or org_bytes, 5)
        ffi.C.VirtualProtect(void_addr, 5, old_prot[0], old_prot)
    end
    new_hook.stop = function() set_status(false) end
    new_hook.start = function() set_status(true) end
    new_hook.start()
    table.insert(call_hook.hooks, new_hook)
    return setmetatable(new_hook, {
        __call = function(self, ...)
            local res = self.call(...)
            return res
        end
    })
end
--CALL HOOKS
--DELETE HOOKS
addEventHandler('onScriptTerminate', function(scr)
    if scr == script.this then
        for i, hook in ipairs(jmp_hook.hooks) do
            if hook.status then
                hook.stop()
            end
        end
		for i, hook in ipairs(call_hook.hooks) do
			if hook.status then
				hook.stop()
			end
		end
        for i, free in ipairs(buff.free) do
            free()
        end
        for i, unHookFunc in ipairs(vmt_hook.hooks) do
            unHookFunc()
        end
    end
end)
--DELETE HOOKS

local function isarray(t, emptyIsObject)
	if type(t)~='table' then return false end
	if not next(t) then return not emptyIsObject end
	local len = #t
	for k,_ in pairs(t) do
		if type(k)~='number' then
			return false
		else
			local _,frac = math.modf(k)
			if frac~=0 or k<1 or k>len then
				return false
			end
		end
	end
	return true
end

local function map(t,f)
	local r={}
	for i,v in ipairs(t) do r[i]=f(v) end
	return r
end

local keywords = {["and"]=1,["break"]=1,["do"]=1,["else"]=1,["elseif"]=1,["end"]=1,["false"]=1,["for"]=1,["function"]=1,["goto"]=1,["if"]=1,["in"]=1,["local"]=1,["nil"]=1,["not"]=1,["or"]=1,["repeat"]=1,["return"]=1,["then"]=1,["true"]=1,["until"]=1,["while"]=1}

local function neatJSON(value, opts) -- https://github.com/Phrogz/NeatJSON
	opts = opts or {}
	if opts.wrap==nil  then opts.wrap = 80 end
	if opts.wrap==true then opts.wrap = -1 end
	opts.indent         = opts.indent         or "  "
	opts.arrayPadding  = opts.arrayPadding  or opts.padding      or 0
	opts.objectPadding = opts.objectPadding or opts.padding      or 0
	opts.afterComma    = opts.afterComma    or opts.aroundComma  or 0
	opts.beforeComma   = opts.beforeComma   or opts.aroundComma  or 0
	opts.beforeColon   = opts.beforeColon   or opts.aroundColon  or 0
	opts.afterColon    = opts.afterColon    or opts.aroundColon  or 0
	opts.beforeColon1  = opts.beforeColon1  or opts.aroundColon1 or opts.beforeColon or 0
	opts.afterColon1   = opts.afterColon1   or opts.aroundColon1 or opts.afterColon  or 0
	opts.beforeColonN  = opts.beforeColonN  or opts.aroundColonN or opts.beforeColon or 0
	opts.afterColonN   = opts.afterColonN   or opts.aroundColonN or opts.afterColon  or 0

	local colon  = opts.lua and '=' or ':'
	local array  = opts.lua and {'{','}'} or {'[',']'}
	local apad   = string.rep(' ', opts.arrayPadding)
	local opad   = string.rep(' ', opts.objectPadding)
	local comma  = string.rep(' ',opts.beforeComma)..','..string.rep(' ',opts.afterComma)
	local colon1 = string.rep(' ',opts.beforeColon1)..colon..string.rep(' ',opts.afterColon1)
	local colonN = string.rep(' ',opts.beforeColonN)..colon..string.rep(' ',opts.afterColonN)

	local build -- set lower
	local function rawBuild(o,indent)
		if o==nil then
			return indent..'null'
		else
			local kind = type(o)
			if kind=='number' then
				local _,frac = math.modf(o)
				return indent .. string.format( frac~=0 and opts.decimals and ('%.'..opts.decimals..'f') or '%g', o)
			elseif kind=='boolean' or kind=='nil' then
				return indent..tostring(o)
			elseif kind=='string' then
				return indent..string.format('%q', o):gsub('\\\n','\\n')
			elseif isarray(o, opts.emptyTablesAreObjects) then
				if #o==0 then return indent..array[1]..array[2] end
				local pieces = map(o, function(v) return build(v,'') end)
				local oneLine = indent..array[1]..apad..table.concat(pieces,comma)..apad..array[2]
				if opts.wrap==false or #oneLine<=opts.wrap then return oneLine end
				if opts.short then
					local indent2 = indent..' '..apad;
					pieces = map(o, function(v) return build(v,indent2) end)
					pieces[1] = pieces[1]:gsub(indent2,indent..array[1]..apad, 1)
					pieces[#pieces] = pieces[#pieces]..apad..array[2]
					return table.concat(pieces, ',\n')
				else
					local indent2 = indent..opts.indent
					return indent..array[1]..'\n'..table.concat(map(o, function(v) return build(v,indent2) end), ',\n')..'\n'..(opts.indentLast and indent2 or indent)..array[2]
				end
			elseif kind=='table' then
				if not next(o) then return indent..'{}' end

				local sortedKV = {}
				local sort = opts.sort or opts.sorted
				for k,v in pairs(o) do
					local kind = type(k)
					if kind=='string' or kind=='number' then
						sortedKV[#sortedKV+1] = {k,v}
						if sort==true then
							sortedKV[#sortedKV][3] = tostring(k)
						elseif type(sort)=='function' then
							sortedKV[#sortedKV][3] = sort(k,v,o)
						end
					end
				end
				if sort then table.sort(sortedKV, function(a,b) return a[3]<b[3] end) end
				local keyvals
				if opts.lua then
					keyvals=map(sortedKV, function(kv)
						if type(kv[1])=='string' and not keywords[kv[1]] and string.match(kv[1],'^[%a_][%w_]*$') then
							return string.format('%s%s%s',kv[1],colon1,build(kv[2],''))
						else
							return string.format('[%q]%s%s',kv[1],colon1,build(kv[2],''))
						end
					end)
				else
					keyvals=map(sortedKV, function(kv) return string.format('%q%s%s',kv[1],colon1,build(kv[2],'')) end)
				end
				keyvals=table.concat(keyvals, comma)
				local oneLine = indent.."{"..opad..keyvals..opad.."}"
				if opts.wrap==false or #oneLine<opts.wrap then return oneLine end
				if opts.short then
					keyvals = map(sortedKV, function(kv) return {indent..' '..opad..string.format('%q',kv[1]), kv[2]} end)
					keyvals[1][1] = keyvals[1][1]:gsub(indent..' ', indent..'{', 1)
					if opts.aligned then
						local longest = math.max(table.unpack(map(keyvals, function(kv) return #kv[1] end)))
						local padrt   = '%-'..longest..'s'
						for _,kv in ipairs(keyvals) do kv[1] = padrt:format(kv[1]) end
					end
					for i,kv in ipairs(keyvals) do
						local k,v = kv[1], kv[2]
						local indent2 = string.rep(' ',#(k..colonN))
						local oneLine = k..colonN..build(v,'')
						if opts.wrap==false or #oneLine<=opts.wrap or not v or type(v)~='table' then
							keyvals[i] = oneLine
						else
							keyvals[i] = k..colonN..build(v,indent2):gsub('^%s+','',1)
						end
					end
					return table.concat(keyvals, ',\n')..opad..'}'
				else
					local keyvals
					if opts.lua then
						keyvals=map(sortedKV, function(kv)
							if type(kv[1])=='string' and not keywords[kv[1]] and string.match(kv[1],'^[%a_][%w_]*$') then
								return {table.concat{indent,opts.indent,kv[1]}, kv[2]}
							else
								return {string.format('%s%s[%q]',indent,opts.indent,kv[1]), kv[2]}
							end
						end)
					else
						keyvals = {}
						for i,kv in ipairs(sortedKV) do
							keyvals[i] = {indent..opts.indent..string.format('%q',kv[1]), kv[2]}
						end
					end
					if opts.aligned then
						local longest = math.max(table.unpack(map(keyvals, function(kv) return #kv[1] end)))
						local padrt   = '%-'..longest..'s'
						for _,kv in ipairs(keyvals) do kv[1] = padrt:format(kv[1]) end
					end
					local indent2 = indent..opts.indent
					for i,kv in ipairs(keyvals) do
						local k,v = kv[1], kv[2]
						local oneLine = k..colonN..build(v,'')
						if opts.wrap==false or #oneLine<=opts.wrap or not v or type(v)~='table' then
							keyvals[i] = oneLine
						else
							keyvals[i] = k..colonN..build(v,indent2):gsub('^%s+','',1)
						end
					end
					return indent..'{\n'..table.concat(keyvals, ',\n')..'\n'..(opts.indentLast and indent2 or indent)..'}'
				end
			end
		end
	end

	-- indexed by object, then by indent level
	local function memoize()
		local memo = setmetatable({},{_mode='k'})
		return function(o,indent)
			if o==nil then
				return indent..(opts.lua and 'nil' or 'null')
			elseif o~=o then --test for NaN
				return indent..(opts.lua and '0/0' or '"NaN"')
			elseif o==math.huge then
				return indent..(opts.lua and '1/0' or '9e9999')
			elseif o==-math.huge then
				return indent..(opts.lua and '-1/0' or '-9e9999')
			end
			local byIndent = memo[o]
			if not byIndent then
				byIndent = setmetatable({},{_mode='k'})
				memo[o] = byIndent
			end
			if not byIndent[indent] then
				byIndent[indent] = rawBuild(o,indent)
			end
			return byIndent[indent]
		end
	end

	build = memoize()
	return build(value,'')
end

function savejson(table, path)
    local f = io.open(path, "w+")
    f:write(table)
    f:close()
end

function convertTableToJsonString(config)
	return (neatJSON(config, { wrap = 174, sort = true, aligned = true, arrayPadding = 1, afterComma = 1 }))
end

local config = {}

if doesFileExist("moonloader/config/RandomVehicle.json") then
    local f = io.open("moonloader/config/RandomVehicle.json")
    config = decodeJson(f:read("*a"))
    f:close()
else
	config = {["vehicle"] = {}}

	if not doesDirectoryExist('moonloader/config') then createDirectory('moonloader/config') end

    savejson(convertTableToJsonString(config), "moonloader/config/RandomVehicle.json")
end

math.randomseed( os.clock()^5 )
math.random(); math.random(); math.random()

function random(min, max)
	local rand = math.random(min, max)
    return tonumber(rand)
end

local NameModel = {[400] = "landstal", [401] = "bravura", [402] = "buffalo", [403] = "linerun", [404] = "peren", [405] = "sentinel", [406] = "dumper",
	[407] = "firetruk", [408] = "trash", [409] = "stretch", [410] = "manana", [411] = "infernus", [412] = "voodoo", [413] = "pony",
	[414] = "mule", [415] = "cheetah", [416] = "ambulan", [417] = "leviathn", [418] = "moonbeam", [419] = "esperant", [420] = "taxi",
	[421] = "washing", [422] = "bobcat", [423] = "mrwhoop", [424] = "bfinject", [425] = "hunter", [426] = "premier", [427] = "enforcer",
	[428] = "securica", [429] = "banshee", [430] = "predator", [431] = "bus", [432] = "rhino", [433] = "barracks", [434] = "hotknife",
	[435] = "artict1", [436] = "previon", [437] = "coach", [438] = "cabbie", [439] = "stallion", [440] = "rumpo", [441] = "rcbandit",
	[442] = "romero", [443] = "packer", [444] = "monster", [445] = "admiral", [446] = "squalo", [447] = "seaspar", [448] = "pizzaboy",
	[449] = "tram", [450] = "artict2", [451] = "turismo", [452] = "speeder", [453] = "reefer", [454] = "tropic", [455] = "flatbed",
	[456] = "yankee", [457] = "caddy", [458] = "solair", [459] = "topfun", [460] = "skimmer", [461] = "pcj600", [462] = "faggio",
	[463] = "freeway", [464] = "rcbaron", [465] = "rcraider", [466] = "glendale", [467] = "oceanic", [468] = "sanchez", [469] = "sparrow",
	[470] = "patriot", [471] = "quad", [472] = "coastg", [473] = "dinghy", [474] = "hermes", [475] = "sabre", [476] = "rustler",
	[477] = "zr350", [478] = "walton", [479] = "regina", [480] = "comet", [481] = "bmx", [482] = "burrito", [483] = "camper", [484] = "marquis",
	[485] = "baggage", [486] = "dozer", [487] = "maverick", [488] = "vcnmav", [489] = "rancher", [490] = "fbiranch", [491] = "virgo", [492] = "greenwoo",
	[493] = "jetmax", [494] = "hotring", [495] = "sandking", [496] = "blistac", [497] = "polmav", [498] = "boxville", [499] = "benson", [500] = "mesa",
	[501] = "rcgoblin", [502] = "hotrina", [503] = "hotrinb", [504] = "bloodra", [505] = "rnchlure", [506] = "supergt", [507] = "elegant", [508] = "journey",
	[509] = "bike", [510] = "mtbike", [511] = "beagle", [512] = "cropdust", [513] = "stunt", [514] = "petro", [515] = "rdtrain", [516] = "nebula", [517] = "majestic", [518] = "buccanee", [519] = "shamal", [520] = "hydra", [521] = "fcr900", [522] = "nrg500", [523] = "copbike", [524] = "cement", [525] = "towtruck", [526] = "fortune",
	[527] = "cadrona", [528] = "fbitruck", [529] = "willard", [530] = "forklift", [531] = "tractor", [532] = "combine", [533] = "feltzer", [534] = "remingtn", [535] = "slamvan",
	[536] = "blade", [537] = "freight", [538] = "streak", [539] = "vortex", [540] = "vincent", [541] = "bullet", [542] = "clover", [543] = "sadler", [544] = "firela", [545] = "hustler", [546] = "intruder", [547] = "primo", [548] = "cargobob", [549] = "tampa", [550] = "sunrise", [551] = "merit", [552] = "utility",
	[553] = "nevada", [554] = "yosemite", [555] = "windsor", [556] = "monstera", [557] = "monsterb", [558] = "uranus", [559] = "jester", [560] = "sultan",
	[561] = "stratum", [562] = "elegy", [563] = "raindanc", [564] = "rctiger", [565] = "flash", [566] = "tahoma", [567] = "savanna", [568] = "bandito", [569] = "freiflat",
	[570] = "streakc", [571] = "kart", [572] = "mower", [573] = "duneride", [574] = "sweeper", [575] = "broadway", [576] = "tornado", [577] = "at400", [578] = "dft30",
	[579] = "huntley", [580] = "stafford", [581] = "bf400", [582] = "newsvan", [583] = "tug", [584] = "petrotr", [585] = "emperor", [586] = "wayfarer",
	[587] = "euros", [588] = "hotdog", [589] = "club", [590] = "freibox", [591] = "artict3", [592] = "androm",
	[593] = "dodo", [594] = "rccam", [595] = "launch", [596] = "copcarla", [597] = "copcarsf", [598] = "copcarvg", [599] = "copcarru",
	[600] = "picador", [601] = "swatvan", [602] = "alpha", [603] = "phoenix", [604] = "glenshit", [605] = "sadlshit", [606] = "bagboxa",
	[607] = "bagboxb", [608] = "tugstair", [609] = "boxburg", [610] = "farmtr1", [611] = "utiltr1";}

--Taken from the sources of Custom SAA2 https://ugbase.eu/threads/samp-saa-custom-saa2-tool.4810/
local standard_car = [[400,	landstal, 	landstal, 	car, 		LANDSTAL, 	LANDSTK, 	null,	normal, 	10,	0,	0,		-1, 0.768, 0.768,	0
401, 	bravura, 	bravura, 	car, 		BRAVURA, 	BRAVURA, 	null,	poorfamily,	10, 	0,	0,		-1, 0.74, 0.74,		0
402, 	buffalo, 	buffalo, 	car, 		BUFFALO, 	BUFFALO, 	null,	executive, 	5, 	0,	0,		-1, 0.7, 0.7,		0
403, 	linerun, 	linerun, 	car, 		LINERUN, 	LINERUN, 	truck,	worker,	 	6,	0,	0,		-1, 1.1, 1.1,		-1
404, 	peren,		peren, 		car, 		PEREN, 		PEREN,	 	null,	poorfamily,	10, 	0,	0,		-1, 0.66, 0.66,		0
405, 	sentinel, 	sentinel, 	car, 		SENTINEL, 	SENTINL, 	null,	richfamily, 	10, 	0,	0,		-1, 0.7, 0.7,		0
406, 	dumper,		dumper,	 	mtruck, 	DUMPER,		DUMPER,		truck,	worker,	 	5,	1,	0,		-1, 2.28, 2.28,		-1
407, 	firetruk, 	firetruk, 	car, 		FIRETRUK, 	FIRETRK, 	truck,	ignore,		10,	0,	0,		-1, 1.0, 1.0,		-1
408, 	trash,		trash,	 	car, 		TRASH, 		TRASHM,		null,	worker,	 	5,	0,	0,		-1, 1.06, 1.06,		-1
409, 	stretch,	stretch, 	car, 		STRETCH, 	STRETCH, 	null,	executive, 	5,	0,	0,		-1, 0.75, 0.75,		0
410, 	manana, 	manana, 	car, 		MANANA, 	MANANA, 	null,	poorfamily,	10, 	0,	0,		-1, 0.62, 0.62,		0
411, 	infernus, 	infernus, 	car, 		INFERNUS, 	INFERNU, 	null,	executive, 	5, 	0,	0,		-1, 0.7, 0.7,		0
412, 	voodoo, 	voodoo, 	car, 		VOODOO, 	VOODOO, 	null,	poorfamily,	10, 	0,	0,		-1, 0.7, 0.7,		0
413, 	pony,		pony,		car, 		PONY, 		PONY, 		van,	worker,		10, 	0,	0,		-1, 0.72, 0.72,		-1
414, 	mule, 		mule, 		car, 		MULE, 		MULE, 		null,	worker, 	10, 	0,	0,		-1, 0.76, 0.76,		-1
415, 	cheetah, 	cheetah, 	car, 		CHEETAH, 	CHEETAH, 	null,	executive, 	5, 	0,	0,		-1, 0.68, 0.68,		0
416, 	ambulan, 	ambulan, 	car, 		AMBULAN, 	AMBULAN, 	van,	ignore,		10,	0,	0,		-1, 0.864, 0.864,	-1
417, 	leviathn, 	leviathn, 	heli, 		LEVIATHN, 	LEVIATH, 	null,	ignore,		5,	0,	0,		-1, 0.54, 0.4,		-1
418, 	moonbeam, 	moonbeam, 	car, 		MOONBEAM, 	MOONBM, 	null,	normal,		10, 	0,	0,		-1, 0.7, 0.7,		0
419, 	esperant, 	esperant, 	car, 		ESPERANT, 	ESPERAN, 	null,	normal,		10, 	0,	0,		-1, 0.64, 0.64,		0
420, 	taxi, 		taxi, 		car, 		TAXI, 		TAXI, 		null,	taxi,		10, 	0,	1f10,		-1, 0.7, 0.7,		0
421, 	washing, 	washing, 	car, 		WASHING, 	WASHING, 	null,	richfamily,	10, 	0,	0,		-1, 0.65, 0.65,		0
422, 	bobcat, 	bobcat, 	car, 		BOBCAT, 	BOBCAT, 	null,	worker, 	10, 	0,	0,		-1, 0.7, 0.7,		0
423, 	mrwhoop, 	mrwhoop, 	car, 		MRWHOOP, 	WHOOPEE, 	null,	worker, 	4,	1,	0,		-1, 0.7, 0.7,		-1
424, 	bfinject, 	bfinject, 	car, 		BFINJECT, 	BFINJC,	 	BF_injection,	executive,	6,	0,	0,		-1, 0.84, 0.92,		-1
425, 	hunter,		hunter, 	heli, 		HUNTER, 	HUNTER,		rustler,ignore,		10,	0,	0,		-1, 0.64, 0.4,		-1
426, 	premier, 	premier, 	car, 		PREMIER, 	PREMIER,	null,	richfamily,		10,	0,	0,		-1, 0.7, 0.7,		0
427, 	enforcer, 	enforcer, 	car, 		ENFORCER, 	ENFORCR, 	van,	ignore,		10,	0,	0,		-1, 0.936, 0.936,	-1
428, 	securica, 	securica, 	car, 		SECURICA, 	SECURI, 	van,	big,	 	4, 	0,	3f10,		-1, 0.914, 0.914,	-1
429, 	banshee, 	banshee, 	car, 		BANSHEE,	BANSHEE, 	null,	executive, 	5, 	0,	0,		-1, 0.7, 0.7,		0
430, 	predator, 	predator, 	boat,		PREDATOR,	PREDATR, 	null,	ignore,		10,	0,	0
431, 	bus, 		bus,	 	car, 		BUS, 		BUS, 		bus,	normal,	 	5, 	0,	0,		-1, 1, 1,		-1
432, 	rhino, 		rhino, 		car, 		RHINO, 		RHINO, 		tank,	ignore,		10, 	0,	0,		-1, 1.3, 1.3,		-1
433, 	barracks, 	barracks, 	car, 		BARRACKS, 	BARRCKS, 	truck,	ignore,		4, 	0,	1f10,		-1, 1.2, 1.2,		-1
434, 	hotknife, 	hotknife, 	car, 		HOTKNIFE, 	HOTKNIF, 	null,	executive, 	4, 	0,	0,		-1, 0.72, 0.8,		-1
435, 	artict1, 	artict1, 	trailer,	ARTICT1, 	ARTICT1, 	null,	ignore,	 	6,	0,	0,		-1, 1.1, 1.1,		-1
436, 	previon, 	previon, 	car, 		PREVION, 	PREVION, 	null,	poorfamily,	10, 	0,	0,		-1, 0.7, 0.7,		0
437,	coach, 		coach, 		car, 		COACH, 		COACH, 		coach,	normal,	 	5,	0,	1f10,		-1, 1.0, 1.0,		-1
438, 	cabbie, 	cabbie, 	car, 		CABBIE, 	CABBIE, 	null,	taxi,	 	6, 	0,	1f10,		-1, 0.7, 0.7,		0
439, 	stallion, 	stallion, 	car, 		STALLION, 	STALION, 	null,	poorfamily,	10, 	0,	3210,		-1, 0.7, 0.7,		0
440, 	rumpo, 		rumpo, 		car, 		RUMPO, 		RUMPO, 		van,	poorfamily, 	10,	0,	0,		-1, 0.7, 0.7,		-1
441, 	rcbandit, 	rcbandit, 	car, 		RCBANDIT, 	RCBANDT, 	null,	ignore,		1, 	0,	0,		-1, 0.25, 0.25,		-1
442, 	romero,		romero, 	car, 		ROMERO,		ROMERO,	 	null,	normal,		4, 	0,	0,		-1, 0.68, 0.68,		0
443, 	packer, 	packer, 	car, 		PACKER, 	PACKER, 	truck,	worker,	 	5,	0,	0,		-1, 1.082, 1.082,	-1
444,	monster, 	monster, 	mtruck,		MONSTER, 	MONSTER, 	truck,	ignore,		1,	0,	0,		-1, 1.5, 1.5,		-1
445, 	admiral, 	admiral, 	car, 		ADMIRAL, 	ADMIRAL, 	null,	richfamily, 	10,	0,	0,		-1, 0.68, 0.68,		0
446, 	squalo, 	squalo, 	boat,		SQUALO,		SQUALO, 	null,	ignore,		10,	0, 	0,
447, 	seaspar,	seaspar, 	heli, 		SEASPAR, 	SEASPAR,	null,	ignore,		10,	0,	0,		-1, 0.7, 0.7,		-1
448,	pizzaboy,	pizzaboy,	bike,		MOPED,		PIZZABO,	bikev,	normal,		4,	1,	0,		16, 0.464, 0.464,	-1
449, 	tram, 		tram, 		train, 		TRAM,		TRAM, 		van,	ignore,		10,	0,	1012,		-1, 0.78, 0.78,		-1
450, 	artict2, 	artict2, 	trailer,	ARTICT2, 	ARTICT2, 	null,	ignore,	 	6,	0,	0,		-1, 1.1, 1.1,		-1
451, 	turismo, 	turismo, 	car, 		TURISMO, 	TURISMO, 	null,	executive, 	4, 	0,	0,		-1, 0.7, 0.75,		0
452, 	speeder, 	speeder, 	boat,		SPEEDER,	SPEEDER, 	null,	leisureboat,	10,	0, 	4fff
453, 	reefer, 	reefer, 	boat,		REEFER,		REEFER, 	null,	workerboat,	10,	0,	3f01
454, 	tropic, 	tropic, 	boat,		TROPIC,		TROPIC, 	null,	leisureboat,	10,	0,	4fff
455, 	flatbed, 	flatbed, 	car, 		FLATBED, 	FLATBED, 	truck,	worker,		5, 	0,	4fff,		-1, 1.2, 1.2,		-1
456, 	yankee, 	yankee, 	car, 		YANKEE, 	YANKEE, 	null,	worker, 	10, 	0,	0,		-1, 0.84, 0.84,		-1
457,	caddy, 		caddy, 		car, 		GOLFCART, 	CADDY, 		null,	richfamily,	1,	0,	30123345,	-1, 0.5, 0.5,		-1
458, 	solair, 	solair, 	car, 		SOLAIR, 	SOLAIR, 	null,	normal,		10, 	0,	0,		-1, 0.72, 0.72,		0
459,	topfun,		topfun,		car,		TOPFUN,		TOPFUN,		van,	ignore,		1,	0,	0,		-1, 0.7, 0.7,		-1
460, 	skimmer,	skimmer, 	plane,		SEAPLANE,	SKIMMER,	null,	ignore,		5,	0,	0
461,	pcj600,		pcj600,		bike,		BIKE,		PCJ600,		bikes,	motorbike,	10,	0,	0,		16, 0.67, 0.67,		-1
462,	faggio,		faggio,		bike,		MOPED,		FAGGIO,		bikev,	moped,		10,	0,	0,		16, 0.464, 0.464,	-1
463,	freeway,	freeway,	bike,		FREEWAY,	FREEWAY,	bikeh,	motorbike,	10,	0,	0,		23, 0.654, 0.654,	-1
464, 	rcbaron, 	rcbaron, 	plane, 		RCBARON, 	RCBARON, 	null,	ignore,		1,	0,	0,		-1, 0.25, 0.25,		-1
465, 	rcraider, 	rcraider, 	heli, 		RCRAIDER, 	RCRAIDE, 	null,	ignore,		1,	0,	0,		-1, 0.25, 0.25,		-1
466, 	glendale, 	glendale, 	car, 		GLENDALE, 	GLENDAL, 	null,	normal,		10, 	0,	0,		-1, 0.7, 0.7,		0
467, 	oceanic, 	oceanic, 	car, 		OCEANIC, 	OCEANIC, 	null,	normal,		10, 	0,	0,		-1, 0.7, 0.7,		0
468,	sanchez,	sanchez,	bike,		DIRTBIKE,	SANCHEZ,	biked,	motorbike,	5,	0,	0,		23, 0.68, 0.62,		-1
469, 	sparrow,	sparrow, 	heli, 		SPARROW, 	SPARROW,	null,	ignore,		10,	0,	0,		-1, 0.7, 0.7,		-1
470,	patriot, 	patriot, 	car, 		PATRIOT, 	PATRIOT, 	null,	ignore,		2,	0,	0,		-1, 0.894, 0.894,	-1
471,	quad,		quad,		quad, 		QUADBIKE, 	QUAD,	 	quad, 	normal,		4,	0,	0,		-1, 0.6, 0.6,		-1
472, 	coastg, 	coastg, 	boat,		COASTGRD,	COASTG, 	null,	ignore,		5,	0, 	3012
473, 	dinghy, 	dinghy, 	boat,		DINGHY,		DINGHY, 	null,	workerboat,	7,	0, 	0
474, 	hermes, 	hermes, 	car, 		HERMES, 	HERMES, 	null,	richfamily,	4, 	0,	0,		-1, 0.7, 0.7,		0
475, 	sabre, 		sabre, 		car, 		SABRE,	 	SABRE, 		null,	normal,		10, 	0,	2ff0,		-1, 0.7, 0.7,		0
476, 	rustler, 	rustler, 	plane, 		RUSTLER, 	RUSTLER,	rustler,ignore,		10,	0,	0,		-1, 0.6, 0.3,		-1
477, 	zr350, 		zr350, 		car, 		ZR350,		ZR350, 		null,	richfamily, 	10, 	0,	0,		-1, 0.76, 0.76,		0
478, 	walton, 	walton, 	car, 		WALTON, 	WALTON, 	null,	worker, 	6, 	0,	0,		-1, 0.7, 0.7,		0
479, 	regina, 	regina, 	car, 		REGINA, 	REGINA, 	null,	normal,		10, 	0,	0,		-1, 0.7, 0.7,		0
480,	comet,		comet,		car, 		COMET,	 	COMET, 		null,	executive, 	5, 	0,	2ff0,		-1, 0.7, 0.7,		0
481,	bmx,		bmx,		bmx, 		BMX,	 	BMX, 		bmx,	bicycle,	5,	0,	0,		23, 0.54, 0.54,		-1
482, 	burrito, 	burrito, 	car, 		BURRITO,	BURRITO, 	van,	normal, 	10,	0,	0,		-1, 0.7, 0.7,		-1
483, 	camper, 	camper, 	car, 		CAMPER, 	CAMPER, 	van,	normal, 	4,	0,	0,		-1, 0.66, 0.66,		-1
484, 	marquis, 	marquis, 	boat,		MARQUIS,	MARQUIS, 	null,	workerboat,	10,	0,	0
485, 	baggage,	baggage,	car, 		BAGGAGE,	BAGGAGE, 	null,	normal,		4, 	0,	0,		-1, 0.6, 0.6,		-1
486, 	dozer, 		dozer, 		car, 		DOZER, 		DOZER, 		dozer,	ignore, 	4, 	0,	0,		-1, 1.5, 1.5,		-1
487, 	maverick,	maverick, 	heli, 		MAVERICK,	MAVERIC,	null,	ignore,		10,	0,	0,		-1, 0.7, 0.7,		-1
488, 	vcnmav,		vcnmav, 	heli, 		COASTMAV, 	SANMAV,		null,	ignore,		6,	0,	0,		-1, 0.7, 0.7,		-1
489,	rancher, 	rancher, 	car,		RANCHER, 	RANCHER, 	null,	normal,		10,	0,	0,		-1, 0.9, 0.9,		0
490,	fbiranch, 	fbiranch, 	car, 		FBIRANCH, 	FBIRANC, 	null,	ignore, 	3,	0,	0,		-1, 0.92, 0.92,		-1
491, 	virgo, 		virgo, 		car, 		VIRGO,	 	VIRGO, 		null,	normal,		10, 	0,	0,		-1, 0.65, 0.65,		0
492, 	greenwoo, 	greenwoo, 	car, 		GREENWOO, 	GREENWO, 	null,	poorfamily,	10, 	0,	0,		-1, 0.7, 0.7,		0
493, 	jetmax, 	jetmax, 	boat,		CUPBOAT,	JETMAX, 	null,	ignore,		8,	0, 	0
494,	hotring, 	hotring, 	car, 		HOTRING, 	HOTRING, 	null,	ignore, 	1,	0,	0,		-1, 0.82, 0.82,		-1
495,	sandking, 	sandking, 	car, 		SANDKING, 	SANDKIN, 	null,	ignore, 	4,	0,	0,		-1, 0.972, 0.972,		-1
496,	blistac, 	blistac, 	car, 		BLISTAC, 	BLISTAC, 	null,	normal, 	10,	0,	0,		-1, 0.7, 0.7,		0
497, 	polmav,		polmav, 	heli, 		POLMAV, 	POLMAV,		null,	ignore,		10,	0,	0,		-1, 0.7, 0.7,		-1
498, 	boxville, 	boxville, 	car, 		BOXVILLE,	BOXVILL, 	van,	worker, 	10, 	0,	0,		-1, 0.76, 0.76,		-1
499, 	benson, 	benson, 	car, 		BENSON,		BENSON, 	null,	worker, 	10, 	0,	0,		-1, 0.8, 0.8,		-1
500,	mesa, 		mesa, 		car, 		MESA,	 	MESAA, 		null,	normal, 	8,	0,	0,		-1, 0.8, 0.8,		0
501, 	rcgoblin, 	rcgoblin, 	heli, 		RCGOBLIN, 	RCGOBLI, 	null,	ignore,		1,	0,	0,		-1, 0.25, 0.25,		-1
502,	hotrina, 	hotrina, 	car, 		HOTRING, 	HOTRINA, 	null,	ignore, 	1,	0,	4fff,		-1, 0.82, 0.82,		-1
503,	hotrinb, 	hotrinb, 	car, 		HOTRING, 	HOTRINB, 	null,	ignore, 	1,	0,	4fff,		-1, 0.82, 0.82,		-1
504, 	bloodra, 	bloodra, 	car, 		BLOODRA, 	BLOODRA, 	BF_injection,	ignore,		1, 	0,	4fff,		-1, 0.7, 0.7,		-1
505,	rnchlure, 	rnchlure, 	car,		RANCHER, 	RANCHER, 	null,	normal,		10,	0,	0,		-1, 0.9, 0.9,		-1
506, 	supergt, 	supergt, 	car, 		SUPERGT, 	SUPERGT, 	null,	executive, 	5, 	0,	0,		-1, 0.7, 0.7,		0
507, 	elegant, 	elegant, 	car, 		ELEGANT, 	ELEGANT, 	null,	normal,		10, 	0,	0,		-1, 0.7, 0.7,		0
508, 	journey, 	journey, 	car, 		JOURNEY,	JOURNEY, 	null,	worker, 	4, 	0,	0,		-1, 0.8, 0.8,		-1
509,	bike,		bike,		bmx, 		CHOPPERB, 	BIKE, 		choppa,	bicycle,	7,	0,	0,		23, 0.526, 0.612,	-1
510,	mtbike,		mtbike,		bmx, 		MTB,	 	MTBIKE, 	mtb,	bicycle,	7,	0,	0,		23, 0.68, 0.68,		-1
511, 	beagle, 	beagle, 	plane, 		BEAGLE, 	BEAGLE,		van,	ignore,		10,	0,	0,		-1, 0.52, 0.52,		-1
512, 	cropdust, 	cropdust, 	plane, 		CROPDUST, 	CROPDST,	rustler,	ignore,		6,	0,	0,		-1, 0.7, 0.3,		-1
513, 	stunt, 		stunt, 		plane, 		STUNT,	 	STUNT,		rustler,	ignore,		6,	0,	0,		-1, 0.48, 0.48,		-1
514, 	petro, 		petro, 		car, 		PETROL, 	PETROL, 	truck,	worker,	 	5,	0,	0,		-1, 1.106, 1.106,	-1
515, 	rdtrain, 	rdtrain, 	car, 		RDTRAIN, 	RDTRAIN, 	truck,	worker,	 	5,	0,	0,		-1, 1.18, 1.18,		-1
516, 	nebula, 	nebula, 	car, 		NEBULA, 	NEBULA, 	null,	poorfamily,	10, 	0,	0,		-1, 0.75, 0.75,		0
517, 	majestic, 	majestic, 	car, 		MAJESTIC, 	MAJESTC, 	null,	poorfamily,	10, 	0,	0,		-1, 0.75, 0.75,		0
518, 	buccanee, 	buccanee, 	car, 		BUCCANEE, 	BUCCANE, 	null,	normal,		10, 	0,	0,		-1, 0.66, 0.66,		0
519, 	shamal, 	shamal, 	plane, 		SHAMAL, 	SHAMAL,		shamal,	ignore,		5,	0,	0,		-1, 0.62, 0.62,		-1
520, 	hydra, 		hydra, 		plane, 		HYDRA,	 	HYDRA,		rustler,	ignore,		4,	0,	0,		-1, 0.7, 0.3,		-1
521,	fcr900,		fcr900,		bike,		FCR900,		FCR900,		bikes,	motorbike,	6,	0,	3f341210,		16, 0.68, 0.68,		-1
522,	nrg500,		nrg500,		bike,		NRG500,		NRG500,		bikes,	motorbike,	10,	0,	1f341210,		16, 0.68, 0.68,		-1
523,	copbike,	copbike,	bike,		HPV1000,	HPV1000,	bikes,	ignore,		10,	0,	0,		16, 0.68, 0.68,		-1
524, 	cement,		cement,	 	car, 		CEMENT,		CEMENT,		null,	worker,	 	4,	0,	0,		-1, 1.12, 1,		-1
525, 	towtruck,	towtruck,	car, 		TOWTRUCK,	TOWTRUK, 	van,	worker,		5, 	0,	0,		-1, 0.92, 0.92,		-1
526, 	fortune, 	fortune, 	car, 		FORTUNE, 	FORTUNE, 	null,	normal,		10, 	0,	0,		-1, 0.7, 0.7,		0
527, 	cadrona, 	cadrona, 	car, 		CADRONA, 	CADRONA, 	null,	poorfamily,	10, 	0,	0,		-1, 0.7, 0.7,		0
528, 	fbitruck, 	fbitruck, 	car, 		FBITRUCK, 	FBITRUK, 	van,	big,	 	4, 	0,	0,		-1, 0.85, 0.85,		-1
529, 	willard, 	willard, 	car, 		WILLARD, 	WILLARD, 	null,	normal,		10, 	0,	0,		-1, 0.7, 0.7,		0
530, 	forklift,	forklift,	car, 		FORKLIFT,	FORKLFT, 	null,	worker,		1, 	0,	0,		-1, 0.45, 0.45,		-1
531, 	tractor,	tractor,	car, 		TRACTOR,	TRACTOR, 	null,	normal,		5, 	0,	0,		-1, 0.68, 1.3,		-1
532, 	combine,	combine,	car, 		COMBINE, 	COMBINE,	truck,	ignore,	 	5,	0,	0,		-1, 0.588, 1,		-1
533,	feltzer,	feltzer,	car, 		FELTZER, 	FELTZER, 	null,	executive, 	10, 	0,	0,		-1, 0.7, 0.7,		0
534, 	remingtn, 	remingtn, 	car, 		REMINGTN, 	REMING, 	null,	executive,	10, 	0,	0,		-1, 0.7, 0.7,		2
535, 	slamvan, 	slamvan, 	car, 		SLAMVAN, 	SLAMVAN, 	null,	richfamily,	5, 	0,	1f10,		-1, 0.74, 0.74,		2
536, 	blade, 		blade, 		car, 		BLADE,	 	BLADE, 		null,	executive,	7, 	0,	0,		-1, 0.7, 0.7,		2
537, 	freight,	freight,	train, 		FREIGHT,	FREIGHT,	truck,	ignore,	 	10,	0,	0,		-1, 1.06, 1.06,		-1
538, 	streak,		streak,	 	train, 		STREAK, 	STREAK,		truck,	ignore,	 	10,	0,	0,		-1, 1.06, 1.06,		-1
539, 	vortex, 	vortex, 	plane, 		VORTEX,		VORTEX, 	vortex,	ignore, 	4,	0,	0,		-1, 0.7, 0.7,		-1
540, 	vincent, 	vincent, 	car, 		VINCENT, 	VINCENT, 	null,	normal,		10, 	0,	0,		-1, 0.7, 0.7,		0
541, 	bullet,		bullet,		car, 		BULLET,		BULLET, 	null,	executive,	4, 	0,	0,		-1, 0.7, 0.75,		0
542, 	clover, 	clover, 	car, 		CLOVER,	 	CLOVER, 	null,	poorfamily,	10, 	0,	0,		-1, 0.74, 0.74,		0
543,	sadler,		sadler,		car, 		SADLER,	 	SADLER, 	null,	normal, 	10, 	0,	0,		-1, 0.7, 0.7,		-1
544, 	firela, 	firela, 	car, 		FIRETRUK, 	FIRELA, 	truck,	ignore,		10,	0,	0,		-1, 1.0, 1.0,		-1
545, 	hustler, 	hustler, 	car, 		HUSTLER, 	HUSTLER, 	null,	normal,		4, 	0,	0,		-1, 0.7, 0.7,		0
546, 	intruder, 	intruder, 	car, 		INTRUDER, 	INTRUDR, 	null,	normal,		10, 	0,	0,		-1, 0.7, 0.7,		0
547, 	primo, 		primo, 		car, 		PRIMO,	 	PRIMO, 		null,	normal,		10, 	0,	0,		-1, 0.7, 0.7,		0
548, 	cargobob, 	cargobob, 	heli, 		CARGOBOB, 	CARGOBB, 	null,	ignore,		5,	0,	0,		-1, 0.74, 0.74,		-1
549,	tampa,		tampa,		car,		TAMPA,		TAMPA,		null,	poorfamily,	10, 	0,	0,		-1, 0.684, 0.684,	0
550, 	sunrise, 	sunrise, 	car, 		SUNRISE, 	SUNRISE, 	null,	normal,		10, 	0,	0,		-1, 0.76, 0.76,		0
551, 	merit, 		merit, 		car, 		MERIT,	 	MERIT, 		null,	richfamily,	10, 	0,	0,		-1, 0.75, 0.75,		0
552, 	utility,	utility,	car, 		UTILITY, 	UTILITY, 	van,	worker,		5, 	0,	0,		-1, 0.84, 0.84,		-1
553, 	nevada, 	nevada, 	plane, 		NEVADA, 	NEVADA,		nevada,	ignore,		4,	0,	0,		-1, 0.85, 0.4,		-1
554,	yosemite, 	yosemite, 	car, 		YOSEMITE,	YOSEMIT, 	null,	normal, 	10,	0,	0,		-1, 0.84, 0.84,		-1
555,	windsor,	windsor,	car, 		WINDSOR, 	WINDSOR, 	null,	executive, 	4, 	0,	0,		-1, 0.7, 0.7,		0
556,	monstera, 	monstera, 	mtruck,		MTRUCK_A, 	MONSTA, 	truck,	ignore,		1,	0,	0,		-1, 1.5, 1.5,		-1
557,	monsterb, 	monsterb, 	mtruck,		MTRUCK_B, 	MONSTB, 	truck,	ignore,		1,	0,	0,		-1, 1.5, 1.5,		-1
558,	uranus,		uranus,		car, 		URANUS, 	URANUS, 	null,	richfamily, 	7, 	0,	0,		-1, 0.7, 0.7,		1
559,	jester,		jester,		car, 		JESTER, 	JESTER, 	null,	richfamily, 	7, 	0,	0,		-1, 0.7, 0.7,		1
560,	sultan,		sultan,		car, 		SULTAN, 	SULTAN, 	null,	richfamily, 	7, 	0,	0,		-1, 0.7, 0.7,		1
561,	stratum,	stratum,	car, 		STRATUM, 	STRATUM, 	null,	richfamily, 	7, 	0,	0,		-1, 0.7, 0.7,		1
562,	elegy,		elegy,		car, 		ELEGY,	 	ELEGY, 		null,	richfamily, 	7, 	0,	0,		-1, 0.68, 0.68,		1
563, 	raindanc, 	raindanc, 	heli, 		RAINDANC, 	RAINDNC, 	null,	ignore,		7,	0,	0,		-1, 0.64, 0.64,		-1
564, 	rctiger, 	rctiger, 	car, 		RCTIGER, 	RCTIGER, 	null,	ignore,		1, 	0,	0,		-1, 0.25, 0.25,		-1
565,	flash,		flash,		car, 		FLASH,	 	FLASH, 		null,	richfamily, 	7, 	0,	0,		-1, 0.64, 0.64,		1
566,	tahoma,		tahoma,		car, 		TAHOMA, 	TAHOMA, 	null,	richfamily, 	10, 	0,	0,		-1, 0.7, 0.7,		0
567, 	savanna, 	savanna, 	car, 		SAVANNA, 	SAVANNA, 	null,	poorfamily,	7, 	0,	2ff0,		-1, 0.7, 0.7,		2
568, 	bandito, 	bandito, 	car, 		BANDITO, 	BANDITO,	null,	ignore,		4,	0,	0,		-1, 0.55, 0.7,		-1
569, 	freiflat,	freiflat,	train, 		FREIFLAT,	FRFLAT,		null,	ignore,	 	10,	0,	0,		-1, 1.06, 1.06,		-1
570, 	streakc,	streakc,	train, 		CSTREAK,	STREAKC,	coach,	ignore,	 	10,	0,	0,		-1, 1.06, 1.06,		-1
571, 	kart, 		kart, 		car, 		KART, 		KART,		KART,	ignore,		4,	0,	0,		-1, 0.26, 0.26,		-1
572,	mower, 		mower, 		car, 		MOWER,	 	MOWER,		null,	ignore,		4,	0,	0,		-1, 0.48, 0.56,		-1
573,	duneride, 	duneride, 	mtruck,		DUNE,	 	DUNE, 		truck,	ignore,		4,	0,	0,		-1, 1.14, 1.14,		-1
574,	sweeper, 	sweeper, 	car, 		SWEEPER, 	SWEEPER,	null,	worker,		4,	0,	0,		-1, 0.5, 0.5,		-1
575, 	broadway, 	broadway, 	car, 		BROADWAY, 	BROADWY, 	null,	poorfamily,	7, 	0,	2ff0,		-1, 0.7, 0.7,		2
576, 	tornado, 	tornado, 	car, 		TORNADO, 	TORNADO, 	null,	poorfamily,	7, 	0,	2ff0,		-1, 0.7, 0.7,		2
577, 	at400, 		at400, 		plane, 		AT400,	 	AT400,		coach,	ignore,		10,	0,	0,		-1, 1.12, 1.12,		-1
578, 	dft30,		dft30,		car, 		DFT30,	 	DFT30, 		truck,	worker,		10, 	0,	4fff,		-1, 1, 1,		-1
579,	huntley, 	huntley, 	car,		HUNTLEY, 	HUNTLEY, 	null,	richfamily,		6,	7,	0,	-1, 0.90, 0.90,		0
580, 	stafford, 	stafford, 	car, 		STAFFORD, 	STAFFRD, 	null,	normal,		4, 	0,	0,		-1, 0.78, 0.78,		0
581,	bf400,		bf400,		bike,		BF400,		BF400,		bikes,	motorbike,	10,	0,	3f341210,		16, 0.68, 0.68,		-1
582,	newsvan,	newsvan,	car,		NEWSVAN,	NEWSVAN,	van,	normal,		4,	0,	0,		-1, 0.77, 0.77,		-1
583,	tug, 		tug, 		car, 		TUG, 		TUG,		null,	normal,		4,	0,	0,		-1, 0.66, 0.75,		-1
584, 	petrotr, 	petrotr, 	trailer,	PETROTR, 	PETROTR, 	null,	ignore,	 	6,	0,	0,		-1, 1.12, 1.12,		-1
585,	emperor,		emperor, 	car, 		EMPEROR, 	EMPEROR, 	null,	normal,		10, 	0,	0,		-1, 0.74, 0.74,		0
586,	wayfarer,	wayfarer,	bike,		WAYFARER,	WAYFARE,	wayfarer,motorbike,	6,	0,	0,		23, 0.654, 0.654,	-1
587, 	euros,		euros,		car, 		EUROS,	 	EUROS, 		null,	richfamily, 	10, 	0,	0,		-1, 0.7, 0.7,		0
588, 	hotdog, 	hotdog, 	car, 		HOTDOG,		HOTDOG, 	van,	worker, 	4, 	0,	0,		-1, 0.86, 0.86,		-1
589,	club, 		club, 		car, 		CLUB,	 	CLUB, 		null,	normal, 	8,	0,	0,		-1, 0.74, 0.74,		0
590, 	freibox,	freibox,	train, 		FREIFLAT,	FRBOX,		null,	ignore,	 	10,	0,	0,		-1, 1.06, 1.06,		-1
591, 	artict3, 	artict3, 	trailer,	ARTICT3, 	ARTICT3, 	null,	ignore,	 	6,	0,	0,		-1, 1.1, 1.1,		-1
592, 	androm, 	androm, 	plane, 		ANDROM, 	ANDROM,		null,	ignore,		4,	0,	0,		-1, 0.95, 0.95,		-1
593,	dodo,		dodo, 		plane, 		DODO,	 	DODO,		van,	ignore,		10,	0,	0,		-1, 0.56, 0.56,		-1
594, 	rccam, 		rccam, 		car, 		RCCAM,	 	RCCAM, 		null,	ignore,		1, 	0,	0,		-1, 0.25, 0.25,		-1
595, 	launch, 	launch, 	boat,		LAUNCH,		LAUNCH, 	null,	leisureboat,	10,	0, 	0
596, 	copcarla, 	copcarla, 	car, 		POLICE_LA, 	POLICAR,	null,	ignore,		10,	0,	0,		-1, 0.7, 0.7,	-1
597, 	copcarsf, 	copcarsf, 	car, 		POLICE_SF, 	POLICAR,	null,	ignore,		10,	0,	0,		-1, 0.7, 0.7,	-1
598, 	copcarvg,	copcarvg,	car, 		POLICE_VG, 	POLICAR,	null,	ignore,		10,	0,	0,		-1, 0.7, 0.7,	-1
599, 	copcarru,	copcarru,	car, 		POLRANGER, 	RANGER,		null,	ignore,		10,	0,	0,		-1, 0.95, 0.95,	-1
600,	picador,	picador,	car, 		PICADOR, 	PICADOR, 	null,	normal, 	10, 	0,	0,		-1, 0.7, 0.7,		0
601, 	swatvan, 	swatvan, 	car, 		SWATVAN, 	SWATVAN, 	van,	big,	 	4, 	0,	0,		-1, 1.366, 1.366,	-1
602,	alpha,		alpha,		car, 		ALPHA,		ALPHA, 		null,	executive, 	10, 	0,	0,		-1, 0.7, 0.7,		0
603, 	phoenix, 	phoenix, 	car, 		PHOENIX, 	PHOENIX, 	null,	normal,		7, 	0,	0,		-1, 0.7, 0.7,		0
604, 	glenshit, 	glenshit, 	car, 		GLENDALE, 	GLENSHI, 	null,	normal,		5, 	0,	0,		-1, 0.7, 0.7,		-1
605,	sadlshit,	sadlshit,	car, 		SADLER,	 	SADLSHI, 	null,	normal, 	10, 	0,	0,		-1, 0.7, 0.7,		-1
606, 	bagboxa, 	bagboxa, 	trailer,	BAGBOXA, 	BAGBOXA, 	null,	ignore,	 	4,	0,	0,		-1, 0.6, 0.6,		-1
607, 	bagboxb, 	bagboxb, 	trailer,	BAGBOXB, 	BAGBOXB, 	null,	ignore,	 	4,	0,	0,		-1, 0.6, 0.6,		-1
608, 	tugstair, 	tugstair, 	trailer,	STAIRS, 	TUGSTAI, 	null,	ignore,	 	4,	0,	0,		-1, 0.6, 0.6,		-1
609, 	boxburg, 	boxburg, 	car, 		BOXBURG,	BOXBURG, 	van,	worker, 	10, 	0,	0,		-1, 0.76, 0.76,		-1
610, 	farmtr1, 	farmtr1, 	trailer,	FARM_TR1, 	FARMTR1, 	null,	ignore,	 	4,	0,	0,		-1, 0.32, 0.32,		-1
611, 	utiltr1, 	utiltr1, 	trailer,	UTIL_TR1, 	UTILTR1, 	null,	ignore,	 	4,	0,	0,		-1, 0.68, 0.68,		-1]]

local audiosettings = [[landstal 0 99 98 0 0.78 1.0 7 1.0 2 0 8 0 0 0.0
bravura 0 8 7 0 0.7 1.0 2 1.18921 2 0 5 0 1 0.0
buffalo 0 38 37 1 0.9 1.0 2 1.05946 2 0 7 0 2 0.0
linerun 0 84 83 0 0.0 1.0 9 0.840896 3 0 2 0 3 6.0
peren 0 95 94 0 0.78 1.0 7 1.12246 1 0 9 0 4 0.0
sentinel 0 87 86 0 0.85 1.0 3 0.943874 2 0 4 0 45 0.0
dumper 0 84 83 0 0.7 0.840896 4 0.793701 3 0 2 0 6 6.0
firetruk 0 84 83 0 0.7 1.0 4 0.890899 3 0 13 3 7 5.0
trash 0 81 80 0 0.7 1.0 5 0.890899 3 0 3 0 8 0.0
stretch 0 87 86 0 0.85 1.0 2 1.0 2 0 10 0 9 0.0
manana 0 95 94 0 0.7 1.0 1 1.05946 1 0 4 0 1 0.0
infernus 0 38 37 1 0.9 1.0 8 1.12246 2 0 6 0 2 0.0
voodoo 0 46 45 0 1.0 1.0 2 1.12246 1 0 6 0 10 0.0
pony 0 137 136 0 0.78 1.0 2 1.25992 4 0 1 0 11 0.0
mule 0 137 136 0 0.7 1.33484 7 0.943874 4 0 2 0 11 5.0
cheetah 0 103 102 1 0.9 1.0 8 1.0 2 0 5 0 2 0.0
ambulan 0 137 136 0 0.7 1.0 7 0.943874 4 0 13 3 12 0.0
leviathn 4 12 -1 0 0.7 1.0 -1 1.0 0 0 3 0 13 0.0
moonbeam 0 95 94 0 0.7 1.0 1 0.890899 4 0 11 0 11 0.0
esperant 0 93 92 0 0.7 1.0 2 1.05946 1 0 10 0 1 0.0
taxi 0 87 86 0 0.85 1.0 5 1.12246 2 0 8 0 14 0.0
washing 0 95 94 0 0.7 1.0 3 0.890899 2 0 11 0 45 0.0
bobcat 0 95 94 0 0.78 1.0 7 1.0 4 0 7 0 15 0.0
mrwhoop 0 79 141 0 0.7 1.0 5 0.943874 4 0 13 0 16 0.0
bfinject 0 76 75 0 0.9 1.0 6 0.890899 -1 0 6 0 17 0.0
hunter 4 12 -1 0 0.85 1.0 -1 1.0 0 0 3 0 13 0.0
premier 0 87 86 0 0.78 1.0 8 1.0 2 0 8 0 45 0.0
enforcer 0 81 80 0 0.7 1.33484 9 1.12246 3 0 13 3 18 0.0
securica 0 137 136 0 0.7 1.0 4 0.890899 4 0 4 0 11 0.0
banshee 0 103 102 1 1.0 1.0 3 1.05946 2 0 7 0 2 0.0
predator 3 22 21 0 0.7 1.0 -1 1.0 -1 0 7 0 19 0.0
bus 0 33 32 0 0.7 1.0 5 0.840896 -1 0 10 0 20 0.0
rhino 0 84 83 0 0.9 1.0 9 0.890899 3 0 13 -1 21 6.0
barracks 0 81 80 0 0.7 1.0 9 0.943874 3 0 13 -1 6 0.0
hotknife 0 76 75 0 0.7 1.0 3 1.12246 1 0 1 0 17 0.0
artict1 9 -1 -1 0 0.7 1.0 -1 1.0 -1 0 13 1 -1 0.0
previon 0 8 7 0 0.78 1.0 1 0.890899 2 0 8 0 1 0.0
coach 0 33 32 0 0.7 1.0 5 0.890899 -1 0 11 0 20 0.0
cabbie 0 26 25 0 0.78 1.0 4 1.05946 1 0 4 0 14 0.0
stallion 0 46 45 0 0.85 1.0 7 1.12246 1 0 3 0 22 0.0
rumpo 0 142 141 0 0.78 1.0 1 0.840896 4 0 1 0 11 0.0
rcbandit 9 36 118 0 0.7 1.0 -1 1.0 -1 0 13 1 -1 0.0
romero 0 95 94 0 0.9 1.0 5 1.12246 4 0 13 0 23 0.0
packer 0 84 83 0 0.78 1.0 9 1.0 3 0 3 0 6 6.0
monster 0 71 70 0 0.9 1.0 9 1.05946 2 0 7 0 24 6.0
admiral 0 87 86 0 0.85 1.0 3 1.0 2 0 8 0 45 0.0
squalo 3 22 21 0 0.7 1.0 -1 1.0 -1 0 3 0 19 0.0
seaspar 4 104 -1 0 0.7 1.0 -1 1.0 0 0 3 0 13 0.0
pizzaboy 1 119 118 2 1.0 1.0 1 1.05946 -1 0 9 0 25 0.0
tram 8 132 133 0 0.7 1.0 -1 1.0 -1 0 13 -1 26 0.0
artict2 9 -1 -1 0 0.7 1.0 -1 1.0 -1 0 13 1 -1 0.0
turismo 0 103 102 1 0.9 1.0 8 1.0 2 0 5 0 2 0.0
speeder 3 22 21 0 0.7 1.0 -1 1.0 -1 0 3 0 19 0.0
reefer 3 22 21 2 0.85 1.0 -1 1.0 -1 0 3 0 19 0.0
tropic 3 22 21 2 0.85 1.0 -1 1.0 -1 0 9 0 19 0.0
flatbed 0 81 80 0 0.7 1.0 9 0.943874 3 0 3 0 6 0.0
yankee 0 142 141 0 0.7 1.0 4 0.943874 3 0 2 0 11 0.0
caddy 9 64 63 2 0.9 1.0 1 1.25992 -1 0 2 0 27 0.0
solair 0 8 7 0 0.78 1.0 3 1.12246 2 0 11 0 4 0.0
topfun 0 137 136 0 0.85 1.0 2 1.05946 4 0 1 0 11 0.0
skimmer 5 120 54 0 0.7 1.0 -1 1.0 0 0 8 0 42 0.0
pcj600 1 125 124 2 0.7 1.18921 6 1.12246 -1 0 7 0 29 0.0
faggio 1 119 118 2 1.0 1.0 1 1.05946 -1 0 10 0 25 0.0
freeway 1 140 139 2 0.65 1.0 1 0.840896 -1 0 3 0 29 0.0
rcbaron 9 107 106 0 0.7 1.0 -1 1.0 -1 0 13 1 -1 0.0
rcraider 9 109 108 0 0.7 1.0 -1 1.0 -1 0 13 1 -1 0.0
glendale 0 17 16 0 0.85 1.0 5 0.943874 1 0 6 0 45 0.0
oceanic 0 17 16 0 0.78 1.0 2 1.0 1 0 4 0 45 0.0
sanchez 1 48 47 2 0.85 1.0 6 0.890899 -1 0 2 0 29 0.0
sparrow 4 104 -1 0 0.7 1.0 -1 1.0 0 0 3 0 13 0.0
patriot 0 99 98 0 0.9 1.18921 9 1.25992 4 0 3 0 0 0.0
quad 0 48 47 2 0.3 1.0 1 1.0 -1 0 2 0 30 0.0
coastg 3 22 21 0 0.7 1.0 -1 1.0 -1 0 13 3 19 0.0
dinghy 3 22 21 2 0.9 1.0 -1 1.0 -1 0 8 0 43 0.0
hermes 0 35 34 0 1.0 1.0 4 1.05946 1 0 6 0 1 0.0
sabre 0 46 45 0 0.85 1.0 8 0.943874 1 0 10 0 1 0.0
rustler 5 53 54 0 0.7 1.0 -1 1.0 0 0 3 0 28 0.0
zr350 0 8 7 1 0.9 1.0 3 1.12246 2 0 5 0 31 0.0
walton 0 89 88 0 0.65 1.0 2 0.943874 4 0 2 0 15 0.0
regina 0 95 94 0 0.65 1.0 7 1.18921 2 0 9 0 4 0.0
comet 0 103 102 1 0.9 1.0 8 1.12246 2 0 8 0 2 0.0
bmx 2 19 18 2 0.7 1.0 0 1.0 -1 0 13 1 41 0.0
burrito 0 137 136 0 0.78 1.0 7 1.12246 4 0 6 0 11 0.0
camper 0 142 141 0 0.7 1.0 2 1.12246 4 0 9 0 44 0.0
marquis 3 22 21 0 0.7 1.0 -1 1.0 -1 0 3 0 19 0.0
baggage 0 11 10 2 1.0 1.0 1 1.12246 -1 0 9 0 6 0.0
dozer 0 89 88 0 0.7 1.0 9 1.0 -1 0 13 -1 32 0.0
maverick 4 85 -1 0 0.7 1.0 -1 1.0 0 0 3 0 13 0.0
vcnmav 4 85 -1 0 0.7 1.0 -1 1.0 0 0 3 0 13 0.0
rancher 0 99 98 0 0.85 1.0 5 0.943874 2 0 3 0 0 0.0
fbiranch 0 99 98 0 0.7 1.0 5 1.0 2 0 13 3 0 0.0
virgo 0 95 94 0 0.7 1.0 3 0.943874 2 0 4 0 1 0.0
greenwoo 0 95 94 0 0.85 1.0 7 1.12246 2 0 6 0 45 0.0
jetmax 3 22 21 1 0.85 1.0 -1 1.0 -1 0 3 0 19 0.0
hotring 0 38 37 0 0.9 1.0 3 1.12246 2 0 7 0 2 0.0
sandking 0 99 98 0 0.7 1.18921 5 0.943874 2 0 3 0 0 0.0
blistac 0 93 92 0 0.78 1.0 8 1.12246 2 0 5 0 31 0.0
polmav 4 85 -1 0 0.7 1.0 -1 1.0 0 0 13 3 13 0.0
boxville 0 142 141 0 0.7 1.0 3 0.840896 3 0 6 0 11 0.0
benson 0 84 83 0 0.65 1.33484 2 0.943874 3 0 2 0 11 3.0
mesa 0 8 7 0 0.85 1.0 6 1.0 2 0 11 0 0 0.0
rcgoblin 9 109 108 0 0.7 1.0 -1 1.0 -1 0 13 1 -1 0.0
hotrina 0 38 37 0 0.9 1.0 3 0.943874 2 0 3 0 2 0.0
hotrinb 0 101 100 0 0.9 1.0 7 1.12246 2 0 7 0 2 0.0
bloodra 0 71 70 0 0.7 1.0 2 0.943874 1 0 2 0 1 0.0
rnchlure 0 99 98 0 0.7 1.0 5 0.943874 2 0 3 0 0 0.0
supergt 0 103 102 1 0.9 1.0 4 1.0 2 0 8 0 2 0.0
elegant 0 87 86 0 0.7 1.0 7 1.18921 2 0 11 0 45 0.0
journey 0 137 136 0 0.65 1.0 4 1.18921 0 0 9 0 44 0.0
bike 2 19 18 2 0.7 1.0 0 1.0 -1 0 13 1 41 0.0
mtbike 2 19 18 2 0.7 1.0 0 1.0 -1 0 13 1 41 0.0
beagle 5 134 135 0 0.7 1.0 -1 1.0 0 0 3 0 28 0.0
cropdust 5 120 54 0 0.7 1.0 -1 1.0 0 0 3 0 28 0.0
stunt 5 53 54 0 0.7 1.0 -1 1.0 0 0 3 0 28 0.0
petro 0 84 83 0 0.85 1.0 9 0.793701 3 0 3 0 3 6.0
rdtrain 0 84 83 0 0.78 1.0 9 0.840896 3 0 2 0 3 6.0
nebula 0 8 7 0 0.7 1.0 4 1.25992 2 0 10 0 45 0.0
majestic 0 93 92 0 0.78 1.0 8 1.12246 2 0 4 0 1 0.0
buccanee 0 46 45 0 0.7 1.0 3 1.0 1 0 1 0 1 0.0
shamal 5 -1 -1 0 0.85 1.0 -1 1.0 0 0 3 0 28 0.0
hydra 5 -1 -1 0 0.78 1.0 -1 1.0 0 0 3 0 28 0.0
fcr900 1 115 114 2 0.78 1.05946 7 1.25992 -1 0 7 0 29 0.0
nrg500 1 125 124 2 0.65 1.0 6 1.18921 -1 0 5 0 29 0.0
copbike 1 41 40 2 0.9 1.0 6 1.0 -1 0 13 3 29 0.0
cement 0 84 83 0 0.65 1.0 4 0.943874 3 0 3 0 6 0.0
towtruck 0 137 136 0 0.7 1.0 4 1.0 4 0 3 0 6 0.0
fortune 0 26 25 0 0.78 1.0 3 0.943874 2 0 8 0 1 0.0
cadrona 0 8 7 0 0.78 1.0 8 1.0 2 0 4 0 1 0.0
fbitruck 0 81 80 0 0.7 1.18921 5 0.943874 4 0 13 3 18 0.0
willard 0 26 25 0 0.7 1.0 2 1.18921 2 0 1 0 45 0.0
forklift 0 58 57 2 1.0 1.0 1 1.05946 -1 0 13 1 33 0.0
tractor 0 89 88 2 0.65 1.0 7 0.890899 -1 0 13 -1 34 0.0
combine 0 69 68 0 0.7 1.0 4 0.840896 0 0 2 0 35 0.0
feltzer 0 93 92 0 0.85 1.0 2 1.18921 2 0 6 0 22 0.0
remingtn 0 35 34 0 0.9 1.0 3 1.05946 1 0 6 0 10 0.0
slamvan 0 76 75 0 1.0 1.0 7 1.12246 2 0 1 0 10 0.0
blade 0 46 45 0 0.9 1.0 2 1.18921 1 1 6 0 10 0.0
freight 8 132 131 0 0.7 1.0 -1 1.0 3 0 13 -1 39 0.0
streak 8 132 131 0 0.7 1.0 -1 1.0 3 0 13 -1 39 0.0
vortex 9 78 77 0 0.85 1.0 -1 1.0 -1 0 7 0 40 0.0
vincent 0 26 25 0 0.85 1.0 3 0.943874 2 0 1 0 45 0.0
bullet 0 17 16 1 1.0 1.18921 2 1.25992 2 0 5 0 2 0.0
clover 0 46 45 0 0.65 1.0 7 1.18921 1 0 9 0 1 0.0
sadler 0 95 94 0 0.78 1.0 7 1.05946 1 0 7 0 15 0.0
firela 0 84 83 0 0.7 1.0 9 0.943874 3 0 13 3 7 5.0
hustler 0 76 75 0 0.85 1.0 8 0.943874 1 0 3 0 1 0.0
intruder 0 26 25 0 0.78 1.0 3 0.890899 2 0 8 0 45 0.0
primo 0 8 7 0 0.7 1.0 1 0.943874 2 0 4 0 45 0.0
cargobob 4 12 -1 0 0.7 1.0 -1 1.0 0 0 3 0 13 0.0
tampa 0 95 94 0 0.65 1.0 2 0.943874 1 0 9 0 1 0.0
sunrise 0 26 25 0 0.7 1.0 8 0.943874 2 0 8 0 45 0.0
merit 0 8 7 0 0.78 1.0 6 0.840896 2 0 11 0 45 0.0
utility 0 137 136 0 0.65 1.0 7 1.12246 4 0 2 0 11 0.0
nevada 5 134 135 0 0.7 1.0 -1 1.0 0 0 3 0 28 0.0
yosemite 0 26 25 0 0.85 1.0 7 1.05946 2 0 3 0 15 0.0
windsor 0 101 100 0 0.78 1.0 2 1.25992 1 0 10 0 1 0.0
monstera 0 71 70 1 0.9 1.18921 9 1.05946 2 0 3 0 24 6.0
monsterb 0 71 70 1 0.9 1.18921 9 1.12246 2 0 7 0 24 6.0
uranus 0 8 7 0 0.85 1.0 8 1.05946 2 2 3 0 31 0.0
jester 0 93 92 1 0.9 1.0 3 1.12246 2 2 8 0 31 0.0
sultan 0 87 86 0 1.0 1.0 7 1.18921 2 2 6 0 45 0.0
stratum 0 87 86 0 0.78 1.0 3 1.05946 2 2 4 0 4 0.0
elegy 0 8 7 0 0.85 1.0 3 1.12246 2 2 8 0 1 0.0
raindanc 4 12 -1 0 0.7 1.0 -1 1.0 0 0 3 0 13 0.0
rctiger 9 113 112 0 0.7 1.0 -1 1.0 -1 0 13 1 -1 0.0
flash 0 93 92 0 0.9 1.0 2 1.25992 2 2 5 0 31 0.0
tahoma 0 93 92 0 0.85 1.0 3 0.943874 2 0 1 0 45 0.0
savanna 0 46 45 0 0.9 1.0 7 0.943874 1 1 6 0 10 0.0
bandito 0 115 114 0 0.7 1.0 7 1.25992 -1 0 13 -1 17 0.0
freiflat 8 132 131 0 0.7 1.0 -1 1.0 -1 0 13 -1 -1 0.0
streakc 8 132 131 0 0.7 1.0 -1 1.0 -1 0 13 -1 -1 0.0
kart 0 62 61 2 0.78 1.0 1 1.12246 -1 0 7 0 36 0.0
mower 0 62 61 2 0.9 1.0 1 0.943874 -1 0 2 0 37 0.0
duneride 0 81 80 0 0.7 1.18921 4 0.890899 3 0 9 0 0 0.0
sweeper 0 127 126 2 0.85 1.0 5 1.18921 4 0 1 0 11 0.0
broadway 0 35 34 0 0.9 1.0 3 0.890899 1 1 10 0 10 0.0
tornado 0 17 16 0 0.78 1.0 5 1.12246 1 1 6 0 10 0.0
at400 5 -1 -1 0 0.7 1.0 -1 1.0 0 0 3 0 28 0.0
dft30 0 33 32 0 0.78 1.0 4 0.840896 3 0 1 0 6 0.0
huntley 0 99 98 0 0.78 1.0 7 1.0 2 0 11 0 0 0.0
stafford 0 87 86 1 0.85 1.0 2 0.890899 2 0 11 0 45 0.0
bf400 1 125 124 2 0.78 1.0 6 0.890899 -1 0 1 0 29 0.0
newsvan 0 137 136 0 0.7 1.0 4 1.05946 4 0 11 0 11 0.0
tug 0 11 10 2 0.65 1.0 1 0.840896 4 0 3 0 11 0.0
petrotr 9 -1 -1 0 0.7 1.0 -1 1.0 3 0 13 1 -1 0.0
emperor 0 87 86 0 0.78 1.0 8 1.0 2 0 8 0 45 0.0
wayfarer 1 41 40 2 0.3 0.890899 7 1.18921 -1 0 2 0 29 0.0
euros 0 8 7 0 0.85 1.0 5 1.25992 2 0 9 0 31 0.0
hotdog 0 142 141 0 0.65 1.0 4 0.943874 4 0 3 0 11 0.0
club 0 93 92 0 1.0 1.0 6 0.943874 2 0 5 0 31 0.0
freibox 8 132 131 0 0.7 1.0 -1 1.0 -1 0 13 -1 -1 0.0
artict3 9 -1 -1 0 0.7 1.0 -1 1.0 -1 0 13 1 -1 0.0
androm 5 -1 -1 0 0.7 1.0 -1 1.0 0 0 3 0 -1 0.0
dodo 5 120 54 0 0.7 1.0 -1 1.0 0 0 3 0 28 0.0
rccam 10 -1 -1 0 0.7 1.0 -1 1.0 -1 0 13 -1 -1 0.0
launch 3 22 21 0 0.7 1.0 -1 1.0 -1 0 13 3 19 0.0
copcarla 0 87 86 0 0.7 1.0 2 1.05946 2 0 13 3 38 0.0
copcarsf 0 87 86 0 0.7 1.0 2 1.05946 2 0 13 3 38 0.0
copcarvg 0 87 86 0 0.7 1.0 7 1.05946 2 0 13 3 38 0.0
copcarru 0 99 98 0 0.7 1.0 4 1.05946 2 0 13 3 38 0.0
picador 0 26 25 0 0.7 1.0 7 1.12246 2 0 6 0 15 0.0
swatvan 0 81 80 0 0.7 1.0 9 0.943874 3 0 13 3 18 0.0
alpha 0 38 37 0 0.85 1.0 3 1.0 2 0 6 0 31 0.0
phoenix 0 101 100 0 0.9 1.0 8 1.05946 1 0 1 0 2 0.0
glenshit 0 17 16 0 0.65 1.0 5 1.05946 1 0 1 0 45 0.0
sadlshit 0 95 94 0 0.65 1.0 7 1.05946 1 0 3 0 15 0.0
bagboxa 10 130 129 0 0.7 1.0 -1 1.0 -1 0 13 -1 -1 0.0
bagboxb 10 130 129 0 0.7 1.0 -1 1.0 -1 0 13 -1 -1 0.0
tugstair 10 130 129 0 0.7 1.0 -1 1.0 -1 0 13 -1 -1 0.0
boxburg 0 137 136 0 0.7 1.0 3 0.840896 -1 0 6 0 -1 0.0
farmtr1 10 130 129 0 0.7 1.0 -1 1.0 -1 0 13 -1 -1 0.0
utiltr1 10 -1 -1 0 0.7 1.0 -1 1.0 -1 0 13 -1 -1 0.0]]

local carcols = [[admiral, 34,34, 35,35, 37,37, 39,39, 41,41, 43,43, 45,45, 47,47
alpha, 58,1, 69,1, 75,77, 18,1, 32,1, 45,45, 13,1, 34,1
ambulan, 1,3
androm, 1,1
artict1, 1,1
artict2, 1,1
artict3, 1,1
at400, 1,3, 8,7, 8,10, 8,16, 23,31, 40,44
baggage, 1,73, 1,74, 1,75, 1,76, 1,77, 1,78, 1,79
bandito, 2,39, 9,39, 17,1, 21,1, 33,0, 37,0, 41,29, 56,29
banshee, 12,12, 13,13, 14,14, 1,2, 2,1, 1,3, 3,1, 10,10
barracks, 43,0
beagle, 3,90, 4,90, 7,68, 8,66, 12,60, 27,97, 34,51, 37,51
benson,  109,25, 109,32, 112,32, 10,32, 30,44, 32,52, 84,66, 84,69
bf400, 54,1, 58,1, 66,1, 72,1, 75,1, 87,1, 101,1, 36,1
bfinject, 1,0, 2,2, 3,2, 3,6, 6,16, 15,30, 24,53, 35,61
bike, 7,1, 74,1, 61,1, 16,1, 25,1, 30,1, 36,1, 53,1
blade, 9,1, 12,1, 26,96, 30,96, 32,1, 37,1, 57,96, 71,96
blistac, 74,72, 66,72, 53,56, 37,19, 22,22, 20,20, 9,14, 0,0
bloodra, 51,39, 57,38, 45,29, 34,9, 65,9, 14,1, 12,9, 26,1
bmx, 1,1, 3,3, 6,6, 46,46, 65,9, 14,1, 12,9, 26,1
bobcat, 96,25, 97,25, 101,25, 111,31, 113,36, 83,57, 67,59
boxburg, 36,36
boxville, 11,123, 13,120, 20,117, 24,112, 27,107, 36,105, 37,107, 43,93
bravura, 41,41, 47,47, 52,52, 66,66, 74,74, 87,87,91,91, 113,113
broadway, 12,1, 19,96, 31,64, 25,96, 38,1, 51,96, 57,1, 66,96
buccanee, 2,39, 9,39, 17,1, 21,1, 33,0, 37,0, 41,29, 56,29
buffalo, 10,10, 13,13, 22,22, 30,30, 39,39, 90,90, 98,98, 110,110
bullet, 51,1, 58,8, 60,1, 68,8, 2,1, 13,8, 22,1, 36,8
burrito, 41,41, 48,48, 52,52, 64,64, 71,71, 85,85, 10,10, 62,62
bus, 71,59, 75,59, 92,72, 47,74, 55,83, 59,83, 71,87, 82,87
cabbie, 6,76
caddy, 58,1, 2,1, 63,1, 18,1, 32,1, 45,1, 13,1, 34,1
cadrona, 52,1, 53,1, 66,1, 75,1, 76,1, 81,1, 95,1, 109,1
cargobob, 1,1
cheetah,  20,1, 25,1, 36,1, 40,1 62,1, 75,1, 92,1, 0,1
clover, 13,118, 24,118, 31,93, 32,92, 45,92, 113,92, 119,113, 122,113
club, 37,37, 31,31, 23,23, 22,22, 7,7, 124,124, 114,114, 112,112
coach,   54,7, 79,7, 87,7, 95,16, 98,20, 105,20, 123,20, 125,21
coastg, 56,15, 56,53
comet, 73,45, 12,12, 2,2, 6,6, 4,4, 46,46, 53,53
copcarla, 0,1
copcarsf, 0,1
copcarvg, 0,1
copcarru, 0,1
cropdust, 17,39, 15,123, 32,112, 45,88, 52,71, 57,67, 61,96, 96,96
dft30, 1,1
dinghy, 56,15, 56,53
dodo, 51,1, 58,8, 60,1, 68,8, 2,1, 13,8, 22,1, 36,8
dozer, 1,1
dumper, 1,1
duneride, 91,38, 115,43, 85,6, 79,7, 78,8, 77,18, 79,18, 86,24
elegant, 37,37, 42,42, 53,53, 62,62, 7,7, 10,10, 11,11, 15,15
elegy, 36,1, 35,1, 17,1, 11,1, 116,1, 113,1, 101,1, 92,1
emperor, 37,37, 42,42, 53,53, 62,62, 7,7, 10,10, 11,11, 15,15
enforcer, 0,1
esperant, 45,75, 47,76, 33,75, 13,76, 54,75, 69,76, 59,75, 87,76
euros, 36,1, 40,1, 43,1, 53,1, 72,1, 75,1, 95,1, 101,1
faggio, 12,12, 13,13, 14,14, 1,2, 2,1, 1,3, 3,1, 10,10
fbiranch, 0,0
fcr900, 74,74, 75,13, 87,118, 92,3, 115,118, 25,118, 36,0, 118,118
feltzer, 73,1, 74,1, 75,1, 77,1, 79,1, 83,1, 84,1, 91,1
firela, 3,1
firetruk, 3,1
flash, 37,37, 42,42, 53,53, 62,62, 7,7, 10,10, 11,11, 15,15
flatbed, 84,15, 84,58, 84,31, 32,74, 43,31, 1,31, 77,31, 32,74
forklift, 110,1, 111,1, 112,1, 114,1, 119,1, 122,1, 4,1, 13,1
fortune, 2,39, 9,39, 17,1, 21,1, 33,0, 37,0, 41,29, 56,29
freeway, 79,79, 84,84, 7,7, 11,11, 19,19, 22,22, 36,36, 53,53
freight, 1,1
glendale, 67,76, 68,76, 78,76, 2,76, 16,76, 18,76, 25,76, 45,88
glenshit, 67,76, 68,76, 78,76, 2,76, 16,76, 18,76, 25,76, 45,88
greenwoo, 30,26, 77,26, 81,27, 24,55, 28,56, 49,59, 52,69, 71,107
hermes, 97,1, 81,1, 105,1, 110,1, 91,1, 74,1, 84,1, 83,1
hotdog, 1,1
hotknife, 1,1, 12,12, 2,2, 6,6, 4,4, 46,46, 53,53
hotrina, 7,94, 36,88, 51,75, 53,75 ,58,67, 75,67, 75,61, 79,62
hotrinb, 83,66, 87,74, 87,75, 98,83, 101,100, 103,101, 117,116, 123,36
hotring, 36,117, 36,13, 42,30, 42,33, 54,36, 75,79, 92,101, 98,109
hunter, 43,0
huntley, 37,37, 42,42, 53,53, 62,62, 7,7, 10,10, 11,11, 15,15
hustler, 50,1, 47,1, 44,96, 40,96, 39,1, 30,1, 28,96, 9,96
infernus, 12,1, 64,1, 123,1, 116,1, 112,1, 106,1, 80,1, 75,1
intruder, 62,37, 78,38, 2,62, 3,87, 2,78, 113,78, 119,62, 7,78
jester, 51,1, 58,8, 60,1, 68,8, 2,1, 13,8, 22,1, 36,8
jetmax, 36,13
journey, 1,1
kart, 2,35, 36,2, 51,53, 91,2, 11,22, 40,35
landstal, 4,1, 123,1, 113,1, 101,1, 75,1, 62,1, 40,1, 36,1
launch, 112,20
linerun, 36,1, 37,1, 30,1, 28,1, 25,1, 40,1, 101,1, 113,1
quad, 120,117, 103,111, 120,114, 74,91, 120,112, 74,83, 120,113, 66,71
majestic, 37,36, 36,36, 40,36, 43,41, 47,41, 51,72, 54,75, 55,84
mtbike, 43,43, 46,46, 39,39, 28,28, 16,16, 6,6, 5,5, 2,2
manana, 4,1, 9,1, 10,1, 25,1, 36,1, 40,1, 45,1, 84,1
marquis, 12,35, 50,32, 40,26, 66,36
maverick, 26,14, 29,42, 26,57, 54,29, 26,3, 3,29, 12,39, 74,35
merit, 67,1, 72,1, 75,1, 83,1, 91,1, 101,1, 109,1, 20,1
mesa, 75,84, 40,84, 40,110, 28,119, 25,119, 21,119, 13,119, 4,119
monster, 32,36, 32,42, 32,53, 32,66, 32,14, 32,32
monstera, 1,1
monsterb, 1,1
moonbeam, 119,119, 117,227, 114,114, 108,108, 95,95, 81,81, 61,61, 41,41
mower, 94,1, 101,1, 116,1, 117,1, 4,1, 25,1, 30,1, 37,1
mrwhoop, 1,16, 1,56, 1,17, 1,53, 1,5, 1,35
mule, 25,1, 28,1, 43,1, 67,1, 72,1, 9,1, 95,1, 24,1
nebula, 116,1, 119,1, 122,1, 4,1, 9,1, 24,1, 27,1, 36,1
nevada, 38,9, 55,23, 61,74, 71,87, 91,87, 98,114, 102,119, 111,3
newsvan, 41,10, 41,20, 49,11, 56,123, 110,113, 112,116, 114,118, 119,101
nrg500, 3,3, 3,8, 6,25, 7,79, 8,82, 36,105, 39,106, 51,118
oceanic, 51,1, 58,8, 60,1, 68,8, 2,1, 13,8, 22,1, 36,8
packer, 4,1, 20,1, 24,1, 25,1, 36,1, 40,1, 54,1, 84,1
patriot, 43,0
pcj600, 36,1, 37,1, 43,1, 53,1, 61,1, 75,1, 79,1, 88,1
peren, 113,39, 119,50, 123,92, 109,100, 101,101, 95,105, 83,110, 66,25
petro, 10,1, 25,1, 28,1, 36,1, 40,1, 54,1, 75,1, 113,1
petrotr, 1,1
phoenix, 58,1, 69,1, 75,77, 18,1, 32,1, 45,45, 13,1, 34,1
picador, 81,8, 32,8, 43,8, 67,8, 11,11, 8,90, 2,2, 83,13
pizzaboy,3,6
polmav, 0,1
pony, 87,1, 88,1, 91,1, 105,1, 109,1, 119,1, 4,1, 25,1
predator, 46,26
premier, 37,37, 42,42, 53,53, 62,62, 7,7, 10,10, 11,11, 15,15
previon, 83,1, 87,1, 92,1, 95,1, 109,1, 119,45, 11,1,
primo, 122,1, 123,1, 125,1, 10,1, 24,1, 37,1, 55,1, 66,1
raindanc, 1,6
rancher, 13,118, 14,123, 120,123, 112,120, 84,110, 76,102
rcbandit, 2,96, 79,42, 82,54, 67,86, 126,96, 70,96, 110,54, 67,98
rcbaron, 14,75
rcraider, 14,75
rcgoblin, 14,75
rdtrain, 13,76, 24,77, 63,78, 42,76, 54,77, 39,78, 11,76, 62,77
reefer, 56,56
regina, 27,36, 59,36, 60,35, 55,41, 54,31, 49,23, 45,32, 40,29
remingtn, 37,37, 42,42, 53,53, 62,62, 7,7, 10,10, 11,11, 15,15
rhino, 43,0
rnchlure, 13,118, 14,123, 120,123, 112,120, 84,110, 76,102
romero, 0,0, 11,105, 25,109, 36,0, 40,36, 75,36, 0,36, 0,109
rumpo, 34,34, 32,32, 20,20, 110,110, 66,66, 84,84, 118,118, 121,121
rustler, 6,7, 7,6, 1,6, 89,91, 119,117, 103,102, 77,87, 71,77
sabre, 2,39, 9,39, 17,1, 21,1, 33,0, 37,0, 41,29, 56,29
sadler, 76,8, 32,8, 43,8, 67,8, 11,11, 8,90, 2,2, 83,13
sadlshit, 61,8, 32,8, 43,8, 67,8, 11,11, 8,90, 2,2, 83,13
sanchez, 6,6, 46,46, 53,53, 3,3
sandking, 123,124, 119,122, 118,117, 116,115, 114,108, 101,106, 88,99, 5,6
savanna, 97,96, 88,64, 90,96, 93,64, 97,96, 99,81, 102,114, 114,1
seaspar, 75,2
securica, 4,75
sentinel, 11,1, 24,1, 36,1, 40,1, 75,1, 91,1, 123,1, 4,1
shamal, 1,1
streak, 1,1
streakc, 1,1
skimmer, 1,3, 1,9, 1,18, 1,30, 17,23, 46,23, 46,32, 57,34
slamvan, 3,1, 28,1, 31,1, 55,1, 66,1 97,1, 123,1, 118,1
solair, 91,1, 101,1, 109,1, 113,1, 4,1, 25,1, 30,1, 36,1
sparrow, 1,3
speeder, 1,3, 1,5, 1,16, 1,22, 1,35, 1,44, 1,53, 1,57
stafford, 92,92, 81,81, 67,67, 66,66, 61,61, 53,53, 51,51, 47,47, 43,43
stallion, 57,8, 8,17, 43,21, 54,38, 67,8, 37,78, 65,79, 25,78
stratum, 57,8, 8,17, 43,21, 54,38, 67,8, 37,78, 65,79, 25,78
stretch, 1,1
stunt, 38,51, 21,36, 21,34, 30,34, 54,34, 55,20, 48,18, 51,6
sultan, 52,39, 9,39, 17,1, 21,1, 33,0, 37,0, 41,29, 56,29
sunrise, 37,37, 42,42, 53,53, 62,62, 7,7, 10,10, 11,11, 15,15
supergt, 3,3, 6,6, 7,7, 52,52, 76,76
swatvan, 1,1
sweeper, 26,26
tahoma, 109,1, 30,8, 95,1, 84,8, 83,1, 72,8, 71,1, 52,8
tampa, 74,39, 72,39, 75,39, 79,39, 83,36, 84,36, 89,35, 91,35
taxi, 6,1
topfun, 26,26, 28,28, 44,44, 51,51, 57,57, 72,72, 106,106, 112,112
tornado, 67,1, 68,96, 72,1, 74,8, 75,96, 76,8, 79,1, 84,96
towtruck, 1,1, 17,20, 18,20, 22,30, 36,43, 44,51, 52,54
tractor, 2,35, 36,2, 51,53, 91,2, 11,22, 40,35
tram, 1,74
trash, 26,26
tropic, 26,26
tug, 1,1
tugstair, 1,1
turismo, 123,123, 125,125, 36,36, 16,16, 18,18, 46,46, 61,61, 75,75
uranus, 112,1, 116,1, 117,1, 24,1, 30,1, 35,1, 36,1, 40,1
utility, 56,56, 49,49, 26,124
vcnmav, 2,26, 2,29
vincent, 37,37, 42,42, 53,53, 62,62, 7,7, 10,10, 11,11, 15,15
virgo, 40,65, 71,72, 52,66, 64,72, 30,72, 60,72
voodoo, 9,1, 10,8, 11,1, 25,8, 27,1, 29,8, 30,1, 37,8
vortex, 96,67, 86,70, 79,74, 70,86, 61,98, 75,75, 75,91
walton, 72,1, 66,1, 59,1, 45,1, 40,1, 39,1, 35,1, 20,1
washing, 4,1, 13,1, 25,1, 30,1, 36,1, 40,1, 75,1, 95,1
wayfarer, 119,1, 122,1, 8,1, 10,1, 13,1, 25,1, 27,1, 32,1
willard, 37,37, 42,42, 53,53, 62,62, 7,7, 10,10, 11,11, 15,15
windsor, 51,1, 58,1, 60,1, 68,1, 2,1, 13,1, 22,1, 36,1
yankee, 84,63, 91,63, 102,65, 105,72, 110,93, 121,93, 12,95, 23,1
yosemite, 53,32, 15,32, 45,32, 34,30, 65,32, 14,32, 12,32, 43,32
zr350, 92,1, 94,1, 101,1, 121,1, 0,1, 22,1, 36,1, 75,1
camper, 1,31,1,0, 1,31,1,0, 1,20,3,0, 1,5,0,0, 0,6,3,0, 3,6,3,0, 16,0,8,0, 17,0,120,0
cement, 60,24,23,0, 61,27,123,0, 65,31,31,0, 61,61,30,0, 81,35,23,0, 62,61,62,0, 83,66,64,0, 83,64,64,0
squalo, 0,0,0,1, 1,5,1,1, 3,3,0,1, 1,22,1,1, 1,35,1,1, 1,44,1,1, 1,53,1,1, 1,57,1,1]]

local carmods = [[admiral, nto_b_l, nto_b_s, nto_b_tw
alpha, nto_b_l, nto_b_s, nto_b_tw
banshee, nto_b_l, nto_b_s, nto_b_tw
blistac, rf_b_sc_r, wg_l_b_ssk, bnt_b_sc_p_m, exh_b_t, spl_b_bbb_m, spl_b_bab_m, nto_b_l, nto_b_s, nto_b_tw, spl_b_mab_m, spl_b_bar_m, bntl_b_ov, exh_b_l
bobcat, exh_b_l, exh_b_m, exh_b_t, lgt_b_rspt, nto_b_l, nto_b_s, nto_b_tw, wg_l_b_ssk
bravura, bnt_b_sc_l, bnt_b_sc_m, bntl_b_ov, bntl_b_sq, exh_b_l, exh_b_t, lgt_b_rspt, nto_b_l, nto_b_s, nto_b_tw, rf_b_sc_r, spl_b_bab_m, spl_b_mab_m, wg_l_b_ssk
buccanee, bnt_b_sc_l, bntl_b_ov, bntl_b_sq, exh_b_l, exh_b_ts, lgt_b_rspt, nto_b_l, nto_b_s, nto_b_tw, rf_b_sc_r, spl_b_bab_m, spl_b_bbb_m, spl_b_mab_m, wg_l_b_ssk
buffalo, nto_b_s, nto_b_s, nto_b_tw
bullet, nto_b_l, nto_b_s, nto_b_tw
cabbie, nto_b_l, nto_b_s, nto_b_tw
cadrona, exh_b_m, exh_b_l, exh_b_ts, nto_b_l, nto_b_s, nto_b_tw, spl_b_bab_m, spl_b_bar_l, spl_b_bbr_l, wg_l_b_ssk
cheetah, exh_b_t, exh_b_ts, nto_b_l, nto_b_s, nto_b_tw, spl_b_bab_m, spl_b_bbb_m, spl_b_mab_m, wg_l_b_ssk
clover, bntl_b_sq, exh_b_l, exh_b_m, exh_b_t, exh_b_ts, nto_b_l, nto_b_s, nto_b_tw, spl_b_bar_l, spl_b_bbr_l
club, bnt_b_sc_l, bnt_b_sc_m, bntl_b_sq, exh_b_l, exh_b_ts, nto_b_l, nto_b_s, nto_b_tw, lgt_b_sspt, lgt_b_rspt, rf_b_sc_r, spl_b_bbr_m, spl_b_mar_m, wg_l_b_ssk
comet, nto_b_l, nto_b_s, nto_b_tw
elegant, nto_b_l, nto_b_s, nto_b_tw
emperor, bntl_b_ov, bntl_b_sq, exh_b_l, exh_b_t, exh_b_ts, lgt_b_rspt, nto_b_l, nto_b_s, nto_b_tw, rf_b_sc_r, spl_b_bab_m, spl_b_bbb_m, spl_b_mab_m, wg_l_b_ssk
esperant, nto_b_l, nto_b_s, nto_b_tw
euros, nto_b_l, nto_b_s, nto_b_tw
feltzer, nto_b_l, nto_b_s, nto_b_tw
fortune, nto_b_l, nto_b_s, nto_b_tw
glendale, nto_b_l, nto_b_s, nto_b_tw
greenwoo, bnt_b_sc_l, bnt_b_sc_m, nto_b_l, nto_b_s, nto_b_tw, rf_b_sc_r, spl_b_bbr_m, spl_b_mar_m
hermes, nto_b_l, nto_b_s, nto_b_tw
huntley, nto_b_l, nto_b_s, nto_b_tw
hustler, nto_b_l, nto_b_s, nto_b_tw
infernus, nto_b_s, nto_b_l, nto_b_tw
intruder, bnt_b_sc_m, bntl_b_ov, bntl_b_sq, exh_b_t, exh_b_ts, lgt_b_sspt, nto_b_l, nto_b_s, nto_b_tw, rf_b_sc_r, spl_b_bar_m, spl_b_bab_m, spl_b_bbb_m, wg_l_b_ssk
landstal, exh_b_l, exh_b_m, exh_b_t, exh_b_ts, lgt_b_rspt, lgt_b_sspt, nto_b_l, nto_b_s, nto_b_tw
majestic, bntl_b_ov, bntl_b_sq, exh_b_l, exh_b_t, exh_b_ts, nto_b_l, nto_b_s, nto_b_tw, spl_b_bar_m, spl_b_bbb_m, spl_b_bbr_m, spl_b_mab_m, wg_l_b_ssk
manana, exh_b_t, exh_b_m, exh_b_l, lgt_b_rspt, lgt_b_sspt, nto_b_l, nto_b_s, nto_b_tw, spl_b_bab_m, spl_b_bbb_m, spl_b_mab_m, wg_l_b_ssk
merit, bnt_b_sc_l, exh_b_l, exh_b_m, exh_b_t, exh_b_ts, nto_b_l, nto_b_s, nto_b_tw, rf_b_sc_r, spl_b_bar_m, spl_b_bbb_m, spl_b_bbr_m, spl_b_mab_m
mesa, exh_b_l, exh_b_m, exh_b_t, lgt_b_rspt, lgt_b_sspt, nto_b_l, nto_b_s, nto_b_tw
moonbeam, exh_b_l, exh_b_m, nto_b_l, nto_b_s, nto_b_tw, rf_b_sc_r, spl_b_bar_m, spl_b_bbr_m
nebula, bnt_b_sc_m, exh_b_l, exh_b_m, exh_b_t, exh_b_ts, nto_b_l, nto_b_s, nto_b_tw, spl_b_bar_m, spl_b_bbr_l, spl_b_bbr_m, spl_b_mar_m, wg_l_b_ssk
oceanic, nto_b_l, nto_b_s, nto_b_tw
peren, exh_b_l, exh_b_m, exh_b_t, lgt_b_rspt, nto_b_l, nto_b_s, nto_b_tw, spl_b_bar_m, spl_b_bbr_m, spl_b_mar_m, wg_l_b_ssk
phoenix, bntl_b_sq, bntl_b_ov, exh_b_l, exh_b_t, exh_b_ts, lgt_b_sspt, nto_b_l, nto_b_s, nto_b_tw, rf_b_sc_r, spl_b_bab_m, spl_b_bbb_m, wg_l_b_ssk
picador, bnt_b_sc_l, bnt_b_sc_m, exh_b_l, exh_b_s, exh_b_ts, lgt_b_rspt, nto_b_l, nto_b_s, nto_b_tw, rf_b_sc_r, wg_l_b_ssk
premier, bnt_b_sc_l, bnt_b_sc_m, exh_b_m, exh_b_t, nto_b_l, nto_b_s, nto_b_tw, rf_b_sc_r, spl_b_bab_m, spl_b_mab_m
previon, exh_b_l, exh_b_m, exh_b_s, exh_b_t, lgt_b_rspt, nto_b_l, nto_b_s, nto_b_tw, rf_b_sc_r, spl_b_bab_m, spl_b_mab_m, wg_l_b_ssk
primo, bntl_b_ov, exh_b_l, exh_b_m, exh_b_t, exh_b_ts, nto_b_l, nto_b_s, nto_b_tw, spl_b_bbr_m, spl_b_mab_m, spl_b_mar_m
rancher, bnt_b_sc_l, bnt_b_sc_m, exh_b_l, exh_b_t, exh_b_ts, lgt_b_rspt, lgt_b_sspt, nto_b_l, nto_b_s, nto_b_tw, rf_b_sc_r, spl_b_bar_m, spl_b_bbr_m, spl_b_mar_m
regina, nto_b_l, nto_b_s, nto_b_tw
romero, nto_b_l, nto_b_s, nto_b_tw
sabre, nto_b_l, nto_b_s, nto_b_tw
sentinel, exh_b_l, exh_b_m, exh_b_t, exh_b_ts, nto_b_l, nto_b_s, nto_b_tw, spl_b_bab_m, spl_b_bar_l, spl_b_bbb_m, spl_b_mar_m
solair, nto_b_l, nto_b_s, nto_b_tw
stafford, exh_b_l, exh_b_ts, nto_b_l, nto_b_s, nto_b_tw, rf_b_sc_r, spl_b_bab_m, spl_b_bbb_m, wg_l_b_ssk
stallion, spl_b_mab_m, spl_b_bbb_m, spl_b_bab_m, nto_b_l, nto_b_s, nto_b_tw, wg_l_b_ssk, bntl_b_ov, bntl_b_sq, lgt_b_rspt
stretch, nto_b_s
sunrise, bnt_b_sc_l, bnt_b_sc_m, bntl_b_ov, bntl_b_sq, exh_b_l, exh_b_t, exh_b_ts, nto_b_l, nto_b_s, nto_b_tw, rf_b_sc_r, spl_b_bab_m, spl_b_bbb_m, spl_b_mab_m
supergt, nto_b_s
tahoma, nto_b_l, nto_b_s, nto_b_tw
tampa, bnt_b_sc_p_l, bnt_b_sc_p_m, bntl_b_ov, bntl_b_sq, exh_b_l, exh_b_t, exh_b_ts, nto_b_l, nto_b_s, nto_b_tw, spl_b_bab_m, spl_b_bbb_m, spl_b_mab_m, wg_l_b_ssk
taxi, bnt_b_sc_l, bnt_b_sc_m, exh_b_m, exh_b_t, nto_b_l, nto_b_s, nto_b_tw, spl_b_bab_m, spl_b_mab_m
turismo, nto_b_l, nto_b_s, nto_b_tw
vincent, bnt_b_sc_m, bntl_b_ov, bntl_b_sq, exh_b_l, exh_b_t, exh_b_ts, lgt_b_sspt, nto_b_l, nto_b_s, nto_b_tw, rf_b_sc_r, spl_b_bab_m, spl_b_bbb_m, wg_l_b_ssk
virgo, bntl_b_ov, bntl_b_sq, exh_b_l, exh_b_m, exh_b_t, exh_b_ts, nto_b_l, nto_b_s, nto_b_tw, spl_b_bar_l, spl_b_bbb_m, spl_b_mab_m, wg_l_b_ssk
voodoo, nto_b_l, nto_b_s, nto_b_tw
walton, bnt_b_sc_l, bnt_b_sc_m, bnt_b_sc_p_l, exh_b_l, exh_b_m, exh_b_s, lgt_b_rspt, lgt_b_sspt, nto_b_l, nto_b_s, nto_b_tw
washing, exh_b_l, exh_b_m, exh_b_t, exh_b_ts, nto_b_l, nto_b_s, nto_b_tw, spl_b_bar_l, spl_b_bbb_m, spl_b_bbr_m, spl_b_mar_m
willard, bnt_b_sc_p_l, bnt_b_sc_p_m, exh_b_l, exh_b_t, exh_b_ts, nto_b_l, nto_b_s, nto_b_tw, rf_b_sc_r, spl_b_bab_m, spl_b_bbb_m, spl_b_mab_m, wg_l_b_ssk
windsor, nto_b_l, nto_b_s, nto_b_tw
zr350, exh_b_l, exh_b_m, exh_b_t, exh_b_ts, nto_b_l, nto_b_s, nto_b_tw, rf_b_sc_r, wg_l_b_ssk
elegy, exh_a_l, exh_c_l, fbmp_a_l, fbmp_c_l, nto_b_l, nto_b_s, nto_b_tw, rbmp_a_l, rbmp_c_l, rf_a_l, rf_c_l, spl_a_l_b, spl_c_l_b, wg_l_a_l, wg_l_c_l
flash, exh_a_f, exh_c_f, fbmp_a_f, fbmp_c_f, nto_b_l, nto_b_s, nto_b_tw, rbmp_a_f, rbmp_c_f, rf_a_f, rf_c_f, spl_a_f_r, spl_c_f_r, wg_l_a_f, wg_l_c_f
jester, exh_a_j, exh_c_j, fbmp_a_j, fbmp_c_j, nto_b_l, nto_b_s, nto_b_tw, rbmp_a_j, rbmp_c_j, spl_a_j_b, spl_c_j_b, rf_a_j, rf_c_j, wg_l_a_j, wg_l_c_j, nto_b_s
stratum, exh_a_st, exh_c_st, fbmp_a_st, fbmp_c_st, nto_b_l, nto_b_s, nto_b_tw, rbmp_a_st, rbmp_c_st, rf_a_st, rf_c_st, spl_a_st_r, spl_c_st_r, wg_l_a_st, wg_l_c_st
sultan, exh_a_s, exh_c_s, fbmp_a_s, fbmp_c_s, nto_b_l, nto_b_s, nto_b_tw, rbmp_a_s, rbmp_c_s, rf_a_s, rf_c_s, spl_a_s_b, spl_c_s_b, wg_l_a_s, wg_l_c_s
uranus, exh_a_u, exh_c_u, fbmp_a_u, fbmp_c_u, nto_b_l, nto_b_s, nto_b_tw, rbmp_a_u, rbmp_c_u, rf_a_u, rf_c_u, spl_a_u_b, spl_c_u_b, wg_l_a_u, wg_l_c_u
blade, exh_lr_bl1, exh_lr_bl2, fbmp_lr_bl1, fbmp_lr_bl2, nto_b_l, nto_b_s, nto_b_tw, rbmp_lr_bl1, rbmp_lr_bl2, rf_lr_bl1, rf_lr_bl2, wg_l_lr_bl1
broadway, exh_lr_br1, exh_lr_br2, fbmp_lr_br1, fbmp_lr_br2, nto_b_l, nto_b_s, nto_b_tw, rbmp_lr_br1, rbmp_lr_br2, wg_l_lr_br1
remingtn, exh_lr_rem1, exh_lr_rem2, fbmp_lr_rem1, fbmp_lr_rem2, misc_c_lr_rem1, misc_c_lr_rem2, misc_c_lr_rem3, nto_b_l, nto_b_s, nto_b_tw, rbmp_lr_rem1, rbmp_lr_rem2, wg_l_lr_rem1, wg_l_lr_rem2
savanna, exh_lr_sv1, exh_lr_sv2, fbmp_lr_sv1, fbmp_lr_sv2, nto_b_l, nto_b_s, nto_b_tw, rbmp_lr_sv1, rbmp_lr_sv2, rf_lr_sv1, rf_lr_sv2, wg_l_lr_sv
slamvan, bbb_lr_slv1, bbb_lr_slv2, exh_lr_slv1, exh_lr_slv2, fbb_lr_slv1, fbb_lr_slv2, fbmp_lr_slv1, nto_b_l, nto_b_s, nto_b_tw, wg_l_lr_slv1, wg_l_lr_slv2
tornado, exh_lr_t1, exh_lr_t2, fbmp_lr_t1, fbmp_lr_t2, nto_b_l, nto_b_s, nto_b_tw, rbmp_lr_t1, rbmp_lr_t2, wg_l_lr_t1]]

local handling_cfg = [[LANDSTAL 1700.0 5008.3 2.5 0.0 0.0 -0.3 85 0.75 0.85 0.5 5 160.0 25.0 20.0 4 D 6.2 0.60 0 35.0 2.4 0.08 0.0 0.28 -0.14 0.5 0.25 0.27 0.23 25000 20 500002 0 1 0
BRAVURA 1300.0 2200.0 1.7 0.0 0.3 0.0 70 0.65 0.80 0.52 5 160.0 15.0 10.0 F P 08.0 0.80 0 30.0 1.3 0.08 0.0 0.31 -0.15 0.57 0.0 0.26 0.50 9000 1 1 0 0 0
BUFFALO 1500.0 4000.0 2.0 0.0 0.0 -0.1 85 0.7 0.9 0.5 5 200.0 28.0 5.0 R P 11.0 0.45 0 30.0 1.2 0.12 0.0 0.28 -0.24 0.5 0.4 0.25 0.50 35000 2800 10200000 1 1 0
LINERUN 3800.0 19953.2 5.0 0.0 0.0 -0.2 90 0.95 0.65 0.4 5 120.0 25.0 30.0 R D 8.0 0.30 0 25.0 1.6 0.06 0.0 0.40 -0.20 0.5 0.0 0.65 0.25 35000 6000 200 0 1 2
PEREN 1200.0 3000.0 2.5 0.0 0.1 0.0 70 0.70 0.90 0.48 5 150.0 18.0 20.0 F P 4.0 0.80 0 30.0 1.4 0.1 0.0 0.37 -0.17 0.5 0.0 0.2 0.60 10000 20 0 1 1 0
SENTINEL 1600.0 4000.0 2.2 0.0 0.0 -0.2 75 0.65 0.75 0.5 5 165.0 24.0 10.0 R P 10.0 0.5 0 27.0 1.0 0.08 0.0 0.30 -0.20 0.5 0.3 0.2 0.56 35000 0 400000 0 1 0
DUMPER 20000.0 200000.0 4.0 0.0 0.5 -0.4 90 0.78 0.8 0.55 4 110.0 25.0 30.0 R D 03.17 0.40 0 30.0 0.8 0.06 0.0 0.20 -0.30 0.55 0.0 0.45 0.20 5000 c008 1340201 0 1 20
FIRETRUK 6500.0 36670.8 3.0 0.0 0.0 0.0 90 0.55 0.8 0.5 5 170.0 27.0 10.0 R D 10.00 0.45 0 27.0 1.2 0.08 0.0 0.47 -0.17 0.5 0.0 0.2 0.26 15000 4098 0 0 1 2
TRASH 5500.0 33187.9 5.0 0.0 0.0 -0.2 90 0.60 0.9 0.5 4 110.0 20.0 30.0 R D 3.5 0.40 0 30.0 1.0 0.06 0.0 0.45 -0.25 0.55 0.3 0.45 0.20 5000 4008 200 0 1 0
STRETCH 2200.0 10000.0 1.8 0.0 0.0 0.0 75 0.60 0.8 0.5 5 180.0 18.0 25.0 R P 10.0 0.40 0 30.0 1.1 0.07 0.0 0.35 -0.20 0.5 0.0 0.2 0.72 40000 282000 10400001 1 1 0
MANANA 1000.0 1400.0 2.8 0.0 0.2 0.0 70 0.80 0.8 0.5 3 160.0 19.0 15.0 F P 8.0 0.80 0 30.0 1.2 0.10 5.0 0.31 -0.15 0.5 0.2 0.26 0.50 9000 0 0 0 0 0
INFERNUS 1400.0 2725.3 1.5 0.0 0.0 -0.25 70 0.70 0.8 0.50 5 240.0 30.0 10.0 4 P 11.0 0.51 0 30.0 1.2 0.19 0.0 0.25 -0.10 0.5 0.4 0.37 0.72 95000 40002004 C04000 1 1 1
VOODOO 1800.0 4411.5 2.0 0.0 -0.1 -0.2 70 0.95 0.80 0.45 5 160.0 23.0 5.0 R P 6.50 0.50 0 30.0 1.0 0.08 0.0 0.20 -0.25 0.5 0.6 0.26 0.41 30000 0 2410008 1 1 0
PONY 2600.0 8666.7 3.0 0.0 0.0 -0.25 80 0.55 0.90 0.50 5 160.0 15.0 25.0 R D 6.0 0.80 0 30.0 2.6 0.07 0.0 0.35 -0.15 0.25 0.0 0.2 0.50 20000 4001 1 0 3 13
MULE 3500.0 14000.0 4.0 0.0 0.0 0.1 80 0.55 0.85 0.46 5 140.0 18.0 20.0 R D 4.5 0.60 0 30.0 2.0 0.07 5.0 0.30 -0.15 0.5 0.0 0.46 0.53 22000 4088 0 0 3 0
CHEETAH 1200.0 3000.0 2.0 0.0 -0.2 -0.2 70 0.80 0.9 0.50 5 230.0 30.0 10.0 R P 11.1 0.48 0 35.0 0.8 0.20 0.0 0.10 -0.15 0.5 0.6 0.40 0.54 105000 c0002004 208000 0 0 1
AMBULAN 2600.0 10202.8 2.5 0.0 0.0 -0.1 90 0.75 0.80 0.47 5 155.0 24.0 10.0 4 D 7.0 0.55 0 35.0 1.0 0.07 0.0 0.40 -0.20 0.5 0.0 0.58 0.33 10000 4001 4 0 1 13
MOONBEAM 2000.0 5848.3 2.8 0.0 0.2 -0.1 85 0.60 0.80 0.50 5 150.0 15.0 15.0 R D 5.5 0.6 0 30.0 1.4 0.1 0.0 0.35 -0.15 0.55 0.0 0.2 0.75 16000 20 0 1 3 0
ESPERANT 1800.0 4350.0 2.0 0.0 0.0 0.0 70 0.55 0.88 0.52 5 160.0 18.0 5.0 R P 4.0 0.60 0 28.0 1.0 0.05 1.0 0.35 -0.18 0.5 0.0 0.36 0.54 19000 40000000 10000000 0 3 0
TAXI 1450.0 4056.4 2.2 0.0 0.3 -0.25 75 0.80 0.75 0.45 5 180.0 19.0 10.0 F P 9.1 0.60 0 35.0 1.4 0.1 0.0 0.25 -0.15 0.54 0.0 0.2 0.51 20000 0 200000 0 1 0
WASHING 1850.0 5000.0 2.2 0.0 0.0 -0.1 75 0.75 0.65 0.52 5 180.0 21.0 10.0 R P 7.5 0.65 0 30.0 1.0 0.20 0.0 0.27 -0.20 0.5 0.35 0.24 0.60 18000 0 10400000 1 1 0
BOBCAT 1700.0 4000.0 2.5 0.0 0.05 -0.2 75 0.65 0.85 0.57 5 165.0 20.0 15.0 4 D 8.5 0.5 0 35.0 1.5 0.10 5.0 0.35 -0.18 0.4 0.0 0.26 0.20 26000 40 104004 0 1 0
MRWHOOP 1700.0 4108.3 3.5 0.0 0.0 0.0 85 0.75 0.75 0.5 5 145.0 14.0 50.0 R D 4.17 0.80 0 35.0 1.2 0.1 0.0 0.35 -0.15 0.5 0.0 0.24 0.77 29000 88 2 0 1 0
BFINJECT 1200.0 2000.0 4.0 0.0 -0.1 -0.1 80 0.75 0.85 0.5 4 170.0 30.0 10.0 R P 6.0 0.50 0 35.0 1.0 0.07 5.0 0.20 -0.15 0.45 0.0 0.38 0.40 15000 201904 308200 1 2 25
PREMIER 1600.0 3921.3 1.8 0.0 -0.4 0.0 75 0.75 0.85 0.52 5 200.0 22.0 10.0 R P 10.0 0.53 0 35.0 1.3 0.12 0.0 0.28 -0.12 0.38 0.0 0.2 0.24 25000 40000000 10200008 0 1 0
ENFORCER 4000.0 17333.3 1.8 0.0 0.1 0.0 85 0.55 0.8 0.48 5 170.0 20.0 20.0 R D 5.4 0.45 0 27.0 1.4 0.1 0.0 0.40 -0.25 0.5 0.0 0.32 0.16 40000 4011 0 0 1 13
SECURICA 7000.0 30916.7 1.5 0.0 0.0 0.0 90 0.50 0.7 0.46 5 170.0 15.0 30.0 R D 8.4 0.45 0 27.0 1.0 0.06 0.0 0.35 -0.15 0.5 0.0 0.27 0.35 40000 4001 4 1 1 13
BANSHEE 1400.0 3000.0 2.0 0.0 0.0 -0.20 70 0.75 0.89 0.50 5 200.0 33.0 10.0 R P 8.0 0.52 0 34.0 1.6 0.10 5.0 0.30 -0.15 0.5 0.3 0.15 0.49 45000 2004 200000 1 1 1
BUS 5500.0 33187.9 2.0 0.0 0.5 0.0 90 0.75 0.85 0.40 4 130.0 14.0 50.0 R D 4.17 0.40 0 30.0 1.2 0.07 0.0 0.45 -0.25 0.45 0.0 0.2 0.75 15000 4002 0 1 1 16
RHINO 25000.0 250000.0 5.0 0.0 0.0 0.0 90 2.50 0.8 0.5 4 80.0 40.0 150.0 4 D 5.0 0.50 0 35.0 0.4 0.02 0.0 0.35 -0.10 0.5 0.0 0.22 0.09 110000 40008008 308840 0 1 24
BARRACKS 10500.0 61407.5 4.0 0.0 0.0 0.0 90 0.65 0.7 0.47 5 180.0 20.0 25.0 4 D 4.00 0.40 0 27.0 1.2 0.05 0.0 0.47 -0.17 0.5 0.0 0.62 0.26 10000 200809 100000 0 1 2
HOTKNIFE 1400.0 3400.0 2.5 0.0 0.3 -0.3 75 0.75 0.8 0.5 5 200.0 28.0 5.0 R P 11.0 0.45 0 30.0 0.8 0.08 0.0 0.28 -0.20 0.4 0.3 0.20 0.60 35000 40006800 8000 1 1 0
ARTICT1 3800.0 30000.0 2.0 0.0 0.0 -0.5 90 0.45 0.75 0.5 5 120.0 18.0 5.0 R D 8.0 0.30 0 25.0 1.5 0.05 0.0 0.30 -0.15 0.5 0.0 0.65 0.25 35000 20002000 0000 0 1 0
PREVION 1400.0 3000.0 2.0 0.0 0.3 -0.1 70 0.70 0.80 0.45 4 160.0 18.0 7.0 F P 8.0 0.65 0 35.0 1.1 0.08 2.0 0.31 -0.18 0.55 0.3 0.21 0.50 9000 0 0 0 0 0
COACH 9500.0 57324.6 1.8 0.0 0.0 0.0 90 0.65 0.85 0.35 5 160.0 18.0 10.0 R D 5.7 0.35 0 30.0 1.5 0.04 0.0 0.45 -0.25 0.5 0.0 0.45 0.48 20000 2 200000 0 1 15
CABBIE 1750.0 4351.7 2.9 0.0 0.1 -0.15 75 0.75 0.85 0.51 4 160.0 24.0 6.0 R P 7.0 0.44 0 40.0 0.7 0.06 2.0 0.25 -0.30 0.5 0.5 0.2 0.40 10000 0 0 1 1 0
STALLION 1600.0 3921.3 2.0 0.0 0.0 -0.15 70 0.80 0.75 0.55 4 160.0 23.0 5.0 R P 8.17 0.52 0 35.0 1.2 0.1 0.0 0.30 -0.2 0.5 0.0 0.3 0.64 19000 2800 4 1 1 0
RUMPO 2000.0 4901.7 2.4 0.0 0.4 -0.1 85 0.6 0.75 0.52 5 160.0 18.0 15.0 F P 5.5 0.45 0 30.0 1.4 0.05 0.0 0.43 -0.11 0.5 0.0 0.2 0.60 26000 1 0 0 1 13
RCBANDIT 100.0 24.1 6.0 0.0 0.05 -0.1 70 0.80 0.90 0.49 1 75.0 35.0 5.0 4 E 5.5 0.50 0 25.0 1.6 0.1 0.0 0.28 -0.08 0.5 0.0 0.2 0.05 500 440000 0 0 1 0
ROMERO 2500.0 5960.4 2.0 0.0 -0.8 0.2 70 0.75 0.80 0.50 5 150.0 16.0 15.0 R P 4.0 0.80 0 30.0 1.0 0.1 0.0 0.35 -0.15 0.4 0.0 0.2 1.25 10000 40000020 0 0 1 0
PACKER 8000.0 48273.3 2.0 0.0 0.0 0.0 90 0.65 0.85 0.35 5 150.0 13.0 5.0 R D 5.7 0.35 0 30.0 1.5 0.04 0.0 0.45 -0.25 0.5 0.0 0.56 0.40 20000 4000 440000 0 1 2
MONSTER 5000.0 20000.0 3.0 0.0 0.0 -0.35 80 0.65 0.85 0.55 5 110.0 45.0 25.0 4 P 7.0 0.45 0 35.0 1.5 0.07 0.0 0.45 -0.30 0.5 0.3 0.44 0.35 40000 28 1300045 0 1 20
ADMIRAL 1650.0 3851.4 2.0 0.0 0.0 -0.05 75 0.65 0.90 0.51 5 165.0 22.0 8.0 F P 8.5 0.52 0 30.0 1.0 0.15 0.0 0.27 -0.19 0.5 0.55 0.2 0.56 35000 0 400000 0 1 0
TRAM 1900.0 4795.9 1.0 0.0 -0.3 0.0 85 0.97 0.77 0.51 5 150.0 25.0 5.0 R P 8.5 0.45 0 30.0 1.3 0.08 0.0 0.0 -1.00 0.4 0.5 0.2 0.50 26000 1 400000 0 1 13
AIRTRAIN 25500.0 139272.5 1.0 0.0 0.0 0.0 85 0.58 0.7 0.46 5 140.0 24.0 5.0 4 D 10.00 0.45 0 27.0 1.2 0.05 0.0 0.47 -0.17 0.5 0.0 0.2 1.00 10000 0 0 0 1 0
ARTICT2 3800.0 30000.0 2.0 0.0 0.0 -0.5 90 0.45 0.75 0.5 5 120.0 18.0 5.0 R D 8.0 0.30 0 25.0 1.5 0.05 0.0 0.30 -0.15 0.5 0.0 0.65 0.25 35000 20002000 0000 0 1 0
TURISMO 1400.0 3000.0 2.0 0.0 -0.3 -0.2 70 0.75 0.85 0.45 5 240.0 30.0 10.0 4 P 11.0 0.51 0 30.0 1.2 0.13 0.0 0.15 -0.20 0.5 0.4 0.17 0.72 95000 40002004 C08401 1 1 1
FLATBED 8500.0 48804.2 2.5 0.0 0.0 0.3 90 0.70 0.7 0.46 5 140.0 25.0 80.0 R D 10.00 0.45 0 27.0 1.2 0.05 0.0 0.47 -0.17 0.5 0.0 0.62 0.43 10000 801 0 0 1 2
YANKEE 4500.0 18003.7 3.0 0.0 0.0 0.0 80 0.55 0.70 0.48 5 160.0 14.0 40.0 R D 4.5 0.80 0 30.0 1.8 0.12 0.0 0.30 -0.25 0.5 0.0 0.35 0.45 22000 4088 1 0 1 0
GOLFCART 1000.0 1354.2 4.0 0.0 0.0 -0.1 70 0.55 0.85 0.5 3 160.0 15.0 30.0 4 E 13.0 0.50 0 30.0 1.0 0.09 0.0 0.28 -0.13 0.5 0.0 0.26 0.50 9000 1100 8804 1 1 0
SOLAIR 2000.0 5500.0 2.0 0.0 0.0 0.0 75 0.75 0.80 0.52 4 165.0 20.0 10.0 R P 5.0 0.60 0 30.0 1.2 0.1 0.0 0.27 -0.17 0.5 0.2 0.24 0.48 18000 20 0 1 1 0
TOPFUN 1900.0 6333.3 2.0 0.0 0.0 -0.2 80 0.85 0.70 0.46 5 160.0 15.0 25.0 R D 6.0 0.80 0 30.0 1.5 0.07 2.0 0.35 -0.15 0.4 0.0 0.2 0.43 20000 1 1 0 3 13
GLENDALE 1600.0 4000.0 2.5 0.0 0.0 0.05 75 0.60 0.84 0.52 5 160.0 22.0 15.0 R P 6.2 0.55 0 30.0 0.8 0.07 0.0 0.35 -0.22 0.5 0.5 0.23 0.40 20000 0 10800002 1 1 0
OCEANIC 1900.0 4529.9 2.0 0.0 0.0 0.0 75 0.67 0.75 0.52 5 160.0 16.0 5.0 R P 5.0 0.55 0 30.0 1.0 0.1 0.0 0.35 -0.17 0.5 0.5 0.23 0.45 20000 0 10800000 2 1 0
PATRIOT 2500.0 7968.7 2.5 0.0 0.0 0.0 80 0.70 0.85 0.5 5 170.0 25.0 20.0 4 P 8.0 0.50 0 30.0 1.5 0.08 4.0 0.35 -0.35 0.5 0.0 0.28 0.25 40000 8 300000 0 1 0
HERMES 1950.0 4712.5 2.0 0.0 0.3 0.0 70 0.70 0.75 0.51 5 160.0 18.0 15.0 F P 3.5 0.60 0 28.0 1.0 0.05 0.0 0.35 -0.20 0.58 0.0 0.25 0.42 19000 40002000 1 1 3 0
SABRE 1700.0 4000.0 2.0 0.0 0.1 0.0 70 0.70 0.80 0.53 4 160.0 24.0 10.0 R P 8.0 0.52 0 35.0 1.3 0.08 5.0 0.30 -0.20 0.5 0.25 0.25 0.52 19000 0 10000006 1 1 0
ZR350 1400.0 2979.7 2.0 0.0 0.2 -0.1 70 0.80 0.80 0.51 5 200.0 28.0 10.0 R P 11.1 0.52 0 30.0 1.2 0.10 0.0 0.31 -0.15 0.5 0.3 0.24 0.60 45000 0 C00000 1 1 0
WALTON 1850.0 3534.0 2.5 0.0 0.0 0.0 75 0.70 0.70 0.5 4 150.0 14.0 25.0 4 D 6.5 0.5 0 35.0 1.6 0.12 0.0 0.35 -0.18 0.4 0.0 0.26 0.19 26000 40 10000006 1 1 0
REGINA 1500.0 3800.0 2.0 0.0 0.2 0.0 75 0.65 0.85 0.52 4 165.0 16.0 25.0 F P 5.0 0.60 0 30.0 1.0 0.1 0.0 0.27 -0.17 0.5 0.2 0.24 0.48 18000 20 1 1 1 0
COMET 1400.0 2200.0 2.2 0.0 0.1 -0.2 75 0.70 0.9 0.5 5 200.0 30.0 10.0 4 P 11.0 0.45 0 30.0 1.4 0.14 3.0 0.28 -0.15 0.5 0.3 0.25 0.60 35000 40000800 0 1 1 19
BURRITO 1900.0 5000.0 2.5 0.0 0.0 -0.2 85 0.60 0.87 0.51 5 150.0 25.0 20.0 R P 8.5 0.45 0 30.0 1.3 0.07 2.0 0.40 -0.25 0.4 0.5 0.2 0.50 26000 1 400000 0 1 13
CAMPER 1900.0 4000.0 2.6 0.0 -0.5 -0.4 85 0.60 0.80 0.46 5 120.0 16.0 20.0 R P 8.5 0.45 0 30.0 1.1 0.08 0.0 0.35 -0.10 0.4 0.5 0.2 0.50 26000 4000c000 400000 0 1 0
BAGGAGE 1000.0 1354.2 5.0 0.0 0.4 -0.2 70 1.00 0.85 0.5 3 160.0 20.0 30.0 R E 5.0 0.50 0 30.0 2.0 0.09 0.0 0.25 -0.10 0.5 0.0 0.26 0.50 9000 3300 4 1 1 0
DOZER 10000.0 35000.0 20.0 0.0 -0.5 -0.5 90 0.85 0.8 0.60 5 100.0 35.0 150.0 4 D 5.0 0.40 0 45.0 1.4 0.15 0.0 0.25 -0.20 0.35 0.0 0.45 0.20 5000 308 340220 0 1 17
RANCHER 2500.0 7604.2 2.5 0.0 0.0 -0.35 80 0.70 0.85 0.54 5 170.0 20.0 5.0 4 P 7.0 0.45 0 35.0 0.8 0.08 0.0 0.45 -0.25 0.45 0.3 0.44 0.35 40000 4020 100004 0 1 0
FBIRANCH 3500.0 11156.2 2.2 0.0 0.0 -0.2 80 0.80 0.80 0.52 5 170.0 22.0 5.0 4 P 8.5 0.50 0 30.0 0.7 0.15 0.0 0.34 -0.20 0.5 0.5 0.44 0.30 40000 4020 500000 0 1 0
VIRGO 1700.0 3435.4 2.0 0.0 0.0 -0.1 70 0.70 0.86 0.5 4 160.0 18.0 15.0 R P 7.0 0.50 0 32.0 0.8 0.10 0.0 0.31 -0.15 0.5 0.5 0.26 0.85 9000 40000000 10000000 0 0 0
GREENWOO 1600.0 4000.0 2.5 0.0 0.0 0.0 70 0.70 0.8 0.52 4 160.0 20.0 20.0 R P 5.4 0.60 0 30.0 1.1 0.12 5.0 0.32 -0.20 0.5 0.0 0.22 0.54 19000 0 10000001 0 3 0
HOTRING 1600.0 4500.0 1.4 0.0 0.2 -0.4 70 0.85 0.80 0.48 5 220.0 26.0 5.0 R P 10.0 0.52 0 30.0 1.5 0.10 10.0 0.29 -0.16 0.6 0.4 0.20 0.56 45000 40002004 C00000 1 1 0
SANDKING 2000.0 4000.0 2.2 0.0 0.0 -0.6 80 0.75 0.85 0.5 5 170.0 28.0 10.0 4 P 8.0 0.50 0 30.0 0.8 0.08 0.0 0.35 -0.31 0.5 0.0 0.38 0.35 40000 0 318800 0 1 22
BLISTAC 1000.0 2141.7 2.4 0.0 0.0 -0.10 50 0.85 0.85 0.5 5 200.0 26.0 5.0 F P 11.0 0.45 0 30.0 1.4 0.1 0.0 0.28 -0.12 0.5 0.0 0.25 0.50 35000 c0000000 C00000 1 1 0
BOXVILLE 5500.0 23489.6 3.0 0.0 0.0 0.0 80 0.82 0.70 0.46 5 140.0 14.0 25.0 R D 4.5 0.60 0 30.0 0.9 0.08 0.0 0.25 -0.25 0.35 0.6 0.26 0.40 22000 4009 201 0 3 13
BENSON 3500.0 13865.8 2.3 0.0 0.0 -0.2 80 0.75 0.70 0.46 5 140.0 14.0 20.0 R D 4.5 0.60 0 30.0 1.2 0.20 0.0 0.35 -0.15 0.45 0.0 0.46 0.53 22000 4088 1 1 3 0
MESA 1300.0 1900.0 3.0 0.0 0.2 -0.3 85 0.70 0.80 0.50 5 160.0 24.0 15.0 4 D 8.0 0.50 0 35.0 1.2 0.08 0.0 0.32 -0.20 0.35 0.4 0.18 0.30 25000 200840 0 0 1 0
BLOODRA 2100.0 5146.7 2.0 0.0 0.0 0.0 75 0.75 0.70 0.52 5 160.0 24.0 5.0 R P 6.2 0.55 0 35.0 1.0 0.06 3.0 0.35 -0.24 0.5 0.0 0.28 0.30 500 100 10800200 1 1 25
BLOODRB 1600.0 3866.7 2.0 0.0 0.0 0.0 75 0.80 0.70 0.52 5 160.0 26.0 5.0 R P 6.2 0.55 0 35.0 1.0 0.06 0.0 0.35 -0.17 0.5 0.0 0.28 0.30 500 0 800200 1 1 0
SUPERGT 1400.0 2800.0 2.0 0.0 -0.2 -0.24 70 0.75 0.86 0.48 5 230.0 26.0 5.0 R P 8.0 0.52 0 30.0 1.0 0.20 0.0 0.25 -0.10 0.5 0.3 0.40 0.54 105000 40002004 208000 0 0 1
ELEGANT 2200.0 5000.0 1.8 0.0 0.1 -0.1 75 0.70 0.80 0.46 5 165.0 20.0 10.0 R P 6.0 0.55 0 30.0 1.0 0.10 0.0 0.35 -0.15 0.5 0.3 0.2 0.30 35000 40000000 10400000 0 1 0
JOURNEY 3500.0 13865.8 3.0 0.0 0.0 0.0 80 0.62 0.70 0.46 5 140.0 14.0 25.0 R D 4.5 0.60 0 30.0 1.5 0.11 0.0 0.30 -0.15 0.5 0.0 0.46 0.53 22000 88 1 0 3 0
PETROL 3800.0 20000.0 2.0 0.0 0.0 -0.2 90 0.85 0.75 0.4 5 120.0 25.0 20.0 R D 8.0 0.30 0 35.0 1.0 0.10 0.0 0.25 -0.20 0.5 0.0 0.35 0.25 35000 20206008 1000001 0 1 2
RDTRAIN 5000.0 28000.0 2.0 0.0 0.5 -0.4 90 0.95 0.65 0.4 5 120.0 25.0 20.0 R D 8.0 0.30 0 25.0 0.7 0.10 0.0 0.20 -0.17 0.5 0.0 0.65 0.25 35000 20200008 200 0 1 2
NEBULA 1400.0 4000.0 2.0 0.0 0.3 -0.1 75 0.65 0.80 0.50 5 165.0 20.0 10.0 F P 8.0 0.55 0 30.0 1.4 0.10 0.0 0.27 -0.10 0.58 0.3 0.2 0.56 35000 0 400000 0 1 0
MAJESTIC 1400.0 3267.8 2.2 0.0 0.1 -0.1 75 0.75 0.80 0.52 5 165.0 22.0 10.0 R P 7.0 0.55 0 30.0 1.3 0.13 0.0 0.27 -0.15 0.5 0.3 0.2 0.56 35000 400000 10400000 0 1 0
BUCCANEE 1700.0 4500.0 2.2 0.0 0.3 0.0 70 0.60 0.86 0.54 4 160.0 24.0 15.0 R P 5.0 0.52 0 35.0 0.8 0.08 0.0 0.20 -0.20 0.54 0.4 0.3 0.52 19000 40400004 4 1 1 1
CEMENT 5500.0 33187.9 2.0 0.0 0.0 0.0 90 0.58 0.8 0.5 4 110.0 20.0 20.0 R D 03.17 0.40 0 30.0 1.4 0.06 0.0 0.45 -0.25 0.55 0.0 0.45 0.20 5000 404008 40200 0 1 0
TOWTRUCK 3500.0 12000.0 2.5 0.0 0.3 -0.25 80 0.85 0.70 0.46 5 160.0 25.0 30.0 R D 6.0 0.80 0 45.0 1.6 0.07 0.0 0.35 -0.15 0.25 0.0 0.2 0.50 20000 240001 1148200 0 3 13
FORTUNE 1700.0 4166.4 2.0 0.0 0.0 -0.2 70 0.70 0.84 0.53 4 160.0 20.0 10.0 R P 8.17 0.52 0 35.0 1.2 0.15 0.0 0.30 -0.10 0.5 0.25 0.3 0.52 19000 40000000 4 1 1 0
CADRONA 1200.0 2000.0 2.2 0.0 0.15 -0.1 70 0.70 0.86 0.5 4 160.0 20.0 5.0 R P 8.0 0.60 0 30.0 1.4 0.12 0.0 0.30 -0.08 0.5 0.0 0.26 0.50 9000 40000000 2 0 0 0
FBITRUCK 4000.0 10000.0 2.0 0.0 0.0 -0.2 85 0.65 0.85 0.54 5 170.0 25.0 25.0 4 D 6.0 0.40 0 30.0 0.8 0.1 0.0 0.30 -0.15 0.5 0.0 0.32 0.16 40000 4001 0 0 1 13
WILLARD 1800.0 4350.0 2.0 0.0 0.0 0.0 70 0.70 0.8 0.52 4 160.0 18.0 15.0 R P 5.4 0.60 0 30.0 1.1 0.15 0.0 0.32 -0.14 0.5 0.0 0.26 0.54 19000 40000000 0 0 3 0
FORKLIFT 1000.0 1354.2 2.0 0.0 -0.2 -0.35 70 0.80 0.85 0.5 3 60.0 20.0 15.0 F E 6.0 0.50 0 30.0 2.0 0.14 0.0 0.25 -0.20 0.5 0.0 0.26 0.50 9000 1300 1040024 1 1 0
TRACTOR 2000.0 5000.0 3.0 0.0 0.0 -0.2 70 0.90 0.85 0.5 4 70.0 20.0 90.0 R D 15.0 0.20 0 50.0 2.0 0.12 0.0 0.25 -0.05 0.5 0.0 0.26 0.50 9000 201310 1340005 1 1 28
COMBINE 8500.0 48804.2 5.0 0.0 0.3 -0.2 90 0.88 0.7 0.46 5 140.0 25.0 80.0 4 D 10.00 0.45 0 27.0 1.2 0.10 0.0 0.47 -0.11 0.5 0.0 1.20 0.43 10000 12c008 20 0 1 20
FELTZER 1600.0 4500.0 2.5 0.0 0.0 -0.15 75 0.65 0.9 0.5 5 200.0 28.0 25.0 R P 7.0 0.52 0 30.0 1.1 0.09 0.0 0.30 -0.10 0.5 0.3 0.25 0.60 35000 40002800 0 1 1 19
REMINGTN 1800.0 4000.0 2.0 0.0 -0.4 -0.2 70 0.75 0.80 0.56 5 160.0 23.0 5.0 R P 6.50 0.50 0 30.0 0.5 0.10 0.0 0.00 -0.20 0.4 0.6 0.21 0.41 30000 40002004 2410000 1 1 1
SLAMVAN 1950.0 4712.5 4.0 0.0 0.1 0.0 70 0.65 0.90 0.50 5 160.0 40.0 10.0 R P 10.0 0.50 0 28.0 1.6 0.12 0.0 0.35 -0.14 0.5 0.3 0.36 0.42 19000 40002000 2010000 1 3 0
BLADE 1500.0 2500.0 2.0 0.0 -0.2 0.1 70 0.75 0.84 0.53 4 160.0 24.0 5.0 R P 8.17 0.52 0 35.0 1.0 0.10 0.0 0.30 -0.15 0.44 0.25 0.3 0.52 19000 40202000 12010000 1 1 0
FREIGHT 5500.0 65000.0 3.0 0.0 0.0 0.0 90 0.58 0.8 0.5 4 110.0 20.0 20.0 R D 03.17 0.40 0 30.0 1.4 0.06 0.0 0.45 0.0 0.55 0.0 0.45 0.20 5000 8 200 0 1 2
STREAK 5500.0 65000.0 3.0 0.0 0.0 0.0 90 0.58 0.8 0.5 4 110.0 20.0 20.0 R D 03.17 0.40 0 30.0 1.4 0.06 0.0 0.45 -0.10 0.55 0.0 0.65 0.20 5000 8 200 0 1 2
VINCENT 1800.0 3000.0 2.0 0.0 0.3 0.0 70 0.70 0.8 0.5 4 160.0 18.0 20.0 F P 5.4 0.60 0 30.0 1.0 0.09 0.0 0.32 -0.16 0.56 0.0 0.26 0.54 19000 0 2 0 3 0
BULLET 1200.0 2500.0 1.8 0.0 -0.15 -0.2 70 0.75 0.90 0.48 5 230.0 30.0 10.0 R P 8.0 0.58 0 30.0 1.0 0.13 5.0 0.25 -0.10 0.45 0.3 0.15 0.54 105000 c0002004 204000 0 0 1
CLOVER 1600.0 3000.0 2.2 0.0 0.0 0.0 70 0.65 0.80 0.52 4 160.0 24.0 10.0 R P 8.0 0.5 0 35.0 1.0 0.10 0.0 0.30 -0.10 0.5 0.25 0.25 0.52 19000 40280000 10008004 1 1 0
SADLER 1700.0 4500.0 2.7 0.0 0.0 -0.05 75 0.65 0.70 0.5 5 165.0 25.0 20.0 4 D 8.5 0.5 0 35.0 0.8 0.08 3.0 0.25 -0.15 0.4 0.4 0.26 0.20 26000 200040 104004 0 1 0
RANGER 1700.0 4108.3 2.5 0.0 0.0 0.0 85 0.85 0.85 0.51 5 160.0 20.0 5.0 4 D 6.2 0.60 0 35.0 1.7 0.08 0.0 0.25 -0.15 0.5 0.25 0.27 0.23 25000 20 700000 0 1 0
HUSTLER 1700.0 4000.0 2.5 0.0 0.0 -0.05 75 0.75 0.75 0.52 5 160.0 22.0 10.0 R P 8.0 0.50 0 30.0 0.45 0.1 0.0 0.10 -0.15 0.5 0.5 0.18 0.45 20000 0 800000 2 1 0
INTRUDER 1800.0 4350.0 2.0 0.0 0.0 0.0 70 0.70 0.8 0.49 5 160.0 18.0 25.0 R P 5.4 0.60 0 30.0 1.0 0.09 0.0 0.32 -0.15 0.54 0.0 0.26 0.54 19000 0 2 0 3 0
PRIMO 1600.0 3300.0 2.2 0.0 0.0 0.0 70 0.70 0.8 0.54 4 160.0 18.0 7.0 R P 5.4 0.60 0 30.0 1.1 0.14 0.0 0.32 -0.14 0.5 0.0 0.26 0.54 19000 0 0 0 3 0
TAMPA 1700.0 4166.4 2.5 0.0 0.15 0.0 70 0.60 0.85 0.52 4 160.0 24.0 10.0 R P 8.17 0.52 0 35.0 0.7 0.08 3.0 0.30 -0.16 0.5 0.50 0.3 0.52 19000 40000004 4 1 1 1
SUNRISE 1600.0 3550.0 2.0 0.0 0.3 0.0 70 0.70 0.8 0.52 5 160.0 17.0 5.0 F P 5.4 0.60 0 30.0 1.0 0.09 0.0 0.30 -0.12 0.55 0.0 0.26 0.54 19000 40000000 1 0 3 0
MERIT 1800.0 4500.0 2.2 0.0 0.2 -0.10 75 0.65 0.8 0.49 5 165.0 22.0 10.0 R P 9.0 0.55 0 30.0 1.1 0.15 0.0 0.27 -0.08 0.54 0.3 0.2 0.56 35000 40000000 400001 0 1 0
UTILITY 2600.0 8666.7 3.0 0.0 0.0 0.0 80 0.85 0.70 0.46 5 160.0 18.0 10.0 R D 6.0 0.80 0 30.0 1.8 0.07 0.0 0.35 -0.18 0.25 0.0 0.2 0.50 20000 1 0 0 3 13
YOSEMITE 3000.0 6000.0 3.0 0.0 0.35 0.0 80 0.60 0.80 0.4 5 170.0 25.0 15.0 R P 8.5 0.30 0 30.0 1.0 0.12 0.0 0.24 -0.20 0.5 0.5 0.44 0.30 40000 20200020 504400 0 1 0
WINDSOR 1500.0 3500.0 3.0 0.0 0.05 -0.2 75 0.55 0.85 0.5 5 180.0 30.0 10.0 R P 8.0 0.45 0 30.0 0.65 0.07 0.0 0.15 -0.10 0.5 0.3 0.25 0.60 35000 40282804 0 1 1 1
MTRUCK_A 5000.0 20000.0 3.0 0.0 0.0 -0.35 80 0.65 0.85 0.55 5 110.0 45.0 25.0 4 P 7.0 0.45 0 35.0 1.5 0.07 0.0 0.45 -0.30 0.5 0.3 0.44 0.35 40000 28 1300045 0 1 20
MTRUCK_B 5000.0 20000.0 3.0 0.0 0.0 -0.35 80 0.65 0.85 0.55 5 110.0 45.0 25.0 4 P 7.0 0.45 0 35.0 1.5 0.07 0.0 0.45 -0.30 0.5 0.3 0.44 0.35 40000 28 1300045 0 1 20
URANUS 1400.0 2998.3 2.0 0.0 0.1 -0.3 75 0.80 0.85 0.47 5 200.0 20.0 5.0 R P 8.0 0.45 0 30.0 1.3 0.15 0.0 0.28 -0.10 0.5 0.3 0.25 0.60 35000 c0002800 4000001 1 1 0
JESTER 1500.0 3600.0 2.2 0.0 0.0 -0.05 75 0.85 0.8 0.5 5 200.0 28.0 10.0 F P 10.0 0.45 0 30.0 1.1 0.10 0.0 0.28 -0.15 0.5 0.3 0.25 0.60 35000 c0002804 4000000 1 1 1
SULTAN 1400.0 3400.0 2.4 0.0 0.1 -0.1 75 0.80 0.8 0.5 5 200.0 28.0 5.0 4 P 10.0 0.5 0 30.0 1.2 0.15 0.0 0.28 -0.20 0.5 0.3 0.25 0.60 35000 2800 4000002 1 1 0
STRATUM 1800.0 4500.0 2.1 0.0 0.1 -0.1 75 0.60 0.85 0.5 5 200.0 20.0 10.0 R P 7.0 0.5 0 30.0 1.0 0.15 0.0 0.28 -0.16 0.5 0.3 0.25 0.60 35000 2800 4000000 1 1 0
ELEGY 1500.0 3500.0 2.2 0.0 0.3 -0.15 75 0.65 0.9 0.5 5 200.0 28.0 5.0 R P 8.0 0.5 0 35.0 1.0 0.20 0.0 0.28 -0.10 0.5 0.3 0.25 0.60 35000 40002804 4000001 1 1 1
RCTIGER 100.0 24.1 5.0 0.0 0.0 -0.1 70 0.70 0.9 0.49 1 75.0 35.0 15.0 4 E 5.0 0.50 0 45.0 1.6 0.1 0.0 0.28 -0.14 0.5 0.0 0.2 0.05 500 0 40 0 1 0
FLASH 1400.0 2998.3 2.2 0.0 0.2 -0.1 75 0.75 0.9 0.5 5 200.0 24.0 10.0 F P 8.0 0.55 0 30.0 1.4 0.15 0.0 0.28 -0.10 0.5 0.3 0.25 0.60 35000 2804 4000001 1 1 1
TAHOMA 1800.0 4000.0 2.3 0.0 -0.3 0.0 75 0.75 0.85 0.52 5 160.0 24.0 10.0 R P 7.0 0.50 0 35.0 1.0 0.08 0.0 0.28 -0.20 0.45 0.3 0.25 0.60 35000 0 12010000 1 1 0
SAVANNA 1500.0 2500.0 2.0 0.0 -0.6 0.1 70 0.70 0.84 0.55 4 160.0 24.0 5.0 R P 8.17 0.52 0 35.0 1.0 0.10 0.0 0.30 -0.15 0.3 0.25 0.3 0.52 19000 200000 2010000 1 1 0
BANDITO 1000.0 2500.3 4.0 0.0 0.0 -0.3 80 0.70 0.88 0.55 4 170.0 35.0 5.0 R P 6.1 0.55 0 35.0 1.0 0.10 5.0 0.25 -0.20 0.35 0.0 0.60 0.40 15000 40001b04 308400 1 2 1
FREIFLAT 5500.0 33187.9 1.0 0.0 0.0 0.0 90 0.58 0.8 0.5 4 110.0 20.0 20.0 R D 03.17 0.40 0 30.0 1.4 0.06 0.0 0.45 0.0 0.55 0.0 0.45 0.20 5000 8 200 0 1 0
CSTREAK 5500.0 33187.9 1.0 0.0 0.0 0.0 90 0.58 0.8 0.5 4 110.0 20.0 20.0 R D 03.17 0.40 0 30.0 1.4 0.06 0.0 0.45 -0.10 0.55 0.0 0.65 0.20 5000 8 200 0 1 21
KART 300.0 150.0 5.0 0.0 0.0 -0.15 110 0.90 0.85 0.48 4 90.0 18.0 5.0 R P 15.0 0.20 0 35.0 1.5 0.20 0.0 0.25 -0.04 0.5 0.0 0.38 0.40 15000 40001b00 308201 1 2 18
MOWER 800.0 500.0 5.0 0.0 0.0 -0.3 80 0.70 0.80 0.48 3 60.0 12.0 30.0 R P 6.1 0.55 0 35.0 1.0 0.15 0.0 0.15 -0.05 0.5 0.0 0.38 0.40 15000 40001b00 1308001 1 2 28
DUNE 10000.0 50000.0 2.0 0.0 0.0 -0.6 80 0.65 0.85 0.5 5 110.0 35.0 25.0 4 P 7.0 0.45 0 35.0 0.8 0.10 0.0 0.40 -0.40 0.5 0.3 0.29 0.35 40000 6028 1300005 0 1 2
SWEEPER 800.0 632.7 5.0 0.0 0.0 -0.3 80 0.70 0.80 0.46 3 60.0 12.0 30.0 R P 6.1 0.55 0 35.0 1.6 0.15 0.0 0.34 -0.10 0.5 0.0 0.30 0.40 15000 40005a00 1308201 1 2 0
BROADWAY 1700.0 4166.4 2.0 0.0 0.1 0.1 70 0.65 0.75 0.46 4 160.0 20.0 10.0 R P 6.0 0.55 0 25.0 0.8 0.07 0.0 0.30 -0.14 0.5 0.25 0.3 0.52 19000 220000 2012100 1 1 0
TORNADO 1700.0 4166.4 2.0 0.0 -0.1 0.1 70 0.75 0.75 0.52 4 160.0 20.0 10.0 R P 6.0 0.55 0 35.0 0.8 0.08 0.0 0.30 -0.15 0.5 0.25 0.3 0.52 19000 400220000 2010000 1 1 0
DFT30 5500.0 33187.9 2.0 0.0 0.0 -0.2 90 0.65 0.8 0.40 5 110.0 20.0 20.0 R D 3.5 0.40 0 30.0 1.4 0.06 0.0 0.45 -0.25 0.55 0.0 0.45 0.20 5000 4008 200 0 1 2
HUNTLEY 2500.0 6000.0 2.5 0.0 0.0 -0.20 80 0.62 0.89 0.5 5 160.0 25.0 25.0 4 P 7.0 0.45 0 35.0 1.0 0.05 0.0 0.45 -0.21 0.45 0.3 0.44 0.35 40000 20 4404 0 1 0
STAFFORD 2200.0 6000.0 2.5 0.0 0.0 0.0 75 0.65 0.92 0.5 5 165.0 24.0 15.0 R P 5.0 0.55 0 30.0 1.1 0.1 0.0 0.27 -0.22 0.5 0.3 0.2 0.56 35000 0 400000 0 1 0
NEWSVAN 1900.0 6333.3 2.0 0.0 0.0 -0.15 80 0.85 0.70 0.46 5 160.0 15.0 15.0 R D 6.0 0.80 0 30.0 1.3 0.07 0.0 0.35 -0.15 0.45 0.0 0.2 0.43 20000 4001 2 0 3 13
TUG 800.0 632.7 5.0 0.0 0.0 -0.1 80 0.85 0.80 0.46 4 170.0 15.0 30.0 R P 6.1 0.55 0 35.0 1.2 0.15 0.0 0.34 -0.10 0.5 0.0 0.38 0.40 15000 1a00 308200 1 2 0
PETROTR 3800.0 30000.0 2.0 0.0 0.0 -0.5 90 0.45 0.75 0.5 5 120.0 18.0 5.0 R D 8.0 0.30 0 25.0 1.5 0.05 0.0 0.30 -0.15 0.5 0.0 0.65 0.25 35000 20002000 0000 0 1 0
EMPEROR 1800.0 4000.0 2.2 0.0 0.2 0.15 75 0.65 0.80 0.52 5 165.0 21.0 20.0 R P 8.0 0.45 0 30.0 0.9 0.13 3.0 0.30 -0.10 0.5 0.3 0.2 0.56 35000 40000000 400000 0 1 0
FLOAT 5500.0 33187.9 2.0 0.0 0.0 0.0 90 0.58 0.8 0.5 4 110.0 20.0 20.0 R D 03.17 0.40 0 30.0 1.4 0.06 0.0 0.45 -0.25 0.55 0.0 0.45 0.20 5000 8 200 0 1 0
EUROS 1400.0 2998.3 2.2 0.0 0.1 -0.1 75 0.70 0.8 0.5 5 200.0 24.0 5.0 4 P 8.0 0.55 0 30.0 1.2 0.15 0.0 0.30 -0.10 0.5 0.3 0.25 0.60 35000 40002804 0 1 1 0
HOTDOG 5500.0 23489.6 3.0 0.0 0.0 0.3 80 0.72 0.70 0.46 5 140.0 14.0 25.0 R D 4.5 0.60 0 30.0 0.6 0.08 0.0 0.30 -0.24 0.4 0.6 0.36 0.40 22000 40000009 201 0 3 13
CLUB 1400.0 3000.0 2.8 0.0 0.0 0.0 80 0.75 0.90 0.49 5 200.0 30.0 10.0 F P 11.0 0.45 0 30.0 1.7 0.1 0.0 0.28 -0.12 0.5 0.0 0.25 0.50 35000 2000 C00000 1 1 0
ARTICT3 3800.0 30000.0 2.0 0.0 0.0 -0.5 90 0.45 0.75 0.5 5 120.0 18.0 5.0 R D 8.0 0.30 0 25.0 1.5 0.05 0.0 0.30 -0.15 0.5 0.0 0.65 0.25 35000 20002000 0000 0 1 0
RCCAM 100.0 50.0 20.0 0.0 0.05 -0.2 70 0.60 0.90 0.49 1 60.0 50.0 10.0 4 E 5.5 0.50 0 25.0 3.0 0.3 0.0 0.15 -0.15 0.5 0.0 0.2 0.05 500 0 1000000 0 1 0
POLICE_LA 1600.0 4500.0 2.0 0.0 0.3 -0.1 75 0.75 0.85 0.50 5 200.0 25.0 10.0 R P 10.0 0.53 0 35.0 1.0 0.12 0.0 0.28 -0.12 0.55 0.0 0.2 0.24 25000 40000000 10200008 0 1 0
POLICE_SF 1600.0 4500.0 2.0 0.0 0.3 -0.15 75 0.75 0.85 0.52 5 200.0 25.0 10.0 R P 10.0 0.53 0 35.0 1.1 0.12 0.0 0.28 -0.17 0.55 0.0 0.2 0.24 25000 40000000 10200008 0 1 0
POLICE_VG 1600.0 4500.0 2.0 0.0 0.3 -0.1 75 0.75 0.85 0.52 5 200.0 25.0 10.0 R P 10.0 0.53 0 35.0 0.9 0.08 0.0 0.28 -0.17 0.55 0.0 0.2 0.24 25000 40000000 10200008 0 1 0
POLRANGER 2500.0 5500.0 3.0 0.0 0.0 -0.2 85 0.65 0.85 0.55 5 160.0 30.0 15.0 4 D 6.2 0.60 0 35.0 0.7 0.06 1.0 0.30 -0.25 0.5 0.25 0.27 0.23 25000 284020 308800 0 1 0
PICADOR 1600.0 3800.0 2.7 0.0 0.2 0.0 75 0.65 0.70 0.52 5 165.0 25.0 20.0 R D 8.5 0.5 0 35.0 0.8 0.08 2.0 0.25 -0.15 0.4 0.4 0.26 0.20 26000 40200040 104004 0 1 0
SWATVAN 5000.0 10000.0 2.5 0.0 0.0 -0.1 85 0.65 0.7 0.46 5 110.0 24.0 25.0 4 D 6.4 0.45 0 27.0 0.7 0.08 1.0 0.30 -0.18 0.5 0.0 0.32 0.06 40000 880010 1000000 0 1 13
ALPHA 1500.0 3400.0 2.0 0.0 0.1 -0.2 85 0.7 0.8 0.5 5 200.0 23.0 5.0 R P 7.0 0.55 0 30.0 1.2 0.12 0.0 0.30 -0.15 0.5 0.4 0.25 0.50 35000 40002800 200000 1 1 0
PHOENIX 1500.0 4000.0 2.2 0.0 0.3 -0.15 85 0.7 0.9 0.52 5 200.0 26.0 5.0 R P 6.0 0.55 0 30.0 0.8 0.08 0.0 0.28 -0.24 0.59 0.4 0.25 0.50 35000 2800 200000 1 1 0
BAGBOXA 1000.0 1354.2 5.0 0.0 0.4 -0.2 70 1.00 0.85 0.5 3 160.0 20.0 30.0 R E 5.0 0.50 0 30.0 2.0 0.09 0.0 0.25 -0.10 0.5 0.0 0.26 0.50 9000 3100 4 1 1 0
BAGBOXB 1000.0 1354.2 5.0 0.0 0.4 -0.2 70 1.00 0.85 0.5 3 160.0 20.0 30.0 R E 5.0 0.50 0 30.0 2.0 0.09 0.0 0.25 -0.10 0.5 0.0 0.26 0.50 9000 3100 4 1 1 0
STAIRS 1000.0 2500.0 5.0 0.0 0.4 -0.2 70 1.00 0.85 0.5 3 160.0 20.0 30.0 R E 5.0 0.50 0 30.0 2.0 0.09 0.0 0.25 -0.10 0.5 0.0 0.26 0.50 9000 3100 4 1 1 0
BOXBURG 5500.0 23489.6 3.0 0.0 0.0 0.0 80 0.82 0.70 0.46 5 140.0 14.0 25.0 R D 4.5 0.60 0 30.0 0.9 0.08 0.0 0.25 -0.25 0.35 0.6 0.36 0.40 22000 4009 201 0 3 13
FARM_TR1 400.0 400.0 5.0 0.0 -0.4 0.0 70 0.60 0.85 0.5 3 160.0 20.0 30.0 R E 5.0 0.50 0 30.0 1.0 0.10 0.0 0.25 -0.10 0.5 0.0 0.26 0.50 9000 3100 4 1 1 0
UTIL_TR1 1000.0 1354.2 5.0 0.0 0.0 0.0 70 1.00 0.85 0.5 3 160.0 20.0 30.0 R E 5.0 0.50 0 30.0 2.0 0.09 0.0 0.25 -0.10 0.5 0.0 0.26 0.50 9000 3100 4 1 1 0
ROLLER 1000.0 1354.2 4.0 0.0 0.0 -0.1 70 0.55 0.85 0.5 3 160.0 15.0 30.0 4 E 13.0 0.50 0 30.0 1.0 0.09 0.0 0.28 -0.13 0.5 0.0 0.26 0.50 9000 1100 8804 1 1 0
BIKE 500.0 161.7 4.0 0.0 0.05 -0.09 103 1.6 0.9 0.48 5 190.0 50.0 5.0 R P 15.0 0.50 0 35.0 0.85 0.15 0.0 0.15 -0.16 0.5 0.0 0.0 0.15 10000 1002000 0 1 1 4
MOPED 350.0 119.6 5.0 0.0 0.05 -0.1 103 1.8 0.9 0.48 3 190.0 30.0 5.0 R P 14.0 0.50 0 35.0 1.0 0.15 0.0 0.12 -0.17 0.5 0.0 0.0 0.11 10000 1000000 0 1 1 5
DIRTBIKE 500.0 195.0 5.0 0.0 0.05 -0.09 103 1.6 0.9 0.48 5 190.0 50.0 5.0 R P 14.0 0.50 0 35.0 0.85 0.15 0.0 0.15 -0.16 0.5 0.0 0.0 0.15 10000 1000000 0 1 1 7
FCR900 500.0 200.0 4.0 0.0 0.05 -0.09 103 1.5 0.9 0.48 5 190.0 50.0 5.0 R P 15.0 0.50 0 35.0 0.85 0.15 0.0 0.15 -0.16 0.5 0.0 0.0 0.11 10000 1000000 0 1 1 4
NRG500 400.0 200.0 4.0 0.0 0.08 -0.09 103 1.8 0.9 0.48 5 190.0 60.0 5.0 R P 15.0 0.50 0 35.0 0.85 0.15 0.0 0.15 -0.16 0.5 0.0 0.0 0.15 10000 1002000 2 1 1 4
HPV1000 500.0 240.0 4.5 0.0 0.05 -0.09 103 1.5 0.9 0.46 5 190.0 50.0 5.0 R P 15.0 0.50 0 35.0 0.85 0.15 0.0 0.15 -0.16 0.5 0.0 0.0 0.15 10000 1002000 0 1 1 4
BF400 500.0 200.0 4.5 0.0 0.05 -0.09 103 1.4 0.9 0.48 5 190.0 50.0 5.0 R P 15.0 0.50 0 35.0 0.85 0.15 0.0 0.15 -0.20 0.5 0.0 0.0 0.15 10000 1000000 0 1 1 4
WAYFARER 800.0 600.0 4.0 0.0 0.1 0.0 103 1.4 0.85 0.48 4 190.0 40.0 5.0 R P 10.0 0.55 0 35.0 0.65 0.20 0.0 0.09 -0.11 0.55 0.0 0.0 0.24 10000 41002000 0 1 1 8
QUADBIKE 400.0 300.0 5.0 0.0 0.05 -0.20 70 0.7 0.9 0.49 4 160.0 25.0 5.0 4 P 8.0 0.50 0 35.0 0.8 0.10 0.0 0.15 -0.15 0.5 0.0 0.2 0.50 9000 281300 205 1 1 12
BMX 100.0 39.0 7.0 0.0 0.05 -0.09 103 1.6 0.9 0.48 5 120.0 18.0 5.0 R P 19.0 0.50 0 35.0 0.80 0.15 0.0 0.20 -0.10 0.5 0.0 0.0 0.15 10000 41000000 0 1 1 9
CHOPPERB 100.0 39.0 6.0 0.0 0.05 -0.09 103 1.6 0.9 0.48 5 120.0 18.0 5.0 R P 19.0 0.50 0 35.0 0.85 0.15 0.0 0.20 -0.10 0.5 0.0 0.0 0.15 10000 41000000 0 1 1 11
MTB 100.0 60.0 5.0 0.0 0.05 -0.09 103 1.6 0.9 0.48 4 140.0 25.0 15.0 R P 19.0 0.50 0 35.0 0.85 0.15 0.0 0.20 -0.10 0.5 0.0 0.0 0.15 10000 41000000 2 1 1 10
FREEWAY 800.0 403.3 4.0 0.0 0.1 0.0 103 1.2 0.82 0.51 4 190.0 40.0 5.0 R P 10.0 0.55 0 35.0 0.65 0.20 0.0 0.09 -0.11 0.55 0.0 0.0 0.24 10000 1002000 0 1 1 6
PREDATOR 2200.0 29333.3 1.0 0.0 0.0 0.0 14 2.30 15.0 0.58 5 190.0 1.7 5.0 R P 0.05 0.01 0 24.0 1.0 3.0 0.0 0.10 0.1 0.0 0.0 0.2 0.33 40000 8000000 0 0 1 0
SPEEDER 2200.0 20210.7 1.0 0.0 0.0 0.0 22 2.5 15.0 0.65 5 190.0 2.5 5.0 R P 0.04 0.01 0 20.0 1.3 3.0 0.0 0.10 0.5 2.0 0.0 0.7 0.39 30000 8000400 0 0 1 0
REEFER 5000.0 25520.8 1.0 0.0 0.0 0.0 15 -1.50 15.0 0.45 5 190.0 0.7 5.0 R P 0.02 0.02 0 25.0 1.0 3.0 0.0 0.10 0.1 0.0 0.0 0.2 0.38 25000 8000000 0 0 1 0
RIO 3000.0 17312.5 1.0 0.0 0.0 0.0 15 -4.00 25.0 0.50 5 190.0 0.5 5.0 R P 0.02 0.00 0 20.0 1.0 3.0 0.0 15.00 0.1 0.0 0.0 0.2 0.23 70000 8000000 0 0 1 0
SQUALO 2200.0 29333.3 1.0 0.0 0.0 0.0 42 3.00 15.0 0.65 5 190.0 3.0 5.0 R P 0.02 0.00 0 24.0 0.45 5.0 0.0 0.10 0.05 0.0 0.0 0.2 0.33 60000 8000400 0 0 1 0
TROPIC 2200.0 29333.3 1.0 0.0 0.0 0.0 10 2.20 12.0 0.45 5 190.0 1.4 5.0 R P 0.05 0.01 0 24.0 1.8 3.0 0.0 0.10 0.1 0.0 0.0 0.2 0.33 73000 8000400 0 0 1 0
COASTGRD 1200.0 6525.0 1.0 0.0 -0.3 0.0 14 2.00 4.2 0.70 5 190.0 1.6 5.0 R P 0.05 0.01 0 24.0 1.0 3.0 0.0 3.20 0.1 2.5 0.0 0.2 0.18 10000 8000000 0 0 1 0
DINGHY 800.0 1483.3 1.0 0.0 0.0 0.0 16 3.50 3.5 1.00 5 190.0 1.2 5.0 R P 0.07 0.01 0 30.0 1.0 4.5 0.0 3.50 0.1 0.7 0.0 0.2 0.12 5000 8000000 0 0 1 0
MARQUIS 5000.0 155520.8 1.0 0.0 0.0 0.0 10 -3.50 25.0 0.40 5 190.0 0.5 5.0 R P 0.04 0.03 0 38.0 1.0 3.0 0.0 0.10 0.0 1.0 0.0 0.2 0.38 99000 8000000 0 0 1 0
CUPBOAT 3000.0 40000.0 1.0 0.0 0.0 0.0 35 2.00 15.0 0.50 5 190.0 3.0 5.0 R P 0.02 0.00 0 24.0 0.75 4.0 0.0 0.10 0.3 1.5 0.0 0.2 0.45 48000 8000400 0 0 1 0
LAUNCH 2200.0 20210.7 1.0 0.0 -1.0 0.0 22 1.5 15.0 0.65 5 190.0 1.5 5.0 R P 0.03 0.01 0 24.0 1.0 3.0 0.0 0.10 0.5 2.0 0.0 0.7 0.39 30000 8000400 0 0 1 0
SEAPLANE 5000.0 27083.3 12.0 0.0 0.0 0.0 9 0.83 45.0 0.5 1 200.0 1.7 5.0 4 P 0.01 0.05 0 24.0 1.5 0.75 0.0 0.10 0.0 2.0 0.0 1.0 0.05 10000 4000400 0 0 1 0
VORTEX 1900.0 4795.9 20.0 0.0 0.0 0.2 85 0.05 1.0 0.5 5 150.0 2.0 5.0 R P 1.0 0.50 0 30.0 0.5 0.05 0.0 0.33 -0.25 0.5 0.02 0.65 0.50 26000 301 400040 0 1 23
RUSTLER 5000.0 27083.3 10.0 0.0 0.0 0.0 75 0.65 0.9 0.5 1 200.0 16.0 5.0 4 P 1.5 0.45 0 45.0 2.0 0.15 0.0 0.50 -0.20 0.5 0.0 0.30 0.75 45000 4008108 400020 0 1 14
BEAGLE 10000.0 80000.0 14.0 0.0 0.0 0.0 75 0.65 0.9 0.5 1 200.0 16.0 5.0 4 P 1.5 0.45 0 45.0 2.0 0.15 0.0 1.00 -0.10 0.35 0.0 0.30 0.75 45000 24000008 400000 0 1 13
CROPDUST 5000.0 27083.3 15.0 0.0 0.0 0.0 75 0.65 0.9 0.5 1 200.0 16.0 5.0 4 P 1.5 0.45 0 45.0 2.0 0.15 0.0 0.55 -0.05 0.5 0.0 0.30 0.75 45000 4008000 400020 0 1 14
STUNT 5000.0 20000.0 14.0 0.0 0.0 0.0 75 0.65 0.9 0.5 1 200.0 16.0 5.0 4 P 1.5 0.45 0 45.0 2.0 0.15 0.0 0.50 -0.10 0.9 0.0 0.30 0.75 45000 4008100 400020 0 1 14
SHAMAL 15000.0 81250.0 8.0 0.0 0.0 0.0 75 0.55 0.8 0.7 1 200.0 16.0 5.0 4 P 1.5 0.15 0 45.0 4.0 0.15 0.0 1.00 -0.00 0.3 0.0 0.30 0.75 45000 400c108 400000 0 1 26
HYDRA 9000.0 48750.0 20.0 0.0 0.0 0.0 75 0.65 0.9 0.5 1 200.0 16.0 5.0 4 P 1.5 0.45 0 45.0 1.0 0.15 0.0 0.50 -0.20 0.8 0.0 0.60 0.75 45000 4008100 400000 0 1 27
NEVADA 25000.0 438750.0 10.0 0.0 0.0 0.0 75 0.65 0.9 0.5 1 200.0 16.0 5.0 4 P 1.0 0.45 0 45.0 1.0 0.10 0.0 0.40 -0.30 0.5 0.0 0.30 0.75 45000 400c108 400020 0 1 29
AT400 60000.0 9000000.0 4.0 0.0 0.0 0.0 75 1.5 0.9 0.85 1 200.0 16.0 5.0 4 P 1.0 0.45 0 45.0 1.5 0.15 0.0 0.50 -0.20 0.3 0.0 0.70 0.75 45000 2400c008 400000 0 1 15
ANDROM 40000.0 3000000.0 4.0 0.0 0.0 0.0 75 0.65 0.9 0.5 1 200.0 16.0 5.0 4 P 1.0 0.45 0 45.0 2.0 0.15 0.0 0.50 -0.20 0.5 0.0 0.30 0.75 45000 24114108 440000 0 1 0
DODO 5000.0 27083.3 12.0 0.0 0.3 0.0 75 0.65 0.9 0.5 1 200.0 16.0 5.0 4 P 1.5 0.45 0 45.0 1.5 0.15 0.0 0.50 -0.05 0.2 0.0 0.50 0.75 45000 4000000 400000 0 1 13
SPARROW 2500.0 6041.7 0.2 0.0 0.0 -0.1 75 0.65 0.9 0.5 1 200.0 16.0 5.0 4 P 5.0 0.45 0 30.0 2.0 0.1 0.0 0.50 -0.20 0.5 0.0 0.30 0.50 25000 2004000 400000 0 1 0
SEASPAR 3000.0 7250.0 0.1 0.0 0.0 -0.1 5 0.65 0.9 0.5 1 200.0 16.0 5.0 4 P 5.0 0.45 0 30.0 2.0 0.1 0.0 0.50 -0.20 0.5 0.0 0.30 0.60 28000 2004000 400000 0 1 0
MAVERICK 5000.0 29270.8 0.2 0.0 0.0 -0.1 75 0.65 0.9 0.5 1 200.0 16.0 5.0 4 P 5.0 0.45 0 30.0 2.0 0.15 0.0 0.50 -0.20 0.5 0.0 0.30 0.75 45000 2004000 400000 0 1 0
COASTMAV 3500.0 8458.3 0.2 0.0 0.0 -0.1 75 0.65 0.9 0.5 1 200.0 16.0 5.0 4 P 5.0 0.45 0 30.0 2.0 0.1 0.0 0.50 -0.20 0.5 0.0 0.30 0.65 50000 2004000 400000 0 1 0
POLMAV 4500.0 26343.7 0.2 0.0 0.0 -0.1 75 0.65 0.9 0.5 1 200.0 16.0 5.0 4 P 5.0 0.45 0 30.0 2.0 0.1 0.0 0.50 -0.20 0.5 0.0 0.30 0.65 52000 2004000 400000 0 1 0
HUNTER 10000.0 150000.0 0.2 0.0 0.0 0.0 75 0.65 0.9 0.5 1 200.0 16.0 5.0 4 P 5.0 0.45 0 30.0 1.0 0.05 0.0 0.20 -0.15 0.85 0.0 0.40 0.50 99000 200c000 400000 0 1 14
LEVIATHN 15000.0 200000.0 0.1 0.0 0.0 0.0 30 0.65 0.9 0.5 1 200.0 16.0 5.0 4 P 5.0 0.45 0 30.0 1.0 0.05 0.0 0.50 -0.20 0.9 0.0 0.30 0.50 25000 2004000 400000 0 1 0
CARGOBOB 20000.0 48333.3 0.2 0.0 0.0 -0.1 75 0.65 0.9 0.5 1 200.0 16.0 5.0 4 P 5.0 0.45 0 30.0 0.6 0.05 0.0 0.50 -0.10 0.3 0.0 0.30 0.50 25000 22004000 400000 0 1 0
RAINDANC 10000.0 96666.7 0.05 0.0 0.0 -1.0 75 0.65 0.9 0.5 1 200.0 16.0 5.0 4 P 5.0 0.45 0 30.0 1.5 0.1 0.0 0.20 -0.15 0.5 0.0 0.70 0.50 99000 2004000 400000 0 1 0
RCBARON 100.0 50.0 120.0 0.0 0.0 0.0 99 0.20 0.9 0.5 1 75.0 1.0 5.0 F P 0.5 0.50 0 45.0 0.6 0.1 0.0 0.25 -0.00 0.8 0.0 0.2 0.08 300 4000000 20 0 1 0
RCGOBLIN 100.0 24.1 0.2 0.0 0.0 -0.1 70 1.10 0.75 0.50 1 75.0 35.0 5.0 4 P 5.5 0.50 0 25.0 1.6 0.1 0.0 0.28 -0.08 0.5 0.0 0.2 0.05 800 2000000 0 0 1 0
RCRAIDER 100.0 24.1 0.2 0.0 0.0 -0.1 70 1.10 0.75 0.50 1 75.0 35.0 5.0 4 P 5.5 0.50 0 25.0 1.6 0.1 0.0 0.28 -0.08 0.5 0.0 0.2 0.10 500 2000000 0 0 1 0]]

local bike_han = [[!	BIKE		0.35	0.15	0.34	0.10	45.0	38.0	0.93	0.70	0.5		0.1		35.0	-40.0	-0.009	0.7		0.6
!	MOPED		0.35	0.25	0.25	0.04	35.0	25.0	0.90	0.75	0.8		0.1		35.0	-45.0	-0.010	0.7		0.5
!	DIRTBIKE	0.40	0.40	0.30	0.08	48.0	43.0	0.92	0.60	1.0		0.1		45.0	-35.0	-0.010	0.5		0.5
!	FCR900		0.33	0.15	0.28	0.15	45.0	38.0	0.93	0.70	0.5		0.1		35.0	-40.0	-0.009	0.7		0.6
!	NRG500		0.25	0.10	0.30	0.10	55.0	38.0	0.95	0.60	0.5		0.1		30.0	-35.0	-0.012	0.7		0.6
!	HPV1000		0.25	0.08	0.25	0.08	40.0	30.0	0.93	0.65	0.5		0.1		35.0	-40.0	-0.009	0.5		0.5
!	BF400		0.35	0.10	0.35	0.10	40.0	30.0	0.92	0.65	0.6		0.1		40.0	-40.0	-0.013	0.6		0.5
!	WAYFARER	0.10	0.05	0.20	0.05	30.0	25.0	0.945	1.20	0.7		0.1		33.0	-55.0	-0.006	0.4		0.3
!	QUADBIKE	0.14	0.04	0.14	0.08	48.0	43.0	0.88	0.60	1.0		0.1		45.0	-35.0	-0.007	1.0		0.5
!	BMX			0.35	0.50	0.30	0.09	48.0	43.0	0.92	0.60	1.0		0.1		45.0	-35.0	-0.007	1.0		0.5
!	CHOPPERB	0.35	0.50	0.30	0.09	40.0	30.0	0.92	0.60	1.0		0.1		45.0	-35.0	-0.007	0.6		0.5
!	MTB			0.35	0.30	0.25	0.08	48.0	43.0	0.92	0.60	1.0		0.1		35.0	-35.0	-0.015	0.6		0.5
!	FREEWAY		0.10	0.05	0.30	0.062	30.0	25.0	0.945	1.20	0.7		0.1		33.0	-55.0	-0.006	0.5		0.3]]

local boats_han = [[%	PREDATOR	0.79	0.5		0.6		7.0		0.60	-1.9	4.0			0.8		0.998	0.998		0.85	0.98	0.97	4.0
%	SPEEDER		0.65	0.5		0.5		8.0		0.70	-0.5	3.0			0.7		0.998	0.999		0.85	0.98	0.96	4.0
%	REEFER		0.35	0.6		0.0		3.0		0.20	-0.9	3.5			0.8		0.998	0.995		0.85	0.98	0.96	4.0
%	RIO			0.75	0.7		0.0		3.0		0.20	0.0		10.0		0.7		0.998	0.999		0.85	0.96	0.96	4.0
%	SQUALO		0.50	1.1 	0.2		9.0		0.80	1.2		4.0			0.90	0.998	0.999		0.89	0.975	0.97	4.0
%	TROPIC		0.35	0.6		0.5		4.0		0.35	-1.0	6.0			0.7		0.998	0.995		0.78	0.985	0.96	5.0
%	COASTGRD	0.50	0.65	0.5		8.0		0.60	-0.3	3.0			0.7		0.996	0.998		0.85	0.96	0.96	3.0
%	DINGHY		0.70	0.6		0.4		5.0		0.30	-0.8	3.0			0.94	0.993	0.997		0.85	0.94	0.94	3.0
%	MARQUIS		0.95	0.7		0.0		1.5		0.10	0.0		3.5			0.8		0.998	0.970		0.84	0.99	0.94	5.0
%	CUPBOAT		0.50	0.6		0.9		9.0 	0.80	-1.0	4.0			0.92	0.998	0.998		0.87	0.96	0.97	4.0
%	LAUNCH		0.50	0.9		0.5		6.0		0.50	-0.5	3.0			0.7		0.998	0.999		0.85	0.98	0.96	4.0
%	SEAPLANE	0.50	1.2		1.2		50.0	0.85	-0.4	20.0		0.93	0.998	0.999		0.95	0.96	0.96	4.5]]

local fly_han = [[$	SEAPLANE	0.5		0.40	-0.00006  0.002	 0.10	0.002	-0.002	0.0002	0.0020	0.020	0.15	1.0	 1.0  0.2		1.0		0.998	0.998	0.995		20.0	50.0  	20.0
$	VORTEX		0.4		0.30 	-0.0025   0.02	 0.10	0.001	-0.002	0.0003	0.0020	0.000	0.10	1.0	 1.0  0.2		0.995	1.000	1.000	0.998		0.0		0.0		10.0
$	RUSTLER		0.5		0.30 	-0.00010  0.004	 0.10	0.002	-0.002	0.0002	0.0020	0.008	0.10	0.2	 1.2  0.2		1.0		0.998	0.998	0.990		10.0	20.0	0.0
$	BEAGLE		0.65	0.10	-0.00010  0.002	 0.10	0.002	-0.002	0.0002	0.0020	0.018	0.15	1.0	 1.0  0.2		1.0		0.998	0.998	0.990		20.0	50.0  	20.0
$	CROPDUST	0.6		0.10	-0.00015  0.002	 0.10	0.002	-0.002	0.0003	0.0020	0.030	0.20	1.0	 1.0  0.2		1.0		0.9985	0.997	0.995		20.0	30.0  	20.0
$	STUNT		0.8		0.30	-0.00020  0.002	 0.010	0.004	-0.001	0.0005	0.0015	0.014	0.14	1.0	 1.0  0.2		1.0		0.997	0.997	0.997		10.0	5.0  	5.0
$	SHAMAL		0.5		1.00	-0.00003  0.001	 0.10	0.002	-0.002	0.00006	0.0015	0.006	0.10	0.3	 1.7  0.2		1.0		0.998	0.996	0.995		20.0	50.0	20.0
$	HYDRA		1.1		1.00 	-0.00010  0.004  0.10	0.002	-0.002	0.0001	0.0020	0.006	0.10	0.1	 1.3  0.2		1.0		0.998	0.997	0.995		10.0	10.0	40.0
$	NEVADA		0.4 	0.30	-0.00001  0.005	 0.10	0.001	-0.003	0.00003	0.0030	0.012	0.20	0.3	 1.3  0.1		1.0		0.998	0.997	0.995		20.0	100.0	20.0
$	AT400		0.35	1.00	-0.000005 0.0002 0.10	0.0003	-0.0001 0.00001	0.00005	0.008	0.10	0.5  1.5  0.1		1.0		0.998	0.997	0.995		20.0	100.0	20.0
$	ANDROM		0.35 	1.00	-0.000005 0.0002 0.10	0.0003	-0.0001	0.00001	0.00005	0.008	0.10	0.5  1.5  0.1		1.0		0.998	0.997	0.995		20.0	100.0	20.0
$	DODO		0.5		0.40	-0.00015  0.002	 0.10	0.003	-0.002	0.0003	0.0020	0.020	0.15	1.0	 1.0  0.2		1.0		0.998	0.998	0.995		20.0	50.0  	20.0
$	SPARROW		0.40	0.95	-0.001	  0.01	 0.05	0.0020	 2.0	0.0020	2.0 	0.7 	0.004	0.2	 1.0  0.2		0.998	0.980	0.980	0.990		1.0		1.0		10.0
$	SEASPAR		0.50	0.95	-0.001	  0.01	 0.05	0.0020	 2.0	0.0020	2.0 	0.7 	0.003	0.2	 1.0  0.2		0.998	0.980	0.980	0.990		1.0		1.0		10.0
$	MAVERICK	0.60	0.85	-0.0005	  0.005	 0.03	0.0010	 1.5	0.0010	1.5 	0.6		0.002	0.2	 1.0  0.2		0.9985	0.992	0.992	0.996		0.5		0.5		10.0
$	COASTMAV	0.60	0.95	-0.0005	  0.005	 0.03	0.0012	 1.0	0.0015	1.0 	0.6		0.002	0.2	 1.0  0.2		0.9985	0.992	0.992	0.996		1.5		1.5		10.0
$	POLMAV		0.60	0.75	-0.0005	  0.005	 0.03	0.0010	 1.5	0.0010	1.5 	0.6		0.002	0.2	 1.0  0.2		0.9985	0.992	0.992	0.996		0.5		0.5		10.0
$	HUNTER		0.55	0.50	-0.0005	  0.005	 0.01	0.001	 1.0	0.001	1.0		0.5		0.001	0.2	 1.0  0.2		0.9985	0.992	0.992	0.992		2.0		2.0		7.0
$	LEVIATHN	0.3		0.85	-0.0003	  0.005	 0.02	0.0007	 1.0	0.0007	1.0		0.5		0.001	0.2	 1.0  0.1		0.9985	0.992	0.992	0.995		2.0		2.0		10.0
$	CARGOBOB	0.4		0.85	-0.0003	  0.005	 0.02	0.0007	 1.0	0.0007	1.0		0.5		0.001	0.2	 1.0  0.1		0.9985	0.992	0.992	0.995		2.0		2.0		10.0
$	RAINDANC	0.4		0.85	-0.0003	  0.005	 0.02	0.0007	 1.0	0.0007	1.0		0.5		0.001	0.2	 1.0  0.1		0.9985	0.992	0.992	0.995		2.0		2.0		10.0
$	RCBARON		0.5		-0.05	-0.006	  0.6 	 0.30	0.015	-0.005	0.005	0.2		0.10	0.30	0.2	 1.0  0.1		1.0		0.998	0.996	0.990		10.0 	40.0	10.0
$	RCGOBLIN	0.20	0.75	-0.001	  0.05	 0.10	0.006	 6.0	0.006	6.0		0.7		0.015	0.2	 1.0  0.1		0.989	0.850	0.860	0.992		0.0		0.0		7.0
$	RCRAIDER	0.25	0.6		-0.002	  0.05	 0.10	0.009	 5.0	0.009	5.0		0.4		0.008	0.2	 1.0  0.1s		0.989	0.880	0.880	0.998		0.0		0.0		5.0]]

function reqandload(id)
	requestModel(id)
	loadAllModelsNow()
end

function CAutomobile(this, modelIndex, createdBy, bool)
	if config.vehicle[tostring(modelIndex)] ~= nil then
		need_id = config.vehicle[tostring(modelIndex)][random(1, #config.vehicle[tostring(modelIndex)])]
		if not hasModelLoaded(need_id) then reqandload(need_id) end
		modelIndex = need_id
	end
	CAutomobile(this, modelIndex, createdBy, bool)
end

function CBike(this, modelIndex, createdBy)
	if config.vehicle[tostring(modelIndex)] ~= nil then
		need_id = config.vehicle[tostring(modelIndex)][random(1, #config.vehicle[tostring(modelIndex)])]
		if not hasModelLoaded(need_id) then reqandload(need_id) end
		modelIndex = need_id
	end
	CBike(this, modelIndex, createdBy)
end

function CBoat(this, modelIndex, createdBy)
	if config.vehicle[tostring(modelIndex)] ~= nil then
		need_id = config.vehicle[tostring(modelIndex)][random(1, #config.vehicle[tostring(modelIndex)])]
		if not hasModelLoaded(need_id) then reqandload(need_id) end
		modelIndex = need_id
	end
	CBoat(this, modelIndex, createdBy)
end

function CPlane(this, modelIndex, createdBy)
	if config.vehicle[tostring(modelIndex)] ~= nil then
		need_id = config.vehicle[tostring(modelIndex)][random(1, #config.vehicle[tostring(modelIndex)])]
		if not hasModelLoaded(need_id) then reqandload(need_id) end
		modelIndex = need_id
	end
	CPlane(this, modelIndex, createdBy)
end

function CHeli(this, modelIndex, createdBy)
	if config.vehicle[tostring(modelIndex)] ~= nil then
		need_id = config.vehicle[tostring(modelIndex)][random(1, #config.vehicle[tostring(modelIndex)])]
		if not hasModelLoaded(need_id) then reqandload(need_id) end
		modelIndex = need_id
	end
	CHeli(this, modelIndex, createdBy)
end

function CBmx(this, modelIndex, createdBy)
	if config.vehicle[tostring(modelIndex)] ~= nil then
		need_id = config.vehicle[tostring(modelIndex)][random(1, #config.vehicle[tostring(modelIndex)])]
		if not hasModelLoaded(need_id) then reqandload(need_id) end
		modelIndex = need_id
	end
	CBmx(this, modelIndex, createdBy)
end

function CTrailer(this, modelIndex, createdBy)
	if config.vehicle[tostring(modelIndex)] ~= nil then
		need_id = config.vehicle[tostring(modelIndex)][random(1, #config.vehicle[tostring(modelIndex)])]
		if not hasModelLoaded(need_id) then reqandload(need_id) end
		modelIndex = need_id
	end
	CTrailer(this, modelIndex, createdBy)
end

function CTrain(this, modelIndex, createdBy)
	if config.vehicle[tostring(modelIndex)] ~= nil then
		need_id = config.vehicle[tostring(modelIndex)][random(1, #config.vehicle[tostring(modelIndex)])]
		if not hasModelLoaded(need_id) then reqandload(need_id) end
		modelIndex = need_id
	end
	CTrain(this, modelIndex, createdBy)
end

function CMonsterTruck(this, modelIndex, createdBy)
	if config.vehicle[tostring(modelIndex)] ~= nil then
		need_id = config.vehicle[tostring(modelIndex)][random(1, #config.vehicle[tostring(modelIndex)])]
		if not hasModelLoaded(need_id) then reqandload(need_id) end
		modelIndex = need_id
	end
	CMonsterTruck(this, modelIndex, createdBy)
end

function CQuadBike(this, modelIndex, createdBy)
	if config.vehicle[tostring(modelIndex)] ~= nil then
		need_id = config.vehicle[tostring(modelIndex)][random(1, #config.vehicle[tostring(modelIndex)])]
		if not hasModelLoaded(need_id) then reqandload(need_id) end
		modelIndex = need_id
	end
	CQuadBike(this, modelIndex, createdBy)
end

function main()
	if script.find("RandomChar") and not doesFileExist(getGameDirectory() .."\\modloader\\RandomChar\\RandomChar.txt") then thisScript():unload() end
	if script.find("RandomWeapon") and not doesFileExist(getGameDirectory() .."\\modloader\\RandomWeapon\\RandomWeapon.ide") then thisScript():unload() end

	if not doesFileExist(folder_txt) then GeneratedIDE() end

	repeat wait(0) until memory.read(0xC8D4C0, 4, false) == 9
	repeat wait(0) until fixed_camera_to_skin()
	
	CAutomobile = jmp_hook.new("void (__thiscall *)(uintptr_t, unsigned int, unsigned char, bool)", CAutomobile, 0x6B0A90)
	CBike = jmp_hook.new("void (__thiscall *)(uintptr_t, unsigned int, unsigned char)", CBike, 0x6BF430)
	CBoat = jmp_hook.new("void (__thiscall *)(uintptr_t, unsigned int, unsigned char)", CBoat, 0x6F2940)
	CPlane = jmp_hook.new("void (__thiscall *)(uintptr_t, unsigned int, unsigned char)", CPlane, 0x6C8E20)
	CHeli = jmp_hook.new("void (__thiscall *)(uintptr_t, unsigned int, unsigned char)", CHeli, 0x6C4190)
	CBmx = jmp_hook.new("void (__thiscall *)(uintptr_t, unsigned int, unsigned char)", CBmx, 0x6BF820)
	CTrailer = jmp_hook.new("void (__thiscall *)(uintptr_t, unsigned int, unsigned char)", CTrailer, 0x6D03A0)
	CTrain = jmp_hook.new("void (__thiscall *)(uintptr_t, unsigned int, unsigned char)", CTrain, 0x6F6030)
	CMonsterTruck = jmp_hook.new("void (__thiscall *)(uintptr_t, unsigned int, unsigned char)", CMonsterTruck, 0x6C8D60)
	CQuadBike = jmp_hook.new("void (__thiscall *)(uintptr_t, unsigned int, unsigned char)", CQuadBike, 0x6CE370)
	
	wait(-1)
end

function fixed_camera_to_skin() -- проверка на приклепление камеры к скину
	return (memory.read(getModuleHandle('gta_sa.exe') + 0x76F053, 1, false) >= 1 and true or false)
end

function GeneratedIDE()
	local freeID = {}
	for i = 1, 20000 do
		if not isModelAvailable(i) and not isModelInCdimage(i) then
			freeID[#freeID+1] = i
		end
	end

	local t={}
	local test123={}
	for str in string.gmatch(standard_car, "([^\n]+)") do
		local v_1, v_2, v_3, v_4, v_5 = tostring(str):match('^(%d+),(%s+%S+,%s+%S+,)(%s+%S+,%s+)(%S+)(,.+)$')
		t[tonumber(v_1)] = {v_3, v_5}
		test123[tonumber(v_1)] = {v_4}
	end
	
	local tha={}
	for strha in string.gmatch(handling_cfg, "([^\n]+)") do
		local v_1, v_2 = tostring(strha):match('^(%S+)(.+)$')
		tha[v_1] = v_2
	end
	
	local tbha={}
	for strbha in string.gmatch(bike_han, "([^\n]+)") do
		local v_1, v_2, v_3  = tostring(strbha):match('^(%S+%s+)(%S+)(.+)$')
		tbha[v_2] = {v_1, v_3}
	end

	local tboha={}
	for strboha in string.gmatch(boats_han, "([^\n]+)") do
		local v_1, v_2, v_3  = tostring(strboha):match('^(%S+%s+)(%S+)(.+)$')
		tboha[v_2] = {v_1, v_3}
	end

	local tfha={}
	for strfha in string.gmatch(fly_han, "([^\n]+)") do
		local v_1, v_2, v_3  = tostring(strfha):match('^(%S+%s+)(%S+)(.+)$')
		tfha[v_2] = {v_1, v_3}
	end


	local tas={}
	for stras in string.gmatch(audiosettings, "([^\n]+)") do
		local v_1, v_2 = tostring(stras):match('^(%w+)%s+(.+)$')
		tas[v_1] = v_2
	end

	local tcc={}
	for strcc in string.gmatch(carcols, "([^\n]+)") do
		local v_1, v_2 = tostring(strcc):match('^(%w+)(.+)$')
		tcc[v_1] = v_2
	end

	local tcm={}
	for strcm in string.gmatch(carmods, "([^\n]+)") do
		local v_1, v_2 = tostring(strcm):match('^(%w+)(.+)$')
		tcm[v_1] = v_2
	end

	config.vehicle = {}

	local txt = 'vehicles\n'
	local carcols_txt = 'carcols\n'
	local carmods_txt = 'carmods\n'
	local fla = audiosettings .. '\n'
	local handling_txt = 'handling\n'
	local num_models = 0

	local handling_txt_tet = ''
	local teststst = ""
	
	if not doesDirectoryExist(getGameDirectory() .."\\modloader\\RandomVehicle\\settings\\") then createDirectory(getGameDirectory() .."\\modloader\\RandomVehicle\\settings\\") end
	for k, v in pairs(NameModel) do
		local folder_dff = getGameDirectory() .."\\modloader\\RandomVehicle\\models\\" ..v.. "\\*.dff"
		local search, file = findFirstFile(folder_dff)
		if file ~= nil then config.vehicle[tostring(k)] = {k} end
		while file do
			if file ~= (v..".dff") then
				if not (teststst):match(v) then 
					teststst = v
					handling_txt_tet = ''
				end
				
				local no_dff = file:gsub("%.[dD][fF][fF]", "")
				local veh_new = freeID[1] .. ", " .. no_dff .. ", " .. no_dff .. ", " .. t[k][1] .. "" .. no_dff:upper() .. t[k][2] .. "\n"
				config.vehicle[tostring(k)][#config.vehicle[tostring(k)]+1] = tonumber(freeID[1])
				table.remove(freeID, 1)
				
				if tha[test123[k][1]] then 
					handling_txt_tet = handling_txt_tet .. handling_txt .. no_dff:upper() .. tha[test123[k][1]] .. '\n'
					if tbha[test123[k][1]] then
						handling_txt_tet = handling_txt_tet .. tbha[test123[k][1]][1] .. no_dff:upper() .. tbha[test123[k][1]][2] .. '\n'
					end
					if tboha[test123[k][1]] then
						handling_txt_tet = handling_txt_tet .. tboha[test123[k][1]][1] .. no_dff:upper() .. tboha[test123[k][1]][2] .. '\n'
					end
					if tfha[test123[k][1]] then
						handling_txt_tet = handling_txt_tet .. tfha[test123[k][1]][1] .. no_dff:upper() .. tfha[test123[k][1]][2] .. '\n'
					end
				end
				
				handling_txt_tet = handling_txt_tet .. txt .. veh_new
				
				if tcc[v] then handling_txt_tet = handling_txt_tet .. carcols_txt .. no_dff .. tcc[v] .. '\n' end
				if tcm[v] then handling_txt_tet = handling_txt_tet .. carmods_txt .. no_dff .. tcm[v] .. '\n' end
				fla = fla .. no_dff .. ' ' .. tas[v] .. '\n'
				num_models = num_models + 1
				handling_txt_tet = handling_txt_tet .. '\n'
					local folder_handling_txt =  getGameDirectory() .."\\modloader\\RandomVehicle\\settings\\"..v..".txt"
					local file_handling = io.open(folder_handling_txt, 'w+')
					file_handling:write(handling_txt_tet)
					file_handling:close()
			end
			file = findNextFile(search)
		end
	end

	local file = io.open(folder_fla, 'w+')
	file:write(fla)
	file:close()

	local file = io.open(folder_txt, 'w+')
	file:write('Спасибо за использование скрипта!\n\nmy vk: https://vk.com/dmitriyewichmods\ngithub: https://github.com/dmitriyewich/RandomVehicle\nyoutube: https://youtu.be/GFBau1hbbyg')
	file:close()

	savejson(convertTableToJsonString(config), "moonloader/config/RandomVehicle.json")
	callFunction(0x81E5E6, 4, 0, 0, u8:decode"[RU] Добавлено: ".. num_models ..u8:decode" моделей\nСформированы:\n	settings\\RandomVehicle.txt\n	Необходимо перезапустить игру\n[EN] Added: ".. num_models .."models\nGenerated:\n	settings\\RandomVehicle.txt\n	Need restart game", "RandomVehicle.lua", 0x00040000)
	os.execute('taskkill /IM gta_sa.exe /F /T')
end

-- Licensed under the GPL-3.0 License
-- Copyright (c) 2022, dmitriyewich <https://github.com/dmitriyewich/RandomVehicle>
