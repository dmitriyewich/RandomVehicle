script_name("RandomVehicle")
script_author("dmitriyewich")
script_url("https://vk.com/dmitriyewichmods", 'https://github.com/dmitriyewich/RandomVehicle')
script_properties('work-in-pause', 'forced-reloading-only')
script_version("0.1")

local lffi, ffi = pcall(require, 'ffi')
local lmemory, memory = pcall(require, 'memory')

local lencoding, encoding = pcall(require, 'encoding')
encoding.default = 'CP1251'
u8 = encoding.UTF8

local folder_fla = getGameDirectory() ..'\\modloader\\$ASI\\$fastman92 limit adjuster\\data\\gtasa_vehicleAudioSettings.cfg'
local folder_txt =  getGameDirectory() .."\\modloader\\RandomVehicle\\RandomVehicle.txt"
local folder_custom =  getGameDirectory() .."\\modloader\\RandomVehicle\\CUSTOM.ide"

changelog = [[
	RandomVehicle v0.1
		- Релиз
]]

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

function SetModelIndex(this, modelIndex)
	if config.vehicle[tostring(modelIndex)] ~= nil then
		need_id = config.vehicle[tostring(modelIndex)][random(1, #config.vehicle[tostring(modelIndex)])]
		if not hasModelLoaded(need_id) then
			requestModel(need_id)
			loadAllModelsNow()
		end
		modelIndex = need_id
	end
	SetModelIndex(this, modelIndex)
end

function main()
	-- if not doesFileExist(folder) then GeneratedIDE() end
	if not doesFileExist(folder_txt) then GeneratedIDE() end

	repeat wait(0) until memory.read(0xC8D4C0, 4, false) == 9
	repeat wait(0) until fixed_camera_to_skin()

	SetModelIndex = jmp_hook.new("void (__thiscall *)(uintptr_t this, unsigned int modelIndex)", SetModelIndex, 0x6D6A40)

	wait(-1)
end

function fixed_camera_to_skin() -- проверка на приклепление камеры к скину
	return (memory.read(getModuleHandle('gta_sa.exe') + 0x76F053, 1, false) >= 1 and true or false)
end

function GeneratedIDE()
	local freeID = {}
	os.remove(folder_custom)
	for i = 1, 20000 do
		if not isModelAvailable(i) and not isModelInCdimage(i) then
			freeID[#freeID+1] = i
		end
	end

	local t={}
	for str in string.gmatch(standard_car, "([^\n]+)") do
		local v_1, v_2, v_3 = tostring(str):match('^(%d+),(%s+%w+,%s+%w+,)(.+)')
		t[tonumber(v_1)] = v_3
	end

	local tas={}
	for stras in string.gmatch(audiosettings, "([^\n]+)") do
		local v_1, v_2 = tostring(stras):match('^(%w+)%s+(.+)$')
		tas[v_1] = v_2
	end

	config.vehicle = {}

	local list = 'cars\n'
	local txt = 'vehicles.ide\n'
	local fla = audiosettings .. '\n'

	for k, v in pairs(NameModel) do
		local folder_dff = getGameDirectory() .."\\modloader\\RandomVehicle\\models\\" ..v.. "\\*.dff"
		local search, file = findFirstFile(folder_dff)
		if file ~= nil then config.vehicle[tostring(k)] = {k} end
		while file do
			if file ~= (v..".dff") then
				local no_dff = file:gsub("%.[dD][fF][fF]", "")
				local veh_new = freeID[1] .. ", " .. no_dff .. ", " .. no_dff .. ", " .. t[k] .. "\n"
				config.vehicle[tostring(k)][#config.vehicle[tostring(k)]+1] = tonumber(freeID[1])
				table.remove(freeID, 1)
				list = list .. veh_new
				txt = txt .. veh_new
				fla = fla .. no_dff .. ' ' .. tas[v] .. '\n'
			end
			file = findNextFile(search)
		end
	end

	list = list .. 'end'

	local file = io.open(folder_fla, 'w+')
	file:write(fla)
	file:close()

	local file = io.open(folder_custom, 'w+')
	file:write(list)
	file:close()

	local file = io.open(folder_txt, 'w+')
	file:write(txt)
	file:close()

	savejson(convertTableToJsonString(config), "moonloader/config/RandomVehicle.json")
	callFunction(0x81E5E6, 4, 0, 0, u8:decode"[RU] Сформированы:\n	RandomVehicle.ide\\CUSTOM.ide\\RandomVehicle.txt\n	Необходимо перезапустить игру\n[EN] Generated:\n	RandomVehicle.ide\\CUSTOM.ide\\RandomVehicle.txt\n	Need restart game", "RandomVehicle.lua", 0x00040000)
	os.execute('taskkill /IM gta_sa.exe /F /T')
end

-- Licensed under the GPL-3.0 License
-- Copyright (c) 2022, dmitriyewich <https://github.com/dmitriyewich/RandomVehicle>