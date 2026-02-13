// app.js

const MQTT_CLUSTER_HOST  = "d58a808ab88a41da8c222dc52957a7ab.s1.eu.hivemq.cloud";
const MQTT_WS_PORT       = 8884; // HiveMQ Cloud WebSockets port
const MQTT_USERNAME      = "Greenhouse1";
const ROOT_TOPIC         = "greenhouse";

// UI elements
const connectionStatusEl        = document.getElementById("connectionStatus");
const lastUpdateEl              = document.getElementById("lastUpdate");

const mqttPassphraseEl          = document.getElementById("mqttPassphrase");
const mqttConnectBtn            = document.getElementById("mqttConnectButton");
const mqttErrorEl               = document.getElementById("mqttError");

const airQualityEl                = document.getElementById("airQuality");
const envTimestampEl            = document.getElementById("envTimestamp");

const uptimeEl                  = document.getElementById("uptime");
const controlModeEl             = document.getElementById("controlMode");
const lightStateEl              = document.getElementById("lightState");
const sysTimestampEl            = document.getElementById("sysTimestamp");

// Timestamp
let lastStatusTimestampMs       = null;

// MQTT statuses
let client     = null;
let connected  = false;
let connecting = false;

// Last sensor values
let lastStatusAirQuality  = null;
let lastSensorTimestamp   = null; // seconds

// Last device state
let lastUptime          = null; // number or null
let lastDesiredLight    = null; // boolean or null
let lastMode            = null; // "auto" | "manual" | null
let lastSystemTimestamp = null; // seconds

// Encrypted MQTT password
const ENCRYPTED_MQTT_PASSWORD = {
        salt: "ELdz1quCae+0pWRWfu+ctQ==",
        iv:   "+73J/iBzfWvvWAek",
        data: "QIdTtKUdyyq/v/gPEKXewMSVA9ThSY4QqTrO+g=="
};

// MQTT & connection
const mqttUrl = `wss://${MQTT_CLUSTER_HOST}:${MQTT_WS_PORT}/mqtt`;
if (mqttConnectBtn) {
	mqttConnectBtn.addEventListener("click", async () => {
		if (connecting || connected) return;

		if (!mqttPassphraseEl) return;

		const passphrase = mqttPassphraseEl.value;
		if (!passphrase) return;

		connecting = true;
		clearMqttError();
		mqttConnectBtn.disabled = true;
		mqttPassphraseEl.disabled = true;
		connectionStatusEl.textContent = "connecting";

		let mqttPassword;
		try {
			mqttPassword = await decryptMqttPassword(passphrase);
		} catch {
			connecting = false;
			mqttConnectBtn.disabled = false;
			mqttPassphraseEl.disabled = false;
			connectionStatusEl.textContent = "disconnected";
			showMqttError("Wrong passphrase");
			return;
		}

		// Create MQTT client
		if (client) {
			client.end(true);
			client = null;
		}
		client = mqtt.connect(mqttUrl, {
			username: MQTT_USERNAME,
			password: mqttPassword,
			clean: true,
			reconnectPeriod: 5000,
			connectTimeout: 4000
		});

		attachMqttHandlers(client);
	});
}

if (mqttPassphraseEl) {
	mqttPassphraseEl.addEventListener("keydown", (e) => {
		if (e.key === "Enter") {
			e.preventDefault();
			mqttConnectBtn?.click();
		}
	});
}

// Command ID storage
const CMD_ID_KEY = "greenhouse:lastCmdId";
let lastCmdId = Number(localStorage.getItem(CMD_ID_KEY)) || Date.now();
function nextCmdId() {
	lastCmdId = lastCmdId + 1;
	localStorage.setItem(CMD_ID_KEY, String(lastCmdId));
	return lastCmdId;
}

// ---------- Web Crypto ----------
async function decryptMqttPassword(passphrase) {
	try {
		const enc = new TextEncoder();
		const dec = new TextDecoder();

		const salt = Uint8Array.from(atob(ENCRYPTED_MQTT_PASSWORD.salt), c => c.charCodeAt(0));
		const iv   = Uint8Array.from(atob(ENCRYPTED_MQTT_PASSWORD.iv),   c => c.charCodeAt(0));
		const data = Uint8Array.from(atob(ENCRYPTED_MQTT_PASSWORD.data), c => c.charCodeAt(0));

		const keyMaterial = await crypto.subtle.importKey(
			"raw",
			enc.encode(passphrase),
			"PBKDF2",
			false,
			["deriveKey"]
		);

		const key = await crypto.subtle.deriveKey(
			{
				name: "PBKDF2",
				salt,
				iterations: 100000,
				hash: "SHA-256"
			},
			keyMaterial,
			{ name: "AES-GCM", length: 256 },
			false,
			["decrypt"]
		);

		const plaintext = await crypto.subtle.decrypt(
			{ name: "AES-GCM", iv },
			key,
			data
		);

		return dec.decode(plaintext);
	} catch (e) {
		throw new Error("decrypt_failed");
	}
}

// ---------- Helpers to update UI ----------
function setText(el, v) {
	if (!el) return;
	if (v === null || v === undefined) el.textContent = "—";
	else el.textContent = String(v);
}

function valueToText(b) {
	if (b === null || b === undefined) return "—";
	if (typeof b === "boolean") return b ? "ON" : "OFF";
	if (typeof b === "number") {
		if (b % 1 === 0) return String(b);
		return b.toFixed(2);
	}
	return String(b);
}

function displayTime(seconds) {
	if (seconds === null || seconds === undefined) return "—";
	seconds = Number(seconds);
	if (Number.isNaN(seconds)) return "—";
	if (seconds < 60) return `${seconds}s`;
	const m = Math.floor((seconds % 3600) / 60);
	if (seconds < 3600) return `${m}m ${seconds % 60}s`;
	const h = Math.floor(seconds / 3600);
	return `${h}h ${m}m ${seconds % 60}s`;
}

function displayDateAndTimeSince(unixTimestampSeconds) {
	if (unixTimestampSeconds === null ||
		unixTimestampSeconds === undefined ||
		Number.isNaN(unixTimestampSeconds ||
		unixTimestampSeconds <= 1609459200 // 2021-01-01
		)) return "—";
	const d = new Date(unixTimestampSeconds * 1000);
	const options = {
		timeZone: 'Asia/Jakarta',
		hour: '2-digit',
		minute: '2-digit',
		second: '2-digit',
		hour12: true,
		weekday: 'long',
		year: 'numeric',
		month: 'long',
		day: 'numeric'
	};
	return `${d.toLocaleDateString('en-US', options)}`; // WIB-7
}

function showMqttError(message, detail = null) {
	if (!mqttErrorEl) return;

	if (detail) {
		mqttErrorEl.textContent = `${message} (${detail})`;
	} else {
		mqttErrorEl.textContent = message;
	}

	mqttErrorEl.style.display = "block";
}

function clearMqttError() {
	if (!mqttErrorEl) return;
	mqttErrorEl.style.display = "none";
	mqttErrorEl.textContent = "";
}

function applyDeviceStatusToUI() {
	setText(airQualityEl, valueToText(lastStatusAirQuality));
	setText(envTimestampEl, displayDateAndTimeSince(lastSensorTimestamp));
	setText(uptimeEl, displayTime(lastUptime));
	setText(lightStateEl, valueToText(lastDesiredLight));
	setText(controlModeEl, valueToText(lastMode));
	setText(sysTimestampEl, displayDateAndTimeSince(lastSystemTimestamp));
	updateLastUpdateText();
}

function updateLastUpdateText() {
	if (!lastUpdateEl) return;

	if (lastStatusTimestampMs === null) {
		lastUpdateEl.textContent = "—";
		return;
	}

	const deltaSec = Math.floor((Date.now() - lastStatusTimestampMs) / 1000);

	if (deltaSec < 5) {
		lastUpdateEl.textContent = `just now (${deltaSec}s ago)`;
	} else {
		lastUpdateEl.textContent = `${displayTime(deltaSec)} ago`;
	}
}

// ---------- MQTT handlers ----------
function attachMqttHandlers(client) {

	// ---------- MQTT lifecycle ----------
	client.on("connect", () => {
		connected = true;
		connecting = false;
		connectionStatusEl.textContent = "connected";
		mqttConnectBtn.disabled = true; // stay disabled while connected
		mqttPassphraseEl.disabled = true;
		client.subscribe(`${ROOT_TOPIC}/status/#`, { qos: 0 }, (err) => {
		if (err) console.warn("Subscribe error:", err);
		});
		updateLastUpdateText();
	});

	client.on("reconnect", () => {
		connected = false;
		connecting = true;
		connectionStatusEl.textContent = "reconnecting";
		clearMqttError();
	});

	client.on("close", () => {
		const wasConnected = connected;

		connected = false;
		connecting = false;
		mqttConnectBtn.disabled = false;
		mqttPassphraseEl.disabled = false;
		connectionStatusEl.textContent = "disconnected";
		lastStatusTimestampMs = null;
		updateLastUpdateText();

		if (wasConnected) {
			showMqttError("Connection lost");
		}
	});

	client.on("error", (err) => {
		console.error("MQTT error", err);
		if (!connected) {
			connecting = false;
			mqttConnectBtn.disabled = false;
			mqttPassphraseEl.disabled = false;
			connectionStatusEl.textContent = "disconnected";

			const msg = (err && err.message) ? err.message.toLowerCase() : "";


			if (msg.includes("not authorized") || msg.includes("bad user")) {
				showMqttError("Authentication failed");
			} else if (msg.includes("certificate") || msg.includes("tls")) {
				showMqttError("TLS / certificate error");
			} else if (msg.includes("websocket") || msg.includes("socket")) {
				showMqttError("WebSocket connection failed");
			} else {
				showMqttError("Unable to connect to broker", err.message);
			}
		}
	});

	// ---------- Message handling ----------
	client.on("message", (topic, payload) => {
		let msg = null;
		let changed = false;
		try {
			msg = JSON.parse(payload.toString());
		} catch (e) {
			console.warn("Invalid JSON on", topic, payload.toString());
			return;
		}

		if (topic.startsWith(`${ROOT_TOPIC}/status/`)) {
			lastStatusTimestampMs = Date.now();
			changed = true;
		}

		// helper to update last status values
		function ifMsgValueElseNull(value) {
			return (msg && typeof msg[value] !== "undefined") ? msg[value] : null;
		}

		if (topic === `${ROOT_TOPIC}/status/sensors`) {
			lastStatusAirQuality = ifMsgValueElseNull("air_quality");
			lastSensorTimestamp  = ifMsgValueElseNull("timestamp");
		} else if (topic === `${ROOT_TOPIC}/status/effectors`) {
			lastDesiredLight     = ifMsgValueElseNull("desired_grow_light_on");
			lastMode             = ifMsgValueElseNull("mode");
			lastSystemTimestamp  = ifMsgValueElseNull("timestamp");
		} else if (topic === `${ROOT_TOPIC}/status/system`) {
			lastUptime           = ifMsgValueElseNull("uptime_s");
			lastSystemTimestamp  = ifMsgValueElseNull("timestamp");

		} else {
			// ignore unknown topics
		}

		if (changed) applyDeviceStatusToUI();
	});
}

// Initial UI state
setText(airQualityEl, null);
setText(uptimeEl, null);
setText(controlModeEl, null);
setText(lightStateEl, null);
connectionStatusEl.textContent = "disconnected";
setInterval(updateLastUpdateText, 1000);
