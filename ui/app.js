// State
let voiceEnabled = true;
let isRecording = false;
let speechRecognizer = null;
let lastDispatchedDay = -1;

// 1-Click Key Portal Links
function openKeyPortal(provider) {
  const urls = {
    groq: 'https://console.groq.com/keys',
    gemini: 'https://aistudio.google.com/app/apikey',
    openrouter: 'https://openrouter.ai/keys',
    cerebras: 'https://cloud.cerebras.ai/'
  };
  const url = urls[provider] || 'https://console.groq.com/keys';
  window.open(url, '_blank', 'noopener,noreferrer');
}

// Onboarding Key Submit
async function handleKeySubmit() {
  const key = document.getElementById('setup-api-key').value.trim();
  const provider = document.getElementById('setup-provider-select').value;

  // Save to backend
  await fetch('/api/settings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ai_api_key: key, ai_provider: provider })
  });

  // Open Apple Permission Sheet Modal
  document.getElementById('permission-modal').classList.add('active');
}

function closePermissionModal() {
  document.getElementById('permission-modal').classList.remove('active');
}

// Grant All Permissions & Unlock Apple 17 Suite
async function grantAllPermissions() {
  closePermissionModal();

  // Save permissions to server
  await fetch('/api/permissions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ all_granted: true })
  });

  // Transition UI
  document.getElementById('screen-setup').style.display = 'none';
  const mainScreen = document.getElementById('screen-main');
  mainScreen.style.display = 'block';
  mainScreen.style.animation = 'slideUp 0.5s cubic-bezier(0.16, 1, 0.3, 1)';

  // Update Dynamic Island
  const statusEl = document.getElementById('island-status');
  statusEl.innerText = 'SHIELDS ACTIVE';
  statusEl.style.color = '#34c759';

  // Voice Welcome
  speakVoice("जय हिन्द! इंटरनेट पुलिस अब आपके डिवाइस पर पूरी तरह सक्रिय है। सभी सुरक्षा शील्ड्स चालू हैं।");

  // Load fresh data
  loadStats();
  loadRecentLogs();
}

// Check initial permission status on app load
async function checkInitialStatus() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    if (data.permissions_granted) {
      document.getElementById('screen-setup').style.display = 'none';
      document.getElementById('screen-main').style.display = 'block';
    }
  } catch (e) {}
}

// Theme Switcher
function setTheme(themeName) {
  document.body.className = `theme-${themeName}`;
  fetch('/api/settings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ theme: themeName })
  });
}

// Dynamic Island Expansion Toggle
function toggleIslandExpansion() {
  const island = document.getElementById('dynamic-island');
  island.classList.toggle('expanded');
}

// Live Metrics
async function loadStats() {
  try {
    const res = await fetch('/api/stats');
    if (!res.ok) return;
    const stats = await res.json();
    document.getElementById('widget-total').innerText = stats.total_events || 0;
    document.getElementById('widget-ads').innerText = stats.blocked_ads || 0;
    document.getElementById('widget-threats').innerText = stats.blocked_threats || 0;
    document.getElementById('widget-dlp').innerText = stats.dlp_alerts || 0;
  } catch (e) {}
}

// Live Logs
async function loadRecentLogs() {
  try {
    const res = await fetch('/api/logs');
    if (!res.ok) return;
    const logs = await res.json();
    const tbody = document.getElementById('police-logs-tbody');
    if (!logs || logs.length === 0) return;

    tbody.innerHTML = logs.slice(0, 15).map(l => {
      const time = new Date(l.timestamp * 1000).toLocaleTimeString();
      let badgeBg = 'rgba(52, 199, 89, 0.2)';
      let badgeCol = '#34c759';
      if (l.action === 'BLOCKED') { badgeBg = 'rgba(255, 59, 48, 0.2)'; badgeCol = '#ff3b30'; }
      else if (l.action === 'ALERT') { badgeBg = 'rgba(255, 149, 0, 0.2)'; badgeCol = '#ff9500'; }

      return `
        <tr style="border-bottom:1px solid rgba(255,255,255,0.04);">
          <td style="padding:10px 12px; font-family:var(--sf-mono);">${time}</td>
          <td style="padding:10px 12px;"><strong>${l.subsystem}</strong></td>
          <td style="padding:10px 12px; font-family:var(--sf-mono); max-width:280px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escapeHtml(l.target)}</td>
          <td style="padding:10px 12px;"><span style="background:${badgeBg}; color:${badgeCol}; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:600;">${l.action}</span></td>
          <td style="padding:10px 12px; font-size:11px;">${l.risk_level}</td>
          <td style="padding:10px 12px; font-size:12px; color:var(--apple-muted);">${escapeHtml(l.details)}</td>
        </tr>
      `;
    }).join('');
  } catch (e) {}
}

// Chat with Internet Police
async function sendPoliceMessage() {
  const input = document.getElementById('chat-input');
  const text = input.value.trim();
  if (!text) return;

  const chatBox = document.getElementById('police-chat-box');

  // Append user bubble
  const userBubble = document.createElement('div');
  userBubble.className = 'chat-bubble bubble-user';
  userBubble.innerHTML = `<strong>You:</strong> ${escapeHtml(text)}`;
  chatBox.appendChild(userBubble);
  input.value = '';

  // Append thinking bubble
  const thinkBubble = document.createElement('div');
  thinkBubble.className = 'chat-bubble bubble-police';
  thinkBubble.innerHTML = `<em>👮 Internet Police is analyzing...</em>`;
  chatBox.appendChild(thinkBubble);
  chatBox.scrollTop = chatBox.scrollHeight;

  try {
    const res = await fetch('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ prompt: text })
    });
    const data = await res.json();
    thinkBubble.innerHTML = `<strong>👮 Internet Police:</strong>\n\n${escapeHtml(data.response)}`;
    chatBox.scrollTop = chatBox.scrollHeight;

    // Speak response out loud in Jarvis mode
    if (voiceEnabled) {
      speakVoice(data.response);
    }
  } catch (e) {
    thinkBubble.innerHTML = `<span style="color:#ff3b30;">Police dispatch connection error: ${escapeHtml(e.message)}</span>`;
  }
}

function sendQuickText(text) {
  document.getElementById('chat-input').value = text;
  sendPoliceMessage();
}

// 9:00 PM Nightly Dispatch Trigger
async function triggerNightlyDispatch() {
  const chatBox = document.getElementById('police-chat-box');
  const dispatchBubble = document.createElement('div');
  dispatchBubble.className = 'chat-bubble bubble-police';
  dispatchBubble.style.border = '2px solid #ff9500';
  dispatchBubble.innerHTML = `<em>⏰ Generating 9:00 PM Nightly Security Dispatch...</em>`;
  chatBox.appendChild(dispatchBubble);
  chatBox.scrollTop = chatBox.scrollHeight;

  try {
    const res = await fetch('/api/dispatch/generate', { method: 'POST' });
    const data = await res.json();
    dispatchBubble.innerHTML = `<strong>🚨 21:00 NIGHTLY SECURITY DISPATCH</strong><br><br>${escapeHtml(data.summary)}`;
    chatBox.scrollTop = chatBox.scrollHeight;

    if (voiceEnabled) {
      speakVoice("इंटरनेट पुलिस दैनिक सुरक्षा ब्रीफिंग: आज आपके डिवाइस पर सभी नेटवर्क कनेक्शन सुरक्षित रहे।");
    }
  } catch (e) {
    dispatchBubble.innerHTML = `Dispatch error: ${escapeHtml(e.message)}`;
  }
}

// Check for 9:00 PM automated dispatch
function checkNightlyClock() {
  const now = new Date();
  const hours = now.getHours();
  const minutes = now.getMinutes();
  const day = now.getDate();

  // If 21:00 (9:00 PM) and hasn't fired today
  if (hours === 21 && minutes === 0 && lastDispatchedDay !== day) {
    lastDispatchedDay = day;
    triggerNightlyDispatch();
  }
}

// Voice Assistant (Text to Speech)
function speakVoice(text) {
  if (!voiceEnabled || !window.speechSynthesis) return;

  window.speechSynthesis.cancel(); // Stop any pending speech
  const cleanedText = text.replace(/[*#`_]/g, '');
  const utterance = new SpeechSynthesisUtterance(cleanedText);
  utterance.rate = 1.05;
  utterance.pitch = 0.95;

  const voices = window.speechSynthesis.getVoices();
  const hindiVoice = voices.find(v => v.lang.includes('hi') || v.lang.includes('IN'));
  if (hindiVoice) utterance.voice = hindiVoice;

  window.speechSynthesis.speak(utterance);
}

function toggleVoiceAudio() {
  voiceEnabled = !voiceEnabled;
  const btn = document.getElementById('voice-toggle-btn');
  btn.innerText = voiceEnabled ? '🔊 Voice: ON' : '🔇 Voice: MUTED';
  btn.style.opacity = voiceEnabled ? '1' : '0.6';
}

// Microphone Voice Recording (Speech Recognition)
function toggleVoiceRecording() {
  const SpeechRec = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (!SpeechRec) {
    alert('Voice input is not supported in this browser. Please use Chrome, Safari or Edge.');
    return;
  }

  const micBtn = document.getElementById('mic-btn');

  if (isRecording && speechRecognizer) {
    speechRecognizer.stop();
    isRecording = false;
    micBtn.classList.remove('active');
    return;
  }

  speechRecognizer = new SpeechRec();
  speechRecognizer.lang = 'hi-IN'; // Multi-language Hindi/Indian English support
  speechRecognizer.continuous = false;
  speechRecognizer.interimResults = false;

  speechRecognizer.onstart = () => {
    isRecording = true;
    micBtn.classList.add('active');
  };

  speechRecognizer.onresult = (event) => {
    const transcript = event.results[0][0].transcript;
    document.getElementById('chat-input').value = transcript;
    sendPoliceMessage();
  };

  speechRecognizer.onerror = (event) => {
    isRecording = false;
    micBtn.classList.remove('active');
  };

  speechRecognizer.onend = () => {
    isRecording = false;
    micBtn.classList.remove('active');
  };

  speechRecognizer.start();
}

function escapeHtml(text) {
  if (!text) return '';
  return String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Initialization & Auto-Polling
checkInitialStatus();
loadStats();
loadRecentLogs();
setInterval(() => {
  loadStats();
  loadRecentLogs();
  checkNightlyClock();
}, 3000);
