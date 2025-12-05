
const facts = [
  "Android malware often hides inside free or cracked apps.",
  "Over 90% of mobile malware targets Android devices.",
  "Malicious APKs can steal passwords, photos, and messages.",
  "Some malware secretly subscribes users to premium SMS services.",
  "Fake update apps are a common malware delivery trick.",
  "Malware can silently record microphone audio in the background.",
  "Banking trojans overlay fake login screens on real apps.",
  "Malicious apps can track GPS location without permission.",
  "Some APKs mine cryptocurrency, draining battery and CPU.",
  "Spyware can capture keystrokes typed on the device.",
  "Ransomware locks Android phones and demands payment.",
  "Adware constantly shows unwanted ads to generate revenue.",
  "Malware developers use packers to avoid detection.",
  "Drive-by downloads install malware without user action.",
  "Side-loaded APKs are the most common source of infections.",
  "Zero-Click Exploits: Some sophisticated malware can infect a device without any user interaction, often via vulnerabilities in communication apps.",
  "Repackaging Attack: Malware developers frequently use repackaging—taking a legitimate app, injecting malicious code, and republishing it to unofficial stores.",
  "Binder Communication: Android's Binder mechanism, used for inter-process communication (IPC), is frequently abused by malware to control legitimate system processes.",
  "Botnet Deployment: Infected devices are often grouped into mobile botnets to carry out large-scale distributed denial-of-service (DDoS) attacks or spam campaigns.",
  "Obfuscation Methods: Malicious code often employs string encryption and control-flow flattening to confuse reverse engineers and automated analysis tools.",
  "The Joker Malware: The infamous Joker malware family uses a technique called fleeceware to repeatedly sign victims up for premium subscriptions.",
  "Smishing (SMS Phishing): Malware is often delivered via smishing, where victims receive a malicious link in a text message disguised as an alert.",
  "App Cloners: Malware sometimes uses app cloning techniques to duplicate legitimate banking apps, allowing the trojan to capture credentials.",
  "Runtime Permission Requests: Modern malware often starts with few permissions but requests highly sensitive permissions only after installation and execution.",
  "Accessibility Services Abuse: Trojans heavily abuse Android Accessibility Services to grant themselves permissions, click buttons, and enter data silently.",
  "DEX File Dynamic Loading: Many advanced threats use dynamic loading of DEX files (Dalvik Executable) at runtime from an external server to bypass static analysis.",
  "Certificate Spoofing: Some early malware families attempted to spoof or reuse legitimate developer certificates to trick security systems into trusting the app's source.",
  "Vulnerability Chaining: Advanced attackers frequently use a chain of two or more vulnerabilities (e.g., a memory corruption bug followed by a privilege escalation bug) to gain root access.",
  "Stagefright Vulnerability: The severe Stagefright vulnerability allowed an attacker to take control of a phone by sending a specially crafted multimedia message (MMS).",
  "Targeting Specific Regions: Many mobile banking trojans are geo-fenced, meaning they only activate their malicious payload if the device is located in a specific target country.",
  "Silent Updates: Malware delivered through unofficial stores or sideloading can perform silent, unauthorized app updates to install new malicious payloads.",
  "Code Emulation Evasion: Malware often checks its runtime environment for signs of an emulator or sandbox, and will refuse to execute its payload if it detects it is being analyzed.",
  "Mobile Ransomware Growth: Mobile ransomware has specialized in locking the screen and demanding gift cards or cryptocurrency.",
  "Root Exploits: The most dangerous malware attempts to exploit vulnerabilities to gain root access (superuser), giving them complete control over the device.",
  "TrollStore Distribution: In Russia and China, TrollStores (unofficial third-party app stores) are a primary vector for distributing malicious or cracked applications.",
  "High Monetization: Mobile adware and premium SMS scams remain popular because they have a high return on investment (ROI) for attackers.",
  "Permission Fatigue: The abundance of legitimate apps requesting many permissions has led to permission fatigue in users, making them likely to blindly grant dangerous permissions.",
  "Kernel-Level Persistence: The most persistent mobile malware tries to embed itself into the device kernel, making it extremely difficult to remove even with factory resets.",
  "Accessibility of Tools: The rise of Malware-as-a-Service (MaaS) means that even low-skilled attackers can purchase and deploy sophisticated mobile trojans for a fee.",
  "Google Play Protect: Google's Play Protect uses machine learning to scan apps daily (both on and off-device) to identify and remove malicious applications.",
];

let index = 0;
const ticker = document.getElementById("ticker");


setInterval(() => {
  ticker.textContent = facts[index]; 
  index = (index + 1) % facts.length; 
}, 5000);
function toggleInfo() {
  const box = document.getElementById("infoPopup");
  box.style.display = box.style.display === "block" ? "none" : "block";
}

let loadPercent = 0;
let loadInterval;

function showLoader() {
  loadPercent = 0;
  const overlay = document.getElementById("loaderOverlay");
  overlay.style.display = "flex";

  loadInterval = setInterval(() => {
    if (loadPercent < 95) {
      loadPercent += Math.floor(Math.random() * 5) + 1;
      document.getElementById(
        "loaderText"
      ).innerText = `Loading ${loadPercent}%`;
    }
  }, 130);
}

function hideLoader() {
  clearInterval(loadInterval);
  document.getElementById("loaderText").innerText = "Loading 100%";
  setTimeout(() => {
    document.getElementById("loaderOverlay").style.display = "none";
  }, 250);
}

function animateGauge(p) {
  document.getElementById("gaugeArc").style.transform = `rotate(${p * 1.8}deg)`;
  document.getElementById("gaugeValue").innerText = p + "%";
}

function severityClass(score) {
  if (score >= 0.7) return "high";
  if (score >= 0.4) return "medium";
  return "low";
}

async function analyzeApk() {
  const file = document.getElementById("apkFile").files[0];
  if (!file) return alert("Select an APK!");

  showLoader();

  const form = new FormData();
  form.append("apkFile", file);


  const res = await fetch("/analyze", { method: "POST", body: form });
  const data = await res.json();

  hideLoader();

  if (data.error) return alert(data.error);

  // Get Modal Elements
  const modalVerdict = document.getElementById("modalVerdict");
  const modalLabel = document.getElementById("modalLabel");
  const modalAppType = document.getElementById("modalAppType");
  const expCount = document.getElementById("expCount");
  const explicitList = document.getElementById("explicitList");
  const impCount = document.getElementById("impCount");
  const implicitList = document.getElementById("implicitList");
  const excessCount = document.getElementById("excessCount");
  const excessList = document.getElementById("excessList");
  const modelScoreList = document.getElementById("modelScoreList");
  const avgScore = document.getElementById("avgScore");
  const chartModelScore = document.getElementById("chartModelScore");
  const chartPermissions = document.getElementById("chartPermissions");
  const chartRisk = document.getElementById("chartRisk");
  const chartInfoGain = document.getElementById("chartInfoGain");
  const chartReliefF = document.getElementById("chartReliefF");
  const chartBorda = document.getElementById("chartBorda");
  const riskyList = document.getElementById("riskyList");
  const resultModal = document.getElementById("resultModal");

  modalVerdict.innerText = data.verdict;
  modalLabel.innerText = data.label;
  modalAppType.innerText = data.app_type;

  expCount.innerText = data.explicit_permissions.length;
  explicitList.innerHTML = data.explicit_permissions
    .map((p) => `<li>${p}</li>`)
    .join("");

  impCount.innerText = data.implicit_permissions.length;
  implicitList.innerHTML = data.implicit_permissions.length
    ? data.implicit_permissions.map((p) => `<li>${p}</li>`).join("")
    : "<li>No implicit permissions</li>";

  excessCount.innerText = data.excessive_permissions.length;
  excessList.innerHTML = data.excessive_permissions
    .map((p) => `<li>${p}</li>`)
    .join("");

  let scoresHTML = "";
  for (const [m, v] of Object.entries(data.model_scores))
    scoresHTML += `<li><b>${m}</b>: ${v}</li>`;
  modelScoreList.innerHTML = scoresHTML;

  avgScore.innerText = data.average_score;

  const threat = Math.round((data.threat_score ?? data.average_score) * 100);
  animateGauge(threat);

  
  chartModelScore.src = "data:image/png;base64," + data.charts.model_scores;
  chartPermissions.src = "data:image/png;base64," + data.charts.permission_pie;
  chartRisk.src = "data:image/png;base64," + data.charts.risk_meter;

  chartInfoGain.src =
    "data:image/png;base64," + data.feature_selection.info_gain;
  chartReliefF.src = "data:image/png;base64," + data.feature_selection.relief_f;
  chartBorda.src =
    "data:image/png;base64," + data.feature_selection.borda_count;

  riskyList.innerHTML = "";
  window.lastRisky = data.top_risky_permissions; 
  data.top_risky_permissions.forEach(([p, s]) => {
    riskyList.innerHTML += `
      <div class="risky-item">
        <span class="badge ${severityClass(s)}">${p}</span>
        <span>${(s * 100).toFixed(2)}%</span>
      </div>`;
  });

  resultModal.style.display = "block";
}

function closeModal() {
  document.getElementById("resultModal").style.display = "none";
}


const downloadBtn = document.getElementById("downloadBtn");
downloadBtn.onclick = async () => {
  const payload = {
    verdict: document.getElementById("modalVerdict").innerText,
    label: document.getElementById("modalLabel").innerText,
    threat_score:
      Number(document.getElementById("gaugeValue").innerText.replace("%", "")) /
      100,
    top_risky_permissions: window.lastRisky,
  };

  
  const res = await fetch("/download_report", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  const blob = await res.blob();
  const url = window.URL.createObjectURL(blob);

  const a = document.createElement("a");
  a.href = url;
  a.download = "malware_analysis_report.pdf";
  a.click();
};
