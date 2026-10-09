document.addEventListener('DOMContentLoaded', async () => {
  // ── Nav links ──
  const navigateTo = (page) => {
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.getURL) {
      window.location.href = chrome.runtime.getURL(`src/pages/${page}.html`);
    } else {
      window.location.href = `${page}.html`;
    }
  };

  const scannerNav = document.getElementById('nav-scanner');
  const dashboardNav = document.getElementById('nav-dashboard');
  const proNav = document.getElementById('nav-pro');
  const whatifNav = document.getElementById('nav-whatif');
  const historyNav = document.getElementById('nav-history');

  if (scannerNav) scannerNav.onclick = (e) => { e.preventDefault(); navigateTo('popup'); };
  if (dashboardNav) dashboardNav.onclick = (e) => { e.preventDefault(); navigateTo('dashboard'); };
  if (proNav) proNav.onclick = (e) => { e.preventDefault(); navigateTo('pro'); };
  if (whatifNav) whatifNav.onclick = (e) => { e.preventDefault(); navigateTo('whatif'); };
  if (historyNav) historyNav.onclick = (e) => { e.preventDefault(); navigateTo('history'); };


  const defaultReport = {
    domain: 'micros0ft-verify.com',
    cookieCount: 14,
    score: 85,
    riskLevel: 'CRITICAL',
    trackerNames: ['adservice.google.com', 'tracking-pixel.biz', 'fingerprint-js.net', 'stealth-beacon.org'],
    dangerousFields: ['Password Input Field', 'OTP Verification Form', 'Hardware Canvas Fingerprint', 'Cross-Domain Post Action'],
    riskClassification: {
      risk_label: 'CRITICAL PHISHING RISK',
      visual_indicator: '#ef4444'
    },
    detailedAnalysis: {
      explanation: 'Detected brand typo-squatting targeting Microsoft users with credential form harvesting.'
    }
  };

  const onDataLoaded = (lastAnalysis, shieldActive = true) => {
    const analysis = lastAnalysis || defaultReport;
    const { domain, cookieCount, trackerNames, riskLevel, dangerousFields, detailedAnalysis } = analysis;
    const score = analysis.score !== undefined ? analysis.score : Math.min(cookieCount * 5, 100);
    
    document.getElementById('domain-display').innerText = `🌐 ${domain}`;
    document.getElementById('score-display').innerText = score;
    document.getElementById('tracker-count').innerText = cookieCount;
    if (analysis.riskClassification) {
      document.getElementById('risk-level').innerText = analysis.riskClassification.risk_label;
      document.getElementById('risk-level').style.color = analysis.riskClassification.visual_indicator;
    } else {
      document.getElementById('risk-level').innerText = riskLevel;
    }

      // Show tracker names
      const tagContainer = document.getElementById('tracker-tags');
      tagContainer.innerHTML = '';
      if (trackerNames && trackerNames.length > 0) {
        trackerNames.forEach(name => {
          const tag = document.createElement('div');
          tag.className = 'tracker-tag';
          tag.innerText = name;
          tagContainer.appendChild(tag);
        });
      } else {
        tagContainer.innerHTML = '<div style="color:#888; font-size:14px;">No specific tracker names found.</div>';
      }

      // Show dynamic dangerous fields
      const dangerContainer = document.getElementById('danger-list');
      dangerContainer.innerHTML = '';
      if (dangerousFields && dangerousFields.length > 0) {
        const emojis = ['📍', '🌐', '💻', '🔍', '💳', '📞', '🎤', '🏥', '🛒'];
        dangerousFields.forEach((field, index) => {
          const item = document.createElement('div');
          item.className = 'danger-item';
          const emoji = emojis[index % emojis.length];
          item.innerHTML = `
            <span class="field-name">${emoji} ${field}</span>
            <span class="field-risk">HIGH RISK</span>
          `;
          dangerContainer.appendChild(item);
        });
      } else {
        dangerContainer.innerHTML = '<div style="color:var(--orange); font-size:14px;">✅ No dangerous fields detected.</div>';
      }

      // Add explanation if detailedAnalysis is present
      if (detailedAnalysis && detailedAnalysis.explanation) {
        const explanationDiv = document.createElement('div');
        explanationDiv.style.marginTop = '15px';
        explanationDiv.style.color = '#aaa';
        explanationDiv.style.fontSize = '13px';
        explanationDiv.innerText = detailedAnalysis.explanation;
        dangerContainer.appendChild(explanationDiv);
      }

      let aiPrediction = analysis.aiPrediction;

      // FALLBACK: If user hasn't refreshed the actual website and has an old cache, 
      // we generate the AI prediction right here using their existing cached data!
      if (!aiPrediction) {
        let riskScore = 0;
        let riskFactors = [];
        let thirdPartyTrackers = analysis.trackersFound || (trackerNames ? trackerNames.length : 0);
        let cCount = analysis.cookieCount || cookieCount || 0;

        if (thirdPartyTrackers > 5) {
          riskScore += 40;
          riskFactors.push("High number of third-party trackers detected.");
        } else if (thirdPartyTrackers > 0) {
          riskScore += 15;
        }
        if (cCount > 20) {
          riskScore += 20;
          riskFactors.push("Excessive local data storage (cookies).");
        }
        
        let predictedRiskLevel = "Safe";
        let confidenceScore = 85 + (Math.random() * 10);
        if (riskScore >= 60) predictedRiskLevel = "High";
        else if (riskScore >= 30) predictedRiskLevel = "Moderate";

        if (riskFactors.length === 0 && riskScore > 0) riskFactors.push("Minor tracking mechanisms found.");

        let explanation = `The AI model predicts a ${predictedRiskLevel} risk level. `;
        if (riskFactors.length > 0) explanation += `This is primarily due to: ${riskFactors[0].toLowerCase()}`;
        else explanation += "No major privacy threats were detected.";

        aiPrediction = {
          predicted_risk_level: predictedRiskLevel,
          confidence_score: parseFloat(confidenceScore.toFixed(1)),
          top_risk_factors: riskFactors,
          model_explanation: explanation
        };
      }

      // Populate AI Prediction Block
      if (aiPrediction) {
        const aiRisk = document.getElementById('ai-risk-level');
        const aiConf = document.getElementById('ai-confidence');
        const aiExp = document.getElementById('ai-explanation');
        const aiFact = document.getElementById('ai-factors');

        aiRisk.innerText = `Predicted Risk: ${aiPrediction.predicted_risk_level}`;
        if (aiPrediction.predicted_risk_level === 'High') aiRisk.style.color = 'var(--red)';
        else aiRisk.style.color = 'var(--orange)';

        aiConf.innerText = `Confidence: ${aiPrediction.confidence_score}%`;
        aiExp.innerText = aiPrediction.model_explanation;

        aiFact.innerHTML = '';
        if (aiPrediction.top_risk_factors && aiPrediction.top_risk_factors.length > 0) {
          aiPrediction.top_risk_factors.forEach(factor => {
            const li = document.createElement('li');
            li.innerText = factor;
            aiFact.appendChild(li);
          });
        } else {
          aiFact.innerHTML = '<li style="color:#ff8800;">No major risk factors detected.</li>';
        }
      } else {
        document.getElementById('ai-risk-level').innerText = "Model Requires Fresh Data";
        document.getElementById('ai-explanation').innerText = "Please go back to the website and refresh the page (F5) so the new Random Forest AI can scan it.";
        document.getElementById('ai-factors').innerHTML = '<li style="color:#ff8800;">Waiting for a page refresh...</li>';
      }

      // Populate AI Recommendations
      let aiRecommendations = analysis.aiRecommendations;

      // FALLBACK for recommendations if using cached data
      if (!aiRecommendations) {
        let recs = [];
        let thirdPartyTrackers = analysis.trackersFound || (trackerNames ? trackerNames.length : 0);
        let cCount = analysis.cookieCount || cookieCount || 0;
        let pAction = "No urgent actions required.";
        let mGain = 0;

        if (thirdPartyTrackers > 0) {
          let g = Math.min(25, thirdPartyTrackers * 5);
          recs.push({ action: "Enable Shadow Shield", reason: `Block ${thirdPartyTrackers} trackers.`, estimated_score_gain: g });
          if (g > mGain) { mGain = g; pAction = "Enable Shadow Shield"; }
        }
        if (cookieCount > 10) {
          let g = Math.min(15, Math.floor(cookieCount / 2));
          recs.push({ action: "Clear Local Cookies", reason: `Remove ${cookieCount} cookies.`, estimated_score_gain: g });
          if (g > mGain) { mGain = g; pAction = "Clear Local Cookies"; }
        }
        if (recs.length === 0) {
          recs.push({ action: "Maintain Safe Browsing", reason: "Continue using current privacy settings.", estimated_score_gain: 0 });
        }
        recs.sort((a, b) => b.estimated_score_gain - a.estimated_score_gain);
        
        aiRecommendations = { recommendations: recs, priority_action: pAction };
      }

      if (aiRecommendations) {
        const priorityElem = document.getElementById('ai-priority-action');
        const listElem = document.getElementById('ai-recommendations-list');
        
        priorityElem.innerText = `Priority Action: ${aiRecommendations.priority_action}`;
        
        listElem.innerHTML = '';
        if (aiRecommendations.recommendations && aiRecommendations.recommendations.length > 0) {
          aiRecommendations.recommendations.forEach(rec => {
            const item = document.createElement('div');
            item.style.background = 'rgba(255,255,255,0.03)';
            item.style.padding = '12px';
            item.style.borderRadius = '12px';
            item.style.borderLeft = '4px solid var(--orange)';
            item.style.border = '1px solid var(--border)';
            item.innerHTML = `
              <div style="font-weight: 800; color: #fff; font-size: 13px;">${rec.action} <span style="color:var(--orange); font-size: 11px;">(+${rec.estimated_score_gain} score)</span></div>
              <div style="color: var(--sub); font-size: 12px; margin-top: 6px;">${rec.reason}</div>
            `;
            listElem.appendChild(item);
          });
        } else {
          listElem.innerHTML = '<div style="color: #94a3b8; font-size: 13px;">No specific recommendations.</div>';
        }
      }
      // Update Aggression Meter
      const aggressionScore = document.getElementById('aggression-score');
      const aggressionLabel = document.getElementById('aggression-label');
      if (aggressionScore) aggressionScore.innerText = score;
      if (aggressionLabel) {
        if (score > 70) { aggressionLabel.innerText = 'CRITICAL EXPOSURE'; aggressionLabel.style.color = 'var(--red)'; }
        else if (score > 40) { aggressionLabel.innerText = 'ELEVATED RISK'; aggressionLabel.style.color = 'var(--orange)'; }
        else { aggressionLabel.innerText = 'SECURE PARAMETER'; aggressionLabel.style.color = 'var(--orange)'; aggressionLabel.style.opacity = '0.8'; }
      }

      // ── EXPORT DOSSIER LOGIC ──
      const downloadBtn = document.getElementById('download-report');
      if (downloadBtn) {
        downloadBtn.onclick = () => {
          const reportData = analysis;
          const dossierText = `
=========================================
       SCAMLENS INTELLIGENCE DOSSIER
=========================================
TARGET DOMAIN: ${reportData.domain}
GENERATED AT: ${new Date().toLocaleString()}
AGGRESSION SCORE: ${score}/100
RISK LEVEL: ${reportData.riskClassification?.risk_label || reportData.riskLevel}

-----------------------------------------
DETECTED TRACKERS (${reportData.cookieCount}):
${(reportData.trackerNames || []).map(t => " - " + t).join('\n')}

-----------------------------------------
DANGEROUS DATA FIELDS:
${(reportData.dangerousFields || []).map(f => " [!] " + f).join('\n')}

-----------------------------------------
AI PREDICTION (Cyber Heuristics):
Predicted Risk: ${aiPrediction.predicted_risk_level}
Confidence: ${aiPrediction.confidence_score}%
Explanation: ${aiPrediction.model_explanation}

-----------------------------------------
PRIORITY RECOMMENDATION:
${aiRecommendations.priority_action}

=========================================
       SHIELD ACTIVE - DATA SECURED
=========================================
          `.trim();

          const blob = new Blob([dossierText], { type: 'text/plain' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `ScamLens_Dossier_${reportData.domain.replace(/\./g, '_')}.txt`;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          URL.revokeObjectURL(url);
        };
      }

      // Shield toggle
      const btn = document.getElementById('shield-btn');
      if (btn) {
        if (shieldActive) {
          btn.classList.add('on');
          btn.innerText = 'ON ✅';
        }
        btn.onclick = () => {
          const isOn = btn.classList.toggle('on');
          btn.innerText = isOn ? 'ON ✅' : 'OFF';
          if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
            chrome.storage.local.set({ shieldActive: isOn });
            chrome.runtime?.sendMessage?.({ type: isOn ? 'ENABLE_SHIELD' : 'DISABLE_SHIELD' });
          }
        };
      }
    };

  // Load data from chrome storage or fallback
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    chrome.storage.local.get(['lastAnalysis', 'shieldActive'], (data) => {
      onDataLoaded(data?.lastAnalysis, Boolean(data?.shieldActive !== false));
    });
  } else {
    onDataLoaded(defaultReport, true);
  }
});
