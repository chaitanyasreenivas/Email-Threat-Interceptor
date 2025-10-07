let lastScannedEmail = null;
let scanTimeout;

function scanForHiddenContent(emailPane) {
  if (!emailPane) return { detected: false, reason: 'OK', severity: 'OK' };

  const getDomain = (str) => {
    if (!str) return null;
    try {
      return new URL(str).hostname.replace('www.', '');
    } catch (e) { return null; }
  };

  const trustedTrackers = [
    'sendgrid.net', 'hubspot.com', 'mailchimp.com', 'klaviyo.com', 
    'em.amazon.com', 'iterable.com', 'braze.com'
  ];

  const links = emailPane.querySelectorAll('a');
  for (const link of links) {
    const linkText = link.innerText;
    const linkHref = link.href;
    const textDomain = getDomain(linkText);
    const hrefDomain = getDomain(linkHref);
    if (textDomain && hrefDomain && textDomain !== hrefDomain) {
      if (hrefDomain.endsWith(textDomain)) continue;
      if (trustedTrackers.some(tracker => hrefDomain.endsWith(tracker))) continue;
      return { detected: true, reason: 'Deceptive Link Found', severity: 'DANGER' };
    }
  }

  const images = emailPane.querySelectorAll('img');
  for (const img of images) {
    if ((img.offsetWidth <= 1 && img.offsetHeight <= 1) || (img.naturalWidth === 1 && img.naturalHeight === 1)) {
      const pixelDomain = getDomain(img.src);
      const isTrusted = pixelDomain && trustedTrackers.some(tracker => pixelDomain.endsWith(tracker));
      if (!isTrusted) {
        return { detected: true, reason: 'Tracking Pixel', severity: 'INFO' };
      }
    }
  }
  
  const textElements = emailPane.querySelectorAll('p, span, div');
   for (const el of textElements) {
    const style = window.getComputedStyle(el);
    if (el.innerText.trim().length > 0) {
      if (parseInt(style.fontSize) <= 1 || style.opacity === '0' || style.visibility === 'hidden') {
        return { detected: true, reason: 'Invisible Text Found', severity: 'DANGER' };
      }
    }
  }

  return { detected: false, reason: 'OK', severity: 'OK' };
}

function displayScanResults(results) {
  const detailsHeader = document.querySelector('.hP');
  if (!detailsHeader) return;

  let resultsUI = document.getElementById('domain-scan-results-ui');
  if (resultsUI) resultsUI.remove();

  resultsUI = document.createElement('div');
  resultsUI.id = 'domain-scan-results-ui';

  let overallStatus, statusGradient, checkItemsHTML;
  
  if (results.error) {
    overallStatus = 'ERROR';
    statusGradient = 'linear-gradient(45deg, #6c757d, #5a6268)';
    checkItemsHTML = `<div class="check-item" style="color: #c82333; font-weight: 500;">${results.error}</div>`;
  } else {
    const spfPass = results.spf === 'PASS';
    const dmarcPass = results.dmarc === 'PASS';
    const hiddenContentResult = results.hiddenContent;
    const hiddenContentFound = hiddenContentResult.detected;
    
    let domainAge = 'N/A';
    let isNewDomain = true;
    if (results.creationYear && results.creationYear !== 'Not found') {
      const currentYear = new Date().getFullYear();
      const yearParsed = parseInt(results.creationYear);
      if (!isNaN(yearParsed)) {
          const domainAgeYears = currentYear - yearParsed;
          domainAge = `${yearParsed} (${domainAgeYears} years old)`;
          isNewDomain = domainAgeYears < 3;
      }
    }
    
    if (!spfPass || !dmarcPass || results.urlStatus === 'Malicious' || (hiddenContentFound && hiddenContentResult.severity === 'DANGER')) {
      overallStatus = 'DANGER';
      statusGradient = 'linear-gradient(45deg, #dc3545, #c82333)';
    } else if (isNewDomain || results.urlStatus === 'Caution' || (hiddenContentFound && hiddenContentResult.severity === 'CAUTION')) {
      overallStatus = 'CAUTION';
      statusGradient = 'linear-gradient(45deg, #ffc107, #e0a800)';
    } else {
      overallStatus = 'SECURE';
      statusGradient = 'linear-gradient(45deg, #28a745, #218838)';
    }
    
    const spfIcon = spfPass ? '✔' : '✖';
    const dmarcIcon = dmarcPass ? '✔' : '✖';
    const domainAgeIcon = isNewDomain ? '⚠️' : '✔';

    let hiddenContentIcon = '✔';
    if (hiddenContentFound) {
      if (hiddenContentResult.severity === 'DANGER') hiddenContentIcon = '✖';
      else if (hiddenContentResult.severity === 'CAUTION') hiddenContentIcon = '⚠️';
      else hiddenContentIcon = '✔';
    }

    let urlStatusIcon;
    if (results.urlStatus === 'Malicious') urlStatusIcon = '✖'; else if (results.urlStatus === 'Caution') urlStatusIcon = '⚠️'; else urlStatusIcon = '✔';

    const spfIconColor = spfPass ? '#28a745' : '#dc3545';
    const dmarcIconColor = dmarcPass ? '#28a745' : '#dc3545';
    const domainAgeIconColor = isNewDomain ? '#b58900' : '#28a745';
    const urlStatusColor = results.urlStatus === 'Safe' ? '#28a745' : (results.urlStatus === 'Caution' ? '#b58900' : '#dc3545');
    
    let hiddenContentIconColor = '#28a745';
    if (hiddenContentFound) {
        if (hiddenContentResult.severity === 'DANGER') hiddenContentIconColor = '#dc3545';
        else if (hiddenContentResult.severity === 'CAUTION') hiddenContentIconColor = '#b58900';
    }

    checkItemsHTML = `
      <div class="check-item"><span class="icon" style="color: ${spfIconColor};">${spfIcon}</span> SPF: ${results.spf}</div>
      <div class="check-item"><span class="icon" style="color: ${dmarcIconColor};">${dmarcIcon}</span> DMARC: ${results.dmarc}</div>
      <div class="check-item"><span class="icon" style="color: ${hiddenContentIconColor};">${hiddenContentIcon}</span> Hidden Content: ${hiddenContentResult.reason}</div>
      <div class="check-item"><span class="icon" style="color: ${urlStatusColor};">${urlStatusIcon}</span> Links (${results.totalUrlCount}): ${results.urlStatus}</div>
      <div class="check-item"><span class="icon" style="color: ${domainAgeIconColor};">${domainAgeIcon}</span> Domain Age: ${domainAge}</div>
    `;
  }

  resultsUI.innerHTML = `
    <style>
      .scan-container { display: flex; border: 1px solid #dee2e6; margin-top: 16px; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.07); background-color: #ffffff; }
      .status-panel { padding: 16px 24px; color: white; text-align: center; font-weight: 600; font-size: 16px; letter-spacing: 0.5px; text-transform: uppercase; display: flex; align-items: center; justify-content: center; background: ${statusGradient}; min-width: 90px; }
      .checks-panel { display: flex; flex-wrap: wrap; align-items: center; padding: 12px 20px; gap: 16px 24px; width: 100%; }
      .check-item { display: flex; align-items: center; gap: 8px; font-size: 15px; color: #495057; }
      .check-item .icon { font-weight: bold; font-size: 22px; }
    </style>
    <div class="scan-container">
      <div class="status-panel">${overallStatus}</div>
      <div class="checks-panel">${checkItemsHTML}</div>
    </div>
  `;
  detailsHeader.appendChild(resultsUI);
}

function startContentScan() {
    const detailsHeader = document.querySelector('.hP');
    if (!detailsHeader) return;
    let tempUI = document.getElementById('domain-scan-results-ui');
    if (tempUI) tempUI.remove();
    tempUI = document.createElement('div');
    tempUI.id = 'domain-scan-results-ui';
    tempUI.innerHTML = `<div style="border: 1px solid #dee2e6; margin-top: 16px; padding: 16px 24px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; font-size: 15px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.07); color: #6c757d;"><strong>Scanning...</strong></div>`;
    detailsHeader.appendChild(tempUI);

    setTimeout(() => {
        const senderElement = document.querySelector('span[email]');
        if (!senderElement) {
            displayScanResults({ error: "Could not find sender email." });
            return;
        }
        
        const email = senderElement.getAttribute('email');
        const domain = email.substring(email.lastIndexOf("@") + 1);
        lastScannedEmail = email; 

        const emailPane = document.querySelector('div.a3s.aiL'); 
        const links = emailPane ? emailPane.querySelectorAll('a[href]') : [];
        const urls = [...new Set(Array.from(links).map(link => link.href).filter(href => href.startsWith('http')))];
        
        const hiddenContentResult = scanForHiddenContent(emailPane);

        chrome.runtime.sendMessage({ action: "checkContent", domain, urls, hiddenContentResult }, (response) => {
            displayScanResults(response);
        });
    }, 1500);
}

const observer = new MutationObserver(() => {
    clearTimeout(scanTimeout);
    scanTimeout = setTimeout(() => {
      const subjectHeader = document.querySelector('.hP');
      if (subjectHeader) {
          const senderElement = document.querySelector('span[email]');
          let currentEmail = senderElement ? senderElement.getAttribute('email') : null;
          const isNewEmail = currentEmail && currentEmail !== lastScannedEmail;
          
          if (isNewEmail) {
              subjectHeader.removeAttribute('data-security-scan');
          }
  
          const isAlreadyScanned = subjectHeader.getAttribute('data-security-scan') === 'scanned';
  
          if (!isAlreadyScanned) {
              subjectHeader.setAttribute('data-security-scan', 'scanned');
              startContentScan();
          }
      }
    }, 500);
});

observer.observe(document.body, {
  childList: true,
  subtree: true,
});