import { mxtoolboxApiKey, ip2whoisApiKey, virusTotalApiKey } from './config.js';

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "checkContent") {
    try {
      (async () => {
        const { domain, urls, hiddenContentResult } = request;

        const [
          spfResult, 
          dmarcResult, 
          whoisResult
        ] = await Promise.all([
          runMxToolboxLookup('spf', domain),
          runMxToolboxLookup('dmarc', domain),
          runIp2WhoisLookup(domain)
        ]);

        const urlScanResults = await Promise.all(urls.map(url => runVirusTotalLookup(url)));
        
        const virusTotalStatus = processUrlResults(urlScanResults);
        const shortenedUrlCount = findShortenedUrls(urls);
        let finalUrlStatus;
        if (virusTotalStatus === 'Malicious') {
          finalUrlStatus = 'Malicious';
        } else if (shortenedUrlCount > 0) {
          finalUrlStatus = 'Caution';
        } else {
          finalUrlStatus = 'Safe';
        }

        const finalResults = {
          spf: processSpf(spfResult),
          dmarc: processDmarc(dmarcResult),
          creationYear: processWhois(whoisResult),
          totalUrlCount: urls.length,
          urlStatus: finalUrlStatus,
          hiddenContent: hiddenContentResult
        };

        sendResponse(finalResults);
      })();
    } catch (e) {
      console.error("Hybrid Domain Scanner - A critical error occurred:", e);
      sendResponse({ error: "The scan failed unexpectedly." });
    }
    return true;
  }
});

async function runMxToolboxLookup(command, argument) {
  const url = `https://api.mxtoolbox.com/api/v1/lookup/${command}/${argument}`;
  try {
    const response = await fetch(url, { headers: { 'Authorization': mxtoolboxApiKey } });
    return await response.json();
  } catch (error) {
    return { Fault: error.message };
  }
}

async function runIp2WhoisLookup(domain) {
  const url = `https://api.ip2whois.com/v2?key=${ip2whoisApiKey}&domain=${domain}`;
  try {
    const response = await fetch(url);
    return await response.json();
  } catch (error) {
    return { error_message: error.message };
  }
}

async function runVirusTotalLookup(urlToScan) {
  const urlId = await sha256(urlToScan);
  const apiUrl = `https://www.virustotal.com/api/v3/urls/${urlId}`;
  try {
    const response = await fetch(apiUrl, { headers: { 'x-apikey': virusTotalApiKey } });
    if (response.status === 404) {
      return { data: { attributes: { last_analysis_stats: { malicious: 0, suspicious: 0 } } } };
    }
    if (!response.ok) {
      return { error: `API Error: ${response.status}` };
    }
    return await response.json();
  } catch (error) {
    return { error: error.message };
  }
}

function processSpf(data) {
  if (!data || data.Fault || data.Errors?.length > 0) return 'FAIL';
  return data.Passed?.length > 0 ? 'PASS' : 'FAIL';
}

function processDmarc(data) {
  if (!data || data.Fault || data.Errors?.length > 0) return 'FAIL';
  return data.Passed?.length > 0 ? 'PASS' : 'FAIL';
}

function processWhois(data) {
  if (!data || data.error_message) {
    return 'Not found';
  }
  const createDate = data.create_date;
  if (createDate) {
    return createDate.substring(0, 4); 
  }
  return 'Not found';
}

function processUrlResults(results) {
  let hasApiError = false;
  for (const result of results) {
    if (result.error) {
      hasApiError = true;
      continue;
    }
    const stats = result.data?.attributes?.last_analysis_stats;
    if (stats && (stats.malicious > 0 || stats.suspicious > 0)) {
      return 'Malicious';
    }
  }
  if (hasApiError) return 'Error';
  return 'Safe';
}

function findShortenedUrls(urls) {
  const shortenerDomains = ['bit.ly', 't.co', 'goo.gl', 'tinyurl.com', 'is.gd', 'ow.ly'];
  return urls.filter(url => {
    try {
      const domain = new URL(url).hostname.replace('www.', '');
      return shortenerDomains.includes(domain);
    } catch {
      return false;
    }
  }).length;
}

async function sha256(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}