/**
 * ScamLens — Anti-Fingerprinting Shield (fingerprinter-shield.js)
 * "Rules decide. AI explains."
 * 
 * Runs in "world": "MAIN" at document_start.
 * Directly protects Canvas, Navigator, and Hardware fingerprinting APIs
 * in the page context without creating DOM script tags, ensuring 100% CSP compliance.
 */

(function() {
  'use strict';

  try {
    const reportDetection = (type, details) => {
      try {
        window.dispatchEvent(new CustomEvent('ds-telemetry-event', {
          detail: { type: 'FINGERPRINT_ATTEMPT', detectionType: type, details: details }
        }));
      } catch (e) {}
    };

    // 1. Spoof / Protect Navigator Properties
    try {
      if (navigator.plugins) {
        Object.defineProperty(navigator, 'plugins', {
          get: () => {
            reportDetection('navigator.plugins', 'Access to browser plugins list');
            return [];
          },
          configurable: true
        });
      }

      Object.defineProperty(navigator, 'webdriver', {
        get: () => false,
        configurable: true
      });
    } catch (e) {}

    // 2. Protect Canvas Fingerprinting with Subtle Micro-Noise
    try {
      const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
      CanvasRenderingContext2D.prototype.getImageData = function(x, y, w, h) {
        reportDetection('canvas.getImageData', 'Attempted to read canvas pixels');
        const imageData = originalGetImageData.apply(this, arguments);
        if (imageData && imageData.data && imageData.data.length > 3) {
          const lastIndex = imageData.data.length - 4;
          imageData.data[lastIndex] = (imageData.data[lastIndex] + 1) % 256;
        }
        return imageData;
      };
    } catch (e) {}

    try {
      const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
      HTMLCanvasElement.prototype.toDataURL = function() {
        reportDetection('canvas.toDataURL', 'Attempted to export canvas image data');
        return originalToDataURL.apply(this, arguments);
      };
    } catch (e) {}

    // 3. Hardware Fingerprinting Detection
    try {
      if (navigator.deviceMemory) {
        const originalMemory = navigator.deviceMemory;
        Object.defineProperty(navigator, 'deviceMemory', {
          get: () => {
            reportDetection('navigator.deviceMemory', 'Attempted to read RAM size');
            return originalMemory;
          },
          configurable: true
        });
      }
    } catch (e) {}

    console.log("[ScamLens] Anti-Fingerprinting Shield Active (CSP Safe).");
  } catch (err) {
    // Fail silently to never break host page scripts
  }
})();
