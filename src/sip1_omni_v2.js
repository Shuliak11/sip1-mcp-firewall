// MODULE 10: SIP-1 v2.5 GLOBAL MULTI-OS ENGINE (CLEAN MONOLITHIC BUILD)
"use strict";

const crypto = require("crypto");
const { SIP1Scanner } = require("./sip1_scanner");

const SECURITY_PROFILES = Object.freeze({
  PERSONAL: {
    id: "PERSONAL",
    entropyThreshold: 3.8,
    scrubNames: true,
    scrubEmailsPhones: true,
    scrubAddresses: true,
    scrubNationalIds: true,
    scrubCryptoMedical: true,
    scrubMilitaryCoords: false
  },
  CORPORATE: {
    id: "CORPORATE",
    entropyThreshold: 3.25,
    scrubNames: true,
    scrubEmailsPhones: true,
    scrubAddresses: true,
    scrubNationalIds: true,
    scrubCryptoMedical: true,
    scrubMilitaryCoords: false
  },
  MILITARY: {
    id: "MILITARY",
    entropyThreshold: 2.75,
    scrubNames: true,
    scrubEmailsPhones: true,
    scrubAddresses: true,
    scrubNationalIds: true,
    scrubCryptoMedical: true,
    scrubMilitaryCoords: true
  }
});

const TWINS = ["Alex Mercer", "Elena Vance", "Marcus Sterling", "Lara Croft", "Victor Reznov", "Sarah Connor"];

class Sip1OmniEngineV2 {
  constructor(profileId) {
    this.setProfile(profileId || "CORPORATE");
    this.baseScanner = new SIP1Scanner();
    this.entityToTwin = new Map();
    this.twinToEntity = new Map();
    this.personCounter = 0;
  }

  setProfile(id) {
    const k = String(id || "CORPORATE").toUpperCase();
    this.profile = SECURITY_PROFILES[k] || SECURITY_PROFILES.CORPORATE;
    return this.profile;
  }

  registerTwin(orig, twin) {
    const c = String(orig);
    if (this.entityToTwin.has(c)) return this.entityToTwin.get(c);
    if (this.entityToTwin.size >= 5000) {
      const firstKey = this.entityToTwin.keys().next().value;
      const firstTwin = this.entityToTwin.get(firstKey);
      this.entityToTwin.delete(firstKey);
      this.twinToEntity.delete(firstTwin);
    }
    this.entityToTwin.set(c, twin);
    this.twinToEntity.set(twin, c);
    return twin;
  }

  normalizeCrossOs(str) {
    return String(str || "")
      .normalize("NFC")
      .replace(/\r\n/g, "\n")
      .replace(/[\u0660-\u0669]/g, c => String(c.charCodeAt(0) - 0x0660))
      .replace(/[\uFF10-\uFF19]/g, c => String(c.charCodeAt(0) - 0xFF10));
  }

  scrubWithProfile(inputText) {
    let text = this.normalizeCrossOs(inputText);
    const detections = [];

    // STAGE A (HIGHEST PRIORITY): Military & Tactical Coordinates (MGRS, GPS, Callsigns)
    if (this.profile.scrubMilitaryCoords) {
      const mgrsRx = /\b\d{1,2}[C-X]\s*[A-Z]{2}\s*\d{3,5}\s*\d{3,5}\b/g;
      text = text.replace(mgrsRx, (m) => {
        const t = this.registerTwin(m, "00X AA 00000 00000 [MGRS_MASKED]");
        detections.push({ category: "MIL_MGRS", twin: t });
        return t;
      });

      const gpsRx = /\b[-+]?([1-8]?\d\.\d{3,8}|90\.0+)\s*,\s*[-+]?(180\.0+|((1[0-7]\d)|([1-9]?\d))\.\d{3,8})\b/g;
      text = text.replace(gpsRx, (m) => {
        const t = this.registerTwin(m, "00.0000, 00.0000 [MIL_GRID_REDACTED]");
        detections.push({ category: "MIL_GPS", twin: t });
        return t;
      });

      const callRx = /\b(?:CALLSIGN|UNIT|FREQ|SECTOR)\s*[:=]\s*([A-Z0-9-]{3,20})\b/gi;
      text = text.replace(callRx, (full, val) => {
        const t = this.registerTwin(val, "[TAC_OPSEC_01]");
        detections.push({ category: "MIL_CALLSIGN", twin: t });
        return full.replace(val, t);
      });
    }

    // STAGE B: Passports (ICAO 9303 MRZ - without trailing \b so <<<< is always matched!)
    if (this.profile.scrubNationalIds) {
      const mrzRx = /\bP<[A-Z]{3}[A-Z0-9<]{39,41}/g;
      text = text.replace(mrzRx, (m) => {
        const tag = crypto.createHash("sha256").update(m).digest("hex").slice(0, 8);
        const t = this.registerTwin(m, `[SIP1:v1:PASSPORT_MRZ:k01:P<....:${tag}]`);
        detections.push({ category: "PASSPORT_MRZ", twin: t });
        return t;
      });
    }

    // STAGE C: Web3 Crypto Wallets & HIPAA Medical ICD-10 Codes
    if (this.profile.scrubCryptoMedical) {
      const cryRx = /\b(?:0x[a-fA-F0-9]{40}|bc1q[a-z0-9]{38,58})\b/g;
      text = text.replace(cryRx, (m) => {
        const tag = crypto.createHash("sha256").update(m).digest("hex").slice(0, 8);
        const t = this.registerTwin(m, `[SIP1:v1:CRYPTO_WALLET:k01:0x....:${tag}]`);
        detections.push({ category: "CRYPTO_WALLET", twin: t });
        return t;
      });

      const icdRx = /(\b(?:ICD-10|Diagnosis)\s*[:=]\s*)([A-Z]\d{2}(?:\.\d{1,4})?)\b/gi;
      text = text.replace(icdRx, (full, lbl, code) => {
        const t = this.registerTwin(code, "[HIPAA_ICD10_MASKED]");
        detections.push({ category: "HIPAA_ICD10", twin: t });
        return lbl + t;
      });
    }

    // STAGE D: Multi-Language Anti-Profiling NER (Latin, Cyrillic, Georgian, CJK, Arabic)
    if (this.profile.scrubNames) {
      const latRx = /\b(?:Mr\.|Mrs\.|Ms\.|Dr\.|Prof\.|Founder|Client|User|Name:|Patient:)\s+([A-Z\u00C0-\u017F][a-z\u00C0-\u017F]{1,20}\s+[A-Z\u00C0-\u017F][a-z\u00C0-\u017F]{1,24})\b/gu;
      text = text.replace(latRx, (full, name) => {
        const t = this.registerTwin(name, TWINS[(this.personCounter++) % TWINS.length] + " [PER_0" + this.personCounter + "]");
        detections.push({ category: "PERSON_LATIN", twin: t });
        return full.replace(name, t);
      });

      const cyrRx = /([\u0410-\u042F\u0401][\u0430-\u044F\u0451]{2,20}\s+[\u0410-\u042F\u0401][\u0430-\u044F\u0451]{2,22})/gu;
      text = text.replace(cyrRx, (m) => {
        const t = this.registerTwin(m, TWINS[(this.personCounter++) % TWINS.length] + " [PER_0" + this.personCounter + "]");
        detections.push({ category: "PERSON_CYRILLIC", twin: t });
        return t;
      });

      const geoRx = /([\u10D0-\u10F0]{3,18}\s+[\u10D0-\u10F0]{3,22})/gu;
      text = text.replace(geoRx, (m) => {
        const t = this.registerTwin(m, TWINS[(this.personCounter++) % TWINS.length] + " [PER_0" + this.personCounter + "]");
        detections.push({ category: "PERSON_GEORGIAN", twin: t });
        return t;
      });

      const cjkRx = /((?:\u59D3\u540D|\u0627\u0644\u0627\u0633\u0645)\s*[:=]\s*)([^\s,|]+(?:\s*[^\s,|]+)?)/gu;
      text = text.replace(cjkRx, (full, lbl, name) => {
        const t = this.registerTwin(name.trim(), "Entity_0" + (++this.personCounter) + " [PER_0" + this.personCounter + "]");
        detections.push({ category: "PERSON_GLOBAL", twin: t });
        return lbl + t;
      });
    }

    // STAGE E: Emails, Full 4-Group International Phones (+995 593 12 47 00) & Street Addresses
    if (this.profile.scrubEmailsPhones) {
      const emailRx = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,10}\b/g;
      text = text.replace(emailRx, (m) => {
        const tag = crypto.createHash("sha256").update(m).digest("hex").slice(0, 8);
        const t = this.registerTwin(m, `[SIP1:v1:EMAIL_PII:k01:mail....:${tag}]`);
        detections.push({ category: "EMAIL", twin: t });
        return t;
      });

      // Captures +995 593 12 47 00 completely (2 to 4 groups after country code) without touching MGRS!
      const phoneRx = /\+\d{1,3}(?:[\s.-]*\d{2,4}){2,4}\b/g;
      text = text.replace(phoneRx, (m) => {
        const d = m.replace(/\D/g, "");
        if (d.length < 9 || d.length > 15) return m;
        const tag = crypto.createHash("sha256").update(d).digest("hex").slice(0, 8);
        const t = this.registerTwin(m, `[SIP1:v1:PHONE_PII:k01:tel....:${tag}]`);
        detections.push({ category: "PHONE", twin: t });
        return t;
      });
    }

    if (this.profile.scrubAddresses) {
      const addrRx = /\b(\d{1,5}\s+[A-Z][a-zA-Z0-9\s.,]{3,35}\b(?:Street|St\.?|Avenue|Ave\.?|Road|Rd\.?|Boulevard|Drive))\b/g;
      text = text.replace(addrRx, (m) => {
        const t = this.registerTwin(m, "742 Evergreen Terrace [LOC_PROTECTED]");
        detections.push({ category: "ADDRESS", twin: t });
        return t;
      });
    }

    // STAGE F: Core 7-Stage Cryptographic & Checksum Pipeline (Cards, IBANs, Cloud Keys, DB URIs)
    const session = this.baseScanner.createSession("v2");
    const coreRes = this.baseScanner.scanText(text, { session });
    this._lastSession = session;

    return {
      profile: this.profile.id,
      sanitizedText: coreRes.sanitizedText,
      totalDetections: detections.length + coreRes.findingsCount,
      detections
    };
  }

  rehydrateAll(aiText) {
    let out = String(aiText || "");
    for (let pass = 0; pass < 4; pass++) {
      let prev = out;
      if (this._lastSession && typeof this._lastSession.rehydrate === "function") {
        out = this._lastSession.rehydrate(out);
      }
      if (this.baseScanner && typeof this.baseScanner.rehydrateText === "function" && this._lastSession) {
        out = this.baseScanner.rehydrateText(out, this._lastSession);
      }
      const rev = Array.from(this.twinToEntity.entries()).sort((a, b) => b[0].length - a[0].length);
      for (const [twin, orig] of rev) {
        if (out.includes(twin)) out = out.split(twin).join(orig);
      }
      if (out === prev) break;
    }
    return out;
  }

  scrubOcrBoundingBoxes(words) {
    const overlays = [];
    for (const w of (words || [])) {
      const r = this.scrubWithProfile(w.text);
      if (r.totalDetections > 0 || r.sanitizedText !== w.text) {
        overlays.push({ originalBbox: w.bbox, action: "PAINT_SYNTHETIC_TWIN", replacementText: r.sanitizedText, exifStripped: true });
      }
    }
    return { mode: this.profile.id, boxesProcessed: (words || []).length, redactedBoxesCount: overlays.length, overlays };
  }

  panicWipeRam() {
    this.entityToTwin.clear();
    this.twinToEntity.clear();
    this.personCounter = 0;
    return { wiped: true };
  }
}

module.exports = { SECURITY_PROFILES, Sip1OmniEngineV2 };
