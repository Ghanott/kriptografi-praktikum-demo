/**
 * Kriptografi Simetris (DES & AES) - Kelompok 1
 * Script: Terpisah untuk Praktik DES, Praktik AES, Perbandingan Komparatif, dan Evaluasi Mode
 */

(function () {
  'use strict';

  // =========================================================================
  // 1. ENGINE DES MURNI (NIST FIPS 46-3)
  // =========================================================================
  const IP = [
    58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7
  ];

  const FP = [
    40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25
  ];

  const E = [
    32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,
    12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,
    24,25,26,27,28,29,28,29,30,31,32,1
  ];

  const P = [
    16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
    2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25
  ];

  const PC1 = [
    57,49,41,33,25,17,9,1,58,50,42,34,26,18,
    10,2,59,51,43,35,27,19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,21,13,5,28,20,12,4
  ];

  const PC2 = [
    14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,
    26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,
    51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32
  ];

  const SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1];

  const SBOXES = [
    [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],[0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],[4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],[15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
    [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],[3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],[0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],[13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
    [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],[13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],[13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],[1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
    [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],[13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],[10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],[3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
    [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],[14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],[4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],[11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
    [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],[10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],[9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],[4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
    [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],[13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],[1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],[6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
    [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],[1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],[7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],[2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]
  ];

  function permute(bits, table) { return table.map(idx => bits[idx - 1]); }

  function bytesToBits(bytes) {
    const bits = [];
    for (let i = 0; i < bytes.length; i++) {
      for (let j = 7; j >= 0; j--) bits.push((bytes[i] >> j) & 1);
    }
    return bits;
  }

  function bitsToBytes(bits) {
    const bytes = [];
    for (let i = 0; i < bits.length; i += 8) {
      let b = 0;
      for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j];
      bytes.push(b);
    }
    return new Uint8Array(bytes);
  }

  function bitsToHex(bits) {
    let hex = '';
    for (let i = 0; i < bits.length; i += 4) {
      const nibble = (bits[i] << 3) | (bits[i+1] << 2) | (bits[i+2] << 1) | bits[i+3];
      hex += nibble.toString(16).toUpperCase();
    }
    return hex;
  }

  function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  }

  function strToUtf8(str) { return new TextEncoder().encode(str); }
  function utf8ToStr(bytes) { return new TextDecoder('utf-8', { fatal: false }).decode(bytes); }

  function bytesToBase64(bytes) {
    let bin = '';
    for (let i = 0; i < bytes.byteLength; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }

  function desGenerateSubkeys(key8Bytes) {
    const keyBits = bytesToBits(key8Bytes);
    const pc1Bits = permute(keyBits, PC1);
    let C = pc1Bits.slice(0, 28);
    let D = pc1Bits.slice(28, 56);
    const subkeys = [];

    for (let r = 0; r < 16; r++) {
      const shift = SHIFTS[r];
      C = C.slice(shift).concat(C.slice(0, shift));
      D = D.slice(shift).concat(D.slice(0, shift));
      subkeys.push(permute(C.concat(D), PC2));
    }
    return subkeys;
  }

  function desFeistelFunction(R, subkey) {
    const expanded = permute(R, E);
    const xored = expanded.map((bit, idx) => bit ^ subkey[idx]);
    const sOutput = [];
    for (let i = 0; i < 8; i++) {
      const chunk = xored.slice(i * 6, (i + 1) * 6);
      const row = (chunk[0] << 1) | chunk[5];
      const col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4];
      const val = SBOXES[i][row][col];
      for (let j = 3; j >= 0; j--) sOutput.push((val >> j) & 1);
    }
    return permute(sOutput, P);
  }

  function desProcessBlock(block8Bytes, subkeys, isDecrypt = false, trace = null) {
    const keys = isDecrypt ? [...subkeys].reverse() : subkeys;
    const bits = bytesToBits(block8Bytes);
    const ipBits = permute(bits, IP);
    let L = ipBits.slice(0, 32);
    let R = ipBits.slice(32, 64);

    for (let i = 0; i < 16; i++) {
      const fRes = desFeistelFunction(R, keys[i]);
      const nextR = L.map((b, idx) => b ^ fRes[idx]);
      const nextL = R;

      if (trace && !isDecrypt) {
        trace.push({
          round: i + 1,
          subkeyHex: bitsToHex(keys[i]),
          leftHex: bitsToHex(nextL),
          rightHex: bitsToHex(nextR),
          fHex: bitsToHex(fRes)
        });
      }

      L = nextL;
      R = nextR;
    }
    const preOutput = R.concat(L);
    return bitsToBytes(permute(preOutput, FP));
  }

  function padPKCS7(bytes, blockSize = 8) {
    const padLen = blockSize - (bytes.length % blockSize);
    const padded = new Uint8Array(bytes.length + padLen);
    padded.set(bytes);
    padded.fill(padLen, bytes.length);
    return padded;
  }

  function unpadPKCS7(bytes) {
    if (bytes.length === 0) return bytes;
    const padLen = bytes[bytes.length - 1];
    if (padLen < 1 || padLen > 8) return bytes;
    for (let i = bytes.length - padLen; i < bytes.length; i++) {
      if (bytes[i] !== padLen) return bytes;
    }
    return bytes.slice(0, bytes.length - padLen);
  }

  let lastDesTrace = [];

  function desEncrypt(dataBytes, key8Bytes, mode = 'CBC', iv8Bytes = null) {
    const subkeys = desGenerateSubkeys(key8Bytes);
    const padded = padPKCS7(dataBytes, 8);
    const output = new Uint8Array(padded.length);
    lastDesTrace = [];
    let prevBlock = iv8Bytes || new Uint8Array(8);

    for (let i = 0; i < padded.length; i += 8) {
      let block = padded.slice(i, i + 8);
      if (mode === 'CBC') {
        block = block.map((b, idx) => b ^ prevBlock[idx]);
      }
      const cipherBlock = desProcessBlock(block, subkeys, false, i === 0 ? lastDesTrace : null);
      output.set(cipherBlock, i);
      if (mode === 'CBC') prevBlock = cipherBlock;
    }
    return output;
  }

  function desDecrypt(cipherBytes, key8Bytes, mode = 'CBC', iv8Bytes = null) {
    if (cipherBytes.length % 8 !== 0) {
      throw new Error("Panjang ciphertext DES harus kelipatan 8 byte!");
    }
    const subkeys = desGenerateSubkeys(key8Bytes);
    const output = new Uint8Array(cipherBytes.length);
    let prevBlock = iv8Bytes || new Uint8Array(8);

    for (let i = 0; i < cipherBytes.length; i += 8) {
      const cipherBlock = cipherBytes.slice(i, i + 8);
      let plainBlock = desProcessBlock(cipherBlock, subkeys, true);
      if (mode === 'CBC') {
        plainBlock = plainBlock.map((b, idx) => b ^ prevBlock[idx]);
        prevBlock = cipherBlock;
      }
      output.set(plainBlock, i);
    }
    return unpadPKCS7(output);
  }

  // =========================================================================
  // 2. ENGINE AES NATIVE (WEB CRYPTO API)
  // =========================================================================
  async function importAesKey(keyBytes, algoName = "AES-CBC") {
    return await window.crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: algoName },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async function aesEncrypt(dataBytes, keyBytes, algoName = "AES-CBC", ivBytes = null) {
    const key = await importAesKey(keyBytes, algoName);
    let config = { name: algoName, iv: ivBytes };
    if (algoName === "AES-GCM") config.tagLength = 128;
    if (algoName === "AES-CTR") config = { name: "AES-CTR", counter: ivBytes, length: 64 };
    const cipherBuffer = await window.crypto.subtle.encrypt(config, key, dataBytes);
    return new Uint8Array(cipherBuffer);
  }

  async function aesDecrypt(cipherBytes, keyBytes, algoName = "AES-CBC", ivBytes = null) {
    const key = await importAesKey(keyBytes, algoName);
    let config = { name: algoName, iv: ivBytes };
    if (algoName === "AES-GCM") config.tagLength = 128;
    if (algoName === "AES-CTR") config = { name: "AES-CTR", counter: ivBytes, length: 64 };
    const plainBuffer = await window.crypto.subtle.decrypt(config, key, cipherBytes);
    return new Uint8Array(plainBuffer);
  }

  function deriveKey(str, length) {
    const raw = strToUtf8(str);
    const out = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
      out[i] = i < raw.length ? raw[i] : (i ^ 0x5a);
    }
    return out;
  }

  function deriveIV(str, length) {
    const raw = strToUtf8(str);
    const out = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
      out[i] = i < raw.length ? raw[i] : (i ^ 0x3c);
    }
    return out;
  }

  function getRandomHexString(byteLen) {
    const arr = new Uint8Array(byteLen);
    window.crypto.getRandomValues(arr);
    return bytesToHex(arr);
  }

  function copyText(el, btn, orig) {
    const txt = el.textContent;
    if (txt && txt !== '-') {
      navigator.clipboard.writeText(txt);
      btn.textContent = "Tersalin!";
      setTimeout(() => { btn.textContent = orig; }, 1500);
    }
  }

  // =========================================================================
  // 3. UI TABS CONTROLLER
  // =========================================================================
  const navBtns = document.querySelectorAll('.nav-btn');
  const tabContents = document.querySelectorAll('.tab-content');

  navBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      navBtns.forEach(b => b.classList.remove('active'));
      tabContents.forEach(t => t.classList.remove('active'));
      btn.classList.add('active');
      const target = document.getElementById(btn.getAttribute('data-tab'));
      if (target) target.classList.add('active');
    });
  });

  // =========================================================================
  // 4. TAB 1: PRAKTIK DES CONTROLLER
  // =========================================================================
  const desModeSelect = document.getElementById('desModeSelect');
  const desPlaintext = document.getElementById('desPlaintext');
  const desCharCount = document.getElementById('desCharCount');
  const desKey = document.getElementById('desKey');
  const desIV = document.getElementById('desIV');
  const desIvGroup = document.getElementById('desIvGroup');
  const btnRandomDesKey = document.getElementById('btnRandomDesKey');
  const btnRandomDesIV = document.getElementById('btnRandomDesIV');
  const btnDesPreset = document.getElementById('btnDesPreset');
  const btnRunDesEncrypt = document.getElementById('btnRunDesEncrypt');
  const btnRunDesDecrypt = document.getElementById('btnRunDesDecrypt');

  const desStatusTag = document.getElementById('desStatusTag');
  const desCipherHexOutput = document.getElementById('desCipherHexOutput');
  const desCipherB64Output = document.getElementById('desCipherB64Output');
  const desDecryptedOutput = document.getElementById('desDecryptedOutput');
  const desExecTime = document.getElementById('desExecTime');
  const desIntegrityStatus = document.getElementById('desIntegrityStatus');
  const btnCopyDesHex = document.getElementById('btnCopyDesHex');
  const btnCopyDesB64 = document.getElementById('btnCopyDesB64');

  const btnOpenDesTrace = document.getElementById('btnOpenDesTrace');
  const desInspectorDrawer = document.getElementById('desInspectorDrawer');
  const btnCloseDrawer = document.getElementById('btnCloseDrawer');
  const desRoundsTableBody = document.querySelector('#desRoundsTable tbody');

  let currentDesCipherBytes = null;
  let currentDesPlain = "";

  desPlaintext.addEventListener('input', () => {
    desCharCount.textContent = `${desPlaintext.value.length} karakter`;
  });

  desModeSelect.addEventListener('change', () => {
    if (desModeSelect.value === 'ECB') {
      desIvGroup.style.display = 'none';
    } else {
      desIvGroup.style.display = 'flex';
    }
  });

  btnRandomDesKey.addEventListener('click', () => {
    desKey.value = getRandomHexString(8);
  });

  btnRandomDesIV.addEventListener('click', () => {
    desIV.value = getRandomHexString(8);
  });

  btnDesPreset.addEventListener('click', () => {
    desPlaintext.value = "Sistem Keamanan Siber Pertemuan 7";
    desCharCount.textContent = `${desPlaintext.value.length} karakter`;
    desKey.value = "KunciDES";
    desIV.value = "12345678";
    runDesEncryption();
  });

  function runDesEncryption() {
    const plain = desPlaintext.value.trim();
    if (!plain) {
      alert("Masukkan plaintext DES terlebih dahulu!");
      return;
    }
    currentDesPlain = plain;
    const plainBytes = strToUtf8(plain);
    const keyBytes = deriveKey(desKey.value, 8);
    const mode = desModeSelect.value;
    const ivBytes = mode === 'CBC' ? deriveIV(desIV.value, 8) : null;

    try {
      const t0 = performance.now();
      const cipher = desEncrypt(plainBytes, keyBytes, mode, ivBytes);
      const t1 = performance.now();

      currentDesCipherBytes = cipher;
      desCipherHexOutput.textContent = bytesToHex(cipher);
      desCipherB64Output.textContent = bytesToBase64(cipher);
      desExecTime.textContent = `${(t1 - t0).toFixed(2)} ms`;
      desStatusTag.textContent = `Terenkripsi (${mode})`;
      desStatusTag.className = "tag tag-warning";
      desDecryptedOutput.textContent = "-";
      desIntegrityStatus.textContent = "Menunggu Dekripsi";
      desIntegrityStatus.style.color = "var(--text-dim)";
    } catch (e) {
      console.error(e);
      desStatusTag.textContent = "Error";
      desStatusTag.className = "tag tag-danger";
    }
  }

  function runDesDecryption() {
    if (!currentDesCipherBytes) {
      runDesEncryption();
    }
    const keyBytes = deriveKey(desKey.value, 8);
    const mode = desModeSelect.value;
    const ivBytes = mode === 'CBC' ? deriveIV(desIV.value, 8) : null;

    try {
      const t0 = performance.now();
      const plainBytes = desDecrypt(currentDesCipherBytes, keyBytes, mode, ivBytes);
      const t1 = performance.now();

      const text = utf8ToStr(plainBytes);
      desDecryptedOutput.textContent = text;
      desExecTime.textContent = `${(t1 - t0).toFixed(2)} ms (Dekripsi)`;

      if (text === currentDesPlain) {
        desIntegrityStatus.textContent = "Cocok (identik)";
        desIntegrityStatus.style.color = "var(--accent-green)";
        desStatusTag.textContent = "Dekripsi berhasil";
        desStatusTag.className = "tag tag-success";
      } else {
        desIntegrityStatus.textContent = "Tidak cocok";
        desIntegrityStatus.style.color = "var(--accent-red)";
      }
    } catch (e) {
      console.error(e);
      desDecryptedOutput.textContent = "[Error dekripsi DES: kunci atau IV salah]";
      desIntegrityStatus.textContent = "Gagal";
      desIntegrityStatus.style.color = "var(--accent-red)";
    }
  }

  btnRunDesEncrypt.addEventListener('click', runDesEncryption);
  btnRunDesDecrypt.addEventListener('click', runDesDecryption);

  btnCopyDesHex.addEventListener('click', () => copyText(desCipherHexOutput, btnCopyDesHex, "Salin Hex"));
  btnCopyDesB64.addEventListener('click', () => copyText(desCipherB64Output, btnCopyDesB64, "Salin Base64"));

  btnOpenDesTrace.addEventListener('click', () => {
    if (!lastDesTrace || lastDesTrace.length === 0) {
      alert("Enkripsi teks terlebih dahulu untuk merekam 16 ronde!");
      return;
    }
    desRoundsTableBody.innerHTML = '';
    lastDesTrace.forEach(r => {
      const row = document.createElement('tr');
      row.innerHTML = `
        <td><strong style="color:var(--accent-orange)">Ronde ${r.round}</strong></td>
        <td class="font-mono">${r.subkeyHex}</td>
        <td class="font-mono">${r.leftHex}</td>
        <td class="font-mono">${r.rightHex}</td>
        <td class="font-mono">${r.fHex}</td>
      `;
      desRoundsTableBody.appendChild(row);
    });
    desInspectorDrawer.style.display = 'block';
  });

  btnCloseDrawer.addEventListener('click', () => {
    desInspectorDrawer.style.display = 'none';
  });

  // =========================================================================
  // 5. TAB 2: PRAKTIK AES CONTROLLER
  // =========================================================================
  const aesAlgorithmSelect = document.getElementById('aesAlgorithmSelect');
  const aesPlaintext = document.getElementById('aesPlaintext');
  const aesCharCount = document.getElementById('aesCharCount');
  const aesKey = document.getElementById('aesKey');
  const aesKeyHelper = document.getElementById('aesKeyHelper');
  const aesIV = document.getElementById('aesIV');
  const aesIvHelper = document.getElementById('aesIvHelper');
  const btnRandomAesKey = document.getElementById('btnRandomAesKey');
  const btnRandomAesIV = document.getElementById('btnRandomAesIV');
  const btnAesPreset = document.getElementById('btnAesPreset');
  const btnRunAesEncrypt = document.getElementById('btnRunAesEncrypt');
  const btnRunAesDecrypt = document.getElementById('btnRunAesDecrypt');

  const aesStatusTag = document.getElementById('aesStatusTag');
  const aesCipherHexOutput = document.getElementById('aesCipherHexOutput');
  const aesCipherB64Output = document.getElementById('aesCipherB64Output');
  const aesTagRow = document.getElementById('aesTagRow');
  const aesTagOutput = document.getElementById('aesTagOutput');
  const aesDecryptedOutput = document.getElementById('aesDecryptedOutput');
  const aesExecTime = document.getElementById('aesExecTime');
  const aesIntegrityStatus = document.getElementById('aesIntegrityStatus');
  const btnCopyAesHex = document.getElementById('btnCopyAesHex');
  const btnCopyAesB64 = document.getElementById('btnCopyAesB64');

  let currentAesCipherBytes = null;
  let currentAesPlain = "";

  aesPlaintext.addEventListener('input', () => {
    aesCharCount.textContent = `${aesPlaintext.value.length} karakter`;
  });

  aesAlgorithmSelect.addEventListener('change', () => {
    const val = aesAlgorithmSelect.value;
    const is256 = val.includes('256');
    const isGCM = val.includes('GCM');

    if (is256) {
      aesKeyHelper.textContent = "Kunci dinormalisasi menjadi 32 byte (256-bit).";
    } else {
      aesKeyHelper.textContent = "Kunci dinormalisasi menjadi 16 byte (128-bit).";
    }

    if (isGCM) {
      aesIvHelper.textContent = "Standar IV/Nonce GCM adalah 12 byte (96-bit).";
      aesTagRow.style.display = 'flex';
    } else {
      aesIvHelper.textContent = "IV untuk CBC/CTR adalah 16 byte (128-bit).";
      aesTagRow.style.display = 'none';
    }
  });

  btnRandomAesKey.addEventListener('click', () => {
    const is256 = aesAlgorithmSelect.value.includes('256');
    aesKey.value = getRandomHexString(is256 ? 32 : 16);
  });

  btnRandomAesIV.addEventListener('click', () => {
    const isGCM = aesAlgorithmSelect.value.includes('GCM');
    aesIV.value = getRandomHexString(isGCM ? 12 : 16);
  });

  btnAesPreset.addEventListener('click', () => {
    aesPlaintext.value = "Kriptografi Simetris Pertemuan 7";
    aesCharCount.textContent = `${aesPlaintext.value.length} karakter`;
    aesKey.value = "KunciRahasiaAES128BitKey";
    aesIV.value = "1234567890abcdef";
    runAesEncryption();
  });

  async function runAesEncryption() {
    const plain = aesPlaintext.value.trim();
    if (!plain) {
      alert("Masukkan plaintext AES terlebih dahulu!");
      return;
    }
    currentAesPlain = plain;
    const plainBytes = strToUtf8(plain);

    const val = aesAlgorithmSelect.value;
    const is256 = val.includes('256');
    const isGCM = val.includes('GCM');
    const isCTR = val.includes('CTR');

    const keyLen = is256 ? 32 : 16;
    const ivLen = isGCM ? 12 : 16;

    const keyBytes = deriveKey(aesKey.value, keyLen);
    const ivBytes = deriveIV(aesIV.value, ivLen);

    let algoName = "AES-CBC";
    if (isGCM) algoName = "AES-GCM";
    if (isCTR) algoName = "AES-CTR";

    try {
      const t0 = performance.now();
      const cipher = await aesEncrypt(plainBytes, keyBytes, algoName, ivBytes);
      const t1 = performance.now();

      currentAesCipherBytes = cipher;
      aesCipherHexOutput.textContent = bytesToHex(cipher);
      aesCipherB64Output.textContent = bytesToBase64(cipher);

      if (isGCM) {
        const tag = cipher.slice(-16);
        aesTagOutput.textContent = bytesToHex(tag);
        aesTagRow.style.display = 'flex';
      } else {
        aesTagRow.style.display = 'none';
      }

      aesExecTime.textContent = `${(t1 - t0).toFixed(2)} ms`;
      aesStatusTag.textContent = `Terenkripsi (${val})`;
      aesStatusTag.className = "tag tag-success";
      aesDecryptedOutput.textContent = "-";
      aesIntegrityStatus.textContent = "Menunggu Dekripsi";
      aesIntegrityStatus.style.color = "var(--text-dim)";
    } catch (e) {
      console.error(e);
      aesStatusTag.textContent = "Error";
      aesStatusTag.className = "tag tag-danger";
    }
  }

  async function runAesDecryption() {
    if (!currentAesCipherBytes) {
      await runAesEncryption();
    }
    const val = aesAlgorithmSelect.value;
    const is256 = val.includes('256');
    const isGCM = val.includes('GCM');
    const isCTR = val.includes('CTR');

    const keyLen = is256 ? 32 : 16;
    const ivLen = isGCM ? 12 : 16;

    const keyBytes = deriveKey(aesKey.value, keyLen);
    const ivBytes = deriveIV(aesIV.value, ivLen);

    let algoName = "AES-CBC";
    if (isGCM) algoName = "AES-GCM";
    if (isCTR) algoName = "AES-CTR";

    try {
      const t0 = performance.now();
      const plainBytes = await aesDecrypt(currentAesCipherBytes, keyBytes, algoName, ivBytes);
      const t1 = performance.now();

      const text = utf8ToStr(plainBytes);
      aesDecryptedOutput.textContent = text;
      aesExecTime.textContent = `${(t1 - t0).toFixed(2)} ms (Dekripsi)`;

      if (text === currentAesPlain) {
        aesIntegrityStatus.textContent = "Cocok (identik)";
        aesIntegrityStatus.style.color = "var(--accent-green)";
        aesStatusTag.textContent = "Dekripsi berhasil";
        aesStatusTag.className = "tag tag-success";
      } else {
        aesIntegrityStatus.textContent = "Tidak cocok";
        aesIntegrityStatus.style.color = "var(--accent-red)";
      }
    } catch (e) {
      console.error(e);
      aesDecryptedOutput.textContent = "[Error dekripsi AES: kunci, IV, atau tag tidak valid]";
      aesIntegrityStatus.textContent = "Gagal";
      aesIntegrityStatus.style.color = "var(--accent-red)";
    }
  }

  btnRunAesEncrypt.addEventListener('click', runAesEncryption);
  btnRunAesDecrypt.addEventListener('click', runAesDecryption);

  btnCopyAesHex.addEventListener('click', () => copyText(aesCipherHexOutput, btnCopyAesHex, "Salin Hex"));
  btnCopyAesB64.addEventListener('click', () => copyText(aesCipherB64Output, btnCopyAesB64, "Salin Base64"));

  // =========================================================================
  // 6. TAB 3: PERBANDINGAN PERFORMA & AVALANCHE (HEAD-TO-HEAD)
  // =========================================================================
  const btnRunBenchmark = document.getElementById('btnRunBenchmark');
  const benchStatusText = document.getElementById('benchStatusText');
  const benchDesTime = document.getElementById('benchDesTime');
  const benchDesOps = document.getElementById('benchDesOps');
  const benchDesBar = document.getElementById('benchDesBar');
  const benchAesTime = document.getElementById('benchAesTime');
  const benchAesOps = document.getElementById('benchAesOps');
  const benchAesBar = document.getElementById('benchAesBar');

  async function runBenchmark500() {
    btnRunBenchmark.disabled = true;
    benchStatusText.textContent = "Menguji komputasi 500 iterasi blok...";

    const block8 = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const block16 = new Uint8Array([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]);
    const desKeyBytes = new Uint8Array([0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1]);
    const aesKeyBytes = new Uint8Array(16).fill(0x33);
    const subkeys = desGenerateSubkeys(desKeyBytes);
    const iterations = 500;

    // Benchmark DES
    await new Promise(r => setTimeout(r, 40));
    const tDes0 = performance.now();
    for (let i = 0; i < iterations; i++) {
      desProcessBlock(block8, subkeys, false);
    }
    const tDes1 = performance.now();
    const desDuration = Math.max(0.1, tDes1 - tDes0);
    const desOps = Math.round((iterations / desDuration) * 1000);

    benchDesTime.textContent = desDuration.toFixed(1);
    benchDesOps.textContent = desOps.toLocaleString('id-ID');

    // Benchmark AES
    await new Promise(r => setTimeout(r, 40));
    const cryptoKey = await importAesKey(aesKeyBytes, "AES-CBC");
    const iv = new Uint8Array(16);

    const tAes0 = performance.now();
    for (let i = 0; i < iterations; i++) {
      await window.crypto.subtle.encrypt({ name: "AES-CBC", iv }, cryptoKey, block16);
    }
    const tAes1 = performance.now();
    const aesDuration = Math.max(0.1, tAes1 - tAes0);
    const aesOps = Math.round((iterations / aesDuration) * 1000);

    benchAesTime.textContent = aesDuration.toFixed(1);
    benchAesOps.textContent = aesOps.toLocaleString('id-ID');

    const maxOps = Math.max(desOps, aesOps);
    benchDesBar.style.width = `${Math.min(100, Math.max(12, (desOps / maxOps) * 100))}%`;
    benchAesBar.style.width = `${Math.min(100, Math.max(12, (aesOps / maxOps) * 100))}%`;

    const ratio = (aesOps / desOps).toFixed(1);
    benchStatusText.textContent = `Selesai: AES sekitar ${ratio}x lebih cepat dibanding DES (akselerasi CPU AES-NI).`;
    btnRunBenchmark.disabled = false;
  }

  btnRunBenchmark.addEventListener('click', runBenchmark500);

  // Dual Avalanche Effect Simulator
  const avalancheInputText = document.getElementById('avalancheInputText');
  const btnRunDualAvalanche = document.getElementById('btnRunDualAvalanche');
  const desAvPercent = document.getElementById('desAvPercent');
  const desAvBits = document.getElementById('desAvBits');
  const desAvStatus = document.getElementById('desAvStatus');
  const desDiffMap = document.getElementById('desDiffMap');

  const aesAvPercent = document.getElementById('aesAvPercent');
  const aesAvBits = document.getElementById('aesAvBits');
  const aesAvStatus = document.getElementById('aesAvStatus');
  const aesDiffMap = document.getElementById('aesDiffMap');

  async function runDualAvalancheTest() {
    const text1 = avalancheInputText.value || "ComputerSecurity2024";
    const bytes1 = strToUtf8(text1);
    const bytes2 = new Uint8Array(bytes1);
    bytes2[0] = bytes2[0] ^ 0x01; // Invert bit 0 pada byte 0 (1-bit flip)

    const keyStr = "KunciSiber2024";

    // 1. DES Avalanche
    const desKeyBytes = deriveKey(keyStr, 8);
    const desC1 = desEncrypt(bytes1, desKeyBytes, 'ECB');
    const desC2 = desEncrypt(bytes2, desKeyBytes, 'ECB');

    const desBits1 = bytesToBits(desC1);
    const desBits2 = bytesToBits(desC2);
    let desDiffCount = 0;
    let desMap = '';
    for (let i = 0; i < desBits1.length; i++) {
      if (desBits1[i] !== desBits2[i]) {
        desDiffCount++;
        desMap += 'X';
      } else {
        desMap += '.';
      }
      if ((i + 1) % 8 === 0 && i < desBits1.length - 1) desMap += ' ';
    }
    const desPct = ((desDiffCount / desBits1.length) * 100).toFixed(1);
    desAvPercent.textContent = `${desPct}%`;
    desAvBits.textContent = desDiffCount;
    desAvStatus.textContent = (desPct >= 40 && desPct <= 60) ? "Ideal (40-60%)" : "Di luar rentang ideal";
    desDiffMap.textContent = desMap;

    // 2. AES Avalanche
    const aesKeyBytes = deriveKey(keyStr, 16);
    const iv = new Uint8Array(16);
    const aesC1 = await aesEncrypt(bytes1, aesKeyBytes, "AES-CBC", iv);
    const aesC2 = await aesEncrypt(bytes2, aesKeyBytes, "AES-CBC", iv);

    const aesBits1 = bytesToBits(aesC1);
    const aesBits2 = bytesToBits(aesC2);
    let aesDiffCount = 0;
    let aesMap = '';
    for (let i = 0; i < aesBits1.length; i++) {
      if (aesBits1[i] !== aesBits2[i]) {
        aesDiffCount++;
        aesMap += 'X';
      } else {
        aesMap += '.';
      }
      if ((i + 1) % 8 === 0 && i < aesBits1.length - 1) aesMap += ' ';
    }
    const aesPct = ((aesDiffCount / aesBits1.length) * 100).toFixed(1);
    aesAvPercent.textContent = `${aesPct}%`;
    aesAvBits.textContent = aesDiffCount;
    aesAvStatus.textContent = (aesPct >= 40 && aesPct <= 60) ? "Ideal (40-60%)" : "Di luar rentang ideal";
    aesDiffMap.textContent = aesMap;
  }

  btnRunDualAvalanche.addEventListener('click', runDualAvalancheTest);

  // =========================================================================
  // 7. TAB 4: MODE OPERASI & PATTERN LEAK DEMO
  // =========================================================================
  const modeDetailPanel = document.getElementById('modeDetailPanel');
  const modeButtons = document.querySelectorAll('.mode-btn');

  const MODE_DATA = {
    ECB: {
      title: "Electronic Codebook (ECB)",
      desc: "Setiap blok plaintext 64/128-bit dienkripsi sendiri dengan kunci yang sama tanpa IV.",
      pros: "Sederhana, setiap blok dapat diproses paralel.",
      cons: "Blok plaintext yang identik menghasilkan ciphertext identik. Pola data tetap terlihat.",
      status: "Tidak disarankan (pola data bocor)."
    },
    CBC: {
      title: "Cipher Block Chaining (CBC)",
      desc: "Setiap blok di-XOR dengan ciphertext blok sebelumnya sebelum dienkripsi. Blok pertama memakai IV acak.",
      pros: "Plaintext yang sama menghasilkan ciphertext acak berbeda.",
      cons: "Enkripsi sekuensial (tidak bisa paralel).",
      status: "Standar industri dengan padding PKCS#7."
    },
    CTR: {
      title: "Counter Mode (CTR)",
      desc: "Counter yang terus bertambah dienkripsi, lalu hasilnya di-XOR dengan data. Mengubah block cipher menjadi stream cipher.",
      pros: "Bisa diproses paralel penuh dan diakses acak.",
      cons: "Counter dan IV tidak boleh dipakai ulang dengan kunci yang sama.",
      status: "Cocok untuk throughput tinggi."
    },
    GCM: {
      title: "Galois/Counter Mode (GCM)",
      desc: "Pengembangan CTR yang menambah autentikasi via Galois Field GF(2^128). Menjamin kerahasiaan sekaligus keaslian data.",
      pros: "Autentikasi bawaan (AEAD) terhadap modifikasi ciphertext.",
      cons: "Implementasi harus aman dari serangan side-channel.",
      status: "Standar modern (TLS 1.3, WireGuard, SSH)."
    }
  };

  function renderMode(modeKey) {
    const d = MODE_DATA[modeKey] || MODE_DATA.ECB;
    modeDetailPanel.innerHTML = `
      <div class="mode-info-grid">
        <div class="mode-summary">
          <h4>${d.title}</h4>
          <p>${d.desc}</p>
          <ul class="mode-features-list">
            <li><span style="color:var(--accent-green)">&#10003;</span> <strong>Kelebihan:</strong> ${d.pros}</li>
            <li><span style="color:var(--accent-red)">&#9888;</span> <strong>Kelemahan:</strong> ${d.cons}</li>
          </ul>
        </div>
        <div class="mode-badge-box">
          <div class="mode-prop-row">
            <span class="label">Rekomendasi:</span>
            <span class="val">${modeKey === 'ECB' ? '<span class="tag-status danger">TIDAK AMAN</span>' : '<span class="tag-status success">AMAN</span>'}</span>
          </div>
          <div class="mode-prop-row">
            <span class="label">Paralelisasi:</span>
            <span class="val">${modeKey === 'CBC' ? 'Sekuensial' : 'Paralel'}</span>
          </div>
          <div class="mode-prop-row">
            <span class="label">Autentikasi:</span>
            <span class="val">${modeKey === 'GCM' ? 'Built-in AEAD Tag' : 'Perlu HMAC'}</span>
          </div>
        </div>
      </div>
    `;
  }

  modeButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      modeButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      renderMode(btn.getAttribute('data-mode'));
    });
  });
  renderMode('ECB');

  // Pattern Leak Test
  const patternInput = document.getElementById('patternInput');
  const btnRunPatternDemo = document.getElementById('btnRunPatternDemo');
  const patternResults = document.getElementById('patternResults');

  function runPatternLeak() {
    const text = patternInput.value || "HELLODESHELLODES";
    const bytes = strToUtf8(text);
    const keyBytes = strToUtf8("DEMOKEY1");
    const ivBytes = strToUtf8("INITVEC1");

    const ecbCipher = desEncrypt(bytes, keyBytes, 'ECB', null);
    const cbcCipher = desEncrypt(bytes, keyBytes, 'CBC', ivBytes);

    const ecbBlocks = [];
    const cbcBlocks = [];
    for (let i = 0; i < ecbCipher.length; i += 8) ecbBlocks.push(bytesToHex(ecbCipher.slice(i, i + 8)));
    for (let i = 0; i < cbcCipher.length; i += 8) cbcBlocks.push(bytesToHex(cbcCipher.slice(i, i + 8)));

    const ecbCounts = {};
    ecbBlocks.forEach(b => { ecbCounts[b] = (ecbCounts[b] || 0) + 1; });

    let html = `
      <div class="block-row-card">
        <div class="block-row-header">
          <span class="title" style="color:var(--accent-red)">Mode ECB (Pola Terlihat):</span>
          <span class="subtext">Blok merah menghasilkan nilai ciphertext yang sama persis</span>
        </div>
        <div class="blocks-container">
    `;
    ecbBlocks.forEach((blk, idx) => {
      const isDup = ecbCounts[blk] > 1;
      html += `
        <div class="cipher-block-chip ${isDup ? 'block-chip-match' : 'block-chip-unique'}">
          <span class="idx-label">Blok #${idx + 1} ${isDup ? '(Identik)' : ''}</span>
          <span>${blk}</span>
        </div>
      `;
    });
    html += `</div></div>`;

    html += `
      <div class="block-row-card">
        <div class="block-row-header">
          <span class="title" style="color:var(--accent-green)">Mode CBC (Pola Tersamarkan):</span>
          <span class="subtext">Setiap blok di-XOR dengan ciphertext sebelumnya</span>
        </div>
        <div class="blocks-container">
    `;
    cbcBlocks.forEach((blk, idx) => {
      html += `
        <div class="cipher-block-chip block-chip-unique">
          <span class="idx-label">Blok #${idx + 1} &check;</span>
          <span>${blk}</span>
        </div>
      `;
    });
    html += `</div></div>`;

    patternResults.innerHTML = html;
  }

  btnRunPatternDemo.addEventListener('click', runPatternLeak);

  // Inisialisasi awal
  runDesEncryption();
  runAesEncryption();
  runDualAvalancheTest();
  runPatternLeak();
})();
