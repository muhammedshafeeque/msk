// validator.js

import { URL } from 'url';

function validateAndNormalizeTarget(input) {
  const trimmedInput = input.trim();

  // === Validate IPv4 ===
  const ipRegex =
    /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  if (ipRegex.test(trimmedInput)) {
    return {
      isValid: true,
      type: 'ip',
      original: trimmedInput,
      normalized: trimmedInput
    };
  }

  // === Validate and Normalize URL ===
  try {
    const url = new URL(
      trimmedInput.startsWith('http://') || trimmedInput.startsWith('https://')
        ? trimmedInput
        : 'http://' + trimmedInput
    );
    return {
      isValid: true,
      type: 'url',
      original: trimmedInput,
      normalized: url.hostname
    };
  } catch (err) {
    return {
      isValid: false,
      reason: 'Input is not a valid IP or URL',
      original: trimmedInput
    };
  }
}

export { validateAndNormalizeTarget };
