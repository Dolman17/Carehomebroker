(() => {
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || '';
  const status = document.getElementById('passkey-status');

  function showStatus(message, isError = false) {
    if (!status) return;
    status.textContent = message;
    status.classList.remove('hidden', 'text-ownerMint', 'text-ownerCoral');
    status.classList.add(isError ? 'text-ownerCoral' : 'text-ownerMint');
  }

  function base64urlToBuffer(value) {
    const padding = '='.repeat((4 - value.length % 4) % 4);
    const base64 = (value + padding).replace(/-/g, '+').replace(/_/g, '/');
    return Uint8Array.from(atob(base64), char => char.charCodeAt(0));
  }

  function bufferToBase64url(value) {
    if (value === null || value === undefined) return null;
    const bytes = new Uint8Array(value);
    let binary = '';
    bytes.forEach(byte => { binary += String.fromCharCode(byte); });
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function creationOptionsFromJSON(options) {
    options.challenge = base64urlToBuffer(options.challenge);
    options.user.id = base64urlToBuffer(options.user.id);
    (options.excludeCredentials || []).forEach(item => {
      item.id = base64urlToBuffer(item.id);
    });
    return options;
  }

  function requestOptionsFromJSON(options) {
    options.challenge = base64urlToBuffer(options.challenge);
    (options.allowCredentials || []).forEach(item => {
      item.id = base64urlToBuffer(item.id);
    });
    return options;
  }

  function registrationCredentialToJSON(credential) {
    return {
      id: credential.id,
      rawId: bufferToBase64url(credential.rawId),
      type: credential.type,
      authenticatorAttachment: credential.authenticatorAttachment,
      clientExtensionResults: credential.getClientExtensionResults(),
      response: {
        clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
        attestationObject: bufferToBase64url(credential.response.attestationObject),
        transports: credential.response.getTransports ? credential.response.getTransports() : [],
      },
    };
  }

  function authenticationCredentialToJSON(credential) {
    return {
      id: credential.id,
      rawId: bufferToBase64url(credential.rawId),
      type: credential.type,
      authenticatorAttachment: credential.authenticatorAttachment,
      clientExtensionResults: credential.getClientExtensionResults(),
      response: {
        clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
        authenticatorData: bufferToBase64url(credential.response.authenticatorData),
        signature: bufferToBase64url(credential.response.signature),
        userHandle: bufferToBase64url(credential.response.userHandle),
      },
    };
  }

  async function postJSON(url, body = {}) {
    const response = await fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: {'Content-Type': 'application/json', 'X-CSRFToken': csrfToken},
      body: JSON.stringify(body),
    });
    const data = await response.json().catch(() => ({}));
    if (data.stepUpUrl) {
      window.location.assign(data.stepUpUrl);
      throw new Error(data.error || 'Passkey confirmation is required.');
    }
    if (!response.ok) throw new Error(data.error || 'The request could not be completed.');
    return data;
  }

  const registerButton = document.getElementById('register-passkey');
  if (registerButton) {
    registerButton.addEventListener('click', async () => {
      registerButton.disabled = true;
      showStatus('Waiting for your device…');
      try {
        const options = await postJSON('/account/passkeys/register/options');
        const challengeId = options.challengeId;
        delete options.challengeId;
        const credential = await navigator.credentials.create({publicKey: creationOptionsFromJSON(options)});
        const result = await postJSON('/account/passkeys/register/verify', {
          challengeId,
          name: document.getElementById('passkey-name')?.value || 'Passkey',
          credential: registrationCredentialToJSON(credential),
        });
        showStatus('Passkey added. Redirecting…');
        window.location.assign(result.redirect);
      } catch (error) {
        showStatus(error.name === 'NotAllowedError' ? 'Passkey setup was cancelled or timed out.' : error.message, true);
        registerButton.disabled = false;
      }
    });
  }

  const prompt = document.getElementById('passkey-prompt');
  const useButton = document.getElementById('use-passkey');
  if (prompt && useButton) {
    useButton.addEventListener('click', async () => {
      useButton.disabled = true;
      showStatus('Waiting for your device…');
      try {
        const options = await postJSON(prompt.dataset.optionsUrl);
        const challengeId = options.challengeId;
        delete options.challengeId;
        const credential = await navigator.credentials.get({publicKey: requestOptionsFromJSON(options)});
        const result = await postJSON(prompt.dataset.verifyUrl, {
          challengeId,
          credential: authenticationCredentialToJSON(credential),
        });
        showStatus('Verified. Redirecting…');
        window.location.assign(result.redirect);
      } catch (error) {
        showStatus(error.name === 'NotAllowedError' ? 'Passkey verification was cancelled or timed out.' : error.message, true);
        useButton.disabled = false;
      }
    });
  }
})();
