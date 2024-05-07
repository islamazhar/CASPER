const { startRegistration, startAuthentication } = SimpleWebAuthnBrowser;

// Registration
const statusRegister = document.getElementById("statusRegister");
const dbgRegister = document.getElementById("dbgRegister");

// Authentication
const statusAuthenticate = document.getElementById("statusAuthenticate");
const dbgAuthenticate = document.getElementById("dbgAuthenticate");

/**
 * Helper methods
 */

function printToDebug(elemDebug, title, output) {
  if (elemDebug.innerHTML !== "") {
    elemDebug.innerHTML += "\n";
  }
  elemDebug.innerHTML += `// ${title}\n`;
  elemDebug.innerHTML += `${output}\n`;
}

function resetDebug(elemDebug) {
  elemDebug.innerHTML = "";
}

function printToStatus(elemStatus, output) {
  elemStatus.innerHTML = output;
}

function resetStatus(elemStatus) {
  elemStatus.innerHTML = "";
}

function getPassStatus() {
  return "✅";
}

function getFailureStatus(message) {
  return `🛑 (Reason: ${message})`;
}

/**
 * Register Button
 */
document
  .getElementById("btnRegister")
  .addEventListener("click", async () => {
    resetStatus(statusRegister);
    resetDebug(dbgRegister);

    // Get options
    let uname = document.getElementById("username").value;
    let registration_end_point = `/generate-registration-options?uname=${uname}`;
    const resp = await fetch(registration_end_point);
    const opts = await resp.json();
    printToDebug(
      dbgRegister,
      "Registration Options",
      JSON.stringify(opts, null, 2)
    );

    // Start WebAuthn Registration
    let regResp;
    try {
      regResp = await startRegistration(opts); // startRegistration is defined within the npm module. 
      printToDebug(
        dbgRegister,
        "Registration Response",
        JSON.stringify(regResp, null, 2)
      );
    } catch (err) {
      printToStatus(statusRegister, getFailureStatus(err));
      throw new Error(err);
    }

    // Send response to server
    const verificationResp = await fetch(
      "/verify-registration-response",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(regResp),
      }
    );

    // Report validation response
    const verificationRespJSON = await verificationResp.json();
    const { verified, msg } = verificationRespJSON;
    if (verified) {
      printToStatus(statusRegister, getPassStatus());
    } else {
      printToStatus(statusRegister, getFailureStatus(msg));
    }
    printToDebug(
      dbgRegister,
      "Verification Response",
      JSON.stringify(verificationRespJSON, null, 2)
    );
  });

/**
 * Authenticate Button
 */
document
  .getElementById("btnAuthenticate")
  .addEventListener("click", async () => {
    resetStatus(statusAuthenticate);
    resetDebug(dbgAuthenticate);

    // Get options. Challenge phase
    const resp = await fetch("/generate-authentication-options");
    const opts = await resp.json();
    printToDebug(
      dbgAuthenticate,
      "Authentication Options",
      JSON.stringify(opts, null, 2)
    );

    // Start WebAuthn Authentication
    let authResp;
    try {
      authResp = await startAuthentication(opts); // startAuthentication is from the npm library. it takes the challenge from the generate-authentication-options
      printToDebug(
        dbgAuthenticate,
        "Authentication Response",
        JSON.stringify(authResp, null, 2)
      );
    } catch (err) {
      printToStatus(statusAuthenticate, getFailureStatus(err));
      throw new Error(err);
    }

    // Send response to server
    const verificationResp = await fetch(
      "/verify-authentication-response",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(authResp),
      }
    );

    // Report validation response
    const verificationRespJSON = await verificationResp.json();
    const { verified, msg } = verificationRespJSON;
    if (verified) {
      printToStatus(statusAuthenticate, getPassStatus());
    } else {
      printToStatus(statusAuthenticate, getFailureStatus(msg));
    }
    printToDebug(
      dbgAuthenticate,
      "Verification Response",
      JSON.stringify(verificationRespJSON, null, 2)
    );
  });
