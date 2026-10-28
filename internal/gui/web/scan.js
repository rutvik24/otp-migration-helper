// Camera scanning. Frames are decoded inside the page (the browser's own QR
// detector when it has one, otherwise the bundled jsQR) and never uploaded;
// only the decoded text is sent to the server.
const SCAN_INTERVAL_MS = 120;

let jsQRReady = null;

function loadJsQR() {
  if (window.jsQR) return Promise.resolve();
  if (!jsQRReady) {
    jsQRReady = new Promise((resolve, reject) => {
      const script = document.createElement("script");
      script.src = "/vendor/jsQR.js";
      script.onload = resolve;
      script.onerror = () => reject(new Error("The QR reader could not be loaded."));
      document.head.append(script);
    });
  }
  return jsQRReady;
}

export function cameraProblem(error) {
  if (!window.isSecureContext) return "Camera scanning needs a secure connection. Open this page over HTTPS or on localhost, or add QR images instead.";
  switch (error && error.name) {
    case "NotAllowedError":
    case "SecurityError":
      return "Camera access was blocked. Allow the camera for this site in your browser settings, then try again.";
    case "NotFoundError":
    case "OverconstrainedError":
      return "No camera was found. Connect one, or add QR images instead.";
    case "NotReadableError":
      return "The camera is in use by another app. Close it and try again.";
    default:
      return "The camera could not be started. Add QR images or paste the text instead.";
  }
}

// startScan opens the camera in `video` and calls onText for every QR code
// text it reads (repeats included; the caller ignores ones it has). It
// resolves to a stop function.
export async function startScan(video, onText) {
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    throw Object.assign(new Error("no camera API"), { name: "SecurityError" });
  }
  const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" }, audio: false });
  video.srcObject = stream;
  await video.play();

  let detector = null;
  if ("BarcodeDetector" in window) {
    try {
      detector = new window.BarcodeDetector({ formats: ["qr_code"] });
    } catch (e) {
      detector = null;
    }
  }
  if (!detector) await loadJsQR();

  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  let stopped = false;
  let last = 0;

  async function frame(now) {
    if (stopped) return;
    if (now - last >= SCAN_INTERVAL_MS && video.videoWidth > 0) {
      last = now;
      try {
        if (detector) {
          for (const code of await detector.detect(video)) if (code.rawValue) onText(code.rawValue);
        } else {
          canvas.width = video.videoWidth;
          canvas.height = video.videoHeight;
          ctx.drawImage(video, 0, 0);
          const data = ctx.getImageData(0, 0, canvas.width, canvas.height);
          const found = window.jsQR(data.data, data.width, data.height, { inversionAttempts: "dontInvert" });
          if (found && found.data) onText(found.data);
        }
      } catch (e) {
        // A bad frame is skipped; the next one is tried.
      }
    }
    requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);

  return () => {
    stopped = true;
    for (const track of stream.getTracks()) track.stop();
    video.srcObject = null;
  };
}
