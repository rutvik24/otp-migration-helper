// Thin wrapper over fetch: every request carries the CSRF header and failures
// become ApiError with a message that is safe to show.
export class ApiError extends Error {
  constructor(status, message, data) {
    super(message);
    this.status = status;
    this.data = data;
  }
}

async function request(method, path, body) {
  const headers = { "X-Requested-With": "otpmh" };
  let payload;
  if (body instanceof FormData) {
    payload = body;
  } else if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch(path, { method, headers, body: payload, credentials: "same-origin" });
  } catch (e) {
    throw new ApiError(0, "Could not reach otpmh. Check that it is still running, then reload this page.");
  }
  if (res.ok) return res;
  let data = null;
  if ((res.headers.get("content-type") || "").includes("application/json")) {
    data = await res.json();
  }
  throw new ApiError(res.status, (data && data.error) || "Something went wrong. Try again.", data);
}

async function json(method, path, body) {
  const res = await request(method, path, body);
  return res.json();
}

export const api = {
  get: (path) => json("GET", path),
  post: (path, body) => json("POST", path, body === undefined ? {} : body),
  upload: (path, form) => json("POST", path, form),
  blob: async (path, body) => (await request("POST", path, body)).blob(),
  getBlob: async (path) => (await request("GET", path)).blob(),
};
