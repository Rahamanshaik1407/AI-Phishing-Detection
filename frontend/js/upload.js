// upload.js – helper for file validation before sending to API
export function validateFile(file, maxSizeMB = 10) {
  if (!file) return { ok: false, error: 'No file selected' };
  const sizeMB = file.size / (1024 * 1024);
  if (sizeMB > maxSizeMB) {
    return { ok: false, error: `File exceeds ${maxSizeMB} MiB limit` };
  }
  return { ok: true };
}
