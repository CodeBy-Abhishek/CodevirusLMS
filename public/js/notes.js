function downloadFile(path) {
  const a = document.createElement("a");
  a.href = path;
  a.download = path.split("/").pop();
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

function downloadFile(path) {
  window.open(path, "_blank");
}
