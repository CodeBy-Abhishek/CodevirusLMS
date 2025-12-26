function downloadFile(filePath) {
    const link = document.createElement("a");
    link.href = filePath;
    link.download = "";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}
