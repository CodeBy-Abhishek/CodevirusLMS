// ▶ Play selected lesson video
function playVideo(videoUrl, title) {
  const video = document.getElementById("mainVideo");
  const source = document.getElementById("videoSource");
  const videoTitle = document.getElementById("videoTitle");

  console.log("Video URL:", videoUrl); // debug

  source.src = videoUrl;
  video.load();
  video.play();

  videoTitle.innerText = title;
}

// 📂 Toggle lesson list (NO CSS DEPENDENCY)
function toggleChapter() {
  const chapter = document.getElementById("chapter");
  const arrow = document.getElementById("arrow");

  if (chapter.style.display === "block") {
    chapter.style.display = "none";
    arrow.innerText = "▼";
  } else {
    chapter.style.display = "block";
    arrow.innerText = "▲";
  }
}

// ✅ AUTO-OPEN lessons on page load (important UX fix)
document.addEventListener("DOMContentLoaded", () => {
  const chapter = document.getElementById("chapter");
  const arrow = document.getElementById("arrow");

  chapter.style.display = "block";
  arrow.innerText = "▲";
});
