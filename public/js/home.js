// Loader
window.addEventListener("load", () => {
  const loader = document.getElementById("loader");
  const main = document.getElementById("main-content");

  setTimeout(() => {
    loader.style.display = "none";
    main.style.opacity = "1";

    document.querySelectorAll(".animate").forEach((el, i) => {
      setTimeout(() => {
        el.classList.add("show");
      }, i * 200);
    });
  }, 1500);
});