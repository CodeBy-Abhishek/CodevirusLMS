// public/js/loader.js

window.addEventListener("load", () => {
    const loader = document.getElementById("page-loader");

    if (!loader) return;

    // 20 seconds = 20000 milliseconds
    setTimeout(() => {
        loader.classList.add("hidden");

        setTimeout(() => {
            loader.style.display = "none";
        }, 500);
    }, 500);
});
