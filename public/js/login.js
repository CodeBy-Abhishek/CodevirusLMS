const signinTab = document.getElementById("signinTab");
const signupTab = document.getElementById("signupTab");
const nameField = document.getElementById("nameField");
const submitBtn = document.getElementById("submitBtn");
const form = document.getElementById("authForm");

// default
nameField.style.display = "none";
form.action = "/login";

signinTab.onclick = () => switchMode("signin");
signupTab.onclick = () => switchMode("signup");

function switchMode(type) {

  signinTab.classList.toggle("active", type === "signin");
  signupTab.classList.toggle("active", type === "signup");

  if (type === "signin") {
    nameField.style.display = "none";
    submitBtn.textContent = "Sign In";
    form.action = "/login";      
  } else {
    nameField.style.display = "block";
    submitBtn.textContent = "Sign Up";
    form.action = "/register";   
  }
}
