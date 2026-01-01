const signinTab = document.getElementById("signinTab");
const signupTab = document.getElementById("signupTab");
const authForm = document.getElementById("authForm");
const submitBtn = document.getElementById("submitBtn");
const nameField = document.getElementById("nameField");

signinTab.addEventListener("click", () => {
  authForm.action = "/login";
  submitBtn.innerText = "Sign In";
  nameField.classList.add("hidden");

  signinTab.classList.add("border-blue-500", "text-blue-600");
  signupTab.classList.remove("border-blue-500", "text-blue-600");
  signupTab.classList.add("text-gray-400");
});

signupTab.addEventListener("click", () => {
  authForm.action = "/register";
  submitBtn.innerText = "Sign Up";
  nameField.classList.remove("hidden");

  signupTab.classList.add("border-blue-500", "text-blue-600");
  signinTab.classList.remove("border-blue-500", "text-blue-600");
  signinTab.classList.add("text-gray-400");
});
