
function toggleProfile(){
    document.getElementById("profileDropdown").classList.toggle("show");
}

// Close dropdown when clicking outside
document.addEventListener("click", function(e){
    const wrapper = document.querySelector(".profile-wrapper");
    const dropdown = document.getElementById("profileDropdown");

    if(wrapper && !wrapper.contains(e.target)){
        dropdown.classList.remove("show");
    }
});

