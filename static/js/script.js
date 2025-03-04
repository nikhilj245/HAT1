function disableButton(){
    document.getElementById("submitBTN").disabled = true;
}

function Get_Cookie(name) {
    var start = document.cookie.indexOf(name + "=");
    if (start === -1) return null; 
    var len = start + name.length + 1;
    var end = document.cookie.indexOf(";", len);
    if (end === -1) end = document.cookie.length;
    return decodeURIComponent(document.cookie.substring(len, end));
}

function cookiecheck() {
    var cookietest = Get_Cookie('access_token_cookie'); 

    if (cookietest == null || cookietest.trim() === "") {
        document.getElementById("nocookie").style.display = "block";
        document.getElementById("cookie").style.display = "none";
    } else {
        document.getElementById("nocookie").style.display = "none";
        document.getElementById("cookie").style.display = "block";
    }
}

function toggleSidebar() {
    var sidebar = document.getElementById("sidebar");
    sidebar.classList.toggle('active');
}

document.addEventListener("DOMContentLoaded", cookiecheck());

document.addEventListener("DOMContentLoaded", function () {
    const lightModeToggle = document.getElementById("toggle-light-mode");

    // Apply settings when the page loads
    function applySettings() {
        if (localStorage.getItem("lightMode") === "enabled") {
            document.body.classList.add("light-modestorage");
            document.body.classList.remove("dark-modestorage");
            document.body.className = "light-modestorage";
        } else {
            document.body.classList.add("dark-modestorage");
            document.body.classList.remove("light-modestorage");
            document.body.className = "dark-modestorage";
        }
    }
    applySettings();

    // Toggle light/dark mode
    if (lightModeToggle) {
        lightModeToggle.addEventListener("click", function () {
            if (document.body.classList.contains("light-modestorage")) {
                document.body.classList.remove("light-modestorage");
                document.body.classList.add("dark-modestorage");
                localStorage.setItem("darkMode", "enabled");
                localStorage.removeItem("lightMode");
            } else {
                document.body.classList.remove("dark-modestorage");
                document.body.classList.add("light-modestorage");
                localStorage.setItem("lightMode", "enabled");
                localStorage.removeItem("darkMode");
            }
        });
    }

    window.addEventListener("storage", function (event) {
        if (event.key === "lightMode" || event.key === "darkMode") {
            console.log("localStorage change detected. Updating theme...");
            applySettings(); // Reapply the theme
        }
    });

});