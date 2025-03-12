// Disable submit button on form submission to prevent multiple submissions
function disableButton() {
    document.getElementById("submitBTN").disabled = true;
}

// Retrieve a specific cookie by name
function Get_Cookie(name) {
    // Find the starting index of the cookie name
    var start = document.cookie.indexOf(name + "=");
    // If the cookie is not found, return null
    if (start === -1) return null;
    // Calculate the starting index of the cookie value
    var len = start + name.length + 1;
    // Find the end of the cookie value (either at the next semicolon or the end of the string)
    var end = document.cookie.indexOf(";", len);
    if (end === -1) end = document.cookie.length;
    // Decode and return the cookie value
    return decodeURIComponent(document.cookie.substring(len, end));
}

// Check if the access token cookie exists and update the UI accordingly
function cookiecheck() {
    // Retrieve the access token cookie
    var cookietest = Get_Cookie('access_token_cookie');
    // If the cookie is missing or empty, show the "nocookie" section and hide the "cookie" section
    if (cookietest == null || cookietest.trim() === "") {
        document.getElementById("nocookie").style.display = "block";
        document.getElementById("cookie").style.display = "none";
    } else {
        // If the cookie exists, hide the "nocookie" section and show the "cookie" section
        document.getElementById("nocookie").style.display = "none";
        document.getElementById("cookie").style.display = "block";
    }
}

// Toggle the visibility of the sidebar by adding/removing the 'active' class
function toggleSidebar() {
    var sidebar = document.getElementById("sidebar");
    sidebar.classList.toggle('active');
}

// Apply theme settings based on the value stored in localStorage
function applySettings() {
    // If light mode is enabled, add the light theme class and remove the dark theme class
    if (localStorage.getItem("lightMode") === "enabled") {
        document.body.classList.add("light-modestorage");
        document.body.classList.remove("dark-modestorage");
    } else {
        // If dark mode is enabled, add the dark theme class and remove the light theme class
        document.body.classList.add("dark-modestorage");
        document.body.classList.remove("light-modestorage");
    }
}

// Event listeners for DOMContentLoaded to initialize the page
document.addEventListener("DOMContentLoaded", function () {
    // Check for cookies when the page loads
    cookiecheck();

    // Apply theme settings when the page loads
    applySettings();

    // Toggle light/dark mode when the toggle button is clicked
    const lightModeToggle = document.getElementById("toggle-light-mode");
    if (lightModeToggle) {
        lightModeToggle.addEventListener("click", function () {
            // If light mode is currently active, switch to dark mode
            if (document.body.classList.contains("light-modestorage")) {
                document.body.classList.remove("light-modestorage");
                document.body.classList.add("dark-modestorage");
                // Update localStorage to reflect the new theme
                localStorage.setItem("darkMode", "enabled");
                localStorage.removeItem("lightMode");
            } else {
                // If dark mode is currently active, switch to light mode
                document.body.classList.remove("dark-modestorage");
                document.body.classList.add("light-modestorage");
                // Update localStorage to reflect the new theme
                localStorage.setItem("lightMode", "enabled");
                localStorage.removeItem("darkMode");
            }
        });
    }

    // Listen for changes in localStorage (so that on page load, it knows whether to display dark or light mode)
    window.addEventListener("storage", function (event) {
        // If the lightMode or darkMode setting changes, reapply the theme
        if (event.key === "lightMode" || event.key === "darkMode") {
            applySettings();
        }
    });
});